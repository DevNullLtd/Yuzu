# Installed-software inventory

Yuzu collects each endpoint's **installed-software inventory** and syncs it to the
central server's PostgreSQL database on a **daily** cadence, so you can answer
fleet-wide questions like "which devices have package X at version < Y" for asset
management and vulnerability relevance. This is the first source of the agent's
**daily-sync framework** (ADR-0016); more data types will follow on their own
cadences.

## What is collected

- **Machine-wide installed software** (blob contract v2): name, version,
  publisher, install date, plus the package-manager fields below. The daily
  sync calls seven inventory actions in-process and merges their rows:
  `installed_apps` `list_inventory` (Windows: `HKLM` + the agent service
  account's own `HKCU`; Linux: `dpkg`/`rpm`/`pacman`/`apk`; macOS:
  `system_profiler`), `pkg_inventory` `packages` and `managers` (Homebrew) and
  `store_packages` (Linux snaps and flatpaks), and
  `windows_optional_features` `list` and `msi_packages` `list_inventory`
  (Windows machine-context MSI products), and `middleware` `ibm_mq` (IBM MQ
  installations; Linux). An action whose plugin is not loaded, or
  that answers "unsupported on this OS", is skipped. A plugin that is not
  loaded is logged at warn (the rows its action produced are removed on the next
  report); without `installed_apps` the source stays idle and sends nothing,
  because it anchors the report.
  An action that fails (non-zero exit, truncated output, a typed result
  completeness of `PARTIAL` unless the action opts in, a `constrained` or
  `unavailable` answer, a malformed status row, no feature rows from
  `windows_optional_features`, or no applications at all from `installed_apps`)
  skips that day's report and keeps the last good state — nothing is deleted. A
  `constrained` `managers` answer that still names at least one present manager
  is accepted: the constraint concerns manager facts the presence row never
  carried. A skipped cycle is retried sooner on a phase-aligned backoff:
  waits that double from 1 h after each consecutive skip (1 h, 2 h, 4 h, 8 h, …),
  each retry capped so it never lands after the next daily slot — up to four
  extra attempts — then one attempt per daily slot until a collection succeeds.
  While it is skipping, the agent publishes the heartbeat tags
  `yuzu.sync.installed_software.skip_streak` (consecutive skips since the last
  success, uncapped) and `yuzu.sync.installed_software.last_skip` (the reason
  token); the heartbeat carries them to the server, but no server page or API
  returns them yet, so read the reason from the agent's own log. Every row's
  `source` names the
  producing action (`installed_apps.list_inventory`, `pkg_inventory.packages`,
  `pkg_inventory.managers`, `pkg_inventory.store_packages`,
  `windows_optional_features.list`, `msi_packages.list_inventory`); `package_id`
  is empty for these producers except `msi_packages.list_inventory`, where it is
  the MSI product code. The operator-facing `list` action keeps its
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
  `bundle_id` is `-` for rows the bounded bundle-id pass (30 s, at most 5000
  applications, one pass in flight) did not reach; that run leads with a
  `warning|bundle_id_*` row and reports CONSTRAINED -- never silently.
  A degraded acquisition on any OS (Linux/macOS: timeout, kill, spawn failure,
  truncation, or a nonzero exit; Windows: an unreadable Uninstall root or
  application subkey) now emits a single `error|installed_apps: acquisition
  degraded (...)` row and a nonzero result instead of an empty or partial
  `app|` list; on macOS a `list` may begin with a `warning|bundle_id_*` row --
  key on the first token `app`. See "Degraded collections are skipped, not
  published" below.
  Automation that only parses `app|` rows and ignores `error|` is
  unaffected; automation that assumed `list` always succeeds needs an
  update. See `docs/user-manual/agent-plugins.md`'s `installed_apps`/
  `msi_packages` entries for the exact per-action wording.
- **The honest-empty contract:** a field the ecosystem does not store is the
  empty string, **never synthesised** (no `-` placeholders, no guessed `0`
  epoch). Per-ecosystem availability:

  | Field | rpm | deb | apk | pacman | Windows | macOS apps | macOS pkgutil | Homebrew formula | Homebrew cask | Windows feature | Snap | Flatpak | MSI product | IBM MQ |
  |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
  | `kind` | `package` | `package` | `package` | `package` | `app` | `app` | `pkg` | `pkg` | `app` | `feat` | `app` or `pkg` | `app` or `pkg` | `pkg` | `app` |
  | `ecosystem` | `rpm` | `deb` | `apk` | `pacman` | `windows` | `macos` | `macos_pkgutil` | `brew` | `brew` | `optional_feature` | `snap` | `flatpak` | `msi` | `ibm_mq` |
  | `name` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (receipt id) | ✓ | ✓ | ✓ | ✓ (snap name) | ✓ (ref id) | ✓ (product name) | ✓ (`IBM MQ`) |
  | `version` (upstream, release stripped) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | DISM state | ✓ (`snap.yaml`; empty if unreadable) | — (the branch is a ref, not a version) | ✓ (`VersionString`; empty if the product has none) | ✓ |
  | `epoch` | ✓ (empty if none) | ✓ (empty if none) | — | ✓ (empty if none) | — | — | — | — | — | — | — | — | — | — |
  | `release` | ✓ | ✓ (empty for native pkgs) | ✓ (pkgrel) | ✓ | — | — | — | — | — | — | revision | commit | — | — |
  | `arch` | ✓ | ✓ | — | — | — | — | — | — | — | — | — | ✓ | — | — |
  | `publisher` | PACKAGER | Maintainer | — | — | Publisher | signing leaf CN | — | — | — | — | — | — | `Publisher` | ✓ (`IBM`) |
  | `install_date` | ✓ | — | — | — | ✓ | Last Modified | epoch seconds | — | — | — | — | — | — | — |
  | `signature_status` | `signed`/`unsigned` (stored header tags) | — | — | — | — | `signed`/`unsigned`; empty = not read | — | — | — | — | — | — | — | — |
  | `distro_id` / `distro_version` | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — | — | — | — | — | — |

  Notes: rpm `signature_status` reflects the **stored** signature header tags in
  the rpmdb (is a signature recorded), never a live `rpm -K` cryptographic
  verification. `distro_id`/`distro_version` are host-level (`/etc/os-release`
  `ID`/`VERSION_ID`), stamped on every Linux row. deb rows include **held**
  packages (they are installed). Machine-scope Homebrew
  is collected through `pkg_inventory` with `ecosystem` `brew`: each formula is
  `kind` `pkg`, each cask `kind` `app` (`source` `pkg_inventory.packages`), plus
  one `kind` `app` row named `homebrew` with `source` `pkg_inventory.managers`
  that records Homebrew itself is present — one row however many prefixes
  exist (`/opt/homebrew` and `/usr/local` on one Mac collapse to one). Per-user
  Homebrew stores are out of scope; the sync is machine-scope. Only Homebrew is
  mapped from `managers` today: the Linux manager rows (dpkg, apt, rpm, dnf,
  pacman, apk, snap, flatpak) are read but not collected as software, and a
  constrained `managers` answer keeps the sync cycle as long as it names at
  least one present manager.

  Linux snaps and flatpaks are collected through `pkg_inventory`
  `store_packages` (`source` `pkg_inventory.store_packages`), active
  revisions only. A snap is `ecosystem` `snap`, `kind` `app` when its
  `snap.yaml` type is `app` (the default) and `pkg` for any other type (base,
  core, kernel, gadget, snapd), with `version` from `snap.yaml` and `release` the
  snap revision; an active snap whose `snap.yaml` cannot be read is collected
  with an empty version and kind `pkg`. A flatpak is `ecosystem` `flatpak`, `kind` `app` for an application
  and `pkg` for a runtime, with `release` the 64-digit commit and `arch` set;
  `version` is empty because a flatpak branch (`stable`, `51`) is a ref, not a
  version. An inactive revision is not installed software and is not
  collected, and an incomplete listing (for example an unreadable flatpak
  directory) skips the cycle rather than publishing a partial roster.

  **Windows optional features** are collected with `ecosystem`
  `optional_feature` and `kind` `feat`, every feature the host knows, enabled or
  not. For these rows `version` carries the DISM feature state verbatim
  (`enabled`, `disabled`, `pending_enable`, `pending_disable`, `superseded`,
  `partially_installed`, `unknown`) because a feature has no version of its own;
  `publisher` is empty. A host with a disabled feature therefore still lists
  it, so the `/software` catalogue count (grouped by name) counts a host with a
  DISABLED feature as having it — read `version` to tell them apart.

  **MSI products** are collected through `msi_packages` `list_inventory`
  (Windows only; `source` `msi_packages.list_inventory`) with `ecosystem` `msi`,
  `kind` `pkg`, `name`/`version`/`publisher` from Windows Installer's
  `InstalledProductName`/`VersionString`/`Publisher`, and `package_id` the MSI
  product code exactly as the product registers it (no case normalisation).
  Only the machine install context is enumerated: a product installed for one
  user is never listed by this source. A property the product does not have is
  empty; a product with no name (for example one that is advertised but not
  installed) is dropped. A property read that fails for any other reason makes
  the whole roster constrained, so the cycle is skipped rather than a product
  silently disappearing. The same product normally also has an `app`/`windows`
  row from `installed_apps`' registry walk, so a Windows host normally carries
  two rows per MSI product. The `msi` row adds the product code (stored as
  `package_id`; the REST and MCP software routes do not return that column yet)
  and the machine-context guarantee. Install location and uninstall string are
  not collected (wire slots 13-14 stay reserved and empty, #5186). If the
  enumeration itself fails the cycle is skipped (see Troubleshooting).

  **IBM MQ** is collected through the `middleware` plugin's `ibm_mq` action (Linux; `source`
  `middleware.ibm_mq`) with `kind` `app`, `ecosystem` `ibm_mq`, `name` `IBM MQ` and `publisher`
  `IBM`, taken from the plugin's product table. `version` is VRM (version.release.modification,
  for example `9.4.5`); the fix-pack level is not carried. The install path and edition
  are shown by the `middleware` definition, not carried into installed software. This is a
  metadata-only read with no subprocess: `mqinst.ini` and the
  swidtag file names, readable by an unprivileged agent. If the answer is `constrained` the
  collector withholds this source's rows for the cycle, logs a warning, and carries on with
  every other source, rather than failing the whole report. Because each cycle replaces the
  agent's stored inventory, the withheld IBM MQ rows are REMOVED from the stored inventory
  until the source recovers, so they are absent from the Software page; the agent's warn line
  and the status token are the signal. This is the one exception to the skip-the-cycle rule
  above. Windows and macOS answer `unsupported` (planned).

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

  **On every OS, degraded collections are skipped, not published.** If
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
  updating — treat repeated warnings as actionable. On Windows the degraded
  conditions are the registry ones described below.

  The "ran but reported nothing" trigger is macOS-only by design: every Mac has
  GUI applications and installer receipts, so zero means the tool failed. On
  Linux an empty result is often honest — a host may legitimately have `rpm`
  installed and no rpm packages — so that check is not applied there.

  **Windows degrades the same way (#4711).** The registry walk is native, so the
  subprocess cases above do not apply, but an Uninstall root that cannot be
  opened or enumerated to the end, or an application subkey whose open fails
  (access denied above all), marks the collection degraded: `list_inventory`
  emits no rows and returns rc 1 (the daily sync skips the cycle; see the
  troubleshooting entry), and `list`/`query` return one
  `error|installed_apps: acquisition degraded (...)` row with rc 1 instead of a
  partial list; `list_per_user` keeps the rows it read and appends
  `warning|hive_read_failed`. A missing HKCU or WoW6432Node Uninstall key is
  normal, not degraded. A value-level failure (a non-REG_SZ or over-64 KiB
  DisplayName) is not distinguished from an absent value (plugin README caveat
  1).
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
  `--inventory-disable`. The sync blob also has `install_location` and
  `uninstall_string` slots, but they are reserved: the server ignores them and
  stores neither, until ADR-0016 §8 is re-classified for them with the
  agent-side change, #5186. No shipped agent fills them; a build that does gets a
  full-resend request every cycle until the server accepts them. (The only `HKCU`
  read is the agent's own service-account hive, which is benign: the agent runs outside any
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
  ecosystem, epoch, release, arch, signature_status, distro_id, distro_version,
  package_id, source, install_id)`
  — one row per installed package per device. Every column except `agent_id`,
  `name` and `install_id` may be empty (`''`) per the honest-empty contract above; rows
  synced by a pre-v2 agent carry `''` in all eight v2 columns until that
  agent's next full resend. Rows from agents older than this release
  carry `''` in `package_id` and `source`; `install_id` (a row id, reassigned
  on each full report) is always populated.
- `inventory_state(agent_id, source, content_hash, first_seen, last_seen)` — per
  device sync bookkeeping. `first_seen`/`last_seen` are **server receipt times**
  (epoch seconds, stamped when the report is ingested), **not** the agent-supplied
  `collected_at` — so the recency filters and freshness gauge below are immune to
  agent clock skew (#1685).

**Upgrading.** The first server start after the release that added the extended
columns (schema v7) rewrites `installed_software` once, under an exclusive lock,
to add `install_id`, then rebuilds the name index. The time grows with the row
count: about 10-20 s at 4M rows (roughly 13,000 machines, assuming about 300
installed items each), measured on one development host with a single-node
Postgres, and longer beyond that. The pool's 30 s per-statement limit is lifted
for that migration only. Before upgrading, count the rows:

```sql
SELECT count(*) FROM software_inventory_store.installed_software;
```

and check free space: the rewrite needs room for a second copy of the table and
the rebuilt index and writes about as much WAL; with a synchronous standby,
expect the lock to be held until the standby confirms the commit.

Start one server replica first and let the migration finish (`migrated to v7` in
its log) before starting the rest: a second replica waits at most 10 s for the
migration lock and then refuses to start. Avoid long-running
`installed_software` readers during that first start. Above about 2 million rows
(when the lock is held for more than 10 s), also stop every replica before
starting that one: a replica still running the old version queues its
`installed_software` reads and writes behind the lock, holding a pooled
connection for up to 10 s each before erroring, and a custom `options` in the
database connection string turns off the pool's timeouts, so they then wait for
the whole migration. If you are unsure of the row count, stop every replica
first.

The migration is one transaction and logs nothing until `migrated to v7`; watch
it in `pg_stat_activity`. If a supervisor or health check kills the server before
it finishes, Postgres rolls the work back only once it notices the lost
connection, which is when the running statement returns, so the backend can keep
the lock for the rest of the rewrite. Find it in `pg_stat_activity` and
`pg_terminate_backend` it before restarting, or the restart waits 10 s at the
lock and refuses to start. Size start deadlines to the row count: the health
check in `docker-compose.reference.yml` reports unhealthy after about two
minutes, and under the shipped systemd unit a replica refused at the lock can
reach `failed` within a minute and needs `systemctl reset-failed`.

A start refused with `post-migration schema projection check failed` usually
means a column the software queries need is missing although the recorded schema
version is current, for example after restoring only the
`software_inventory_store` schema from an older dump while `public.schema_meta`
kept its newer version. The log ends with the PostgreSQL error, which names the
first missing column; a connection, permission or lock-timeout error there is
not a schema mismatch, so restart. The recorded version is:

```sql
SELECT version FROM public.schema_meta WHERE store = 'software_inventory_store';
```

Deploy the server before any agent that emits the new fields.

**Agent upgrade.** An agent that collects the extra actions (`source`,
Homebrew, optional features) changes its content hash, so its first report after
the upgrade is a full one. It arrives at the agent's existing phase-spread slot
(within about 24 h), not all at once, and carries the new rows; hash-skip
resumes afterwards.

The inventory is queried today with **direct SQL**, e.g.:

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
- Returns up to `limit` rows (max 1000; any integer that fits int64 is clamped to 1..1000).
  When `result_truncated_by_cap` is `true` more rows may exist: pass `next_cursor` back as
  `cursor` to continue the keyset walk (the cursor is opaque and bound to the filter set).
  Optional `version` filter; each row also carries `source`. A wrongly typed argument (a
  non-string `agent_id`, `name`, `version` or `cursor`, or a non-integer `limit`) is refused
  with `kInvalidParams`, never ignored or converted.
- **The caller's scope is applied in SQL** — the gate composes management-group
  visibility with the caller's service-scope tag
  (`meet(management-group, service-scope)`), so a management-group-confined
  operator and a correctly-confined service-scoped API token both get a real
  filtered result — a service-scoped token is no longer denied outright as it
  was before #3290. `devices_omitted` is `0` under push-down (up to 10 000
  visible devices), where the result is complete for the caller's own devices. Above that,
  the rows are filtered after the read and `devices_omitted` is the count of distinct
  out-of-scope devices within the scanned window(s), a bounded and audited signal that
  out-of-scope matches exist. A page there can be empty with a non-null `next_cursor`: keep
  paging until it is `null`. This is distinct from the generic
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

- Query params: `name` (exact), `agent_id` (exact), `version` (exact; present-empty
  selects the empty-version rows), `q` (case-insensitive literal substring), `kind`,
  `ecosystem`, `source` (exact), `limit` (max 1000; 10000 with `format`), `cursor` and `format` (`json` or
  `csv`: an export). Omit `name` and `agent_id` for a fleet-wide scan. The full parameter
  and error tables are in [rest-api.md](rest-api.md); `q`, `kind`, `ecosystem` and
  `source` are REST-only (the MCP tool takes `name`, `agent_id`, `version`, `limit` and
  `cursor`).
- Success body: `{"data": {"software": [...], "count": N, "devices_omitted": M, ...},
  "meta": {"api_version": "v1"}}`. Each row has 14 fields: `{agent_id, name, version,
  publisher, install_date, kind, ecosystem, epoch, release, arch, signature_status,
  distro_id, distro_version, source}` — the v2 fields are `""` where the ecosystem does not
  store them (see the availability matrix above), and `source` is the
  `<plugin>.<action>` that produced the row. The MCP tool's rows carry the identical
  field set.
- **Carries the same scope push-down as the MCP tool** — the SAME
  `require_fleet_read` gate, so REST and MCP cannot observe a different
  admit/filter decision for the same caller (see the MCP note above). A positive
  `devices_omitted` appears only on the wide-scope post-filter path and is
  audited as `denied`; an explicit `agent_id` outside the caller's scope is also audited as
  `denied`, with an empty page.
- `result_truncated_by_cap: true` (present only when set) means more rows may exist; continue
  with `next_cursor` (keyset pagination, opaque cursor bound to the filter set). A
  `format=csv` export carries its continuation in the `X-Next-Cursor` response header, with
  `X-Result-Truncated-By-Cap: true` and a trailing `# result_truncated_by_cap` record; a
  wide-scope export can hold fewer than `limit` rows and still be capped.
- **On store degradation** the endpoint returns **`503`** (an A4 error envelope with a
  `correlation_id`), **never** an empty `200` — so a vulnerability query cannot read a
  transient Postgres outage as "installed nowhere" (ADR-0016 §7 authoritative reads).
  Distinct from a genuinely empty result (`200` with `count: 0`), which means the query
  succeeded and matched nothing in your scope. An unexpected `503` here for a
  management-group-scoped-only caller (no global grant) correlates with the
  `YuzuMgmtGroupReadDegraded` Prometheus alert firing — a management-group store
  degrade, not an authorization problem; retry once it clears (sre, governance run
  2026-08-20).

**Scope is applied in SQL.** A confined caller's visible-device set is pushed into the query
for up to 10 000 devices, so it gets **complete pages of its own devices** — the old
"the cap was consumed by out-of-scope devices" short page no longer occurs, and
`devices_omitted` is `0`. Only a scope wider than 10 000 devices falls back to the in-process
post-filter, where `devices_omitted` is a distinct-device count within the scanned window(s)
and still signals that out-of-scope matches exist. The page is refilled with at most four
bounded reads, so it can be empty with a non-null `next_cursor`; that cursor re-anchors at
the last row you were served and skips the rows already scanned (a row inserted or deleted inside
that span, or a scope that widens between pages, can make a walk miss or repeat a row, the
same class as the `install_id` churn noted for a concurrent resync). A continuation's skip is
a position count, so a long run of out-of-scope rows costs proportionally more to resume, and
a statement timeout there degrades the page to a 503 (tracked in #5698). Keep paging until
`next_cursor` is `null`.

### REST: software title catalogue

`GET /api/v1/inventory/software/catalogue` returns one row per software title across the
fleet with filtered `totals`, first-page KPIs, a keyset `next_cursor` and a `format=csv`
export; `GET /api/v1/inventory/software/catalogue/versions` returns installs per version
of one title. Unlike the raw route above, a management-group-confined caller gets `403` on
the fleet view (pass `agent_id` for an in-scope device) and service-scoped tokens are
denied. A degraded read is `503`, never an empty `200`; the fleet export and the unfiltered
versions read are also `503` until the first catalogue refresh has landed. Parameters,
responses and audit behaviour: [REST API](rest-api.md#get-apiv1inventorysoftwarecatalogue).

### Dashboard (`/inventory` → `/hardware` / `/software`)

The old three-tab **Inventory** dashboard is gone. `/inventory` itself still exists as a
route, but it now just **302-redirects to `/hardware`** (auth still gates first, so an
unauthenticated visitor lands on `/login`, never in a redirect loop through an
authed-only destination) — old bookmarks and links keep working, nothing to change on
your end beyond expecting a redirect. The sidebar's **Estate** group carries two separate links in its
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
  Stale / CI coverage) is computed over the same rows the table shows. Two readouts sit
  beside it: **Median memory** (over the devices that have synced a positive RAM figure,
  with that device count in the label) and a **By manufacturer** line (case-folded, the
  top eight and an "Other" tail). Both are computed from the devices you can see before
  any search or filter narrows the table, and both are hidden when no device has synced
  the figure or the CI columns are degraded. **The list is
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
  - **Tags and properties** — inline add/remove via the existing tag routes. Add is
    shown when a `Tag:Write` probe passes for the device; Remove needs its own
    `Tag:Delete` probe (a different permission), taken only when this lens is open. The
    lens also hosts **Custom properties** (the device's `props.<key>` values, read from
    `GET /api/agents/{id}/properties`, gated on scoped `Infrastructure:Read`; edit
    controls need `Infrastructure:Write`) and **Property schemas** (fleet-wide, read from
    `GET /api/property-schemas`, so a management-group-confined operator sees a note
    naming the missing fleet-wide `Infrastructure:Read` grant instead). Both load in one
    fragment, `GET /fragments/hardware/ci/properties?id=`; a degraded store reads
    "could not be read", never "No properties set." Property values are written to the
    audit log (`custom_property.set`) and take part in scope expressions.
    Add tag, Remove tag, Add or edit property, Delete property and Save schema open a
    dialog (`static/yuzu-device-data.js` on the shared dialog module); removing or setting
    the `service` tag says that it decides which service-scoped API tokens can reach the
    device. The **environment** tag accepts only `Dev`, `UAT` or `Production`, exact case.
  - **Installed software** also shows "N applications, last synced <time>" (a device that
    never synced and a degraded read are worded differently), and two **click-to-load**
    panels: **Application usage** (hours and runs over the last 30 days, first and last
    seen, the first 200 executables by hours; scoped `Forensics:Read`, audit verb
    `app_usage.agent.view`) and **Detected licences** (scoped `SoftwareLicensing:Read`,
    audit verb `sle.agent.view`; no per-user column). Both write the audit row before
    reading and, when it cannot persist, show "withheld" with `Sec-Audit-Failed: true`
    and no data. They are the HTML twins of `GET /api/v1/forensics/agents/{id}/app-usage`
    and `GET /api/v1/sle/agents/{id}`.
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
    underlying action itself succeeded) — see [Audit log](audit-log.md). The reply of
    a Forensics-tier plugin is shown only to a caller who also holds a global `Forensics:Read`
    (there is no per-device or management-group scoped read tier); any other caller sees a note naming that
    permission instead of the reply.

- **`/software`** — installed software by application, version and device, rebuilt on the
  catalogue model that the REST and MCP twins (`GET /api/v1/inventory/software/catalogue`,
  `query_software_catalogue`) share, so the page, the API and the agent tools cannot
  disagree.
  - **Metrics strip.** Inventory coverage (devices reporting software, devices connected
    now, devices not seen in 48 hours), Titles and publishers, Installs with a
    Windows/macOS/Linux bar and the average per device, Stay current (installs on their
    title's newest version seen in the fleet, a proxy and not a vendor feed), Version
    sprawl (titles on three or more versions; click it to filter to just those) and
    Unsigned packages (rpm only). Figures that cannot be computed show a dash, never a
    guess. A link under the strip reveals five faded tiles for metrics that need data
    Yuzu does not hold yet (end-of-support, unused, unauthorised, new titles,
    normalisation). The strip is the fleet-wide hourly rollup and does not change with
    the filters.
  - **Inventory sources.** A panel under the results lists each collector that has
    written inventory (Source, Devices, Last collected). It is the HTML twin of
    `GET /api/v1/inventory/tables` and needs the fleet-wide `Inventory:Read` grant; a
    caller without it sees a note, a degraded store says so, and an empty store says no
    inventory has been collected yet.
  - **Search and filters.** One search box matches title, publisher, ecosystem or the
    source that found the software; chips narrow by kind, ecosystem and found-by; a host
    type-ahead shows a single device's software. The type-ahead lists the first 1,000
    named hosts by name and says so when the fleet has more; a name it does not list
    cannot be selected, so open that device from Hardware instead. Two devices that share a
    hostname resolve to the first one listed; open the other from Hardware. Active filters appear
    as pills with a Clear all, the URL hash carries them (so a view can be bookmarked or shared), and the
    exact REST call the view corresponds to is shown with a copy button. The filter box on an
    expanded devices table filters only the rows already loaded; the catalogue search
    and chips are server-side.
  - **The table** lists titles most-installed first, 100 at a time with a keyset
    **Load more**. **Installs** is the exact number of distinct devices carrying the
    title under the active filters (a device carrying one title through two sources
    counts once), and the count line gives the exact totals across every page. Click a
    row for **installs per version** (share bars and a "newest in fleet" mark; the 200 most-installed versions, and the table says when a title may have more) inline, and
    **devices** on a title or on one version for the hosts running it (a host that carries a
    title through two sources, such as an MSI product also found by the registry walk, appears once
    per source there although **Installs** counts it once). The devices table
    links each host to its Hardware record and shows OS, version, ecosystem and source,
    install date and **Last synced** — the device's installed-software sync time, the same
    value the Hardware record and `GET /api/v1/hardware/{id}` show. It pages 100 at a
    time and gains a filter box once more than eight hosts are loaded; the filter applies
    to the loaded rows only.
  - **Exports** are plain download links to the REST routes: the matching install rows as
    JSON or CSV (up to 10,000; the file says if it was cut off) and the titles as CSV.
    The sprawl filter is not applied to install exports.
  - **Sync now.** The button at the top of the page asks devices to re-send their
    installed-software inventory now instead of waiting for the ~24 h cadence. A dialog
    offers three choices: **This device** (offered while the Host box names a listed host),
    **Devices matching a scope expression or group** (a scope expression, or `group:<id>`),
    and **Whole fleet**. For a scope expression the Review step previews the match count
    through `POST /api/v1/scope/preview`; that route needs `Infrastructure:Read`, so if it is
    refused for lack of permission the dialog goes on to the confirm step without a count; any
    other preview error (an invalid expression, for example) is shown in the dialog before you
    can confirm. After you confirm, a
    notice says how many devices were asked to sync and how many were skipped. It calls
    `POST /api/v1/hardware/sync`.
    - **Who may.** The route needs `Execution:Execute`, checked as a **global** grant (or
      RBAC off). An operator whose `Execution:Execute` is limited to management groups is
      refused with `403` for every choice, including a single device. A browser (session-cookie) request must carry an `Origin` or `Referer` naming this site (`403` otherwise; token callers are exempt). The route also
      confines its targets to the caller's own `Execution:Execute` visible set and refuses
      **Whole fleet** (`403`) unless that set is unfiltered; with a global grant neither
      changes the outcome today, and both stay in place as defence in depth for when the
      gate becomes scope-aware.
    - **Which devices.** A run reaches agents attached to **this server process** only.
      `skipped_offline` counts the devices this server process did not reach that are not too old: it has no live session for them (a disconnected device, or one attached to another server), or the send was refused by the live stream (for example a gateway-attached agent whose gateway lacks the dispatch capability).
      Which devices are candidates depends on the scope: a group or a single named device lists its disconnected members too, but an `__all__` or scope-expression run lists only this server's own sessions plus the shared presence record, so a device that is offline everywhere is never counted, and if the presence read is degraded an `__all__` run lists fewer devices (those attached to other servers are not listed) while a scope-expression run is refused with 503 (the scope could not be evaluated) and sends nothing.
      `requested` and `skipped_offline` therefore describe what this server could reach; they are not a census of the fleet. Agents older than 0.13.1 are skipped
      and counted separately (`skipped_version`). One request reaches at most 500 devices (`413` above that, counted after the skips:
      narrow the scope). A scope expression may be up to 1,024 bytes and a device or group id
      up to 256 bytes.
    - **Limits.** A group, scope or fleet run is limited to one per operator per 60 seconds
      (`429` with `Retry-After`; an attempt refused for exceeding 500 devices, or with no live target, counts as a run, a send every device refused does not) and one at a time per server process (`409`); a single device
      is exempt from both. A `409` can follow a slow agent connection: the server sends to its
      targets one after another, and a connected agent that has stopped reading holds the run
      for at most 120 seconds, after which the next request takes the run over (`retry_after_ms` on the `409` is the time until that lease lapses; the stalled send itself is not cancelled). At most three runs are alive at once: while three stalled sends are still alive, no further takeover is allowed, the `409` keeps answering, and a WARN line is logged, until one of those sends unwinds (the agent reads, or its connection is cut) or the server restarts. A server clock that steps backwards
      cannot lock an operator out: a last-run time in the future is ignored. Both limits are
      held in each server process, not across a cluster: with several active servers every
      one allows its own run and keeps its own per-operator cooldown, and each run is still
      bounded by the 500-device cap. One run can make up to 500 agents upload their
      inventory at nearly the same moment; see the connection-pool note in
      [Server administration](server-admin.md).
    - **Audit and result.** The request is audited as `inventory.sync.request` before
      anything is sent, and is refused if the audit row cannot be written. `202` means the
      request was sent, not that the devices have synced: the page's figures change when each
      device reports back. In the `202` body `agents_reached` is the number of agents that
      accepted the request; the audit row's `reached` is the number the run planned to send
      to.
  - **Who sees what.** The catalogue is a fleet-wide aggregate that cannot be narrowed to
    a management group, so the fleet view, the strip and the version counts need an
    unfiltered `Inventory:Read`; a management-group-scoped account is told so and refused
    (audited as denied); the notice points to Hardware and carries a
    **Clear all filters and reload** link. A scoped account can still use the host view
    and the devices tables for devices in its scope, but only through a hand-typed
    `/software#host=<agent_id>` address, which has no host-name type-ahead; there the "newest in fleet" mark is
    blanked, no fleet
    figures are read, and device counts omit "of M". A scope wider than 10,000 devices is
    applied after the read in at most four bounded reads, so a devices page can come back short or
    even empty while **Load more** is still offered; keep loading. Service-scoped API
    tokens are denied outright.
  - **Audit.** Every call that serves data (or is refused on scope) is audited, not only the first page: `inventory.software.catalog`
    (title pages), `inventory.software.versions` and `inventory.software.query` (devices
    tables). A continuation page is tagged `page=continuation`; a degraded read is
    `failure`; a refused caller is `denied`, as is a devices page that drops devices through the
    scope post-filter or names an `agent_id` outside the caller's scope. See [Audit log](audit-log.md).
  - **Degraded or refused.** A store that cannot answer shows an unavailable banner with
    a Retry button on the catalogue and a plain retry notice on the version and device tables, never an empty table. A malformed filter in the URL shows a notice
    and reads nothing; use the **Clear all filters and reload** link, which drops the
    stored filters. A Load-more token from a different filter set or from before the
    latest hourly refresh shows a notice and reads nothing; reload the page to restart
    from the first page.
  - **Removed routes.** The standalone **Find software** tab and the old Devices-tab
    fragments are gone: `/fragments/inventory/find`, `/fragments/inventory/find/results`,
    `/fragments/inventory/devices` and `/fragments/inventory/device` return `404` for an
    authenticated caller (an unauthenticated request is redirected to the login page
    first, like any other dashboard path); `/inventory` itself still redirects (`302`) to
    `/hardware`.

**On store degradation** the **`/software`** catalogue, its inline version and devices tables, and
the CI record's **Installed software** lens — the *authoritative* reads — show an
explicit **"unavailable"** banner rather than an empty table, because an empty table
would read as "installed nowhere", the fail-open the authoritative-read contract
(ADR-0016 §7) forbids. The **Hardware list** itself (hostname/OS/status/last-seen/IP/
DEX/version) is sourced from the endpoint-state store (a failed read is reported as such, never shown as an empty roster), with the
CI and Tags columns layered on top from a best-effort `DeviceInventoryStore`/tag-store
read — a *whole-store* degrade there is now its own explicit "CI columns unavailable" /
"Tags unavailable" banner (an improvement on the old Devices tab, where a
`DeviceInventoryStore` degrade during the list render was indistinguishable from "not
yet synced"); a FAILED roster read (not only an unwired provider) shows a dedicated
"roster unavailable" banner rather than an empty table, makes `GET /api/v1/hardware`
answer `503` with `retry_after_ms`, and audits `result=failure` (see Troubleshooting
for where to look). On the dashboard's CI record, an unreadable roster with no CI
record to show reads "roster unreadable"; otherwise the record is shown with a note
on the Overview lens that the device identity is unavailable. **REST:** `GET /api/v1/hardware/{id}`
distinguishes "not found" (`404`) from "roster unreadable" (`503`, the device was not
otherwise found: CI record readable-and-absent, no software, no tags) from a record
served with a degraded identity (`identity_state: degraded`). **REST:** a degraded CI store
alongside a degraded roster is a `200` carrying both `identity_state` and `ci_state` as
`degraded`. The **per-device CI record's Overview lens**, by contrast, has always been
an authoritative three-state read: found / genuinely-not-yet-synced ("no CI record
synced yet") / degraded (an explicit "CI record unavailable" banner) are never
conflated.

The Hardware list and its KPI strip serve at most the 100,000 most recently seen
endpoints within the 30-day window; a fleet above that sees a capped list without a
warning (a truncation signal is tracked in #5712). The cap counts distinct enrolled
`agent_id`s seen in the window: a device that disconnects cleanly stays listed as
Offline for the full 30 days (#5678), and a device re-enrolled under a new `agent_id`
appears as two rows until the old one ages out. The per-device record's offline
identity fallback reads the same capped set, so an offline device outside it shows no
identity and, with nothing else synced, reads as not found.

A decommissioned device is removed from the roster when `DELETE /api/v1/sle/agents/{id}`
deletes its stored record (#5682); a still-enrolled agent that heartbeats again re-creates
it. A device that is never decommissioned stays listed as Offline for the 30-day window,
and its stored record is deleted 37 days after its last contact.

## Access control

Inventory reads are governed by the **`Inventory`** RBAC securable
(`Inventory:Read`), granted by default to the Administrator, ITServiceOwner,
PlatformEngineer, Viewer, and Operator roles. (The gate applies to the
inventory REST/MCP surfaces; direct database access is governed by your Postgres
credentials.)

## Troubleshooting

**The `installed_software` table is empty after upgrading agents.** Most likely
the `installed_apps` plugin isn't loaded — the sync source then idles
(it logs `sync: installed_apps plugin not loaded` at **warn**, and publishes
`installed_apps:not_loaded` as its `yuzu.sync.installed_software.last_skip`
heartbeat tag). Verify the
agent was built with `-Dbuild_agent=true` (the default for released binaries)
and that `installed_apps` is present in the agent's `--plugin-dir`. The sync also
only runs once per ~24 h per agent (spread across the fleet), so a freshly
enrolled agent populates within minutes (jittered first sync), not instantly.

**One host stopped reporting after upgrading agents; its log shows
`sync: <plugin>.<action> … — skipping this cycle`.** One of the collected
actions failed, and a failure skips the WHOLE report for that day — the
applications too — and keeps the last good inventory (nothing is deleted).
Typical causes: Windows DISM busy or `api_unavailable` (the
`windows_optional_features` action answers `feature|unavailable|…`), a
constrained Homebrew `packages` read on macOS (a constrained `managers` answer
that names a present manager no longer skips), or on Linux an unreadable,
symlinked or over-cap snap or flatpak store directory, or a MAC (SELinux or
AppArmor) denial, which makes `store_packages` constrained; the skip reason
reads `pkg_inventory.store_packages:linux:<source>:<detail>`, and the remedy is
read access for the agent identity to `/var/lib/snapd/snaps` and
`/var/lib/flatpak/{app,runtime}`. The warning names the action and the
reason. A Windows host whose reason reads
`msi_packages.list_inventory:windows:msi_enum:<code>` has a Windows Installer
enumeration error (for example `1610`, a corrupt registration): the skip repeats
every cycle until the host's Windows Installer registration is repaired, and
nothing is deleted meanwhile (`last_seen` stops advancing). A reason that reads
`msi_packages.list_inventory:windows:msi_prop:<code>` means a product property
could not be read for a reason other than the product not having it (or, as
`windows:msi_prop:oversized`, the value was implausibly long); it behaves the same
way. The same reason is published on the agent's heartbeat as
`yuzu.sync.installed_software.last_skip` (characters outside
`A-Z a-z 0-9 _ . : = , -` become `_`, and the value is cut at 64 bytes, so a long
list of constraint tokens is shortened; no server page or API returns the tag
yet), and
`yuzu.sync.installed_software.skip_streak` counts consecutive skips (uncapped): an
online host that is skipping publishes a non-zero streak, an offline host no
heartbeat at all. The agent retries
a skipped cycle on the bounded backoff described under *What is collected*, then
falls back to one attempt per daily slot. A host that keeps skipping is flagged by `yuzu_inventory_stale_agents`
after two missed daily cycles; fix the failing action, or remove its plugin,
and the next retry or daily sync recovers. A warning of the form `sync: <plugin>.<action>
read more than 20000 rows` (or a merged-entry or 3 MiB blob cap) is not an
action failure: that host reports more software rows than one report can carry,
so its report is skipped rather than sent truncated; review the host's
inventory rather than removing a plugin.

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
  `pool_acquire_timeout` / `query_error`, plus `admission_full` for `source="installed_software"` and `source="ca_issued"` only: a `/crypto` read refused by its in-flight bound before any store call; source ∈ `installed_software` / `device_ci` /
  `software_licensing` / `product_registry` / `app_usage` / `generic`, and the `/crypto` sources `ca_issued` (Yuzu-issued certificate reads) and `crypto_layout` (dashboard layouts), see [metrics.md](metrics.md#crypto-dashboard-metrics)) — an
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
- `yuzu_fleet_inventory_sync_skipping{source}` (gauge) — agents currently
  heartbeating whose `source` skipped its latest collection cycle(s), from the agent
  heartbeat tag `yuzu.sync.<source>.skip_streak` (today only `source="installed_software"`,
  written by agents that include the skip-visibility change, #5327). The cause is in the agent's own log (the `sync: … — skipping this cycle`
  warning, or `sync: installed_apps plugin not loaded`); the agent also publishes it as the
  `yuzu.sync.<source>.last_skip` heartbeat tag, which no server page or API returns yet.
  Published every sweep, 0 included. The gauge only counts agents that emit the
  skip-streak heartbeat tag: an agent that does not emit it (older agents, during a
  rollout, or in a mixed-version fleet) contributes zero even when its collector is
  skipping, so a zero gauge does not establish that all collectors are healthy.
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
  — one per recompute attempt that completes or fails (a shutdown-cancelled attempt is
  not counted as an error). A rising `error` count with a frozen
  `…_last_success_timestamp` means recomputes are failing (PG outage, a statement over
  its 60 s limit, or the 10-minute whole-refresh limit exceeded at scale) and the
  catalogue is going stale; keep-last-good serves the prior rollup meanwhile, except for
  the first refresh after the v8 upgrade, which has no last-good and leaves the catalogue
  "building". The failing statement and its cause are in the server log (warning).
- `yuzu_inventory_catalog_rollup_duration_seconds` (gauge) — the last recompute's
  whole-refresh wall-clock. Compare it with the two compile-time limits (not flags): 60 s
  per statement and 600 s for the whole refresh. A value rising towards either is the
  leading indicator that the fleet is nearing the ceiling below. (A gauge, not a
  histogram: at one sample/hour percentiles add nothing.)
- `yuzu_inventory_catalog_rollup_last_success_timestamp` (gauge, epoch seconds) — the
  primary liveness signal; it is the source of the Software tab's "updated N ago" stamp.
  **Seeded to `0` at startup** so the series always exists (a never-succeeded server is
  still alertable). Alert on `time() - this > 7200` **guarded by `and this > 0`** — the
  `> 0` guard skips the cold-boot "building" window (epoch 0); the never-succeeded /
  ongoing-failure case is caught by `…_rollup_total{outcome="error"}` instead.

**Catalogue rollup grain and KPIs.** The rollup keeps one precomputed row per title x
filter grain x distinct dimension combination, where the grain is which of kind, ecosystem
and source are fixed (eight grains, from "title total" to "one exact combination"); a title
therefore has between 8 and 8 x C rows (C = its count of distinct kind/ecosystem/source
combinations), and every read is one exact lookup, never a sum. The refresh runs in one
`REPEATABLE READ` transaction: one `GROUPING SETS` pass fills every grain (about three sorted
passes of `installed_software`), one further pass computes the exact per-OS-family split, and
the fleet-newest version of every title is folded from `version_rollup` through a server-side
cursor into a transaction-scoped temp table with memory bounded by the batch size, not the
title count. The refresh keeps the 60 s per-statement limit, gains a 10-minute whole-refresh
limit (both compile-time), and aborts cleanly (last-good rollup kept) on shutdown.
Scale ceiling (measured on PostgreSQL 18.6 with synthetic data at about 450 rows per
endpoint, on one M-series host with a warm cache and 4 MB `work_mem`; read it as plus or
minus 40%): the `GROUPING SETS` statement costs about 12.8 times the former single
`GROUP BY` (37 s against 2.9 s at 1.8M installed rows; the whole refresh about 6.5 times)
and reaches the flat 60 s statement limit at about 2.7M installed rows, roughly 6,000
endpoints. A fleet already over that size at the v8 upgrade has no last-good rollup, so its
catalogue stays "building" until the rollup is made incremental; a fleet that outgrows it
later keeps serving the last-good rollup while its "updated N ago" stamp ages. A Windows endpoint
that also reports MSI products adds roughly 120 rows (118 in one capture) to that 450-row basis, about a
quarter more, so a fleet of such endpoints reaches the same limit at about 4,700 endpoints rather than
6,000 (arithmetic from the figures above, not re-measured). The server's
database role needs the `TEMPORARY` privilege (the default `PUBLIC` grant; re-grant it after
a `REVOKE TEMP` hardening), because the refresh uses a transaction-scoped temporary table;
without it every refresh fails with a permission-denied error (SQLSTATE 42501) and the
catalogue stays "building". The [`/crypto` page](crypto.md) does not depend on that: while the catalogue is not fresh (never built, or older than two hours) it reads its package names live from `installed_software` instead (always, on a fleet above about 2.7M rows, until the rollup is incremental). A rollback to an older binary is clean: its grain-less refresh
and read treat every row as a title-grain row (each title once). On an upgrade with older
replicas still running, restart them promptly: the v8 `DROP` queues behind an old replica's
refresh and dies at the pool's 10 s `lock_timeout` (the new server then refuses to start,
fail-closed). A mixed old/new window has three transient asymmetries until each side's next
hourly refresh: an old replica's read lists every grain row the new binary wrote (8 to
8 x C per title), and after an old replica's refresh the new binary's filtered reads are
empty (not "building"), and the KPI numbers stay at their last new-binary values under a
fresh "updated" stamp.

KPI definitions: total installs = distinct (device, title) pairs; the OS split counts each
(device, title) pair once per OS family derived from the ecosystem; stay-current = distinct devices on each title's exact newest
version string divided by distinct devices carrying the title, over every title with a known
version (equivalent spellings such as `1.0` and `1.0.0` are not merged); "newest" is decided
by the catalogue's own transitive version order, which agrees with the NVD comparator on its
documented examples; version sprawl = titles on three or more versions; rpm unsigned = the
unsigned share of rpm installs. After an upgrade the catalogue reads "building" until the
first refresh completes (the rollup tables are derived data and are rebuilt, never migrated).

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
separate "agents offline" from "sync source broken / disabled". Also
correlate with `yuzu_fleet_inventory_sync_skipping{source="installed_software"}`: a
host counted there is online but its collector is skipping (the reason is in that agent's
log, and in its `last_skip` heartbeat tag, which no server page or API returns yet). The two gauges count different populations (stored-receipt age over 48 h in
Postgres vs live heartbeats, which include hosts skipping for less than 48 h and
hosts that have never reported), so read them side by side and never subtract one
from the other. Agents that do not emit the skip tag (older agents, or during a
rollout) are not counted, so a zero there does not rule out a skipping collector.

**A Windows device's software inventory stops updating although the agent is healthy.** Since the #4711 hardening, an Uninstall registry root that cannot be opened or enumerated to the end, or one application subkey whose open fails (access denied above all) or whose name exceeds 255 characters, makes `list_inventory` return rc 1 and the daily sync skips that cycle rather than committing a shorter inventory as authoritative; the device keeps its last good inventory and `last_seen` stops advancing. `list` and `query` return the `error|` row with rc 1 for the same condition. The agent log carries both halves: `installed_apps: Uninstall root <HKLM-64|HKLM-32|HKCU> could not be fully read -- the collection is degraded` and `sync: installed_apps.list_inventory rc=1 — skipping this cycle`. Fix the ACL (the agent runs as LocalSystem) and the next 24 h cycle re-collects. The only fleet-side signal is the indirect `yuzu_inventory_stale_agents{source="installed_software"}` gauge (two missed cycles; its alert `YuzuInventoryStaleAgents` ships disabled and a never-synced device is not counted); there is no direct skip counter yet.

**The Hardware list shows "Hardware roster unavailable" (or `GET /api/v1/hardware` answers `503`).** The persisted device roster could not be read. Check `yuzu_server_agent_presence_store_failed_total{op="query_stale_within"}`: `reason="store_unavailable"` means no database connection could be obtained (the pool wait is 0.5-2 s, plus up to 10 s to connect to an unreachable database; see `/readyz` `pg_reachable` and the Postgres pool alerts: `YuzuPgPoolSaturated` with `pg_reachable` green points at pool saturation), `reason="db_error"` means the query itself failed (detail in the server's `query_stale_within failed` warn line). The audit row is `inventory.devices` with `result=failure` and detail `hardware roster read failed`; the REST `503` message `hardware roster unavailable` tells it apart from the audit-persist `503` (`audit subsystem unavailable`), which shares the same `retry_after_ms`. The CI-record symptoms ("Device roster unreadable", "Device identity unavailable", the record `503`) share the counter but audit as `inventory.device.ci` / `inventory.device.software`. The banner clears on the next successful read; no restart is needed.

**`install_location` is `-` for many Windows applications and every Linux application.** `-` means the OS
reported no location, not that collection failed. Windows reads each Uninstall key's `InstallLocation`, which many
MSI-registered products, SDK and runtime component packages and some system components never populate (182 of
241 rows on one developer workstation); Linux is always `-` by design, since a package installs to many prefixes.
`-` also results from a Windows value longer than 64 KiB or stored with a non-string registry type (applications installed only into a logged-in
user's own hive produce no row at all; see `list_per_user`). `bundle_id` is `-` on Windows
and Linux, and on macOS for a non-bundle location or for a row the bounded bundle-id pass (30 s, at most 5000 applications, one pass in flight) did not reach -- that run also carries a leading `warning|bundle_id_*` row and a CONSTRAINED status, so a `-` from a cut-short pass is never silent.

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
