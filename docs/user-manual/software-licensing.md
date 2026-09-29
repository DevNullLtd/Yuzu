# Software licence detection (SLE)

Yuzu detects each endpoint's **installed software licences** — what is licensed, of
what type and channel, and what has lapsed or expires soon — and syncs the result to
the central server's PostgreSQL database on a **daily** cadence. This is a source of
the agent **daily-sync framework** (ADR-0016), governed by **ADR-0024 (Software
Licensing & Entitlements, "SLE")**, and it powers the `/api/v1/sle/*` REST surface and
its MCP twin. **There is no SLE dashboard page in this release** — this release ships the
read/erase API only; see
[Reading detected licences](#reading-detected-licences) for what is and is not built.

> **Terminology.** This page is about **detected software licences** — third-party
> licence facts observed on the endpoint (Microsoft, Autodesk, JetBrains, …). It is
> **not** about *Yuzu's own product licence* (the `License` securable / entitlement to
> run Yuzu), which is a separate, untouched subsystem. Where both meanings could
> collide, the product always qualifies: "Yuzu licence" vs "detected/software licence".

## What is collected

The `license_scan` plugin probes several **surfaces** per OS and emits one record per
detected licence. Each record carries: **product, vendor, version, `license_type`,
channel, status, `expires_at`, `source`, `confidence`, a redacted `key_hint`,
`exe_hints`** (the product→executable bridge used later for usage matching), and — on
per-user surfaces only — **`user_scope`** and **`user_ref`** (see
[Per-user detection](#per-user-detection-and-privacy) below).

Detection surfaces v1:

| Platform | Surface | Confidence | Yields |
|---|---|---|---|
| Windows | WMI `SoftwareLicensingProduct` (SLP) | authoritative | OS + Office / MS-server licence **status**, **channel** (KMS / MAK / OEM / retail), grace state, evaluation-end date, a **partial** product key (never the full key) |
| Windows | Office **Click-to-Run** registry (`HKLM\…\ClickToRun\Configuration`) | probable | C2R SKU → subscription / volume licence type |
| Windows | Extensible **`ProbeSpec`** table — MS server products (SQL Server, Exchange, Visual Studio), Autodesk (AdskLicensing), security / backup agents (Veeam, Acronis, AV suites), VMware Workstation, WinRAR, open-source classification rows | probable / heuristic | presence, type, serial-derived hints, `exe_hints` |
| Windows | **Per-user surfaces** — loaded `HKU\<SID>` hives first, then offline `NTUSER.DAT`; per-profile licence files (e.g. JetBrains `%LOCALAPPDATA%`, Adobe NGL) | probable | per-user records with `user_scope=user` + `user_ref` |
| Linux | `rpm --qf %{LICENSE}` / dpkg DEP-5 `copyright` header | probable / heuristic | declared SPDX-style licence classification (no lapse detection — stated gap) |
| Linux | RHEL entitlement certificates (`/etc/pki/entitlement/*.pem`, `notAfter`) | authoritative | subscription expiry |
| Linux | FlexLM `.lic` files (`INCREMENT` parser, MATLAB / Ansys class) | authoritative (expiry) | feature expiry dates |
| macOS | `_MASReceipt` presence + `Info.plist` identity; machine-scope vendor plists (Office volume, Parallels) | probable | App Store / retail licensed |

Adding a vendor later is one `ProbeSpec` row (plus an optional interpreter function) —
no engine change.

**Closed vocabularies.** The classifier maps every detection into fixed sets;
anything unrecognised becomes `unknown` (never a fabricated value):

- `license_type`: `perpetual`, `subscription`, `trial`, `volume`, `oem`, `retail`, `open_source`, `freeware`, `unknown`
- `status`: `licensed`, `subscription_active`, `trial`, `grace`, `expired`, `unlicensed`, `unknown`
- `source`: `os_licensing_api`, `entitlement_cert`, `registry_probe`, `license_file`, `package_metadata`, `app_receipt`, `heuristic`
- `confidence`: `authoritative`, `probable`, `heuristic`

A licence is **lapsed** when its effective state is `expired` or `unlicensed`.

## Per-user detection and privacy

Most surfaces are **machine scope**. The per-user surfaces (loaded `HKU\<SID>` hives
and per-profile licence files) are the deliberate exception: they attribute a licence
to a **local profile** and therefore emit two extra fields — `user_scope=user` and
`user_ref`. This is a **contained, maintainer-signed-off deviation** from ADR-0016's
machine-scope / no-PII posture (ADR-0024 Decision 11), confined to these two fields on
this one source.

`user_ref` is a **local profile name only** — never a SID, email, or directory
identity. A single flag controls how it is recorded:

**`--license-scan-user-ref=collect|hash|omit`** (env
`YUZU_AGENT_LICENSE_SCAN_USER_REF`), **default `hash`**:

- **`hash`** (default) — a per-agent keyed pseudonym `HMAC-SHA256(k_agent, profile)`
  truncated to 16 hex. `k_agent` is a 256-bit CSPRNG key persisted locally and
  **never transmitted or logged**. (This is *not* an unsalted `sha256/12`, which a
  low-entropy name like `jsmith` would make trivially reversible.)
- **`collect`** — sends the raw profile name (opt-in).
- **`omit`** — suppresses the **identifier**, not the **probe**: `user_scope` still
  distinguishes a per-user detection, but no `user_ref` is recorded.

If a profile name cannot be resolved, the identifier is **omitted** — a SID (or its
hash) is never substituted.

### Honest limits of the `hash` pseudonym

These limits are stated plainly so a works council or DPO can be shown exactly what the
default does and does not achieve:

> `hash` pseudonyms are **per-device**: the same person on two devices yields two
> unrelated pseudonyms — cross-device user dedup requires `collect`; works-council-grade
> suppression is `omit`, not `hash`. Full per-user-probe suppression today is the
> source-level `inventory_disable` opt-out; a dedicated per-user-probe disable is the
> named future knob if a deployment demands it.

In other words: **`hash` is per-device pseudonymisation, not anonymisation**, and a
hashed `user_ref` **is still personal data** under GDPR (Recital 26). Enabling the
per-user surfaces for an EU workforce should be treated as a works-council
co-determination question; set the mode per that agreement.

## How the sync behaves

- **Daily, per source.** Detected licences sync every ~24 h, phase-spread across the
  fleet (a stable per-agent offset) so agents do not all report at once; a freshly
  enrolled agent does a jittered first sync shortly after connecting.
- **Hash-skip.** The agent canonicalises the detection blob and sends only a small
  content **hash** when nothing has changed; the server asks for the full blob only
  when it cannot match the hash. Expiry countdowns are emitted as an absolute
  UTC-midnight epoch, so a ticking clock alone never defeats hash-skip.
- **Full-replace on change.** When the blob does change, the server replaces the
  device's licence rows in a single transaction — the store is always current-state,
  never an append log.
- **Resilient.** Sync state lives on the agent and survives reconnects and reboots; a
  failed sync retries on the next cycle.

## Reading detected licences

Per **ADR-0024's "Placement under ADR-1005"**, the server hosts the **discovery
mechanism** only. The in-server read/erase surface (gated on the `SoftwareLicensing`
securable — see [Access control](#access-control)):

| Surface | Returns | Scope |
|---|---|---|
| `GET /api/v1/sle/agents/{agent_id}` | one device's discovered licences, **including any `user_ref` rows** | **per-device scoped** (403 outside your management-group scope) |
| `DELETE /api/v1/sle/agents/{agent_id}` | erases a device's stored rows (the audited decommission trigger — see [Erasure](#erasure-and-opt-out)) | **per-device scoped** `SoftwareLicensing:Delete` **and** `Inventory:Delete` **and** `GuaranteedState:Delete` (see below) |
| MCP `query_software_licenses` | one device's discovered-licence **facts** (machine-scope; **no `user_ref`**) | **per-device scoped** `SoftwareLicensing:Read` (the drill's confinement + #1717 fail-closed guard) |

The **single-agent drill** (`GET /sle/agents/{id}`) takes a real per-device scoped gate
and is **audited on every open** (`sle.agent.view`, fail-closed: a non-persistable audit
row returns `503` and serves no licence data), because it can render per-user `user_ref`
rows. Its **MCP twin** (`query_software_licenses`) returns machine-scope facts only — the
per-user `user_ref` personal data is served solely by the audited REST drill. On a store
degradation the drill returns a **`503` degrade**, never a successful empty result — so a
licence query can never read a transient outage as "nothing licensed".

**Evidence-gap signal (`audit_persisted`).** Every read of this data is recorded as an
access-audit row (SOC 2 CC7.2). If that row cannot be persisted, the two surfaces differ,
because only one of them has a header channel:

- **REST drill** — refuses. It returns `503` with `Sec-Audit-Failed: true` and serves **no
  licence data**: the `user_ref` personal data it renders is never disclosed without
  durable evidence of who read it.
- **MCP twin** — serves the data (machine-scope facts, no personal data) but flags the
  gap: the response payload carries **`audit_persisted: false`** (found at
  `result.structuredContent.audit_persisted`, and in the `result.content[0].text` payload).
  The key is **absent** when the audit row persisted normally — so treat *presence of the
  key* as the alarm, not its value. Alert on it: it means a licence read happened with no
  durable trail.

**Compliance, entitlements, usage/reclamation, and the fleet posture reads** (`/sle/summary`,
`/sle/licenses`, the per-product device fan-out, and the compliance MCP tool) **interpret**
discovered facts against purchased rights and are the **SAM use-case-engine module's**
surface — not built in-server. The **SLE page** (the Licences view plus the
compliance / entitlement / reclamation views) lands with that work, not in this release.

## Access control

SLE reads and writes are governed by a new **`SoftwareLicensing`** RBAC securable. Its
seeded description: *gates the `/api/v1/sle/*` detected-licence reads and the
agent-decommission erasure; the `/inventory` software catalog remains under
`Inventory:Read`.* Default per-role grants:

| Role | Grant |
|---|---|
| Viewer | Read |
| PlatformEngineer | Read |
| Operator | Read + Write |
| ITServiceOwner | full CRUD |
| Administrator | full CRUD (global admin pattern) |
| ApiTokenManager | none |

There is **no MFA step-up** anywhere in the SLE surface — nothing here executes on an
endpoint; RBAC Write plus full audit (including denied reads/writes) is the control.
See [Upgrading](upgrading.md) for the on-upgrade auto-grant note (deployments that must
restrict entitlement-cost visibility should deny/remove the Viewer grant **before**
enabling the SLE sources — deny-override wins).

## Erasure and opt-out

- **Turn the source off entirely:** pass **`--inventory-disable`** (or set
  `YUZU_AGENT_INVENTORY_DISABLE`) on the agent — the whole daily-sync thread idles and
  no licence data (or anything else) is collected. Deploy-time opt-out.
- **Suppress the identifier only:** `--license-scan-user-ref=omit` — per-user probing
  continues (so `user_scope` counts stay honest) but no `user_ref` is recorded.
- **Erase an already-collected `user_ref`:** flip the knob to `omit` (or `--inventory-disable`).
  Because each sync **full-replaces** the device's rows, the identifier is purged
  **within one 24 h cycle** for a syncing agent (an offline agent purges on reconnect).
  This knob-flip full-replace is the erasure path available today.
- **Decommission cascade — live via `DELETE /api/v1/sle/agents/{id}`.** This release wires
  the agent-decommission cascade to an audited REST route that clears **all five** of a
  removed device's per-agent stores (inventory, installed-software, device-CI, app-perf
  and detected-licence rows). Because it erases well beyond licences, it is gated on a
  **conjunction over every securable it destroys through** — the caller needs all of
  `SoftwareLicensing:Delete`, `Inventory:Delete` and `GuaranteedState:Delete`, each scoped
  to the device. (Administrator and ITServiceOwner hold all three by default; a custom role
  holding only some of them is refused, so nobody can destroy data they cannot read.) It is
  **audit-before-erase, fail-closed**: it records a durable
  `sle.agent.decommission|attempt` and refuses to erase if that evidence row cannot persist,
  then reports the per-store outcome. Because each store's delete now returns its committed
  status, a store whose delete rolled back is reported `failed` (HTTP 500 — re-issue the
  idempotent DELETE), never a false "decommissioned".
- **Stated gap:** there is **no row-level erasure API** — you cannot delete a single
  `user_ref` row while keeping the device's other rows. The knob-flip full-replace and the
  device-level decommission above are the erasure mechanisms shipped today; a targeted
  per-subject (DSAR) delete is a tracked platform follow-up, not shipped here.

## Agent privilege (per-user hive probing)

The per-user offline-hive probe reads other profiles' `NTUSER.DAT` and rides
**`SeBackupPrivilege` / `SeRestorePrivilege`**, which the agent service account is
**already granted** by `scripts/install-agent-user.ps1` — **no new privilege** is
introduced by this feature. On a hardened install that strips those privileges,
machine-scope surfaces (SLP, C2R, ProbeSpec) still report normally; only the per-user
surface reports `privilege_missing` through the live diagnostics. (The same diagnostic
channel reports `hive_unload_failed` in the exotic case where a probed offline hive
cannot be unmounted afterwards — the probe's rows are still valid, but that profile's
`NTUSER.DAT` stays locked until the mount is unloaded. Most commonly this is a transient
third-party handle (Search Indexer, AV, System Restore) briefly holding the branch,
recoverable without reboot by retrying `reg unload` once that holder releases; a
genuinely stuck holder is the rarer case reboot actually resolves.) The profile walk is
also capped at 512
profiles (#2771; previously unbounded), reported as `profile_list_truncated` through
the same channel if a host has more. Per-user hives are
**never a primary surface**, so none of these three conditions skips or wipes the sync
cycle — the machine-scope detections proceed. See
[`docs/agent-privilege-model.md`](../agent-privilege-model.md) (the `license_scan` row).

## See also

- `docs/adr/0024-software-licensing-entitlements.md` — the design of record.
- [Installed-Software Inventory](inventory.md) — the machine-scope software asset inventory (sibling daily-sync source).
- `docs/agent-privilege-model.md` — the `license_scan` privilege row and degraded-mode behaviour.
- `docs/enterprise-readiness-soc2-first-customer.md` — the Workstream-E data-inventory rows and read-inventory channel for this source.
- `docs/os-capability-matrix.md` — per-OS collection coverage.
