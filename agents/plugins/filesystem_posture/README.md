# filesystem_posture

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports mounted filesystems, per-mount quota-subsystem state, and snapshot-capable volumes |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.storage.mounts, crossplatform.storage.quotas, crossplatform.storage.snapshots) |
| **Platforms** | Windows 🟡 constrained · macOS ✅ · Linux 🟡 constrained |
| **Actions** | `mounts` (definition `crossplatform.storage.mounts`) · `quotas` (definition `crossplatform.storage.quotas`) · `snapshots` (definition `crossplatform.storage.snapshots`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

All three actions are reads; none can change host state. `mounts` lists the mounted volumes with device, filesystem type, mount options, capacity and a fixed flags vocabulary. `quotas` walks the same volumes and reports only whether the volume's quota subsystem is switched on and, where the OS exposes one, the volume's default limit; it is deliberately not a per-user or per-group quota inventory on any OS. `snapshots` reports what each OS can actually enumerate: real VSS shadow copies on Windows and real APFS snapshots on macOS, but on Linux only the identity of snapshot-capable volumes (a mounted btrfs subvolume, or a device-mapper source that may or may not be a snapshot volume). It is not a Linux snapshot inventory, because that needs privileged calls this read-only plugin never makes.

On Linux all three actions read `/proc/self/mountinfo`, each action reading it afresh (up to 4 MiB and 4,096 entries); `mounts` adds `statvfs` for capacity and `quotas` adds a `quotactl` probe per block-device mount. On macOS the list comes from `getmntinfo`, quota state from `getattrlist` and snapshots from `fs_snapshot_list`. On Windows the volume list comes from `FindFirstVolumeW`, quota state from `IDiskQuotaControl` and snapshots from the VSS COM interface. A read that is refused or degraded is reported through a typed result status and, where a row exists, a row state, never folded into a clean-looking row set.

```mermaid
flowchart LR
  OP["Operator or workflow"] -->|"authz: Inventory Read"| SRV["Server"]
  SRV -->|"gRPC mTLS"| HOST["Agent plugin host"]
  HOST --> EX["filesystem_posture execute"]
  EX --> WIN["Windows: FindFirstVolumeW and GetDiskFreeSpaceExW, IDiskQuotaControl, VSS Query"]
  EX --> MAC["macOS: getmntinfo, getattrlist volume quota, fs_snapshot_list"]
  EX --> LIN["Linux: mountinfo and statvfs, quotactl Q_GETFMT, mountinfo btrfs and dm detection"]
  WIN --> ROWS["pipe rows and typed result status"]
  MAC --> ROWS
  LIN --> ROWS
  ROWS -->|"CommandResponse"| RS[("ResponseStore")] --> API["REST /api/responses"]
```

### What you can decide with it

| Question | Action | Windows | macOS | Linux |
|---|---|---|---|---|
| What is mounted and how full is it? | `mounts` | Local volumes, one row per mount path; a volume with no mount path is listed under its volume GUID path. Mapped network drives are not listed. No option string (reads `-`). | Every mount from the kernel's cached list, including system volumes. No option string (reads `-`). | Every line of the agent's own mount table. Capacity is `-` for network filesystems. |
| Is a volume writable, or mounted with restrictive flags? | `mounts` `flags` | `ro`/`rw`, plus `removable`, `remote` or `cdrom` | `ro`/`rw`, `nosuid`, `nodev`, `noexec`, `noatime` | `ro`/`rw`, `nosuid`, `nodev`, `noexec`, `noatime`, `relatime` |
| Is a disk quota switched on for a volume? | `quotas` | NTFS volumes with a drive letter: `not_enabled` or `configured` with the default limit and threshold. Tracking-only and enforcing are not told apart. | APFS and HFS+ volumes: `none` (no volume quota set) or `configured` with quota and reserved size. | Block-device mounts: `configured` only means a user-quota format is enabled; group and project quotas are not probed. |
| Does a volume have point-in-time copies? | `snapshots` | Every VSS shadow copy on the machine: id and device path, no size or content. Needs Administrator rights. | Every APFS snapshot by name, per mount point. | Only that a btrfs subvolume or device-mapper volume exists. It does not say a snapshot exists. |

What it cannot tell you: who is over quota (no per-user data anywhere), how large a snapshot is, whether a Linux host has any snapshot at all, or the state of a non-NTFS Windows volume or non-APFS/HFS+ macOS volume (reported `unsupported_fs`). A `none` row in `snapshots` is a sentinel, not a count: its detail says whether nothing was found or the read failed. A `CONSTRAINED` or `PERMISSION_DENIED` result means rows may be missing or marked unavailable; check the row `state` and `detail` before treating the host as quota-free or snapshot-free.

### Diagrams

```mermaid
sequenceDiagram
  participant D as Dispatch pool worker
  participant C as COM and VSS
  participant S as Volume Shadow Copy service
  D->>C: initialise COM (MTA)
  D->>C: CreateVssBackupComponents
  C-->>D: E_ACCESSDENIED unless Administrator or SYSTEM
  D->>C: InitializeForBackup
  D->>C: SetContext VSS_CTX_ALL
  D->>C: Query for snapshot objects
  C->>S: cross-process call, no timeout
  loop up to 1024 turns
    D->>C: Next one object
    C->>S: cross-process call, no timeout
    S-->>D: snapshot id, volume, device path
  end
  Note over D,S: a wedged service or backup provider holds this worker indefinitely
  D-->>D: rows, or one none row plus a degraded status
```

The Windows `snapshots` action makes a chain of synchronous cross-process COM calls on one shared agent worker. Each call has no deadline, so a hung Volume Shadow Copy service or third-party backup provider keeps that worker occupied, and a repeating schedule can occupy more of them. The walk itself is capped at 1,024 turns, and any failure is reported distinctly from a genuinely empty set.

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `mounts` | 🟡 constrained · rung 1 · FindFirstVolumeW + GetVolumeInformationW + GetDriveTypeW + GetDiskFreeSpaceExW | ✅ supported · rung 1 · getmntinfo(3) MNT_NOWAIT | 🟡 constrained · rung 1 · /proc/self/mountinfo + statvfs(3) |
| `quotas` | 🟡 constrained · rung 1 · IDiskQuotaControl (dskquota.h) | 🟡 constrained · rung 1 · getattrlist(2) ATTR_VOL_QUOTA_SIZE/ATTR_VOL_RESERVED_SIZE | 🟡 constrained · rung 1 · quotactl(2) Q_GETFMT |
| `snapshots` | 🟡 constrained · rung 1 · IVssBackupComponents::Query (VSS) | ✅ supported · rung 1 · fs_snapshot_list(2) | 🟡 constrained · rung 1 · /proc/self/mountinfo btrfs subvol + device-mapper source detection |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`mounts` / Windows** — enumerates local volumes only; a mapped network drive is not a volume and is not listed, and no per-mount option string exists so that column reads '-'
- **`mounts` / Linux** — capacity columns are omitted for network filesystems (nfs/cifs/smb/ceph/afs and network FUSE mounts) because a statvfs against an unreachable server blocks the dispatch worker indefinitely; the mount itself is still listed
- **`quotas` / Windows** — volume quota state and default limit/threshold only, opened read-only; per-user quota entries are not enumerated; a volume that denies the query reports permission_denied; a build whose SDK lacks dskquota.h reports unavailable; compiled and linked on a live Windows host but not asserted against one with quotas configured, so the populated-quota path is unexercised
- **`quotas` / macOS** — volume-level quota and reserved size only; per-user and per-group quotas do not exist on APFS (quotactl returns ENOTSUP on every APFS mount while succeeding on HFS+), so no per-identity rows are reported; a volume the agent may not read reports permission_denied
- **`quotas` / Linux** — reports per-mount quota-subsystem state only; per-user and per-group limits are not enumerated, and a mount whose source is not a block device (overlay, tmpfs, network) reports no_block_device; a walk in which every probed device returns EPERM/EACCES reports permission_denied rather than a generic degradation
- **`snapshots` / Windows** — enumerates VSS shadow copies machine-wide, one row per snapshot, reporting its snapshot ID and shadow-copy device path but no size or per-file content; REQUIRES ADMINISTRATIVE RIGHTS -- the agent runs as LocalSystem today so this succeeds; under an unprivileged service account CreateVssBackupComponents returns E_ACCESSDENIED and the action reports permission_denied rather than an empty snapshot set; any VSS failure is reported distinctly from a genuinely empty set and degrades the result status
- **`snapshots` / macOS** — one row per (mount point, snapshot): an APFS snapshot visible under two mount points of the same volume lineage is reported under each
- **`snapshots` / Linux** — reports snapshot-capable volumes and the mounted btrfs subvolume identity, not a snapshot inventory: a device-mapper source may be dm-crypt, dm-multipath or dm-integrity rather than a snapshot-capable LV, enumerating unmounted btrfs snapshots needs CAP_SYS_ADMIN via BTRFS_IOC_TREE_SEARCH, and telling an LVM snapshot LV from a linear LV needs a device-mapper DM_TABLE_STATUS ioctl -- none of which this read-only plugin performs
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account; LocalSystem today, not yet the intended `NT SERVICE\YuzuAgent` (see `docs/agent-privilege-model.md`) | `mounts`, `quotas`: **none** (`FindFirstVolumeW`, `GetVolumeInformationW`, `GetDiskFreeSpaceExW`; `IDiskQuotaControl` opened read-only). `snapshots`: **Administrative rights** for `CreateVssBackupComponents` and `IVssBackupComponents::Query`; LocalSystem has them, so it succeeds with no extra grant today | 2026-09-03 on a lab host: `NT AUTHORITY\SYSTEM` succeeds (3 shadow copies found); `NT AUTHORITY\LOCAL SERVICE` and `NT AUTHORITY\NETWORK SERVICE` both fail `E_ACCESSDENIED`; `NT SERVICE\YuzuAgent` not measured. Sample capture 2026-09-07 as `SYSTEM`, bare metal | `quotas`: per-volume state `permission_denied` (`E_ACCESSDENIED`); `snapshots`: whole-run `PERMISSION_DENIED` with a `none` row naming the HRESULT, never an empty snapshot set |
| macOS | agent daemon as root; the shipped LaunchDaemon has no `UserName` key (`docs/agent-privilege-model.md`) | None; `getmntinfo`, `getattrlist` and `fs_snapshot_list` are unprivileged reads | 2026-09-07 on bare metal as an interactive non-root user, not the production root daemon | `quotas`: per-volume `permission_denied` (`getattrlist` returning `EPERM`/`EACCES`); `snapshots`: `permission_denied` when opening a volume root fails with `EACCES`/`EPERM` |
| Linux | dedicated unprivileged account (`yuzu`; `docs/agent-privilege-model.md`) | None for `mounts` and `snapshots` (mountinfo read and `statvfs`). `quotas` probes with `quotactl`; the plugin's own diagnostic says that query requires `CAP_SYS_ADMIN`, which was not measured on the unprivileged account | 2026-09-06 in a container as root, so the unprivileged-account answers are not evidenced | `quotas`: `PERMISSION_DENIED` when every probed device returns `EPERM`/`EACCES`; `mounts` and `snapshots` make no privileged call, so a failed read there degrades to `CONSTRAINED` |

No external binaries and no subprocesses. No network access is initiated; the Linux `mounts` action deliberately skips `statvfs` on network filesystem types so that it cannot block on one. The Linux actions read the agent's own mount table, so inside a container or a private mount namespace they describe that view, not the host's.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows. Field 0 is a literal discriminator (`mount`, `quota` or `snapshot`). A byte count that was not read and any inapplicable or unread text field render as the literal `-`, which never means zero. Fields carrying arbitrary OS-supplied text go through the shared `safe_output_field` escaper; fields drawn from a fixed vocabulary (`flags`, the quota `state`, `scope`, `kind`) are emitted verbatim. A `snapshots` run that finds nothing still emits one `kind=none` row rather than zero rows, so an empty result can never be misread as the action not having run; its `detail` says whether nothing was found or the read failed. On Windows a volume with no mount path is keyed by its volume GUID path in `mount_point`, and a quota row for it reads `unavailable` with the detail `volume has no drive letter`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.storage.mounts` — `mount_point|device|fstype|options|total_bytes|free_bytes|available_bytes|flags`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `mount_point` | string | - | Windows, Linux, macOS | `/` | Filesystem path (Linux, macOS) or drive/volume path (Windows) the volume is mounted at. Values: free text. |
| `device` | string | - | Windows, Linux, macOS | `/dev/vda1` | OS-reported mount source or volume identifier backing this mount point. Values: free text. |
| `fstype` | string | - | Windows, Linux, macOS | `ext4` | OS-supplied filesystem type name. Values: free text. |
| `options` | string | - | Linux | `rw,relatime` | Comma-separated mount options as reported by the OS, or "-" when no per-mount option string exists. Values: free text or "-". |
| `total_bytes` | int64 | - | Windows, Linux, macOS | `485473984512` | Raw filesystem capacity in bytes, or "-" when not read (omitted for network filesystems on Linux to avoid a blocking statvfs call). Values: integer or "-". |
| `free_bytes` | int64 | - | Windows, Linux, macOS | `432465076224` | Free space in bytes, or "-" under the same conditions as total_bytes. Values: integer or "-". |
| `available_bytes` | int64 | - | Windows, Linux, macOS | `407729119232` | Space available to an unprivileged caller in bytes, or "-" under the same conditions as total_bytes. Values: integer or "-". |
| `flags` | string | - | Windows, Linux, macOS | `rw,relatime` | Comma-joined mount flags drawn from a fixed vocabulary; any option outside the vocabulary is dropped rather than passed through. Values: ro, rw, nosuid, nodev, noexec, noatime, relatime, removable, remote, cdrom. |

**`crossplatform.storage.quotas` — `mount_point|scope|state|limit_bytes|reserved_bytes|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `mount_point` | string | - | Windows, Linux, macOS | `/` | Filesystem path or volume path the quota state applies to, or "-" on the aggregate Linux no_block_device row. Values: free text or "-". |
| `scope` | string | - | Windows, Linux, macOS | `volume` | Fixed literal identifying the quota scope; this plugin never reports a narrower scope. Values: volume. |
| `state` | string | - | Windows, Linux, macOS | `not_enabled` | Classified quota-subsystem state for this volume. Values: configured, none, not_enabled, unsupported_fs, no_block_device, permission_denied, unavailable. |
| `limit_bytes` | int64 | - | Windows, macOS | `-` | Default quota limit in bytes; only populated when state is configured. Values: integer or "-". |
| `reserved_bytes` | int64 | - | Windows, macOS | `-` | Reserved/threshold size in bytes; only populated when state is configured. Values: integer or "-". |
| `detail` | string | - | Windows, Linux, macOS | `ESRCH` | Free-text reason or errno/HRESULT name explaining the state, or "-" when nothing further applies. Values: free text or "-". |

**`crossplatform.storage.snapshots` — `mount_point|name|kind|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `mount_point` | string | - | Windows, Linux, macOS | `C:/` | Filesystem path or volume path the snapshot (or snapshot-capable volume) belongs to, or "-" on a kind=none sentinel row. Values: free text or "-". |
| `name` | string | - | Windows, Linux, macOS | `{9F2F924B-2DD2-46D5-A779-709B2F6FFB9B}` | Snapshot identifier — a GUID on Windows, an APFS snapshot name on macOS, a btrfs subvolume path/id or device-mapper source on Linux — or "-" on a none row. Values: free text or "-". |
| `kind` | string | - | Windows, Linux, macOS | `vss` | Fixed-vocabulary classification of what this row represents. Values: apfs, btrfs_subvolume, device_mapper, vss, none. |
| `detail` | string | - | Windows, Linux, macOS | `//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy1` | Free-text detail — a device path, an operator-actionable reason on a none row, or "-". Values: free text or "-". |
<!-- END GENERATED -->

### Result status

Surfaced as `plugin_result_status` on the command response. `mark_result_partial` sets `CONSTRAINED`/`PARTIAL`; `mark_result_denied` sets `PERMISSION_DENIED`/`PARTIAL`. `set_result_status` assigns rather than accumulates, so when several degradations occur inside one `execute()` call, the last call's provenance is what the server sees — every degradation still reaches the agent log regardless.

| Status | Completeness | Provenance (examples) | When |
|---|---|---|---|
| `UNDECLARED` (agent-derived `OK`) | — | — | clean read on every action; both captured Unix samples for all three actions, and the Windows `snapshots` sample |
| `CONSTRAINED` | partial | `linux:mountinfo`, `linux:mountinfo:malformed`, `macos:getmntinfo`, `macos:getattrlist`, `macos:fs_snapshot_list`, `windows:volume_enum`, `windows:dskquota`, `windows:vss` | an OS call failed, a malformed/truncated mountinfo, an unrecognized quota state, or a VSS step (`SetContext`, a non-snapshot object) narrowed but did not stop the walk |
| `CONSTRAINED` | partial | `linux:mountinfo:unreadable`, `linux:mountinfo:entry_cap`, `linux:mountinfo:quotas`, `linux:mountinfo:entry_cap:quotas`, `linux:mountinfo:malformed:quotas`, `linux:mountinfo:snapshots`, `linux:mountinfo:entry_cap:snapshots`, `linux:mountinfo:malformed:snapshots`, `linux:statvfs` | Linux, per action: the `/proc/self/mountinfo` read for `mounts` (`:unreadable`/`:entry_cap`) or for `quotas`/`snapshots` (action-suffixed `:quotas`/`:snapshots` variants) failed outright, hit its entry-count cap, or contained a malformed line; or a per-mount `statvfs(3)` call failed (`linux:statvfs`, `mounts` only) |
| `PERMISSION_DENIED` | partial | `linux:quotactl` (every probed device `EPERM`/`EACCES`), `macos:getattrlist`, `macos:fs_snapshot_list` (`EACCES`/`EPERM` on a volume root), `windows:dskquota` (`E_ACCESSDENIED`), `windows:vss` (`E_ACCESSDENIED`) | a privilege denial specifically, reported distinctly from every other degradation so a status-keyed consumer can tell "not allowed to read this" from a generic failure |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}` and aggregatable (`mounts` groups by `fstype`, `quotas` by `state`, `snapshots` by `kind`). The three definitions are gathered, with response TTLs of 60 s (`mounts`), 300 s (`quotas`) and 300 s (`snapshots`).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX (Digital Employee Experience) or metrics; nothing runs on a schedule unless an operator or schedule dispatches the instruction.
- **Sensitivity.** Rows carry filesystem and volume metadata only: mount points, device and volume paths (`/dev/vda1`, a Windows volume GUID), capacity figures, quota state and snapshot names or GUIDs. A mount point or volume path can embed text a person chose, such as an external drive's label under `/Volumes` or a user directory used as an automount target, but no hostname, MAC address or account name is emitted as its own column.
- **Siblings:** `crossplatform.storage.smart` and `crossplatform.storage.volumes` (`disk_actions`: physical drive health and the drive-to-volume join) and `crossplatform.storage.free` (`disk_space`).
- **MCP / REST.** Discover: `discover_plugins` (summary), `yuzu://plugin-docs` (this page as data), `discover_instructions` / `get_definition("crossplatform.storage.mounts")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 6094b93f5b9d

```
== action=mounts
mount|//?/Volume{0a35801e-3f40-4114-a073-3d7ea1dd7664}/|//?/Volume{0a35801e-3f40-4114-a073-3d7ea1dd7664}/|NTFS|-|524283904|509657088|509657088|rw
mount|C:/|//?/Volume{c9a5f911-4689-41b2-b774-5b0e25b60e10}/|NTFS|-|248158089216|20788932608|20788932608|rw
mount|//?/Volume{daa59534-884a-4ce4-8fc8-4244f7bbe7ae}/|//?/Volume{daa59534-884a-4ce4-8fc8-4244f7bbe7ae}/|NTFS|-|967831552|63561728|63561728|rw
mount|D:/|//?/Volume{785383ef-b682-41d9-9b28-27c4b8882d65}/|NTFS|-|1000187359232|66670665728|66670665728|rw
mount|//?/Volume{b188886e-39bb-4915-a893-d61a3ca3c707}/|//?/Volume{b188886e-39bb-4915-a893-d61a3ca3c707}/|FAT32|-|268435456|231624704|231624704|rw
[result_status] CONSTRAINED / PARTIAL / windows:volume_enum

== action=quotas
quota|//?/Volume{0a35801e-3f40-4114-a073-3d7ea1dd7664}/|volume|unavailable|-|-|volume has no drive letter
quota|C:/|volume|not_enabled|-|-|-
quota|//?/Volume{daa59534-884a-4ce4-8fc8-4244f7bbe7ae}/|volume|unavailable|-|-|volume has no drive letter
quota|D:/|volume|not_enabled|-|-|-
quota|//?/Volume{b188886e-39bb-4915-a893-d61a3ca3c707}/|volume|unsupported_fs|-|-|-
[result_status] CONSTRAINED / PARTIAL / windows:dskquota

== action=snapshots
snapshot|C:/|{9F2F924B-2DD2-46D5-A779-709B2F6FFB9B}|vss|//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy1
snapshot|C:/|{E6484C8F-1467-4FC8-8577-85677F599D41}|vss|//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy2
snapshot|C:/|{671203BF-A8FA-4ED5-9360-4CBB9B65272E}|vss|//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy3
snapshot|C:/|{21E68FE4-CB60-454D-A893-9420AD8EE750}|vss|//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy4
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 6094b93f5b9d

```
== action=mounts
mount|/|/dev/disk3s1s1|apfs|-|494384795648|313557540864|313557540864|ro
mount|/dev|devfs|devfs|-|201728|0|0|rw
mount|/System/Volumes/VM|/dev/disk3s6|apfs|-|494384795648|313795141632|313795141632|rw,noexec,noatime
mount|/System/Volumes/Preboot|/dev/disk3s2|apfs|-|494384795648|313549758464|313549758464|rw
mount|/System/Volumes/Update|/dev/disk3s4|apfs|-|494384795648|313795141632|313795141632|rw
mount|/System/Volumes/xarts|/dev/disk1s2|apfs|-|524288000|506204160|506204160|rw,noexec,noatime
mount|/System/Volumes/iSCPreboot|/dev/disk1s1|apfs|-|524288000|506204160|506204160|rw
mount|/System/Volumes/Hardware|/dev/disk1s3|apfs|-|524288000|506204160|506204160|rw
mount|/System/Volumes/Data|/dev/disk3s5|apfs|-|494384795648|313557196800|313557196800|rw
mount|/System/Volumes/Data/home|map auto_home|autofs|-|0|0|0|rw
[result_status] UNDECLARED / UNKNOWN

== action=quotas
quota|/|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/dev|volume|unsupported_fs|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/VM|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/Preboot|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/Update|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/xarts|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/iSCPreboot|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/Hardware|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/Data|volume|none|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
quota|/System/Volumes/Data/home|volume|unsupported_fs|-|-|volume-level only; per-user/group quotas are unsupported on APFS (quotactl returns ENOTSUP on every APFS mount, though it succeeds on HFS+)
[result_status] UNDECLARED / UNKNOWN

== action=snapshots
snapshot|/|com.apple.os.update-60587424F5399FC05D957DF05B4D2F65543462495C77AEF520F790FBB57CB212|apfs|-
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 6094b93f5b9d

```
== action=mounts
mount|/|overlay|overlay|rw,relatime|485473984512|432465076224|407729119232|rw,relatime
mount|/proc|proc|proc|rw,nosuid,nodev,noexec,relatime|0|0|0|rw,nosuid,nodev,noexec,relatime
mount|/dev|tmpfs|tmpfs|rw,nosuid|67108864|67108864|67108864|rw,nosuid
mount|/dev/pts|devpts|devpts|rw,nosuid,noexec,relatime|0|0|0|rw,nosuid,noexec,relatime
mount|/sys|sysfs|sysfs|rw,nosuid,nodev,noexec,relatime|0|0|0|rw,nosuid,nodev,noexec,relatime
mount|/sys/fs/cgroup|cgroup|cgroup2|rw,nosuid,nodev,noexec,relatime|0|0|0|rw,nosuid,nodev,noexec,relatime
mount|/dev/mqueue|mqueue|mqueue|rw,nosuid,nodev,noexec,relatime|0|0|0|rw,nosuid,nodev,noexec,relatime
mount|/dev/shm|shm|tmpfs|rw,nosuid,nodev,noexec,relatime|67108864|67108864|67108864|rw,nosuid,nodev,noexec,relatime
mount|/etc/resolv.conf|/dev/vda1|ext4|rw,relatime|485473984512|432465076224|407729119232|rw,relatime
mount|/etc/hostname|/dev/vda1|ext4|rw,relatime|485473984512|432465076224|407729119232|rw,relatime
mount|/etc/hosts|/dev/vda1|ext4|rw,relatime|485473984512|432465076224|407729119232|rw,relatime
[result_status] UNDECLARED / UNKNOWN

== action=quotas
quota|/etc/resolv.conf|volume|not_enabled|-|-|ESRCH
quota|/etc/hostname|volume|not_enabled|-|-|ESRCH
quota|/etc/hosts|volume|not_enabled|-|-|ESRCH
quota|-|volume|no_block_device|-|-|8 non-block-device mounts (overlay/tmpfs/virtual/network) not quota-capable
[result_status] UNDECLARED / UNKNOWN

== action=snapshots
snapshot|-|-|none|no btrfs or device-mapper mount found
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Quotas and Linux snapshots report less than their names suggest.** Quota reporting is volume-level on every OS and never per-identity; on APFS that is structural, because `quotactl` returns `ENOTSUP` on every APFS mount while succeeding on HFS+, and on Linux only the user-quota format is probed. Linux `snapshots` reports capability, not inventory: it cannot list unmounted btrfs snapshots (needs `CAP_SYS_ADMIN` through `BTRFS_IOC_TREE_SEARCH`) or tell an LVM snapshot volume from a dm-crypt, multipath or integrity target (needs a `DM_TABLE_STATUS` ioctl), and this plugin issues neither.
2. **A typical Windows host returns `CONSTRAINED` for `quotas`, and the captured `mounts` run was too.** Every NTFS volume with no drive letter (recovery and similar partitions) gets an `unavailable` quota row, which marks the run `windows:dskquota`; in the captured `mounts` run every row carried a size and filesystem type yet the run was `windows:volume_enum`, because the code treats an empty mount-path list as a failed lookup. Read the per-row state rather than the run status alone.
3. **Windows VSS enumeration has no deadline.** `CreateVssBackupComponents`, `Query` and `Next` are synchronous COM calls with no timeout, run on a bounded agent dispatch-pool worker shared with quarantine and containment dispatch. A wedged VSS service or a hung third-party backup provider parks that worker, so prefer on-demand `snapshots` over a frequent schedule on hosts running third-party backup software.
4. **Linux `mounts` omits capacity for network filesystems.** `nfs`, `nfs3`, `nfs4`, `cifs`, `smb3`, `smbfs`, `afs`, `ceph`, `glusterfs`, `9p`, `virtiofs`, `lustre`, `beegfs`, `gfs2`, `ocfs2`, `gpfs`, `panfs`, `vboxsf`, `vmhgfs`, `prl_fs`, `autofs`, and network-backed `fuse.*` mounts (`sshfs`, `s3fs`, `davfs`, `rclone`, `cephfs`, `ceph-fuse`, `glusterfs`, `nfs`, `smb`, `vmhgfs-fuse`, `prl_fsd`; the list is `agents/shared/network_fstype.hpp`) are still listed, but their capacity columns read `-`, because a `statvfs` against an unreachable server blocks the dispatch worker indefinitely.
5. **`FSCTL_SRV_ENUMERATE_SNAPSHOTS` was rejected as the Windows snapshots mechanism; do not reintroduce it.** No header in SDK 10.0.26100.0 declares it (a direct probe fails `C2065: undeclared identifier`), and an earlier build had silently compiled the real path out behind a guard. It is also the wrong question: an SMB server-side control that lists previous versions a share exposes, not the shadow copies a volume holds.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/filesystem_posture/src/filesystem_posture_legs.hpp` · `agents/plugins/filesystem_posture/src/filesystem_posture_linux.cpp` · `agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp` · `agents/plugins/filesystem_posture/src/filesystem_posture_parsers.hpp` · `agents/plugins/filesystem_posture/src/filesystem_posture_plugin.cpp` · `agents/plugins/filesystem_posture/src/filesystem_posture_win.cpp`
- Definitions: `content/definitions/filesystem_posture.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_filesystem_posture.hpp`
- Tests: `tests/unit/test_filesystem_posture_local_dispatcher.cpp` · `tests/unit/test_filesystem_posture_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
