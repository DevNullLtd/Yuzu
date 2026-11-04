# hardware

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports hardware inventory: manufacturer, model, BIOS, CPU, memory, disks, drivers, chassis, baseboard, swap, machine id |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (device.hardware.manufacturer, device.hardware.model, device.hardware.bios, device.hardware.processors, device.hardware.memory, device.hardware.disks, device.hardware.drivers, device.hardware.system) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `baseboard` (definition `device.hardware.baseboard`) · `bios` (definition `device.hardware.bios`) · `chassis` (definition `device.hardware.chassis`) · `disks` (definition `device.hardware.disks`) · `drivers` (definition `device.hardware.drivers`) · `drivers_inventory` (definition `device.hardware.drivers_inventory`) · `machine_id` (definition `device.hardware.machine_id`) · `manufacturer` (definition `device.hardware.manufacturer`) · `memory` (definition `device.hardware.memory`) · `model` (definition `device.hardware.model`) · `processors` (definition `device.hardware.processors`) · `swap` (definition `device.hardware.swap`) · `system` (definition `device.hardware.system`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

Thirteen independent actions, dispatched by action name (`hardware_plugin.cpp` `execute()`). `manufacturer`/`model`/`processors`/`system` are single native calls per OS (WMI, `sysctlbyname`/IOKit, or a `/sys`/`/proc` file read) with no subprocess. `bios` and `disks` need data no native API on macOS exposes, so those two legs shell out through the agent's bounded subprocess runner (`run_bounded_subprocess`, fixed deadline, no shell) to `system_profiler` and parse its output with a pure header-only parser (`hardware_macos_bios.hpp`, `hardware_disks_macos.hpp`). `memory` tries `dmidecode` on Linux (also via the bounded runner) and falls back to `/proc/meminfo`'s aggregate total when `dmidecode` is missing or fails. `drivers` enumerates `Win32_PnPSignedDriver` on Windows or reads `/proc/modules` on Linux; it is not implemented on macOS (no public per-driver/kext enumeration API). `drivers_inventory` is its stable-ordered, bounded sibling (the `drivers` action and its rows are unchanged): it adds signer, signed state, INF name and hardware id, sorts every row by (name, INF, hardware id, version), removes exact duplicates, and always leads with one `status|drivers_inventory|<supported|constrained|unsupported>|<tokens or ->` row followed by `driver_inv|<name>|<version>|<date>|<provider>|<class>|<signer>|<signed>|<inf>|<hwid>` rows, `-` standing in for any value that is absent. Windows runs one bounded WMI query on `Win32_PnPSignedDriver` (nine properties, `WHERE DeviceName IS NOT NULL`, a 4096-row cap rather than the 512-row cap the other actions use). Linux reads `/proc/modules` (bounded to 1 MiB, module names validated to `[A-Za-z0-9_-]{1,64}`) and, under one opened `/sys/module` directory descriptor, `<module>/version` and `<module>/taint` with 256-byte no-follow reads; no subprocess runs and no `.ko` file is opened. Ordering, de-duplication, escaping and the status row are one pure header (`hardware_drivers_inventory.hpp`) shared by both legs. The four newest actions (`chassis`, `baseboard`, `swap`, `machine_id`) read nothing yet: each answers with exactly one `status|<action>|unsupported|<os>:planned` row from the shared planned-leg reporter (`agents/shared/planned_leg.hpp`, called from the dispatch in `hardware_plugin.cpp`), until the per-OS leg PRs land the real reads.

Every action that can find nothing still emits one row carrying the literal `unknown` in place of an unread value (`hardware_plugin.cpp:243`, `:257`, `:342-344` and equivalents) — never a silent zero-row output — so a consumer can tell "the probe ran and found nothing" from "this action produced no output for an unrelated reason." This plugin is deliberately not a live-monitoring feed: every action is a point-in-time read with no polling, no event stream, and (except `drivers` and `drivers_inventory`, whose WMI query can take several seconds) no expectation of taking more than a few milliseconds.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[hardware.execute]
  EX --> WIN[Windows leg<br/>WMI Win32_ComputerSystem/BIOS/Processor/PhysicalMemory/DiskDrive/PnPSignedDriver]
  EX --> MAC[macOS leg<br/>sysctlbyname + IOKit; system_profiler via bounded runner for bios/disks]
  EX --> LIN[Linux leg<br/>/sys/class/dmi, /proc/cpuinfo, /proc/modules; dmidecode via bounded runner for memory]
  WIN & MAC & LIN --> ROWS[pipe rows +<br/>typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `baseboard` | 🟡 planned · rung 1 · GetSystemFirmwareTable('RSMB') SMBIOS type 2 via the shared SMBIOS walker | 🟡 planned · rung 1 · no public source on Apple hardware; a later change declares it unsupported | 🟡 planned · rung 1 · /sys/class/dmi/id/board_{vendor,name,serial} + SMBIOS type 2 |
| `bios` | ✅ supported · rung 1 · WMI Win32_BIOS | ✅ supported · rung 2 · run_bounded_subprocess(system_profiler SPHardwareDataType) + native parser (hardware_macos_bios.hpp) | ✅ supported · rung 1 · /sys/class/dmi/id/bios_vendor + bios_version + bios_date |
| `chassis` | 🟡 planned · rung 1 · GetSystemFirmwareTable('RSMB') SMBIOS type 3 via the shared SMBIOS walker | 🟡 planned · rung 1 · no public source on Apple hardware; a later change declares it unsupported | 🟡 planned · rung 1 · /sys/class/dmi/id/chassis_{type,serial,asset_tag} + SMBIOS type 3 |
| `disks` | ✅ supported · rung 1 · WMI Win32_DiskDrive | ✅ supported · rung 2 · run_bounded_subprocess(system_profiler SPStorageDataType SPNVMeDataType SPSerialATADataType -json) + native parser (hardware_disks_macos.hpp) | ✅ supported · rung 1 · /sys/block/*/{size,device/model} native walk |
| `drivers` | ✅ supported · rung 1 · WMI Win32_PnPSignedDriver | ⛔ unsupported | ✅ supported · rung 1 · /proc/modules |
| `drivers_inventory` | ✅ supported · rung 1 · WMI Win32_PnPSignedDriver (DeviceName, DriverVersion, DriverDate, DriverProviderName, DeviceClass, Signer, IsSigned, InfName, HardWareID), bounded | ⛔ unsupported | ✅ supported · rung 1 · /proc/modules + /sys/module/<m>/{version,taint} bounded no-follow reads |
| `machine_id` | 🟡 planned · rung 1 · keyed hash of the registry MachineGuid | 🟡 planned · rung 1 · no public source beyond the hardware UUID `system` already reports; a later change declares it unsupported | 🟡 planned · rung 1 · keyed hash of /etc/machine-id |
| `manufacturer` | ✅ supported · rung 1 · WMI Win32_ComputerSystem.Manufacturer | ✅ supported · rung 1 · sysctlbyname(hw.manufacturer) | ✅ supported · rung 1 · /sys/class/dmi/id/sys_vendor |
| `memory` | ✅ supported · rung 1 · WMI Win32_PhysicalMemory | 🟡 constrained · rung 1 · sysctlbyname(hw.memsize) | 🟡 constrained · rung 2 · run_bounded_subprocess(dmidecode -t memory) |
| `model` | ✅ supported · rung 1 · WMI Win32_ComputerSystem.Model | ✅ supported · rung 1 · sysctlbyname(hw.model) | ✅ supported · rung 1 · /sys/class/dmi/id/product_name |
| `processors` | ✅ supported · rung 1 · WMI Win32_Processor | ✅ supported · rung 1 · sysctlbyname(machdep.cpu.*, hw.*cpu*) | ✅ supported · rung 1 · /proc/cpuinfo |
| `swap` | 🟡 planned · rung 1 · WMI Win32_PageFileUsage | 🟡 planned · rung 1 · sysctlbyname(vm.swapusage) | 🟡 planned · rung 1 · /proc/swaps |
| `system` | ✅ supported · rung 1 · WMI Win32_BIOS.SerialNumber + Win32_ComputerSystemProduct.UUID | ✅ supported · rung 1 · IOServiceGetMatchingService(IOPlatformExpertDevice) + IORegistryEntryCreateCFProperty(kIOPlatformSerialNumberKey/kIOPlatformUUIDKey) | ✅ supported · rung 1 · /sys/class/dmi/id/product_serial + product_uuid |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`baseboard` / Windows** — not read yet: one unsupported status row, windows:planned
- **`baseboard` / macOS** — not read yet: one unsupported status row, macos:planned
- **`baseboard` / Linux** — not read yet: one unsupported status row, linux:planned
- **`chassis` / Windows** — not read yet: one unsupported status row, windows:planned
- **`chassis` / macOS** — not read yet: one unsupported status row, macos:planned
- **`chassis` / Linux** — not read yet: one unsupported status row, linux:planned
- **`drivers_inventory` / macOS** — no public kext/dext enumeration API
- **`drivers_inventory` / Linux** — signed state is derived from the per-module taint flag E only; signer, INF, hardware id and date have no Linux source
- **`machine_id` / Windows** — not read yet: one unsupported status row, windows:planned
- **`machine_id` / macOS** — not read yet: one unsupported status row, macos:planned
- **`machine_id` / Linux** — not read yet: one unsupported status row, linux:planned
- **`memory` / macOS** — aggregate total only, no per-DIMM breakdown (macOS has no public per-DIMM API)
- **`memory` / Linux** — falls back to the aggregate MemTotal from /proc/meminfo (no per-DIMM detail) when dmidecode is unavailable or unprivileged
- **`swap` / Windows** — not read yet: one unsupported status row, windows:planned
- **`swap` / macOS** — not read yet: one unsupported status row, macos:planned
- **`swap` / Linux** — not read yet: one unsupported status row, linux:planned
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None documented for this plugin (`docs/agent-privilege-model.md:96`) | 2026-10-27, bare-metal, `LocalSystem (elevated)` (sample stamp) | WMI query returns `error`, action falls back to its `unknown` sentinel row (`wmi_query`, `hardware_plugin.cpp:216-235`) |
| macOS | agent daemon, default (no extra entitlement) | None (`docs/agent-privilege-model.md:96`) | 2026-10-27, bare-metal, euid 501 (unprivileged, sample stamp) | native call/subprocess fails, action emits `unknown`/sentinel row |
| Linux | agent daemon, default, except `system` needs `cap_dac_read_search` (`docs/agent-privilege-model.md:97`) | `system` reads `/sys/class/dmi/id/product_serial` + `product_uuid` (mode `0400`); the packaged systemd unit grants the agent `CAP_DAC_READ_SEARCH` as an ambient capability (bounding set limited to that one capability, `NoNewPrivileges` kept), and the dev install script sets `cap_dac_read_search+eip` on the binary instead (`hardware_plugin.cpp:365-371`). The agent clears its inheritable and ambient sets at start, so an exec'd child such as `dmidecode` does not inherit the capability (the in-process read is deliberate). Without the capability (opt-out, `--no-setcap`, or a manual launch) both fields read back `unknown`. The unit also keeps a root-made copy of the firmware tables under `/var/lib/yuzu-agent/dmi/`; this plugin does not read it. Not yet tested on systemd 239 (RHEL 8). `memory`'s `dmidecode` branch typically needs root and fails EPERM unprivileged, silently falling through to the `/proc/meminfo` total (`hardware_plugin.cpp:506-509`). | 2026-10-27, vm, euid 0 (sample stamp — root, so the `cap_dac_read_search` gate is not exercised by this capture; WSL VM, no DMI) | file read fails, action emits `unknown` |

The four planned actions (`chassis`, `baseboard`, `swap`, `machine_id`) read nothing on any OS and need no grant.

Binaries/subprocesses: `/usr/sbin/system_profiler` (macOS `bios`, `disks`, via `run_bounded_subprocess`) and `dmidecode` (Linux `memory`, resolved via `probe_tool_path`, also via `run_bounded_subprocess`) — both bounded, no shell. No network access. Windows uses in-process WMI (COM), no child process.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per record via `write_output()`. Scalar actions (`manufacturer`, `model`) emit `key|value`; the rest emit one or more `key|field1|field2|...` rows. A field the underlying probe could not read is the literal string `unknown` rather than an omitted field or an empty row — this applies to every read action's identity/value fields (`manufacturer`, `model`, `bios`, `processors`, `memory`, `disks`, `system`); `processors` rows end in two appended columns (`socket_designation`, `stepping`) and `memory` rows in three (`manufacturer`, `part_number`, `serial`), every one the literal `-` until a leg reads it (a DIMM serial is personal data, classified with the system serial, and is not read in this release). The four planned actions emit one typed status row (`status|<action>|unsupported|<os>:planned`) and nothing else. `drivers` additionally emits `__truncated__` in the name field when the Windows WMI row cap (512, `agents/shared/wmi_bounded.hpp`) is hit (`hardware_plugin.cpp:746-753`).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.hardware.baseboard` — `row_kind|vendor|product|serial|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `baseboard` | Windows, Linux, macOS | `status` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), baseboard (one per record read). |
| `vendor` | string | - | Windows, Linux, macOS | `ASUSTeK COMPUTER INC.` | Baseboard vendor, or "-" when absent. Status rows: the action name. |
| `product` | string | - | Windows, Linux, macOS | `PRIME B450M-A` | Baseboard product name, or "-" when absent. Status rows: the level (unsupported). |
| `serial` | string | - | Windows, Linux, macOS | `-` | Baseboard serial number, or "-" when absent. Status rows: the reason token (<os>:planned). |
| `source` | string | - | Windows, Linux, macOS | `/sys/class/dmi/id` | Where the value was read from, or "-" when absent. Absent on status rows. |

**`device.hardware.bios` — `bios_vendor|bios_version|bios_date`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `bios_vendor` | string | - | Windows, Linux, macOS | `American Megatrends Inc.` | BIOS/firmware vendor name; the fixed literal "Apple" on macOS, or "unknown" when unread. Values: free text, the literal "Apple" (macOS only), or the sentinel "unknown". |
| `bios_version` | string | - | Windows, Linux, macOS | `3801` | BIOS/firmware version string, or "unknown" when unread. Values: free text, or the sentinel "unknown". |
| `bios_date` | string | - | Windows, Linux, macOS | `2021-07-30` | BIOS release date as YYYY-MM-DD on Windows/Linux; the fixed literal "N/A" on macOS (no BIOS date concept); "unknown" when unread. Values: YYYY-MM-DD format, the literal "N/A" (macOS only), or the sentinel "unknown". |

**`device.hardware.chassis` — `row_kind|type|serial|asset_tag|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `chassis` | Windows, Linux, macOS | `status` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), chassis (one per record read). |
| `type` | string | - | Windows, Linux, macOS | `Desktop` | Chassis type (SMBIOS type 3), or "-" when absent. Status rows: the action name. |
| `serial` | string | - | Windows, Linux, macOS | `-` | Chassis serial number, or "-" when absent. Status rows: the level (unsupported). |
| `asset_tag` | string | - | Windows, Linux, macOS | `-` | Chassis asset tag, or "-" when absent. Status rows: the reason token (<os>:planned). |
| `source` | string | - | Windows, Linux, macOS | `/sys/class/dmi/id` | Where the value was read from, or "-" when absent. Absent on status rows. |

**`device.hardware.disks` — `index|model|size_gb|media_type|interface`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `index` | int32 | - | Windows, Linux, macOS | `0` | Enumeration index (Windows Win32_DiskDrive.Index; macOS/Linux assigned during enumeration, not guaranteed stable across runs). Values: integer, 0-based. |
| `model` | string | - | Windows, Linux, macOS | `Samsung SSD 970 EVO Plus 1TB` | Disk model/device string, or "unknown" when nothing was found. Values: free text, or the sentinel "unknown". |
| `size_gb` | int64 | - | Windows, Linux, macOS | `931` | Disk capacity in GB, integer-divided from raw bytes (Windows/macOS) or 512-byte sectors (Linux). |
| `media_type` | string | - | Windows, Linux, macOS | `SSD` | Media classification. Windows matches the WMI MediaType string; macOS treats every NVMe device as SSD and looks up SATA media from SPStorageDataType; Linux reads the removable/rotational sysfs attributes. Values: SSD, HDD, Removable, or the sentinel "unknown". |
| `interface` | string | - | Windows, Linux, macOS | `SCSI` | Bus/interface label. Windows reports the WMI storage-stack InterfaceType (often "SCSI" even for NVMe/SATA disks, not the physical bus); macOS reports "NVMe"/"SATA"; Linux infers a transport from the /sys/block symlink target. Values: SCSI (Windows); NVMe or SATA (macOS); nvme, usb, virtio, mmc, sata, scsi, or unknown (Linux). |

**`device.hardware.drivers` — `index|name|version|date|provider|device_class`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `index` | int32 | - | Windows, Linux | `0` | Enumeration order; on the truncation-marker row (Windows only), carries the reached row count instead of an index. Values: integer, 0-based, or the reached count on a truncation-marker row. |
| `name` | string | - | Windows, Linux | `Realtek Audio Universal Service` | Driver/module display name; "unknown" when nothing was found; the literal "__truncated__" marks a Windows WMI row-cap hit (512 rows, agents/shared/wmi_bounded.hpp). Values: free text, the sentinel "unknown", or the literal "__truncated__". |
| `version` | string | - | Windows | `6.0.9977.1` | Driver version string (Windows only; Linux /proc/modules carries no version, always empty). Values: free text, or empty. |
| `date` | string | - | Windows | `2026-04-14` | Driver release date as YYYY-MM-DD, parsed from the WMI CIM datetime (Windows only; empty if malformed or on Linux). Values: YYYY-MM-DD format, or empty. |
| `provider` | string | - | Windows, Linux | `Realtek Semiconductor Corp.` | Driver publisher (Windows DriverProviderName; the fixed literal "kernel" on Linux). Values: free text, or the literal "kernel". |
| `device_class` | string | - | Windows, Linux | `MEDIA` | Windows DeviceClass (e.g. NET, SYSTEM, MEDIA); the fixed literal "module" on Linux. Values: free text WMI device class, or the literal "module". |

**`device.hardware.drivers_inventory` — `row_kind|name|version|date|provider|device_class|signer|signed|inf|hwid`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `driver_inv` | Windows, Linux | `driver_inv` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), driver_inv (one per driver). |
| `name` | string | - | Windows, Linux | `AMD Audio CoProcessor` | Driver or module name: the Windows DeviceName, or the Linux kernel module name. Status rows: the action name. |
| `version` | string | - | Windows, Linux | `6.0.0.109` | Driver version (Windows DriverVersion; Linux /sys/module/<m>/version), or "-" when the host reports none. Status rows: the level (supported, constrained or unsupported). |
| `date` | string | - | Windows | `2025-03-26` | Driver date as YYYY-MM-DD (Windows only), or "-" when empty or in a form that cannot be read unambiguously. Status rows: the reason tokens, comma-separated, or "-" when there are none. |
| `provider` | string | - | Windows, Linux | `AMD` | Driver publisher (Windows DriverProviderName; the fixed literal "kernel" on Linux), or "-" when empty. |
| `device_class` | string | - | Windows, Linux | `SYSTEM` | Windows DeviceClass (e.g. SYSTEM, NET, MEDIA); the fixed literal "module" on Linux; "-" when empty. |
| `signer` | string | - | Windows | `Microsoft Windows Hardware Compatibility Publisher` | Windows signer of the driver package (Signer), or "-" when empty. No Linux source. |
| `signed` | string | `signed` `unsigned` `-` | Windows, Linux | `signed` | Signature state. Windows: IsSigned True/False. Linux: "unsigned" only when the module taint flags contain E; "-" otherwise, since no flag proves a module signed. Values: signed, unsigned, or "-" when unknown. |
| `inf` | string | - | Windows | `oem18.inf` | Windows INF name (InfName, e.g. oem18.inf), or "-" when empty. No Linux source. |
| `hwid` | string | - | Windows | `PCI/VEN_1022&DEV_15E2&SUBSYS_15E21022&REV_63` | Windows hardware id (HardWareID); a backslash is written as "/" by the row escaper. "-" when empty. No Linux source. |

**`device.hardware.machine_id` — `row_kind|hash_hex|algorithm|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `machine_id` | Windows, Linux, macOS | `status` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), machine_id (one per record read). |
| `hash_hex` | string | - | Windows, Linux, macOS | `-` | Keyed hash of the machine identifier, hex, or "-" when absent. Status rows: the action name. |
| `algorithm` | string | - | Windows, Linux, macOS | `-` | Name of the keyed hash used, or "-" when absent. Status rows: the level (unsupported). |
| `source` | string | - | Windows, Linux, macOS | `/etc/machine-id` | Where the identifier was read from, or "-" when absent. Status rows: the reason token (<os>:planned). |

**`device.hardware.manufacturer` — `manufacturer`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `manufacturer` | string | - | Windows, Linux, macOS | `PCSpecialist` | The system manufacturer string, or "unknown" when the probe could not read one. Values: free text, or the sentinel "unknown". |

**`device.hardware.memory` — `slot|size_mb|type|speed_mhz|manufacturer|part_number|serial`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `slot` | string | - | Windows, Linux | `DIMM_A2` | DIMM locator on Windows/Linux dmidecode, or the fixed literal "total" for an aggregate-only row (macOS always, Linux when dmidecode is unavailable or unprivileged). Values: free text locator, or the literal "total". |
| `size_mb` | int64 | - | Windows, Linux, macOS | `8192` | Module capacity in MB, or the aggregate total in MB on an aggregate-only row. Values: integer. |
| `type` | string | - | Windows, Linux | `DDR4` | Memory type (DDR2/DDR3/DDR4/DDR5); "unknown" on every aggregate-only row (macOS, and the Linux /proc/meminfo fallback carry no type). Values: DDR2, DDR3, DDR4, DDR5, or the sentinel "unknown". |
| `speed_mhz` | int32 | - | Windows, Linux | `3600` | Module speed in MHz; 0 on every aggregate-only row. Values: integer, or 0 on an aggregate-only row. |
| `manufacturer` | string | - | Windows, Linux | `-` | DIMM manufacturer. Always "-" until a leg reads it. Values: "-". |
| `part_number` | string | - | Windows, Linux | `-` | DIMM part number. Always "-" until a leg reads it. Values: "-". |
| `serial` | string | - | Windows, Linux | `-` | DIMM serial number. Always "-" in this release: a per-module serial is personal data, classified with the system serial, and is not read in this release. Values: "-". |

**`device.hardware.model` — `model`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `model` | string | - | Windows, Linux, macOS | `Amd Am4 Gen3` | The system model or product name string, or "unknown" when the probe could not read one. Values: free text, or the sentinel "unknown". |

**`device.hardware.processors` — `index|model|cores|threads|clock_mhz|socket_designation|stepping`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `index` | int32 | - | Windows, Linux, macOS | `0` | Physical socket index (Linux DMI "physical id"; always 0 on macOS; enumeration order on Windows). Values: integer, 0-based. |
| `model` | string | - | Windows, Linux, macOS | `AMD Ryzen 9 5900X 12-Core Processor` | CPU brand/model string, or "unknown" when no CPU rows were found. Values: free text, or the sentinel "unknown". |
| `cores` | int32 | - | Windows, Linux, macOS | `12` | Physical core count for this socket. Values: integer. |
| `threads` | int32 | - | Windows, Linux, macOS | `24` | Logical thread count for this socket. Values: integer. |
| `clock_mhz` | int32 | - | Windows, Linux, macOS | `4200` | Reported/maximum clock speed in MHz; 0 when the OS exposes no frequency (e.g. Apple Silicon has no hw.cpufrequency). Values: integer, or 0 when unreadable. |
| `socket_designation` | string | - | Windows, Linux, macOS | `-` | Socket label (e.g. "CPU 1"). Always "-" until a leg reads it. Values: "-". |
| `stepping` | string | - | Windows, Linux, macOS | `-` | CPU stepping. Always "-" until a leg reads it. Values: "-". |

**`device.hardware.swap` — `row_kind|device|total_mb|used_mb|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `swap` | Windows, Linux, macOS | `status` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), swap (one per record read). |
| `device` | string | - | Windows, Linux, macOS | `/dev/sda3` | Swap device or page-file path, or "-" when absent. Status rows: the action name. |
| `total_mb` | string | - | Windows, Linux, macOS | `8192` | Total size in MB, or "-" when unread. Status rows: the level (unsupported). |
| `used_mb` | string | - | Windows, Linux, macOS | `512` | Used size in MB, or "-" when unread. Status rows: the reason token (<os>:planned). |
| `source` | string | - | Windows, Linux, macOS | `/proc/swaps` | Where the value was read from, or "-" when absent. Absent on status rows. |

**`device.hardware.system` — `serial|system_uuid`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `serial` | string | - | Windows, Linux, macOS | `EXAMPLE0001` | Hardware serial number, or "unknown" when absent (e.g. a VM with no SMBIOS serial) or unreadable. Values: free text, or the sentinel "unknown". |
| `system_uuid` | string | - | Windows, Linux, macOS | `00000000-0000-0000-0000-000000000001` | SMBIOS/firmware system UUID, or "unknown" when absent or unreadable. Values: free text UUID, or the sentinel "unknown". |
<!-- END GENERATED -->

### Result status

The four planned actions set a typed result status: `UNAVAILABLE` / `UNKNOWN`, provenance `<os>:planned` (`windows:planned`, `linux:planned` or `macos:planned`), one unsupported status row. `drivers_inventory` also sets one, matching its leading status row:

| Status row level | Typed status | When | Reason tokens (status row field 4, comma-joined) |
|---|---|---|---|
| `supported` | `OK` / `FULL` | the read completed | `-` |
| `constrained` | `CONSTRAINED` / `PARTIAL` | the read was cut short or partly refused; the rows that were read are still emitted | `linux:drivers_inventory:row_cap`, `windows:drivers_inventory:row_cap` (4096 rows reached), `linux:drivers_inventory:permission_denied` (EACCES/EPERM on `/proc/modules` or a `/sys/module` file), `linux:drivers_inventory:read_failed` (any other failed read, including a symlinked attribute), `linux:drivers_inventory:invalid_module_name` (a module name outside the kernel alphabet was skipped), `linux:drivers_inventory:proc_modules_oversized`, `windows:drivers_inventory:<wmi error token>` (the query failed; no rows) |
| `unsupported` | `UNAVAILABLE` / `PARTIAL` | macOS | `macos:no_enumeration_api` |

The provenance of a constrained result is the same token list. Every other action leaves the status undeclared; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /` for them on every OS.

### Where the data goes

- **Instruction result, plus a daily-sync consumer for eleven of the thirteen actions.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. The `device_ci` daily-sync source (ADR-0016) additionally invokes `manufacturer`, `model`, `system`, `bios`, `processors`, `memory`, `disks`, `chassis`, `baseboard`, `machine_id` and `swap` in-process via `LocalDispatcher` and folds their output into its canonical CI record (`agents/core/src/sync_source_device_ci.hpp`), which the server reconstructs field-for-field (`server/core/src/device_ci_ingestion.cpp`). The four newest actions (`chassis`, `baseboard`, `swap`, `machine_id`) are optional sections of that record: each contributes its own status, the planned one included, and a failure in one never stops the report. `drivers` and `drivers_inventory` are not part of the record (`drivers_inventory` is an on-demand question with no gather block). `content/definitions/hardware.yaml:517-518` documents this for the `system` action specifically.
- **Not consumed by** Echo, DEX, or metrics. `manufacturer`/`model`/`bios`/`processors`/`memory`/`disks` gather on a 3600s TTL; `drivers` and `system` on an 86400s TTL (`content/definitions/hardware.yaml`); nothing polls continuously.
- **Sensitivity.** `system` rows carry the hardware serial number and SMBIOS/firmware UUID — direct, stable device identifiers; `manufacturer`/`model`/`bios`/`disks` name the specific hardware but not a person; `drivers` and `drivers_inventory` rows name installed driver software (`name`/`provider`, plus `signer`, INF name and hardware id on `drivers_inventory`) — a software inventory by another route. No row carries a username or account name.
- **Siblings:** `device_identity` (domain/OU join state, same Wave 3 native-acquisition migration), `disk_actions` (SMART health and volume-to-drive mapping — `hardware.disks` reports the drive inventory, `disk_actions` reports its health and logical mounts).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.hardware.system")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-11-04 · interactive user (elevated; serial, system UUID, computer-device GUID and peripheral BLE addresses redacted) · leg-hash 93cbaf4434ef

```
== action=manufacturer
manufacturer|Micro Computer (HK) Tech Limited
[result_status] UNDECLARED / UNKNOWN

== action=model
model|EliteMini Series
[result_status] UNDECLARED / UNKNOWN

== action=bios
bios_vendor|American Megatrends International, LLC.
bios_version|1.06
bios_date|2025-11-10
[result_status] UNDECLARED / UNKNOWN

== action=processors
cpu|0|AMD Ryzen 9 PRO 8945HS w/ Radeon 780M Graphics|8|16|4001|-|-
[result_status] UNDECLARED / UNKNOWN

== action=memory
dimm|DIMM 0|32768|DDR5|5600|-|-|-
[result_status] UNDECLARED / UNKNOWN

== action=disks
disk|0|YMTC PC41Q-1TB-B|953|HDD|SCSI
[result_status] UNDECLARED / UNKNOWN

== action=drivers
driver|0|Microsoft iSCSI Initiator|10.0.26100.9711|2006-06-21|Microsoft|SCSIADAPTER
driver|1|Tailscale Tunnel|0.14.0.0|2021-10-13|WireGuard LLC|NET
driver|2|WAN Miniport (Network Monitor)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|3|WAN Miniport (IPv6)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|4|WAN Miniport (IP)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|5|WAN Miniport (PPPOE)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|6|WAN Miniport (PPTP)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|7|WAN Miniport (L2TP)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|8|WAN Miniport (IKEv2)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|9|WAN Miniport (SSTP)|10.0.26100.1|2006-06-21|Microsoft|NET
driver|10|Generic software device|10.0.26100.1|2006-06-21|Microsoft|SOFTWAREDEVICE
driver|11|Hyper-V Virtual Switch Extension Adapter|10.0.26100.1|2006-06-21|Microsoft|NET
… 12 of 178 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=drivers_inventory
status|drivers_inventory|supported|-
driver_inv|ACP HDA Node|-|-|-|-|-|-|-|ACP/DEVTYPE_0001&DEVREV_0000&VEN_1022&DEV_15E2&SUBSYS_102215E2&REV_63
driver_inv|ACPI Power Button|10.0.26100.1150|2006-06-21|Microsoft|SYSTEM|Microsoft Windows|signed|machine.inf|ACPI/VEN_PNP&DEV_0C0C
driver_inv|ACPI Processor Container Device|10.0.26100.1150|2006-06-21|Microsoft|SYSTEM|Microsoft Windows|signed|machine.inf|ACPI/VEN_ACPI&DEV_0010
driver_inv|ACPI Thermal Zone|10.0.26100.1150|2006-06-21|Microsoft|SYSTEM|Microsoft Windows|signed|machine.inf|ACPI/ThermalZone
driver_inv|ACPI x64-based PC|10.0.26100.1|2006-06-21|Microsoft|COMPUTER|Microsoft Windows|signed|hal.inf|acpiapic
driver_inv|AMD Audio CoProcessor|6.0.0.109|2025-03-26|AMD|SYSTEM|Microsoft Windows Hardware Compatibility Publisher|signed|oem18.inf|PCI/VEN_1022&DEV_15E2&SUBSYS_15E21022&REV_63
driver_inv|AMD Controller Emulation|24.20.0.10|2024-03-21|AMD|SYSTEM|Microsoft Windows Hardware Compatibility Publisher|signed|oem5.inf|ROOT/AMDXE
driver_inv|AMD Crash Defender|25.10.0.1|2025-01-27|Advanced Micro Devices, Inc.|SYSTEM|Microsoft Windows Hardware Compatibility Publisher|signed|oem7.inf|ROOT/AMDLOG
driver_inv|AMD GPIO Controller|2.2.0.130|2022-09-15|Advanced Micro Devices, Inc|SYSTEM|Microsoft Windows Hardware Compatibility Publisher|signed|oem0.inf|ACPI/VEN_AMDI&DEV_0030
driver_inv|AMD High Definition Audio Device|10.0.1.40|2025-03-17|Advanced Micro Devices|MEDIA|Microsoft Windows Hardware Compatibility Publisher|signed|oem13.inf|HDAUDIO/FUNC_01&VEN_1002&DEV_AA01&SUBSYS_00AA0100&REV_1008
driver_inv|AMD Micro PEP Device|1.0.42.0|2023-02-10|Advanced Micro Devices, Inc.|SYSTEM|Microsoft Windows Hardware Compatibility Publisher|signed|oem2.inf|ACPI/VEN_AMDI&DEV_0009
… 12 of 138 rows shown
[result_status] OK / FULL

== action=system
serial|1234567890
system_uuid|00000000-0000-0000-0000-000000000002
[result_status] UNDECLARED / UNKNOWN

== action=chassis
status|chassis|unsupported|windows:planned
[result_status] UNAVAILABLE / UNKNOWN / windows:planned

== action=baseboard
status|baseboard|unsupported|windows:planned
[result_status] UNAVAILABLE / UNKNOWN / windows:planned

== action=swap
status|swap|unsupported|windows:planned
[result_status] UNAVAILABLE / UNKNOWN / windows:planned

== action=machine_id
status|machine_id|unsupported|windows:planned
[result_status] UNAVAILABLE / UNKNOWN / windows:planned
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-10-27 · euid 501 · leg-hash 93cbaf4434ef

```
== action=manufacturer
manufacturer|Apple Inc.
[result_status] UNDECLARED / UNKNOWN

== action=model
model|Mac16,10
[result_status] UNDECLARED / UNKNOWN

== action=bios
bios_vendor|Apple
bios_version|18000.161.10
bios_date|N/A
[result_status] UNDECLARED / UNKNOWN

== action=processors
cpu|0|Apple M4|10|10|0|-|-
[result_status] UNDECLARED / UNKNOWN

== action=memory
dimm|total|32768|unknown|0|-|-|-
[result_status] UNDECLARED / UNKNOWN

== action=disks
disk|0|APPLE SSD AP0512Z|465|SSD|NVMe
[result_status] UNDECLARED / UNKNOWN

== action=drivers
driver|0|unknown||||
[result_status] UNDECLARED / UNKNOWN

== action=system
serial|EXAMPLE0001
system_uuid|00000000-0000-0000-0000-000000000001
[result_status] UNDECLARED / UNKNOWN

== action=chassis
status|chassis|unsupported|macos:planned
[result_status] UNAVAILABLE / UNKNOWN / macos:planned

== action=baseboard
status|baseboard|unsupported|macos:planned
[result_status] UNAVAILABLE / UNKNOWN / macos:planned

== action=swap
status|swap|unsupported|macos:planned
[result_status] UNAVAILABLE / UNKNOWN / macos:planned

== action=machine_id
status|machine_id|unsupported|macos:planned
[result_status] UNAVAILABLE / UNKNOWN / macos:planned

== action=drivers_inventory
status|drivers_inventory|unsupported|macos:no_enumeration_api
[result_status] UNAVAILABLE / PARTIAL / macos:no_enumeration_api
```

**Linux** — captured: linux Ubuntu 26.04.1 LTS x86_64 · vm · 2026-11-04 · euid 0 · leg-hash 93cbaf4434ef

```
== action=manufacturer
manufacturer|unknown
[result_status] UNDECLARED / UNKNOWN

== action=model
model|unknown
[result_status] UNDECLARED / UNKNOWN

== action=bios
bios_vendor|unknown
bios_version|unknown
bios_date|unknown
[result_status] UNDECLARED / UNKNOWN

== action=processors
cpu|0|AMD Ryzen 9 PRO 8945HS w/ Radeon 780M Graphics|8|16|3993|-|-
[result_status] UNDECLARED / UNKNOWN

== action=memory
dimm|total|15993|unknown|0|-|-|-
[result_status] UNDECLARED / UNKNOWN

== action=disks
disk|0|Virtual Disk|1024|HDD|unknown
disk|1|Virtual Disk|0|HDD|unknown
disk|2|Virtual Disk|8|HDD|unknown
disk|3|Virtual Disk|0|HDD|unknown
[result_status] UNDECLARED / UNKNOWN

== action=drivers
driver|0|xt_nat|||kernel|module
driver|1|nf_conntrack_netlink|||kernel|module
driver|2|xt_conntrack|||kernel|module
driver|3|xt_MASQUERADE|||kernel|module
driver|4|xfrm_user|||kernel|module
driver|5|xfrm_algo|||kernel|module
driver|6|xt_set|||kernel|module
driver|7|ip_set|||kernel|module
driver|8|xt_addrtype|||kernel|module
driver|9|nft_compat|||kernel|module
driver|10|sch_fq_codel|||kernel|module
driver|11|autofs4|||kernel|module
… 12 of 18 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=system
serial|unknown
system_uuid|unknown
[result_status] UNDECLARED / UNKNOWN

== action=chassis
status|chassis|unsupported|linux:planned
[result_status] UNAVAILABLE / UNKNOWN / linux:planned

== action=baseboard
status|baseboard|unsupported|linux:planned
[result_status] UNAVAILABLE / UNKNOWN / linux:planned

== action=swap
status|swap|unsupported|linux:planned
[result_status] UNAVAILABLE / UNKNOWN / linux:planned

== action=machine_id
status|machine_id|unsupported|linux:planned
[result_status] UNAVAILABLE / UNKNOWN / linux:planned

== action=drivers_inventory
status|drivers_inventory|supported|-
driver_inv|autofs4|-|-|kernel|module|-|-|-|-
driver_inv|br_netfilter|-|-|kernel|module|-|-|-|-
driver_inv|bridge|2.3|-|kernel|module|-|-|-|-
driver_inv|ip_set|-|-|kernel|module|-|-|-|-
driver_inv|ip_tables|-|-|kernel|module|-|-|-|-
driver_inv|llc|-|-|kernel|module|-|-|-|-
driver_inv|nf_conntrack_netlink|-|-|kernel|module|-|-|-|-
driver_inv|nft_compat|-|-|kernel|module|-|-|-|-
driver_inv|sch_fq_codel|-|-|kernel|module|-|-|-|-
driver_inv|stp|-|-|kernel|module|-|-|-|-
driver_inv|tun|-|-|kernel|module|-|-|-|-
… 12 of 19 rows shown
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The eight read actions never set a typed result status.** Every such sample line reads `UNDECLARED / UNKNOWN /` regardless of whether the underlying probe succeeded, partially failed, or hit an unsupported leg (e.g. Linux `manufacturer`/`model`/`bios`/`system` all read `unknown` in the sample, and get the same `UNDECLARED` status as a clean Windows read). A consumer must inspect the row content (`unknown` fields, the `drivers` action's `__truncated__` marker), not the status, to tell success from degradation.
2. **Two legs are partial: `drivers` on macOS, `memory` on Linux and macOS.** `drivers` is not implemented on macOS. No public per-driver/kext enumeration API exists; the descriptor declares it `YUZU_SUPPORT_UNSUPPORTED` (`hardware_plugin.cpp:858`) and the macOS sample shows the house `unknown` row rather than a capture. `memory` is aggregate-only on Linux and macOS. Linux needs `dmidecode` (typically root) for per-DIMM detail and falls back to `/proc/meminfo`'s total when unavailable or unprivileged; the Linux sample (captured as root/euid 0 in a container) still shows the aggregate `total` row, meaning `dmidecode` itself found nothing usable in that environment even with root. macOS has no public per-DIMM API at all and always reports the aggregate. Separately: On macOS there is no public source for `chassis`, `baseboard` or `machine_id` (the hardware UUID from `system` already identifies the machine), yet all four new actions are advertised `planned` on every OS. The per-OS leg PRs move such legs to a typed `unsupported` with a reason; until then a consumer must read `<os>:planned` as "not read", never as "this host has no value". The appended `cpu`/`dimm` columns are likewise always `-`: `socket_designation`, `stepping`, `manufacturer`, `part_number` and `serial` ride on every `cpu`/`dimm` row so downstream schemas are final, but no leg fills them yet.
3. **A connected-but-empty WMI query now emits an explicit `unknown` row instead of silently emitting nothing** — a deliberate divergence from the plugin's pre-#3404 behavior, made so a consumer can distinguish "the probe ran and found nothing" from an unrelated dispatch failure (`hardware_plugin.cpp:190-205`). Do not revert this to match the old silent-gap behavior.
4. **Windows `disks.interface` reports the WMI-layer bus (`SCSI`), not the physical bus** — both drives in the Windows sample are NVMe/SATA but report `SCSI`, because `Win32_DiskDrive.InterfaceType` reports the storage stack layer WMI actually asks, not the physical connector. `disk_actions.smart` decodes the true bus (`nvme`/`sata`/`usb`) via a lower-level IOCTL and is the more accurate source when that distinction matters.
5. **`drivers_inventory` on Linux derives its signed state from one flag, and only toward "unsigned".** `/sys/module/<module>/taint` holds the module's taint letters; `E` (an unsigned module was loaded) maps to `unsigned`. A module without `E` reads `-`, never `signed`: the kernel may not enforce signatures at all, so the absence of the flag proves nothing. Signer, INF name, hardware id and date have no Linux source and are always `-`; provider and class are the fixed literals `kernel` and `module`, as in `drivers`. A built-in module has no `version` file and reads `-`. A module unloaded between the `/proc/modules` read and its `/sys/module` read also reads `-` (a normal race, not recorded as a failure); a refused or failed `/sys` read is recorded as a status token. Windows: Hitting the cap sets `windows:drivers_inventory:row_cap` and a `constrained` status (the rows read are still emitted). Many `Win32_PnPSignedDriver` rows carry only a hardware id (a device with no driver bound, for example `ACP HDA Node` on the capture host): every other field of those rows is `-`. `DriverDate` is accepted only as a CIM datetime or an ISO date; the locale-formatted text a PowerShell session prints (`21/06/2006 01:00:00`) cannot be read unambiguously and gives `-`. The row escaper folds a backslash to `/`, so a hardware id is written `ACPI/VEN_PNP&DEV_0C0C`. The Windows leg is verified here only by reading and by the pure header's tests; the WMI call itself runs on a Windows host.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/hardware/src/hardware_disks_macos.hpp` · `agents/plugins/hardware/src/hardware_drivers_inventory.hpp` · `agents/plugins/hardware/src/hardware_estate_legs.hpp` · `agents/plugins/hardware/src/hardware_linux_parsers.hpp` · `agents/plugins/hardware/src/hardware_macos_bios.hpp` · `agents/plugins/hardware/src/hardware_plugin.cpp`
- Definitions: `content/definitions/hardware.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: `tests/test_hardware_definition.py` · `tests/unit/server/test_hardware_list_model.cpp` · `tests/unit/server/test_hardware_routes.cpp` · `tests/unit/server/test_hardware_sync_routes.cpp` · `tests/unit/server/test_hardware_ui.cpp` · `tests/unit/test_hardware_device_identity_posix_actions.cpp` · `tests/unit/test_hardware_disks_macos.cpp` · `tests/unit/test_hardware_drivers_inventory.cpp` · `tests/unit/test_hardware_linux_parsers.cpp` · `tests/unit/test_hardware_local_dispatcher.cpp` · `tests/unit/test_hardware_macos_bios.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
