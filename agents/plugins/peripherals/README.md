# peripherals

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | USB, PCI and Thunderbolt/USB4 device inventory |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.peripherals.usb, crossplatform.peripherals.pci, crossplatform.peripherals.thunderbolt) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `pci` (definition `crossplatform.peripherals.pci`) · `thunderbolt` (definition `crossplatform.peripherals.thunderbolt`) · `usb` (definition `crossplatform.peripherals.usb`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

Three independent bus walks, dispatched by action name (`peripherals_plugin.cpp`): `usb` and `pci` enumerate the platform's device tree for that bus, one row per device; `thunderbolt` is the bus_inventory fold — one row per Thunderbolt/USB4 node, host controller or attached device, from whatever mechanism each OS exposes for that bus (there is no single "Thunderbolt API" the way there is a PCI or USB one). Every leg is a pure device-tree read: no configuration, no authorization-state change, no write of any kind. A leg that finds nothing still emits one `<kind>|none` row rather than silence, and a leg that cannot even attempt the read emits `<kind>|unavailable|<token>` and reports a degraded result status — never a plain empty result standing in for a failure. This plugin is deliberately NOT the source of PCI/USB vendor-ID-to-name lookups (no `pci.ids`/`usb.ids` database is shipped or parsed — vendor/product strings, where present, come straight from the OS), never shells out to a subprocess on any leg, and does not yet cover displays, Bluetooth, audio or camera devices (scoped out at Wave 1 planning, deferred to a later PR).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[peripherals.execute]
  EX --> WIN[Windows leg<br/>SetupAPI SetupDiGetClassDevsW]
  EX --> MAC[macOS leg<br/>IOKit IOServiceMatching]
  EX --> LIN[Linux leg<br/>/sys/bus/{usb,pci,thunderbolt}/devices reads]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `pci` | ✅ supported · rung 1 · SetupAPI (PCI enumerator) | ✅ supported · rung 1 · IOKit IOServiceMatching(IOPCIDevice) | ✅ supported · rung 1 · /sys/bus/pci/devices sysfs attribute reads |
| `thunderbolt` | 🟡 constrained · rung 1 · SetupAPI PCI enumerator, DEVICEDESC contains Thunderbolt/USB4 | ✅ supported · rung 1 · IOKit IOServiceMatching(IOThunderboltSwitch) | 🟡 constrained · rung 1 · /sys/bus/thunderbolt/devices sysfs reads |
| `usb` | ✅ supported · rung 1 · SetupAPI SetupDiGetClassDevsW(USB enumerator) + SPDRP_HARDWAREID/COMPATIBLEIDS | ✅ supported · rung 1 · IOKit IOServiceMatching(IOUSBHostDevice) | ✅ supported · rung 1 · /sys/bus/usb/devices sysfs attribute reads |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`thunderbolt` / Windows** — string-heuristic identification; no Thunderbolt device class in SetupAPI
- **`thunderbolt` / Linux** — walk verified against a sysfs fixture tree only; no live Linux venue with a Thunderbolt bus in this run
<!-- END GENERATED -->

The capability-matrix block above was regenerated on a Linux container by `tools/capmatrix-gen` dlopening the plugin's built binary on each OS (I91-6), and every sample's leg-hash stamp is resolved against it (I91-7) — the plugin's own descriptor (`peripherals_plugin.cpp`'s `kActionDescriptors`) and the generated block above now agree.

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None documented for this plugin (`docs/agent-privilege-model.md`) | 2026-09-08, bare-metal, the-rig, `LocalSystem (elevated)` — P91-7's real MSVC capture (`docs/samples/windows.txt`) | `SetupDiGetClassDevsW` fails, action reports `<kind>\|unavailable\|windows:setupapi:getclassdevs_failed:<GetLastError>` |
| macOS | agent daemon, root today (LaunchDaemon carries no `UserName` key — `docs/agent-privilege-model.md` TL;DR); this plugin's own reads need no elevation beyond that default | None — IOKit registry property reads are unprivileged | 2026-09-08, bare-metal, this Mac (`braga`), unprivileged (uid 501) — real `ioreg`-equivalent captures behind P91-6's fixtures (`tests/unit/fixtures/wave9/peripherals/macos/*.provenance.txt`); no root-privileged run of this plugin has been captured yet, so the root identity above is the documented production default, not a measured one | `IOServiceGetMatchingServices` itself fails (`kr != KERN_SUCCESS`), action reports `<kind>\|unavailable\|macos:iokit:matching_failed`; a query that succeeds but matches zero services is a clean `<kind>\|none`, not a failure |
| Linux | agent daemon, default | None — sysfs bus directories under `/sys/bus/{usb,pci,thunderbolt}/devices` are world-readable by default | 2026-09-14, container (Docker VM on this Mac), root (`euid 0`) — a real live capture (`docs/samples/linux.txt`, I91-6/I91-7), plus the fixture tree at `tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree/` (P91-5/P91-7) for the walk-logic unit tests | The bus directory exists but is unreadable (EACCES) or another listing error occurs, action reports `<kind>\|unavailable\|linux:sysfs:eacces` or `linux:sysfs:read_failed`; an absent bus directory (no such bus on this host) is a clean `<kind>\|none`, not a failure |

Binaries/subprocesses: none — every leg is an in-process native call (SetupAPI, IOKit, or a direct `std::filesystem` sysfs read). Network: none.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per device, written via `write_output()`. Every field beyond the fixed-vocabulary `role` column goes through the shared untrusted-output escaper; a device with no value for a given optional field reports `-` rather than an empty or omitted field. A bus with no devices reports a single `<kind>|none` row; a leg that could not attempt the read at all reports `<kind>|unavailable|<token>` instead of any device rows.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.peripherals.pci` — `bus_path|vendor_id|device_id|class|subsystem_vendor|subsystem_device|driver|description`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `bus_path` | string | - | Windows, Linux, macOS | `0000:00:02.0` | Platform-native PCI bus location (e.g. a SetupAPI device instance path, a sysfs bus path, or an IOKit registry path). |
| `vendor_id` | string | - | Windows, Linux, macOS | `8086` | PCI vendor id, 4 lowercase hex digits. |
| `device_id` | string | - | Windows, Linux, macOS | `9a49` | PCI device id, 4 lowercase hex digits. |
| `class` | string | - | Windows, Linux, macOS | `030000` | PCI class code (base class + subclass + programming interface), 6 lowercase hex digits. |
| `subsystem_vendor` | string | - | Windows, Linux, macOS | `1028` | PCI subsystem vendor id, 4 lowercase hex digits; "0000" where unread. |
| `subsystem_device` | string | - | Windows, Linux, macOS | `0a5c` | PCI subsystem device id, 4 lowercase hex digits; "0000" where unread. |
| `driver` | string | - | Windows, Linux, macOS | `i915` | Bound driver name, where the platform exposes one; "-" otherwise. |
| `description` | string | - | Windows, Linux, macOS | `Intel Iris Xe Graphics` | Human-readable device description, where the platform exposes one; "-" otherwise. |

**`crossplatform.peripherals.thunderbolt` — `path|role|vendor|model|unique_id|generation|authorized`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `path` | string | - | Windows, Linux, macOS | `domain0/0-0` | Platform-native location for this node (e.g. a SetupAPI device instance path, a sysfs bus path, or an IOKit registry path). |
| `role` | string | - | Windows, Linux, macOS | `host_controller` | Reported node role. Values: host_controller, device. |
| `vendor` | string | - | Windows, Linux, macOS | `Apple Inc.` | Vendor string, where the platform exposes one; "-" otherwise. |
| `model` | string | - | Windows, Linux, macOS | `Thunderbolt 4 Pro Dock` | Model/device name string, where the platform exposes one; "-" otherwise. |
| `unique_id` | string | - | Windows, Linux, macOS | `00340000-0044-4123-8000-000103ffffff` | Node-unique identifier, where the platform exposes one; "-" otherwise. |
| `generation` | string | - | Windows, Linux, macOS | `4` | Reported Thunderbolt/USB4 generation, where the platform exposes one (e.g. "4"); "-" otherwise. |
| `authorized` | string | - | Windows, Linux, macOS | `1` | Security-level authorization state, where the platform exposes one. Values: 1 (authorized), 0 (not authorized), - (not exposed by this platform mechanism). |

**`crossplatform.peripherals.usb` — `bus_path|vendor_id|product_id|class|subclass|vendor|product|serial|speed|is_hub`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `bus_path` | string | - | Windows, Linux, macOS | `1-2.1` | Platform-native bus location for this device (e.g. a SetupAPI device instance path, a sysfs bus path, or an IOKit registry path). |
| `vendor_id` | string | - | Windows, Linux, macOS | `046d` | USB vendor id, 4 lowercase hex digits. |
| `product_id` | string | - | Windows, Linux, macOS | `c52b` | USB product id, 4 lowercase hex digits. |
| `class` | string | - | Windows, Linux, macOS | `09` | USB device class code, 2 lowercase hex digits. |
| `subclass` | string | - | Windows, Linux, macOS | `00` | USB device subclass code, 2 lowercase hex digits. |
| `vendor` | string | - | Windows, Linux, macOS | `Logitech` | Vendor string, where the device or platform exposes one; "-" otherwise. |
| `product` | string | - | Windows, Linux, macOS | `USB Receiver` | Product string, where the device or platform exposes one; "-" otherwise. |
| `serial` | string | - | Windows, Linux, macOS | `-` | Device serial number, where exposed; "-" otherwise. |
| `speed` | string | - | Windows, Linux, macOS | `480` | Negotiated link speed, platform-native token (e.g. "480" Mbps); "-" where unread. |
| `is_hub` | boolean | - | Windows, Linux, macOS | `0` | Whether this node is itself a USB hub. Values: 1 (hub), 0 (not a hub) — a digit, never true/false. |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | `FULL` | — | The leg attempted the read and either found devices or found none (`<kind>\|none`) — an empty bus is a complete answer, not a degradation. |
| `CONSTRAINED` | `PARTIAL` | `linux:sysfs:eacces` | Linux: the bus's `devices` directory exists but could not be opened (permission denied). |
| `CONSTRAINED` | `PARTIAL` | `linux:sysfs:read_failed` | Linux: the bus's `devices` directory exists but listing it failed for a reason other than EACCES. |
| `CONSTRAINED` | `PARTIAL` | `macos:iokit:matching_failed` | macOS: `IOServiceGetMatchingServices` itself returned a non-success `kern_return_t` — the IOKit main port was unreachable, not merely "no matches". |
| `CONSTRAINED` | `PARTIAL` | `windows:setupapi:getclassdevs_failed` | Windows: `SetupDiGetClassDevsW` itself failed; the row and status reason carry the literal token with `GetLastError()`'s numeric code appended. |

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. Each of the three actions is also a gathered definition (`crossplatform.peripherals.usb`/`.pci`/`.thunderbolt`, 300s TTL).
- **Not consumed by** daily-sync, TAR, DEX, or metrics.
- **Sensitivity.** Rows carry hardware identifiers (USB/PCI vendor and product ids, serial numbers, Thunderbolt unique ids) that can fingerprint a specific device, and vendor/product strings that name installed peripheral hardware — a software/hardware inventory by another route. No row carries a username or account name.
- **Siblings:** `hardware` (system/BIOS/CPU/memory/disk inventory — this plugin covers the bus-attached device tree `hardware` does not).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-09-08 · LocalSystem (elevated) · leg-hash 25220299bc79

```
== action=usb
usb|USB/VID_046D&PID_C548&MI_03/7&247BA993&0&0003|046d|c548|03|00|(Standard system devices)|USB Input Device|-|-|0
usb|USB/VID_0B05&PID_18F3/9876543210|0b05|18f3|00|00|(Standard USB Host Controller)|USB Composite Device|-|-|0
usb|USB/VID_0B0E&PID_2E56&MI_03/9&3135CDCD&0&0003|0b0e|2e56|03|00|(Standard system devices)|USB Input Device|-|-|0
usb|USB/VID_0B0E&PID_2E56/6CFBEDC4770B|0b0e|2e56|00|00|(Standard USB Host Controller)|USB Composite Device|-|-|0
usb|USB/VID_8087&PID_0029/8&384B90AF&0&6|8087|0029|e0|01|Intel Corporation|Intel(R) Wireless Bluetooth(R)|-|-|0
usb|USB/VID_0B05&PID_18F3&MI_02/A&2EFC6B98&0&0002|0b05|18f3|03|00|(Standard system devices)|USB Input Device|-|-|0
usb|USB/ROOT_HUB30/7&14C6E8AD&0&0|0000|0000|00|00|(Standard USB HUBs)|USB Root Hub (USB 3.0)|-|-|0
usb|USB/VID_174C&PID_3074/8&1B878445&0&8|174c|3074|00|00|(Standard USB HUBs)|Generic SuperSpeed USB Hub|-|-|0
usb|USB/VID_046D&PID_C548&MI_01/9&32226396&0&0001|046d|c548|03|01|(Standard system devices)|USB Input Device|-|-|0
usb|USB/VID_046D&PID_C548&MI_02/9&32226396&0&0002|046d|c548|03|00|(Standard system devices)|USB Input Device|-|-|0
usb|USB/VID_046D&PID_C548&MI_00/7&247BA993&0&0000|046d|c548|03|01|Logitech (x64)|Logitech USB Input Device|-|-|0
usb|USB/VID_0B0E&PID_2E56&MI_00/9&3135CDCD&0&0000|0b0e|2e56|01|01|(Generic USB Audio)|Jabra Link 390|-|-|0
… 12 of 24 rows shown
[result_status] OK / FULL

== action=pci
pci|PCI/VEN_1022&DEV_1444&SUBSYS_00000000&REV_00/3&11583659&0&C4|1022|1444|060000|0000|0000|-|PCI standard host CPU bridge
pci|PCI/VEN_1022&DEV_1486&SUBSYS_88081043&REV_00/4&231A312E&0&0141|1022|1486|108000|0000|0000|-|AMD PSP 11.0 Device
pci|PCI/VEN_8086&DEV_1539&SUBSYS_85F01043&REV_03/6&2AD155D1&0&0028000A|8086|1539|020000|0000|0000|-|Intel(R) I211 Gigabit Network Connection
pci|PCI/VEN_1022&DEV_1441&SUBSYS_00000000&REV_00/3&11583659&0&C1|1022|1441|060000|0000|0000|-|PCI standard host CPU bridge
pci|PCI/VEN_1022&DEV_1485&SUBSYS_88081043&REV_00/6&313998C&0&0040000A|1022|1485|130000|0000|0000|-|AMD PCI
pci|PCI/VEN_1022&DEV_790E&SUBSYS_87C01043&REV_51/3&11583659&0&A3|1022|790e|060100|0000|0000|-|PCI standard ISA bridge
pci|PCI/VEN_1022&DEV_1484&SUBSYS_88081043&REV_00/3&11583659&0&39|1022|1484|060400|0000|0000|-|PCI-to-PCI Bridge
pci|PCI/VEN_1022&DEV_1484&SUBSYS_88081043&REV_00/3&11583659&0&41|1022|1484|060400|0000|0000|-|PCI-to-PCI Bridge
pci|PCI/VEN_1022&DEV_149C&SUBSYS_88081043&REV_00/6&313998C&0&0140000A|1022|149c|0c0330|0000|0000|-|USB xHCI Compliant Host Controller
pci|PCI/VEN_10DE&DEV_228B&SUBSYS_40761458&REV_A1/4&1D81E16&0&0119|10de|228b|040300|0000|0000|-|High Definition Audio Controller
pci|PCI/VEN_1022&DEV_57A3&SUBSYS_88081043&REV_00/5&2BFB86CE&0&08000A|1022|57a3|060400|0000|0000|-|PCI-to-PCI Bridge
pci|PCI/VEN_1022&DEV_1446&SUBSYS_00000000&REV_00/3&11583659&0&C6|1022|1446|060000|0000|0000|-|PCI standard host CPU bridge
… 12 of 48 rows shown
[result_status] OK / FULL

== action=thunderbolt
thunderbolt|none
[result_status] OK / FULL
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-14 · euid 501 · leg-hash 25220299bc79

```
== action=usb
usb|02200000|05ac|800c|09|00|Apple|USB3 Gen2 Hub|7423J07|super+|1
usb|02100000|05ac|800b|09|00|Apple|USB2 Hub|7423J07|high|1
[result_status] OK / FULL

== action=pci
pci|0:0:0(1:128)|106b|1017|060400|0000|0000|ApplePCIECHostBridge|pci-bridge
pci|0:0:0(1:128)|106b|1017|060400|0000|0000|ApplePCIECHostBridge|pci-bridge
pci|0:0:0(1:128)|106b|1017|060400|0000|0000|ApplePCIECHostBridge|pci-bridge
pci|0:0:0(2:2)|106b|100c|060400|0000|0000|ApplePCIEHostBridge|pci-bridge
pci|0:2:0(1:1)|106b|100c|060400|0000|0000|ApplePCIEHostBridge|pci-bridge
pci|1:0:0|14e4|1682|020000|14e4|1682|BCM5701Enet|ethernet
pci|2:0:0|14e4|4434|028000|106b|4388|IOUserService|pci14e4,4434
pci|2:0:1|14e4|5f72|028000|106b|4388|AppleConvergedPCI|pci14e4,5f72
[result_status] OK / FULL

== action=thunderbolt
thunderbolt|0|host_controller|Apple Inc.|iOS|05ac5cb2a9f494b1|-|-
thunderbolt|0|host_controller|Apple Inc.|iOS|05ac5cb2a9f494b0|-|-
thunderbolt|0|host_controller|Apple Inc.|iOS|05ac5cb2a9f494b3|-|-
[result_status] OK / FULL
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-14 · euid 0 · leg-hash 25220299bc79

```
== action=usb
usb|usb1|1d6b|0002|09|00|Linux 7.0.12-linuxkit vhci_hcd|USB/IP Virtual Host Controller|vhci_hcd.0|480|1
usb|usb2|1d6b|0003|09|00|Linux 7.0.12-linuxkit vhci_hcd|USB/IP Virtual Host Controller|vhci_hcd.0|10000|1
[result_status] OK / FULL

== action=pci
pci|0000:00:08.0|1af4|105a|018000|1af4|005a|virtio-pci|-
pci|0000:00:0d.0|1af4|105a|018000|1af4|005a|virtio-pci|-
pci|0000:00:10.0|1af4|1045|058000|1af4|0045|virtio-pci|-
pci|0000:00:01.0|1af4|1041|020000|1af4|0041|virtio-pci|-
pci|0000:00:07.0|1af4|1042|018000|1af4|0042|virtio-pci|-
pci|0000:00:0c.0|1af4|105a|018000|1af4|005a|virtio-pci|-
pci|0000:00:0f.0|1af4|1044|100000|1af4|0044|virtio-pci|-
pci|0000:00:00.0|106b|1a05|060000|0000|0000|-|-
pci|0000:00:06.0|1af4|1042|018000|1af4|0042|virtio-pci|-
pci|0000:00:0b.0|1af4|105a|018000|1af4|005a|virtio-pci|-
pci|0000:00:09.0|1af4|105a|018000|1af4|005a|virtio-pci|-
pci|0000:00:0e.0|1af4|1053|078000|1af4|0053|virtio-pci|-
… 12 of 14 rows shown
[result_status] OK / FULL

== action=thunderbolt
thunderbolt|none
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Windows Thunderbolt identification is a string heuristic, not a device class.** SetupAPI's PCI enumerator exposes no dedicated Thunderbolt/USB4 device class, so the Windows leg matches `DEVICEDESC` containing "Thunderbolt" or "USB4" (case-insensitive) on the PCI walk. It also only ever surfaces the host controller — SetupAPI's PCI enumerator cannot see a downstream Thunderbolt device — so every Windows Thunderbolt row reports role `host_controller`.
2. **Linux Thunderbolt support is fixture-tree-verified only.** The `/sys/bus/thunderbolt/devices` walk has been exercised against a synthetic sysfs fixture tree (`tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree/`); no live Linux host with an actual Thunderbolt bus has run this leg in this project to date.
3. **Linux `pci` never reports a `description`.** Unlike Windows (`DEVICEDESC`) and macOS (`IOName`), no sysfs attribute carries a human-readable PCI device description, so the Linux `pci` action's `description` field is always `-`.
4. **macOS `pci` reports the matched service's child class name as `driver`, not a kext/bundle identifier.** `IORegistryEntryGetChildEntry` in the service plane returns a generic IOKit class name (e.g. `IOPCI2PCIBridge`), which is the closest available proxy to "what's bound to this device" on macOS — it is not the driver bundle identifier a Windows `INF`/driver-key lookup or a Linux `driver` symlink would give.
5. **Windows `pci`'s subsystem vendor/device fields are always `0000`.** SetupAPI's `SPDRP_HARDWAREID` `SUBSYS_` token and a driver-key lookup for the bound driver name are out of Wave-2 scope; both fields report the honest-unfilled `0000`/`-` sentinel rather than a guess (`peripherals_win.cpp`'s `emit_pci_row`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/peripherals/src/peripherals_legs.hpp` · `agents/plugins/peripherals/src/peripherals_linux.cpp` · `agents/plugins/peripherals/src/peripherals_linux_parsers.hpp` · `agents/plugins/peripherals/src/peripherals_macos.cpp` · `agents/plugins/peripherals/src/peripherals_macos_parsers.hpp` · `agents/plugins/peripherals/src/peripherals_parsers.hpp` · `agents/plugins/peripherals/src/peripherals_plugin.cpp` · `agents/plugins/peripherals/src/peripherals_win.cpp` · `agents/plugins/peripherals/src/peripherals_win_parsers.hpp`
- Definitions: `content/definitions/peripherals.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_peripherals.hpp`
- Tests: `tests/unit/test_peripherals_linux_parsers.cpp` · `tests/unit/test_peripherals_local_dispatcher.cpp` · `tests/unit/test_peripherals_macos_parsers.cpp` · `tests/unit/test_peripherals_parsers.cpp` · `tests/unit/test_peripherals_win_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
