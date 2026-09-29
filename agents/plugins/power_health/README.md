# power_health

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Battery, thermal, and power-plan inventory, plus a gated power-plan switch |
| **Version** | 1.0.0 |
| **Kind** | Action · mutating · gathered (crossplatform.power.battery, crossplatform.power.thermal, crossplatform.power.power_plan, crossplatform.power.set_power_plan) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux 🟡 constrained |
| **Actions** | `battery` (definition `crossplatform.power.battery`) · `power_plan` (definition `crossplatform.power.power_plan`) · `set_power_plan` (definition `crossplatform.power.set_power_plan`) · `thermal` (definition `crossplatform.power.thermal`) |
| **Security** | `battery`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `thermal`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `power_plan`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `set_power_plan`: securable `PowerManagement` · operation Write · risk Medium · dispatch Destructive · approval gate AdminOrApproval |
| **Roles** | execute: `battery`: endpoint-admin, endpoint-operator; `thermal`: endpoint-admin, endpoint-operator; `power_plan`: endpoint-admin, endpoint-operator; `set_power_plan`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`battery` enumerates power sources and classifies each into a closed state set (`charging`/`discharging`/`full`/`not_charging`/`ac_no_battery`/`unknown`) from `GetSystemPowerStatus`+`CallNtPowerInformation` (Windows), `IOPSCopyPowerSourcesInfo`/`IOPSCopyPowerSourcesList` (macOS), or `/sys/class/power_supply` uevent parsing (Linux). `thermal` reads per-zone Celsius on Windows (PDH) and Linux (sysfs), or macOS's 4-level thermal-pressure enum (`NSProcessInfo.thermalState`, never a temperature) supplemented by `IOPMGetThermalWarningLevel`. `power_plan` enumerates named Windows power schemes (PowrProf) and which is active; macOS has no named schemes so it is unsupported, and Linux support is declared but not implemented. `set_power_plan` is the plugin's only mutating action: it resolves the `scheme` parameter to exactly one live scheme, reads the prior active scheme, calls `PowerSetActiveScheme`, then reads back and verifies the switch took — every branch before the set call is guaranteed to leave the system unmutated, and a failure after the set call reports the final state as unknown rather than falsely claiming it is unchanged.

Deliberately not: macOS battery never reads the `AppleSmartBattery` IORegistry node, which is present and active even on battery-less Mac minis and would report a phantom battery; Windows never uses WMI, `powercfg`, or COM for any action; a PDH zero-instance thermal read is reported as an explicit `no_thermal_zones_exposed` success, never an error or a fabricated zero.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read (reads)<br/>PowerManagement.Write (set_power_plan)]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[power_health.execute]
  EX --> WIN[Windows leg<br/>GetSystemPowerStatus/CallNtPowerInformation<br/>PDH · PowrProf]
  EX --> MAC[macOS leg<br/>IOPSCopyPowerSourcesInfo/List<br/>NSProcessInfo.thermalState · IOPMGetThermalWarningLevel]
  EX --> LIN[Linux leg<br/>/sys/class/power_supply<br/>/sys/class/thermal]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `battery` | ✅ supported · rung 1 · GetSystemPowerStatus + CallNtPowerInformation(SystemBatteryState) | ✅ supported · rung 1 · IOPSCopyPowerSourcesInfo/IOPSCopyPowerSourcesList | 🟡 constrained · rung 1 · /sys/class/power_supply uevent parsing |
| `power_plan` | ✅ supported · rung 1 · PowrProf PowerEnumerate + PowerReadFriendlyName + PowerGetActiveScheme | ⛔ unsupported | 🟡 planned · rung 1 · platform_profile |
| `set_power_plan` | ✅ supported · rung 1 · PowrProf PowerSetActiveScheme | ⛔ unsupported | 🟡 planned · rung 1 · platform_profile |
| `thermal` | 🟡 constrained · rung 1 · PDH \\Thermal Zone Information(*)\\Temperature | 🟡 constrained · rung 1 · NSProcessInfo.thermalState + IOPMGetThermalWarningLevel | 🟡 constrained · rung 1 · /sys/class/thermal zone parsing |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`battery` / Windows** — no-system-battery path measured live on the-rig (BatteryFlag=128); the battery-PRESENT path is now verified on real hardware (HP ZBook Firefly, PR #4009 review), which is what caught the AC-resting state being reported as unknown rather than not_charging
- **`battery` / macOS** — IOPS is used deliberately over the AppleSmartBattery IORegistry node, which is present, matched and active even on a battery-less Mac mini and would report a phantom battery; the battery-PRESENT path is fixture-tested and UNVERIFIED on real Mac battery hardware — the run host was a desktop
- **`battery` / Linux** — fixture-verified; no live Linux venue in this run
- **`power_plan` / Windows** — 4 schemes verified live on the-rig, 2026-09-04 (agrees with powercfg /list)
- **`power_plan` / macOS** — macOS has no named power schemes; IOPMSetPMPreferences is SPI — not adopted
- **`power_plan` / Linux** — declared only; not implemented in this package
- **`set_power_plan` / macOS** — macOS has no named power schemes; IOPMSetPMPreferences is SPI — not adopted
- **`set_power_plan` / Linux** — declared only; not implemented in this package
- **`thermal` / Windows** — zero live counter instances is the measured normal case on desktop hardware (the-rig, 2026-09-04); reports no_thermal_zones_exposed as an explicit success, never an error or a fabricated zero
- **`thermal` / macOS** — reports a 4-level thermal-pressure enum, never a temperature reading
- **`thermal` / Linux** — fixture-verified; no live Linux venue in this run
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — `GetSystemPowerStatus`/`CallNtPowerInformation`/PDH/PowrProf calls need no elevated right; `set_power_plan`'s `PowerManagement.Write`/AdminOrApproval requirement is an application-level RBAC/approval gate, not an OS privilege | captured 2026-09-07 as `SYSTEM` (`docs/samples/windows.txt`) | `battery`: result status `UNAVAILABLE`, "GetSystemPowerStatus failed" (`power_health_plugin.cpp:247`); `thermal` failures are typed per-branch but leave result status `UNDECLARED` (see Result status) |
| macOS | agent daemon, dedicated unprivileged account by design (`docs/agent-privilege-model.md:12`) | None — `IOPSCopyPowerSourcesInfo`/`List` and `NSProcessInfo`/`IOPMGetThermalWarningLevel` are public frameworks needing no entitlement | captured 2026-09-07 at euid 501, unprivileged (`docs/samples/macos.txt`) | `battery`: an empty power-source list is reported as a genuine empty result, never a permission error (`power_health_plugin.cpp:274-283`) |
| Linux | dedicated unprivileged account (`yuzu`), never root by design (`docs/agent-privilege-model.md:12`) | None — `/sys/class/power_supply` and `/sys/class/thermal` are normally world-readable | captured 2026-09-06 at euid 0 in a container (`docs/samples/linux.txt`) — a more privileged posture than the intended unprivileged design | `battery`: result status `CONSTRAINED`, "/sys/class/power_supply not readable" (`power_health_plugin.cpp:288`); `thermal`: row reports `unavailable`/`sys_class_thermal_not_readable` but result status stays `UNDECLARED` (`power_health_plugin.cpp:457-463`) |

No external binaries, no subprocesses, no network access — "no WMI, no powercfg or any subprocess, no COM/CoInitialize* anywhere" (`power_health_plugin.cpp:58-59`); no `popen`/`CreateProcess`/socket call appears in any of the plugin's three source files.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `crossplatform.power.set_power_plan` | `scheme` | string | yes | - | - | Target power scheme — a GUID, or a friendly name that must match exactly one live scheme (case-insensitive). |
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows via `write_output()`, one line per record. `thermal`'s field count varies by row (see below); every other action's row has a fixed field count. `-` marks an absent field, never an empty one.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.power.battery` — `present|state|percent|time_to_empty_min|cycle_count|health_percent`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `present` | boolean | - | Windows, Linux, macOS | `0` | Whether a power source was found by the platform mechanism. Values: 1 (battery present), 0 (none) — a digit, never true/false. |
| `state` | string | - | Windows, Linux, macOS | `ac_no_battery` | Reported battery state. Values: charging, discharging, full, not_charging, ac_no_battery, unknown. |
| `percent` | int64 | - | Windows, Linux, macOS | `-1` | Battery charge percentage. Values: 0-100, or -1 (unknown). |
| `time_to_empty_min` | int64 | - | Windows, Linux, macOS | `-1` | Estimated minutes until empty. Values: non-negative integer, or -1 (unknown). |
| `cycle_count` | int64 | - | Linux | `-1` | Battery charge-cycle count. Neither GetSystemPowerStatus/ CallNtPowerInformation (Windows) nor IOPSKeys.h (macOS) expose a cycle counter, so this is structurally -1 on those two platforms; only the Linux leg has a real source (POWER_SUPPLY_CYCLE_COUNT). Values: non-negative integer, or -1 (unknown / not exposed by the platform mechanism). |
| `health_percent` | int64 | - | Linux | `-1` | Battery health as current-full-charge/design-capacity, derived only when the Linux kernel driver exposes both CHARGE_FULL and CHARGE_FULL_DESIGN. Windows and macOS have no equivalent source and are structurally -1. Values: 0-100, or -1 (unknown / not exposed by the platform mechanism). |

**`crossplatform.power.power_plan` — `guid|friendly_name|active|status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `guid` | string | - | Windows | `381b4222-f694-41f0-9685-ff5bb260df2e` | Power scheme GUID, or "-" when no scheme rows were produced. Values: GUID string, or -. |
| `friendly_name` | string | - | Windows | `Balanced` | Operator-visible scheme name (Windows PowerReadFriendlyName; operator-settable via powercfg -changename, so it is untrusted input to the pipe-delimited grammar), or "-". Values: free text, or -. |
| `active` | string | - | Windows, Linux, macOS | `1` | Tri-state: "1" active, "0" not active/inapplicable, "-" only when every scheme WAS enumerated but the active-scheme read itself failed (status=active_unknown). Values: "0", "1", "-". |
| `status` | string | - | Windows, Linux, macOS | `ok` | Row outcome: ok (a real enumerated scheme), timeout, enumeration_incomplete, no_schemes_enumerated, active_unknown, unsupported_on_macos, or planned_not_implemented. Values: ok, timeout, enumeration_incomplete, no_schemes_enumerated, active_unknown, unsupported_on_macos, planned_not_implemented. |

**`crossplatform.power.set_power_plan` — `status|reason|previous_guid|new_guid`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `error` | Mutation outcome. Values: ok, error. |
| `reason` | string | - | Windows, Linux, macOS | `missing_param` | Failure token, or "-" on a success row. missing_param, timeout, enumeration_incomplete, ambiguous, no_match, read_prior_failed, set_failed, readback_failed, and readback_mismatch are Windows failure branches; unsupported_on_macos and planned_not_implemented are the permanent macOS/Linux postures. Values: missing_param, timeout, enumeration_incomplete, ambiguous, no_match, read_prior_failed, set_failed, readback_failed, readback_mismatch, unsupported_on_macos, planned_not_implemented, or -. |
| `previous_guid` | string | - | Windows | `-` | The scheme GUID active before the mutation attempt (read before any mutation runs), or "-" when not reached or not applicable. Values: GUID string, or -. |
| `new_guid` | string | - | Windows | `-` | The scheme GUID observed by the post-set read-back, or "-" when not reached. Values: GUID string, or -. |

**`crossplatform.power.thermal` — `status|zone_or_detail|celsius`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `ok` | Thermal read outcome. constrained is a positive claim of no sensors; unavailable means the read itself failed. Values: ok, constrained, unavailable. |
| `zone_or_detail` | string | - | Windows, Linux, macOS | `nominal` | The zone/sensor name on a Windows or Linux status=ok row, the macOS thermal-pressure level (nominal/fair/serious/critical) on a macOS status=ok row, or a failure/constrained token (no_thermal_zones_exposed, pdh_open_failed, pdh_add_counter_failed, pdh_collect_rejected, pdh_collect_timed_out, pdh_collect_failed, pdh_fetch_failed, pdh_provider_degraded, sys_class_thermal_not_readable) otherwise. Values: free text (zone name), nominal \| fair \| serious \| critical (macOS), or a fixed failure/constrained token. |
| `celsius` | number | - | Windows, Linux | `-` | Sensor temperature in Celsius. Present only on a status=ok row that carries a real per-zone reading (Windows/Linux); the field is omitted entirely (not "-") on every macOS row and on any non-ok row, which is why this column's field count varies by row — see the plugin README's Outputs section. Values: decimal degrees Celsius, or the field is absent. |
<!-- END GENERATED -->

### Result status

`do_thermal` never calls `set_result_status` on any platform or branch — its typed outcome lives only in the row's own `status`/`detail` fields. `do_battery` calls it on exactly one failure path (Windows `GetSystemPowerStatus` failure); every other battery branch, including a clean read and a genuinely-empty result, is also `UNDECLARED`.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNAVAILABLE` | partial | "GetSystemPowerStatus failed" | Windows `battery`: the Win32 call itself failed |
| `CONSTRAINED` | partial | "/sys/class/power_supply not readable" | Linux `battery`: the sysfs directory could not be opened |
| `CONSTRAINED` | partial | "bounded_call timed out enumerating power schemes" / "PowerEnumerate ended on a non-terminal error; inventory is incomplete" / "failed to read the active scheme; active flag is unknown for every row" | Windows `power_plan`: enumeration timeout, incomplete enumeration, or active-scheme read failure |
| `UNAVAILABLE` | partial | "macOS has no named power schemes…" / "power_plan is PLANNED…not implemented" | macOS/Linux `power_plan`: always (no mutation, no enumeration) |
| `UNAVAILABLE` | partial | one of `missing_param`/`timeout`/`enumeration_incomplete`/`ambiguous`/`no_match`/`read_prior_failed`/`set_failed`/`readback_failed`/`readback_mismatch` | Windows `set_power_plan`: every failure branch |
| `UNAVAILABLE` | partial | "macOS has no named power schemes; no mutation attempted" / "…PLANNED on Linux…no mutation attempted" | macOS/Linux `set_power_plan`: always |
| `OK` | full | — | Windows `set_power_plan`: the mutation was applied and the read-back verified it |
| `UNDECLARED` | — | — | `thermal` on every platform and branch; `battery` on every branch except the one Windows failure above (including a clean read on any platform, and Windows `power_plan`'s successful enumeration path) — the agent records `UNDECLARED`/`UNKNOWN`, exactly as every sample below shows |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — a grep of `server/core/src` for `power_health`/`crossplatform.power` finds only the capability-catalogue registration and the `PowerManagement` RBAC securable seed (`server/core/src/rbac_store.cpp:582`, `server/core/src/server.cpp:138,22119`), no sync-source or TAR consumer. `gather.ttlSeconds` (300s reads, 60s `set_power_plan`) is a response-cache TTL, not a scheduled dispatch.
- **Sensitivity.** Rows carry no device, person, or software identifiers — `battery`/`thermal` report only charge/thermal state and percentages, and `power_plan`'s `friendly_name` is a generic, operator-settable scheme label (`Balanced`, `High performance`, `Power saver`), never a serial number, MAC, hostname, or username; nothing here goes beyond the device id.
- **Siblings:** none — this is the fleet's only power-state source.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.power.battery")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 082db96f6e05

```
== action=battery
battery|0|ac_no_battery|-1|-1|-1|-1
[result_status] UNDECLARED / UNKNOWN

== action=thermal
thermal|unavailable|pdh_collect_failed
[result_status] UNDECLARED / UNKNOWN

== action=power_plan
power_plan|381b4222-f694-41f0-9685-ff5bb260df2e|Balanced|1|ok
power_plan|8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c|High performance|0|ok
power_plan|a1841308-3541-4fab-bc81-f71556f20b4a|Power saver|0|ok
power_plan|b1000fa2-4bc5-4da1-b3b1-27c753763a67|AMD Ryzen™ Balanced|0|ok
[result_status] UNDECLARED / UNKNOWN

== action=set_power_plan
set_power_plan|error|missing_param|-|-
[result_status] UNAVAILABLE / PARTIAL / missing required param 'scheme'
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 082db96f6e05

```
== action=battery
battery|0|unknown|-1|-1|-1|-1
[result_status] UNDECLARED / UNKNOWN

== action=thermal
thermal|ok|nominal
[result_status] UNDECLARED / UNKNOWN

== action=power_plan
power_plan|-|-|0|unsupported_on_macos
[result_status] UNAVAILABLE / PARTIAL / macOS has no named power schemes; IOPMSetPMPreferences is SPI, not adopted

== action=set_power_plan
set_power_plan|error|unsupported_on_macos|-|-
[result_status] UNAVAILABLE / PARTIAL / macOS has no named power schemes; no mutation attempted
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 082db96f6e05

```
== action=battery
battery|0|unknown|-1|-1|-1|-1
[result_status] UNDECLARED / UNKNOWN

== action=thermal
thermal|unavailable|sys_class_thermal_not_readable
[result_status] UNDECLARED / UNKNOWN

== action=power_plan
power_plan|-|-|0|planned_not_implemented
[result_status] UNAVAILABLE / PARTIAL / power_plan is PLANNED (platform_profile) — not implemented in this package

== action=set_power_plan
set_power_plan|error|planned_not_implemented|-|-
[result_status] UNAVAILABLE / PARTIAL / power_plan mutation is PLANNED on Linux, not implemented; no mutation attempted
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`battery` and `thermal` never set a typed result status.** `do_thermal` has no `set_result_status` call on any platform (`power_health_plugin.cpp:320-493`), and `do_battery` calls it only on the single Windows `GetSystemPowerStatus`-failure branch (`:247`) — every other battery/thermal branch, clean reads included, stays `UNDECLARED`/`UNKNOWN`, exactly as all three samples above show.
2. **The Windows battery-PRESENT path was fixed only after a real hardware run.** A present battery resting on AC below 100% was originally classified `unknown`; PR #4009's HP ZBook Firefly review caught the firmware charge-hold case and it now reports `not_charging` (`power_health_parsers.hpp:174-181`). The equivalent macOS branch (`:244-252`) is still fixture-only and UNVERIFIED on real battery hardware.
3. **`thermal`'s row shape differs by platform and status.** A non-ok row omits the `celsius` field entirely (`thermal|status|detail`), an ok row with real zones repeats one row per zone (`thermal|ok|name|celsius`), and macOS's ok row is always the 3-field form carrying the pressure level instead of a zone name (`power_health_parsers.hpp:361-375`; macOS sample: `thermal|ok|nominal`) — no sample in this package captures a numeric Celsius value.
4. **`set_power_plan` guarantees no mutation on every pre-set failure, but a post-set failure leaves state genuinely unknown.** `MissingParam`/`Timeout`/`EnumerationIncomplete`/`Ambiguous`/`NoMatch`/`ReadPriorFailed` are all pre-mutation; `SetFailed`/`ReadbackFailed`/`ReadbackMismatch` deliberately do NOT claim "unchanged" because the mutation may already be applied — `previous_guid` is still emitted so the caller can revert manually (`power_health_parsers.hpp:658-681`, `power_health_plugin.cpp:670-705`). It is the first Destructive+Reversible row in the catalogue and is allowlisted by name in `tests/unit/server/test_capability_catalogue.cpp:180`.
5. **Linux `power_plan`/`set_power_plan` are declared, not implemented; macOS is unsupported by design.** Linux is PLANNED (`platform_profile`); macOS has no named power schemes and `IOPMSetPMPreferences` is SPI, deliberately not adopted (`power_health_plugin.cpp:729-755`). The Linux capture in this package ran at euid 0 in a container — more privileged than the agent's intended unprivileged posture (`docs/agent-privilege-model.md:12`) — so it is not representative of production privilege.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/power_health/src/power_health_macos.mm` · `agents/plugins/power_health/src/power_health_parsers.hpp` · `agents/plugins/power_health/src/power_health_plugin.cpp`
- Definitions: `content/definitions/power_health.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_power_health.hpp`
- Tests: `tests/unit/test_power_health_local_dispatcher.cpp` · `tests/unit/test_power_health_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
