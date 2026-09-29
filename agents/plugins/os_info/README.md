# os_info

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports OS name, version, build, architecture, and system uptime |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (device.os_info.os_name, device.os_info.os_version, device.os_info.os_build, device.os_info.os_arch, device.os_info.uptime) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `os_arch` (definition `device.os_info.os_arch`) · `os_build` (definition `device.os_info.os_build`) · `os_name` (definition `device.os_info.os_name`) · `os_version` (definition `device.os_info.os_version`) · `uptime` (definition `device.os_info.uptime`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

All five actions are single reads, no parameters. `os_name` builds the human-facing product name: Linux reads `PRETTY_NAME` from `/etc/os-release`; macOS reads `ProductName`/`ProductVersion` from `SystemVersion.plist` (sysctl and literal fallbacks); Windows reads the registry `ProductName` and corrects the Windows 10→11 naming lie for builds ≥ 22000. `os_version` reports the kernel/OS version — `uname(2)` release on Linux/macOS, `RtlGetVersion` on Windows (avoids `GetVersionEx`'s manifest-dependent lies) — and on macOS additionally emits a second row, the user-facing `os_product_version`. `os_build` reads `/proc/version` (Linux), `SystemVersion.plist`'s `ProductBuildVersion` (macOS), or `CurrentBuildNumber`+`UBR` from the registry (Windows). `os_arch` reads `uname(2).machine` on Linux/macOS (raw, unnormalized) or maps `GetNativeSystemInfo` to a fixed token set on Windows. `uptime` reads `/proc/uptime`, the `KERN_BOOTTIME` sysctl, or `GetTickCount64`, and always emits both a raw second count and a formatted display string.

Every leg is native in-process (ADR-3002 rung 1, zero subprocesses) — including macOS, which read `sw_vers` output until the Wave 3/PR31 syscall promotion moved it onto `SystemVersion.plist` + `sysctlbyname`. The plugin deliberately does not persist OS identity as a typed daily-sync inventory record; it is a live/on-demand read surface only, and it never sets a typed result status.

```mermaid
flowchart LR
  OP[Operator / workflow / live panel] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[os_info.execute]
  EX --> WIN[Windows leg<br/>Reg*W CurrentVersion + RtlGetVersion<br/>GetNativeSystemInfo + GetTickCount64]
  EX --> MAC[macOS leg<br/>SystemVersion.plist + sysctlbyname<br/>uname(2) + sysctl KERN_BOOTTIME]
  EX --> LIN[Linux leg<br/>/etc/os-release + /proc/version<br/>uname(2) + /proc/uptime]
  WIN & MAC & LIN --> ROWS[key\|value rows<br/>UNDECLARED status] --> RS[(ResponseStore)] --> API[REST /api/responses · live JSON]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `os_arch` | ✅ supported · rung 1 · GetNativeSystemInfo | ✅ supported · rung 1 · uname(2) | ✅ supported · rung 1 · uname(2) |
| `os_build` | ✅ supported · rung 1 · Reg*W CurrentBuildNumber + UBR | ✅ supported · rung 1 · SystemVersion.plist + sysctlbyname | ✅ supported · rung 1 · /proc/version |
| `os_name` | ✅ supported · rung 1 · Reg*W CurrentVersion\\ProductName + build-number correction | ✅ supported · rung 1 · SystemVersion.plist + sysctlbyname | ✅ supported · rung 1 · /etc/os-release |
| `os_version` | ✅ supported · rung 1 · RtlGetVersion (ntdll) | ✅ supported · rung 1 · uname(2) + SystemVersion.plist + sysctlbyname | ✅ supported · rung 1 · uname(2) |
| `uptime` | ✅ supported · rung 1 · GetTickCount64 | ✅ supported · rung 1 · sysctl(2) KERN_BOOTTIME | ✅ supported · rung 1 · /proc/uptime |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account — registered as **LocalSystem** today (#1442; `docs/agent-privilege-model.md` Correction, 2026-07-03) | None — `os_info.*` row is `default` (`docs/agent-privilege-model.md:84`) | 2026-09-07, bare-metal, `SYSTEM` (windows.txt sample stamp) | the affected field falls back to its literal (`unknown`, or the bare `Windows`/`macOS` name); no dedicated denial path — result status stays `UNDECLARED` regardless |
| macOS | agent LaunchDaemon — runs as **root** today (no `UserName` key; `docs/agent-privilege-model.md` TL;DR) | None — `os_info.*` row is `default` | 2026-09-07, bare-metal, euid 501 (jsmith) — the capture ran **unprivileged**, not as the deployed root daemon (macos.txt sample stamp) | same fallback-to-literal behavior |
| Linux | agent daemon — unprivileged `yuzu` account by design (`docs/agent-privilege-model.md` TL;DR); `os_info.*` needs nothing beyond default | None | 2026-09-06, container, euid 0 — the capture ran as **root**, not the intended unprivileged account (linux.txt sample stamp) | same fallback-to-literal behavior |

None — every leg reads native OS surfaces in-process (files, registry, sysctl, `uname`); zero subprocesses anywhere (`os_info_plugin.cpp:381-388`; confirmed by `changelog.d/20260819-wave3-pr31-syscall-promotion.changed.md`, which removed the last macOS `sw_vers` shell-out). No network access.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited `key|value` lines via `write_output()` — no row discriminator (unlike a multi-row action, each call emits one fixed set of known keys). A key is always present; when the underlying read fails the value is the literal `unknown` rather than the key being omitted.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.os_info.os_arch` — `os_arch`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `os_arch` | string | - | Windows, Linux, macOS | `x86_64` | CPU architecture. Linux and macOS report the raw uname(2) machine string unnormalized (e.g. "aarch64", "arm64" -- not the same token); Windows maps GetNativeSystemInfo to a fixed set: x86_64, aarch64, x86, arm, or unknown. Values: free text (Linux/macOS); "x86_64", "aarch64", "x86", "arm", "unknown" (Windows). |

**`device.os_info.os_build` — `os_build`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `os_build` | string | - | Windows, Linux, macOS | `26200.9278` | The OS build identifier: registry CurrentBuildNumber.UBR on Windows; the third whitespace field of /proc/version on Linux; SystemVersion.plist's ProductBuildVersion (sysctl kern.osversion fallback) on macOS. Values: free text. |

**`device.os_info.os_name` — `os_name`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `os_name` | string | - | Windows, Linux, macOS | `Windows 11 Pro` | The OS product name as read by the platform-specific leg (registry ProductName on Windows, corrected for the Windows 11 naming quirk; PRETTY_NAME from /etc/os-release on Linux; ProductName + ProductVersion from SystemVersion.plist on macOS). Values: free text. |

**`device.os_info.os_version` — `os_version|os_product_version`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `os_version` | string | - | Windows, Linux, macOS | `10.0.26200` | The kernel/version string: Major.Minor.Build from RtlGetVersion on Windows; the uname(2) kernel release on Linux and macOS. Values: free text. |
| `os_product_version` | string | - | macOS | `26.6.2` | macOS-only: the user-facing product version read from SystemVersion.plist's ProductVersion key (sysctl kern.osproductversion fallback); not emitted on Windows or Linux. Values: free text. |

**`device.os_info.uptime` — `uptime_seconds|uptime_display`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `uptime_seconds` | int64 | - | Windows, Linux, macOS | `69193` | Seconds since boot. Emitted as the literal string "unknown" instead of an integer if the platform read fails (/proc/uptime unreadable on Linux, the KERN_BOOTTIME sysctl failing on macOS) -- never observed in this capture set. Values: integer, or the literal "unknown". |
| `uptime_display` | string | - | Windows, Linux, macOS | `0d 19h 13m` | Human-readable uptime formatted "<days>d <hours>h <minutes>m"; "unknown" if the platform read failed. Values: free text ("<n>d <n>h <n>m"), or the literal "unknown". |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result.** Rows land in the ResponseStore over the agent's command-response channel; `os_info` is in the `kKeyValuePlugins` set (`server/core/src/result_parsing.hpp:63`), so SSE row rendering, ResponseStore facet extraction, and DashboardRoutes fragment rendering all render it as an `Agent · Key · Value` table.
- **Live snapshot / device dashboard.** `uptime` is one of two allow-listed "Get live info" kinds (`server/core/src/live_kinds.hpp:43`, `resolve_kind("uptime") → LiveKind{"os_info","uptime",...}`), dispatched as a real, deliberately **untracked** instruction (no `ExecutionTracker` row — `server/core/src/server.cpp:19704`) and rendered as a KPI tile (`server/core/src/device_routes.hpp:130`). Reachable via `POST /api/v1/dex/devices/{id}/live?kind=uptime` (`server/core/src/rest_api_v1.cpp:10424-10437`).
- **Pre-flight (`/auto`) gate.** `os_version` and `os_arch` are two of the five blocking Slice-1 checks, parsed by raw pipe-field index — bypassing `result.columns` entirely (`server/core/src/preflight_parse.hpp:13-15,51-52`).
- **Not consumed by** daily-sync, the TAR warehouse, or typed inventory: `is_typed_inventory_source` (`server/core/src/typed_inventory_sources.hpp:22-26`) lists only `installed_software`, `app_perf`, `device_ci`, `software_licensing` — `os_info` is absent, so its result never lands in a typed daily-sync store.
- **Sensitivity.** Rows carry only OS name/version/build/architecture and uptime — no device id, MAC, hostname, username, or installed-software identifier appears in any field.
- **Siblings:** `device_identity` (the typed `device_ci` daily-sync source), `hardware.*` (also a `kKeyValuePlugins` entry).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.os_info.uptime")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}` for an instruction dispatch; `/api/v1/dex/devices/{id}/live?kind=uptime` for the live KPI path.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 45e627d9dfa2

```
== action=os_name
os_name|Windows 11 Pro
[result_status] UNDECLARED / UNKNOWN

== action=os_version
os_version|10.0.26200
[result_status] UNDECLARED / UNKNOWN

== action=os_build
os_build|26200.9278
[result_status] UNDECLARED / UNKNOWN

== action=os_arch
os_arch|x86_64
[result_status] UNDECLARED / UNKNOWN

== action=uptime
uptime_seconds|69193
uptime_display|0d 19h 13m
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 45e627d9dfa2

```
== action=os_name
os_name|macOS 26.6.2
[result_status] UNDECLARED / UNKNOWN

== action=os_version
os_version|25.6.0
os_product_version|26.6.2
[result_status] UNDECLARED / UNKNOWN

== action=os_build
os_build|25G83
[result_status] UNDECLARED / UNKNOWN

== action=os_arch
os_arch|arm64
[result_status] UNDECLARED / UNKNOWN

== action=uptime
uptime_seconds|48996
uptime_display|0d 13h 36m
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 45e627d9dfa2

```
== action=os_name
os_name|Debian GNU/Linux 13 (trixie)
[result_status] UNDECLARED / UNKNOWN

== action=os_version
os_version|7.0.12-linuxkit
[result_status] UNDECLARED / UNKNOWN

== action=os_build
os_build|7.0.12-linuxkit
[result_status] UNDECLARED / UNKNOWN

== action=os_arch
os_arch|aarch64
[result_status] UNDECLARED / UNKNOWN

== action=uptime
uptime_seconds|184116
uptime_display|2d 3h 8m
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **macOS product-name/version reads never shell out today.** Wave 3/PR31 (2026-08-19) moved `os_name`/`os_version`/`os_build` off `sw_vers` onto `SystemVersion.plist` + `sysctlbyname`, reaching ADR-3002 rung 1 with zero spawned processes (`changelog.d/20260819-wave3-pr31-syscall-promotion.changed.md`); the definition YAML's prose describing `sw_vers` for these three fields was stale and is fixed as part of this documentation pass.
2. **`uptime_seconds` can emit a non-numeric string despite its declared `int64` type.** When the platform read fails (`/proc/uptime` unreadable on Linux, the `KERN_BOOTTIME` sysctl failing on macOS), the leg writes the literal `unknown` instead of an integer (`os_info_plugin.cpp:371-377`); no sample in this capture set hit that path.
3. **`os_product_version` is macOS-only and conditionally emitted.** It rides a second `write_output` call inside `#ifdef __APPLE__` on the `os_version` action (`os_info_plugin.cpp:251-256`); Windows and Linux responses for `os_version` carry only one row.
4. **`os_arch` is not normalized on Linux/macOS.** Those legs return the raw `uname().machine` string verbatim (e.g. `aarch64` vs `arm64` — not the same token); only the Windows leg maps to a fixed `x86_64`/`aarch64`/`x86`/`arm`/`unknown` set (`os_info_plugin.cpp:311-343`).
5. **The plist parser is deliberately not a general XML parser.** `os_info_macos.hpp` scans for a flat `<dict>` of sibling `<key>/<string>` pairs only, because `SystemVersion.plist` is Apple-authored and not adversarial input; it returns `nullopt` on any nesting or a nearer sibling tag rather than guessing (`os_info_macos.hpp:14-19,48-55`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/os_info/src/os_info_macos.hpp` · `agents/plugins/os_info/src/os_info_plugin.cpp`
- Definitions: `content/definitions/os_info.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: `tests/unit/test_os_info_macos.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
