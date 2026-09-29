# device_identity

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports device hostname, domain membership, and AD organizational unit |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (device.device_identity.device_name, device.device_identity.domain, device.device_identity.ou) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `device_name` (definition `device.device_identity.device_name`) · `domain` (definition `device.device_identity.domain`) · `ou` (definition `device.device_identity.ou`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`device_name` is a single native call on every OS — `gethostname(3)` on Linux/macOS, `GetComputerNameExA` on Windows — with no fallback and no subprocess. `domain` and `ou` are AD-join lookups, and each platform has its own chain: Windows makes one native call each (`NetGetJoinInformation`, `GetComputerObjectNameA`) and trusts the result. Linux's `domain` first parses `/etc/resolv.conf` for the DNS domain, then asks sssd's D-Bus InfoPipe whether the host is AD-joined (zero subprocesses); on any InfoPipe failure it falls through to a bounded `realm list` call, then to reading `/etc/sssd/sssd.conf` directly. Linux's `ou` skips InfoPipe (it has no OU surface) and goes straight to `realm list`, falling back to the same `sssd.conf` file. macOS's `domain` and `ou` each independently run the bounded `dsconfigad -show` subprocess and parse it with the shared `device_identity_macos.hpp` parser; `domain` additionally falls back to a native `gethostname()` + `getaddrinfo(AI_CANONNAME)` lookup when the device isn't AD-bound.

The plugin deliberately never distinguishes "not domain-joined" from "the AD lookup was refused or failed" — every degraded path in `domain`/`ou` reports the same `N/A` / `joined=false` shape as a clean not-joined read, and the plugin never calls a typed result-status setter (see Caveats).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[device_identity.execute]
  EX --> WIN[Windows leg<br/>GetComputerNameExA /<br/>NetGetJoinInformation /<br/>GetComputerObjectNameA]
  EX --> MAC[macOS leg<br/>gethostname(3) /<br/>dsconfigad -show via bounded runner]
  EX --> LIN[Linux leg<br/>gethostname(3) /<br/>resolv.conf + sd-bus InfoPipe /<br/>realm list]
  WIN & MAC & LIN --> ROWS[key|value rows] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `device_name` | ✅ supported · rung 1 · GetComputerNameExA | ✅ supported · rung 1 · gethostname(3) | ✅ supported · rung 1 · gethostname(3) |
| `domain` | ✅ supported · rung 1 · NetGetJoinInformation | ✅ supported · rung 2 · run_bounded_subprocess(dsconfigad -show) + native parser (device_identity_macos.hpp) [fallback: gethostname(3) + getaddrinfo(AI_CANONNAME)] | ✅ supported · rung 1 · /etc/resolv.conf read + sd-bus org.freedesktop.sssd.infopipe ListDomains [fallback: run_bounded_subprocess(realm list); further fallback: /etc/sssd/sssd.conf read] |
| `ou` | ✅ supported · rung 1 · GetComputerObjectNameA | ✅ supported · rung 2 · run_bounded_subprocess(dsconfigad -show) + native parser (device_identity_macos.hpp) | ✅ supported · rung 2 · run_bounded_subprocess(realm list) [fallback: /etc/sssd/sssd.conf read] |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442 — `docs/agent-privilege-model.md:12`) | None. All three calls are unprivileged native APIs. | 2026-09-07, bare-metal, `SYSTEM` (sample stamp) | `domain`/`ou` silently report `N/A` / `joined=false` (`device_identity_plugin.cpp:418-421`) — no distinct "refused" signal |
| macOS | agent daemon, root (no `UserName` key in the LaunchDaemon — `docs/agent-privilege-model.md:8`) | None. `dsconfigad -show` runs unprivileged (`docs/agent-spawn-sink-manifest.md:77-78`). | 2026-09-07, bare-metal, euid 501 (jsmith) — i.e. captured unprivileged, not as the daemon's real root identity | falls through to the `gethostname()`+`getaddrinfo` fallback (`device_identity_plugin.cpp:390-401`); `ou` reports `N/A` |
| Linux | unprivileged `yuzu` account (`docs/agent-privilege-model.md`, Linux account section) | None. The sd-bus call, `realm list`, and the `sssd.conf` read are all unprivileged (`docs/agent-spawn-sink-manifest.md:76,79`). | 2026-09-06, container, euid 0 (root) — captured privileged, not as the daemon's real unprivileged identity | can fail closed on a stock host: sssd's InfoPipe defaults to root-only and `/etc/sssd/sssd.conf` ships mode 0600, so a genuinely joined host can report `joined=false` (`device_identity_plugin.cpp:252-268`, BR-011) |

Subprocesses: `realm list` (Linux, `domain`/`ou` fallback, path resolved via `probe_tool_path`) and `/usr/sbin/dsconfigad -show` (macOS, `domain` and `ou`, each its own call), both via the bounded runner with a 10s deadline. Local IPC: one sd-bus call to sssd's InfoPipe (Linux `domain`, only when built with `YUZU_HAVE_LIBSYSTEMD`). No outbound network.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Each action writes one or more `key|value` lines via `write_output()` (`device_identity_plugin.cpp:9-10`); there is no shared multi-field row shape. `device_name` and `ou` each write exactly one line; `domain` writes two (`domain|...` then `joined|...`). A value of `N/A` (for `domain`/`ou`) means the lookup completed but found nothing to report — it is not distinguishable from a failed lookup (see Caveats).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.device_identity.device_name` — `device_name`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `device_name` | string | - | Windows, Linux, macOS | `DESKTOP-04DNSIG` | The device's hostname as reported by the OS. Values: free text. |

**`device.device_identity.domain` — `domain|joined`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `domain` | string | - | Windows, Linux, macOS | `WORKGROUP` | The DNS or Active Directory domain name the device reports, or "N/A" if none was found. Values: free text (or the literal "N/A"). |
| `joined` | bool | - | Windows, Linux, macOS | `false` | Whether the device is currently joined to a domain or realm. |

**`device.device_identity.ou` — `ou`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `ou` | string | - | Windows, Linux, macOS | `N/A` | The Active Directory organizational unit distinguished-name path, or "N/A" if the device is not domain-joined or the OU could not be read. Values: free text (AD DN fragment) or the literal "N/A". |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the samples show `UNDECLARED / UNKNOWN /` for every action on every OS.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, rendered as `Agent · Key · Value` (`device_identity` is in `kKeyValuePlugins`, `server/core/src/result_parsing.hpp:63`) for SSE, ResponseStore facet extraction, and dashboard fragments.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — no reference to `device_identity` or its definition ids was found outside the instruction-result path.
- **Sensitivity.** `device_name` is the host's own hostname, and `domain`/`ou` report its AD domain membership and organizational-unit placement — all three directly identify the specific device (and, via the OU, the org unit it belongs to); nothing here names a person or installed software.
- **Siblings:** `os_info`, `hardware`, `status` — other inventory/system plugins declared alongside `device_identity` in the same ABI4 capability pass (`changelog.d/2204-declarations-group-b.added.md`).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.device_identity.domain")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash fdf67a9b8831

```
== action=device_name
device_name|DESKTOP-04DNSIG
[result_status] UNDECLARED / UNKNOWN

== action=domain
domain|WORKGROUP
joined|false
[result_status] UNDECLARED / UNKNOWN

== action=ou
ou|N/A
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash fdf67a9b8831

```
== action=device_name
device_name|workstation1.local
[result_status] UNDECLARED / UNKNOWN

== action=domain
domain|local
joined|false
[result_status] UNDECLARED / UNKNOWN

== action=ou
ou|N/A
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash fdf67a9b8831

```
== action=device_name
device_name|d7023653759f
[result_status] UNDECLARED / UNKNOWN

== action=domain
domain|N/A
joined|false
[result_status] UNDECLARED / UNKNOWN

== action=ou
ou|N/A
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Linux AD-join detection can fail closed under the unprivileged agent account.** sssd's InfoPipe defaults to root-only access and `/etc/sssd/sssd.conf` ships mode 0600; the agent runs as the unprivileged `yuzu` account, so both paths can be denied on a stock SSSD host. `realm list` is kept as the confirmed-unprivileged fallback specifically to cover this gap (`device_identity_plugin.cpp:252-268`, BR-011).
2. **No typed result status.** Every sample shows `UNDECLARED / UNKNOWN /` — the plugin never calls a `set_result_status`-style API, so a permission failure and a genuine "not joined" answer are indistinguishable to a consumer.
3. **macOS runs `dsconfigad -show` twice per full identity read.** `domain` and `ou` each make their own independent bounded-subprocess call (`device_identity_plugin.cpp:368-370`, `:505-507`); there is no cross-action caching of the AD-bind check within one instruction batch.
4. **macOS AD lookups are capped at rung 2 (bounded subprocess), not native.** An OpenDirectory native implementation is explicitly deferred, coordinated with a parallel effort doing the same OpenDirectory work elsewhere (`device_identity_plugin.cpp:505-512`); do not reintroduce a raw `popen(dsconfigad)` in its place — that was already replaced by the bounded runner (`changelog.d/2380-hardware-device-identity-native-acquisition.changed.md`).
5. **The macOS and Linux samples were captured at the extremes of privilege, not the daemon's real identity.** The macOS sample ran unprivileged (euid 501); the Linux sample ran as root in a container (euid 0). Neither matches the daemon's actual runtime account (root on macOS, unprivileged `yuzu` on Linux) — see the Privileges table.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/device_identity/src/device_identity_macos.hpp` · `agents/plugins/device_identity/src/device_identity_plugin.cpp`
- Definitions: `content/definitions/device_identity.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: `tests/unit/test_device_identity_macos.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
