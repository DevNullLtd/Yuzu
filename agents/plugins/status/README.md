# status

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports agent version, system info, health, modules, connection, switch, and config |
| **Version** | - |
| **Kind** | Collector · read-only · gathered (device.status.version, device.status.info, device.status.health, device.status.plugins, device.status.modules, device.status.connection, device.status.switch, device.status.config) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `config` (definition `device.status.config`) · `connection` (definition `device.status.connection`) · `health` (definition `device.status.health`) · `info` (definition `device.status.info`) · `modules` (definition `device.status.modules`) · `plugins` (definition `device.status.plugins`) · `switch` (definition `device.status.switch`) · `version` (definition `device.status.version`) |
| **Security** | `version`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `info`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `health`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `plugins`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `modules`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `connection`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `switch`: securable `PluginSecret` · operation Read · risk Medium · dispatch ReadOnly · approval gate None; `config`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: `version`: endpoint-admin, endpoint-operator; `info`: endpoint-admin, endpoint-operator; `health`: endpoint-admin, endpoint-operator; `plugins`: endpoint-admin, endpoint-operator; `modules`: endpoint-admin, endpoint-operator; `connection`: endpoint-admin; `switch`: endpoint-admin; `config`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`version` and `info` are pure reads that never touch plugin state: `version` formats three compile-time constants (`yuzu::kFullVersionString`/`kBuildNumber`/`kGitCommitHash`), `info` calls `uname(2)`+`gethostname(3)` on Linux/macOS or `GetNativeSystemInfo`+`GetComputerNameA` on Windows. `health` reads process memory via the platform's own API (`/proc/self/status`, Mach `task_info`, or `K32GetProcessMemoryInfo`) and computes uptime from a `steady_clock` timestamp taken in `init()`.

The other five actions — `plugins`, `modules`, `connection`, `switch`, `config` — all read the agent's in-process config map through one helper, `cfg()`, which forwards to `yuzu_ctx_get_config()` against a raw context pointer captured in `init()`. That map is a snapshot: the agent copies its master config into every plugin's own context once, right after every plugin finishes loading, so these five actions only ever see the config as it stood at that moment (see Caveats).

The plugin deliberately does not call `yuzu_ctx_get_secret()` (always returns `nullptr` on this agent build) and does not shell out, open a socket, or mutate anything — `execute()` is a flat action-name dispatch with no side effects beyond the one `init_time_` timestamp.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read or<br/>PluginSecret.Read for switch]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[status.execute]
  EX --> WIN[Windows leg<br/>native API / in-process config]
  EX --> MAC[macOS leg<br/>native API / in-process config]
  EX --> LIN[Linux leg<br/>native API / in-process config]
  WIN & MAC & LIN --> ROWS[key|value rows,<br/>UNDECLARED status] --> RS[(ResponseStore)] --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `config` | ✅ supported · rung 1 · in-process agent config (agent.*) | ✅ supported · rung 1 · in-process agent config (agent.*) | ✅ supported · rung 1 · in-process agent config (agent.*) |
| `connection` | ✅ supported · rung 1 · in-process agent config (agent.server_address/tls_enabled/*) | ✅ supported · rung 1 · in-process agent config (agent.server_address/tls_enabled/*) | ✅ supported · rung 1 · in-process agent config (agent.server_address/tls_enabled/*) |
| `health` | ✅ supported · rung 1 · K32GetProcessMemoryInfo + steady_clock | ✅ supported · rung 1 · task_info(MACH_TASK_BASIC_INFO) + steady_clock | ✅ supported · rung 1 · /proc/self/status VmRSS + steady_clock |
| `info` | ✅ supported · rung 1 · GetNativeSystemInfo + GetComputerNameA | ✅ supported · rung 1 · uname(2) + gethostname(3) | ✅ supported · rung 1 · uname(2) + gethostname(3) |
| `modules` | ✅ supported · rung 1 · in-process agent config (agent.modules.*) | ✅ supported · rung 1 · in-process agent config (agent.modules.*) | ✅ supported · rung 1 · in-process agent config (agent.modules.*) |
| `plugins` | ✅ supported · rung 1 · in-process agent config (agent.plugins.*) | ✅ supported · rung 1 · in-process agent config (agent.plugins.*) | ✅ supported · rung 1 · in-process agent config (agent.plugins.*) |
| `switch` | ✅ supported · rung 1 · in-process agent config (agent.server_address/session_id/*) | ✅ supported · rung 1 · in-process agent config (agent.server_address/session_id/*) | ✅ supported · rung 1 · in-process agent config (agent.server_address/session_id/*) |
| `version` | ✅ supported · rung 1 · in-process (compiled version constants) | ✅ supported · rung 1 · in-process (compiled version constants) | ✅ supported · rung 1 · in-process (compiled version constants) |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — every call (`GetNativeSystemInfo`, `GetComputerNameA`, `K32GetProcessMemoryInfo`) works for an unprivileged process on its own memory/host info. | 2026-09-07 on the-rig as `SYSTEM` | No typed denial path exists; a failed native call is simply not written (see `health` in Caveats) |
| macOS | agent daemon, unprivileged | None — `uname`, `gethostname`, and `task_info(MACH_TASK_BASIC_INFO)` on the calling process require no entitlement. | 2026-09-07 at euid 501 (jsmith) | Same — no typed denial path |
| Linux | agent daemon, root today | None — `uname`, `gethostname`, and reading the process's own `/proc/self/status` require no capability. | 2026-09-06 in a container at euid 0 | Same — no typed denial path |

No external binaries, no subprocesses, no network access. Every call in `status_plugin.cpp` is either an in-process constant, a config-map lookup, or a single native syscall.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Every field is written as its own pipe-delimited `key|value` row via `write_output()` — not one row per entity. `plugins` and `modules` are the two exceptions: after their own `<action>_count|<n>` row, each lists one `plugin|name|version|description` or `module|name|version|status` row per item, and `modules` additionally emits a separate `module_description|name|description` row only when a description is non-empty. The YAML declares `bool`/`int` types for several columns (`tls_enabled`, `encrypted`, `debug_mode`, `verbose_logging`, `reconnect_count`, …) purely for consumer convenience — every value actually travels as raw text from the agent's config map, and an unset or not-yet-synced key comes through as an empty string, never a typed `false`/`0`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.status.config` — `agent_id|agent_version|build_number|git_commit|server_address|tls_enabled|heartbeat_interval|plugin_dir|data_dir|log_level|debug_mode|verbose_logging`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `agent_id` | string | - | Windows, Linux, macOS | - | Agent's assigned id, from agent.id. Values: free text. |
| `agent_version` | string | - | Windows, Linux, macOS | - | Full agent version string with build suffix, from agent.version (set from kFullVersionString). Values: free text. |
| `build_number` | string | - | Windows, Linux, macOS | - | Build number as text, from agent.build_number. Values: free text (integer as string). |
| `git_commit` | string | - | Windows, Linux, macOS | - | Short git commit hash, from agent.git_commit. Values: free text. |
| `server_address` | string | - | Windows, Linux, macOS | - | Configured server address, from agent.server_address. Values: free text (host:port), or empty if unset. |
| `tls_enabled` | bool | - | Windows, Linux, macOS | - | Raw config value of agent.tls_enabled as text. Values: "true", "false", or empty if unset. |
| `heartbeat_interval` | string | - | Windows, Linux, macOS | - | Configured heartbeat interval in seconds, as text, from agent.heartbeat_interval. Values: free text (integer seconds as string). |
| `plugin_dir` | string | - | Windows, Linux, macOS | - | Configured plugin directory path, from agent.plugin_dir. Values: free text (filesystem path). |
| `data_dir` | string | - | Windows, Linux, macOS | - | Configured data directory path, from agent.data_dir. Values: free text (filesystem path). |
| `log_level` | string | - | Windows, Linux, macOS | - | Configured log level, from agent.log_level. Values: free text (e.g. "info", "debug"). |
| `debug_mode` | bool | - | Windows, Linux, macOS | - | Raw config value of agent.debug_mode as text. Values: "true", "false", or empty if unset. |
| `verbose_logging` | bool | - | Windows, Linux, macOS | - | Raw config value of agent.verbose_logging as text. Values: "true", "false", or empty if unset. |

**`device.status.connection` — `server_address|tls_enabled|encrypted|debug_mode|verbose_logging|log_level`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `server_address` | string | - | Windows, Linux, macOS | - | Configured server address the agent connects to, from agent.server_address. Values: free text (host:port), or empty if unset. |
| `tls_enabled` | bool | - | Windows, Linux, macOS | - | Raw config value of agent.tls_enabled as text; not validated or cast to bool at read time. Values: "true", "false", or empty if unset. |
| `encrypted` | bool | - | Windows, Linux, macOS | `true` | Derived field — "false" only when tls_enabled is literally "false"; "true" in every other case, including when tls_enabled is empty. Values: "true", "false". |
| `debug_mode` | bool | - | Windows, Linux, macOS | - | Raw config value of agent.debug_mode as text. Values: "true", "false", or empty if unset. |
| `verbose_logging` | bool | - | Windows, Linux, macOS | - | Raw config value of agent.verbose_logging as text. Values: "true", "false", or empty if unset. |
| `log_level` | string | - | Windows, Linux, macOS | - | Configured log level string, from agent.log_level. Values: free text (e.g. "info", "debug"), or empty if unset. |

**`device.status.health` — `uptime_seconds|timestamp_epoch_ms|memory_rss_kb`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `uptime_seconds` | int64 | - | Windows, Linux, macOS | `49012` | Seconds since the plugin's init() ran, measured with steady_clock; only meaningful once init() has actually been called by the host. Values: non-negative integer (seconds). |
| `timestamp_epoch_ms` | int64 | - | Windows, Linux, macOS | `1788774965076` | Wall-clock time the action ran, in epoch milliseconds (system_clock::now()). Values: integer (Unix epoch milliseconds). |
| `memory_rss_kb` | int64 | - | Windows, Linux, macOS | `31056` | Process resident set size in kilobytes; the row is omitted entirely (not zeroed) if the platform read fails. Values: non-negative integer (kilobytes), or the row is absent. |

**`device.status.info` — `os|arch|hostname`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `os` | string | - | Windows, Linux, macOS | `Darwin` | OS family name. "Darwin"/"Linux" from uname(2) on macOS/Linux, or the literal "Windows" on Windows. Values: "Darwin", "Linux", "Windows". |
| `arch` | string | - | Windows, Linux, macOS | `arm64` | CPU architecture. uname(2)'s machine field on Linux/macOS; mapped from GetNativeSystemInfo on Windows. Values: free text on Linux/macOS (whatever uname reports); on Windows one of "x86_64", "aarch64", "x86", "arm", "unknown". |
| `hostname` | string | - | Windows, Linux, macOS | `workstation1.local` | Agent host's configured hostname (gethostname(3) on Linux/macOS, GetComputerNameA on Windows); the row is simply not emitted if the call fails. Values: free text. |

**`device.status.modules` — `modules_count|module_name|module_version|module_status|module_description`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `modules_count` | int32 | - | Windows, Linux, macOS | `0` | Number of modules recorded in the agent's module roster (agent.modules.count), including both successful loads and rejected loads. Values: non-negative integer. |
| `module_name` | string | - | Windows, Linux, macOS | `-` | Module's file stem name; one "module\|name\|version\|status" row is emitted per module. Values: free text. |
| `module_version` | string | - | Windows, Linux, macOS | `-` | Module's declared version; empty for a rejected load. Values: free text or empty. |
| `module_status` | string | - | Windows, Linux, macOS | `-` | Load outcome for the module, as recorded by the agent's loader. Values: "loaded", "init_failed", "load_failed". |
| `module_description` | string | - | Windows, Linux, macOS | `-` | Human-readable description, or the rejection reason for a failed load; emitted as a separate "module_description\|name\|description" row, and only when non-empty. Values: free text, or the row is absent. |

**`device.status.plugins` — `plugins_count|plugin_name|plugin_version|plugin_description`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `plugins_count` | int32 | - | Windows, Linux, macOS | `0` | Number of plugins currently loaded by the agent, from agent.plugins.count in the in-process config; 0 if the config context isn't yet populated. Values: non-negative integer. |
| `plugin_name` | string | - | Windows, Linux, macOS | `-` | Loaded plugin's name; one "plugin\|name\|version\|description" row is emitted per loaded plugin. Values: free text. |
| `plugin_version` | string | - | Windows, Linux, macOS | `-` | Loaded plugin's declared version string. Values: free text. |
| `plugin_description` | string | - | Windows, Linux, macOS | `-` | Loaded plugin's declared description. Values: free text. |

**`device.status.switch` — `switch_address|session_id|connected_since|reconnect_count`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `switch_address` | string | - | Windows, Linux, macOS | - | Same value as connection.server_address, from agent.server_address. Values: free text (host:port), or empty if unset. |
| `session_id` | string | - | Windows, Linux, macOS | - | The agent's live session id, the same value Register/Heartbeat use server-side to resolve identity; classified as a plugin secret, not plain inventory. Values: free text (opaque token), or empty. |
| `connected_since` | string | - | Windows, Linux, macOS | - | Epoch milliseconds the current session connected, from agent.connected_since. Values: integer-as-string (Unix epoch milliseconds), or empty. |
| `reconnect_count` | int32 | - | Windows, Linux, macOS | - | Number of reconnect attempts recorded by the register/reconnect loop, from agent.reconnect_count. Values: non-negative integer, or empty string when the config key is unset (despite the declared int32 type). |

**`device.status.version` — `version|build_number|git_commit`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `version` | string | - | Windows, Linux, macOS | `0.13.1+5871` | Full agent version string, "<semver>+<build_number>" (yuzu::kFullVersionString). Values: free text (semver + build suffix). |
| `build_number` | string | - | Windows, Linux, macOS | `5871` | The build's numeric build number, formatted as text (yuzu::kBuildNumber). Values: free text (integer as string). |
| `git_commit` | string | - | Windows, Linux, macOS | `4c377398e` | Short git commit hash of the build (yuzu::kGitCommitHash), or "unknown" when the build did not set one. Values: free text (hex hash or "unknown"). |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /` for every action.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`; none of the eight definitions override `spec.response.retentionDays`, so the store's default retention applies.
- **Not consumed by** daily-sync inventory, the TAR warehouse, or DEX — `status_plugin.cpp` has no `sync_source_*`, TAR cursor, or Guardian/DEX integration. Nothing runs on a schedule; every action executes only when an operator or workflow dispatches its definition.
- **Sensitivity.** `info`'s `hostname` row identifies the device; `plugins`/`modules` rows name the agent's own installed plugin/module inventory (an installed-software listing, though of agent components rather than third-party apps); `switch`'s `session_id` is a live session credential, deliberately gated as `PluginSecret` rather than plain inventory (see Caveat 3); `config`'s `agent_id`, `server_address`, and `plugin_dir`/`data_dir` filesystem paths can also identify the specific device and its install layout. `version`, `health`, and `connection` rows carry nothing beyond build/runtime metadata.
- **Siblings:** `os_info` (a separate, broader platform-inventory plugin) and `agent_actions.info` (a separate plugin action that also reads "agent runtime info from config context" — overlaps in spirit with `status.info`/`status.config` but is a distinct code path).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.status.version")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 0e82a6f385ea

```
== action=version
version|0.13.1+7854
build_number|7854
git_commit|4c377398e
[result_status] UNDECLARED / UNKNOWN

== action=info
os|Windows
arch|x86_64
hostname|DESKTOP-04DNSIG
[result_status] UNDECLARED / UNKNOWN

== action=health
uptime_seconds|69196
timestamp_epoch_ms|1788775738117
memory_rss_kb|9772
[result_status] UNDECLARED / UNKNOWN

== action=plugins
plugins_count|0
[result_status] UNDECLARED / UNKNOWN

== action=modules
modules_count|0
[result_status] UNDECLARED / UNKNOWN

== action=connection
server_address|
tls_enabled|
encrypted|true
debug_mode|
verbose_logging|
log_level|
[result_status] UNDECLARED / UNKNOWN

== action=switch
switch_address|
session_id|
connected_since|
reconnect_count|
[result_status] UNDECLARED / UNKNOWN

== action=config
agent_id|
agent_version|
build_number|
git_commit|
server_address|
tls_enabled|
heartbeat_interval|
plugin_dir|
data_dir|
log_level|
debug_mode|
verbose_logging|
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 0e82a6f385ea

```
== action=version
version|0.13.1+5871
build_number|5871
git_commit|4c377398e
[result_status] UNDECLARED / UNKNOWN

== action=info
os|Darwin
arch|arm64
hostname|workstation1.local
[result_status] UNDECLARED / UNKNOWN

== action=health
uptime_seconds|49012
timestamp_epoch_ms|1788774965076
memory_rss_kb|31056
[result_status] UNDECLARED / UNKNOWN

== action=plugins
plugins_count|0
[result_status] UNDECLARED / UNKNOWN

== action=modules
modules_count|0
[result_status] UNDECLARED / UNKNOWN

== action=connection
server_address|
tls_enabled|
encrypted|true
debug_mode|
verbose_logging|
log_level|
[result_status] UNDECLARED / UNKNOWN

== action=switch
switch_address|
session_id|
connected_since|
reconnect_count|
[result_status] UNDECLARED / UNKNOWN

== action=config
agent_id|
agent_version|
build_number|
git_commit|
server_address|
tls_enabled|
heartbeat_interval|
plugin_dir|
data_dir|
log_level|
debug_mode|
verbose_logging|
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 0e82a6f385ea

```
== action=version
version|0.13.1+0
build_number|0
git_commit|unknown
[result_status] UNDECLARED / UNKNOWN

== action=info
os|Linux
arch|aarch64
hostname|988e0b888baf
[result_status] UNDECLARED / UNKNOWN

== action=health
uptime_seconds|184122
timestamp_epoch_ms|1788722304837
memory_rss_kb|15020
[result_status] UNDECLARED / UNKNOWN

== action=plugins
plugins_count|0
[result_status] UNDECLARED / UNKNOWN

== action=modules
modules_count|0
[result_status] UNDECLARED / UNKNOWN

== action=connection
server_address|
tls_enabled|
encrypted|true
debug_mode|
verbose_logging|
log_level|
[result_status] UNDECLARED / UNKNOWN

== action=switch
switch_address|
session_id|
connected_since|
reconnect_count|
[result_status] UNDECLARED / UNKNOWN

== action=config
agent_id|
agent_version|
build_number|
git_commit|
server_address|
tls_enabled|
heartbeat_interval|
plugin_dir|
data_dir|
log_level|
debug_mode|
verbose_logging|
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The capture driver never calls `init()`, so five of eight actions read an empty config.** `plugins`, `modules`, `connection`, `switch`, and `config` all read through `cfg()` (`status_plugin.cpp:305-310`), which returns empty unconditionally until `init()` sets `raw_plugin_ctx_` (`status_plugin.cpp:264-273`) — every sample above shows this: `plugins_count|0`, `modules_count|0`, and every `connection`/`switch`/`config` field blank. On a running agent `init()` runs at plugin load, before any action executes.
2. **`switch`'s `session_id`, `connected_since`, and `reconnect_count` never populate on a live agent either.** The post-load config sync (`agents/core/src/agent.cpp:1017`, mechanism documented in `plugin_config_sync.hpp:24-29`) is one-shot and runs before `Register` sets `agent.session_id`/`agent.connected_since` (`agent.cpp:1896-1897`) or the reconnect loop updates `agent.reconnect_count` past its startup value of `"0"` (`agent.cpp:787`, updated at `agent.cpp:1630`) — so this action reports the live session id and reconnect count as empty/`0` for the whole life of the agent process, independent of this capture. `switch_address` (from `agent.server_address`, set at `agent.cpp:770`, before the sync) is the one field here that does reflect reality.
3. **`switch`'s `session_id` is classified as a live session credential, not plain inventory.** `server/core/src/capability_decls/plugin_action_catalogue_b.hpp:296-303` deliberately gates it under `PluginSecret`/Medium risk because Heartbeat/ReportInventory resolve the agent's identity from that same session id — do not reclassify it to `Inventory`/Low to match the other seven actions.
4. **`health.memory_rss_kb` is silently omitted, not placeholdered, on a failed read.** `get_memory_rss_kb()` returns `-1` on failure and `do_health` only calls `write_output` when the result is `>= 0` (`status_plugin.cpp:418-421`) — unlike the empty-string convention used by the config-backed actions, a failed read here drops the row entirely.
5. **`connection.encrypted` defaults to `"true"` whenever `tls_enabled` isn't the literal string `"false"`** (`status_plugin.cpp:343`) — including when the config value is unset, as in every capture above. A misconfigured or not-yet-synced agent reports itself encrypted by default on this field, never unencrypted.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/status/src/status_plugin.cpp`
- Definitions: `content/definitions/status.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: none found by name
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
