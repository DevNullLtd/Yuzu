# agent_logging

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Remote agent log access — retrieve log tail, list key agent files |
| **Version** | 0.1.0 |
| **Kind** | Collector · read-only · gathered (device.agent_logging.get_log, device.agent_logging.get_key_files) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `get_key_files` (definition `device.agent_logging.get_key_files`) · `get_log` (definition `device.agent_logging.get_log`) |
| **Security** | `get_log`: securable `PluginSecret` · operation Read · risk Medium · dispatch ReadOnly · approval gate None; `get_key_files`: securable `Security` · operation Read · risk Medium · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`get_log` resolves the agent log path through a three-tier fallback — explicit `agent.log_file` config, then `agent.data_dir`/`yuzu-agent.log`, then platform default paths — and tails it line-by-line into a bounded deque, clamped to 500 lines. A log path that resolves to nothing is not an error: the action returns rc=0 with `status|empty` and `line_count|0`, while an out-of-range `lines` parameter returns rc=1 with `status|error`. Every `fs::exists` check in the path search deliberately uses the non-throwing `error_code` overload — the throwing form raised `filesystem_error` on `EACCES` and crashed the whole agent process on a macOS host with a restricted log directory.

`get_key_files` walks a fixed list of locations — the agent's own executable path (via an OS-specific self-lookup), its log file, up to three config file names and two data-store file names under `agent.data_dir`, every regular file in `agent.plugin_dir`, and three TLS certificate/key config keys — emitting one `file|<path>|<size>|<mtime>` row per file actually found. A missing file, an unreadable size, or an unreadable mtime is skipped or zeroed rather than failing the whole action.

Neither action shells out or spawns a subprocess; both are native, in-process filesystem/config reads on every OS. This plugin is deliberately not a live log tail or a file-content reader: `get_log` re-reads the whole file on every call rather than streaming, and `get_key_files` reports paths, sizes and mtimes only — never file contents, including for the TLS private key it enumerates.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: PluginSecret.Read get_log<br/>Security.Read get_key_files]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[agent_logging.execute]
  EX --> WIN[Windows leg<br/>ifstream tail read /<br/>GetModuleFileNameA]
  EX --> MAC[macOS leg<br/>ifstream tail read /<br/>_NSGetExecutablePath + realpath]
  EX --> LIN[Linux leg<br/>ifstream tail read /<br/>proc self exe symlink]
  WIN & MAC & LIN --> ROWS[key|value rows,<br/>no typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `get_key_files` | ✅ supported · rung 1 · GetModuleFileNameA + std::filesystem metadata | ✅ supported · rung 1 · _NSGetExecutablePath + realpath(3) + std::filesystem metadata | ✅ supported · rung 1 · /proc/self/exe symlink + std::filesystem metadata |
| `get_log` | ✅ supported · rung 1 · agent config lookup + std::ifstream tail read | ✅ supported · rung 1 · agent config lookup + std::ifstream tail read | ✅ supported · rung 1 · agent config lookup + std::ifstream tail read |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account, registered as LocalSystem in practice today (docs/agent-privilege-model.md:12, #1442) | None — both actions are plain Win32 calls (`GetModuleFileNameA`, `std::filesystem`) with no elevated handle opened | 2026-09-07, bare-metal, SYSTEM (windows.txt sample stamp) | the file is silently omitted from the row set — `emit_file_info` returns early on a failed `fs::exists` |
| macOS | agent daemon, root today (LaunchDaemon plist carries no `UserName` key) (docs/agent-privilege-model.md:14) | None — ordinary filesystem/config reads under the daemon's own permissions | 2026-09-07, bare-metal, euid 501 (jsmith) (macos.txt sample stamp — unprivileged, not the production root daemon) | same silent omission |
| Linux | agent daemon, designed to run unprivileged as `yuzu` (docs/agent-privilege-model.md:12) | None declared | 2026-09-06, container, euid 0 (linux.txt sample stamp — root, not the designed `yuzu` account) | same silent omission |

No external binaries, no subprocesses, no network access — both actions are native, in-process filesystem/config reads on every OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `device.agent_logging.get_log` | `lines` | int32 | no | 50 | - | Number of trailing log lines to return, 1-500 (e.g. 100). Defaults to 50; values above 500 are clamped, values below 1 are rejected with a status\|error result. |
<!-- END GENERATED -->

### Outputs

Output is a stream of pipe-delimited `key|value` lines via `write_output()`, not typed row-per-record output. `get_log` emits `log_file`, `line_count`, then one `line` entry per tailed line — except when no log file resolves, where it emits only `status|empty` and `line_count|0`, or when `lines` is invalid, where it emits only `status|error` and returns non-zero; neither `status` value is a declared result column. `get_key_files` emits one `file|<path>|<size>|<mtime>` row per file found; a missing file is skipped outright rather than emitted as a placeholder row, so an empty result set here means literally nothing was found, not a signal of failure.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.agent_logging.get_key_files` — `path|size|modified`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `path` | string | - | Windows, Linux, macOS | `/private/tmp/claude-501/-Users-jsmith-yuzu-dev/00000000-0000-0000-0000-000000000000/scratchpad/d2/plugin_capture` | Absolute path of a discovered agent file (executable, log file, config file, data store, plugin file, or TLS certificate/key). Values: absolute path. |
| `size` | int64 | - | Windows, Linux, macOS | `142208` | File size in bytes; 0 if the size read failed. Values: non-negative integer (bytes). |
| `modified` | int64 | - | Windows, Linux, macOS | `1788774907` | Last-write time as Unix epoch seconds; 0 if the mtime read failed. Values: non-negative integer (unix epoch seconds). |

**`device.agent_logging.get_log` — `log_file|line_count|line`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `log_file` | string | - | Windows, Linux, macOS | `field omitted in every captured sample — no capture has resolved a log file (see status\|empty)` | Absolute path to the log file that was read; the field is omitted from the output entirely when no log file resolves on this host. Values: absolute path, or field absent. |
| `line_count` | int32 | - | Windows, Linux, macOS | `0` | Count of line entries returned; 0 when no log file resolves. Values: non-negative integer. |
| `line` | string | - | Windows, Linux, macOS | `field omitted in every captured sample — no capture has resolved a log file` | One raw line from the tailed log file, unescaped and in file order; omitted entirely when no log file resolves. Values: free text, or field absent. |
<!-- END GENERATED -->

**Empty-result convention.** `get_log`'s empty case is reported entirely through `status|empty` + `line_count|0`, never a placeholder `log_file`/`line` row. `get_key_files` simply emits zero `file|` rows when nothing is found — there is no placeholder row for this action.

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's response channel into the ResponseStore (default 90-day retention via `reap_expired()`), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. The plugin executes only when an operator or workflow dispatches `device.agent_logging.get_log` or `device.agent_logging.get_key_files`; outside `agent_registry.cpp`'s static action-description catalogue (a name/description list, not a data sink), no other server code references this plugin.
- **Sensitivity.** `get_log`'s `line` field is a verbatim tail of the agent's log, which includes the line `"Registered with server (session=..., ...)"` — the agent's live session credential — plus whatever other free text the agent logged, including file paths that may embed a username; `get_key_files`'s `path` rows can likewise embed a username or hostname in the file path. Neither action names installed third-party software.
- **Siblings:** none — no other plugin's definition references `agent_logging`.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.agent_logging.get_log")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 6e239e35ca05

```
== action=get_log
status|empty|agent log file not configured on this host
line_count|0
[result_status] UNDECLARED / UNKNOWN

== action=get_key_files
file|D:\yuzu-dev\Yuzu-worktrees\docs-plugin-readme-sweep\build-windows\tools\plugin-capture-tmp\plugin_capture.exe|64512|1788774930
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 6e239e35ca05

```
== action=get_log
status|empty|agent log file not configured on this host
line_count|0
[result_status] UNDECLARED / UNKNOWN

== action=get_key_files
file|/private/tmp/claude-501/-Users-jsmith-yuzu-dev/00000000-0000-0000-0000-000000000000/scratchpad/d2/plugin_capture|142208|1788774907
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 6e239e35ca05

```
== action=get_log
status|empty|agent log file not configured on this host
line_count|0
[result_status] UNDECLARED / UNKNOWN

== action=get_key_files
file|/src/builddir/tools/plugin-capture/plugin-capture|75168|1788720500
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`get_log` can expose the agent's live session credential.** The tailed log is the same file the agent writes `"Registered with server (session={}, ...)"` to (`agents/core/src/agent.cpp:1928`); `get_log` is classified under securable `PluginSecret` rather than plain `Inventory` for exactly this reason.
2. **The declared result schema doesn't name a `status` field.** `get_log`'s empty path (`status|empty`, rc=0) and error path (`status|error`, rc=1) both emit a `status` key that the definition's three columns (`log_file`, `line_count`, `line`) never declare.
3. **No capture has ever resolved a log file.** All three samples (Windows, macOS, Linux) returned `status|empty` — `log_file` and `line` have never been observed populated in a real run.
4. **`get_key_files` reports the calling process's own executable, not necessarily `yuzu-agent`'s.** `GetModuleFileNameA`/`/proc/self/exe`/`_NSGetExecutablePath` all resolve to whichever process is running the plugin; each sample here was captured through the `plugin-capture` harness, so its first `file|` row names the harness binary, not the production agent.
5. **No typed result status is ever set.** Every sample shows `UNDECLARED / UNKNOWN /` regardless of outcome — a caller must parse the `status|` output line itself to tell "no log configured" from "action failed".

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/agent_logging/src/agent_logging_plugin.cpp`
- Definitions: `content/definitions/agent_logging.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: none found by name
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
