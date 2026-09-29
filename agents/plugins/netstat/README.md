# netstat

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Enumerates active network connections and listening sockets |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (device.network.netstat_list, device.network.netstat_attribution) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `attribution` (definition `device.network.netstat_attribution`) · `netstat_list` (definition `device.network.netstat_list`) |
| **Security** | securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`netstat_list` enumerates active TCP/UDP connections and listening sockets, returning protocol, local/remote address and port, connection state, and owning PID. `attribution` runs the same enumeration and additionally resolves the owning process's name and executable path — this is the retired `sockwho` plugin's functionality, folded in as netstat's second action (#3403). `attribution` emits `netstat_list`'s 7 fields as a prefix with `process_name`/`process_path` appended (9 total); `pid` stays in its `netstat_list` position (6th field), not sockwho's old 1st-column layout.

On macOS both actions walk the same shared `agents/shared/macos_socket_walk.hpp` libproc enumeration with `dedup=true`, so a socket shared across a fork (multiple PIDs holding the same fd) collapses to one row — a deliberate match to `netstat_list`'s semantics, and a deliberate *difference* from the retired `sockwho`, which emitted one row per (pid, fd). On Linux, `attribution` builds its inode→PID and PID→process maps in one `/proc` scan rather than reusing `netstat_list`'s separate scan. On Windows, `attribution` resolves each owning PID via `QueryFullProcessImageNameW`, cached per PID for the duration of one call. `escape_pipes()` (`netstat_parsers.hpp`) escapes `|` and strips CR/LF from `process_name`/`process_path` so an attacker-controlled process name can't split one row into extra server-visible lines.

Neither action takes parameters, sets a typed result status, filters by protocol/state, or schedules itself — both are one-shot, unfiltered reads dispatched on demand.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Infrastructure.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[netstat.execute]
  EX --> WIN[Windows leg<br/>GetExtendedTcpTable/UdpTable<br/>+ QueryFullProcessImageNameW]
  EX --> MAC[macOS leg<br/>libproc via macos_socket_walk.hpp]
  EX --> LIN[Linux leg<br/>/proc/net/tcp,udp[6] + /proc/pid/fd]
  WIN & MAC & LIN --> ROWS[pipe rows,<br/>UNDECLARED result status]
  ROWS -- CommandResponse --> RS[(ResponseStore<br/>90-day retention)]
  RS --> API[REST /api/responses · dashboard table]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `attribution` | ✅ supported · rung 1 · IP Helper API + QueryFullProcessImageNameW | ✅ supported · rung 1 · libproc | ✅ supported · rung 1 · /proc/net/* + /proc/[pid]/{comm,exe,fd} |
| `netstat_list` | ✅ supported · rung 1 · GetExtendedTcpTable/GetExtendedUdpTable | ✅ supported · rung 1 · libproc | ✅ supported · rung 1 · /proc/net/{tcp,udp}[6] |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | LocalSystem today (#1442); intended target is `NT SERVICE\YuzuAgent` | None — `GetExtendedTcpTable`/`GetExtendedUdpTable` and `QueryFullProcessImageNameW(PROCESS_QUERY_LIMITED_INFORMATION)` need no elevation | 2026-09-07, bare metal, as SYSTEM | No typed error path: a table-query failure (return code other than `NO_ERROR`/`ERROR_INSUFFICIENT_BUFFER`) or a failed `QueryFullProcessImageNameW` is swallowed — the call returns with whatever rows it already emitted, or an attribution row with empty `process_name`/`process_path` (see `tcp\|203.0.113.131\|139\|0.0.0.0\|0\|LISTEN\|4\|\|` in the Windows sample below, PID 4) |
| macOS | root — the LaunchDaemon has no `UserName` key (#1455 tracks narrowing this) | None beyond the agent's actual (root) identity; libproc reads need no separate entitlement | 2026-09-07, bare metal, at euid 501 (jsmith) — captured unprivileged, not as the production root daemon | `walk_sockets`/`resolve_proc_name_path` silently skip a PID libproc can't inspect (`proc_pidinfo`/`proc_name`/`proc_pidpath` returning ≤0); the socket, or its process fields, is simply omitted — never a typed status |
| Linux | dedicated unprivileged `_yuzu`/`yuzu` account (`docs/agent-privilege-model.md:95`, `netstat.*` row: default/default/default) | None declared — but see Caveats: `/proc/[pid]/fd` on another user's process needs a matching uid or `CAP_SYS_PTRACE`, which the "default" grant does not include | 2026-09-06, container, at euid 0 (root) — captured privileged, not as the least-privilege agent | `opendir()`/`ifstream` failures return silently (`if (!fd_dir) continue;` / `if (!f) return;`, `netstat_plugin.cpp:164-165,197-198`); an unresolved socket's `pid` stays `-1` (netstat_list) or its `process_name`/`process_path` stay empty (attribution) — never a typed status |

No external binaries, no subprocesses, no sockets of its own — every leg reads OS-supplied tables/files or calls native Win32/libproc APIs directly (`netstat_plugin.cpp` has no `popen`/`CreateProcess`/`system(`/`exec*` call).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
Neither action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per socket, written via `ctx.write_output()`. `netstat_list` emits 7 fields; `attribution` emits the same 7 as a prefix with `process_name`/`process_path` appended (9 total). A leg that finds no connections emits zero rows and sets no status — there is no one-row placeholder convention here (contrast `disk_actions`); an empty action block in the sample output below means the host genuinely had nothing to report at capture time.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.network.netstat_attribution` — `proto|local_addr|local_port|remote_addr|remote_port|state|pid|process_name|process_path`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `proto` | string | `tcp` `tcp6` `udp` `udp6` | Windows, Linux, macOS | `tcp` | Transport protocol and IP version of the socket. |
| `local_addr` | string | - | Windows, Linux, macOS | `198.51.100.77` | The connection's local IP address, in the address family matching proto. Values: free text (IPv4 or IPv6 address). |
| `local_port` | int32 | - | Windows, Linux, macOS | `52882` | The connection's local TCP or UDP port number. Values: integer, 0-65535. |
| `remote_addr` | string | - | Windows, Linux, macOS | `198.51.100.121` | The connection's remote IP address. UDP sockets report the literal '*' on macOS and Windows (no fixed peer); Linux instead parses the real value from /proc/net/udp* (normally 0.0.0.0). Values: free text (IPv4 or IPv6 address) or "*". |
| `remote_port` | int32 | - | Windows, Linux, macOS | `22` | The connection's remote port; always 0 for UDP (no fixed peer). Values: integer, 0-65535. |
| `state` | string | - | Windows, Linux, macOS | `ESTABLISHED` | TCP connection state name; always empty for UDP rows (never a fabricated LISTEN). The exact name set differs slightly per OS. Values: ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSE_WAIT, LAST_ACK, LISTEN, CLOSING, UNKNOWN, CLOSE (Linux only), CLOSED/DELETE_TCB (Windows only), or empty (UDP). |
| `pid` | int32 | - | Windows, Linux, macOS | `9653` | PID of the process holding the socket, or -1 (Linux only) when no matching /proc/[pid]/fd inode was found. Values: integer, or -1 on Linux. |
| `process_name` | string | - | Windows, Linux, macOS | `ssh` | Name of the process owning the socket (Linux: /proc/[pid]/comm; macOS: libproc proc_name, 16-char truncated; Windows: basename of the QueryFullProcessImageNameW path). Pipe and CR/LF characters are escaped/stripped. Empty when the owning process could not be resolved. Values: free text, or empty when unresolved. |
| `process_path` | string | - | Windows, Linux, macOS | `/usr/bin/ssh` | Full executable path of the owning process (Linux: /proc/[pid]/exe symlink target; macOS: libproc proc_pidpath; Windows: QueryFullProcessImageNameW). Pipe and CR/LF characters are escaped/stripped. Empty when the owning process could not be resolved. Values: free text (absolute path), or empty when unresolved. |

**`device.network.netstat_list` — `proto|local_addr|local_port|remote_addr|remote_port|state|pid`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `proto` | string | `tcp` `tcp6` `udp` `udp6` | Windows, Linux, macOS | `tcp` | Transport protocol and IP version of the socket. |
| `local_addr` | string | - | Windows, Linux, macOS | `198.51.100.77` | The connection's local IP address, in the address family matching proto. Values: free text (IPv4 or IPv6 address). |
| `local_port` | int32 | - | Windows, Linux, macOS | `52882` | The connection's local TCP or UDP port number. Values: integer, 0-65535. |
| `remote_addr` | string | - | Windows, Linux, macOS | `198.51.100.121` | The connection's remote IP address. UDP sockets report the literal '*' on macOS and Windows (no fixed peer); Linux instead parses the real value from /proc/net/udp* (normally 0.0.0.0). Values: free text (IPv4 or IPv6 address) or "*". |
| `remote_port` | int32 | - | Windows, Linux, macOS | `22` | The connection's remote port; always 0 for UDP (no fixed peer). Values: integer, 0-65535. |
| `state` | string | - | Windows, Linux, macOS | `ESTABLISHED` | TCP connection state name; always empty for UDP rows (never a fabricated LISTEN). The exact name set differs slightly per OS. Values: ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSE_WAIT, LAST_ACK, LISTEN, CLOSING, UNKNOWN, CLOSE (Linux only), CLOSED/DELETE_TCB (Windows only), or empty (UDP). |
| `pid` | int32 | - | Windows, Linux, macOS | `9653` | PID of the process holding the socket, or -1 (Linux only) when no matching /proc/[pid]/fd inode was found. Values: integer, or -1 on Linux. |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /` (no `set_result_status`/`yuzu_ctx_set_result_status` call anywhere in `netstat_plugin.cpp`).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention — `docs/yaml-dsl-spec.md:194`, `response_store.hpp:167`), queryable at `/api/responses/{id}` and dashboard-rendered: `netstat_list` uses a static 8-column schema (`result_parsing.hpp:56`), while `attribution`'s 9-column schema is resolved from the content-definition `result` schema instead of a static entry (`result_parsing.hpp:50-55`).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — grepping `server/` and `agents/plugins/tar/` for `netstat` finds only the dashboard-schema and command-catalogue sites above; nothing runs on a schedule.
- **Sensitivity.** `netstat_list` rows carry local/remote IPs and a bare `pid` — enough to fingerprint the device's active network identity, but nothing else. `attribution` rows add `process_name`/`process_path`, which name installed software and, for a per-user-profile install, can embed a person's account name in the path (the macOS sample below shows a VS Code extension path under `/Users/jsmith/...`).
- **Siblings:** `network_diag` (connection/socket diagnostics), `netprobe` (active reachability probes), the retired `sockwho` (folded into `attribution`, #3403).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.network.netstat_attribution")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash f31d206bb2ee

```
== action=netstat_list
tcp|0.0.0.0|22|0.0.0.0|0|LISTEN|5148
tcp|198.51.100.121|22|198.51.100.77|53137|ESTABLISHED|5148
tcp|0.0.0.0|135|0.0.0.0|0|LISTEN|1008
tcp|203.0.113.131|139|0.0.0.0|0|LISTEN|4
tcp|0.0.0.0|3389|0.0.0.0|0|LISTEN|9048
tcp|0.0.0.0|5040|0.0.0.0|0|LISTEN|14216
tcp|127.0.0.1|5432|0.0.0.0|0|LISTEN|6436
tcp|127.0.0.1|5432|127.0.0.1|49748|ESTABLISHED|6436
tcp|127.0.0.1|5432|127.0.0.1|49749|ESTABLISHED|6436
tcp|127.0.0.1|5432|127.0.0.1|50169|ESTABLISHED|6436
tcp|0.0.0.0|8080|0.0.0.0|0|LISTEN|13676
tcp|127.0.0.1|8080|127.0.0.1|49754|ESTABLISHED|13676
… 12 of 97 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=attribution
tcp|0.0.0.0|22|0.0.0.0|0|LISTEN|5148|sshd.exe|C:\Windows\System32\OpenSSH\sshd.exe
tcp|198.51.100.121|22|198.51.100.77|53137|ESTABLISHED|5148|sshd.exe|C:\Windows\System32\OpenSSH\sshd.exe
tcp|0.0.0.0|135|0.0.0.0|0|LISTEN|1008|svchost.exe|C:\Windows\System32\svchost.exe
tcp|203.0.113.131|139|0.0.0.0|0|LISTEN|4||
tcp|0.0.0.0|3389|0.0.0.0|0|LISTEN|9048|svchost.exe|C:\Windows\System32\svchost.exe
tcp|0.0.0.0|5040|0.0.0.0|0|LISTEN|14216|svchost.exe|C:\Windows\System32\svchost.exe
tcp|127.0.0.1|5432|0.0.0.0|0|LISTEN|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|127.0.0.1|5432|127.0.0.1|50169|ESTABLISHED|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|127.0.0.1|5432|127.0.0.1|49749|ESTABLISHED|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|127.0.0.1|5432|127.0.0.1|49748|ESTABLISHED|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|0.0.0.0|8080|0.0.0.0|0|LISTEN|13676|yuzu-server.exe|C:\yuzu-rig\yuzu-0.13.0-windows-x64\bin\yuzu-server.exe
tcp|127.0.0.1|8080|127.0.0.1|49754|ESTABLISHED|13676|yuzu-server.exe|C:\yuzu-rig\yuzu-0.13.0-windows-x64\bin\yuzu-server.exe
… 12 of 97 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash f31d206bb2ee

```
== action=netstat_list
tcp|198.51.100.77|52882|198.51.100.121|22|ESTABLISHED|9653
tcp|203.0.113.66|52771|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52775|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52773|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52789|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52801|34.149.66.165|443|ESTABLISHED|9039
tcp|203.0.113.66|52777|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52779|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52781|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52856|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52783|160.79.104.10|443|ESTABLISHED|9039
tcp|203.0.113.66|52785|160.79.104.10|443|ESTABLISHED|9039
… 12 of 105 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=attribution
tcp|198.51.100.77|52882|198.51.100.121|22|ESTABLISHED|9653|ssh|/usr/bin/ssh
tcp|203.0.113.66|52771|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52775|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52773|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52789|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52801|34.149.66.165|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52777|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52779|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52781|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52856|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52783|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|203.0.113.66|52785|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/jsmith/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
… 12 of 105 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash f31d206bb2ee

```
== action=netstat_list
[result_status] UNDECLARED / UNKNOWN

== action=attribution
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **UDP's remote address is not the same sentinel on every OS.** macOS and Windows report the literal `*` with `remote_port=0` for a UDP row (`macos_socket_walk.hpp:181,185`; `netstat_plugin.cpp:579,606`). Linux instead runs UDP rows through the same parser as TCP (`netstat_plugin.cpp:203-249`), so it reports the real value parsed from `/proc/net/udp*` — normally `0.0.0.0`, not `*`. The Linux sample below has no UDP rows to demonstrate this; it follows from the shared code path.
2. **The Linux capture returned zero rows for both actions.** `docs/samples/linux.txt` was taken in a container with no active TCP/UDP connections at capture time (`euid 0`, i.e. privileged) — this is an empty result, not a failure; the plugin has no placeholder-row convention (see Outputs) so an idle host legitimately shows nothing.
3. **`/proc/[pid]/fd` access on Linux is per-owner, not blanket-readable.** `build_inode_to_pid_map`/`build_socket_and_proc_maps` silently skip a PID whose `fd` directory they can't open (`netstat_plugin.cpp:163-165,311-313`); under the agent's default (non-root) Linux identity, sockets owned by other users resolve `pid=-1` in `netstat_list` and empty `process_name`/`process_path` in `attribution`, with no status flagging the gap. The captured sample ran as root in a container and can't show this.
4. **TCP state name sets differ slightly per OS.** Linux's `tcp_state_str` has no `CLOSED`; Windows's `tcp_state_str_win` alone has `DELETE_TCB`; only Linux has a plain `CLOSE` (`netstat_plugin.cpp:76-103,453-482`; `macos_socket_walk.hpp:54-82`). A consumer matching on exact state strings across a mixed fleet should treat the set as a per-OS union, not one fixed enum.
5. **`attribution`'s macOS dedup is deliberate, not inherited by accident.** `enumerate_and_stream_attribution` explicitly passes `dedup=true` to match `netstat_list`'s semantics; the retired `sockwho` used the opposite (one row per fd-holder). Do not revert this to `dedup=false` to restore sockwho's old shape (`netstat_plugin.cpp:429-435`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/netstat/src/netstat_parsers.hpp` · `agents/plugins/netstat/src/netstat_plugin.cpp`
- Definitions: `content/definitions/netstat.yaml` · `content/definitions/netstat_attribution.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/agent/test_netstat_attribution.cpp` · `tests/unit/test_netstat_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
