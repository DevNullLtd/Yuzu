# ioc

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Indicator of Compromise checking — match IOCs against local endpoint state |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (security.ioc.check) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `check` (definition `security.ioc.check`) |
| **Security** | securable `Security` · operation Read · risk Medium · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`check` is the plugin's only action. It takes five optional, comma-separated parameters (`ip_addresses`, `domains`, `file_hashes`, `file_paths`, `ports`); if none are supplied it writes one `error|none|false|No IOC parameters provided` row and returns 1 without ever writing the column-header line (`ioc_plugin.cpp:802-809`). Otherwise it writes a literal `type|value|matched|detail` header line (`ioc_plugin.cpp:809`), then runs each supplied check in a fixed order — IP, domain, hash, path, port — reporting progress at 30/50/70/90/100% (`ioc_plugin.cpp:817-847`). Active connections are enumerated once and shared by the IP and port checks (`ioc_plugin.cpp:812-815`). Domain checking is two different mechanisms depending on OS: the Windows leg queries the live DNS resolver cache via the undocumented `DnsGetCacheDataTable` export; Linux and macOS instead do a substring search over `/etc/hosts` (`ioc_plugin.cpp:392-425,604-629`). Hash checking never touches an IOC feed or reputation service — it computes SHA-256 (a from-scratch implementation, no OpenSSL) over every path in `file_paths` and compares against each requested hash (`ioc_plugin.cpp:452-549,633-674`); without `file_paths` every requested hash reports unmatched. The plugin deliberately does no network calls, no threat-intel lookup, and no quarantine or remediation action — it only reports what is locally observable at call time.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Security.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[ioc.execute]
  EX --> WIN[Windows leg<br/>GetExtendedTcpTable/UdpTable<br/>DnsGetCacheDataTable<br/>GetFileAttributesEx-family]
  EX --> MAC[macOS leg<br/>libproc via macos_socket_walk.hpp<br/>/etc/hosts + stat]
  EX --> LIN[Linux leg<br/>/proc/net/tcp[6] + /etc/hosts + stat]
  WIN & MAC & LIN --> ROWS[pipe rows +<br/>UNDECLARED status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `check` | ✅ supported · rung 1 · iphlpapi_dnsapi | ✅ supported · rung 1 · libproc | ✅ supported · rung 1 · procfs |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`check` / macOS** — UDP rows carry an empty state (no fabricated "LISTEN") — a real UDP listener still matches a port check, but its detail text differs from a TCP match; a port shared by more than one process (SO_REUSEPORT, prefork) reports the pid of one arbitrarily-chosen owner in its match detail, not every owner
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | no `docs/agent-privilege-model.md` row; sample captured as `SYSTEM` | None observed — `GetExtendedTcpTable`/`GetExtendedUdpTable`, `DnsGetCacheDataTable`, and `GetFileAttributesEx`-family calls read attributes only (`ioc_plugin.cpp:141-242,393-425,436-446`) | 2026-09-07, bare-metal, Windows NT 10.0.26200.0 x64 (`docs/samples/windows.txt:1`) | Silent degradation, not an error: a failed `GetExtendedTcpTable`/`UdpTable` call is skipped with no rows added (`ioc_plugin.cpp:141-179,222-242`), so an IP/port check that can't read the connection table reports "not found" rather than a typed failure — the plugin never calls a result-status API |
| macOS | no privilege-model row; sample captured at euid 501 (jsmith), unprivileged | None observed — the shared `libproc` walk and `/etc/hosts`/`stat()` checks ran successfully unprivileged in the sample | 2026-09-07, bare-metal, macOS 26.6.2 arm64 (`docs/samples/macos.txt:1`) | Same silent-degradation pattern as Windows; no typed failure status exists to distinguish it |
| Linux | no privilege-model row; sample captured at euid 0, container | None observed — `/proc/net/tcp[6]`, `/etc/hosts`, and `stat()` are world-readable | 2026-09-07, container, Debian GNU/Linux 13 aarch64 (`docs/samples/linux.txt:1`) | Same silent-degradation pattern; additionally, PID is never available from `/proc/net/tcp` parsing on Linux (`ioc_plugin.cpp:341`), so IP/port match details there never name a process |

No external binaries or subprocesses on any OS — all three legs read OS-native tables/files directly (`ioc_plugin.cpp:21-25`). No outbound network access; the Windows DNS check reads the local resolver cache, it does not resolve or query anything.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `security.ioc.check` | `ip_addresses` | string | no | - | - | Comma-separated list of IP addresses (e.g. `192.168.1.100`) to check against active connections' local and remote addresses. Windows and macOS enumerate TCP and UDP; Linux enumerates TCP only (no /proc/net/udp read). |
| `security.ioc.check` | `domains` | string | no | - | - | Comma-separated list of domain names (e.g. `evil.example.com`) to check. On Windows this queries the DNS resolver cache; on Linux/macOS it is a substring search over /etc/hosts lines (comments stripped), so a short domain can match more than intended. |
| `security.ioc.check` | `file_hashes` | string | no | - | - | Comma-separated list of SHA-256 hashes (e.g. `2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae`), lower- or upper-case. Compared against every file in file_paths; without file_paths every hash reports unmatched with "No target file paths specified for hash comparison". |
| `security.ioc.check` | `file_paths` | string | no | - | - | Comma-separated list of file paths (e.g. `C:\bad.exe` or `/tmp/bad.bin`) to check for existence and size. Also used as the target set for file_hashes comparison. |
| `security.ioc.check` | `ports` | string | no | - | - | Comma-separated list of port numbers (e.g. `4444`) to check against the same connection table as ip_addresses — Linux sees TCP listeners only, Windows and macOS see TCP and UDP. |
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, `type|value|matched|detail` (`ioc_plugin.cpp:809`). Unlike the collector-style plugins, the field-name header is itself written as the first output line whenever at least one check ran — it is not a data row and downstream consumers keying on `type` should skip it. Any literal `|` in `value` or `detail` is escaped to `\|` (`ioc_plugin.cpp:107-118`). There is no empty-row placeholder: a parameter that matches nothing simply gets `matched=false` with an explanatory `detail`, and a `check` call with no parameters at all skips the header and emits exactly one `error` row instead (`ioc_plugin.cpp:802-809`).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`security.ioc.check` — `type|value|matched|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `type` | string | `ip` `domain` `hash` `file` `port` `error` | Windows, Linux, macOS | `ip` | Which IOC category this row checked. `error` appears only once, in place of all rows, when no IOC parameter was provided at all. |
| `value` | string | - | Windows, Linux, macOS | `127.0.0.1` | The IOC value that was checked, copied from the input parameter with any literal `\|` escaped to `\\|`. Values: free text. |
| `matched` | bool | - | Windows, Linux, macOS | `true` | Whether the IOC was found on this endpoint. Always `false` for the single `error` row. Values: true, false. |
| `detail` | string | - | Windows, Linux, macOS | `Found in /etc/hosts` | Human-readable explanation of the match or non-match (e.g. which PID owns a connection, or why a check could not run). Values: free text. |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /` (`ioc_plugin.cpp` has no `set_result_status`/`yuzu_ctx_set_result_status` call anywhere in the file; confirmed against `docs/samples/windows.txt:7`, `macos.txt:7`, `linux.txt:7`).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention, `response_store.hpp:8`), queryable at `/api/responses/{id}` and aggregatable by `(type, matched)` count per the definition's own `aggregation` block (`content/definitions/ioc.yaml:112-114`).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Nothing runs on a schedule; the plugin executes only when an operator or workflow dispatches `security.ioc.check`.
- **Sensitivity.** `value` is the operator-supplied IOC being checked (an IP, domain, hash, path, or port — not host state), and `detail` can name an owning process id (`pid`) on Windows/macOS matches — no row carries a device serial/hostname, a username, or an installed-software name/version.
- **Siblings:** grouped with `security.quarantine.{isolate,release,status,whitelist}`, `security.certificates.{list,details,delete}`, and `security.sccm.{client_version,site}` under the `core.security.security-response` instruction set (`content/definitions/security_response_set.yaml:20-32`).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("security.ioc.check")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 4c1360bf4eef

```
== action=check ip_addresses=127.0.0.1 domains=localhost ports=22
type|value|matched|detail
ip|127.0.0.1|true|Active connection - ESTABLISHED (pid 6436)
domain|localhost|false|Not in DNS cache
port|22|true|Listening (pid 5148)
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 4c1360bf4eef

```
== action=check ip_addresses=127.0.0.1 domains=localhost ports=22
type|value|matched|detail
ip|127.0.0.1|true|Active connection - LISTEN (pid 20945)
domain|localhost|true|Found in /etc/hosts
port|22|false|No listening service on this port
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-07 · euid 0 · leg-hash 4c1360bf4eef

```
== action=check ip_addresses=127.0.0.1 domains=localhost ports=22
type|value|matched|detail
ip|127.0.0.1|false|Not found in active connections
domain|localhost|true|Found in /etc/hosts
port|22|false|No listening service on this port
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **IP matching includes local bind addresses, not just remote peers.** `check_ip_addresses()` matches an IOC IP against either `conn.local_addr` or `conn.remote_addr` (`ioc_plugin.cpp:575`) — the macOS capture shows `127.0.0.1` reported `matched=true` with detail `Active connection - LISTEN (pid 20945)` (`docs/samples/macos.txt:4`), i.e. a socket merely *bound* to the checked address counts as a match even with no outbound connection to it.
2. **Linux sees TCP only.** `get_connections()` on Linux parses `/proc/net/tcp` and `/proc/net/tcp6` only — there is no `/proc/net/udp` read (`ioc_plugin.cpp:346-351`) — so `ip_addresses`/`ports` checks against a UDP-only listener silently report "not found" on Linux even though the same check would match on Windows or macOS.
3. **Silent degradation on API failure, not a typed error.** If `GetExtendedTcpTable`/`GetExtendedUdpTable` returns a non-`NO_ERROR` status, `get_connections()` simply adds no rows for that table rather than surfacing a failure (`ioc_plugin.cpp:141-179,222-242`); combined with the plugin never setting a result status, a caller cannot distinguish "checked, not present" from "the connection table couldn't be read."
4. **`/etc/hosts` domain matching is a raw substring search.** `check_domains()` on Linux/macOS strips comments then does `line.find(domain)` (`ioc_plugin.cpp:613-621`) — a short or partial domain can match unrelated lines; there is no word-boundary or exact-hostname check.
5. **PID is never available from the Linux TCP parse.** `parse_proc_net()` hard-codes PID 0 for every connection (`ioc_plugin.cpp:341`), so Linux `ip`/`port` match details never name an owning process the way Windows and macOS do.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/ioc/src/ioc_plugin.cpp`
- Definitions: `content/definitions/ioc.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: none found by name
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
