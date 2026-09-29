# users

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports logged-on users, sessions, local accounts, admin group members, group membership, primary user, and session history |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (device.users.logged_on, device.users.sessions, device.users.local_users, device.users.local_admins, device.users.group_members, device.users.primary_user, device.users.session_history) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `group_members` (definition `device.users.group_members`) · `local_admins` (definition `device.users.local_admins`) · `local_users` (definition `device.users.local_users`) · `logged_on` (definition `device.users.logged_on`) · `primary_user` (definition `device.users.primary_user`) · `session_history` (definition `device.users.session_history`) · `sessions` (definition `device.users.sessions`) |
| **Security** | securable `UserManagement` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

All seven actions are reads (`Mutability::None` on every leg); nothing in this plugin creates, deletes, or modifies an account, session, or group. `logged_on`/`sessions` answer "who is on this box right now" from the OS's live session table (utmp, WTS, or `who`/`w`). `local_users`/`local_admins`/`group_members` enumerate account and group membership from the OS's own directory (passwd/group, Directory Services, or the Windows Net APIs) — `group_members` takes an arbitrary group name as a parameter, `local_admins` is a fixed lookup of the built-in admin group. `primary_user` and `session_history` both mine login history — the Security event log on Windows, `last` on Linux/macOS — the former reducing it to one answer (the most-frequent account), the latter returning it as time-ordered rows. On Linux/macOS every OS-tool invocation goes through a bounded, no-shell argv runner (`run_tool`, ADR-3002 rung 2) with a 10s deadline; a tool that fails to spawn, times out, or is killed reports itself through the ABI4 result-status seam rather than surfacing as a silent empty list.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: UserManagement.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[users.execute]
  EX --> WIN[Windows leg<br/>WTSEnumerateSessionsW · NetUserEnum<br/>NetLocalGroupGetMembers · wevtapi]
  EX --> MAC[macOS leg<br/>utmp-free: who/w/last/dscl argv]
  EX --> LIN[Linux leg<br/>utmp · getgrnam/getpwuid · lastlog/last/w argv]
  WIN & MAC & LIN --> ROWS[pipe rows +<br/>typed result status] --> RS[(ResponseStore<br/>90-day retention)]
  RS --> API[REST /api/responses<br/>· MCP get_definition/execute_instruction]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `group_members` | ✅ supported · rung 1 · NetLocalGroupGetMembers | ✅ supported · rung 2 · runner argv 'dscl . -read /Groups/<name> GroupMembership' | ✅ supported · rung 1 · getgrnam + /etc/passwd primary-group scan |
| `local_admins` | ✅ supported · rung 1 · NetLocalGroupGetMembers | ✅ supported · rung 2 · runner argv 'dscl . -read /Groups/admin GroupMembership' | ✅ supported · rung 1 · getgrnam(sudo/wheel) + getpwuid(0) |
| `local_users` | ✅ supported · rung 1 · NetUserEnum | ✅ supported · rung 2 · runner argv 'dscl . -list/-read UserShell/RealName' + 'last -y -1 <user>' per account | ✅ supported · rung 2 · /etc/passwd read + runner argv 'lastlog -u <user>' per account |
| `logged_on` | ✅ supported · rung 1 · WTSEnumerateSessionsW + WTSQuerySessionInformationW | ✅ supported · rung 2 · runner argv 'who' | ✅ supported · rung 1 · utmp (setutent/getutent) |
| `primary_user` | ✅ supported · rung 1 · wevtapi (EvtQuery/EvtRender, Security 4624) | ✅ supported · rung 2 · runner argv 'last' (max_lines=200 cap) | ✅ supported · rung 2 · runner argv 'last -F' (max_lines=200 cap) |
| `session_history` | 🟡 constrained · rung 1 · wevtapi (EvtQuery/EvtRender, Security 4624/4634) | ✅ supported · rung 2 · runner argv 'last -n <count>' | ✅ supported · rung 2 · runner argv 'last -F -n <count>' |
| `sessions` | ✅ supported · rung 1 · WTSEnumerateSessionsW + WTSQuerySessionInformationW | ✅ supported · rung 2 · runner argv 'w -h' | ✅ supported · rung 2 · runner argv 'w -h' |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`primary_user` / Windows** — falls back to a native ProfileList registry enumeration (no login count) when the Security channel is inaccessible
- **`session_history` / Windows** — requires an elevated token to read the Security channel; reports an error otherwise
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | **None** for the other six actions (WTS/NetAPI calls succeed under the daemon's own account). `session_history` (and `primary_user`'s Security-log path) needs an elevated token to read the Security channel — an unelevated read reports `PERMISSION_DENIED`/`CONSTRAINED`/`UNAVAILABLE` depending on the failure (`users_plugin.cpp:234-253`) and `primary_user` still answers via the ProfileList fallback. | 2026-09-07, bare-metal, SYSTEM | `session_history`/`primary_user` set a typed result status (see Result status below) and emit an `error`-prefixed row naming the cause |
| macOS | agent daemon, unprivileged | **None.** Every leg is either an IOKit-free `dscl`/`who`/`w`/`last` argv call or the shared `SCDynamicStoreCopyConsoleUser` console-user read — no elevated open. | 2026-09-07, bare-metal, euid 501 (jsmith) | a spawn/timeout is forwarded via `forward_runner_failure` as `UNAVAILABLE`/`CONSTRAINED`; the action falls back to its own "unknown"/error row text |
| Linux | agent daemon (no row in `docs/agent-privilege-model.md`) | **None** for the native legs (utmp, `getgrnam`, `getpwuid`). `local_users`/`primary_user`/`session_history` also shell out to `lastlog`/`last`, which need to be present on `$PATH` — the 2026-09-06 container capture had neither installed, and both actions degraded to `UNAVAILABLE`/`PARTIAL`. | 2026-09-06, container, euid 0 | a missing/failed tool is forwarded via `forward_runner_failure` as `UNAVAILABLE`/`CONSTRAINED`; native legs (`logged_on`, `local_admins`, `group_members`) are unaffected |

Binaries/subprocesses: Linux — `w`, `lastlog`, `last` (probed via `probe_tool_path`, direct argv, no shell). macOS — `who`, `w`, `last`, `dscl`, and `/usr/bin/env` (used only to pin `LC_ALL=C` ahead of `last -y`, still a plain exec, not a shell). Windows — none; every leg is a native Win32/WTS/NetAPI/wevtapi call. No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `device.users.group_members` | `group` | string | yes | - | minLength 1 · maxLength 256 | Name of the local group to enumerate members for (e.g., "Administrators", "Remote Desktop Users", "sudo"). |
| `device.users.session_history` | `count` | string | no | 50 | pattern: ^[0-9]+$ | Maximum number of session records to return, as a digit string (e.g. "100"); values outside 1-500 are clamped back to the default of 50. |
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per record, discriminated by a literal first field (`user`, `session`, `local_user`, `admin`, `group_member`, `primary_user`, or `session_history`). Unlike some collector plugins, `logged_on`/`sessions`/`group_members` emit **zero rows**, not a placeholder, when there is nothing to report (an empty Windows/Linux `logged_on` and `sessions` capture is exactly this case — see Sample output) — the empty result is legitimate on its own and is not itself a failure signal; only the typed result status (below) tells a genuinely degraded read apart from a clean empty one. A query-level problem (missing/invalid parameter, tool not found, group not found) instead emits a single `<action>|error|<message>` row. `local_users` additionally varies its own field count by OS: Linux and Windows rows carry 4 data fields, macOS rows carry 5 (`console_state` is appended, not padded in with a placeholder) — `users_plugin.cpp:800-806`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.users.group_members` — `member_name|group_name|member_type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `member_name` | string | - | Windows, Linux, macOS | `Alex` | The account (or nested group, on Windows) belonging to the queried group. Values: free text. |
| `group_name` | string | - | Windows, Linux, macOS | `Administrators` | The group name from the "group" parameter, echoed back on every row. Values: free text. |
| `member_type` | string | - | Windows, Linux, macOS | `user` | The kind of membership. Values: user, primary_group (Linux only); Windows: user, group, well_known_group, alias. |

**`device.users.local_admins` — `member_name|member_type|domain_or_group`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `member_name` | string | - | Windows, Linux, macOS | `Alex` | The name of an account or group belonging to the local admin membership. Values: free text. |
| `member_type` | string | - | Windows, Linux, macOS | `user` | The kind of member. Values: user (always on Linux/macOS); Windows: user, group, well_known_group, alias, unknown. |
| `domain_or_group` | string | - | Windows, Linux, macOS | `DESKTOP-04DNSIG` | The domain owning the member (Windows), or the source group/account name (Linux "sudo"/"wheel"/"root", macOS literal "admin"). Values: free text. |

**`device.users.local_users` — `username|enabled|last_logon|description|console_state`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows, Linux, macOS | `Alex` | The local account's username. Values: free text. |
| `enabled` | bool | - | Windows, Linux, macOS | `true` | Whether the account is enabled. Values: true, false. |
| `last_logon` | string | - | Windows, Linux, macOS | `2026-09-07 11:08:37` | The account's most recent login timestamp, or a sentinel when unknown or never logged in. Values: "YYYY-MM-DD HH:MM:SS", "Never", "unknown". |
| `description` | string | - | Windows, Linux, macOS | `Built-in account for administering the computer/domain` | The account's comment/description text (Windows comment, macOS RealName, Linux GECOS field), or "-" when empty. Values: free text or "-". |
| `console_state` | string | - | macOS | `true` | Tri-state flag for whether this account is the current GUI/console-login user; the field is entirely absent (not empty) on Linux and Windows. Values: true, false, unknown. |

**`device.users.logged_on` — `username|domain|logon_type|session_id`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows, Linux, macOS | `alex` | The account name of a currently logged-on user. Values: free text. |
| `domain` | string | - | Windows, Linux, macOS | `local` | The host or domain the session belongs to, or the literal "local" when it has none. Values: hostname/domain or the literal "local". |
| `logon_type` | string | - | Windows, Linux, macOS | `console` | How the session was established. Values: console, remote, RDP (Windows only). |
| `session_id` | string | - | Windows, Linux, macOS | `console` | The session's terminal identifier — a utmp line name (Linux), a tty (macOS), or a numeric WTS session ID (Windows). Values: free text. |

**`device.users.primary_user` — `username|login_count|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows, Linux, macOS | `Alex` | The account with the most login events in the examined history, or "unknown" when none could be determined. Values: free text or "unknown". |
| `login_count` | int32 | - | Windows, Linux, macOS | `118` | The number of login events counted for this user; "0" for the Windows ProfileList fallback, which carries no count. Values: integer. |
| `source` | string | - | Windows, Linux, macOS | `event_log_4624` | How the answer was derived. Values: last (Linux/macOS); event_log_4624, profile_list (Windows); free text on a query failure. |

**`device.users.session_history` — `username|event_type|logon_type|source|timestamp|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows, Linux, macOS | `Alex` | The account named in the record. Values: free text. |
| `event_type` | string | - | Windows, Linux, macOS | `logoff` | Windows: "logon" or "logoff". Linux/macOS: actually the session's tty, not an event-type label — see the plugin README's Caveats. Values: logon, logoff (Windows); a tty name (Linux/macOS). |
| `logon_type` | string | - | Windows, Linux, macOS | `network` | Windows: the mapped LogonType name or raw numeric code, empty when absent. Linux/macOS: actually last's host/source token, usually empty for a local session. Values: interactive, network, batch, service, unlock, network_cleartext, new_credentials, remote_interactive, cached_interactive, or a raw numeric code (Windows); free text, often empty (Linux/macOS). |
| `source` | string | - | Windows, Linux, macOS | `-` | Windows: the event's IpAddress, or "-". Linux/macOS: actually the derived console/remote/system classification, not a network source. Values: an IP address or "-" (Windows); console, remote, system (Linux/macOS). |
| `timestamp` | string | - | Windows, Linux, macOS | `2026-09-07T10:08:37.8345208Z` | Windows: the event's TimeCreated, full-precision UTC. Linux/macOS: actually the completed/active/crash status word, not a timestamp — the real date/time is embedded in "detail". Values: ISO-8601 UTC (Windows); completed, active, crash (Linux/macOS). |
| `detail` | string | - | Windows, Linux, macOS | `4634` | Windows: the raw EventID text. Linux/macOS: the remainder of the 'last' line verbatim (weekday, date, time, and logout/duration or "still logged in"). Values: free text. |

**`device.users.sessions` — `session_id|username|state|client|idle`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `session_id` | string | - | Windows, Linux, macOS | `console` | The session's controlling tty (Linux/macOS) or numeric WTS session ID (Windows). Values: free text. |
| `username` | string | - | Windows, Linux, macOS | `alex` | The account that owns this session. Values: free text. |
| `state` | string | - | Windows, Linux, macOS | `Active` | The session's connection state. Values: Active (Linux/macOS, always); Windows: Active, Connected, Disconnected, Idle, Listen, Other. |
| `client` | string | - | Windows, Linux, macOS | `-` | The remote host the session connects from ('w' FROM column) or the RDP client name on Windows; "-" when none. Values: free text or "-". |
| `idle` | string | - | Windows, Linux, macOS | `13:35` | Idle time as reported by 'w' on Linux/macOS; always the literal "0" on Windows, where idle-time decoding is unimplemented. Values: free text (Linux/macOS) or the literal "0" (Windows). |
<!-- END GENERATED -->

### Result status

`ctx.set_result_status` is called explicitly twice (both on Windows), and indirectly on every POSIX `run_tool()` call via `forward_runner_failure`/`classify_runner_failure` (`agents/core/include/yuzu/agent/runner_status.hpp:44-97`), which latches on the **first** non-`exited` runner outcome per call (`status_forwarded`, e.g. `users_plugin.cpp:340-347`).

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (no call made) | UNKNOWN | — | default; every OS tool/native call `exited` (any exit code) — this is the status on every clean or intentionally-empty read, e.g. every sample's `logged_on`/`sessions` |
| `OK` | PARTIAL | `subprocess_runner:line_limit` | a POSIX `run_tool()` call hits its `max_lines` cap (`primary_user`'s 200-line bound) before the tool finished — deliberate truncation, not a failure |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:deadline` / `subprocess_runner:cancelled` / `subprocess_runner:signaled` | a POSIX tool exceeds the 10s `kUsersCmdDeadline` or is killed/signalled mid-run |
| `UNAVAILABLE` | PARTIAL | `subprocess_runner:spawn_error` | `probe_tool_path` found no binary, or the spawn itself failed — the 2026-09-06 Linux container sample (`lastlog`/`last` missing) |
| `PERMISSION_DENIED` | PARTIAL | `users_win_events:access_denied` | Windows Security-channel query denied (`session_history`, `primary_user`'s event-log path) |
| `UNAVAILABLE` | PARTIAL | `users_win_events:channel_not_found` | Windows Security channel missing/uninstalled |
| `CONSTRAINED` | PARTIAL | `users_win_events:evt_next_timeout` | Windows `EvtNext` timed out mid-query |
| `UNAVAILABLE` | PARTIAL | `users_win_events:evt_query_failed` | any other Windows `EvtQuery`/`EvtNext` error |

### Where the data goes

- **Instruction result only.** Rows travel the agent's mTLS gRPC channel as the command response and land in the `ResponseStore` (90-day default retention, `server/core/src/response_store.hpp:153`), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — nothing in this plugin runs on a schedule; `gather.ttlSeconds` (60–300s per definition) is a repeat-query cache TTL, not a cron trigger.
- **Sensitivity.** Every action's rows name a specific account: `username`/`member_name` (local or logged-on account names, including admin-group members), `domain`/`domain_or_group` (Windows domain or hostname), and `session_history`'s Windows leg carries the raw Security-log event detail for that account's logons/logoffs. `session_id`/`client` can carry a remote hostname or RDP client name — a device identifier for whatever machine connected in. No column carries installed-software data.
- **Siblings:** `core.crossplatform.users` (`content/definitions/users_set.yaml`, "User Account Management") is the mutating counterpart in a separate plugin — this plugin never creates, deletes, disables, or reassigns an account.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.users.session_history")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 5734018da5be

```
== action=logged_on
[result_status] UNDECLARED / UNKNOWN

== action=sessions
[result_status] UNDECLARED / UNKNOWN

== action=local_users
local_user|Administrator|false|2021-10-14 11:15:58|Built-in account for administering the computer/domain
local_user|Alex|true|2026-09-07 11:08:37|-
local_user|CodexSandboxOffline|true|Never|-
local_user|CodexSandboxOnline|true|Never|-
local_user|DefaultAccount|false|Never|A user account managed by the system.
local_user|Guest|false|Never|Built-in account for guest access to the computer/domain
local_user|WDAGUtilityAccount|false|Never|A user account managed and used by the system for Windows Defender Application Guard scenarios.
[result_status] UNDECLARED / UNKNOWN

== action=local_admins
admin|Administrator|user|DESKTOP-04DNSIG
admin|Alex|user|DESKTOP-04DNSIG
[result_status] UNDECLARED / UNKNOWN

== action=group_members group=Administrators
group_member|Administrator|Administrators|user
group_member|Alex|Administrators|user
[result_status] UNDECLARED / UNKNOWN

== action=primary_user
primary_user|Alex|118|event_log_4624
[result_status] UNDECLARED / UNKNOWN

== action=session_history
session_history|Alex|logoff|network|-|2026-09-07T10:08:37.8345208Z|4634
session_history|sshd_6888|logoff|service|-|2026-09-07T10:08:37.8345130Z|4634
session_history|Alex|logon|network|-|2026-09-07T10:08:37.5888936Z|4624
session_history|Alex|logoff|network|-|2026-09-07T10:08:37.5439466Z|4634
session_history|Alex|logon|network|-|2026-09-07T10:08:37.5436517Z|4624
session_history|sshd_6888|logon|service|-|2026-09-07T10:08:37.4636668Z|4624
session_history|Alex|logoff|network|-|2026-09-07T10:08:06.3059890Z|4634
session_history|sshd_4452|logoff|service|-|2026-09-07T10:08:06.3059802Z|4634
session_history|Alex|logon|network|-|2026-09-07T10:08:06.0444630Z|4624
session_history|Alex|logoff|network|-|2026-09-07T10:08:05.9047716Z|4634
session_history|Alex|logon|network|-|2026-09-07T10:08:05.9044759Z|4624
session_history|sshd_4452|logon|service|-|2026-09-07T10:08:05.8249284Z|4624
… 12 of 50 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 5734018da5be

```
== action=logged_on
user|jsmith|local|console|console
[result_status] UNDECLARED / UNKNOWN

== action=sessions
session|console|jsmith|Active|-|13:35
[result_status] UNDECLARED / UNKNOWN

== action=local_users
local_user|jsmith|true|2026-09-06 21:20:00|Jordan Smith|true
local_user|root|true|2026-09-06 21:15:00|System Administrator|false
[result_status] UNDECLARED / UNKNOWN

== action=local_admins
admin|root|user|admin
admin|jsmith|user|admin
admin|_mbsetupuser|user|admin
[result_status] UNDECLARED / UNKNOWN

== action=group_members group=admin
group_member|root|admin|user
group_member|jsmith|admin|user
group_member|_mbsetupuser|admin|user
[result_status] UNDECLARED / UNKNOWN

== action=primary_user
primary_user|jsmith|35|last
[result_status] UNDECLARED / UNKNOWN

== action=session_history
session_history|jsmith|console|Sun|console|active|Sep  6 21:20   still logged in
session_history|reboot|time|Sun|system|completed|Sep  6 21:19
session_history|shutdown|time|Sun|system|completed|Sep  6 21:15
session_history|root|console|Sun|console|completed|Sep  6 21:15 - shutdown  (00:00)
session_history|jsmith|ttys000|Sun|remote|completed|Sep  6 18:53 - 18:53  (00:00)
session_history|jsmith|ttys000|Sun|remote|completed|Sep  6 18:53 - 18:53  (00:00)
session_history|jsmith|ttys000|Mon|remote|completed|Aug 31 09:30 - 09:30  (00:00)
session_history|jsmith|console|Mon|console|completed|Aug 31 09:30 - 21:14 (6+11:44)
session_history|reboot|time|Mon|system|completed|Aug 31 09:29
session_history|jsmith|ttys000|Fri|remote|completed|Aug 28 09:51 - 09:51  (00:00)
session_history|jsmith|console|Fri|console|completed|Aug 28 09:51 - 22:26  (12:35)
session_history|reboot|time|Fri|system|completed|Aug 28 09:50
… 12 of 50 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 5734018da5be

```
== action=logged_on
[result_status] UNDECLARED / UNKNOWN

== action=sessions
[result_status] UNDECLARED / UNKNOWN

== action=local_users
local_user|root|true|unknown|root
local_user|nobody|false|unknown|nobody
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error

== action=local_admins
admin|root|user|root
[result_status] UNDECLARED / UNKNOWN

== action=group_members group=sudo
[result_status] UNDECLARED / UNKNOWN

== action=primary_user
primary_user|unknown|0|last command failed
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error

== action=session_history
session_history|error|last command failed
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`session_history`'s Linux/macOS fields do not line up with the declared schema.** The Windows leg (`users_win_events.hpp:329-333`) fills `event_type|logon_type|source|timestamp|detail` correctly, but the Linux/macOS leg (`users_plugin.cpp:1279-1305`, `:1328-1352`) does a raw `ls >> user >> tty >> source` against `last`'s columns and writes `(tty, source-token, derived-console/remote/system, completed/active/crash, free-text-remainder)` into those same five slots. The real timestamp only exists as unparsed free text inside `detail`. Do not consume this action's Linux/macOS output as if it matched the Windows/YAML field semantics.
2. **`sessions`' idle time is always `0` on Windows.** The code queries `WTSSessionInfo` but never decodes the returned `IdleTime`, explicitly "for simplicity" (`users_plugin.cpp:511-525`). Linux/macOS idle text (via `w`) is real.
3. **Windows-only exclusion filter.** `primary_user`/`session_history`'s Windows leg drops machine accounts (`...$`) and `SYSTEM` (`users_win_events.hpp:236-237`); the Linux/macOS `last`-based leg instead drops `reboot`/`shutdown`/`wtmp` boilerplate lines. A description that says "excludes machine accounts and SYSTEM" without an OS qualifier is describing the Windows leg only.
4. **`local_users`' Linux last-logon lookup is gated by `is_safe_identifier`.** A username outside `[A-Za-z0-9._-]` (most commonly an AD/Samba machine account ending `$`) skips the `lastlog -u` call and reports `last_logon=unknown`; the account row is still emitted (`users_plugin.cpp:590-606`).
5. **A minimal Linux image can be missing `lastlog`/`last` entirely.** The 2026-09-06 container capture had neither on `$PATH`: `local_users` degraded to `unknown` last-logons and `UNAVAILABLE`, and `primary_user`/`session_history` failed outright with the same status — while `logged_on` (utmp), `local_admins`/`group_members` (native `getgrnam`), and `sessions` (`w`, which was present) were unaffected. The same capture's `group_members group=sudo` returned zero rows and no `error` row: `getgrnam` only emits `group_member|error|Group not found: <name>` and returns 1 when the group doesn't exist (`users_plugin.cpp:971-975`); zero rows with rc 0 means the `sudo` group existed but had no explicit members and no `/etc/passwd` account with a matching primary GID (`users_plugin.cpp:976-1008`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/users/src/users_macos_last.hpp` · `agents/plugins/users/src/users_plugin.cpp` · `agents/plugins/users/src/users_win_events.hpp`
- Definitions: `content/definitions/users.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: `tests/unit/test_users_macos_last.cpp` · `tests/unit/test_users_posix_actions.cpp` · `tests/unit/test_users_win_events.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
