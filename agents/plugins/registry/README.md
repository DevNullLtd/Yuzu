# registry

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Windows Registry -- get, set (six types, verified), delete value, delete key, enumerate, per-user reads |
| **Version** | 2.0.0 |
| **Kind** | Action · mutating · on-demand |
| **Platforms** | Windows ✅ · macOS 🟡 planned · Linux 🟡 planned |
| **Actions** | `delete_key` (definition `windows.registry.delete_key`) · `delete_value` (definition `windows.registry.delete_value`) · `enumerate_keys` (definition `windows.registry.enumerate_keys`) · `enumerate_values` (definition `windows.registry.enumerate_values`) · `get_user_value` (definition `windows.registry.get_user_value`) · `get_value` (definition `windows.registry.get_value`) · `key_exists` (definition `windows.registry.key_exists`) · `list_profiles` (definition `windows.registry.list_profiles`) · `set_value` (definition `windows.registry.set_value`) |
| **Security** | `get_value`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `set_value`: securable `Infrastructure` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval; `delete_value`: securable `Infrastructure` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval; `delete_key`: securable `Infrastructure` · operation Delete · risk Critical · dispatch Destructive · approval gate AdminOrApproval; `key_exists`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `enumerate_keys`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `enumerate_values`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `get_user_value`: securable `Infrastructure` · operation Read · risk Medium · dispatch ReadOnly · approval gate AdminOrApproval; `list_profiles`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: `get_value`: endpoint-admin, endpoint-operator; `get_user_value`: endpoint-admin; `list_profiles`: endpoint-admin, endpoint-operator; `set_value`: endpoint-admin; `enumerate_keys`: endpoint-admin, endpoint-operator; `delete_value`: endpoint-admin; `delete_key`: endpoint-admin; `key_exists`: endpoint-admin, endpoint-operator; `enumerate_values`: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

All nine actions are direct, synchronous Win32 registry calls: there is no scheduled gather. The six read actions (`get_value`, `key_exists`, `enumerate_keys`, `enumerate_values`, `get_user_value`, `list_profiles`) open a key read-only and read or list it; every registry-controlled string they render passes through `sanitize_field` (`|`, CR and LF become `_`), so no read output can contain a line that starts with `audit|`. `get_user_value` resolves the target profile through the same `ProfileList` walk `list_profiles` exposes, reads the live `HKEY_USERS\<SID>` hive if the user is logged in, and falls back to an offline `RegLoadKeyW` mount of `NTUSER.DAT` (under `SeBackup`/`SeRestore` and a process-wide mutex serialising the whole offline arm) only when the user is logged out. The seven `hive`+`key` actions validate through one `parse_target` helper, which also logs (never blocks) access to a few sensitive `HKLM` subtrees via `spdlog::info`.

The three mutating actions (`set_value`, `delete_value`, `delete_key`) share one core (`registry_core.hpp`, over an injected registry; `registry_win.cpp` binds it to `Reg*W`). Each obtains a CHECKED handle for the key, and every step after that -- the previous-value capture, `RegSetValueExW`, the verifying read-back, `RegDeleteValueW`, `NtDeleteKey(h)` -- runs on that handle: nothing re-resolves the path by name, and no handle outlives the command. There are two ways to the handle.

- **The fast open (`HKLM` and `HKU` only).** ONE `RegOpenKeyExW` of the whole path with `REG_OPTION_OPEN_LINK`, then `NtQueryKey(KeyNameInformation)` names the object the handle is bound to. The open is accepted only when that kernel name equals `<root kernel name>\<requested path>` (every byte exact except that A-Z fold, so a name that differs in non-ASCII case, a name that does not fit the 4 KiB buffer and a failed query all decline) and the leaf has no `SymbolicLinkValue`. A registry link before the leaf makes the kernel open the link's TARGET, whose name cannot equal the requested one, so the fast open can only accept the canonical object with no real link traversed; everything else declines to the walk. A `set_value` on an existing key is 7 calls across the plugin's registry seam (`open_path`, `final_name`, the link probe, capture, set, read-back, close; the cached root-name lookup is an eighth), the same at every depth; they are about 7 Win32 calls, because the link probe, the capture and the read-back are each one `RegQueryValueExW` for a value that fits a 256-byte first buffer (a larger value costs one more read). The walk costs about 3 more per path component, plus two name queries.
- **The walk (the reference).** `open_checked` walks the path component by component from the hive root, opening each component from the previous HANDLE with `REG_OPTION_OPEN_LINK` and probing it for `SymbolicLinkValue`: a registry link is refused (`key_is_link`), never followed. A probe only sees the key as it is at that instant, and a link is made in two steps (the key, then its `SymbolicLinkValue`), so the walk also ends on the fast open's test. It reads the canonical kernel name of the FIRST component's handle right after that open (before its probe; it has to end in the requested first component, else `key_is_link`) and of the leaf handle at the end (after the create loop too), and hands the leaf over only when the leaf's name equals the first component's name plus the remaining requested components (A-Z fold). A link completed after its probe, or a component moved away by a rename, leaves the handle bound to an object whose name is not the requested path: the action is refused `key_is_link` and no value is written, and a name that cannot be read is refused with its Win32 token. A link completed during the create loop is the one case where the walk has already written: a create is relative to a handle the kernel parses again, so the keys can land beneath the link's target. A walk that does not hand its leaf over (the name test refuses, a later create fails, or a later create finds its key already there) deletes every key it created, by its own handle, leaf first, so nothing is left (`result=refused`, `created=0`, with the reason it stopped for: `key_is_link`, `concurrent_change` or the Win32 token). The rule is the same without an attacker: a create that fails part-way under a plain parent (say `access_denied` on the second component) also removes the first. A key a create merely opened is closed, never deleted; a key it could not delete (one that now holds another party's key, for example) is reported (`result=failed`, `created=<n>` in the audit line). One derivation serves every hive, `HKCU` and `HKCR` included, and costs two `final_name` calls per walk whatever the depth. It is always used for `HKCU` (it resolves per calling user) and `HKCR` (a merged view of two trees), neither of which has one kernel name to compare with, for a key that is missing, and whenever the fast open declines. It alone produces the verdict token and creates: a missing component is created component-wise from the checked parent, a create that finds the key already there refuses `concurrent_change`, and a creating action never creates a key directly beneath the hive root (`root_level_create`).

The two differ in exactly two ancestor-only cases where the walk is the stricter (see Caveats); in both the write lands on the real requested key, as registry 1.0.0's single open did. A path under `HKLM\SYSTEM\CurrentControlSet`, itself a link to the active control set, is refused on both: write under `HKLM\SYSTEM\ControlSet001` (or the numbered set `Select\Current` names); registry 1.0.0 followed it, reads still do. `set_value` writes any of the six types (`REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_MULTI_SZ`, `REG_QWORD`) from text or exact `data_hex` bytes, reads the value back on the same handle and compares type and bytes; a mismatch fails the action (`verify_mismatch`). `delete_key` refuses a key that has subkeys (`key_has_subkeys`) and otherwise deletes the key by handle with `NtDeleteKey`, never `RegDeleteTreeW`, which follows a registry link met inside a tree; a link at the leaf is opened as the link object, so the delete removes the link and never its target. Its counts are what the key held: `counted_keys|1` and `counted_values|<n>`, with `capped|1` when the value enumeration stopped at its cap of 10,000 nodes, the key plus up to 9,999 values (`counted_values` is then a lower bound; the delete still removes the key with all its values). Every mutating action captures the previous value first and emits ONE `audit|` line (see "Audit line grammar and producer contract").

Code anchors (file and function; line numbers move with every edit): the fast open `open_fast`, the checked walk `open_checked`, its name test `leaf_name_check` and its link probe `probe_link`, the guarded value read `query_value_bounded`, the verifying write `write_value_on`, the by-handle delete `delete_key_on` and the counts in `delete_key_tree` (all in `registry_core.hpp`); the encoders `encode_value`, `validate_key_path` and `render_audit_line` (`registry_parsers.hpp`); the kernel calls `Win32Registry::open_path`, `final_name`, `root_name` and `delete_key_by_handle` (`registry_win.cpp`); the server-side binding `registry_audit_events_for_frame` (`server/core/src/plugin_result_audit.hpp`).

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Infrastructure.Read/Write/Delete<br/>ExecuteGate: None or AdminOrApproval]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[registry.execute]
  EX --> WIN[Windows leg<br/>fast open (HKLM, HKU) or checked-handle walk<br/>capture, mutate, read back<br/>NtDeleteKey by handle]
  EX --> MAC[macOS leg<br/>PLANNED stub: honest 'unsupported' sentinel]
  EX --> LIN[Linux leg<br/>PLANNED stub: honest 'unsupported' sentinel]
  WIN & MAC & LIN --> ROWS[rows / lines + audit line +<br/>result status]
  ROWS -- CommandResponse<br/>action stamped --> RS[(ResponseStore)]
  ROWS -- registry.write rows --> AU[(AuditStore)]
  RS --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `delete_key` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `delete_value` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `enumerate_keys` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `enumerate_values` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `get_user_value` | ✅ supported · rung 1 · win32_registry+hive_mount | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `get_value` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `key_exists` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `list_profiles` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `set_value` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`delete_key` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_key` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`enumerate_keys` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`enumerate_keys` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`enumerate_values` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`enumerate_values` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`get_user_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`get_user_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`get_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`get_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`key_exists` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`key_exists` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`list_profiles` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`list_profiles` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`set_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`set_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | Writes against `HKLM\*` need the service account in `Administrators`; `HKCU\*` needs no elevation. `get_user_value` uses the offline-hive fallback only when the target user is logged out: it needs `SeBackupPrivilege`+`SeRestorePrivilege`, already granted to the service account, so there is no new grant; the live-hive path, the machine-hive writes and `list_profiles` need no elevated privilege beyond the key's own ACL. `NtDeleteKey` and `NtQueryKey` (ntdll) need no privilege beyond `DELETE` on the key and a handle the caller already holds. | 2026-10-17, bare-metal, elevated interactive user: the nine actions captured (`docs/samples/windows.txt`); the write arms also run in `tests/unit/test_registry_write_local_dispatcher.cpp` and `tests/unit/test_registry_win_internals.cpp` on elevated Windows runs | `error\|key not found` / `error\|value not found` (reads); the mutating actions name the cause: `error\|access_denied`, `key_not_found`, `value_not_found`, `key_is_link`, `key_has_subkeys`, `concurrent_change`, `root_level_create`, `verify_mismatch`, `invalid_key_path`, `invalid_value_name`, `invalid_type`, `invalid_data`, `value_overflow` or `win32:<code>` |
| macOS | n/a: plugin loads but every action is the honest `unsupported` stub (plist support is PLANNED) | n/a | 2026-10-17, bare-metal, euid 501 | always `registry\|unsupported\|Windows registry has no macOS equivalent; use defaults/plists`, rc 0 (reads) / rc 1 (mutators) |
| Linux | n/a: plugin loads but every action is the honest `unsupported` stub (dconf support is PLANNED) | n/a | 2026-10-17, container, euid 0 | always `registry\|unsupported\|Windows registry is not available on this platform`, rc 0 (reads) / rc 1 (mutators) |

No external binaries, no subprocesses, no network access: every call is an in-process Win32 `Reg*W`/`AdjustTokenPrivileges`/`NtDeleteKey`/`NtQueryKey` call (`registry_win.cpp`, `agents/shared/win_profiles.hpp`, `agents/shared/win_reg_handle.hpp`).

**`HKCU` is a per-process alias, not a real hive.** `parse_hive` maps `"HKCU"` straight to the predefined handle `HKEY_CURRENT_USER`, which Win32 resolves against the calling process's own token rather than any hive path the plugin names. The agent runs as `SYSTEM`/LocalSystem with no interactively logged-on user context, so every `hive=HKCU` call in this plugin resolves to `HKEY_USERS\.DEFAULT`. An operator who needs a specific user's hive reads it with `get_user_value` (or `list_profiles` + an explicit `sid`) or, while the user's hive is loaded, writes it through `hive=HKU` with the user's SID as the first key component, never `hive=HKCU`; `HKCU` and `HKCR` always take the component walk. Writes use the 64-bit registry view only (no `KEY_WOW64_*` flag, x64 agent: reach `WOW6432Node` by its name); an `HKCR` write lands in the merged view's backing hive while its audit row says `HKCR`.

**Controlling the write actions.** There is no built-in key policy (no protected-key denylist, by owner decision): the controls are the `endpoint-admin` role with approval (`AdminOrApproval`) on every mutating definition, the `registry.write` audit row, and the per-action kill switch (`PUT /api/v1/plugin-config/registry/kill-switch`, add `?action=set_value` for one action; `PluginConfig:Write`; no row means allowed). A scheduled execution can fan an approved write out to many devices.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `windows.registry.delete_key` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive containing the key, e.g. "HKCU". |
| `windows.registry.delete_key` | `key` | string | yes | - | - | Registry key path to delete, relative to the hive root. |
| `windows.registry.delete_value` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive containing the value, e.g. "HKCU". |
| `windows.registry.delete_value` | `key` | string | yes | - | - | Registry key path containing the value, relative to the hive root. |
| `windows.registry.delete_value` | `name` | string | yes | - | - | The value name to delete. |
| `windows.registry.enumerate_keys` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive to enumerate, e.g. "HKLM". |
| `windows.registry.enumerate_keys` | `key` | string | yes | - | - | Registry key path relative to the hive root, e.g. "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion". |
| `windows.registry.enumerate_values` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive to enumerate, e.g. "HKLM". |
| `windows.registry.enumerate_values` | `key` | string | yes | - | - | Registry key path relative to the hive root. |
| `windows.registry.get_user_value` | `username` | string | no | - | maxLength 256 | Windows profile folder name to resolve via ProfileList (see list_profiles), matched case-insensitively. This is not always the same as the account name (renamed accounts, domain profiles). Either username or sid is required; sid takes precedence if both are given. |
| `windows.registry.get_user_value` | `sid` | string | no | - | maxLength 256 | Windows security identifier (e.g., "S-1-5-21-...-1001") of the target profile, as an alternative to username. Must match one of the profiles list_profiles would report; a sid not found there is rejected. Either username or sid is required. |
| `windows.registry.get_user_value` | `key` | string | yes | - | maxLength 1024 | Registry key path relative to the resolved user's hive root (e.g., "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"). |
| `windows.registry.get_user_value` | `name` | string | no | - | maxLength 256 | The registry value name to read. |
| `windows.registry.get_value` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive to read from, e.g. "HKLM". |
| `windows.registry.get_value` | `key` | string | yes | - | - | Registry key path relative to the hive root, e.g. "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion". |
| `windows.registry.get_value` | `name` | string | yes | - | - | The value name to read, e.g. "ProductName". |
| `windows.registry.key_exists` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive to check, e.g. "HKLM". |
| `windows.registry.key_exists` | `key` | string | yes | - | - | Registry key path relative to the hive root. |
| `windows.registry.set_value` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive to write to, e.g. "HKCU". |
| `windows.registry.set_value` | `key` | string | yes | - | - | Registry key path relative to the hive root; created if it does not already exist beneath an existing top-level key, e.g. "Software\\MyApp". At most 255 bytes and 32 components; a hive alias, an empty, "." or ".." component and control characters are refused. |
| `windows.registry.set_value` | `name` | string | yes | - | - | The value name to write, e.g. "InstallPath". Empty writes the key's default value. At most 16,383 bytes. |
| `windows.registry.set_value` | `value` | string | yes | - | - | The value data to write, as text; interpreted per `type`: decimal digits for REG_DWORD / REG_QWORD, literal text for REG_SZ / REG_EXPAND_SZ, LF-separated records for REG_MULTI_SZ (empty text is the empty list), hex digits for REG_BINARY (empty is zero bytes). Leave empty when `data_hex` is given. |
| `windows.registry.set_value` | `data_hex` | string | no | - | maxLength 2097152 | The exact bytes to write, as hex, for any type; give it INSTEAD of `value` (both non-empty is refused as invalid_data). Shape is checked per type: 4 bytes for REG_DWORD, 8 for REG_QWORD, a terminating NUL for the string types, a trailing double NUL for REG_MULTI_SZ. Use it to restore a value captured by an earlier write. An empty `data_hex` is the same as omitting it here. At most 1 MiB of data. Needs registry 2.0.0 on the agent: registry 1.x ignores it and writes an EMPTY REG_SZ over the value, answering `status\|ok`. |
| `windows.registry.set_value` | `type` | string | no | - | enum: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD | Registry value type to write. Defaults to REG_SZ when omitted. |
<!-- END GENERATED -->

### Outputs

This plugin does not emit a uniform pipe-joined "row"; each action has its own shape. `get_value`, `get_user_value` and `key_exists` write one self-describing `field_name|value` line per field on success; a failure writes an `error|...` line and returns rc 1, so `-` is never used as an absence placeholder in the read actions. Every mutating action that resolves its target writes ONE `audit|...` line first (grammar below; `-` is "not applicable" inside it), then `status|ok` or `error|<token>`; a missing hive or key or an unparseable hive is a bare `error|...` line with nothing opened and no audit line, while a key path or value name that fails shape validation after the hive resolved is audited as `result=refused`; the dashboard shows the `audit` line as one more row. `delete_key` appends four `key|value` rows after `status|ok`: `counted_keys` (1), `counted_values` (the values the key held), `dry_run` (always 0 in this version) and `capped` (1 when the value count stopped at its cap of 10,000 nodes, the key plus up to 9,999 values, which makes `counted_values` a lower bound; the key is still deleted with all its values); the counts are point in time, since a writer racing the delete can add values the count never saw. `enumerate_keys` writes one `subkey|<name>` line per subkey; a genuinely empty key emits zero lines with rc 0. `enumerate_values` writes one line per value shaped `value|<name>|<type>` -- the leading `value` is a fixed literal tag, not one of the two documented columns (`name`, `type`); see Caveats. `list_profiles` writes one true pipe-joined row per profile (`<sid>|<name>|<path>|<state>`, no discriminator prefix) and zero rows is a structural success.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`windows.registry.delete_key` — `status|counted_keys|counted_values|dry_run|capped`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the delete succeeded and the handle read back as deleted; only ever emitted on success — a failure is reported as an `error\|<token>` line (not exhaustive: key_not_found, key_has_subkeys, key_is_link, access_denied, verify_mismatch, concurrent_change, invalid_key_path or win32:<code>) and a non-zero exit instead of this column. A run that resolves its hive and key, success or not, also emits one `audit\|op=delete_key\|...` row; a missing hive or key, or an unparseable hive, is a bare `error\|...` line with nothing opened and no audit row. Values: ok. |
| `counted_keys` | int32 | - | Windows | `1` | Keys removed: always the target alone, so 1. Values: 1. |
| `counted_values` | int32 | - | Windows | `5` | Values the key held, counted before the delete (a lower bound whenever capped is 1). Point in time: a writer racing the delete can add values this count never saw. Values: a non-negative integer. |
| `dry_run` | bool | - | Windows | `0` | Always 0: this version has no dry run (the column is kept for the audit row and later releases). Values: 0 — a digit, never true/false. |
| `capped` | bool | - | Windows | `0` | Whether the value enumeration stopped at its cap of 10,000 nodes (the key plus up to 9,999 values), making counted_values a lower bound; the delete still removes the key with all its values. Values: 1 (capped), 0 (complete) — a digit, never true/false. |

**`windows.registry.delete_value` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the delete succeeded; only ever emitted on success — a failure is reported as an `error\|` line and a non-zero exit instead of this column. Values: ok. |

**`windows.registry.enumerate_keys` — `subkey`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `subkey` | string | - | Windows | `ProfileList` | One immediate subkey name under the given key; zero rows means the key has no subkeys. Values: free text. |

**`windows.registry.enumerate_values` — `name|type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `name` | string | - | Windows | `ProductName` | The value's name; zero rows means the key has no values. Values: free text. |
| `type` | string | - | Windows | `REG_SZ` | The value's registry type, named via the shared type table shared with get_value and get_user_value. Values: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN. |

**`windows.registry.get_user_value` — `username|value|type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows | `jsmith` | The resolved profile display name the value was read from — falls back to the caller's own username/sid input, then the resolved sid, but is never fabricated and never empty (ADR-0024 D11). Values: free text. |
| `value` | string | - | Windows | `1` | The value's data, decoded the same way get_value decodes it, plus REG_MULTI_SZ (records semicolon-joined) and REG_LINK (target string) — the two types get_value leaves hex-encoded — both sanitised against '\|'/CR/LF so a value cannot forge a column or row. Values: free text. |
| `type` | string | - | Windows | `REG_DWORD` | The registry value type, named via the shared type table. Values: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN. |

**`windows.registry.get_value` — `value|type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `value` | string | - | Windows | `Windows 10 Pro` | The value's data, decoded to a display string. Never truncated or fabricated; a value over the registry's own limits fails the action rather than returning a partial string. Values: free text. |
| `type` | string | - | Windows | `REG_SZ` | The registry value type, named via the shared type table shared with get_user_value and enumerate_values. Values: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN. |

**`windows.registry.key_exists` — `exists`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `exists` | bool | - | Windows | `true` | Whether the key could be opened for read. Values: true, false. |

**`windows.registry.list_profiles` — `sid|profile_name|profile_path|hive_state`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `sid` | string | - | Windows | `S-1-5-21-1111111111-2222222222-3333333333-1001` | The profile's Windows security identifier. Values: free text (a Windows SID string). |
| `profile_name` | string | - | Windows | `jsmith` | The resolved profile folder name (the last path component of ProfileImagePath); rendered "-" when it cannot be resolved — never falls back to the sid (ADR-0024 D11). Values: free text or "-". |
| `profile_path` | string | - | Windows | `C:\Users\jsmith` | The profile's ProfileImagePath, environment-expanded; rendered "-" when it is absent or unreadable. Values: free text or "-". |
| `hive_state` | string | - | Windows | `loaded` | Whether the profile's registry hive is reachable right now. Values: loaded, loaded_classes_only, not_loaded. |

**`windows.registry.set_value` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the write succeeded and read back identical; only ever emitted on success — a failure is reported as an `error\|<token>` line (not exhaustive: access_denied, key_not_found, root_level_create, key_is_link, concurrent_change, invalid_type, invalid_data, value_overflow, invalid_key_path, invalid_value_name, verify_mismatch or win32:<code>) and a non-zero exit instead of this column. A run that resolves its hive and key, success or not, also emits one `audit\|op=set_value\|...` row carrying the previous and new values (hex, capped); a missing hive or key, or an unparseable hive, is a bare `error\|...` line with nothing opened and no audit row, while a key path or value name that fails shape validation after the hive resolved (invalid_key_path, invalid_value_name) is audited as result=refused. Values: ok. |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result.** Rows/lines travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90 days), queryable at `/api/responses/{id}`.
- **Audit log.** The server records a `registry.write` row only for a `registry` command whose agent-stamped `CommandResponse.action` is one of the three mutating actions; an agent older than this plugin stamps none and produces no rows. Principal, result, retention and the join to the operator's row: `docs/user-manual/audit-log.md`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics: nothing here runs on a schedule; the plugin executes only when an operator or workflow dispatches one of its nine definitions.
- **Sensitivity.** The audit rows and the `set_value`/`delete_value` responses carry registry data OLD and NEW (hex of the raw bytes, 256 bytes at most per value in an audit row) and key paths, so they can hold secrets that live in the registry (a service account's autologon password, a product key, an agent token). `get_value`/`enumerate_values`/`get_user_value` can return arbitrary registry data, among it `RegisteredOwner`/`DigitalProductId` (a person's name and a device-specific product-key hash); `get_user_value`'s `username` and `list_profiles`' `profile_name`/`profile_path` (e.g. `jsmith`/`C:\Users\jsmith`) directly identify a person and their home directory. The readers are wider than the writers: `AuditLog:Read` and `Response:Read` (the Operator, PlatformEngineer and ITServiceOwner roles hold both; `Response:Read` is not floored while RBAC is off), the legacy `/events` stream (any authenticated session) and MCP `query_audit_log`; the write parameters (`value`, `data_hex`) are stored unredacted in `executions.parameter_values`, and `delete_value` returns the old value in its response too. Read-time redaction is not built.
- **Siblings:** none. Guardian's own real-time registry-key watch (`guard_type: "registry"`) is an unrelated detection mechanism; this plugin is on-demand only, with no watch/trigger surface.
- **MCP / REST.** Discover: `discover_plugins` (summary) -> `yuzu://plugin-docs` (this page as data) -> `discover_instructions` / `get_definition("windows.registry.get_value")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; the audit rows: the audit log API filtered on `registry.write`.

### Audit line grammar and producer contract

The plugin is the producer of the `audit|` line the server parses (`server/core/src/plugin_result_audit.hpp`). One line is the tag `audit` and 19 `name=value` fields, 20 `|`-separated parts, in this order:

| # | Field | Content |
|---|---|---|
| 1 | `op` | `set_value`, `delete_value` or `delete_key` |
| 2 | `hive` | `HKLM`, `HKCU`, `HKCR` or `HKU` |
| 3 | `result` | `ok`, `refused` (nothing was mutated) or `failed` (a mutation was attempted) |
| 4 | `reason` | the error token (`access_denied`, `key_is_link`, `verify_mismatch`, `win32:<n>`, ...) or `-` |
| 5 | `verify` | `ok`, `mismatch` or `-` (not read back) |
| 6 | `key` | the key path, scrubbed, cut at 256 bytes with `~<total length>` |
| 7 | `name` | the value name, same rule; `-` for the default value |
| 8 | `type` | the requested value type, or `-` |
| 9 | `len` | length in bytes of the new data, or `-` |
| 10 | `dry_run` | `0` for `delete_key` (this version has no dry run), `-` otherwise |
| 11 | `counted_keys` | `delete_key`: the number of keys removed or refused (0 or 1), else `-` |
| 12 | `counted_values` | `delete_key`: the values the key held, else `-` |
| 13 | `capped` | `delete_key`: `1` when `counted_values` stopped at its cap of 10,000 nodes (the key plus up to 9,999 values), else `0`; `-` otherwise |
| 14 | `created` | the keys this operation created and left behind: `0` when none (always `0` for the deletes); for a walk that stopped after it created keys, only those it could not delete again |
| 15 | `sid` | always `-` in this version |
| 16 | `old_state` | the value before the mutation: `absent`, `present` or `unreadable`; `-` when none was captured |
| 17 | `old_type` | its type, or `-` |
| 18 | `old` | hex of its raw bytes, the first 256 only, then `~<total>` when cut; `-` |
| 19 | `new` | hex of the bytes written, same rule; `-` |

The contract the server relies on (it cannot recover from a violation):

- **One record per operation, one LF-terminated line.** The agent writes the LF; the server tolerates one trailing CR and strips it.
- **No `|`, LF, CR or other control byte inside a field.** `audit_token` replaces every control byte, `|`, space, `=` and `,` with `_` and invalid UTF-8 with `?`, and cuts a field at 256 bytes (64 for `op`, `hive`, `reason`, `sid`; 32 for `type`) with `~<length>`, so a registry key or value name that holds a delimiter cannot forge a field, pick the row's `result` or start a second row.
- **`result=`, `reason=` and `verify=` come before the caller-sized `key=` and `name=`.** The server reads `result` as the first `|result=` token of the whole line (never `dry_run=`), but a line past its 4,096-byte bound loses its tail; the whole line stays under 2 KiB by construction.
- **Server bounds.** At most 300 lines of 4,096 bytes per output frame and 600 rows per agent per 60-second window; a bound that bites is counted and logged (`docs/user-manual/audit-log.md`).
- **What `old=` and `new=` carry.** The registry data itself, as hex of the raw bytes, the first 256 per value, with no filter by key or value type: an audit row can therefore hold a secret, and every role that holds `AuditLog:Read` or `Response:Read` can read it. A row is evidence of the change, not a restore point (a value cut at 256 bytes cannot be rebuilt from it).
- **Pinned by tests.** The byte-exact line and the contract case in `tests/unit/test_registry_parsers.cpp`; the plugin's real renderer fed through the server's extractor in `tests/unit/server/test_plugin_result_audit.cpp`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-10-22 · interactive user (elevated; username, SID and profile path anonymised) · leg-hash 8e63a482f476

```
== action=get_value hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion" name=ProductName
value|Windows 10 Pro
type|REG_SZ
[result_status] UNDECLARED / UNKNOWN

== action=set_value hive=HKCU key=Software\YuzuCaptureTmp name=probe value=1
audit|op=set_value|hive=HKCU|result=ok|reason=-|verify=ok|key=Software\YuzuCaptureTmp|name=probe|type=REG_SZ|len=4|dry_run=-|counted_keys=-|counted_values=-|capped=-|created=1|sid=-|old_state=absent|old_type=-|old=-|new=31000000
status|ok
[result_status] UNDECLARED / UNKNOWN

== action=delete_value hive=HKCU key=Software\YuzuCaptureTmp name=probe
audit|op=delete_value|hive=HKCU|result=ok|reason=-|verify=ok|key=Software\YuzuCaptureTmp|name=probe|type=-|len=-|dry_run=-|counted_keys=-|counted_values=-|capped=-|created=0|sid=-|old_state=present|old_type=REG_SZ|old=31000000|new=-
status|ok
[result_status] UNDECLARED / UNKNOWN

== action=delete_key hive=HKCU key=Software\YuzuCaptureTmp
audit|op=delete_key|hive=HKCU|result=ok|reason=-|verify=ok|key=Software\YuzuCaptureTmp|name=-|type=-|len=-|dry_run=0|counted_keys=1|counted_values=0|capped=0|created=0|sid=-|old_state=-|old_type=-|old=-|new=-
status|ok
counted_keys|1
counted_values|0
dry_run|0
capped|0
[result_status] UNDECLARED / UNKNOWN

== action=key_exists hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
exists|true
[result_status] UNDECLARED / UNKNOWN

== action=enumerate_keys hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
subkey|Accessibility
subkey|AdaptiveDisplayBrightness
subkey|AeDebug
subkey|AppCompatFlags
subkey|ASR
subkey|Audit
subkey|BackgroundModel
subkey|ClipSVC
subkey|Compatibility32
subkey|Console
subkey|Containers
subkey|CorruptedFileRecovery
… 12 of 101 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=enumerate_values hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
value|SystemRoot|REG_SZ
value|BaseBuildRevisionNumber|REG_DWORD
value|BuildBranch|REG_SZ
value|BuildGUID|REG_SZ
value|BuildLab|REG_SZ
value|BuildLabEx|REG_SZ
value|CompositionEditionID|REG_SZ
value|CurrentBuild|REG_SZ
value|CurrentBuildNumber|REG_SZ
value|CurrentMajorVersionNumber|REG_DWORD
value|CurrentMinorVersionNumber|REG_DWORD
value|CurrentType|REG_SZ
… 12 of 32 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=get_user_value username=jsmith key=Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced name=Hidden
username|jsmith
value|2
type|REG_DWORD
[result_status] UNDECLARED / UNKNOWN

== action=list_profiles
S-1-5-21-1111111111-2222222222-3333333333-1001|jsmith|C:\Users\jsmith|loaded
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-10-22 · euid 501 · leg-hash 8e63a482f476

```
== action=get_value hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion" name=ProductName
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN

== action=set_value hive=HKCU key=Software\YuzuCaptureTmp name=probe value=1
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=delete_value hive=HKCU key=Software\YuzuCaptureTmp name=probe
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=delete_key hive=HKCU key=Software\YuzuCaptureTmp
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=key_exists hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN

== action=enumerate_keys hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN

== action=enumerate_values hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN

== action=get_user_value username=jsmith key=Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced name=Hidden
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN

== action=list_profiles
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Ubuntu 26.04.1 LTS x86_64 · vm · 2026-10-22 · euid 0 · leg-hash 8e63a482f476

```
== action=get_value hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion" name=ProductName
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN

== action=set_value hive=HKCU key=Software\YuzuCaptureTmp name=probe value=1
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=delete_value hive=HKCU key=Software\YuzuCaptureTmp name=probe
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=delete_key hive=HKCU key=Software\YuzuCaptureTmp
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=key_exists hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN

== action=enumerate_keys hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN

== action=enumerate_values hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN

== action=get_user_value username=jsmith key=Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced name=Hidden
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN

== action=list_profiles
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The fast open is more permissive than the walk in two ancestor-only cases.** An ancestor the caller may traverse but not read: the walk answers `access_denied`, the fast open accepts. An ordinary non-link ancestor that carries a value named `SymbolicLinkValue`: the link probe cannot tell it from a link, so the walk answers `key_is_link` and the fast open accepts. In both the write lands on the real requested key, which is what registry 1.0.0's single open did; probing every ancestor on the fast path would cost it the constant call count. A decoy value on the LEAF is refused on both paths. `HKCU`, `HKCR`, a missing key and any failed name query take the walk (same verdicts, more calls; a name query that keeps failing refuses there too). A path whose case differs from the stored spelling only outside ASCII declines the fast open, and the walk then refuses it `key_is_link` (every component, the first included, is compared with the kernel's name by the same ASCII-only fold): write such a key with its stored spelling. If the kernel name of `HKLM` or `HKU` cannot be read at the first write, the fast open is off for that root until the agent restarts. **`HKCR` may be refused `key_is_link` where its merged view reaches the other backing hive.** `HKCR` merges `HKLM\SOFTWARE\Classes` with the calling user's classes hive (the agent runs as `SYSTEM`, so that half is `HKU\.DEFAULT_Classes`). The walk requires the leaf's kernel name to equal the first component's name plus the rest of the requested path, the same compare for every hive; if the merged view resolves a lower component into the other backing hive than the first component, the two names differ and the write is refused `key_is_link` with nothing written, although no link is involved. A refusal is the failure mode, never an unverified write. Whether it occurs on a real host is not yet measured (the Windows build host's `HKCR` probe decides it); until then write under `HKLM\SOFTWARE\Classes` or `HKU\.DEFAULT_Classes` directly if an `HKCR` write is refused.
2. **The audit trail is lossy by design.** Key and value names go through `yuzu::log_token` (space, `=`, `,`, control bytes and `|` become `_`; over 256 bytes they are cut with `~<length>`) and old/new data is hex capped at 256 raw bytes, so an audit row identifies the change but cannot always reproduce it (there is no digest of a value cut at 256 bytes, and a `delete_key` row carries counts, not values: `old=-|new=-`); `old=` and the delete counts are point in time, so a stale `old=` can make a restore overwrite a concurrent writer; the single actions accept a value named `-`, whose audit line renders `name=-` exactly like the default value. Rows exist only for agents that stamp `CommandResponse.action`: an agent at v0.14.1 or earlier writes registry values but produces no `registry.write` rows, and a read action never does. An exception inside a mutating action answers a bare `error|exception` (rc 1) with no audit line; the server's `command.dispatch` row and the stored response keep the attempt attributable to the command.
3. **Behaviour changes from 1.0.** The changes to existing actions are listed in the 2.0.0 changelog entry (`changelog.d/2026-10-22-registry-typed-writes.changed.md`) and in `docs/user-manual/upgrading.md`, which also gives the rollout order (server replicas first) and the minimum agent version for `registry.write` rows (the first release that contains the audit binding of #6294, later than 0.14.1). **Mixed fleets:** an agent still running registry 1.x writes an EMPTY `REG_SZ` over the value for a `data_hex`-only `set_value` (it reads only `name`, `value` and `type`), stores `REG_QWORD`, `REG_MULTI_SZ`, `REG_EXPAND_SZ` and `REG_BINARY` values as `REG_SZ` text, reports `status|ok` for all of those, and follows a write under `HKLM\SYSTEM\CurrentControlSet` that 2.0.0 refuses; nothing on the server gates dispatch on a plugin version (the definitions' `minAgentVersion` is stored and shown, not compared), so upgrade the agents before using the new types or `data_hex`. **Creating a key now asks for `DELETE` on it**, so that a walk that stops can remove what it made by handle: where an inherited ACL gives the agent identity no `DELETE` on a new key (SYSTEM and Administrators have it on the usual parents) the create answers `access_denied`, and there is deliberately no retry without it.
4. **`delete_key` removes only a key with no subkeys.** A key with subkeys is refused `key_has_subkeys` and nothing is deleted; there is no recursive delete and no `dry_run` in this version (the `dry_run` column is always 0). The key's own values go with it, and the counts are a point-in-time read of them.
5. **The read-side gaps are unchanged.** `enumerate_values` writes `value|<name>|<type>` (the leading `value` is a literal tag, not a third column), `get_value`/`enumerate_values` leave `REG_MULTI_SZ`/`REG_LINK` values hex-encoded where `get_user_value` decodes them (changing that changes `get_value`'s output for existing callers), and `PrivilegeScope`'s `AdjustTokenPrivileges` call must keep its `ReturnLength` argument (without it the offline fallback silently never enabled the privileges until #2771: `agents/shared/win_profiles.hpp`, `changelog.d/2771-privilegescope-token-adjust-bug.fixed.md`). The `get_user_value` capture exercised the live-hive path, not the offline mount.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/registry/src/registry_core.hpp` · `agents/plugins/registry/src/registry_parsers.hpp` · `agents/plugins/registry/src/registry_plugin.cpp` · `agents/plugins/registry/src/registry_win.cpp`
- Definitions: `content/definitions/registry.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_a.hpp`
- Tests: `tests/test_registry_definition.py` · `tests/unit/test_registry_core.cpp` · `tests/unit/test_registry_local_dispatcher.cpp` · `tests/unit/test_registry_parsers.cpp` · `tests/unit/test_registry_win_internals.cpp` · `tests/unit/test_registry_write_local_dispatcher.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2026-10-22-registry-typed-writes.added.md` · `changelog.d/2026-10-22-registry-typed-writes.changed.md`
<!-- END GENERATED -->
