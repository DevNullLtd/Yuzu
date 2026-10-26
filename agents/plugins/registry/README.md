# registry

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Windows Registry -- get, set (six types, verified), delete value, delete key, enumerate, per-user reads |
| **Version** | 2.0.1 |
| **Kind** | Action · mutating · on-demand |
| **Platforms** | Windows ✅ · macOS 🟡 planned · Linux 🟡 planned |
| **Actions** | `delete_key` (definition `windows.registry.delete_key`) · `delete_value` (definition `windows.registry.delete_value`) · `enumerate_keys` (definition `windows.registry.enumerate_keys`) · `enumerate_values` (definition `windows.registry.enumerate_values`) · `get_user_value` (definition `windows.registry.get_user_value`) · `get_value` (definition `windows.registry.get_value`) · `key_exists` (definition `windows.registry.key_exists`) · `list_profiles` (definition `windows.registry.list_profiles`) · `set_value` (definition `windows.registry.set_value`) |
| **Security** | `get_value`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `set_value`: securable `Infrastructure` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval; `delete_value`: securable `Infrastructure` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval; `delete_key`: securable `Infrastructure` · operation Delete · risk Critical · dispatch Destructive · approval gate AdminOrApproval; `key_exists`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `enumerate_keys`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `enumerate_values`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `get_user_value`: securable `Infrastructure` · operation Read · risk Medium · dispatch ReadOnly · approval gate AdminOrApproval; `list_profiles`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: `get_value`: endpoint-admin, endpoint-operator; `get_user_value`: endpoint-admin; `list_profiles`: endpoint-admin, endpoint-operator; `set_value`: endpoint-admin; `enumerate_keys`: endpoint-admin, endpoint-operator; `delete_value`: endpoint-admin; `delete_key`: endpoint-admin; `key_exists`: endpoint-admin, endpoint-operator; `enumerate_values`: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

All nine actions are direct, synchronous Win32 registry calls: there is no scheduled gather. The six read actions (`get_value`, `key_exists`, `enumerate_keys`, `enumerate_values`, `get_user_value`, `list_profiles`) open a key read-only and read or list it; every registry-controlled string they render passes through `sanitize_field` (`|`, CR, LF, ESC and the Unicode line breaks U+0085, U+2028 and U+2029 become `_`), so no read output can contain a line that starts with `audit|`. `get_user_value` resolves the target profile through the same `ProfileList` walk `list_profiles` exposes, reads the live `HKEY_USERS\<SID>` hive if the user is logged in, and falls back to an offline `RegLoadKeyW` mount of `NTUSER.DAT` (under `SeBackup`/`SeRestore` and a process-wide mutex serialising the whole offline arm) only when the user is logged out. The seven `hive`+`key` actions validate through one `parse_target` helper, which also logs (never blocks) access to a few sensitive `HKLM` subtrees via `spdlog::info`.

The three mutating actions (`set_value`, `delete_value`, `delete_key`) share one core (`registry_core.hpp`, over an injected registry; `registry_win.cpp` binds it to `Reg*W`). Each obtains a CHECKED handle for the key, and every step after that -- the previous-value capture, `RegSetValueExW`, the verifying read-back, `RegDeleteValueW`, `NtDeleteKey(h)` -- runs on that handle: nothing re-resolves the path by name, and no handle outlives the command. There are two ways to the handle.

- **The fast open (`HKLM` and `HKU` only).** ONE `RegOpenKeyExW` of the whole path with `REG_OPTION_OPEN_LINK`, then `NtQueryKey(KeyNameInformation)` names the object the handle is bound to. The open is accepted only when that kernel name equals `<root kernel name>\<requested path>` (every byte exact except that A-Z fold, so a name that differs in non-ASCII case, a name that does not fit the 4 KiB buffer and a failed query all decline) and the leaf has no `SymbolicLinkValue`. A registry link before the leaf makes the kernel open the link's TARGET, whose name cannot equal the requested one, so the fast open can only accept the canonical object with no real link traversed; everything else declines to the walk. A `set_value` on an existing key is 7 calls across the plugin's registry seam (`open_path`, `final_name`, the link probe, capture, set, read-back, close; the cached root-name lookup is an eighth), the same at every depth, and about 7 Win32 calls: the link probe, the capture and the read-back are each one `RegQueryValueExW` for a value that fits a 256-byte first buffer (a larger value costs one more read). The walk costs about 3 more per path component, plus two name queries.
- **The walk (the reference).** `open_checked` walks the path component by component from the hive root, opening each component from the previous HANDLE with `REG_OPTION_OPEN_LINK` and probing it for `SymbolicLinkValue`: a registry link is refused (`key_is_link`), never followed. A probe only sees the key as it is at that instant, and a link is made in two steps (the key, then its `SymbolicLinkValue`), so the walk also ends on the fast open's test. It reads the canonical kernel name of the FIRST component's handle right after that open (before its probe; it has to end in the requested first component, else `key_is_link`) and of the leaf handle at the end (after the create loop too), and hands the leaf over only when the leaf's name equals the first component's name plus the remaining requested components (A-Z fold). A link completed after its probe, or a component moved away by a rename, leaves the handle bound to an object whose name is not the requested path: the action is refused `key_is_link` and no value is written, and a name that cannot be read is refused with its Win32 token. A link completed during the create loop is the one case where the walk has already written: a create is relative to a handle the kernel parses again, so the keys can land beneath the link's target. The keys a creating walk makes stay owned by the operation until its verified write is over (`Opened::made`; its destructor is the rollback). So a walk that does not hand its leaf over (the name test refuses, a later create fails, or a later create finds its key already there), and an exception anywhere from the first create to the end of the verified write (an allocation failure while capturing the previous value, writing or reading back), try to delete every key the walk created, by its own handle, leaf first, after the value the write had set when it had landed, so that normally nothing is left (`result=refused`, `created=0`, with the reason it stopped for: `key_is_link`, `concurrent_change` or the Win32 token; after an exception the plugin's fixed failed audit line, caveat 2). The rule is the same without an attacker: a create that fails part-way under a plain parent (say `access_denied` on the second component) also removes the first. A key a create merely opened is closed, never deleted. The rollback is BEST EFFORT. A key that holds a value or a subkey when the rollback checks it is kept, because `NtDeleteKey` would destroy the values with it (the rollback asks `RegEnumValueW` first), and so is a key whose delete failed: each is counted in the audit line (`result=failed`, `created=<n>`). Windows has no delete-if-empty call, so two windows stay open: a value another writer puts into the key between that check and the delete is deleted with the key, and a value another writer puts over our own same-named value before the rollback deletes it by name is deleted with it. After a double fault (a rollback step that itself fails or throws) the value and the keys can stay with `created=-` and nothing logged. One derivation serves every hive, `HKCU` and `HKCR` included, and costs two `final_name` calls per walk whatever the depth. It is always used for `HKCU` (it resolves per calling user) and `HKCR` (a merged view of two trees), neither of which has one kernel name to compare with, for a key that is missing, and whenever the fast open declines. It alone produces the verdict token and creates: a missing component is created component-wise from the checked parent, a create that finds the key already there refuses `concurrent_change`, and a creating action never creates a key directly beneath the hive root (`root_level_create`).

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
| Windows | agent service account (LocalSystem today, #1442) | Writes against `HKLM\*` need the service account in `Administrators`; `HKCU\*` needs no elevation. `get_user_value` uses the offline-hive fallback only when the target user is logged out: it needs `SeBackupPrivilege`+`SeRestorePrivilege`, already granted to the service account, so there is no new grant; the live-hive path, the machine-hive writes and `list_profiles` need no elevated privilege beyond the key's own ACL. `NtDeleteKey` and `NtQueryKey` (ntdll) need no privilege beyond `DELETE` on the key and a handle the caller already holds. | 2026-10-23, bare-metal, elevated interactive user: the nine actions captured (`docs/samples/windows.txt`); the write arms also run in `tests/unit/test_registry_write_local_dispatcher.cpp` and `tests/unit/test_registry_win_internals.cpp` on elevated Windows runs | `error\|key not found` / `error\|value not found` (reads); the mutating actions name the cause: `error\|access_denied`, `key_not_found`, `value_not_found`, `key_is_link`, `key_has_subkeys`, `concurrent_change`, `root_level_create`, `verify_mismatch`, `invalid_key_path`, `invalid_value_name`, `invalid_type`, `invalid_data`, `value_overflow`, `win32:<code>` or `exception` (the token table under Outputs says what each means) |
| macOS | n/a: plugin loads but every action is the honest `unsupported` stub (plist support is PLANNED) | n/a | 2026-10-22, bare-metal, euid 501 | always `registry\|unsupported\|Windows registry has no macOS equivalent; use defaults/plists`, rc 0 (reads) / rc 1 (mutators) |
| Linux | n/a: plugin loads but every action is the honest `unsupported` stub (dconf support is PLANNED) | n/a | 2026-10-22, vm, euid 0 | always `registry\|unsupported\|Windows registry is not available on this platform`, rc 0 (reads) / rc 1 (mutators) |

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
| `windows.registry.set_value` | `key` | string | yes | - | - | Registry key path relative to the hive root; created if it does not already exist beneath an existing top-level key, e.g. "Software\\MyApp". At most 255 bytes and 32 components; a hive alias, an empty, "." or ".." component and control characters are refused on the instruction and MCP routes; POST /api/command passes an embedded NUL to the plugin as a C string, so the value is cut at it. |
| `windows.registry.set_value` | `name` | string | yes | - | - | The value name to write, e.g. "InstallPath". Empty writes the key's default value. At most 16,383 bytes. |
| `windows.registry.set_value` | `value` | string | no | - | - | The value data to write, as text; interpreted per `type`: decimal digits for REG_DWORD / REG_QWORD, literal text for REG_SZ / REG_EXPAND_SZ, LF-separated non-empty records for REG_MULTI_SZ (split on LF only, so a CR stays inside its record; an empty record or a trailing LF is refused as invalid_data; empty text is the empty list), hex digits for REG_BINARY (empty is zero bytes). Send exactly one of `value` and `data_hex`. When neither is sent, or the one sent is empty, the write stores an empty value of the type and answers ok: an empty string, the empty list or zero bytes (REG_DWORD and REG_QWORD refuse it as invalid_data), so a misspelt parameter name writes an empty value instead of failing. Through MCP `execute_instruction` and the result-set execute routes every parameter value is limited to 64 KiB. |
| `windows.registry.set_value` | `data_hex` | string | no | - | maxLength 2097152 | The exact bytes to write, as hex, for any type; give it INSTEAD of `value` (both non-empty is refused as invalid_data). Shape is checked per type: 4 bytes for REG_DWORD, 8 for REG_QWORD, a terminating NUL for the string types, a trailing double NUL for REG_MULTI_SZ. Use it for exact bytes you hold from another source. An empty `data_hex` is the same as omitting it here. The plugin takes at most 1 MiB of data (2,097,152 hex characters), but MCP `execute_instruction` and the result-set execute routes limit every parameter value to 64 KiB, so through them it carries at most 32 KiB of data; the direct command route is not under that cap. Needs registry 2.0.0 on the agent: registry 1.x ignores it and writes an EMPTY REG_SZ over the value, answering `status\|ok` (with type=REG_DWORD and data_hex only, 1.x throws and writes nothing). |
| `windows.registry.set_value` | `type` | string | no | - | enum: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD | Registry value type to write. Defaults to REG_SZ when omitted. Mixed fleets: an agent still running registry 1.x stores REG_QWORD, REG_MULTI_SZ, REG_EXPAND_SZ and REG_BINARY values as REG_SZ text and answers `status\|ok`, so upgrade the agents to registry 2.0.0 before using them. |
<!-- END GENERATED -->

### Outputs

This plugin does not emit a uniform pipe-joined "row"; each action has its own shape. `get_value`, `get_user_value` and `key_exists` write one self-describing `field_name|value` line per field on success; a failure writes an `error|...` line and returns rc 1, so `-` is never used as an absence placeholder in the read actions. Every mutating action that resolves its target writes ONE `audit|...` line first (grammar below; `-` is "not applicable" inside it), then `status|ok` or `error|<token>`; a missing hive or key or an unparseable hive is a bare `error|...` line with nothing opened and no audit line, while a key path or value name that fails shape validation after the hive resolved is audited as `result=refused`; the dashboard shows the `audit` line as one more row. `delete_key` appends four `key|value` rows after `status|ok`: `counted_keys` (1), `counted_values` (the values the key held), `dry_run` (always 0 in this version) and `capped` (1 when the value count stopped at its cap of 10,000 nodes, the key plus up to 9,999 values, which makes `counted_values` a lower bound; the key is still deleted with all its values); the counts are point in time, since a writer racing the delete can add values the count never saw. `enumerate_keys` writes one `subkey|<name>` line per subkey; a genuinely empty key emits zero lines with rc 0. `enumerate_values` writes one line per value shaped `value|<name>|<type>` -- the leading `value` is a fixed literal tag, not one of the two documented columns (`name`, `type`); see Caveats. `list_profiles` writes one true pipe-joined row per profile (`<sid>|<name>|<path>|<state>`, no discriminator prefix) and zero rows is a structural success.

**Error tokens of the mutating actions.** `error|<token>` and the audit line's `reason=` carry the bare token and nothing more, and the agent logs nothing about an ordinary failure (an exception is the exception: it is logged with the action name). What each means and where to look:

| Token | Meaning | What to check |
|---|---|---|
| `access_denied` | `ERROR_ACCESS_DENIED`, from several causes: the agent identity's ACL on the key refuses an access the action asks for (caveat 3 lists them); a parent the walk may traverse but not read (the walk opens every component with `KEY_QUERY_VALUE` to probe it; the fast open does not); a create refused on a parent, or an inherited ACL that gives the new key no `DELETE`; the link probe itself refused | the ACL of the key and of each parent for the agent identity |
| `key_not_found` | the key, or a component of the path, does not exist (nothing was written) | the spelling; `key_exists`; a `WOW6432Node` path |
| `value_not_found` | `delete_value` named a value the key does not hold (nothing deleted) | `enumerate_values` |
| `root_level_create` | the first key component is missing directly under the hive root; a creating write never creates one | the parent has to exist already |
| `key_is_link` | a component is a registry symbolic link, or the handle's kernel name is not the requested path (a link completed mid-walk, a component renamed, a non-ASCII case variant, a decoy value named `SymbolicLinkValue` on an ancestor); nothing was written | the link's target path; the key's stored spelling |
| `key_has_subkeys` | `delete_key` on a key with subkeys (nothing deleted) | delete the subkeys first, one key per call |
| `concurrent_change` | another party created the key between the walk's check and its create, or the handle went stale (`ERROR_KEY_DELETED`) | read the key and retry |
| `verify_mismatch` | the read-back differs from what was written, or the key did not read back as deleted. It can be a false positive: another writer, or a Group Policy refresh, that touches the value between the write and the read-back looks the same | `get_value` the value and decide |
| `invalid_key_path`, `invalid_value_name` | the input failed shape validation before anything was opened (limits under Inputs) | the parameter |
| `invalid_type` | `type` is not one of the six names (case-sensitive) | the spelling |
| `invalid_data` | the text or `data_hex` does not fit the type: not decimal digits for a number; not hex, or an odd count; a string without its terminating NUL; a REG_MULTI_SZ with an empty record or a trailing LF (records are split on LF only, so a CR stays in its record); `value` and `data_hex` both sent | the parameter |
| `value_overflow` | a number out of range for its type, or data over 1 MiB | the parameter |
| `win32:<code>` | any other Win32 or NT failure, by number, including the answer when `NtDeleteKey` refuses for a reason not listed here (caveat 4) | `net helpmsg <code>` |
| `exception` | an exception ended the action (an allocation failure is the realistic one); the audit line is the fixed failed line of caveat 2 | the agent log, and "A partial or failed create" under Where the data goes |

A misspelt or missing `value` parameter on a `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ` or `REG_BINARY` write is not an error: it writes an empty value of the type and answers `status|ok` (`REG_DWORD` and `REG_QWORD` refuse it as `invalid_data`).

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
| `value` | string | - | Windows | `Windows 10 Pro` | The value's data, decoded to a display string, for a value of at most 1 MiB (the same bound as get_user_value). Never truncated or fabricated: a larger value fails the action with `error\|value exceeds 1 MiB limit` rather than returning a partial string. Values: free text. |
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
- **Agent log.** The plugin's own `spdlog` error lines (for example `registry: <action> raised an exception`) carry no command id: the plugin ABI hands a plugin no command identifier. Attribute a command through the response and audit rows above, which are joined on the command id.
- **A partial or failed create.** A `set_value` row with `result=failed` and `created=<n>` above 0, an `error|exception` reply, or an agent that stopped in the middle of a command can leave keys the call made (and, for a write that landed, its value). Take the hive, key and value name from the request that dispatched the command, not from the audit row: the exception row has `hive=-|key=-|created=-`, and the `command.dispatch` row carries only `registry:set_value -> N agent(s)`. The request parameters are in `executions.parameter_values` of the execution that holds the row's `command_id` (join on it; the command-to-execution mapping is reaped after 24 hours, so the join can come back empty, and then only the dispatching script, workflow or schedule holds the request), or in the dispatching script, workflow or schedule. A call creates only the trailing components of a path that did not exist and the leading ones existed before, and a pre-existing empty parent looks exactly like a created one; the rollback goes leaf first, so the keys a failed call leaves are normally the shallowest of the ones it made, but not when the leaf holds a value or key another party put there: the leaf is kept and every ancestor above it survives with it (`created=<n>` counts the survivors on a returning exit). Read the candidates with `key_exists`, `enumerate_values` and `enumerate_keys`, and decide per key: remove it with `delete_key` (it refuses a key with subkeys, so go leaf first, one call per key) only when this call's creation of it can be shown (for example an earlier `key_exists` for the path answered false) and it is empty; a key that holds a value you did not write is another party's and stays, and so does any key whose creation by this call you cannot show. For an exception whose audit line could not be written, and for an agent that died mid-command, there is no `registry.write` row: only the `command.dispatch` row and the stored response show the attempt.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics: nothing here runs on a schedule; the plugin executes only when an operator or workflow dispatches one of its nine definitions.
- **Sensitivity.** The audit rows and the `set_value`/`delete_value` responses carry registry data OLD and NEW (hex of the raw bytes, 256 bytes at most per value in an audit row, for every value type) and key paths, so they can hold secrets that live in the registry (a service account's autologon password, a product key, an agent token). **Owner risk acceptance:** old and new values are recorded as raw hex and can contain secrets; the product owner accepted this risk on 2026-10-20 and masking is a planned later change, and nothing in the plugin redacts them today. A key path can name a person. `get_value`/`enumerate_values`/`get_user_value` can return arbitrary registry data, among it `RegisteredOwner`/`DigitalProductId` (a person's name and a device-specific product-key hash); `get_user_value`'s `username` and `list_profiles`' `profile_name`/`profile_path` (e.g. `jsmith`/`C:\Users\jsmith`) directly identify a person and their home directory. The readers are wider than the writers: `AuditLog:Read` and `Response:Read` (the Viewer, Operator, PlatformEngineer, ITServiceOwner and Administrator roles hold both; `Response:Read` is not floored while RBAC is off), the legacy `/events` stream (any authenticated non-service-scoped session) and MCP `query_audit_log`; the executions' `parameter_values` carries the write parameters, `value` and `data_hex` alike, unredacted, and `delete_value` returns the old value in its response too. By default audit rows are retained 365 days (`--audit-retention-days`) and the response store 90 days (`--response-retention-days`); the executions table is not in the server's retention settings and no pass prunes it, so `parameter_values` stays until the database is purged. Read-time redaction is not built.
- **Siblings:** none. Guardian's own real-time registry-key watch (`guard_type: "registry"`) is an unrelated detection mechanism; this plugin is on-demand only, with no watch/trigger surface.
- **MCP / REST.** Discover: `discover_plugins` (summary) -> `yuzu://plugin-docs` (this page as data) -> `discover_instructions` / `get_definition("windows.registry.get_value")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; the audit rows: the audit log API filtered on `registry.write`.

### Audit line grammar and producer contract

The plugin is the producer of the `audit|` line the server parses (`server/core/src/plugin_result_audit.hpp`). One line is the tag `audit` and 19 `name=value` fields, 20 `|`-separated parts, in this order:

| # | Field | Content |
|---|---|---|
| 1 | `op` | `set_value`, `delete_value` or `delete_key` |
| 2 | `hive` | `HKLM`, `HKCU`, `HKCR` or `HKU` |
| 3 | `result` | `ok`, `refused` (nothing was mutated, or every key the walk created was removed again) or `failed` (a mutation was attempted) |
| 4 | `reason` | the error token (`access_denied`, `key_is_link`, `verify_mismatch`, `win32:<n>`, ...) or `-` |
| 5 | `verify` | `ok`, `mismatch` or `-` (not read back) |
| 6 | `key` | the key path, scrubbed, cut at 256 bytes with `~<total length>` |
| 7 | `name` | the value name, same rule; `-` for the default value |
| 8 | `type` | the requested value type, or `-` |
| 9 | `len` | length in bytes of the new data, or `-` |
| 10 | `dry_run` | `0` for `delete_key` (this version has no dry run), `-` otherwise |
| 11 | `counted_keys` | `delete_key`: `1` once the key was found to be a leaf (also when the value count or the delete then failed), `0` when the call was refused earlier (a subkey, or the subkey enumeration failed) or the key not found; `-` otherwise |
| 12 | `counted_values` | `delete_key`: the values counted before the delete (a lower bound when `capped`; a partial count when the value enumeration itself failed; `0` when the call was refused before any value was counted, or the key not found); `-` otherwise |
| 13 | `capped` | `delete_key`: `1` when `counted_values` stopped at its cap of 10,000 nodes (the key plus up to 9,999 values), else `0`; `-` otherwise |
| 14 | `created` | the keys this operation created and that are still present: on `ok` the keys the write made (`0` when it made none, always `0` for the deletes); after a walk that stopped, only those it could not delete again or that now hold another party's value or key; `-` in the exception line |
| 15 | `sid` | always `-` in this version |
| 16 | `old_state` | the value before the mutation: `absent`, `present` or `unreadable`; `-` when none was captured |
| 17 | `old_type` | its type, or `-` |
| 18 | `old` | hex of its raw bytes for every value type, the first 256 only, then `~<total>` when cut; `-` when none was captured and in a `delete_key` row |
| 19 | `new` | the same rule for the bytes written; `-` for the deletes |

The contract the server relies on (it cannot recover from a violation):

- **One record per operation, one LF-terminated line.** The agent writes the LF; the server tolerates one trailing CR and strips it.
- **No `|`, LF, CR or other control byte inside a field.** `audit_token` replaces every control byte, `|`, space, `=` and `,` with `_` and invalid UTF-8 with `?`, and cuts a field at 256 bytes (64 for `op`, `hive`, `reason`, `sid`; 32 for `type`) with `~<length>`, so a registry key or value name that holds a delimiter cannot forge a field, pick the row's `result` or start a second row.
- **`result=`, `reason=` and `verify=` come before the caller-sized `key=` and `name=`.** The server reads `result` as the first `|result=` token of the whole line (never `dry_run=`), but a line past its 4,096-byte bound loses its tail; the whole line stays under 2 KiB by construction.
- **Server bounds.** At most 300 lines of 4,096 bytes per output frame and 600 rows per agent per 60-second window; a bound that bites is counted and logged (`docs/user-manual/audit-log.md`).
- **What `old=` and `new=` carry.** The registry data itself, as hex of the raw bytes, the first 256 per value, then `~<total>` when cut, for every value type (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_QWORD`), with no filter by key or value type: an audit row can therefore hold a secret. **OWNER RISK ACCEPTANCE:** the product owner accepted this risk on 2026-10-20 and masking is a planned later change; no redaction code exists. The readers are every role that holds `AuditLog:Read` or `Response:Read` (Viewer, Operator, PlatformEngineer, ITServiceOwner and Administrator), the legacy `/events` stream (any authenticated non-service-scoped session), MCP `query_audit_log`, and, for the write parameters (`value` as well as `data_hex`), `executions.parameter_values`. By default audit rows are retained 365 days and the response store 90 days; no server pass prunes the executions table. A row is evidence of the change, not a restore point (a value cut at 256 bytes cannot be rebuilt from it).
- **Pinned by tests.** The byte-exact line and the contract case in `tests/unit/test_registry_parsers.cpp`; the plugin's real renderer fed through the server's extractor in `tests/unit/server/test_plugin_result_audit.cpp`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-10-23 · interactive user (elevated; username, SID and profile path anonymised) · leg-hash 8e63a482f476

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

1. **The fast open is more permissive than the walk in two ancestor-only cases.** An ancestor the caller may traverse but not read: the walk answers `access_denied`, the fast open accepts. An ordinary non-link ancestor that carries a value named `SymbolicLinkValue`: the link probe cannot tell it from a link, so the walk answers `key_is_link` and the fast open accepts. In both the write lands on the real requested key, which is what registry 1.0.0's single open did; probing every ancestor on the fast path would cost it the constant call count. A decoy value on the LEAF of a `set_value` or `delete_value` is refused on both paths (a `delete_key` leaf is opened as a possible link, so it is not probed). `HKCU`, `HKCR`, a missing key and any failed name query take the walk (same verdicts, more calls; a name query that keeps failing refuses there too). A path whose case differs from the stored spelling only outside ASCII declines the fast open, and the walk then refuses it `key_is_link` (every component, the first included, is compared with the kernel's name by the same ASCII-only fold): write such a key with its stored spelling. If the kernel name of `HKLM` or `HKU` cannot be read at the first write, the fast open is off for that root until the agent restarts. **`HKCR` may be refused `key_is_link` where its merged view reaches the other backing hive.** `HKCR` merges `HKLM\SOFTWARE\Classes` with the calling user's classes hive (the agent runs as `SYSTEM`, so that half is `HKU\.DEFAULT_Classes`). The walk requires the leaf's kernel name to equal the first component's name plus the rest of the requested path, the same compare for every hive; if the merged view resolves a lower component into the other backing hive than the first component, the two names differ and the write is refused `key_is_link` with nothing written, although no link is involved. A refusal is the failure mode, never an unverified write. Measured on Windows 11 (2026-10-23): for an interactive user a key whose first component exists in both backing hives and whose lower component exists only in the machine hive IS refused `key_is_link` (the first component is bound to the user hive, the lower one to `HKLM`); the reverse orientation and every key wholly inside one hive are accepted. As `SYSTEM`, the agent's identity, `HKCR` shows only `HKLM\SOFTWARE\Classes`, so the shape does not arise there. If an `HKCR` write is refused, write under `HKLM\SOFTWARE\Classes` or `HKU\<SID>_Classes` directly. **`HKCU\Software\Classes` is a registry link for a real user.** Measured on Windows (2026-10-25): For a real user's hive `HKCU\Software\Classes` is itself a registry link (to the user's `_Classes` hive), so a creating write below it is refused `key_is_link` (1.0.0 followed it); as SYSTEM, the agent's identity, `HKCU` is `HKU\.DEFAULT` and `Software\Classes` is not a link, so such writes succeed; to write a user's classes use `hive=HKU` with `<SID>_Classes`.
2. **The audit trail is lossy by design.** Key and value names go through `yuzu::log_token` (space, `=`, `,`, control bytes, `|` and the line breaks U+0085, U+2028 and U+2029 become `_`, and so does a trailing backslash; over 256 bytes they are cut with `~<length>`), and old/new data is hex capped at 256 raw bytes, so an audit row identifies the change but cannot always reproduce it (a value cut at 256 bytes cannot be rebuilt from it, and the hex can hold a secret: owner risk acceptance, see "Sensitivity"); a `delete_key` row carries counts, not values: `old=-|new=-`; `old=` and the delete counts are point in time; the single actions accept a value named `-`, whose audit line renders `name=-` exactly like the default value. Rows exist only for agents that stamp `CommandResponse.action`: an agent at v0.14.1 or earlier writes registry values but produces no `registry.write` rows, and a read action never does. **An exception inside a mutating action** (an allocation failure while capturing, writing or reading back is the realistic one) is contained at the plugin ABI seam: the plugin writes a fixed failed audit line (`result=failed`, `reason=exception`, every other field `-`, so `created=-` and no `old=`/`new=`) and then `error|exception` with rc 1, and the server records that line as a failed `registry.write` row. A creating write tries to remove the keys it made, and the value it had written into them, on an exception before its verified write ends (best effort, below); a write onto an existing key that had already landed keeps its value, and so does a write whose exception came after its verified write (while the reply was being built): the row says `failed`, and the key must be read back to know. An agent that dies mid-command writes no row at all; the server's `command.dispatch` row and the stored response keep the attempt attributable. The rollback is BEST EFFORT: a key that holds a value or a subkey when it checks is kept and, on a returning exit, counted in `created=` (`result=failed`), and `created=` can also count a key another party deleted first, which the rollback then cannot delete again. A write that lands between the check and the delete, or over our own same-named value before the rollback deletes it by name, can still be lost, because Windows has no delete-if-empty call. After a double fault (a rollback step that fails or throws) the value and the keys may stay with `created=-` and nothing logged. "Where the data goes" has the procedure for what a failed create can leave.
3. **Behaviour changes from 1.0.** The changes to existing actions are listed in the 2.0.0 changelog entry (`changelog.d/2026-10-22-registry-typed-writes.changed.md`) and in `docs/user-manual/upgrading.md`, which also gives the rollout order (server replicas first) and the minimum agent version for `registry.write` rows (the first release that contains the audit binding of #6294, later than 0.14.1). **Mixed fleets:** an agent still running registry 1.x writes an EMPTY `REG_SZ` over the value for a `data_hex`-only `set_value` (it reads only `name`, `value` and `type`; with `type=REG_DWORD` and `data_hex` only it throws and writes nothing), stores `REG_QWORD`, `REG_MULTI_SZ`, `REG_EXPAND_SZ` and `REG_BINARY` values as `REG_SZ` text, reports `status|ok` for all of those, and follows a write under `HKLM\SYSTEM\CurrentControlSet` that 2.0.0 refuses; nothing on the server gates dispatch on a plugin version (the definitions' `minAgentVersion` is declared and exported, not compared at dispatch), so upgrade the agents before using the new types or `data_hex`, in schedules, workflows, policies and bundles as well as scripts. **Embedded NUL:** a NUL inside a parameter sent through `POST /api/command` reaches the plugin as a C string and cuts the value at the NUL on every agent version (the instruction and MCP routes refuse control bytes), so a key or value name that carries one writes a shorter key or name than the one sent. A reply that is a bare `status|ok` with no leading `audit|` row came from a 1.x agent: read the value back with `get_value`. **An existing server install keeps the 1.0.0 definitions:** bundled definitions are inserted only when absent, so an install that already holds `windows.registry.set_value`, `delete_value` and `delete_key` keeps their 1.0.0 text, enum and parameters (no `data_hex`, a `type` enum of `REG_SZ` and `REG_DWORD` only, `value` required) until they are replaced, and a stored `windows.registry.get_value` keeps its 1.0.0 description (only its text changed in 1.1.0): export, delete and re-import the four definitions, `get_value` included (`docs/user-manual/instructions.md`, "Replacing a stored parameter schema") to get the 1.1.0 text, enum and `data_hex`. Until the fleet is upgraded, scope such a write to upgraded devices (`ostype == "windows" AND tag:<key> == "<value>"`, with a tag that marks the upgraded devices) or switch the action off with the `set_value` kill switch. **2.0.0 asks the key for more access than 1.0.0 did.** `set_value` opens the leaf with `KEY_SET_VALUE` and `KEY_QUERY_VALUE` (the read-back and the link probe need the second), and `KEY_CREATE_SUB_KEY` on each parent it creates under; `delete_value` the same two on the leaf; `delete_key` `DELETE`, `KEY_ENUMERATE_SUB_KEYS` and `KEY_QUERY_VALUE`; the walk adds `KEY_QUERY_VALUE` on every component it passes through. An ACL that grants less answers `access_denied`. **Creating a key now asks for `DELETE` on it**, so that a walk that stops can remove what it made by handle: where an inherited ACL gives the agent identity no `DELETE` on a new key (SYSTEM and Administrators have it on the usual parents) the create answers `access_denied`, and there is deliberately no retry without it.
4. **`delete_key` removes only a key with no subkeys.** A key with subkeys is refused `key_has_subkeys` and nothing is deleted; there is no recursive delete and no `dry_run` in this version (the `dry_run` column is always 0). The key's own values go with it, and the counts are a point-in-time read of them. A subkey created between the check and the delete cannot be refused as `key_has_subkeys`: `NtDeleteKey` refuses the delete and the action answers a failure token (`access_denied` or `win32:<code>`, not `key_has_subkeys`), with the key still in place and nothing deleted.
5. **Three read-side gaps are unchanged; `get_value` has been bounded at 1 MiB since 2.0.1.** `enumerate_values` writes `value|<name>|<type>` (the leading `value` is a literal tag, not a third column), `get_value`/`enumerate_values` leave `REG_MULTI_SZ`/`REG_LINK` values hex-encoded where `get_user_value` decodes them (changing that changes `get_value`'s output for existing callers), and `PrivilegeScope`'s `AdjustTokenPrivileges` call must keep its `ReturnLength` argument (without it the offline fallback silently never enabled the privileges until #2771: `agents/shared/win_profiles.hpp`, `changelog.d/2771-privilegescope-token-adjust-bug.fixed.md`). The `get_user_value` capture exercised the live-hive path, not the offline mount. `get_value` reads at most 1 MiB (2.0.1), the bound `get_user_value` and the write path already use: a larger value answers `error|value exceeds 1 MiB limit` with rc 1, so a value that any writer of the key made huge is never read whole into the agent's memory (three copies: the bytes, their hex and the sanitised string). Registry 2.0.0 and earlier read the whole value.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/registry/src/registry_core.hpp` · `agents/plugins/registry/src/registry_parsers.hpp` · `agents/plugins/registry/src/registry_plugin.cpp` · `agents/plugins/registry/src/registry_win.cpp`
- Definitions: `content/definitions/registry.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_a.hpp`
- Tests: `tests/test_registry_definition.py` · `tests/unit/test_registry_core.cpp` · `tests/unit/test_registry_local_dispatcher.cpp` · `tests/unit/test_registry_parsers.cpp` · `tests/unit/test_registry_win_internals.cpp` · `tests/unit/test_registry_write_local_dispatcher.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2026-10-22-registry-typed-writes.added.md` · `changelog.d/2026-10-22-registry-typed-writes.changed.md` · `changelog.d/6487-registry-kernel-name-fail-closed.security.md` · `changelog.d/6490-registry-get-value-bound.changed.md` · `changelog.d/6491-registry-output-line-breaks.fixed.md`
<!-- END GENERATED -->
