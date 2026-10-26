# registry

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Windows Registry -- get, set (six types, verified), delete value, delete key (optionally recursive), enumerate, per-user reads and writes, bulk apply with an undo manifest |
| **Version** | 2.1.0 |
| **Kind** | Action · mutating · on-demand |
| **Platforms** | Windows ✅ · macOS 🟡 planned · Linux 🟡 planned |
| **Actions** | `apply` (definition `windows.registry.apply`) · `delete_key` (definition `windows.registry.delete_key`) · `delete_user_value` (definition `windows.registry.delete_user_value`) · `delete_value` (definition `windows.registry.delete_value`) · `enumerate_keys` (definition `windows.registry.enumerate_keys`) · `enumerate_values` (definition `windows.registry.enumerate_values`) · `get_user_value` (definition `windows.registry.get_user_value`) · `get_value` (definition `windows.registry.get_value`) · `key_exists` (definition `windows.registry.key_exists`) · `list_profiles` (definition `windows.registry.list_profiles`) · `set_user_value` (definition `windows.registry.set_user_value`) · `set_value` (definition `windows.registry.set_value`) |
| **Security** | `get_value`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `set_value`: securable `Infrastructure` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval; `delete_value`: securable `Infrastructure` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval; `delete_key`: securable `Infrastructure` · operation Delete · risk Critical · dispatch Destructive · approval gate AdminOrApproval; `key_exists`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `enumerate_keys`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `enumerate_values`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `get_user_value`: securable `Infrastructure` · operation Read · risk Medium · dispatch ReadOnly · approval gate AdminOrApproval; `list_profiles`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `set_user_value`: securable `Infrastructure` · operation Write · risk High · dispatch Mutating · approval gate AdminOrApproval; `delete_user_value`: securable `Infrastructure` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval; `apply`: securable `Infrastructure` · operation Delete · risk Critical · dispatch Destructive · approval gate AdminOrApproval |
| **Roles** | execute: `get_value`: endpoint-admin, endpoint-operator; `get_user_value`: endpoint-admin; `list_profiles`: endpoint-admin, endpoint-operator; `set_value`: endpoint-admin; `enumerate_keys`: endpoint-admin, endpoint-operator; `delete_value`: endpoint-admin; `delete_key`: endpoint-admin; `key_exists`: endpoint-admin, endpoint-operator; `enumerate_values`: endpoint-admin, endpoint-operator; `set_user_value`: endpoint-admin; `delete_user_value`: endpoint-admin; `apply`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

All twelve actions are direct, synchronous Win32 registry calls: there is no scheduled gather. The six read actions (`get_value`, `key_exists`, `enumerate_keys`, `enumerate_values`, `get_user_value`, `list_profiles`) open a key read-only and read or list it; every registry-controlled string they render passes through `sanitize_field` (trailing NULs are dropped; `|`, every control character except TAB (CR, LF, ESC and an interior NUL among them), DEL, the C1 controls U+0080-U+009F and U+2028 and U+2029 each become `_`), so no read output can contain a line that starts with `audit|`, split a log line, start a terminal escape or be cut short at the plugin ABI. `get_user_value` and `list_profiles` read a REG_SZ, REG_EXPAND_SZ or REG_LINK value up to its first NUL, as Windows does, so data after an interior NUL is not shown there; `get_value` shows it as `_`. The rendered text is DISPLAY text: the folded characters cannot be recovered from a row, so two names that differ only in one of them render alike (caveat 5). `get_user_value` resolves the target profile through the same `ProfileList` walk `list_profiles` exposes, reads the live `HKEY_USERS\<SID>` hive if the user is logged in, and falls back to an offline `RegLoadKeyW` mount of `NTUSER.DAT` (under `SeBackup`/`SeRestore` and a process-wide mutex serialising the whole offline arm) only when the user is logged out. The seven `hive`+`key` actions validate through one `parse_target` helper, which also logs (never blocks) access to a few sensitive `HKLM` subtrees via `spdlog::info`.

The six mutating actions (`set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, `apply`) share one core (`registry_core.hpp`, over an injected registry; `registry_win.cpp` binds it to `Reg*W`). Each obtains a CHECKED handle for the key, and every step after that -- the previous-value capture, `RegSetValueExW`, the verifying read-back, `RegDeleteValueW`, `NtDeleteKey(h)` -- runs on that handle: nothing re-resolves the path by name, and no handle outlives the command. There are two ways to the handle.

- **The fast open (`HKLM` and `HKU` only).** ONE `RegOpenKeyExW` of the whole path with `REG_OPTION_OPEN_LINK`, then `NtQueryKey(KeyNameInformation)` names the object the handle is bound to. The open is accepted only when that kernel name equals `<root kernel name>\<requested path>` (every byte exact except that A-Z fold, so a name that differs in non-ASCII case, a name that does not fit the 4 KiB buffer and a failed query all decline) and the leaf has no `SymbolicLinkValue`. A registry link before the leaf makes the kernel open the link's TARGET, whose name cannot equal the requested one, so the fast open can only accept the canonical object with no real link traversed; everything else declines to the walk. A `set_value` on an existing key is 7 calls across the plugin's registry seam (`open_path`, `final_name`, the link probe, capture, set, read-back, close; the cached root-name lookup is an eighth), the same at every depth, and about 7 Win32 calls: the link probe, the capture and the read-back are each one `RegQueryValueExW` for a value that fits a 256-byte first buffer (a larger value costs one more read). The walk costs about 3 more per path component, plus two name queries.
- **The walk (the reference).** `open_checked` walks the path component by component from the hive root, opening each component from the previous HANDLE with `REG_OPTION_OPEN_LINK` and probing it for `SymbolicLinkValue`: a registry link is refused (`key_is_link`), never followed. A probe only sees the key as it is at that instant, and a link is made in two steps (the key, then its `SymbolicLinkValue`), so the walk also ends on the fast open's test. It reads the canonical kernel name of the FIRST component's handle right after that open (before its probe; it has to end in the requested first component, else `key_is_link`) and of the leaf handle at the end (after the create loop too), and hands the leaf over only when the leaf's name equals the first component's name plus the remaining requested components (A-Z fold). A link completed after its probe, or a component moved away by a rename, leaves the handle bound to an object whose name is not the requested path: the action is refused `key_is_link` and no value is written, and a name that cannot be read is refused with its Win32 token (including one holding a NUL or a lone surrogate: `win32:13`). A link completed during the create loop is the one case where the walk has already written: a create is relative to a handle the kernel parses again, so the keys can land beneath the link's target. The keys a creating walk makes stay owned by the operation until its verified write is over (`Opened::made`; its destructor is the rollback). So a walk that does not hand its leaf over (the name test refuses, a later create fails, or a later create finds its key already there), and an exception anywhere from the first create to the end of the verified write (an allocation failure while capturing the previous value, writing or reading back), try to delete every key the walk created, by its own handle, leaf first, after the value the write had set when it had landed, so that normally nothing is left (`result=refused`, `created=0`, with the reason it stopped for: `key_is_link`, `concurrent_change` or the Win32 token; after an exception the plugin's fixed failed audit line, caveat 2). The rule is the same without an attacker: a create that fails part-way under a plain parent (say `access_denied` on the second component) also removes the first. A key a create merely opened is closed, never deleted. The rollback is BEST EFFORT. A key that holds a value or a subkey when the rollback checks it is kept, because `NtDeleteKey` would destroy the values with it (the rollback asks `RegEnumValueW` first), and so is a key whose delete failed: each is counted in the audit line (`result=failed`, `created=<n>`). Windows has no delete-if-empty call, so two windows stay open: a value another writer puts into the key between that check and the delete is deleted with the key, and a value another writer puts over our own same-named value before the rollback deletes it by name is deleted with it. After a double fault (a rollback step that itself fails or throws) the value and the keys can stay with `created=-` and nothing logged. One derivation serves every hive, `HKCU` and `HKCR` included, and costs two `final_name` calls per walk whatever the depth. It is always used for `HKCU` (it resolves per calling user) and `HKCR` (a merged view of two trees), neither of which has one kernel name to compare with, for a key that is missing, and whenever the fast open declines. It alone produces the verdict token and creates: a missing component is created component-wise from the checked parent, a create that finds the key already there refuses `concurrent_change`, and a creating action never creates a key directly beneath the hive root (`root_level_create`).

The two differ in exactly two ancestor-only cases where the walk is the stricter (see Caveats); in both the write lands on the real requested key, as registry 1.0.0's single open did. A path under `HKLM\SYSTEM\CurrentControlSet`, itself a link to the active control set, is refused on both: write under `HKLM\SYSTEM\ControlSet001` (or the numbered set `Select\Current` names); registry 1.0.0 followed it, reads still do. `set_value` writes any of the six types (`REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_MULTI_SZ`, `REG_QWORD`) from text or exact `data_hex` bytes, reads the value back on the same handle and compares type and bytes; a mismatch fails the action (`verify_mismatch`). `delete_key` refuses a key that has subkeys (`key_has_subkeys`) unless `recursive=true`, and deletes by handle with `NtDeleteKey`, never `RegDeleteTreeW`, which follows a registry link met inside a tree; a link at the leaf is opened as the link object, so the delete removes the link and never its target. Without `recursive` its counts are what the key held: `counted_keys|1` and `counted_values|<n>`, with `capped|1` when the value enumeration stopped at its cap of 10,000 nodes, the key plus up to 9,999 values (`counted_values` is then a lower bound; the delete still removes the key with all its values). Every mutating action captures the previous value first and emits ONE `audit|` line per operation (see "Audit line grammar and producer contract"; `apply` emits one per plan item).

**Recursive `delete_key`.** `recursive=true` first VETS the tree (`count_tree`): every child is opened from its parent's handle with `REG_OPTION_OPEN_LINK` and probed for `SymbolicLinkValue`, up to 10,000 keys and values and 600 levels (one open handle per level is held, at most 601). A link anywhere in the tree refuses the call `key_is_link` with nothing deleted, and so does a child whose raw UTF-16 name is not well-formed (a lone surrogate or a NUL: its lossy U+FFFD spelling would open a sibling, or nothing), as `unrepresentable_name`; a tree the vet could not finish is refused `tree_too_large` when the delete is real (a dry run reports the lower bound with `capped|1`). `dry_run=true` stops there: `status|ok`, the vet's counts, `dry_run|1`, nothing deleted. The real delete (`delete_subtree`) is post-order: every child it finds AT DELETE TIME is opened again with `DELETE` and probed again, and removed by `NtDeleteKey` on its own handle; a removed child no longer enumerates, so the loop asks for index 0 until none is left. **The vet is a size bound and a link sweep, not a list of the keys it saw.** A key added under the tree after the vet is deleted and counted like any other (it sits under the key the operator named); a link added since is refused `key_is_link`, and a child with a malformed raw name added since `unrepresentable_name` (the keys already removed stay counted and the result is `failed`); a tree that outgrew the bound stops `concurrent_change`. The counts of a real run are what was REMOVED (exact when it succeeds, the partial total when it stopped), so they can exceed a dry run's snapshot. A link key whose `SymbolicLinkValue` lands after its probe is still only ever deleted as the link object by its own handle and has no children to enumerate; the walk does not repeat the kernel-name check per child (one `NtQueryKey` each, on the delete path): it relies on a link key enumerating no children.

**Per-user writes (`set_user_value`, `delete_user_value`).** The profile is resolved as `get_user_value` resolves it (`resolve_profile`), and the core's `set_value_verified` / `delete_value_verified` then run on the ROOT of the hive `with_user_hive` hands over: the live `HKEY_USERS\<SID>` hive when the user is logged in (no lock), otherwise the offline `NTUSER.DAT` mount, under the process-wide `offline_hive_mutex` for the whole arm and behind the DEFAULT-ON hive-file guard (no custom check, so no deadline). The root of a user hive has no kernel name the fast open could compare, so a per-user write takes the walk, which never creates a key directly beneath the hive root (`root_level_create`). On the offline arm the written key is flushed with `RegFlushKey` before the unload (`flush_on`), because `RegUnLoadKeyW` does not itself modify the file; a flush that fails fails the write (`flush_failed:<token>`: durability is unknown; a creating write's keys are rolled back, an overwrite keeps its verified value in the mounted hive). After the unload the plugin probes `HKU\<SID>` once (`classify_offline_write_race`): a hive that has become LOADED means a session loaded the file after the write returned and is reported as `warning|hive_loaded_after_offline_write`; a logon that failed while the hive was mounted leaves no trace (caveat 4). `render_user_write` orders the output: the `hive_unload_failed` warning first, then the terminal hive error naming the guard's token, then the race warning, then the audit line (`hive=HKU`, `sid=<SID>`; a hive that was not reached or was refused is `result=refused` with `hive_not_found`, `privilege_missing`, `hive_mount_failed` or the guard's token as the reason; a durable write whose mount then failed to unload stays `result=ok` with `reason=hive_unload_failed`) and `status|ok` / `error|<token>`.

**`apply`.** One `plan` (a JSON array of at most 256 flat objects, at most 64 KiB) of `set_value`, `delete_value`, `create_key` and non-recursive `delete_key` items on `HKLM`, `dry_run` true by default. `parse_plan` refuses a whole plan on a shape error (`invalid_plan:<why>[:<index>]`) or as `dependent_items:<i>:<j>` (two value ops on one key and name, or a key op over another item's equal, ancestor or descendant key, ASCII-case-insensitively), so no item's verdict depends on an earlier one and a dry run can equal a real run; every other defect rides its item (`invalid_hive`, a bad path or name, a value that does not encode). `run_apply` opens each DISTINCT key once, on a checked handle (the first item on it does the open; `HKLM` is fast-eligible), and every later value item on that key reuses the handle; a FAILED open is never cached, so a `delete_value` on a missing key followed by a `set_value` on it still creates the key. Per item it captures the facts, takes the ONE verdict function (`refusal_reason`), identically in both modes, and only a real run then mutates and verifies; its verdicts are `would_apply` / `applied` / `refused` / `failed` / `skipped`. The dry run opens with the mutation's own access mask and, where a real run would create, asks for create access on the deepest existing key by a self re-open with `KEY_CREATE_SUB_KEY` (nothing is created); a first component missing under the hive root is `root_level_create` in both modes. **That probe has a limit, stated plainly: it proves create access on the existing parent, not the ACL a key that does not exist yet will inherit.** A real run can therefore still be refused or fail where the dry run said `would_apply` (the keys it made are rolled back by handle and `created` reports any that stayed). `delete_key` in a plan is non-recursive and refuses a link leaf (no op recreates a link); it vets EVERY value of the leaf by streaming (`vet_leaf_values`: up to the 10,000-node bound, past which the item is `tree_too_large`) and refuses `unsupported_old_type` or `unrepresentable_name` before deleting. The plan is NOT transactional: `continue_on_error=false` stops at the first refused or failed item and reports the rest `skipped`; the exit code is 1 and `error|partial_failure` closes the reply whenever any item was refused or failed. Nothing is persisted on the endpoint: the undo manifest is the reply.

**The exact-name rule and the undo budget.** Every key path and value name a manifest row carries must read back as exactly what is in the registry, so one predicate (`representable`) decides: `row_field(name) == name` -- no `|`, no control character (TAB aside), no DEL, C1 control, U+2028 or U+2029, no invalid UTF-8, no NUL -- and in addition not the literal `-` (a row spells the default value that way) and not ending in a backslash (the server's column splitter reads `\|` as an escaped pipe). A name that fails it is refused `unrepresentable_name` before anything is changed, for the plan's own names and for the name of every value of a key an item would delete. That value name is the raw UTF-16 name the registry enumerates, and it must be well-formed UTF-16: one holding a lone surrogate or a NUL (the kernel accepts any 16-bit unit) has no exact UTF-8 spelling, a display read shows a lone surrogate as U+FFFD, and that form names a different value (or none), so it is refused `unrepresentable_name` too, in the dry run and the real run alike; a value really named with U+FFFD is well-formed and is deleted and restored like any other. a value of a key an item would delete whose name this plugin could not write back with `set_value` (a TAB, which `representable` itself accepts, or another control byte) is refused `unrepresentable_name` too, so on a `delete_key` item the token means "the manifest could not restore it by that name", not only "a row cannot spell it". A previous value this plugin could not write back (a type it cannot write, such as `REG_NONE`, a shape it would refuse, or a size over 1 MiB) is `unsupported_old_type`. One 512 KiB `CaptureBudget` charges every retained byte -- the data, the name and a fixed 64 bytes per row -- BEFORE anything is kept or rendered; a row that does not fit is not retained and the summary says `undo_complete|0`. The dry run charges the same way, so the operator sees an incomplete manifest before mutating. Hex doubles what is retained, so the whole reply stays under the dispatcher's 2 MiB capture cap (`local_dispatcher.hpp`): the retained rows render to about 1 MiB, at most 256 audit lines (each under 2 KiB) add 512 KiB, and the item rows (key and name text from the 64 KiB plan) and the summary add about 100 KiB. Undo coverage per op:

| Op | What undoes it |
|---|---|
| `set_value` | the item row's previous value (`old_state`, `old_type`, `old_hex`): `present` -> `set_value` with `data_hex`; `absent` -> `delete_value`; `created` above 0 means the write also made that many trailing key components -> `delete_key` of each, deepest first (one plan cannot hold a key and its descendant: `dependent_items`, so one call per level); `unreadable` was refused before anything changed |
| `delete_value` | the previous value in the item row -> `set_value` with `data_hex` |
| `create_key` | `created` above 0 -> `delete_key`, deepest first; 0 means the key existed and there is nothing to undo |
| `delete_key` | one `undo` row per retained value (name, type, hex) -> `create_key`, then `set_value` per row, in a second plan (a key op and a value op on one key are `dependent_items`); a row cut or not retained makes `undo_complete|0` |

Code anchors (file and function; line numbers move with every edit): the fast open `open_fast`, the checked walk `open_checked`, its name test `leaf_name_check` and its link probe `probe_link`, the guarded value read `query_value_bounded`, the verifying write `write_value_on`, the by-handle delete `delete_key_on`, the recursion `count_tree` / `delete_subtree` and the counts in `delete_key_tree`, the flush `flush_on`, the per-user output `render_user_write`, the apply layer `refusal_reason` / `vet_leaf_values` / `run_apply` (all in `registry_core.hpp`); the plan and row layer `parse_plan`, `representable` and `row_field` (`registry_plan.hpp`); the encoders `encode_value`, `validate_key_path`, `render_audit_line`, `restorable` and `classify_offline_write_race` (`registry_parsers.hpp`); the kernel calls `Win32Registry::open_path`, `final_name`, `root_name`, `delete_key_by_handle` and `flush_key` (`registry_win.cpp`); the server-side binding `registry_audit_events_for_frame` (`server/core/src/plugin_result_audit.hpp`).

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
| `apply` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `delete_key` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `delete_user_value` | ✅ supported · rung 1 · win32_registry+hive_mount | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `delete_value` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `enumerate_keys` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `enumerate_values` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `get_user_value` | ✅ supported · rung 1 · win32_registry+hive_mount | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `get_value` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `key_exists` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `list_profiles` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `set_user_value` | ✅ supported · rung 1 · win32_registry+hive_mount | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |
| `set_value` | ✅ supported · rung 1 · win32_registry | 🟡 planned · rung 1 · defaults/CFPreferences (per-domain plist) | 🟡 planned · rung 2 · dconf/gsettings |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`apply` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`apply` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_key` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_key` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_user_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`delete_user_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
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
- **`set_user_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`set_user_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
- **`set_value` / macOS** — planned stub: not implemented, the action answers registry|unsupported|...
- **`set_value` / Linux** — planned stub: not implemented, the action answers registry|unsupported|...
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | Writes against `HKLM\*` need the service account in `Administrators`; `HKCU\*` needs no elevation. `get_user_value`, `set_user_value` and `delete_user_value` use the offline-hive fallback only when the target user is logged out: it needs `SeBackupPrivilege`+`SeRestorePrivilege`, already granted to the service account, so there is no new grant (the privileges are enabled on the PROCESS token for the span of the mount, a documented residual of `with_user_hive`); the live-hive path, the machine-hive writes (`apply` included) and `list_profiles` need no elevated privilege beyond the key's own ACL. `NtDeleteKey` and `NtQueryKey` (ntdll) need no privilege beyond `DELETE` on the key and a handle the caller already holds. | 2026-10-23, bare-metal, elevated interactive user: the nine registry 2.0.1 actions captured (`docs/samples/windows.txt`; the three added in 2.1.0 carry a `[not captured]` marker there: they mutate the live registry, so they are not run on a capture host); the write arms, the recursive delete, the per-user writes and `apply` also run in `tests/unit/test_registry_write_local_dispatcher.cpp` and `tests/unit/test_registry_win_internals.cpp` on elevated Windows runs | `error\|key not found` / `error\|value not found` (reads; `get_value` answers `error\|value changed while reading ...` for a value that kept growing through its bounded re-reads and `error\|win32:<code>` for any other failed read); the mutating actions name the cause: `error\|access_denied`, `key_not_found`, `value_not_found`, `key_is_link`, `key_has_subkeys`, `concurrent_change`, `root_level_create`, `verify_mismatch`, `invalid_key_path`, `invalid_value_name`, `invalid_type`, `invalid_data`, `value_overflow`, `tree_too_large`, `unsupported_old_type`, `unrepresentable_name`, `flush_failed:<token>`, `win32:<code>` or `exception` (the token table under Outputs says what each means) |
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
| `windows.registry.apply` | `plan` | string | yes | - | maxLength 65536 | A JSON array of up to 256 flat objects (64 KiB at most). Fields (all strings): `op` (set_value, delete_value, create_key or delete_key), `hive` (HKLM, the default and the only one), `key`, `name`, `type`, `value`, `data_hex`. set_value takes type (default REG_SZ) and value or data_hex, exactly as the set_value action; a present but empty `data_hex` is the zero-byte form (REG_BINARY only), which lets a captured empty value round-trip. delete_value takes key and name; create_key and delete_key take key only (delete_key is NOT recursive and refuses a link). A set_value or create_key item whose first key component does not already exist directly under the hive is refused root_level_create, in a dry run and a real run alike. An agent still on registry 2.0.x answers `error\|unknown action`. |
| `windows.registry.apply` | `dry_run` | string | no | true | enum: true, false | "true" (the default) reports every item's verdict and changes nothing; "false" applies the plan. Any other spelling is refused as invalid_data. |
| `windows.registry.apply` | `continue_on_error` | string | no | false | enum: true, false | "true" keeps applying later items after a refused or failed one; "false" (the default) stops and reports the remaining items skipped. |
| `windows.registry.delete_key` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive containing the key, e.g. "HKCU". |
| `windows.registry.delete_key` | `key` | string | yes | - | - | Registry key path to delete, relative to the hive root. |
| `windows.registry.delete_key` | `recursive` | string | no | false | enum: true, false | "true" deletes every subkey and value beneath the key as well; "false" (the default) refuses a key that has subkeys. The tree is vetted first (at most 10,000 keys and values and 600 levels, else tree_too_large with nothing deleted; a registry link inside it is refused as key_is_link), and the counts of a dry run are a snapshot. Any other spelling is refused as invalid_data. Needs registry 2.1.0 on the agent: registry 2.0.x ignores it. |
| `windows.registry.delete_key` | `dry_run` | string | no | false | enum: true, false | "true" counts what a real run would remove (with `recursive`, the vetted tree) and deletes nothing; "false" (the default) deletes. Needs registry 2.1.0 on the agent: an agent at registry 2.0.x ignores this flag and DELETES a key that has no subkeys, so upgrade agents first (docs/user-manual/upgrading.md). |
| `windows.registry.delete_user_value` | `username` | string | no | - | maxLength 256 | Windows profile folder name to resolve via ProfileList (see list_profiles), matched case-insensitively. Either username or sid is required; sid takes precedence if both are given. |
| `windows.registry.delete_user_value` | `sid` | string | no | - | maxLength 256 | Windows security identifier of the target profile, as an alternative to username. Must match one of the profiles list_profiles would report. |
| `windows.registry.delete_user_value` | `key` | string | yes | - | maxLength 255 | Registry key path relative to the resolved user's hive root (at most 255 bytes and 32 components). |
| `windows.registry.delete_user_value` | `name` | string | yes | - | maxLength 16383 | The registry value name to delete. Empty deletes the key's default value. |
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
| `windows.registry.set_user_value` | `username` | string | no | - | maxLength 256 | Windows profile folder name to resolve via ProfileList (see list_profiles), matched case-insensitively. Either username or sid is required; sid takes precedence if both are given. |
| `windows.registry.set_user_value` | `sid` | string | no | - | maxLength 256 | Windows security identifier of the target profile, as an alternative to username. Must match one of the profiles list_profiles would report; a sid not found there is rejected. |
| `windows.registry.set_user_value` | `key` | string | yes | - | maxLength 255 | Registry key path relative to the resolved user's hive root (e.g., "Software\\MyApp"); created if it does not exist beneath an existing top-level key. At most 255 bytes and 32 components, as set_value. |
| `windows.registry.set_user_value` | `name` | string | yes | - | maxLength 16383 | The registry value name to write. Empty writes the key's default value. At most 16,383 bytes. |
| `windows.registry.set_user_value` | `value` | string | no | - | - | The value data to write, as text; interpreted per `type` exactly as in set_value. Send exactly one of `value` and `data_hex`; a missing or empty one writes an empty value of the type. |
| `windows.registry.set_user_value` | `data_hex` | string | no | - | maxLength 2097152 | The exact bytes to write, as hex, for any type; give it INSTEAD of `value` (both non-empty is refused as invalid_data). Shape is checked per type, as in set_value. |
| `windows.registry.set_user_value` | `type` | string | no | - | enum: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD | Registry value type to write. Defaults to REG_SZ when omitted. |
| `windows.registry.set_value` | `hive` | string | yes | - | enum: HKLM, HKCU, HKCR, HKU | Registry hive to write to, e.g. "HKCU". |
| `windows.registry.set_value` | `key` | string | yes | - | - | Registry key path relative to the hive root; created if it does not already exist beneath an existing top-level key, e.g. "Software\\MyApp". At most 255 bytes and 32 components; a hive alias, an empty, "." or ".." component and control characters are refused on the instruction and MCP routes; POST /api/command passes an embedded NUL to the plugin as a C string, so the value is cut at it. |
| `windows.registry.set_value` | `name` | string | yes | - | - | The value name to write, e.g. "InstallPath". Empty writes the key's default value. At most 16,383 bytes. |
| `windows.registry.set_value` | `value` | string | no | - | - | The value data to write, as text; interpreted per `type`: decimal digits for REG_DWORD / REG_QWORD, literal text for REG_SZ / REG_EXPAND_SZ, LF-separated non-empty records for REG_MULTI_SZ (split on LF only, so a CR stays inside its record; an empty record or a trailing LF is refused as invalid_data; empty text is the empty list), hex digits for REG_BINARY (empty is zero bytes). Send exactly one of `value` and `data_hex`. When neither is sent, or the one sent is empty, the write stores an empty value of the type and answers ok: an empty string, the empty list or zero bytes (REG_DWORD and REG_QWORD refuse it as invalid_data), so a misspelt parameter name writes an empty value instead of failing. Through MCP `execute_instruction` and the result-set execute routes every parameter value is limited to 64 KiB. |
| `windows.registry.set_value` | `data_hex` | string | no | - | maxLength 2097152 | The exact bytes to write, as hex, for any type; give it INSTEAD of `value` (both non-empty is refused as invalid_data). Shape is checked per type: 4 bytes for REG_DWORD, 8 for REG_QWORD, a terminating NUL for the string types, a trailing double NUL for REG_MULTI_SZ. Use it for exact bytes you hold from another source. An empty `data_hex` is the same as omitting it here. The plugin takes at most 1 MiB of data (2,097,152 hex characters), but MCP `execute_instruction` and the result-set execute routes limit every parameter value to 64 KiB, so through them it carries at most 32 KiB of data; the direct command route is not under that cap. Needs registry 2.0.0 on the agent: registry 1.x ignores it and writes an EMPTY REG_SZ over the value, answering `status\|ok` (with type=REG_DWORD and data_hex only, 1.x throws and writes nothing). |
| `windows.registry.set_value` | `type` | string | no | - | enum: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD | Registry value type to write. Defaults to REG_SZ when omitted. Mixed fleets: an agent still running registry 1.x stores REG_QWORD, REG_MULTI_SZ, REG_EXPAND_SZ and REG_BINARY values as REG_SZ text and answers `status\|ok`, so upgrade the agents to registry 2.0.0 before using them. |
<!-- END GENERATED -->

### Outputs

This plugin does not emit a uniform pipe-joined "row"; each action has its own shape. `get_value`, `get_user_value` and `key_exists` write one self-describing `field_name|value` line per field on success; a failure writes an `error|...` line and returns rc 1, so `-` is never used as an absence placeholder in the read actions. Every mutating action that resolves its target writes ONE `audit|...` line first (grammar below; `-` is "not applicable" inside it), then `status|ok` or `error|<token>`; a missing hive or key or an unparseable hive is a bare `error|...` line with nothing opened and no audit line, while a key path or value name that fails shape validation after the hive resolved is audited as `result=refused`; the dashboard shows the `audit` line as one more row. `delete_key` appends four `key|value` rows after `status|ok`: `counted_keys` and `counted_values` (without `recursive`, the key itself and the values it held; with it, the keys and values the delete REMOVED, or on a dry run the vet's count), `dry_run` (1 for a dry run, 0 for a real run) and `capped` (1 when the vet or the value count stopped at its bound, 10,000 keys and values and 600 levels, which makes the counts a lower bound; a real recursive delete past the bound is refused `tree_too_large` instead); the counts are point in time, since a writer racing the delete can add values the count never saw. `set_user_value` and `delete_user_value` write the hive lines first when there are any (a `warning|hive_unload_failed: ...`, the race warning, the terminal `error|...` of an unreachable or refused hive), then the audit line (`hive=HKU`, `sid=<SID>`) and `status|ok` or `error|<token>`. `apply` writes, per plan item that ran or was refused, its `audit|` line and then its `item|` row (an item skipped after a stop has only its `item|` row), then one `undo|` row per retained value of each key it deleted, one `summary|` row and, when any item was refused or failed, `error|partial_failure` with rc 1. A whole-plan refusal (`error|invalid_plan:<why>[:<index>]`, `error|dependent_items:<i>:<j>` or `error|invalid_data` for a flag that is not `true`/`false`) is a bare error line with nothing opened and no audit line. The row shapes (cells split on `|`):

| Row | Cells |
|---|---|
| `item` (14) | `item`, index, op, hive, key, name (`-` for none or the default value), verdict, reason (`-` when none), verify (`ok`, `mismatch`, `-`), created, old_state (`absent`, `present`, `unreadable`, `-` for a key op), old_type, old_hex (the retained bytes, then `~<total>` when cut or dropped by the budget), new_len |
| `undo` (6) | `undo`, the index of the `delete_key` item, name (`-` for the default value), type, hex (the retained bytes, then `~<total>` when cut), truncated (1 when cut) |
| `summary` (8) | `summary`, total, applied (would apply, in a dry run), refused, failed, skipped, dry_run (1/0), undo_complete (1/0) |

The key and name cells of an item that proceeds are exact (`representable`); a refused item's cells are the folded display form. An `audit|` row is the same 20-part line as for a single action, with `op=apply.<op>`. `enumerate_keys` writes one `subkey|<name>` line per subkey; a genuinely empty key emits zero lines with rc 0. `enumerate_values` writes one line per value shaped `value|<name>|<type>` -- the leading `value` is a fixed literal tag, not one of the two documented columns (`name`, `type`); see Caveats. `list_profiles` writes one true pipe-joined row per profile (`<sid>|<name>|<path>|<state>`, no discriminator prefix) and zero rows is a structural success.

**Error tokens of the mutating actions.** `error|<token>` and the audit line's `reason=` carry the bare token and nothing more, and the agent logs nothing about an ordinary failure (an exception is the exception: it is logged with the action name). What each means and where to look:

| Token | Meaning | What to check |
|---|---|---|
| `access_denied` | `ERROR_ACCESS_DENIED`, from several causes: the agent identity's ACL on the key refuses an access the action asks for (caveat 3 lists them); a parent the walk may traverse but not read (the walk opens every component with `KEY_QUERY_VALUE` to probe it; the fast open does not); a create refused on a parent, or an inherited ACL that gives the new key no `DELETE`; the link probe itself refused | the ACL of the key and of each parent for the agent identity |
| `key_not_found` | the key, or a component of the path, does not exist (nothing was written) | the spelling; `key_exists`; a `WOW6432Node` path |
| `value_not_found` | `delete_value` named a value the key does not hold (nothing deleted) | `enumerate_values` |
| `root_level_create` | the first key component is missing directly under the hive root; a creating write never creates one | the parent has to exist already |
| `key_is_link` | a component is a registry symbolic link, or the handle's kernel name is not the requested path (a link completed mid-walk, a component renamed, a non-ASCII case variant, a decoy value named `SymbolicLinkValue` on an ancestor); nothing was written | the link's target path; the key's stored spelling |
| `key_has_subkeys` | `delete_key` without `recursive` on a key with subkeys (nothing deleted); an `apply` `delete_key` item on one | `recursive=true`, or delete the subkeys first |
| `tree_too_large` | a REAL recursive delete whose vet hit its bound (10,000 keys and values, 600 levels), or an `apply` `delete_key` item on a leaf with more values than that; nothing deleted | delete the tree in parts |
| `unsupported_old_type` | an `apply` item's previous value (or a value of a key it would delete) is a type this plugin cannot write (`REG_NONE`, `REG_LINK`, `REG_DWORD_BIG_ENDIAN`, unknown), a shape `set_value` would refuse, or over 1 MiB; refused before anything changed, so the change could not be undone | change it with another tool |
| `unrepresentable_name` | an `apply` key path or value name a manifest row cannot spell exactly (see "The exact-name rule"), a value of a key it would delete that this plugin could not write back by that name or whose raw UTF-16 name is not well-formed, or (a recursive `delete_key`) a key in the tree whose raw name is not well-formed | rename, or remove it with another tool |
| `flush_failed:<token>` | a per-user write verified, but `RegFlushKey` on the offline hive failed; durability is unknown | read the value back, retry |
| `hive_not_found`, `privilege_missing`, `hive_mount_failed`, a hive-file guard token (`hive_path_reparse_ancestor`, ...) | a per-user write could not reach or trust the hive; nothing was written | the hive line above the audit line says why |
| `concurrent_change` | another party created the key between the walk's check and its create, or the handle went stale (`ERROR_KEY_DELETED`) | read the key and retry |
| `verify_mismatch` | the read-back differs from what was written, or the key did not read back as deleted. It can be a false positive: another writer, or a Group Policy refresh, that touches the value between the write and the read-back looks the same | `get_value` the value and decide |
| `invalid_key_path`, `invalid_value_name` | the input failed shape validation before anything was opened (limits under Inputs) | the parameter |
| `invalid_hive`, `dependent_items`, `invalid_plan:<why>` | `apply`: an item names a hive other than `HKLM`; two items touch the same value or overlap on a key (the whole plan is refused `dependent_items:<i>:<j>`); the plan is not a flat array of objects, too long (256 items, 64 KiB) or has an unknown key, a non-string field or an unknown `op` | the plan |
| `invalid_type` | `type` is not one of the six names (case-sensitive) | the spelling |
| `invalid_data` | the text or `data_hex` does not fit the type: not decimal digits for a number; not hex, or an odd count; a string without its terminating NUL; a REG_MULTI_SZ with an empty record or a trailing LF (records are split on LF only, so a CR stays in its record); `value` and `data_hex` both sent | the parameter |
| `value_overflow` | a number out of range for its type, or data over 1 MiB | the parameter |
| `win32:<code>` | any other Win32 or NT failure, by number, including the answer when `NtDeleteKey` refuses for a reason not listed here (caveat 4) | `net helpmsg <code>` |
| `exception` | an exception ended the action (an allocation failure is the realistic one); the audit line is the fixed failed line of caveat 2 | the agent log, and "A partial or failed create" under Where the data goes |

A misspelt or missing `value` parameter on a `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ` or `REG_BINARY` write is not an error: it writes an empty value of the type and answers `status|ok` (`REG_DWORD` and `REG_QWORD` refuse it as `invalid_data`).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`windows.registry.apply` — `row_kind|field_1|field_2|field_3|field_4|field_5|field_6|field_7|field_8|field_9|field_10|field_11|field_12|field_13`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `item` `undo` `audit` `summary` | Windows | `item` | Row shape discriminator (field 0). Values: item, undo, audit, summary. A closing `error\|partial_failure` line, which has no row_kind, follows the summary whenever any item was refused or failed. |
| `field_1` | string | - | Windows | `0` | item and undo: the plan item index (0-based). audit: op=apply.<op>. summary: the item count. |
| `field_2` | string | - | Windows | `set_value` | item: the op (set_value, delete_value, create_key, delete_key). undo: the value name ("-" for the default value). audit: hive=. summary: items applied (or that would apply in a dry run). |
| `field_3` | string | - | Windows | `HKLM` | item: the hive. undo: the value type. audit: result= (ok, refused, failed). summary: items refused. |
| `field_4` | string | - | Windows | `SOFTWARE\Acme` | item: the key path (exact for an item that proceeds). undo: the value data as hex (the kept bytes, then ~<total> when the capture was cut). audit: reason=. summary: items failed. |
| `field_5` | string | - | Windows | `Mode` | item: the value name ("-" for none or the default value; exact for an item that proceeds). undo: 1 when the capture was cut, else 0. audit: verify=. summary: items skipped after a stop. |
| `field_6` | string | - | Windows | `applied` | item: the verdict (would_apply in a dry run, applied, refused, failed, skipped). audit: key= (capped at 256 bytes). summary: 1 for a dry run, 0 for a real run. |
| `field_7` | string | - | Windows | `-` | item: the refusal or failure token (key_not_found, value_not_found, key_has_subkeys, key_is_link, access_denied, root_level_create, tree_too_large, unsupported_old_type, unrepresentable_name, verify_mismatch, invalid_* ...) or "-". audit: name= (capped). summary: 1 when the undo manifest is complete, 0 when anything was cut or a creating item failed part-way. |
| `field_8` | string | - | Windows | `ok` | item: the read-back verification (ok, mismatch, "-"). audit: type=. |
| `field_9` | string | - | Windows | `0` | item: the number of key components this item created (reverse: delete_key of each, deepest first), predicted in a dry run. audit: len=. |
| `field_10` | string | - | Windows | `present` | item: the previous value state (absent, present, unreadable) for value ops. audit: dry_run=. |
| `field_11` | string | - | Windows | `REG_SZ` | item: the previous value type. audit: counted_keys=. |
| `field_12` | string | - | Windows | `6f006c006400` | item: the previous value as hex (the kept bytes, then ~<total> when it was cut or the undo budget dropped it); restore it with data_hex. audit: counted_values=. |
| `field_13` | string | - | Windows | `8` | item: the new value length in bytes, or "-". audit: capped=. (The six audit tokens that follow -- created, sid, old_state, old_type, old, new -- are in the raw row and the registry.write audit row.) |

**`windows.registry.delete_key` — `status|counted_keys|counted_values|dry_run|capped`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the run succeeded and, on a real run, that the handle read back as deleted (a dry run answers ok too); only ever emitted on success — a failure is reported as an `error\|<token>` line (not exhaustive: key_not_found, key_has_subkeys, tree_too_large, key_is_link, access_denied, verify_mismatch, concurrent_change, invalid_key_path, invalid_data or win32:<code>) and a non-zero exit instead of this column. A run that resolves its hive and key, success or not, also emits one `audit\|op=delete_key\|...` row (dry_run=1 on a dry run, whose success row records that a vet ran, not a deletion); a missing hive or key, or an unparseable hive, is a bare `error\|...` line with nothing opened and no audit row. Values: ok. |
| `counted_keys` | int32 | - | Windows | `4` | Keys in the subtree, the target included: on a real run what the delete REMOVED (exact when it succeeds, the partial total when it stopped), on a dry run or a refusal what the vet counted (a lower bound when capped is 1). A non-recursive delete counts the target alone, so 1. Values: a non-negative integer. |
| `counted_values` | int32 | - | Windows | `5` | Values in those keys, counted the same way (a lower bound whenever capped is 1). Point in time: a writer racing the delete can add values a dry run never saw. Values: a non-negative integer. |
| `dry_run` | bool | - | Windows | `0` | Whether this was a dry run: 1 (counted, nothing deleted) or 0 (a real run). Values: 1, 0 — a digit, never true/false. |
| `capped` | bool | - | Windows | `0` | Whether the vet or the value enumeration stopped at its bound (10,000 keys and values, 600 levels), making the counts a lower bound; reported on a dry run, a refusal as tree_too_large, or a non-recursive delete of a key holding more than 10,000 values (it removes that key with all its values). A real recursive delete past the bound is refused, never capped. Values: 1 (capped), 0 (complete) — a digit, never true/false. |

**`windows.registry.delete_user_value` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the delete was verified (and, on the offline NTUSER.DAT arm only, flushed with RegFlushKey before the unload; a live HKEY_USERS\<SID> delete is not flushed); only ever emitted on success — a failure is an `error\|<token>` line (not exhaustive: value_not_found, key_not_found, hive_not_found, privilege_missing, hive_mount_failed, profile_list_unreadable, a hive-file guard token, flush_failed:<token>, access_denied or win32:<code>), preceded by the hive's own error sentence, and a non-zero exit. The same warnings as set_user_value may precede the audit row. A run whose profile resolves also emits one `audit\|op=delete_user_value\|...` row (hive=HKU, sid=<SID>); a missing sid, username or key, or a profile that is not found, is a bare `error\|...` line with nothing opened and no audit row, while a key path or value name that fails shape validation after the profile resolved is audited as result=refused. Values: ok. |

**`windows.registry.delete_value` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the delete succeeded; only ever emitted on success — a failure is reported as an `error\|` line and a non-zero exit instead of this column. Values: ok. |

**`windows.registry.enumerate_keys` — `subkey`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `subkey` | string | - | Windows | `ProfileList` | One immediate subkey name under the given key; zero rows means the key has no subkeys. Display text (registry 2.0.1 and later): `\|`, every control character except TAB, DEL, the C1 controls, U+2028 and U+2029 each become `_`, so two names that differ only there render alike. Values: free text. |

**`windows.registry.enumerate_values` — `name|type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `name` | string | - | Windows | `ProductName` | The value's name; zero rows means the key has no values. Display text (registry 2.0.1 and later): `\|`, every control character except TAB, DEL, the C1 controls, U+2028 and U+2029 each become `_`, so two names that differ only there render alike. Values: free text. |
| `type` | string | - | Windows | `REG_SZ` | The value's registry type, named via the shared type table shared with get_value and get_user_value. Values: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN. |

**`windows.registry.get_user_value` — `username|value|type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows | `jsmith` | The resolved profile display name the value was read from — falls back to the caller's own username/sid input, then the resolved sid, but is never fabricated and never empty (ADR-0024 D11). Values: free text. |
| `value` | string | - | Windows | `1` | The value's data as a display string: a REG_SZ, REG_EXPAND_SZ or REG_LINK value is read up to its first NUL (as Windows reads it; get_value shows an interior NUL as `_`), REG_MULTI_SZ records are semicolon-joined and REG_LINK gives its target (get_value leaves those two hex-encoded). Display text, not exact: the characters get_value's value column folds become `_` here too (registry 2.0.1 and later). Values: free text. |
| `type` | string | - | Windows | `REG_DWORD` | The registry value type, named via the shared type table. Values: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN. |

**`windows.registry.get_value` — `value|type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `value` | string | - | Windows | `Windows 10 Pro` | The value's data, decoded to a display string, for a value of at most 1 MiB (registry 2.0.1 and later; older agents read the whole value). Never truncated: a larger value fails the action with `error\|value exceeds 1 MiB limit` rather than returning a partial string. Display text, not exact: `\|`, every control character except TAB, DEL, the C1 controls (U+0080-U+009F), U+2028 and U+2029 each become `_` and trailing NULs are dropped, so those characters cannot be recovered from the row; get_value has no exact-bytes mode for a string value (the types it returns as hex are exact). Values: free text. |
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

**`windows.registry.set_user_value` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the write was verified (and, on the offline NTUSER.DAT arm only, flushed with RegFlushKey before the unload; a live HKEY_USERS\<SID> write is not flushed); only ever emitted on success — a failure is an `error\|<token>` line (not exhaustive: hive_not_found, privilege_missing, hive_mount_failed, profile_list_unreadable, a hive-file guard token such as hive_path_reparse_ancestor, flush_failed:<token>, or any set_value token), preceded by the hive's own error sentence, and a non-zero exit. A `warning\|hive_unload_failed: ...`, `warning\|hive_loaded_after_offline_write` or `warning\|hive_post_unload_probe_failed:win32_<n>` line may precede the audit row. A run whose profile resolves also emits one `audit\|op=set_user_value\|...` row (hive=HKU, sid=<SID>); a missing sid, username or key, or a profile that is not found, is a bare `error\|...` line with nothing opened and no audit row, while a key path or value name that fails shape validation after the profile resolved is audited as result=refused. Values: ok. |

**`windows.registry.set_value` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows | `ok` | Confirms the write succeeded and read back identical; only ever emitted on success — a failure is reported as an `error\|<token>` line (not exhaustive: access_denied, key_not_found, root_level_create, key_is_link, concurrent_change, invalid_type, invalid_data, value_overflow, invalid_key_path, invalid_value_name, verify_mismatch or win32:<code>) and a non-zero exit instead of this column. A run that resolves its hive and key, success or not, also emits one `audit\|op=set_value\|...` row carrying the previous and new values (hex, capped); a missing hive or key, or an unparseable hive, is a bare `error\|...` line with nothing opened and no audit row, while a key path or value name that fails shape validation after the hive resolved (invalid_key_path, invalid_value_name) is audited as result=refused. Values: ok. |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result.** Rows/lines travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90 days), queryable at `/api/responses/{id}`.
- **Audit log.** The server records a `registry.write` row only for a `registry` command whose agent-stamped `CommandResponse.action` is one of the six mutating actions; an agent older than this plugin stamps none and produces no rows. Principal, result, retention and the join to the operator's row: `docs/user-manual/audit-log.md`.
- **Agent log.** The plugin's own `spdlog` error lines (for example `registry: <action> raised an exception`) carry no command id: the plugin ABI hands a plugin no command identifier. Attribute a command through the response and audit rows above, which are joined on the command id.
- **A partial or failed create.** A `set_value` row with `result=failed` and `created=<n>` above 0, an `error|exception` reply, or an agent that stopped in the middle of a command can leave keys the call made (and, for a write that landed, its value). Take the hive, key and value name from the request that dispatched the command, not from the audit row: the exception row has `hive=-|key=-|created=-`, and the `command.dispatch` row carries only `registry:set_value -> N agent(s)`. The request parameters are in `executions.parameter_values` of the execution that holds the row's `command_id` (join on it; the command-to-execution mapping is reaped after 24 hours, so the join can come back empty, and then only the dispatching script, workflow or schedule holds the request), or in the dispatching script, workflow or schedule. A call creates only the trailing components of a path that did not exist and the leading ones existed before, and a pre-existing empty parent looks exactly like a created one; the rollback goes leaf first, so the keys a failed call leaves are normally the shallowest of the ones it made, but not when the leaf holds a value or key another party put there: the leaf is kept and every ancestor above it survives with it (`created=<n>` counts the survivors on a returning exit). Read the candidates with `key_exists`, `enumerate_values` and `enumerate_keys`, and decide per key: remove it with `delete_key` (it refuses a key with subkeys, so go leaf first, one call per key) only when this call's creation of it can be shown (for example an earlier `key_exists` for the path answered false) and it is empty; a key that holds a value you did not write is another party's and stays, and so does any key whose creation by this call you cannot show. For an exception whose audit line could not be written, and for an agent that died mid-command, there is no `registry.write` row: only the `command.dispatch` row and the stored response show the attempt.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics: nothing here runs on a schedule; the plugin executes only when an operator or workflow dispatches one of its twelve definitions.
- **Sensitivity.** The audit rows and the `set_value`/`delete_value` responses carry registry data OLD and NEW (hex of the raw bytes, 256 bytes at most per value in an audit row, for every value type) and key paths, so they can hold secrets that live in the registry (a service account's autologon password, a product key, an agent token). **Owner risk acceptance:** old and new values are recorded as raw hex and can contain secrets; the product owner accepted this risk on 2026-10-20 and masking is a planned later change, and nothing in the plugin redacts them today. A key path can name a person. `get_value`/`enumerate_values`/`get_user_value` can return arbitrary registry data, among it `RegisteredOwner`/`DigitalProductId` (a person's name and a device-specific product-key hash); `get_user_value`'s `username` and `list_profiles`' `profile_name`/`profile_path` (e.g. `jsmith`/`C:\Users\jsmith`) directly identify a person and their home directory. The readers are wider than the writers: `AuditLog:Read` and `Response:Read` (the Viewer, Operator, PlatformEngineer, ITServiceOwner and Administrator roles hold both; `Response:Read` is not floored while RBAC is off), the legacy `/events` stream (any authenticated non-service-scoped session) and MCP `query_audit_log`; the executions' `parameter_values` carries the write parameters, `value` and `data_hex` alike, unredacted, and `delete_value` returns the old value in its response too. By default audit rows are retained 365 days (`--audit-retention-days`) and the response store 90 days (`--response-retention-days`); the executions table is not in the server's retention settings and no pass prunes it, so `parameter_values` stays until the database is purged. Read-time redaction is not built.
- **Siblings:** none. Guardian's own real-time registry-key watch (`guard_type: "registry"`) is an unrelated detection mechanism; this plugin is on-demand only, with no watch/trigger surface.
- **MCP / REST.** Discover: `discover_plugins` (summary) -> `yuzu://plugin-docs` (this page as data) -> `discover_instructions` / `get_definition("windows.registry.get_value")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; the audit rows: the audit log API filtered on `registry.write`.

### Audit line grammar and producer contract

The plugin is the producer of the `audit|` line the server parses (`server/core/src/plugin_result_audit.hpp`). One line is the tag `audit` and 19 `name=value` fields, 20 `|`-separated parts, in this order:

| # | Field | Content |
|---|---|---|
| 1 | `op` | `set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, or `apply.<op>` (one line per `apply` plan item, `<op>` being its plan op) |
| 2 | `hive` | `HKLM`, `HKCU`, `HKCR` or `HKU` |
| 3 | `result` | `ok`, `refused` (nothing was mutated, or every key the walk created was removed again) or `failed` (a mutation was attempted) |
| 4 | `reason` | the error token (`access_denied`, `key_is_link`, `verify_mismatch`, `win32:<n>`, ...) or `-` |
| 5 | `verify` | `ok`, `mismatch` or `-` (not read back) |
| 6 | `key` | the key path, scrubbed, cut at 256 bytes with `~<total length>` |
| 7 | `name` | the value name, same rule; `-` for the default value |
| 8 | `type` | the requested value type, or `-` |
| 9 | `len` | length in bytes of the new data, or `-` |
| 10 | `dry_run` | `delete_key` and every `apply.<op>` line: `1` for a dry run (a `result=ok` row then records that a vet ran, not a change: a reader filtering `result=success` must also read `dry_run`), `0` for a real run; `-` otherwise |
| 11 | `counted_keys` | `delete_key` with `recursive`: the keys removed (a real run; the partial total when it stopped) or the vet's count (a dry run, a refusal); without it `1` once the key was found to be a leaf (also when the value count or the delete then failed), `0` when the call was refused earlier (a subkey, or the subkey enumeration failed) or the key not found; `apply.delete_key`: `1` when the key exists, else `0`; `-` otherwise |
| 12 | `counted_values` | `delete_key`: the values counted the same way (a lower bound when `capped`; a partial count when the value enumeration itself failed; `0` when the call was refused before any value was counted, or the key not found); `apply.delete_key`: the values the leaf held; `-` otherwise |
| 13 | `capped` | `delete_key`: `1` when the vet or the count stopped at its bound (10,000 nodes, the keys and values together, and 600 levels), else `0`; `apply.delete_key`: `1` when the leaf holds more values than the bound; `-` otherwise |
| 14 | `created` | the keys this operation created and that are still present: on `ok` the keys the write made (`0` when it made none, always `0` for the deletes); after a walk that stopped, only those it could not delete again or that now hold another party's value or key; `-` in the exception line |
| 15 | `sid` | the resolved profile SID on `set_user_value` and `delete_user_value`; `-` otherwise |
| 16 | `old_state` | the value before the mutation: `absent`, `present` or `unreadable`; `-` when none was captured |
| 17 | `old_type` | its type, or `-` |
| 18 | `old` | hex of its raw bytes for every value type, the first 256 only, then `~<total>` when cut; `-` when none was captured and in a `delete_key` row (an `apply` `delete_key` returns the deleted values as `undo` rows, not here) |
| 19 | `new` | the same rule for the bytes written; `-` for the deletes |

The contract the server relies on (it cannot recover from a violation):

- **One record per operation, one LF-terminated line.** The agent writes the LF; the server tolerates one trailing CR and strips it. An `apply` is one operation per plan item: up to 256 records in one reply, inside the server's 300-line frame bound; three 256-item applies inside one 60-second window exceed the 600-row-per-agent budget, and the later rows are suppressed (counted and logged, `docs/user-manual/audit-log.md`). The `audit|` line of an item is written before its `item|` row, so a sink failure on a later line never costs the evidence; a dry run mints `success` rows with `dry_run=1`.
- **No `|`, LF, CR or other control byte inside a field.** `audit_token` replaces every control byte, `|`, space, `=`, `,`, the C1 controls U+0080-U+009F, U+2028 and U+2029 with `_` and invalid UTF-8 with `?`, and cuts a field at 256 bytes (64 for `op`, `hive`, `reason`, `sid`; 32 for `type`) with `~<length>`, so a registry key or value name that holds a delimiter cannot forge a field, pick the row's `result` or start a second row.
- **`result=`, `reason=` and `verify=` come before the caller-sized `key=` and `name=`.** The server reads `result` as the first `|result=` token of the whole line (never `dry_run=`), but a line past its 4,096-byte bound loses its tail; the whole line stays under 2 KiB by construction.
- **Server bounds.** At most 300 lines of 4,096 bytes per output frame and 600 rows per agent per 60-second window; a bound that bites is counted and logged (`docs/user-manual/audit-log.md`).
- **What `old=` and `new=` carry.** The registry data itself, as hex of the raw bytes, the first 256 per value, then `~<total>` when cut, for every value type (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_QWORD`), with no filter by key or value type: an audit row can therefore hold a secret. **OWNER RISK ACCEPTANCE:** the product owner accepted this risk on 2026-10-20 and masking is a planned later change; no redaction code exists. The readers are every role that holds `AuditLog:Read` or `Response:Read` (Viewer, Operator, PlatformEngineer, ITServiceOwner and Administrator), the legacy `/events` stream (any authenticated non-service-scoped session), MCP `query_audit_log`, and, for the write parameters (`value` as well as `data_hex`), `executions.parameter_values`. By default audit rows are retained 365 days and the response store 90 days; no server pass prunes the executions table. A row is evidence of the change, not a restore point (a value cut at 256 bytes cannot be rebuilt from it).
- **Pinned by tests.** The byte-exact line and the contract case in `tests/unit/test_registry_parsers.cpp`; the plugin's real renderer fed through the server's extractor in `tests/unit/server/test_plugin_result_audit.cpp`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-10-23 · interactive user (elevated; username, SID and profile path anonymised) · leg-hash 2db0b6e73233

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

== action=set_user_value username=jsmith key=Software\YuzuCaptureTmp name=probe value=1
[not captured] Mutating/Irreversible: not executed on a live host

== action=delete_user_value username=jsmith key=Software\YuzuCaptureTmp name=probe
[not captured] Destructive/Irreversible: not executed on a live host

== action=apply plan=[{"op":"create_key","key":"SOFTWARE\\YuzuCaptureTmp"}]
[not captured] Destructive/Irreversible: not executed on a live host
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-10-26 · euid 501 · leg-hash 2db0b6e73233

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

== action=set_user_value username=jsmith key=Software\YuzuCaptureTmp name=probe value=1
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=delete_user_value username=jsmith key=Software\YuzuCaptureTmp name=probe
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=apply plan=[{"op":"create_key","key":"SOFTWARE\\YuzuCaptureTmp"}]
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**Linux** — captured: linux Ubuntu 26.04.1 LTS x86_64 · vm · 2026-10-22 · euid 0 · leg-hash pending

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

== action=set_user_value username=jsmith key=Software\YuzuCaptureTmp name=probe value=1
[not captured] Mutating/Irreversible: not executed on a Linux host (the registry 2.1.0 actions were added after this leg's 2026-10-22 capture)

== action=delete_user_value username=jsmith key=Software\YuzuCaptureTmp name=probe
[not captured] Destructive/Irreversible: not executed on a Linux host (the registry 2.1.0 actions were added after this leg's 2026-10-22 capture)

== action=apply plan=[{"op":"create_key","key":"SOFTWARE\\YuzuCaptureTmp"}]
[not captured] Destructive/Irreversible: not executed on a Linux host (the registry 2.1.0 actions were added after this leg's 2026-10-22 capture)
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The fast open is more permissive than the walk in two ancestor-only cases.** An ancestor the caller may traverse but not read: the walk answers `access_denied`, the fast open accepts. An ordinary non-link ancestor that carries a value named `SymbolicLinkValue`: the link probe cannot tell it from a link, so the walk answers `key_is_link` and the fast open accepts. In both the write lands on the real requested key, which is what registry 1.0.0's single open did; probing every ancestor on the fast path would cost it the constant call count. A decoy value on the LEAF of a `set_value` or `delete_value` is refused on both paths (a `delete_key` leaf is opened as a possible link, so it is not probed). `HKCU`, `HKCR`, a missing key and any failed name query take the walk (same verdicts, more calls; a name query that keeps failing refuses there too). A path whose case differs from the stored spelling only outside ASCII declines the fast open, and the walk then refuses it `key_is_link` (every component, the first included, is compared with the kernel's name by the same ASCII-only fold): write such a key with its stored spelling. If the kernel name of `HKLM` or `HKU` cannot be read at the first write, the fast open is off for that root until the agent restarts. **`HKCR` may be refused `key_is_link` where its merged view reaches the other backing hive.** `HKCR` merges `HKLM\SOFTWARE\Classes` with the calling user's classes hive (the agent runs as `SYSTEM`, so that half is `HKU\.DEFAULT_Classes`). The walk requires the leaf's kernel name to equal the first component's name plus the rest of the requested path, the same compare for every hive; if the merged view resolves a lower component into the other backing hive than the first component, the two names differ and the write is refused `key_is_link` with nothing written, although no link is involved. A refusal is the failure mode, never an unverified write. Measured on Windows 11 (2026-10-23): for an interactive user a key whose first component exists in both backing hives and whose lower component exists only in the machine hive IS refused `key_is_link` (the first component is bound to the user hive, the lower one to `HKLM`); the reverse orientation and every key wholly inside one hive are accepted. As `SYSTEM`, the agent's identity, `HKCR` shows only `HKLM\SOFTWARE\Classes`, so the shape does not arise there. If an `HKCR` write is refused, write under `HKLM\SOFTWARE\Classes` or `HKU\<SID>_Classes` directly. **`HKCU\Software\Classes` is a registry link for a real user.** Measured on Windows (2026-10-25): For a real user's hive `HKCU\Software\Classes` is itself a registry link (to the user's `_Classes` hive), so a creating write below it is refused `key_is_link` (1.0.0 followed it); as SYSTEM, the agent's identity, `HKCU` is `HKU\.DEFAULT` and `Software\Classes` is not a link, so such writes succeed; to write a user's classes use `hive=HKU` with `<SID>_Classes`.
2. **The audit trail is lossy by design.** Key and value names go through `audit_token`, which applies `yuzu::log_token` (space, `=`, `,`, control bytes, DEL, `|` become `_`, and so does a trailing backslash) and then `fold_line_breaks` (the C1 controls U+0080-U+009F and U+2028 and U+2029 become `_`; over 256 bytes, measured after folding, they are cut with `~<length>`), and old/new data is hex capped at 256 raw bytes, so an audit row identifies the change but cannot always reproduce it (a value cut at 256 bytes cannot be rebuilt from it, and the hex can hold a secret: owner risk acceptance, see "Sensitivity"); a `delete_key` row carries counts, not values: `old=-|new=-`; `old=` and the delete counts are point in time; the single actions accept a value named `-`, whose audit line renders `name=-` exactly like the default value. Rows exist only for agents that stamp `CommandResponse.action`: an agent at v0.14.1 or earlier writes registry values but produces no `registry.write` rows, and a read action never does. **An exception inside a mutating action** (an allocation failure while capturing, writing or reading back is the realistic one) is contained at the plugin ABI seam: the plugin writes a fixed failed audit line (`result=failed`, `reason=exception`, every other field `-`, so `created=-` and no `old=`/`new=`) and then `error|exception` with rc 1, and the server records that line as a failed `registry.write` row. A creating write tries to remove the keys it made, and the value it had written into them, on an exception before its verified write ends (best effort, below); a write onto an existing key that had already landed keeps its value, and so does a write whose exception came after its verified write (while the reply was being built): the row says `failed`, and the key must be read back to know. An agent that dies mid-command writes no row at all; the server's `command.dispatch` row and the stored response keep the attempt attributable. The rollback is BEST EFFORT: a key that holds a value or a subkey when it checks is kept and, on a returning exit, counted in `created=` (`result=failed`), and `created=` can also count a key another party deleted first, which the rollback then cannot delete again. A write that lands between the check and the delete, or over our own same-named value before the rollback deletes it by name, can still be lost, because Windows has no delete-if-empty call. After a double fault (a rollback step that fails or throws) the value and the keys may stay with `created=-` and nothing logged. "Where the data goes" has the procedure for what a failed create can leave.
3. **Behaviour changes from 1.0.** The changes to existing actions are listed in the 2.0.0 changelog entry (`changelog.d/2026-10-22-registry-typed-writes.changed.md`) and in `docs/user-manual/upgrading.md`, which also gives the rollout order (server replicas first) and the minimum agent version for `registry.write` rows (the first release that contains the audit binding of #6294, later than 0.14.1). **Mixed fleets:** an agent still running registry 1.x writes an EMPTY `REG_SZ` over the value for a `data_hex`-only `set_value` (it reads only `name`, `value` and `type`; with `type=REG_DWORD` and `data_hex` only it throws and writes nothing), stores `REG_QWORD`, `REG_MULTI_SZ`, `REG_EXPAND_SZ` and `REG_BINARY` values as `REG_SZ` text, reports `status|ok` for all of those, and follows a write under `HKLM\SYSTEM\CurrentControlSet` that 2.0.0 refuses; nothing on the server gates dispatch on a plugin version (the definitions' `minAgentVersion` is declared and exported, not compared at dispatch), so upgrade the agents before using the new types or `data_hex`, in schedules, workflows, policies and bundles as well as scripts. **Embedded NUL:** a NUL inside a parameter sent through `POST /api/command` reaches the plugin as a C string and cuts the value at the NUL on every agent version (the instruction and MCP routes refuse control bytes), so a key or value name that carries one writes a shorter key or name than the one sent. A reply that is a bare `status|ok` with no leading `audit|` row came from a 1.x agent: read the value back with `get_value`. **An existing server install keeps the 1.0.0 definitions:** bundled definitions are inserted only when absent, so an install that already holds `windows.registry.set_value`, `delete_value` and `delete_key` keeps their 1.0.0 text, enum and parameters (no `data_hex`, a `type` enum of `REG_SZ` and `REG_DWORD` only, `value` required) until they are replaced, and a stored `windows.registry.get_value` keeps its 1.0.0 description (only its text changed in 1.1.0): export, delete and re-import the four definitions, `get_value` included (`docs/user-manual/instructions.md`, "Replacing a stored parameter schema") to get the 1.1.0 text, enum and `data_hex`. Until the fleet is upgraded, scope such a write to upgraded devices (`ostype == "windows" AND tag:<key> == "<value>"`, with a tag that marks the upgraded devices) or switch the action off with the `set_value` kill switch. **2.0.0 asks the key for more access than 1.0.0 did.** `set_value` opens the leaf with `KEY_SET_VALUE` and `KEY_QUERY_VALUE` (the read-back and the link probe need the second), and `KEY_CREATE_SUB_KEY` on each parent it creates under; `delete_value` the same two on the leaf; `delete_key` `DELETE`, `KEY_ENUMERATE_SUB_KEYS` and `KEY_QUERY_VALUE`; the walk adds `KEY_QUERY_VALUE` on every component it passes through. An ACL that grants less answers `access_denied`. **Creating a key now asks for `DELETE` on it**, so that a walk that stops can remove what it made by handle: where an inherited ACL gives the agent identity no `DELETE` on a new key (SYSTEM and Administrators have it on the usual parents) the create answers `access_denied`, and there is deliberately no retry without it. **2.1.0 mixed fleets: a registry 2.0.x agent sent `dry_run=true` DELETES a leaf key.** `do_delete_key` in 2.0.x reads neither `recursive` nor `dry_run`: a `delete_key` with `dry_run=true` on a key with no subkeys deletes it and answers `status|ok` with `dry_run|0` (a key with subkeys is refused `key_has_subkeys`), and `recursive=true` is ignored the same way. `set_user_value`, `delete_user_value` and `apply` answer `error|unknown action` there. Nothing on the server compares a plugin version at dispatch (the definitions' `minAgentVersion` is declared and exported, not compared; the root-cause tracker is #6484), so upgrade the agents to registry 2.1.0 first and scope any preview to a tag that marks devices verified at 2.1.0, in schedules, workflows, policies and bundles as well as scripts. As declared, the `minAgentVersion: 0.15.0` on `delete_key` 1.2.0 and on the three new definitions tells a registry 2.0.x agent from a 2.1.0 one only if registry 2.0.x and 2.1.0 first ship in the same agent release; the 0.15.0 pin on `set_value` (registry 2.0.0) has the same limitation. `delete_key` definition 1.2.0 needs a re-import on an existing server install (bundled definitions are inserted only when absent). A reply whose last count row says `dry_run|0` for a request that asked for `dry_run=true` came from a 2.0.x agent.
4. **`delete_key` without `recursive` removes only a key with no subkeys; the per-user writes and `apply` have limits of their own.** A key with subkeys is refused `key_has_subkeys` and nothing is deleted. The key's own values go with it, and the counts are a point-in-time read of them. A subkey created between the check and the delete cannot be refused as `key_has_subkeys`: `NtDeleteKey` refuses the delete and the action answers a failure token (`access_denied` or `win32:<code>`, not `key_has_subkeys`), with the key still in place and nothing deleted. `recursive=true` has its own bound and its own races ("How it works"): a tree over 10,000 keys and values or 600 levels cannot be deleted in one call (`tree_too_large`); the counts of a dry run are a snapshot and the counts of the real run are what it removed, which can be more; a registry link anywhere in the tree refuses the whole call. **Per-user writes: what the offline arm cannot promise.** The offline mount is serialised process-wide under the offline-hive lock (a long write holds it, and with it every other offline hive reader); the write is bounded by 1 MiB plus one flush. The post-unload probe sees a hive loaded AFTER the write returned; a logon that failed while the hive was mounted leaves no trace, and the probe cannot tell a hive loaded by another actor from a failed one. A flush that fails fails the write although the verified value is in the mounted hive (durability unknown); a creating write's keys are rolled back, an overwrite keeps its value. A mount that is refused or fails to load writes nothing. The privileges are enabled on the process token for the span of the mount (`with_user_hive`). **`apply` limits.** Machine hive only (`HKLM`): a per-user bulk apply is not built. Not transactional, with an undo you read from the reply, not a rollback; the manifest is bounded (one 512 KiB budget; an incomplete one says `undo_complete|0`, in the dry run too). A dry run cannot see the ACL a key that does not exist yet will inherit ("How it works"), so `would_apply` is a prediction for a missing key and a fact for an existing one; the create probe is measured only on Windows (`tests/unit/test_registry_win_internals.cpp`). Keys that differ only in non-ASCII case are not recognised as one key by `dependent_items` or by the per-key handle map, so such a plan opens the key twice (the kernel folds them; the plugin's ASCII-only fold is a strict subset). The value-op items on one key share a handle opened with `KEY_QUERY_VALUE` and `KEY_SET_VALUE`; a key op is always alone on its key. A value named `-`, a name ending in a backslash and any name the row spelling cannot carry are refused ("The exact-name rule"); the default value (empty name) is spelt `-` in a row. A dry run mints `registry.write` rows (`result=success`, `dry_run=1`), and a 256-item plan is up to 256 of the 600 rows an agent may write per minute.
5. **Three read-side gaps are unchanged.** `get_value` is bounded at 1 MiB since 2.0.1. `enumerate_values` writes `value|<name>|<type>` (the leading `value` is a literal tag, not a third column), `get_value`/`enumerate_values` leave `REG_MULTI_SZ`/`REG_LINK` values hex-encoded where `get_user_value` decodes them (changing that changes `get_value`'s output for existing callers), and `PrivilegeScope`'s `AdjustTokenPrivileges` call must keep its `ReturnLength` argument (without it the offline fallback silently never enabled the privileges until #2771: `agents/shared/win_profiles.hpp`, `changelog.d/2771-privilegescope-token-adjust-bug.fixed.md`). The `get_user_value` capture exercised the live-hive path, not the offline mount. `get_value` reads at most 1 MiB (2.0.1), the bound `get_user_value` and the write path already use: a larger value answers `error|value exceeds 1 MiB limit` with rc 1, so a value that any writer of the key made huge is never read whole into the agent's memory (three copies: the bytes, their hex and the sanitised string). Registry 2.0.0 and earlier read the whole value. **Read output is display text.** In every registry-controlled string the read actions render (names, subkey names, decoded string data), `|`, the control characters except TAB, DEL, the C1 controls, U+2028 and U+2029 each become `_` and trailing NULs are dropped, so the exact characters cannot be recovered from a row: `a<U+2028>b`, `a<VT>b` and `a_b` render alike. `get_value` has no exact-bytes mode for a string value (the types it returns as hex are exact); before 2.0.1 an embedded NUL in a name or in `get_value` data cut the row short instead; `get_user_value` reads a string value up to its first NUL. A name that ends in a NUL renders the same as the name without it.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/registry/src/registry_core.hpp` · `agents/plugins/registry/src/registry_parsers.hpp` · `agents/plugins/registry/src/registry_plan.hpp` · `agents/plugins/registry/src/registry_plugin.cpp` · `agents/plugins/registry/src/registry_win.cpp`
- Definitions: `content/definitions/registry.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_a.hpp`
- Tests: `tests/test_registry_definition.py` · `tests/unit/test_registry_core.cpp` · `tests/unit/test_registry_local_dispatcher.cpp` · `tests/unit/test_registry_parsers.cpp` · `tests/unit/test_registry_plan.cpp` · `tests/unit/test_registry_win_internals.cpp` · `tests/unit/test_registry_write_local_dispatcher.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2026-10-22-registry-typed-writes.added.md` · `changelog.d/2026-10-22-registry-typed-writes.changed.md` · `changelog.d/2026-10-26-registry-recursion-user-apply.added.md` · `changelog.d/2026-10-26-registry-recursion-user-apply.changed.md` · `changelog.d/6487-registry-kernel-name-fail-closed.security.md` · `changelog.d/6490-registry-get-value-bound.changed.md` · `changelog.d/6491-registry-output-line-breaks.fixed.md`
<!-- END GENERATED -->
