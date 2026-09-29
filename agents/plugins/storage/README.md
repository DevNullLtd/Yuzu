# storage

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Persistent key-value storage — set, get, delete, list, clear |
| **Version** | 1.0.0 |
| **Kind** | Action · mutating · gathered (agent.storage.set, agent.storage.get, agent.storage.delete, agent.storage.list, agent.storage.clear) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `clear` (definition `agent.storage.clear`) · `delete` (definition `agent.storage.delete`) · `get` (definition `agent.storage.get`) · `list` (definition `agent.storage.list`) · `set` (definition `agent.storage.set`) |
| **Security** | `set`: securable `Infrastructure` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval; `get`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `delete`: securable `Infrastructure` · operation Delete · risk High · dispatch Mutating · approval gate AdminOrApproval; `list`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `clear`: securable `Infrastructure` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval |
| **Roles** | execute: `set`: endpoint-admin; `get`: endpoint-admin, endpoint-operator; `delete`: endpoint-admin; `list`: endpoint-admin, endpoint-operator; `clear`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

All five actions are thin wrappers over the agent's own in-process KV store (`agents/core/src/agent.cpp:577-627`), reached through the C ABI functions `yuzu_ctx_storage_{set,get,delete,list}` — no OS-specific code and no subprocess anywhere in the plugin (`agents/plugins/storage/src/storage_plugin.cpp:27-29`). `set`/`get`/`delete` operate on a single key; `list` enumerates keys under an optional prefix; `clear` is built from `list` + `delete` — it reads every key in the plugin's namespace, deletes each one in a loop, and reports the size of that initial list as `cleared`, not a per-key confirmed-delete count (`storage_plugin.cpp:189-198`). The store is namespaced by the calling plugin's own declared name (`impl->plugin_name`, `agent.cpp:246,970`), so one plugin cannot read another's keys; there is no TTL, versioning, or value type-checking — every value is opaque text.

**Root cause worth stating plainly:** the C ABI depends on `StoragePlugin::init()` having already run and cached the host's `YuzuPluginContext*` into the static `g_ctx` (`storage_plugin.cpp:25,108`). A harness that loads the plugin and calls `execute()` without first calling `init()` — which is exactly how the docs capture driver and the `PluginHandle::load` + `LocalDispatcher::run` pattern work — leaves `g_ctx` null, so every `yuzu_ctx_storage_*` call takes its `!ctx` early-return path (`agent.cpp:578,587,604,613,622`). `set` surfaces this loudly as `error|storage write failed` (`storage_plugin.cpp:145`). `get`, `delete`, and `list` mask it instead: their SDK wrappers treat a null/negative ABI return as an empty result rather than an error (`sdk/include/yuzu/plugin.hpp:122-129,132-134,142-145`), and `do_delete` never inspects the bool `storage_delete()` returns (`storage_plugin.cpp:172-174`) — so a run through this path reads as "no such key" or "cleared 0 keys" when the real cause is that storage was never wired up at all. In the real agent boot path, `init()` is called with a correctly-wired context before any dispatch (`agent.cpp:966-983`), so this only bites harnesses that skip it — which is exactly what produced the `[rc] 1` on every OS's `set` sample below.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Read/Write/Delete<br/>concurrency: per-device]
  SRV -- gRPC mTLS --> HOST[Agent plugin host<br/>calls StoragePlugin::init() first]
  HOST --> EX[storage.execute]
  EX --> WIN[Windows leg<br/>in-process agent KV store]
  EX --> MAC[macOS leg<br/>in-process agent KV store]
  EX --> LIN[Linux leg<br/>in-process agent KV store]
  WIN & MAC & LIN --> ROWS[rows + UNDECLARED status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `clear` | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) |
| `delete` | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_delete) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_delete) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_delete) |
| `get` | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_get) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_get) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_get) |
| `list` | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_list) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_list) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_list) |
| `set` | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_set) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_set) | ✅ supported · rung 1 · in-process agent KV store (yuzu_ctx_storage_set) |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — pure in-process SQLite KV read/write inside the agent's own data directory; no privileged API is touched | 2026-09-07, bare-metal, `SYSTEM` | No permission gate exists in this plugin. A missing/uninitialized store takes the ABI's `!ctx` early-return path (`agent.cpp:577-627`), not a typed permission error |
| macOS | agent daemon; ships root today per `docs/agent-privilege-model.md` (narrowing tracked in #1455) | None | 2026-09-07, bare-metal, euid 501 (jsmith) — **unprivileged**, i.e. this capture was taken at a weaker identity than the shipped root daemon | same as above |
| Linux | agent service account `yuzu`, unprivileged, per `docs/agent-privilege-model.md` | None | 2026-09-06, container, euid 0 — this capture was taken as root, not the production `yuzu` identity | same as above |

No external binaries, no subprocesses, no network access — every action stays in-process against the agent's own `kv_store.db` (`storage_plugin.cpp:27-29`; `agent.cpp:799-803`).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `agent.storage.delete` | `key` | string | yes | - | - | Storage key to delete, e.g. "yuzu_capture_tmp". |
| `agent.storage.get` | `key` | string | yes | - | - | Storage key to retrieve, e.g. "yuzu_capture_tmp". |
| `agent.storage.list` | `prefix` | string | no | - | - | Only return keys starting with this prefix, e.g. "yuzu_". Default is all keys. |
| `agent.storage.set` | `key` | string | yes | - | - | Storage key name, arbitrary text, e.g. "yuzu_capture_tmp". |
| `agent.storage.set` | `value` | string | yes | - | - | Value to store, arbitrary text, stored and returned byte-for-byte. |
<!-- END GENERATED -->

### Outputs

Each action writes one or more independently-shaped, pipe-delimited lines via `write_output()` (`storage_plugin.cpp:132-198`) rather than a uniform repeating row. `set`, `delete`, and `clear` announce success as a literal `status|ok` line — or, on failure, no `status` line at all and instead a separate `error|<message>` line (not represented in the YAML columns below, since it only appears when the row-producing path is never reached). `get` always writes exactly one `key|<key>|<value-or-not_found>` line, where the sentinel `not_found` means both "no such key" and — per the root-cause note above — "storage was never wired up." `list` writes one `count|<n>` line followed by `n` `key|<k>` lines, with zero `key` rows when `n` is 0.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`agent.storage.clear` — `status|cleared`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `ok` | Write outcome. Always the literal "ok", written after the clear loop completes. |
| `cleared` | int32 | - | Windows, Linux, macOS | `-` | Count of keys deleted in this run — the size of the key list read at the start of the pass, not a per-key confirmed-delete count. Values: integer >= 0. |

**`agent.storage.delete` — `status|key`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `ok` | Write outcome. Always the literal "ok" when present — written unconditionally once the delete call returns, without checking whether the delete actually succeeded. |
| `key` | string | - | Windows, Linux, macOS | `yuzu_capture_tmp` | The key name that was targeted for deletion, echoed back unchanged. Values: free text. |

**`agent.storage.get` — `key|value`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `key` | string | - | Windows, Linux, macOS | `yuzu_capture_tmp` | The requested key name, echoed back unchanged. (The literal "key" row-discriminator emitted before this field is not itself a separate column.). Values: free text. |
| `value` | string | - | Windows, Linux, macOS | `not_found` | The stored value, or the literal sentinel "not_found" when the key has no stored value. Values: free text, or the sentinel not_found. |

**`agent.storage.list` — `count|key`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `count` | int32 | - | Windows, Linux, macOS | `0` | Number of keys returned, written once as the first row of every response. Values: integer >= 0. |
| `key` | string | - | Windows, Linux, macOS | `-` | One row per matching key name; no key rows at all when count is 0. Values: free text. |

**`agent.storage.set` — `status|key`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `ok` | Write outcome. Present and equal to "ok" only when the write succeeded; on failure this row is absent and an "error\|<message>" line is written instead (not represented as a column). |
| `key` | string | - | Windows, Linux, macOS | `yuzu_capture_tmp` | The key name that was stored, echoed back unchanged. Values: free text. |
<!-- END GENERATED -->

### Result status

`storage_plugin.cpp` never calls `set_result_status`/`yuzu_ctx_set_result_status` — grep of the file finds no call site. This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample line below reads `UNDECLARED / UNKNOWN /`, regardless of whether the action actually succeeded — including the `set` calls that returned `[rc] 1`.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — a grep of `server/core/src` for `"storage"` and for the five `agent.storage.*` ids finds no server-side consumer beyond the generic dispatch/response path.
- **Sensitivity.** The plugin never interprets its `key`/`value` content — every row is opaque caller-supplied text, so whether a given row identifies a device, a person, or installed software depends entirely on what the calling plugin chose to store there, not on anything this plugin's own columns declare. The `status`/`count`/`cleared` fields carry nothing beyond the device id.
- **Siblings:** none. `content/definitions/storage.yaml` is the only definitions file with `execution.plugin: storage`; the plugin's five actions are the only definitions that execute against it.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("agent.storage.get")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash cc5994a9097a

```
== action=set key=yuzu_capture_tmp value=1
error|storage write failed
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=get key=yuzu_capture_tmp
key|yuzu_capture_tmp|not_found
[result_status] UNDECLARED / UNKNOWN

== action=delete key=yuzu_capture_tmp
status|ok
key|yuzu_capture_tmp
[result_status] UNDECLARED / UNKNOWN

== action=list
count|0
[result_status] UNDECLARED / UNKNOWN

== action=clear
[not captured] Destructive/Irreversible: not executed on a live host
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash cc5994a9097a

```
== action=set key=yuzu_capture_tmp value=1
error|storage write failed
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=get key=yuzu_capture_tmp
key|yuzu_capture_tmp|not_found
[result_status] UNDECLARED / UNKNOWN

== action=delete key=yuzu_capture_tmp
status|ok
key|yuzu_capture_tmp
[result_status] UNDECLARED / UNKNOWN

== action=list
count|0
[result_status] UNDECLARED / UNKNOWN

== action=clear
[not captured] Destructive/Irreversible: not executed on a live host
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash cc5994a9097a

```
== action=set key=yuzu_capture_tmp value=1
error|storage write failed
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=get key=yuzu_capture_tmp
key|yuzu_capture_tmp|not_found
[result_status] UNDECLARED / UNKNOWN

== action=delete key=yuzu_capture_tmp
status|ok
key|yuzu_capture_tmp
[result_status] UNDECLARED / UNKNOWN

== action=list
count|0
[result_status] UNDECLARED / UNKNOWN

== action=clear
[not captured] Destructive/Irreversible: not executed on a live host
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The docs capture bypasses `init()`, and `set` is the only action that shows it.** The capture driver loads the plugin and dispatches through `LocalDispatcher` without calling `StoragePlugin::init()`, leaving the static `g_ctx` null (`storage_plugin.cpp:25,108`) and every `yuzu_ctx_storage_*` call on its `!ctx` early-return path (`agent.cpp:578,587,604,613,622`). Only `set` reports this as a visible failure; `get`/`delete`/`list` mask it as an empty result (see *How it works*).
2. **`delete` reports success unconditionally.** `do_delete` never inspects the bool `storage_delete()` returns (`storage_plugin.cpp:172-174`), so a failed delete — including the null-context case above — still emits `status|ok`.
3. **No typed result status.** Grep of `storage_plugin.cpp` finds no `set_result_status`/`yuzu_ctx_set_result_status` call; every response reads `UNDECLARED / UNKNOWN`, so a caller cannot distinguish "wrote fine" from "silently no-opped" without also checking the command's `rc`.
4. **`clear` is Destructive and was never captured live.** Per `plugin_action_catalogue_b.hpp:440-449`, `clear` is `DispatchClass::Destructive`/`Irreversible`; `changelog.d/3885-dashboard-destructive-targeting.security.md` names `storage.clear` explicitly as one of the actions a prior dashboard gap let fan across the whole fleet by omitting a target (now closed). The capture driver correspondingly never executes it against a live host — all three sample files show `[not captured]`.
5. **The YAML under-declares `get`'s row shape.** `get` writes a 3-field row, `key|<key>|<value-or-not_found>` (`storage_plugin.cpp:158-160`), but `content/definitions/storage.yaml`'s `agent.storage.get` declares only two `result.columns` (`key`, `value`) — the literal row-discriminator field has no column of its own. Left as-is rather than restructured, since this enrichment pass adds metadata to existing columns without renaming or reordering them.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/storage/src/storage_plugin.cpp`
- Definitions: `content/definitions/storage.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: none found by name
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
