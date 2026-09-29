# content_dist

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Content staging — download, verify, execute, and manage staged files (no shell-out) |
| **Version** | 1.1.0 |
| **Kind** | Action · mutating · gathered (agent.content_dist.upload_file) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `cleanup` (definition `agent.content_dist.cleanup`) · `execute_staged` (definition `agent.content_dist.execute_staged`) · `list_staged` (definition `agent.content_dist.list_staged`) · `stage` (definition `agent.content_dist.stage`) · `upload_file` (definition `agent.content_dist.upload_file`) |
| **Security** | `stage`: securable `SoftwareDeployment` · operation Write · risk High · dispatch Destructive · approval gate AdminOrApproval; `execute_staged`: securable `Execution` · operation Execute · risk High · dispatch Destructive · approval gate AdminOrApproval; `list_staged`: securable `SoftwareDeployment` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `cleanup`: securable `SoftwareDeployment` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval; `upload_file`: securable `FileRetrieval` · operation Write · risk High · dispatch Destructive · approval gate AdminOrApproval |
| **Roles** | execute: `stage`: endpoint-admin; `execute_staged`: endpoint-admin; `list_staged`: endpoint-admin, endpoint-operator; `cleanup`: endpoint-admin; `upload_file`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`stage` downloads over a raw httplib socket it opens itself (no shell), verifies the SHA-256 against the caller-supplied `sha256`, and — only once verified — persists that hash into agent KV under `staged_hash:<filename>` so a later `execute_staged` has a source of truth the staging-dir attacker can't also rewrite (`content_dist_plugin.cpp:529-540`, #808). `execute_staged` re-verifies the hash from KV (never trusts a caller-supplied hash), rejects a shebang-interpreted script on Linux before it ever reaches the runner (B6 fd-exec has no resolvable path for `binfmt_script`), chmods the file `0700` on POSIX, then execs it directly — no shell — via `yuzu::agent::run_bounded_subprocess` with a fixed 30-minute deadline. `list_staged` and `cleanup` are plain `std::filesystem` walks of the same staging directory; `cleanup` removes files older than an age cutoff and evicts their KV hash entry alongside them. `upload_file` is an unrelated protocol: it drives a session-open/chunk/commit/cancel exchange against the agent's own configured server URL (never an operator-supplied one) using a one-time `grant_id`/`grant_secret`, hashing the exact bytes each chunk transmitted as it is acknowledged.

Deliberately not: a shell. No action here ever invokes `/bin/sh`, `cmd.exe`, or any interpreter — downloads and uploads are direct socket clients, execution is a direct argv exec. Deliberately not: a general file manager — every filesystem action is scoped to the plugin's own `staging_dir()`.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>or the /auto Deploy engine] --> SRV[Server<br/>authz: SoftwareDeployment/Execution/FileRetrieval per action]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[content_dist.execute]
  EX --> WIN[Windows leg<br/>httplib_tls · subprocess_runner:staged_payload · std_filesystem]
  EX --> MAC[macOS leg<br/>httplib_tls · subprocess_runner:staged_payload · std_filesystem]
  EX --> LIN[Linux leg<br/>httplib_tls · subprocess_runner:staged_payload (native only) · std_filesystem]
  WIN & MAC & LIN --> ROWS[pipe rows +<br/>typed result status on execute_staged only]
  ROWS -- CommandResponse --> RS[(ResponseStore)]
  RS --> API[REST /api/responses · /auto Deploy engine]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `cleanup` | ✅ supported · rung 1 · std_filesystem | ✅ supported · rung 1 · std_filesystem | ✅ supported · rung 1 · std_filesystem |
| `execute_staged` | ✅ supported · rung 2 · subprocess_runner:staged_payload | ✅ supported · rung 2 · subprocess_runner:staged_payload | 🟡 constrained · rung 2 · subprocess_runner:staged_payload |
| `list_staged` | ✅ supported · rung 1 · std_filesystem | ✅ supported · rung 1 · std_filesystem | ✅ supported · rung 1 · std_filesystem |
| `stage` | 🟡 constrained · rung 1 · httplib_tls | ✅ supported · rung 1 · httplib_tls | ✅ supported · rung 1 · httplib_tls |
| `upload_file` | 🟡 constrained · rung 1 · httplib_tls | ✅ supported · rung 1 · httplib_tls | ✅ supported · rung 1 · httplib_tls |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`execute_staged` / Linux** — shebang-interpreted (#!) staged payloads are rejected -- B6 fd-exec (execveat O_CLOEXEC) is incompatible with the kernel's binfmt_script re-open; native executables only
- **`stage` / Windows** — requires OpenSSL to be found at build time; HTTPS unavailable if absent
- **`upload_file` / Windows** — requires OpenSSL to be found at build time; HTTPS unavailable if absent
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442); `execute_staged` runs as `YuzuAgent` (`docs/agent-privilege-model.md:121`) | **None.** Every action stays inside the agent-owned staging directory or a socket the agent opens itself. | 2026-09-07, bare-metal, as `SYSTEM` (`windows.txt`) | no typed status — a filesystem/network failure surfaces as an `error\|<message>` line, not a `PERMISSION_DENIED` result status |
| macOS | agent daemon, unprivileged (`_yuzu`) | **None.** `staging_dir()` creates the directory owner-only (`fs::perms::owner_all`, `content_dist_plugin.cpp:72-75`). | 2026-09-07, bare-metal, euid 501 (`macos.txt`) | same — an `error\|` line, no typed status |
| Linux | agent daemon, unprivileged (`yuzu`) | **None.** Same owner-only staging directory. | 2026-09-06, container, euid 0 (`linux.txt`) — captured as root, not the unprivileged `yuzu` identity `execute_staged` actually runs as in production | same — an `error\|` line, no typed status |

Binaries/subprocesses/network: `stage`/`upload_file` open raw TCP/TLS sockets via cpp-httplib (no subprocess). `execute_staged` spawns exactly one process — the staged file itself — via `yuzu::agent::run_bounded_subprocess` (no shell, no other binary). `list_staged`/`cleanup` touch no network and spawn nothing.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `agent.content_dist.cleanup` | `filename` | string | no | - | - | Declared but NOT read by the current implementation (content_dist_plugin.cpp's do_cleanup only reads "hours") — setting this parameter has no effect on which files are removed. Left in place for API compatibility; see the plugin README's Caveats section. |
| `agent.content_dist.execute_staged` | `filename` | string | yes | - | - | Name of a previously staged file, e.g. pkg-1.2.3.msi. Must already have a verified hash on record from a prior stage action (agent KV key staged_hash:<filename>) — the hash is re-verified against that record, not against this parameter, before anything runs. |
| `agent.content_dist.execute_staged` | `args` | string | no | - | - | Optional whitespace-separated argv tail, e.g. "/quiet /norestart". Never shell-parsed (no quoting/escaping); rejected outright if it contains a shell metacharacter such as ; \| & ` $ ( ) { } < >. |
| `agent.content_dist.stage` | `url` | string | yes | - | - | Source URL, e.g. https://cdn.example.com/pkg-1.2.3.msi. Must start with http:// or https://; downloaded directly over a socket the agent opens itself, never via a shell command. |
| `agent.content_dist.stage` | `filename` | string | yes | - | - | Destination filename inside the agent's staging directory, e.g. pkg-1.2.3.msi. Alphanumeric, dots, hyphens, and underscores only (no path separators or ".."); any other character is refused. |
| `agent.content_dist.stage` | `sha256` | string | yes | - | - | Lowercase hex SHA-256 the downloaded file must hash to, e.g. "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3...". A mismatch deletes the downloaded file and fails the action; the verified hash is what execute_staged later re-checks from agent KV, not this parameter. |
| `agent.content_dist.upload_file` | `path` | string | yes | - | maxLength 4096 | The local file path on the endpoint to upload. |
| `agent.content_dist.upload_file` | `grant_id` | string | yes | - | maxLength 64 | The one-time upload grant's id, minted operator-side via POST /api/v1/upload-grants. Paired with grant_secret to authenticate the session; both are revealed by the mint response exactly once. |
| `agent.content_dist.upload_file` | `grant_secret` | string | yes | - | maxLength 128 | The one-time upload grant's secret, minted alongside grant_id. Never logged or echoed back by the server after the mint response. |
| `agent.content_dist.upload_file` | `base_dir` | string | no | - | maxLength 4096 | If set, path must resolve (after symlink canonicalisation) inside this directory, or the upload is refused before anything is read. |
| `agent.content_dist.upload_file` | `max_size_mb` | int32 | no | 100 | minimum 1 · maximum 1000 | Maximum allowed file size in megabytes, checked locally before the session opens. Default: 100. |
<!-- END GENERATED -->

### Outputs

Every action writes independent `key|value` lines via `ctx.write_output` — not a fixed-width pipe row like a collector's table. A validation or transport failure typically replaces the whole declared line set with a single unstructured `error|<message>` line rather than filling the declared columns with a placeholder value; there is no `-`-for-unknown convention in this plugin.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`agent.content_dist.cleanup` — `status|files_removed`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | all | `-` | Declared but never emitted — do_cleanup writes only a "removed\|<n>" line, no "status\|" line at all, on every run (including a hours-parse failure, which is silently ignored rather than reported). |
| `files_removed` | int32 | - | Windows, Linux, macOS | `-` | Declared column name does not match the wire field: the actual emitted line is "removed\|<n>", not "files_removed\|<n>" — the count of files whose last-write time was older than the cutoff. Values: non-negative integer. |

**`agent.content_dist.execute_staged` — `status|exit_code|output`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | `ok` `error` | Windows, Linux, macOS | `ok` | "ok" when the staged file exited 0, "error" for any nonzero exit, spawn failure, or a deadline/cancel kill. On an early rejection (not staged, no trusted hash, hash mismatch, unsafe args) this column is never emitted at all — only an "error\|<message>" line is. |
| `exit_code` | int32 | - | Windows, Linux, macOS | `-` | The staged process's exit code, or -1 for a spawn failure or a deadline/cancel kill (subprocess_runner's sentinel, never a real process exit status in that case). Values: process exit code, or -1. |
| `output` | string | - | Windows, Linux, macOS | `-` | Combined stdout+stderr, capped at 16 MiB, with a "[output truncated at 16 MiB]" and/or "[terminated: deadline exceeded]"/"[terminated: cancelled]" annotation appended when applicable. Omitted entirely (no output\| line at all) when the captured text is empty. Values: free text, truncated/terminated annotations, or omitted. |

**`agent.content_dist.list_staged` — `file|size|sha256`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `file` | string | - | Windows, Linux, macOS | `-` | Filename of one staged file (relative, no path). One row per file in the staging directory; a "count\|<n>" summary line follows the last row and is not itself a declared column. An empty directory emits zero rows and count\|0, never an error. Values: free text. |
| `size` | int64 | - | Windows, Linux, macOS | `-` | File size in bytes, from std::filesystem::file_size. Values: non-negative integer. |
| `sha256` | string | - | Windows, Linux, macOS | `-` | Lowercase hex SHA-256 of the file's current on-disk contents, recomputed on every list_staged call (not cached from stage time). Values: 64 lowercase hex characters. |

**`agent.content_dist.stage` — `status|staged_path`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | `ok` | Windows, Linux, macOS | `ok` | Literal "ok" on a verified download. content_dist never writes "status\|error" — a failure instead replaces this whole line with a single unstructured "error\|<message>" line, so a failed stage never populates this column at all. |
| `staged_path` | string | - | Windows, Linux, macOS | `-` | Absolute filesystem path of the downloaded, hash-verified file under the agent's staging directory (content_dist_plugin.cpp's staging_dir(): <agent.data_dir>/staged, or a temp-dir fallback). Only present on success — no captured sample shows a populated value. Values: absolute path. |

**`agent.content_dist.upload_file` — `status|sha256|size|upload_id`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | `ok` | Windows, Linux, macOS | `not observed in any capture (every capture failed at parameter validation, before this line could be reached)` | Outcome of the upload; the only value the plugin emits on success (content_dist_plugin.cpp:1171). |
| `sha256` | string | - | Windows, Linux, macOS | `not observed in any capture (every capture failed at parameter validation, before this line could be reached)` | Server-confirmed SHA-256 digest of the committed upload, computed from the exact bytes the server acknowledged. Values: hex digest. |
| `size` | int64 | - | Windows, Linux, macOS | `not observed in any capture (every capture failed at parameter validation, before this line could be reached)` | Server-reported size in bytes of the committed upload (commit_result.actual_size), which must match the local file size. Values: integer (bytes). |
| `upload_id` | string | - | Windows, Linux, macOS | `not observed in any capture (every capture failed at parameter validation, before this line could be reached)` | Server-assigned session id from the upload grant, used to address the /api/v1/uploads/{id}/... endpoints. Values: free text (opaque session id). |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNAVAILABLE` | PARTIAL | `subprocess_runner:spawn_error` | `execute_staged` only: the runner never confirmed exec (missing/non-executable staged file, or a Linux B6 exec_verify rejection) |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:deadline` | `execute_staged` only: the fixed 30-minute deadline fired and the process was killed |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:cancelled` | `execute_staged` only: a cancellation reached the runner mid-run |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:signaled` | `execute_staged` only: the staged process died of a signal it received itself |
| `OK` | PARTIAL | `subprocess_runner:line_limit` | never reached for this plugin — `content_dist` never sets `max_lines`/`stop_after_max_lines` (`content_dist_exec_parsers.hpp:288-291`) |

`execute_staged`'s ordinary exit (rc 0 or nonzero) sets no typed status at all — `classify_runner_failure` returns `nullopt` for `exited` by design, leaving the `status`/`exit_code` lines to carry the outcome (`runner_status.hpp`). `stage`, `list_staged`, `cleanup`, and `upload_file` never call `set_result_status` anywhere in `content_dist_plugin.cpp`; every sample capture for all five actions shows `UNDECLARED / UNKNOWN /` because each capture failed at parameter validation, before any runner call could occur.

### Where the data goes

- **Instruction result, and the `/auto` Deploy engine.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore. `content_dist.stage`/`execute_staged` are additionally dispatched by the `/auto` Deploy engine (`server/core/src/deployment_engine.cpp:306,331`), which parses this exact wire contract via `server/core/src/deployment_parse.hpp:17-25` to drive its own per-device state machine — `content_dist` needed no new agent code for that surface.
- **`upload_file`'s `grant_id`/`grant_secret` are redacted before any persisted audit/history copy** (`server/core/src/sensitive_instruction_params.hpp:6`) — never logged or stored beyond the upload store's own hashed record.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics.
- **Sensitivity.** `execute_staged`'s `output` line is the combined stdout+stderr of whatever binary the caller staged and ran — it can carry anything that process prints, including usernames, hostnames, or credentials — but the plugin's own declared columns (`staged_path`, `file`, `sha256`, `upload_id`) carry only caller-chosen filenames and content hashes, nothing that independently identifies a device, a person, or installed software.
- **Siblings:** none in this catalogue — `execute_staged` is the only "run an arbitrary binary" action here; compare `script_exec.exec` for ad hoc admin commands/scripts.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("agent.content_dist.execute_staged")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; `content_dist.stage`/`execute_staged` results are also polled by the `/auto` Deploy engine's `deployment_run_store`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 590399d7174c

```
== action=stage
error|missing required parameters: url, filename, sha256
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=execute_staged
error|missing required parameter: filename
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=list_staged
count|0
[result_status] UNDECLARED / UNKNOWN

== action=cleanup
[not captured] Destructive/Irreversible: not executed on a live host

== action=upload_file
error|missing required parameters: path, grant_id, grant_secret
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 590399d7174c

```
== action=stage
error|missing required parameters: url, filename, sha256
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=execute_staged
error|missing required parameter: filename
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=list_staged
count|0
[result_status] UNDECLARED / UNKNOWN

== action=cleanup
[not captured] Destructive/Irreversible: not executed on a live host

== action=upload_file
error|missing required parameters: path, grant_id, grant_secret
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 590399d7174c

```
== action=stage
error|missing required parameters: url, filename, sha256
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=execute_staged
error|missing required parameter: filename
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=list_staged
count|0
[result_status] UNDECLARED / UNKNOWN

== action=cleanup
[not captured] Destructive/Irreversible: not executed on a live host

== action=upload_file
error|missing required parameters: path, grant_id, grant_secret
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`cleanup`'s `filename` parameter is dead code.** The definition declares `filename` for targeted removal, but `do_cleanup` (`content_dist_plugin.cpp:1179-1209`) only ever reads an undeclared `hours` parameter and sweeps the whole staging directory by age (default 24h) — a single-file removal is not implemented today. The definition's description and the `filename` parameter now disclose this.
2. **`cleanup`'s declared result columns don't match its wire output.** `status` is never emitted — there is no `status|` line anywhere in `do_cleanup`, including on an hours-parse failure (silently ignored, not reported) — and the declared `files_removed` column is actually wired as `removed|<n>`.
3. **`execute_staged` rejects Linux shebang scripts by design — do not "fix" this.** B6 fd-exec (`execveat` with `AT_EMPTY_PATH`) gives the kernel no resolvable path for `binfmt_script` to build the interpreter's argv from; a `#!`-interpreted staged file is refused up front (`content_dist_exec_seam.hpp:81-105`) rather than spawn-failing opaquely. Stage a native executable instead.
4. **A residual hash-time-to-exec-time swap window is accepted, not closed (CDX-001).** The #808 KV hash re-verification and the seam's independent B6 open both target the same path but not the same fd; full closure needs the runner itself to accept a caller-supplied digest, deferred to a follow-up runner package (`content_dist_plugin.cpp:628-652`).
5. **Windows soft-terminate grace is configured but undeliverable.** `no_window=true` (restoring the deleted launcher's `CREATE_NO_WINDOW`) means a console-less child can never receive `GenerateConsoleCtrlEvent`/`CTRL_BREAK`, so the 30s grace is zeroed on the Windows path rather than claiming a grace the platform cannot deliver (`content_dist_exec_parsers.hpp:242-268`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/content_dist/src/content_dist_exec_parsers.hpp` · `agents/plugins/content_dist/src/content_dist_exec_seam.hpp` · `agents/plugins/content_dist/src/content_dist_plugin.cpp` · `agents/plugins/content_dist/src/content_dist_upload_parsers.hpp`
- Definitions: `content/definitions/content_dist.yaml` · `content/definitions/t2_capabilities.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_content_dist.hpp`
- Tests: `tests/unit/test_content_dist_actions.cpp` · `tests/unit/test_content_dist_exec_parsers.cpp` · `tests/unit/test_content_dist_exec_seam.cpp` · `tests/unit/test_content_dist_exec_seam_win.cpp` · `tests/unit/test_content_dist_upload_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
