# interaction

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Desktop user interaction — notifications, message boxes, input dialogs, surveys, DND |
| **Version** | 0.3.0 |
| **Kind** | Action · mutating · gathered (device.interaction.notify, device.interaction.message_box, device.interaction.input, device.interaction.survey, device.interaction.set_dnd) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `input` (definition `device.interaction.input`) · `message_box` (definition `device.interaction.message_box`) · `notify` (definition `device.interaction.notify`) · `set_dnd` (definition `device.interaction.set_dnd`) · `survey` (definition `device.interaction.survey`) |
| **Security** | securable `Infrastructure` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval |
| **Roles** | execute: `notify`: endpoint-admin, endpoint-operator; `message_box`: endpoint-admin; `input`: endpoint-admin; `survey`: endpoint-admin; `set_dnd`: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

Four of the five actions dispatch a platform-native dialog or notification mechanism and report what happened; the fifth, `set_dnd`, is a pure local KV-store flag with no OS call. `notify` and `survey` first check whether Do Not Disturb is active and, if so, short-circuit to `status|suppressed` without ever spawning anything. Every dialog action validates its required parameters in the OS-agnostic dispatch layer before reaching a platform leg — a missing `title` never spawns a subprocess, on any OS. Text fields are then sanitized (metacharacters and quotes stripped) before being interpolated into an osascript/PowerShell script fragment; every spawn itself goes through the bounded argv runner with no shell involved end to end. The plugin never fabricates a dialog outcome: a non-zero exit, a runner-level failure, or an unreachable GUI session is always reported as an honest `status|unavailable`/`status|not_reachable`/`status|error` line rather than a guessed button or cancellation. It is deliberately not a general scripting surface — the only mechanisms it invokes are ShellNotifyIcon/MessageBoxW/PowerShell (Windows), notify-send/zenity (Linux), and osascript (macOS).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Write]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[interaction.execute]
  EX --> DND{DND active?<br/>notify/survey only}
  DND -- yes --> SUP[status suppressed]
  DND -- no / n-a --> VAL{required params present?}
  VAL -- no --> ERR[status error]
  VAL -- yes --> WIN[Windows leg<br/>Shell_NotifyIconW / MessageBoxW /<br/>PowerShell InputBox / WinForms]
  VAL -- yes --> MAC[macOS leg<br/>osascript display notification / dialog]
  VAL -- yes --> LIN[Linux leg<br/>notify-send / zenity]
  SUP & ERR & WIN & MAC & LIN --> ROWS[key|value rows] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `input` | ✅ supported · rung 3 · powershell_inputbox | 🟡 constrained · rung 3 · osascript | ✅ supported · rung 2 · zenity |
| `message_box` | ✅ supported · rung 1 · messageboxw | 🟡 constrained · rung 3 · osascript | ✅ supported · rung 2 · zenity |
| `notify` | ✅ supported · rung 1 · shell_notifyicon | 🟡 constrained · rung 3 · osascript | ✅ supported · rung 2 · notify_send |
| `set_dnd` | ✅ supported · rung 1 · local_kv_store | ✅ supported · rung 1 · local_kv_store | ✅ supported · rung 1 · local_kv_store |
| `survey` | ✅ supported · rung 3 · powershell_winforms | 🟡 constrained · rung 3 · osascript | ✅ supported · rung 2 · zenity |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`input` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
- **`message_box` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
- **`notify` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
- **`survey` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account; registers and runs as LocalSystem today (#1442, not yet the intended virtual service account) | None — `Shell_NotifyIconW`/`MessageBoxW` are unprivileged, and PowerShell needs no elevation to run `InputBox`/`WinForms` | 2026-09-07, bare-metal, as `SYSTEM` | PowerShell dialogs (`input`/`survey`) report `status\|unavailable\|PowerShell dialog exited with an error` or `...timed out`; native `notify`/`message_box` have no refusal path — `MessageBoxW` always returns a button |
| macOS | root (shipped LaunchDaemon has no `UserName` key) | None — but no LaunchDaemon has a reachable Aqua/GUI session by design | 2026-09-07, bare-metal, as euid 501 (jsmith) — an interactive logged-in user, **not** the production root-daemon posture | `status\|unavailable\|no reachable GUI session` (`notify`) or `status\|not_reachable` (`message_box`/`input`/`survey`) |
| Linux | agent unprivileged account (`yuzu`) | None — the plugin checks `DISPLAY`/`WAYLAND_DISPLAY` before ever spawning | 2026-09-06, container, as euid 0 | `status\|unavailable\|no reachable GUI session`, checked upfront before spawning zenity/notify-send |

Binaries/subprocesses: PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Windows `input`/`survey`) · osascript (`/usr/bin/osascript`, macOS all four dialog actions) · zenity and notify-send (`/usr/bin/zenity`, `/usr/local/bin/zenity`, `/usr/bin/notify-send`, `/usr/local/bin/notify-send`, Linux). No network access. `set_dnd` and Windows `notify`/`message_box` spawn nothing.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `device.interaction.input` | `title` | string | yes | - | - | Dialog title text |
| `device.interaction.input` | `prompt` | string | yes | - | - | Prompt text shown above the input field |
| `device.interaction.input` | `default_value` | string | no |  | - | Pre-filled default text in the input field |
| `device.interaction.message_box` | `title` | string | yes | - | - | Dialog title text |
| `device.interaction.message_box` | `message` | string | yes | - | - | Dialog body text |
| `device.interaction.message_box` | `buttons` | string | no | ok | - | Button configuration: ok, okcancel, or yesno |
| `device.interaction.notify` | `title` | string | yes | - | - | Notification title text |
| `device.interaction.notify` | `message` | string | yes | - | - | Notification body text |
| `device.interaction.notify` | `type` | string | no | info | - | Notification severity: info, warning, or error |
| `device.interaction.set_dnd` | `enabled` | string | yes | - | - | Set to 'true' to enable DND, 'false' to disable |
| `device.interaction.set_dnd` | `duration_minutes` | int32 | no | 0 | - | Optional duration in minutes. If set and enabled=true, DND will automatically expire after this many minutes. If 0 or omitted, DND remains active indefinitely until explicitly disabled. |
| `device.interaction.survey` | `title` | string | yes | - | - | Survey window title |
| `device.interaction.survey` | `questions` | string | yes | - | - | JSON array of question objects. Each object has: prompt (string), type (text\|yesno\|choice), and choices (array of strings, required when type=choice). Example: [{"prompt":"Your name?","type":"text"}, {"prompt":"Agree?","type":"yesno"}, {"prompt":"Department","type":"choice","choices":["IT","HR","Eng"]}] |
<!-- END GENERATED -->

### Outputs

Each action writes one or more `key|value` lines via `write_output()`. The dashboard/REST layer treats `interaction` as a key/value plugin and splits each line into exactly a key and the remainder of the line as its value — so a value can itself contain literal `|` characters, e.g. `status|error|missing required parameter: title` has key `status` and value `error|missing required parameter: title`. Not every declared column is written on every invocation: `response`/`cancelled` are mutually exclusive per action, and `status` appears only on a validation failure, a suppressed DND, or an undeliverable/failed dialog — a clean button press or clean survey completion never emits a `status` line at all.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.interaction.input` — `response|cancelled|status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `response` | string | - | Windows, Linux, macOS | `-` | The text the operator/user entered and confirmed. Absent when the dialog was cancelled or could not be shown. Values: free text. |
| `cancelled` | bool | - | Windows, Linux, macOS | `true` | true when the user dismissed the dialog without entering text (Escape, Cancel, or AppleScript error -128); omitted otherwise. |
| `status` | string | - | Windows, Linux, macOS | `error\|missing required parameter: title` | Set instead of response/cancelled when the dialog never ran: a validation failure (every platform), or an unavailable/failed dialog on Windows, macOS, or Linux. Values: error\|<reason>, unavailable\|<reason>. |

**`device.interaction.message_box` — `response|status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `response` | string | - | Windows, Linux, macOS | `ok` | The button the operator/user clicked on the dialog. Absent when the dialog could not be shown — see status. Values: ok, cancel, yes, no. |
| `status` | string | - | Windows, Linux, macOS | `error\|missing required parameter: title` | Set when no button could be returned: a validation failure (missing title/message or a bad buttons value — every platform), the macOS not_reachable sentinel (no GUI session), or a Linux zenity delivery failure. Empty on a normal button-press response. Values: not_reachable, error\|<reason>, unavailable\|<reason>. |

**`device.interaction.notify` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `error\|missing required parameter: title` | Outcome of the notification attempt: ok (shown, or handed to the OS successfully), suppressed\|<reason> (Do Not Disturb was active), error\|<reason> (missing/invalid parameter, or an unsupported platform), or unavailable\|<reason> (macOS/Linux: no reachable GUI session). Values: ok, suppressed\|<reason>, error\|<reason>, unavailable\|<reason> (reason is free text). |

**`device.interaction.set_dnd` — `dnd_enabled|dnd_duration_minutes|dnd_expires_at|status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `dnd_enabled` | bool | - | Windows, Linux, macOS | `true` | The DND state after this call — true when DND is now active, false when cleared. Values: true, false. |
| `dnd_duration_minutes` | int32 | - | Windows, Linux, macOS | `-` | The duration parameter echoed back, in minutes. Only emitted when DND was enabled with a positive duration_minutes. Values: integer. |
| `dnd_expires_at` | int64 | - | Windows, Linux, macOS | `-` | Unix epoch seconds when DND auto-clears. Only emitted alongside dnd_duration_minutes (enabled with a positive duration); 0 or omitted means indefinite. Values: epoch seconds, or omitted. |
| `status` | string | - | Windows, Linux, macOS | `ok` | Always ok — set_dnd is a local KV-store write with no external dependency and no failure path once dispatched. |

**`device.interaction.survey` — `cancelled|question_count|answer_0|answer_1|answer_2|answer_3|answer_4|status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `cancelled` | bool | - | Windows, Linux, macOS | `true` | true when the user dismissed the survey (Cancel, Escape, or AppleScript error -128) before answering every question. |
| `question_count` | int32 | - | Windows, Linux, macOS | `-` | The number of questions in the submitted survey. Only emitted when the survey completed without cancellation or failure. Values: integer. |
| `answer_0` | string | - | Windows, Linux, macOS | `-` | The answer to question 0 (0-indexed): free text for a text question, yes/no for a yesno question, or the chosen item's text for a choice question. Omitted if the survey was cancelled or could not be shown. Values: free text, or yes/no for a yesno question. |
| `answer_1` | string | - | Windows, Linux, macOS | `-` | The answer to question 1 (0-indexed), same convention as answer_0. Omitted past question_count-1. Values: free text, or yes/no for a yesno question. |
| `answer_2` | string | - | Windows, Linux, macOS | `-` | The answer to question 2 (0-indexed), same convention as answer_0. Omitted past question_count-1. Values: free text, or yes/no for a yesno question. |
| `answer_3` | string | - | Windows, Linux, macOS | `-` | The answer to question 3 (0-indexed), same convention as answer_0. Omitted past question_count-1. Values: free text, or yes/no for a yesno question. |
| `answer_4` | string | - | Windows, Linux, macOS | `-` | The answer to question 4 (0-indexed), same convention as answer_0. Omitted past question_count-1. Values: free text, or yes/no for a yesno question. |
| `status` | string | - | Windows, Linux, macOS | `error\|missing required parameter: title` | Set instead of cancelled/answers when the survey never completed: a validation failure (every platform, e.g. missing title or unparseable questions), a suppressed Do Not Disturb, or an undeliverable/unrecognized-response dialog. Values: suppressed\|<reason>, error\|<reason>, unavailable\|<reason>. |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (agent-recorded default) | — | — | Every clean dialog outcome — a button press, survey answers, a DND-suppressed run, or a validation failure — matches every sample's `[result_status] UNDECLARED / UNKNOWN /` line. `forward_runner_failure` is a no-op unless the runner itself failed. |
| `UNAVAILABLE` | `PARTIAL` | `subprocess_runner:spawn_error` | The dialog child process (osascript/zenity/notify-send/PowerShell) could not be spawned at all. |
| `CONSTRAINED` | `PARTIAL` | `subprocess_runner:deadline` | The runner's deadline elapsed and the still-running dialog process was killed. |
| `CONSTRAINED` | `PARTIAL` | `subprocess_runner:cancelled` | The run was cancelled before it finished. |
| `CONSTRAINED` | `PARTIAL` | `subprocess_runner:signaled` | The child was killed by a signal, not a clean exit. |
| `OK` | `PARTIAL` | `subprocess_runner:line_limit` | A deliberate bounded stop: the runner capped output at its line limit and killed a still-producing child — not a failure, but incomplete. |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, TAR, DEX, or metrics. Nothing runs on a schedule; the plugin executes only when an operator or workflow dispatches one of its five definitions. The dashboard's generic key/value renderer is the only non-ResponseStore consumer of these rows.
- **Sensitivity.** Nothing beyond the device id. Every column is either an enum/bool the plugin itself computes (`status`, `response` button choice, `cancelled`, `dnd_enabled`, `question_count`) or free text the interactively-logged-in user typed into a dialog (`response`, `answer_0`–`answer_4`) — the schema targets no username, device identifier, or software name, though a user could in principle type anything into a free-text field.
- **Siblings:** none — no other plugin performs desktop notification/dialog interaction.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.interaction.notify")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash dc6c8e5f72d5

```
== action=notify
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=message_box
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=input
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=survey
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=set_dnd
dnd_enabled|true
status|ok
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash dc6c8e5f72d5

```
== action=notify
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=message_box
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=input
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=survey
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=set_dnd
dnd_enabled|true
status|ok
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash dc6c8e5f72d5

```
== action=notify
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=message_box
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=input
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=survey
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=set_dnd
dnd_enabled|true
status|ok
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No sample shows a real dialog.** All three captures ran with zero parameters, so every dialog action failed validation before reaching a platform leg. `response`, `cancelled`, `answer_0`–`answer_4`, `question_count`, `dnd_duration_minutes`, and `dnd_expires_at` have no observed real value anywhere in this repo — see the code paths in Data contract → Outputs for what would populate them.
2. **The macOS capture ran as an interactive user, not the production posture.** It was taken at euid 501 (a logged-in human), not as the root LaunchDaemon the plugin actually ships under, so it cannot demonstrate the constrained "no reachable GUI session" path even though the descriptor declares macOS `CONSTRAINED` for all four dialog actions.
3. **Honest-status is a hard invariant, not a bug to "fix."** Every dialog leg treats a non-zero exit, a runner failure, or an unreachable session as `status|unavailable`/`status|not_reachable`, never a fabricated button. A pre-0.3.0 version wrongly reported `response|ok` for an undelivered macOS dialog; do not reintroduce a catch-all "unrecognized output → ok" branch on any platform.
4. **`message_box`'s `status` fires on every OS, not only macOS.** It is set on a validation failure (missing title/message or a bad `buttons` value — all three OSes, confirmed by every sample), the macOS `not_reachable` sentinel, or a Linux zenity delivery failure — never only the macOS undeliverable path.
5. **`executeRoles` differs per action.** `notify`/`set_dnd` allow `endpoint-operator`; `message_box`/`input`/`survey` are `endpoint-admin`-only. Do not assume one roles line covers every action of this plugin.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/interaction/src/interaction_parsers.hpp` · `agents/plugins/interaction/src/interaction_plugin.cpp`
- Definitions: `content/definitions/interaction.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: `tests/unit/test_interaction_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
