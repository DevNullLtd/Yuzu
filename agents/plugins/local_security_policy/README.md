# local_security_policy

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports local password, lockout and audit policy posture and sudoers content |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.local_security_policy.password_policy, crossplatform.local_security_policy.lockout_policy, crossplatform.local_security_policy.audit_policy, crossplatform.local_security_policy.sudoers) |
| **Platforms** | Windows 🟡 constrained · macOS 🟡 constrained · Linux 🟡 constrained |
| **Actions** | `audit_policy` (definition `crossplatform.local_security_policy.audit_policy`) · `lockout_policy` (definition `crossplatform.local_security_policy.lockout_policy`) · `password_policy` (definition `crossplatform.local_security_policy.password_policy`) · `sudoers` (definition `crossplatform.local_security_policy.sudoers`) |
| **Security** | `password_policy`: securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `lockout_policy`: securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `audit_policy`: securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `sudoers`: securable `Security` · operation Read · risk Medium · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

Four read-only actions (`local_security_policy_plugin.cpp`) report a host's local security policy: `password_policy`, `lockout_policy`, `audit_policy` and `sudoers`. Each writes pipe-delimited rows, the first field being the action name, then `<key>|<value>|<source>` (`sudoers` rows carry `<file>|<kind>|<subject>|<runas>|<nopasswd>|<commands>`). No action takes parameters, so no request text reaches a path or an argv. No host policy is ever configured or imported. Linux and macOS write nothing; the only file the Windows leg stages is `secedit`'s own export, in a scratch directory under `agent.data_dir` that it removes on return (`secedit` itself may also append to its default log; see "Scratch directory and stale sweep" below).

- **Linux (rung 1, bounded file reads):** `/etc/login.defs`, `/etc/security/pwquality.conf`, `/etc/security/faillock.conf`, the PAM files for each action — `password_policy` reads the `password`-type lines of `pam_pwquality`, `pam_pwhistory`, `pam_cracklib` and `pam_unix` in `/etc/pam.d/common-password`, `system-auth` and `password-auth`; `lockout_policy` reads the `auth`/`account`-type lines of `pam_faillock`, `pam_tally2` and `pam_tally` in `/etc/pam.d/common-auth`, `common-account`, `system-auth` and `password-auth` (each row keyed `pam.<type>.<module>`, valued `<control> <args>`) — `/etc/audit/audit.rules` (rule, watch-rule, syscall-rule, unmodelled-line and control-line counts and the `-e` state -- `rules` is the RULE count, equal to `watch_rules + syscall_rules + unmodelled_lines`, while `control_lines` counts the directives that configure auditd rather than add a rule — exactly `-D`, `-b`, `-f`, `-r`, `-i`, `-c`, `-e`, `--backlog_wait_time` and `--loginuid-immutable` — so a stock file of nothing but control directives correctly reports `rules|0`; `enabled` is `enabled`/`disabled`/`immutable` for `-e 1`/`0`/`2`, `unset` with no `-e`, and `unmodelled:<raw>` for any other `-e` value), and `/etc/sudoers` plus `/etc/sudoers.d`.
- **macOS:** `password_policy` and `lockout_policy` come from `pwpolicy -getaccountpolicies`, a **rung-2** argv leaf (one spawn per action, sink `local_security_policy/collect_pwpolicy#1`), because no public OpenDirectory global-policy API exists; the plist is parsed with `CFPropertyListCreateWithData`, never a hand-rolled scanner. A plist item not in the documented shape — a category whose value is not an array, a policy that is not a dictionary, `policyParameters` that is not a dictionary, a modelled field (`policyIdentifier`, `policyContent`, a parameter value) that is not a scalar, a non-string dictionary key, a key with no UTF-8 rendering, or an element carrying none of the reportable keys (`missing_content`) — is a `source_state|unreadable:<defect>` row with a `pwpolicy:<defect>` token (`CONSTRAINED`), never dropped and never `policies|none`. A string holding U+0000 has no faithful rendering and is the same defect, never a value cut at the NUL. A `policyAttribute*` parameter is its own key; any other scalar parameter (e.g. `autoEnableInSeconds`, the lockout duration) is `unmodelled_parameter` with the value `<name>=<value>`. Policy keys other than `policyIdentifier`, `policyContent` and `policyParameters` (e.g. the localised `policyContentDescription`) are ignored by design. `audit_policy` reads `/etc/security/audit_control` (absent by default on current macOS) and `sudoers` reads `/etc/sudoers` and `/etc/sudoers.d`.
- **Windows (rung 2, not rung 1):** `password_policy`, `lockout_policy` and `audit_policy` share one `secedit.exe /export /areas SECURITYPOLICY` argv leaf (sink `local_security_policy/do_export#1`; `argv[0]` is the system directory from `GetSystemDirectoryW` plus `\secedit.exe`, never a `C:\Windows\System32` literal, and an unresolved system directory reports `secedit:system_directory_unresolved`), parsed from its UTF-16LE INI (`[System Access]` and `[Event Audit]`). An export counts only when it is whole: both of those sections present and the file ending in the `[Version]` section with `signature="$CHICAGO$"`, the shape measured on the-rig; anything else is `secedit:export_incomplete`, so a truncated file never reports its lost keys as `absent`. The roadmap first drafted this leg as `NetUserModalsGet`/`LsaQueryInformationPolicy` at rung 1; the tree has no LSA policy-query precedent, `NetUserModalsGet` was passed over, and `docs/agent-privilege-model.md` names `secedit /export` the authoritative source on a running box, so the leg is declared rung 2 and the descriptor, the capability matrix and this page all say so. `sudoers` has no Windows leg.

**Scratch directory and stale sweep (Windows).** `secedit` writes the export itself, to `<agent.data_dir>\local_security_policy-<32 hex>\policy.inf`: the **whole** `SECURITYPOLICY` area (privilege-right assignments with SIDs, registry values and more), not only the keys this plugin reports. Each dispatch creates that directory itself (random 128-bit name, created with `CREATE_NEW`; the directory carries an owner-only DACL, while the export the child writes inside it gets the child's default DACL), holds it open, checks it is the agent's own, and removes it and the file on every path the process survives. With `agent.data_dir` unset the action reports `constrained|data_dir_unset`: there is no fallback location. A crash or service stop between the export and the delete orphans that copy, so each Windows policy dispatch with `agent.data_dir` set and the system directory resolved first sweeps `local_security_policy-<32 hex>` directories older than one hour under `agent.data_dir`, ownership-verified (a same-named directory owned by another SID is skipped; a non-flat one is left intact). What a crash leaves behind: the orphaned directory stays until a later Windows dispatch finds it more than an hour old — indefinitely if none follows. The sweep outcome is never a row or a token; it is logged at warn, only when the pass did something, as `scratch_sweep: removed <n> failed <n> fresh <n> not_ours <n> deferred <n>`, plus a separate warn when `agent.data_dir` cannot be enumerated. A directory whose mtime is more than an hour in the FUTURE counts as stale too (a clock that ran ahead when a dispatch crashed would otherwise hide the orphan for as long as the skew). `secedit` is run with `/log <scratch>\secedit.log`, so any log output it produces lands in the scratch directory and is removed with it. Per Microsoft's documentation, without that argument `secedit` appends to `%windir%\security\logs\scesrv.log`, a log the agent does not own; on the rig (Windows 11, `/quiet`) no such file was written with or without `/log` (measured 2026-09-30), so this is precautionary. A shipped install always has `agent.data_dir` set (the daemon defaults it, and the Windows installer passes `--data-dir`), so `data_dir_unset` is reachable only from a harness or a non-daemon host.

Every source reads as exactly one of three things: a **value**, **`absent`** (the OS definitively reports the file, key or directory is not there) or **`unreadable`** (the read failed). A failed read never reads as absent, and absence is not a failure: an `absent` row adds no reason token and does not lower the status. Each failure adds one token, `<source>:<cause>` except for the Windows scratch-directory tokens (`data_dir_unset`, `dest_dir_*`), which keep the sibling `execution_artifacts` spelling. The status is `PERMISSION_DENIED` only when at least one read was refused, no source was readable and nothing else failed; a refusal alongside any readable source, and every other failure, is `CONSTRAINED` (so a Linux `sudoers` refusal next to a readable `/etc/sudoers.d` file is `CONSTRAINED`). A value the tables cannot interpret is named `unmodelled`, never dropped. Some shapes are silent by design, not failures: one absent PAM file while a sibling alternative exists (only all-absent is a `source_state|absent|/etc/pam.d` row); a file read successfully that sets none of the reported keys (Debian's all-commented `faillock.conf`, a PAM file with no matching module line); a PAM line that is not `type control module`, which PAM itself would reject; `login.defs` keys outside the per-action allow-list; `pwpolicy` element keys other than `policyIdentifier`/`policyContent`/`policyParameters` (such as the localised `policyContentDescription`); and a Windows `[Event Audit]` category the export omits. A `pwpolicy` element carrying none of those reportable keys is not silent: it is an `unreadable:missing_content` row.

**Why this plugin exists (stated plainly, not inflated).** Zero documented INTERNAL driver anywhere: not even a tangential mention across capability-map, enterprise-parity, the SOC 2 doc or `docs/roadmap.md` (the capability-map plugin-inventory row is added by this change as a listing, not a driver). The SOC 2 doc's Workstream B (Identity/Access/Admin Security) covers RBAC/SSO/MFA for **Yuzu's own** admin accounts, with zero overlap with a managed endpoint's local security policy. This is pure capability-gap reasoning, not evidenced demand. What the plugin actually reports does map onto well-known EXTERNAL compliance frameworks, even though no internal ticket cites them: password minimum-length/complexity settings are CIS Benchmark 5.2-class controls and PCI-DSS 8.3-class requirements; the lockout threshold/duration settings are PCI-DSS 8.3.4/8.1.6-class; the audit-daemon posture (enabled state, rule coverage) is CIS 4.x/PCI-DSS 10.x-class. This mapping is offered as orientation for an operator assessing coverage, not as a claim that this plugin was built to satisfy any of those frameworks.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Security.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[local_security_policy.execute]
  EX --> WIN[Windows leg<br/>secedit /export argv leaf, rung 2]
  EX --> MAC[macOS leg<br/>pwpolicy argv leaf rung 2 + file reads]
  EX --> LIN[Linux leg<br/>bounded config-file reads]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `audit_policy` | 🟡 constrained · rung 2 · secedit.exe (system directory via GetSystemDirectoryW) /export /areas SECURITYPOLICY into an agent.data_dir scratch file | 🟡 constrained · rung 1 · /etc/security/audit_control (bounded file read) | 🟡 constrained · rung 1 · /etc/audit/audit.rules (bounded file read) |
| `lockout_policy` | 🟡 constrained · rung 2 · secedit.exe (system directory via GetSystemDirectoryW) /export /areas SECURITYPOLICY into an agent.data_dir scratch file | 🟡 constrained · rung 2 · pwpolicy -getaccountpolicies (CFPropertyList) | 🟡 constrained · rung 1 · /etc/login.defs + /etc/security/faillock.conf + /etc/pam.d/{common-auth,common-account,system-auth,password-auth} (bounded file reads) |
| `password_policy` | 🟡 constrained · rung 2 · secedit.exe (system directory via GetSystemDirectoryW) /export /areas SECURITYPOLICY into an agent.data_dir scratch file | 🟡 constrained · rung 2 · pwpolicy -getaccountpolicies (CFPropertyList) | 🟡 constrained · rung 1 · /etc/login.defs + /etc/security/pwquality.conf + /etc/pam.d/{common-password,system-auth,password-auth} (bounded file reads) |
| `sudoers` | ⛔ unsupported · no sudoers on Windows | 🟡 constrained · rung 1 · /etc/sudoers + /etc/sudoers.d (bounded file reads) | 🟡 constrained · rung 1 · /etc/sudoers + /etc/sudoers.d (bounded file reads) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`audit_policy` / Windows** — the LEGACY [Event Audit] categories only. Where Advanced Audit Policy subcategories are in force -- the Windows 10/11 default and the norm under GPO -- these are NOT the effective audit state: a category reading none means the legacy category is unset, not that the host is not auditing. auditpol subcategories are not read. It is the local security database (secedit /export without /mergedpolicy); domain-joined behaviour is unmeasured. The export (the whole SECURITYPOLICY area) is staged as agent.data_dir\\local_security_policy-{32 hex}\\policy.inf in an owner-only directory removed on return; each policy dispatch first sweeps such directories older than one hour, so a crash leaves one until a later dispatch. Measured only as LocalSystem, elevated, on a standalone host; see the Windows leg banner
- **`audit_policy` / macOS** — absent by default on current macOS (only audit_control.example ships), reported as absent; a present file is root-readable only
- **`audit_policy` / Linux** — rule counts and -e state of the rule file only, not the live kernel rules (auditctl -l) and not /etc/audit/rules.d; the file is 0640 root, so an unprivileged agent reports permission_denied; in a container (deploy/docker/Dockerfile.agent) these are the image's files, not the host's
- **`lockout_policy` / Windows** — argv leaf parsed from the exported UTF-16LE INI: the local security database (secedit /export without /mergedpolicy); domain-joined behaviour is unmeasured. The export (the whole SECURITYPOLICY area) is staged as agent.data_dir\\local_security_policy-{32 hex}\\policy.inf in an owner-only directory removed on return; each policy dispatch first sweeps such directories older than one hour, so a crash leaves one until a later dispatch. Measured only as LocalSystem, elevated, on a standalone host; see the Windows leg banner
- **`lockout_policy` / macOS** — global account policies only; no authentication policy reports policies|none (the default); a plist item not in the documented shape is an unreadable row and constrained. Measured on an UNMANAGED Mac, so on a managed device policies|none must not be read as 'no lockout enforced' -- profile-delivered policy is unverified here
- **`lockout_policy` / Linux** — reports configuration, not live lockout counters; faillock.conf drop-ins and PAM include/substack targets are not read; in a container (deploy/docker/Dockerfile.agent) these are the image's files, not the host's
- **`password_policy` / Windows** — argv leaf parsed from the exported UTF-16LE INI: the local security database (secedit /export without /mergedpolicy); domain-joined behaviour is unmeasured. The export (the whole SECURITYPOLICY area) is staged as agent.data_dir\\local_security_policy-{32 hex}\\policy.inf in an owner-only directory removed on return; each policy dispatch first sweeps such directories older than one hour, so a crash leaves one until a later dispatch. Measured only as LocalSystem, elevated, on a standalone host; see the Windows leg banner
- **`password_policy` / macOS** — global account policies only; rung 2 because no public OpenDirectory global-policy API exists; policy expressions are verbatim; a policyAttribute* parameter is its own key and any other is unmodelled_parameter <name>=<value>; a plist item not in the documented shape is an unreadable row and constrained. Measured on an UNMANAGED Mac: whether an MDM configuration-profile passcode payload surfaces here is unverified
- **`password_policy` / Linux** — reports what the config files state, not the live PAM decision; pwquality.conf.d fragments and PAM include/substack targets are not read; a missing file is reported as absent, an unreadable one as unreadable (permission_denied/constrained); in a container (deploy/docker/Dockerfile.agent) these are the image's files, not the host's
- **`sudoers` / macOS** — /etc/sudoers is root:wheel 0440: reading it needs root or group wheel, otherwise permission_denied (kind unreadable)
- **`sudoers` / Linux** — parsed content, not sudo's evaluation: include directives are listed, not followed; unrecognised lines are kind unmodelled; needs read access to the 0440 root files; in a container (deploy/docker/Dockerfile.agent) these are the image's files, not the host's
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | `secedit /export` needs an elevated token. What was measured, and only that: on the-rig, run as LocalSystem from a scheduled task (RunLevel Highest), the export succeeded with `SeSecurityPrivilege` present but in its default **Disabled** state (the `RIG PROBE` banner in `local_security_policy_win.cpp`, `docs/samples/windows.txt`). Which privilege is actually required, and whether the dedicated `NT SERVICE\YuzuAgent` account (which holds `SeSecurityPrivilege` via `scripts/install-agent-user.ps1`) succeeds, were **not** measured | Yes, as LocalSystem on a standalone Windows 11 Pro host (rig probe 2026-09-21; committed sample re-captured 2026-09-29): a real 12,828-byte `secedit` export (UTF-16LE) and the committed sample. No fixture of the export is committed | A refused `secedit` run is expected to exit non-zero and report `CONSTRAINED` with `secedit:exit_<n>` (not measured). `PERMISSION_DENIED` with `secedit:access_denied` is reported only when the agent cannot open its own export file (`ERROR_ACCESS_DENIED`; never observed). Either way the action returns 0 with the row `constrained\|<token>` (degradation is the typed status; rc is not a proxy for it) |
| macOS | agent daemon, root today (LaunchDaemon carries no `UserName` key, `docs/agent-privilege-model.md` TL;DR) | None for `pwpolicy -getaccountpolicies`; `/etc/sudoers` is `root:wheel` `0440`, so reading it needs root or group wheel | Bare-metal, this Mac (`braga`), unprivileged (euid 501; probe 2026-09-21, committed sample re-captured 2026-09-29): real capture (`docs/samples/macos.txt`); no root-privileged run has been captured | `EACCES` on `/etc/sudoers` reports the row kind `unreadable` with `permission_denied` and the action reports `PERMISSION_DENIED`/`PARTIAL`; a failed `pwpolicy` run reports `CONSTRAINED` with `pwpolicy:<cause>` |
| Linux | agent daemon, default | None for the world-readable config; `/etc/audit/audit.rules` (`0640`) and `/etc/sudoers` plus `/etc/sudoers.d/*` (`0440`) need root or a read-override capability | Only in a container: the live sample under `docs/samples/linux.txt` is a run of the built `.so` as root inside a Debian 13 container hardened for the capture (sudo with a `sudoers.d` drop-in, auditd rules, pwquality and faillock values), so it describes that container's `/etc`, not a host (caveat 4). No fixtures are committed and no bare-metal Linux host has been captured | `EACCES`/`EPERM` reports the source `unreadable` with `<path>:permission_denied`; the action reports `PERMISSION_DENIED` when nothing else was readable, otherwise `CONSTRAINED`; a missing file (`ENOENT`) reports `absent` with no token |

Binaries/subprocesses: Windows runs `<system directory>\secedit.exe /export /cfg <agent.data_dir>\local_security_policy-<32 hex>\policy.inf /areas SECURITYPOLICY /quiet` (system directory from `GetSystemDirectoryW`, absolute path, no shell, no PowerShell, no `/configure`; the only file the agent stages is that export, and `secedit` is given `/log <scratch>\secedit.log` so any log output stays in that directory); macOS runs `/usr/bin/pwpolicy -getaccountpolicies` (absolute path, no shell); Linux runs nothing. Network: none.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
No action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows via `write_output()`. The first field is the fixed literal action name (`password_policy`, `lockout_policy`, `audit_policy` or `sudoers`), then `<key>`, `<value>` and `<source>` (for `sudoers`: `<file>`, `<kind>`, `<subject>`, `<runas>`, `<nopasswd>`, `<commands>`). Every field passes through the shared untrusted-output escaper. A key present with no value reads `present`. A source that is missing or unreadable is one `source_state` row (`absent`, or `unreadable:<token>`); a `sudoers` source is instead a row of kind `absent` (`commands` is `-`) or `unreadable` (`commands` is the bare token, e.g. `permission_denied`). A macOS `pwpolicy` item not in the documented plist shape is a `source_state|unreadable:<defect>` row whose source names the policy identifier or category (`pwpolicy` when neither is known). Windows `password_policy`/`lockout_policy` always emit their fixed key list, and a key the export does not carry reads `absent`; Windows `audit_policy` instead emits one row per `[Event Audit]` category the export actually carries — a category the export omits has no row (no `absent` row), and an export with no `[Event Audit]` or `[System Access]` section fails the completeness check (`secedit:export_incomplete`); a section that is present but empty is `CONSTRAINED` with `secedit:section_missing_event_audit` / `secedit:section_missing_system_access`. macOS reports `policies|none` when no matching policy is set and no item was malformed, which is the default. In `sudoers`, each `:`-separated `Host_List = ...` clause of a user spec is its own row, and so is each change of run-as or `NOPASSWD` tag within a clause (`alice ALL = (root) NOPASSWD: /a, (bob) /b` is two rows), and Option_Spec words (`CWD=`, `CHROOT=`, `TIMEOUT=`, `NOTBEFORE=`, `ROLE=`, `APPARMOR_PROFILE=`, ...) stay verbatim in `commands` like every tag other than `NOPASSWD`/`PASSWD`. Files are lexed as sudo 1.9.16's `toke.l` lexes them: a `:` inside a quoted value (`CWD="/x y:z"`), an escape, an IPv6 host or a digest never splits a clause, and a `#` comment, glued to a word or not, never continues onto the next line. That was checked differentially against sudo's own `sudo -ll` verdicts on a generated corpus of `visudo`-accepted files, with no mismatch. As a fail-safe, a line still carrying a `NOPASSWD:`/`PASSWD:` tag the parser could not decode is kind `unmodelled` plus the token `<file>:undecoded_passwd_tag` (`CONSTRAINED`). What this does not cover: `nopasswd` is the tag alone (see "Sensitivity"); aliases and includes are not resolved; another sudo version may lex differently; a line sudo itself rejects is reported best-effort. Limits per file: a User_List, Host_List or run-as over 4 KiB, or a line that would expand to more than 256 rows, is not decoded (it is one `unmodelled` row with its raw text), and parsing stops once the 4096-row cap is reached. The shared row escaper renders a literal backslash as `/` (`%domain\ admins` reads `%domain/ admins`, `foo\ bar` reads `foo/ bar`); this is the platform's deliberately lossy output convention, not a sudoers rule. A file holding a NUL byte is `unreadable:embedded_nul` as a whole (`<path>:embedded_nul`): C consumers stop at the NUL, so no value after it can be reported as the one in force. A Windows export holding one anywhere is `secedit:embedded_nul` with no rows.

**Row cap.** Every action stops at 4096 rows per dispatch: 4095 data rows plus one marker row, and the status becomes `CONSTRAINED` with the token `row_cap`. For the file-backed Linux/macOS-`audit_policy` sources the marker is `<action>|source_state|unreadable:row_cap|<action>` (its source field is the action name, not a path), and `sudoers|-|unreadable|-|-|-|row_cap` for `sudoers`; the macOS `pwpolicy` path's own row cap writes the four-field shape but a fixed literal `pwpolicy` in the source field instead, since a pwpolicy dispatch has no single "action name" source the way a file read does. The `pwpolicy` path is additionally bounded by the tool's own output cap (`pwpolicy:output_truncated`) before the row cap can even apply, and each row's own source field truncates a long policy identifier/category to 256 bytes before embedding it, so one oversized identifier repeated across many rows cannot itself grow the response past the row cap's intent. On the Windows `secedit` path `password_policy` and `lockout_policy` emit one row per fixed key, while `audit_policy` emits one row per `[Event Audit]` key the export carries (a real export has nine); the export is bounded by the 1 MiB cap (`secedit:output_oversized`), which is the only bound on that row count. The `/etc/sudoers.d` listing is separately capped at 256 entries (`sudoers.d:truncated`, row `sudoers|/etc/sudoers.d|unreadable|-|-|-|truncated`).

**Failure rows and return codes.** When a non-OK outcome produced no rows at all — today only a failed `pwpolicy` run (spawn error, deadline, truncated output, non-zero exit, no plist or an unparseable one) — the action writes one `<action>|status|constrained|<reason>` row rather than an empty result; the fourth field carries the reason token, not a source. (`status|permission_denied` exists only as a defensive branch: no current source reaches it.) File-backed and `pwpolicy` failures are data-level outcomes and the action returns 0. Only two cases write the two-field row `constrained|<token>`: every Windows-leg failure (rc 0 -- degradation is the typed status, rc is not a proxy for it) and an exception contained on any OS (`constrained|internal_error`, rc 1). On Windows that row reads `constrained` even when the typed status is `PERMISSION_DENIED` (the status field and the token, e.g. `secedit:access_denied`, carry the distinction). `sudoers` on Windows returns 1 with the row `sudoers|-|unsupported|-|-|-|windows_has_no_sudoers` and status `UNAVAILABLE`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.local_security_policy.audit_policy` — `row_kind|key|value|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `audit_policy` `constrained` | Windows, Linux, macOS | `audit_policy` | Fixed row tag, always the action name. Two cases write a two-field constrained\|<reason> row instead, whose second field is the reason: every Windows-leg failure (scratch directory, secedit run or export), and an exception contained on any OS (constrained\|internal_error). Linux and macOS read failures stay in this four-field shape as source_state or status rows. |
| `key` | string | - | Windows, Linux, macOS | `watch_rules` | Setting name: rules, watch_rules, syscall_rules, unmodelled_lines, control_lines or enabled (Linux), an audit_control key (macOS), an [Event Audit] category name (Windows -- one row per category the export carries; a category the export omits has no row), or source_state when the source is absent or unreadable (and on the row-cap marker). |
| `value` | string | - | Windows, Linux, macOS | `12` | The setting value: a count (Linux -- rules is the RULE count, equal to watch_rules + syscall_rules + unmodelled_lines; control_lines counts the lines that configure auditd rather than add a rule, exactly -D, -b, -f, -r, -i, -c, -e, --backlog_wait_time and --loginuid-immutable), the audit_control value (macOS), none/success/failure/success_failure or unmodelled:<raw> (Windows), or, for the Linux enabled row, enabled/disabled/immutable for -e 1/0/2, unset with no -e line, or unmodelled:<raw> for any other -e value. For source_state, absent or unreadable:<reason> (unreadable:row_cap on the row-cap marker). |
| `source` | string | - | Windows, Linux, macOS | `/etc/audit/audit.rules` | Where the row was read: /etc/audit/audit.rules (Linux), /etc/security/audit_control (macOS) or secedit (Windows). The row-cap marker carries audit_policy. |

**`crossplatform.local_security_policy.lockout_policy` — `row_kind|key|value|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `lockout_policy` `constrained` | Windows, Linux, macOS | `lockout_policy` | Fixed row tag, always the action name. Two cases write a two-field constrained\|<reason> row instead, whose second field is the reason: every Windows-leg failure (scratch directory, secedit run or export), and an exception contained on any OS (constrained\|internal_error). Linux and macOS read failures stay in this four-field shape as source_state or status rows. |
| `key` | string | - | Windows, Linux, macOS | `LOGIN_RETRIES` | Setting name: a login.defs / faillock.conf key or a pam.<type>.<module> stack line (Linux), a pwpolicy item (macOS: policy_content, a policyAttribute* name, unmodelled_category, unmodelled_parameter, policies), a secedit key (Windows), source_state when a whole source is absent or unreadable (also a macOS pwpolicy item not in the documented plist shape, and the row-cap marker), or status when a non-OK outcome produced no rows at all (only a failed macOS pwpolicy run). |
| `value` | string | - | Windows, Linux, macOS | `5` | The setting value; present when a key has no value; absent for a Windows key the export does not carry; for a pam.<type>.<module> row, the control followed by the module arguments; for unmodelled_parameter (macOS), <name>=<value>. For source_state, absent or unreadable:<reason> (a macOS pwpolicy defect is unreadable:malformed_category, malformed_policy, malformed_identifier, malformed_content, malformed_parameters, malformed_parameter_value, non_string_key, unconvertible_key or missing_content; a file holding a NUL byte is unreadable:embedded_nul; the row-cap marker is unreadable:row_cap). For status, constrained -- the only state any leg reaches today. |
| `source` | string | - | Windows, Linux, macOS | `/etc/login.defs` | Where the row was read: a file path, or /etc/pam.d when every PAM file of the action is absent (Linux); pwpolicy:<policy identifier>, pwpolicy:<category> when the policy has no identifier, or pwpolicy (macOS); secedit (Windows). The row-cap marker carries the action name. On a status row this field carries the failure reason token instead, not a source. |

**`crossplatform.local_security_policy.password_policy` — `row_kind|key|value|source`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `password_policy` `constrained` | Windows, Linux, macOS | `password_policy` | Fixed row tag, always the action name. Two cases write a two-field constrained\|<reason> row instead, whose second field is the reason: every Windows-leg failure (scratch directory, secedit run or export), and an exception contained on any OS (constrained\|internal_error). Linux and macOS read failures stay in this four-field shape as source_state or status rows. |
| `key` | string | - | Windows, Linux, macOS | `PASS_MAX_DAYS` | Setting name: a login.defs / pwquality key or a pam.<type>.<module> stack line (Linux), a pwpolicy item (macOS: policy_content, minimum_length, a policyAttribute* name, unmodelled_category, unmodelled_parameter, policies), a secedit key (Windows), source_state when a whole source is absent or unreadable (also a macOS pwpolicy item not in the documented plist shape, and the row-cap marker), or status when a non-OK outcome produced no rows at all (only a failed macOS pwpolicy run). |
| `value` | string | - | Windows, Linux, macOS | `99999` | The setting value; present when a key has no value; absent for a Windows key the export does not carry; for a pam.<type>.<module> row, the control followed by the module arguments; for unmodelled_parameter (macOS), <name>=<value>. For source_state, absent or unreadable:<reason> (a macOS pwpolicy defect is unreadable:malformed_category, malformed_policy, malformed_identifier, malformed_content, malformed_parameters, malformed_parameter_value, non_string_key, unconvertible_key or missing_content; a file holding a NUL byte is unreadable:embedded_nul; the row-cap marker is unreadable:row_cap). For status, constrained -- the only state any leg reaches today. |
| `source` | string | - | Windows, Linux, macOS | `/etc/login.defs` | Where the row was read: a file path, or /etc/pam.d when every PAM file of the action is absent (Linux); pwpolicy:<policy identifier>, pwpolicy:<category> when the policy has no identifier, or pwpolicy (macOS); secedit (Windows). The row-cap marker carries the action name. On a status row this field carries the failure reason token instead, not a source. |

**`crossplatform.local_security_policy.sudoers` — `row_kind|file|kind|subject|runas|nopasswd|commands`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `sudoers` `constrained` | Linux, macOS | `sudoers` | Fixed row tag, always sudoers. Read failures stay in this seven-field shape (kind absent or unreadable); only an exception contained in the plugin writes a two-field constrained\|internal_error row instead. |
| `file` | string | - | Linux, macOS | `/etc/sudoers` | The file the entry was read from; /etc/sudoers.d on a row about the directory listing itself; a dash on the row-cap marker. |
| `kind` | string | `defaults` `alias` `include` `includedir` `user_spec` `unmodelled` `ignored` `absent` `unreadable` | Linux, macOS | `user_spec` | Entry kind. defaults, alias, include, includedir, user_spec: a recognised line. unmodelled: a line the parser has no interpretation for (raw line in commands); one that still carries a NOPASSWD: or PASSWD: tag the parser could not decode also adds the failure token <file>:undecoded_passwd_tag (CONSTRAINED). Lines are lexed as sudo 1.9.16 lexes them (checked against sudo -ll), so a colon in a quoted value, an IPv6 host or a digest never splits a clause; the nopasswd column is the tag alone, and a line sudo itself rejects is best-effort. ignored: a sudoers.d file sudo skips by name (commands name_ignored_by_sudo). absent: the file or the /etc/sudoers.d directory does not exist. unreadable: the read failed (bare reason token in commands, e.g. permission_denied; truncated on the /etc/sudoers.d row when the listing hit its 256-entry cap; row_cap, with file -, on the marker row once output reaches 4096 rows). The plugin also emits kind unsupported on Windows (reason windows_has_no_sudoers in commands), which this definition cannot surface because it does not run there. |
| `subject` | string | - | Linux, macOS | `%sudo@ALL` | Who the entry applies to. A user spec carries <user>@<host> -- the user, group or alias joined to the host list the spec applies on; each colon-separated Host_List clause of one line is its own row. An alias row carries <Alias_Type>:<name>. A scoped Defaults line carries its scope (user:, host:, cmnd:, runas:). A dash when not applicable. |
| `runas` | string | - | Linux, macOS | `ALL` | Run-as user/group of a user spec; a dash when not applicable. |
| `nopasswd` | string | `true` `false` `-` | Linux, macOS | `false` | Whether a user spec carries the NOPASSWD tag: true or false; a dash on a row that is not a user spec. It reflects the tag only: a Defaults row with !authenticate (kind defaults) also makes matching grants passwordless and must be read alongside it. |
| `commands` | string | - | Linux, macOS | `ALL` | The command list of a user spec (any tag other than NOPASSWD/PASSWD, e.g. SETENV:, is kept in front of its command as TAG: , and any Option_Spec such as CWD=/tmp or TIMEOUT=5m verbatim), the Defaults or alias body, an include path, the raw text of an unmodelled line, the reason on an ignored or unreadable row, or a dash on an absent row. |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | `FULL` | - | Every source was read or definitively `absent`. An absent source adds no token, so a default macOS host with no `audit_control` reports `OK`. |
| `CONSTRAINED` | `PARTIAL` | `<path>:symlink_loop`, `<path>:io_error`, `<path>:oversized`, `<path>:not_regular`, `<path>:errno_<n>`, `<path>:embedded_nul`, `<path>:symlink_refused`, `<path>:insecure_owner_or_mode`, `<path>:permission_denied`, `<path>:undecoded_passwd_tag`, `sudoers.d:<cause>`, `sudoers.d:truncated`, `row_cap` | Linux and macOS file reads: at least one source failed for a reason other than a refusal, or a refusal while something else was readable; the reason lists one token per failure. `<path>` is the full path, including `/etc/sudoers.d/<name>` for a file in that directory; a failure to list the directory itself is `sudoers.d:<cause>` (the bare name `sudoers.d`, not the path). `symlink_refused` and `insecure_owner_or_mode` are the sudoers-only checks: those sources are opened without following links and must be owned by uid 0 and not group/other-writable (stricter than sudo, which allows a group-writable file owned by the sudoers group), so a planted link on a sudoers file never turns the action into a read of another file. Only the file itself is checked, not its parent directories. |
| `CONSTRAINED` | `PARTIAL` | `pwpolicy:spawn_error`, `pwpolicy:deadline`, `pwpolicy:cancelled`, `pwpolicy:signaled`, `pwpolicy:unexpected_termination`, `pwpolicy:output_truncated`, `pwpolicy:exit_<n>`, `pwpolicy:no_plist`, `pwpolicy:plist_unparseable` | macOS `password_policy` and `lockout_policy`: the `pwpolicy` run or its plist failed. |
| `CONSTRAINED` | `PARTIAL` | `pwpolicy:malformed_category`, `pwpolicy:malformed_policy`, `pwpolicy:malformed_parameters`, `pwpolicy:malformed_identifier`, `pwpolicy:malformed_content`, `pwpolicy:malformed_parameter_value`, `pwpolicy:non_string_key`, `pwpolicy:unconvertible_key`, `pwpolicy:missing_content` | macOS `password_policy` and `lockout_policy`: the plist parsed but an item was not in the documented shape; each is also a `source_state\|unreadable:<defect>` row, alongside every well-formed policy's rows. |
| `CONSTRAINED` | `PARTIAL` | `data_dir_unset`, `secedit:system_directory_unresolved`, `dest_dir_create_<n>`, `dest_dir_open_<n>`, `dest_dir_acl`, `secedit:spawn_error`, `secedit:deadline`, `secedit:cancelled`, `secedit:signaled`, `secedit:unexpected_termination`, `secedit:exit_<n>`, `secedit:output_missing`, `secedit:read_<n>`, `secedit:output_not_regular`, `secedit:output_oversized`, `secedit:output_short_read`, `secedit:decode_failed`, `secedit:export_incomplete`, `secedit:embedded_nul`, `secedit:section_missing_system_access`, `secedit:section_missing_event_audit`, `secedit:unsupported_action` | Windows: the scratch directory or the `secedit` run or export failed; the action returns 0 (degradation is carried by the typed status) with the row `constrained\|<token>`. |
| `CONSTRAINED` | `PARTIAL` | `internal_error` | Any leg: an unexpected exception was contained in `execute()`; the action returns 1 with the row `constrained\|internal_error`. |
| `PERMISSION_DENIED` | `PARTIAL` | `<path>:permission_denied`, `sudoers.d:permission_denied`, `secedit:access_denied` | File legs: at least one read was refused, no source was readable and nothing else failed. Windows: the agent could not open its own export file (`ERROR_ACCESS_DENIED`; never observed — a refused `secedit` run surfaces as `secedit:exit_<n>` instead). |
| `UNAVAILABLE` | `PARTIAL` | `windows_has_no_sudoers`, `unsupported_os` | `sudoers` dispatched on Windows; or any action on an OS with no leg (not a supported platform; row `constrained\|unsupported_os`). |

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. Each action is a gathered definition (`crossplatform.local_security_policy.<action>`, 300s TTL).
- **Not consumed by** daily-sync, TAR, DEX, or metrics.
- **Sensitivity.** Password, lockout and audit rows are a compliance baseline of the host (a short minimum length, no lockout, auditing off), which is useful to an attacker choosing a target. `sudoers` rows carry account and group names, run-as targets, `NOPASSWD` flags and command paths, i.e. who may become root. The `nopasswd` column reflects the `NOPASSWD` tag only: a `Defaults[:user] !authenticate` row also makes matching grants passwordless and must be read alongside it. `sudoers` rows carry usernames, groups and command text verbatim (an argument can embed a secret), and stay in the response store under its generic retention. With RBAC off (the shipped default) any authenticated session that can dispatch to the device can read them; the action is `Security:Read`, not `UserManagement:Read`, because it sits with the other privilege-posture reads. Treat all four like other `Security` data.
- **Siblings:** `firewall`, `bitlocker` and `antivirus` (other `Security` posture plugins) and `users` (account and group membership; this plugin reports policy, not accounts).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-09-29 · LocalSystem (elevated) · leg-hash 0fe9f183d5a9

```
== action=password_policy
password_policy|MinimumPasswordAge|0|secedit
password_policy|MaximumPasswordAge|42|secedit
password_policy|MinimumPasswordLength|0|secedit
password_policy|PasswordComplexity|0|secedit
password_policy|PasswordHistorySize|0|secedit
password_policy|ClearTextPassword|0|secedit
[result_status] OK / FULL

== action=lockout_policy
lockout_policy|LockoutBadCount|0|secedit
lockout_policy|ResetLockoutCount|absent|secedit
lockout_policy|LockoutDuration|absent|secedit
[result_status] OK / FULL

== action=audit_policy
audit_policy|AuditAccountLogon|none|secedit
audit_policy|AuditAccountManage|none|secedit
audit_policy|AuditDSAccess|none|secedit
audit_policy|AuditLogonEvents|none|secedit
audit_policy|AuditObjectAccess|none|secedit
audit_policy|AuditPolicyChange|none|secedit
audit_policy|AuditPrivilegeUse|none|secedit
audit_policy|AuditProcessTracking|none|secedit
audit_policy|AuditSystemEvents|none|secedit
[result_status] OK / FULL

== action=sudoers
sudoers|-|unsupported|-|-|-|windows_has_no_sudoers
[result_status] UNAVAILABLE / PARTIAL / windows_has_no_sudoers
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-29 · euid 501 · leg-hash 0fe9f183d5a9

```
== action=password_policy
password_policy|policy_content|policyAttributePassword matches '.{4,}+'|pwpolicy:com.apple.defaultpasswordpolicy.fde
password_policy|minimum_length|4|pwpolicy:com.apple.defaultpasswordpolicy.fde
[result_status] OK / FULL

== action=lockout_policy
lockout_policy|policies|none|pwpolicy
[result_status] OK / FULL

== action=audit_policy
audit_policy|source_state|absent|/etc/security/audit_control
[result_status] OK / FULL

== action=sudoers
sudoers|/etc/sudoers|unreadable|-|-|-|permission_denied
[result_status] PERMISSION_DENIED / PARTIAL / /etc/sudoers:permission_denied
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-29 · euid 0 · leg-hash 0fe9f183d5a9

```
== action=password_policy
password_policy|PASS_MAX_DAYS|99999|/etc/login.defs
password_policy|PASS_MIN_DAYS|0|/etc/login.defs
password_policy|PASS_WARN_AGE|7|/etc/login.defs
password_policy|ENCRYPT_METHOD|YESCRYPT|/etc/login.defs
password_policy|source_state|absent|/etc/security/pwquality.conf
password_policy|pam.password.pam_unix.so|[success=1 default=ignore] obscure yescrypt|/etc/pam.d/common-password
[result_status] OK / FULL

== action=lockout_policy
lockout_policy|LOGIN_RETRIES|5|/etc/login.defs
lockout_policy|LOGIN_TIMEOUT|60|/etc/login.defs
[result_status] OK / FULL

== action=audit_policy
audit_policy|source_state|absent|/etc/audit/audit.rules
[result_status] OK / FULL

== action=sudoers
sudoers|/etc/sudoers|defaults|-|-|-|env_reset
sudoers|/etc/sudoers|defaults|-|-|-|mail_badpass
sudoers|/etc/sudoers|defaults|-|-|-|secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
sudoers|/etc/sudoers|defaults|-|-|-|use_pty
sudoers|/etc/sudoers|user_spec|root@ALL|ALL:ALL|false|ALL
sudoers|/etc/sudoers|user_spec|%sudo@ALL|ALL:ALL|false|ALL
sudoers|/etc/sudoers|includedir|-|-|-|/etc/sudoers.d
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No documented business driver.** The priority for this plugin is asserted from a capability-gap reading, not evidenced by any tracked demand (see "How it works"); there is no capability-map requirement, named customer, SOC 2 control or CVE behind it.
2. **Configuration, not evaluation; Windows `audit_policy` is the legacy categories only.** Files are reported as written, not as PAM, sudo or auditd would evaluate them (drop-ins, includes and `/etc/audit/rules.d` are not followed), and a Windows `none` means the legacy `[Event Audit]` category is unset, not that the host is not auditing — Advanced Audit Policy (`auditpol`) is not read. Some shapes produce no row at all (listed under "How it works"), so for them "not set" and "not read" look the same.
3. **Windows is measured once, as LocalSystem on a standalone host with the default `agent.data_dir`, and stages a full policy export on disk.** Which privilege is required, whether `NT SERVICE\YuzuAgent` succeeds, domain-joined behaviour (the export is the local security database, without `/mergedpolicy`) and a non-default `agent.data_dir` (an SMB share, a non-NTFS volume, a path over `MAX_PATH`, which may fail the leg as `dest_dir_acl` or `secedit:exit_<n>`) are unmeasured; the staged copy holds the whole `SECURITYPOLICY` area and outlives a crash until a later Windows dispatch sweeps it, indefinitely if none follows, and an uninstall that keeps the data directory keeps it too.
4. **Privileged files read `unreadable` for an unprivileged agent, and a container reports its own `/etc`.** `sudoers`, `sudoers.d` and `audit.rules` need root or a read-override capability, and are then an `unreadable` row, never an empty list. The sudoers sources are read without following symlinks and must be root-owned and not group/other-writable, so a symlinked `/etc/sudoers` (NixOS and some configuration-management layouts) or a loosely-permissioned entry reports `unreadable` with `symlink_refused` / `insecure_owner_or_mode` rather than being followed; PAM files, which are legitimately symlinked (authselect), are still followed, and so are the other file-backed sources (`pwquality.conf`, `faillock.conf`, macOS `audit_control`): only sudoers is strict today. Only the leaf is checked; a symlinked parent directory is followed. A `User_List`, `Host_List` or run-as over 4 KiB is reported as one `unmodelled` row, still with a clean status. The shipped `Dockerfile.agent` image runs unprivileged with no host `/etc`, so it reports the image's files (the committed Linux sample is a root run in a hardened Debian 13 container, which likewise describes that container, not a host).
5. **Global scope only, unmanaged captures, and no cross-OS normalisation.** macOS reports global (not per-user) policy from an unmanaged Mac, so on an MDM-managed device `policies|none` must not be read as "no lockout enforced". Keys stay in each OS's own vocabulary (`MinimumPasswordLength`, `PASS_MIN_LEN`/`minlen`, `minimum_length`), so fleet baselines branch per OS.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/local_security_policy/src/local_security_policy_legs.hpp` · `agents/plugins/local_security_policy/src/local_security_policy_linux.cpp` · `agents/plugins/local_security_policy/src/local_security_policy_macos.cpp` · `agents/plugins/local_security_policy/src/local_security_policy_parsers.hpp` · `agents/plugins/local_security_policy/src/local_security_policy_plugin.cpp` · `agents/plugins/local_security_policy/src/local_security_policy_scratch_identity.hpp` · `agents/plugins/local_security_policy/src/local_security_policy_scratch_sweep.hpp` · `agents/plugins/local_security_policy/src/local_security_policy_win.cpp`
- Definitions: `content/definitions/local_security_policy.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_local_security_policy.hpp`
- Tests: `tests/unit/test_local_security_policy_local_dispatcher.cpp` · `tests/unit/test_local_security_policy_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2026-09-29-local_security_policy-windows-sudoers.added.md` · `changelog.d/5069-local_security_policy.added.md`
<!-- END GENERATED -->
