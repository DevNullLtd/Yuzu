# remote_access_audit

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | SSH inbound-access audit: sshd_config as written, per-account authorized_keys fingerprints, sshd service state; never key comments, option values or paths |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.security.remote_access_audit) |
| **Platforms** | Windows 🟡 planned · macOS ✅ · Linux ✅ |
| **Actions** | `list` (definition `crossplatform.security.remote_access_audit`) |
| **Security** | securable `Forensics` · operation Read · risk High · dispatch ReadOnly · approval gate AdminOrApproval |
| **Roles** | execute: admin · author: content-author |
<!-- END GENERATED -->

## How it works

`list` reports who can log in to this host over SSH, as configured, in four parts: the `sshd_config` values that govern inbound access, the public keys each account trusts, whether the `sshd` service is enabled, and where each fact came from. It changes nothing. The first row is always a `status` row saying whether the read was complete, then three `source` rows (`sshd_config`, `homes`, `service`; each says `read`, `absent`, `refused` or `failed`, so zero `key` rows is never an ambiguous empty success), then a `config` row for every allowlisted setting, the `service` rows, and finally one `file` row per `authorized_keys` file followed by one `key` row for every key line `sshd` would accept.

`sshd_config` is read as `sshd` reads it: the first value of a setting wins in directive order, `Include` files are parsed at the directive's position (relative paths are taken under `/etc/ssh/`, a leaf wildcard is expanded in byte order, up to 4 levels and 32 files), and a `Match` block is counted but never evaluated and nothing inside it is applied. `AuthorizedKeysFile` decides which files are read per account (`.ssh/authorized_keys` and `.ssh/authorized_keys2` when unset; `%h` and `%%` are expanded, `%u`, `%U` and `~` are reported as unsupported rather than guessed). A key row carries the type, the fingerprint (`SHA256:` plus unpadded base64, byte-identical to `ssh-keygen -lf`; a certificate reports the key it carries), the key size, flags (`certificate`, `cert_authority`, `has_command`, `has_from`, `has_principals`, `unknown_type`) and the option **names** it uses. Every key blob and certificate is decoded completely and within bounds, and trailing bytes are refused. A key comment, an option **value** (`command=`, `from=`, `principals=`), a principals list and any key-file path are never emitted, not even in the `authorizedkeysfile` config row, which says only `default`, `none` or `custom:<n>`.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Forensics.Read + AdminOrApproval, single target, kill switch]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[remote_access_audit.execute]
  EX --> WIN[Windows leg<br/>status row only: windows:planned]
  EX --> MAC[macOS leg<br/>sshd_config, authorized_keys, launchctl print-disabled]
  EX --> LIN[Linux leg<br/>sshd_config, authorized_keys, systemctl is-enabled]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list` | 🟡 planned · rung 1 · per-profile .ssh\\authorized_keys, %ProgramData%\\ssh\\administrators_authorized_keys and sshd_config via win_profiles | ✅ supported · rung 2 · bounded reads of /etc/ssh/sshd_config (Include followed, config symlinks followed as sshd does) and each account's authorized_keys (no-follow; pure parsers, SHA-256 fingerprints); one bounded launchctl print-disabled system argv | ✅ supported · rung 2 · bounded reads of /etc/ssh/sshd_config (Include followed, config symlinks followed as sshd does) and each account's authorized_keys (no-follow; pure parsers, SHA-256 fingerprints); one bounded systemctl is-enabled argv per sshd unit |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`list` / Windows** — not read yet: one unsupported status row, windows:planned
- **`list` / macOS** — configured access as written, not sshd's effective policy; the launchd override is not 'running'; key comments, option values and key-file paths are never emitted; a symlinked key file or .ssh is refused; network mounts are skipped
- **`list` / Linux** — configured access as written, not sshd's effective policy (Match is not evaluated); key comments, option values and key-file paths are never emitted; a home the agent cannot open is refused, not empty (constrained is the common unprivileged outcome); a symlinked key file or .ssh is refused; network mounts are skipped
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | n/a — the leg reads nothing (caveat 5) | n/a | n/a | n/a — the placeholder reports `unsupported` with `windows:planned` |
| macOS | agent daemon (root LaunchDaemon) | None for `launchctl print-disabled system`, which answers an unprivileged caller. Reading another user's `~/.ssh` needs the access the agent identity already has as root; an identity that cannot open a home reports it refused | `launchctl print-disabled system` and `/etc/ssh` reads verified as a normal user on macOS 26.6.2; see Sample output | `PERMISSION_DENIED` / partial with `macos:remote_access_audit:<source>:permission_denied` when a source was refused and none was read, `CONSTRAINED` when another source was read; the `file` row says `refused` |
| Linux | agent daemon, dedicated unprivileged account (`yuzu`), never root by design (`docs/agent-privilege-model.md`) | None for `sshd_config` and `systemctl is-enabled` (world-readable and unprivileged). **Other users' homes are usually 0700 or 0750, so an unprivileged agent cannot open them: `CONSTRAINED` with `linux:remote_access_audit:homes:permission_denied` and one `refused` file row per account is the common outcome, never "no keys".** The real options are `CAP_DAC_READ_SEARCH` on the agent binary or accepting the refusal; do not loosen home modes | Not measured on the `yuzu` account; the capture runs as euid 0 in a container, see Sample output | `PERMISSION_DENIED` / partial with `linux:remote_access_audit:<source>:permission_denied` when a source was refused and none was read, `CONSTRAINED` when another source was read |

Subprocesses: Linux runs `systemctl is-enabled <unit>` once for each of `ssh.service`, `sshd.service` and `ssh.socket` (argv resolved from `/usr/bin/systemctl` or `/bin/systemctl`, no shell, 5 s deadline each, no sudo); macOS runs `/bin/launchctl print-disabled system` once (5 s deadline). Both go through the bounded runner and have sink-manifest rows (`docs/agent-spawn-sink-manifest.md`). Files are read in process. A symlink in the `/etc/ssh` config tree (`sshd_config`, the Include directory, an Include file) is followed as `sshd` follows it; on the key side (homes, `.ssh`, `authorized_keys*`) a symlink anywhere in the home's path, in `.ssh` or at the key file is never followed. No network use.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
The action takes no parameters.
<!-- END GENERATED -->

### Outputs

Every row is pipe-delimited; field 0 is the row kind, `-` is an absent value, and the first row is always `status|list|<supported\|constrained\|permission_denied\|unsupported>|<reason or ->`. The rest, in this order: `source|<sshd_config\|homes\|service>|<read\|absent\|refused\|failed>|<count or ->` (files read including includes, accounts walked, units queried); `config|<key>|<value or ->|<sshd_config\|include:<file> or ->` for each of `permitrootlogin`, `passwordauthentication`, `pubkeyauthentication`, `kbdinteractiveauthentication` (the deprecated `ChallengeResponseAuthentication` shares its slot), `permitemptypasswords`, `usepam`, `port` (comma-joined across occurrences), `authorizedkeysfile` (`default\|none\|custom:<n>`), `allowusers_count`, `allowgroups_count`, `denyusers_count`, `denygroups_count` and `match_blocks` (always all thirteen; `-` when `sshd_config` was not read, and an unset setting is `-` because defaults are not applied); `service|<unit>|<state>|<mechanism>` (the `systemctl is-enabled` words `enabled`, `enabled-runtime`, `linked`, `linked-runtime`, `alias`, `masked`, `masked-runtime`, `static`, `indirect`, `disabled`, `generated`, `transient`, `bad`, `not-found`, or `unknown`; on macOS `com.openssh.sshd` is `enabled`, `disabled` or `unknown`, and `enabled` is a launchd override, not "running"); `file|<account>|<authorized_keys\|authorized_keys2\|custom>|<read\|absent\|refused\|failed>|<keys>|<malformed>|<oversized>`; and `key|<account>|<kind>|<type>|<fingerprint>|<bits or ->|<flags or ->|<option names or ->`. The account is the home directory's name, not necessarily the login name. A `key` row flagged `unknown_type` records a line present in the file, not a key sshd is known to accept: OpenSSH 10 refuses an unknown type at parse time; whether this host's sshd knows the type is not checked. Every free field is scrubbed of NUL and invalid UTF-8, pipe-escaped and cut at 4096 bytes.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.security.remote_access_audit` — `row_kind|field_1|field_2|field_3|field_4|field_5|field_6|field_7`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `source` `config` `service` `file` `key` | Windows, Linux, macOS | `key` | Row shape discriminator (field 0). Values: status, source, config, service, file, key. |
| `field_1` | string | - | Windows, Linux, macOS | `alice` | status: the literal "list". source: sshd_config, homes or service. config: the setting (permitrootlogin, passwordauthentication, pubkeyauthentication, kbdinteractiveauthentication, permitemptypasswords, usepam, port, authorizedkeysfile, allowusers_count, allowgroups_count, denyusers_count, denygroups_count, match_blocks). service: the unit (ssh.service, sshd.service, ssh.socket, or com.openssh.sshd on macOS). file and key: the account, which is the HOME DIRECTORY NAME, not necessarily the login name. |
| `field_2` | string | - | Windows, Linux, macOS | `supported` | status: supported, constrained, permission_denied or unsupported (the planned Windows leg, and a leg that threw). source: read, absent, refused or failed (absent is a state, not a failure). config: the value as written in the first occurrence, "-" when unset or sshd_config was not read; authorizedkeysfile reports only default, none or custom:<n>, never a path; the counts are numbers. service: the state - systemctl is-enabled output (enabled, enabled-runtime, linked, linked-runtime, alias, masked, masked-runtime, static, indirect, disabled, generated, transient, bad, not-found) or enabled/disabled for launchd, or unknown (never read as disabled). file: authorized_keys, authorized_keys2 or custom. key: the same kind. |
| `field_3` | string | - | Windows, Linux, macOS | `SHA256:BPH4QduMtDlX59CWZCda5Zf0U0jseMmFVimvek7EMhA` | status: reason token(s) for a non-supported read, "-" when complete; tokens look like linux:remote_access_audit:homes:permission_denied or windows:planned. source: files read (sshd_config plus includes), accounts walked, or units queried, "-" unless read. config: where the value came from (sshd_config or include:<file name>), "-" when unset. service: the mechanism. file: read, absent, refused or failed. key: the key type as written (ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, a -cert-v01 certificate type, ...). |
| `field_4` | string | - | Linux, macOS | `2` | file: the number of key lines accepted, "-" unless read. key: the fingerprint, SHA256: plus unpadded base64, identical to ssh-keygen -lf (a certificate reports the key it carries). |
| `field_5` | string | - | Linux, macOS | `256` | file: the number of lines sshd would not accept (unparseable key, unknown option, truncated or trailing-byte blob, RSA under 1024 bits), "-" unless read. key: the key size in bits (RSA modulus, 256 for ed25519, the curve size for ECDSA), "-" for a key of an unknown type. |
| `field_6` | string | - | Linux, macOS | `has_command,has_from` | file: the number of lines over 16 KiB that were not parsed, "-" unless read. key: comma-separated flags from cert_authority, certificate, has_command, has_from, has_principals, unknown_type, or "-". A row flagged unknown_type records a line present in the file, not a key sshd is known to accept: OpenSSH 10 refuses an unknown type at parse time; whether this host's sshd knows the type is not checked. |
| `field_7` | string | - | Linux, macOS | `no-pty,command,from` | key: the lowercased option NAMES the line carries (restrict, cert-authority, [no-]port-forwarding, [no-]agent-forwarding, [no-]x11-forwarding, [no-]touch-required, [no-]verify-required, [no-]pty, [no-]user-rc, command, principals, from, expiry-time, environment, permitopen, permitlisten, tunnel), or "-". Option VALUES are never emitted. Not used by the other kinds. |
<!-- END GENERATED -->

### Result status

`list` sets `OK`/`FULL` when every source that exists was read in full, including a host with no `sshd_config` or no keys. A source that could not be read for a reason other than being absent makes the result `CONSTRAINED`/`PARTIAL` (or `PERMISSION_DENIED`/`PARTIAL` when a source was refused and none was read), with the same tokens in the leading `status` row. No exception crosses the plugin boundary: a leg that throws is reported as an `unsupported` status row and `UNAVAILABLE` (the last status row wins if the leg had already written one).

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | (empty) | every source that exists was read in full; no keys is `supported` with `file` rows saying `absent` or `read\|0` |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:sshd_config:<cause>`, `<os>:remote_access_audit:include:<cause>`, `<os>:remote_access_audit:keys:<cause>`, with `<cause>` one of `symlink_refused`, `not_regular`, `oversized`, `invalid_bytes`, or an errno token (`eio`, `eloop`, `enotdir`, `enametoolong`, `errno_<n>`) | a file could not be read: a symlinked key-side file, `.ssh` or home (refused, never followed), a config link that dangles (`include:enoent`, as `sshd` refuses to start) or loops (`include:eloop`), a FIFO or other non-regular target, a file over 256 KiB (config) or 1 MiB (keys), a NUL byte in `sshd_config` or an `Include` file (in `authorized_keys` a NUL cuts that line only, see the keys row below), an I/O error; its source or `file` row says `failed` and the other sources are still reported |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:sshd_config:invalid_quotes` | a configuration line has an unterminated quote and was skipped, as `sshd` would refuse it |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:include:depth_cap`, `<os>:remote_access_audit:include:too_many`, `<os>:remote_access_audit:include:in_match`, `<os>:remote_access_audit:include:pattern_unsupported` | an `Include` was not followed: nested deeper than 4 levels, more than 32 files in all, inside a `Match` block (whose condition is not evaluated), or a `~` path or wildcard in a directory component |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:keys:path_token_unsupported`, `<os>:remote_access_audit:keys:match_scoped_authorizedkeysfile` | an `AuthorizedKeysFile` entry uses `%u`, `%U`, another token or `~` and was skipped (never guessed), or `AuthorizedKeysFile` also appears inside a `Match` block (the global value is used) |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:keys:malformed`, `<os>:remote_access_audit:keys:oversized_line`, `<os>:remote_access_audit:keys:unknown_key_type`, `<os>:remote_access_audit:keys:invalid_bytes` | an `authorized_keys` line `sshd` would not accept (unparseable key, unknown option, a second `command`/`from`/`principals`, truncated or trailing-byte blob, RSA under 1024 bits) or a line over 16 KiB was counted and not emitted; or a key of a type this plugin does not know was inventoried over its raw blob; or a line held a NUL byte and was read only up to it, as `sshd` reads it (the file row stays `read` and the key before the NUL is reported) |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:keys:network_mount_skipped`, `<os>:remote_access_audit:keys:mounts_unreadable`, `<os>:remote_access_audit:homes:too_many`, `<os>:remote_access_audit:keys:file_cap`, `<os>:remote_access_audit:keys:row_cap`, `<os>:remote_access_audit:keys:field_oversized` | a home root, home or key path on a network filesystem named by the run-start mount table was never opened; or the mount table could not be read (the walk proceeds unguarded); or more than 512 accounts, 1024 key-file reads or 2048 rows / 1 MiB were reached (the listing stops there); or a field was cut at 4096 bytes |
| `CONSTRAINED` | partial | `<os>:remote_access_audit:service:systemctl_unavailable`, `<os>:remote_access_audit:service:launchctl_unavailable`, `<os>:remote_access_audit:service:output_truncated`, `<os>:remote_access_audit:service:no_output`, `<os>:remote_access_audit:service:unrecognised_output`, `<os>:remote_access_audit:service:exit_nonzero`, `subprocess_runner:deadline`, `subprocess_runner:cancelled`, `subprocess_runner:signaled`, `subprocess_runner:line_limit` | the service query failed: the tool is not installed (a non-systemd host, which is a failed service source and never "disabled"), timed out, was cut short, printed nothing or something unrecognised; the `service` source row says `failed` |
| `PERMISSION_DENIED` | partial | `<os>:remote_access_audit:sshd_config:permission_denied`, `<os>:remote_access_audit:homes:permission_denied`, `<os>:remote_access_audit:keys:permission_denied`, `<os>:remote_access_audit:include:permission_denied` | a source was refused and no source was read; accumulated constrained tokens may follow, comma-joined |
| `UNAVAILABLE` | unknown | `subprocess_runner:spawn_error` | the bounded runner could not start the tool (reported through the service query, which then constrains the listing) |
| `UNAVAILABLE` | unknown | `windows:planned` | Windows: one `status\|list\|unsupported\|windows:planned` row (caveat 5) |
| `UNAVAILABLE` | unknown | `windows:leg:exception` / `linux:leg:exception` / `macos:leg:exception` | a leg threw: an `unsupported` status row, reported instead of unwinding across the plugin boundary |

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. `list` is also a gathered definition (`crossplatform.security.remote_access_audit`, 3600s TTL).
- **Not consumed by** daily-sync, TAR, DEX, or metrics.
- **Default off, and how to turn it on.** The plugin is Forensics-class and ships off: the server seeds a default-off kill switch at boot, so nothing dispatches until an operator runs `PUT /api/v1/plugin-config/remote_access_audit/kill-switch {"enabled":true}`. After that, dispatch is gated at `Forensics:Read` with `AdminOrApproval` (Administrator by default) and is single-target: exactly one device per request.
- **Sensitivity.** Per-account key fingerprints on one named machine are identity material: they say which keys can log in as which account, and the account is the home directory's name. Key comments, option values, principals lists and key-file paths are never emitted. The stored result is readable by `Response:Read` holders, as for every plugin (known gap #4990), and the Instructions UAT runner cannot exercise Forensics-tier dispatch (known gap #5261); neither is fixed here.
- **Siblings:** `privacy_permissions`, `browser_inventory` and `execution_artifacts` (the other Forensics-class plugins) and `mgmt_posture` (which plane controls the device).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-10-17 · euid 501 (account redacted to jsmith) · leg-hash af04792464e9

```
== action=list
status|list|constrained|macos:remote_access_audit:homes:permission_denied
source|sshd_config|read|3
source|homes|read|2
source|service|read|1
config|permitrootlogin|-|-
config|passwordauthentication|-|-
config|pubkeyauthentication|-|-
config|kbdinteractiveauthentication|-|-
config|permitemptypasswords|-|-
config|usepam|yes|include:100-macos.conf
config|port|-|-
config|authorizedkeysfile|custom:1|sshd_config
… 12 of 21 rows shown
[result_status] CONSTRAINED / PARTIAL / macos:remote_access_audit:homes:permission_denied
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-10-17 · euid 0 · leg-hash af04792464e9

```
== action=list
status|list|constrained|linux:remote_access_audit:keys:malformed,linux:remote_access_audit:keys:oversized_line,linux:remote_access_audit:keys:symlink_refused
source|sshd_config|read|3
source|homes|read|4
source|service|read|3
config|permitrootlogin|prohibit-password|include:10-test.conf
config|passwordauthentication|no|include:10-test.conf
config|pubkeyauthentication|-|-
config|kbdinteractiveauthentication|no|sshd_config
config|permitemptypasswords|-|-
config|usepam|yes|sshd_config
config|port|-|-
config|authorizedkeysfile|custom:3|sshd_config
… 12 of 47 rows shown
[result_status] CONSTRAINED / PARTIAL / linux:remote_access_audit:keys:malformed,linux:remote_access_audit:keys:oversized_line,linux:remote_access_audit:keys:symlink_refused
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Configured, not effective.** Rows report what the files say, not what `sshd` enforces: a `Match` block is counted and not evaluated, defaults are not applied (an unset setting is `-`), and an `Include` wildcard is expanded in byte order where `sshd` uses `glob(3)`'s locale order (it only matters when two included files set the same setting). Symlinks follow a two-tier rule. Under `/etc/ssh` (writable by root only: `sshd_config`, the Include directory, each Include file) a link is followed as `sshd` follows it, so stock macOS (`crypto.conf` links to `crypto/apple.conf`) and NixOS read as `SUPPORTED`; a link target outside `/etc/ssh` is read, with no owner or mode check on the target (`sshd` applies none to its config), and a non-regular target is still refused. A home parent (`/home`, `/Users`) is root-owned like `/etc/ssh`, so one link hop is allowed (Fedora Atomic ships `/home -> var/home`): the link is resolved by `readlink`, its target is checked against the mount table before anything is opened, and the target is then opened component by component with no further link followed (a link chain or a linked component is refused as `homes:eloop`); only the entries beneath it are the account's to write. Where the audited account can write (a home, `.ssh`, `authorized_keys*`, an absolute `AuthorizedKeysFile` path) a link is never followed, because a root agent would read what the account cannot: that file reports `failed` with a `symlink_refused`/`enotdir` token and the listing is `CONSTRAINED`. An absolute `AuthorizedKeysFile` path is opened from `/` one component at a time, so a link anywhere in its directory chain (stock macOS `/etc`, `/var` and `/tmp` are links to `/private/*`) is reported `failed` with `symlink_refused`, with no allow-list of platform aliases. A home is opened the same way, from `/` one component at a time, so a link in the home's own path is refused as `homes:eloop` and no `realpath` ever touches a dead mount; the macOS root home is therefore configured as `/private/var/root`, the canonical spelling of `/var/root`.
2. **A syntactic inventory, not `sshd`'s validity check.** A key row means the line parses by `sshd`'s grammar and its blob decodes completely. Option **values** are not validated (a nonsense `expiry-time` or `environment` still counts), an ECDSA point is checked for its length and `0x04` prefix but not for lying on the curve, a certificate's signature is not verified (its structure is), and a key of a type this plugin does not know (`ssh-dss`, a newer algorithm) is inventoried over its raw blob with the `unknown_type` flag and no size; a row flagged `unknown_type` records a line present in the file, not a key sshd is known to accept: OpenSSH 10 refuses an unknown type at parse time; whether this host's sshd knows the type is not checked. A tampered certificate or off-curve point that `sshd` would reject can therefore appear here. A certificate row reports the fingerprint of the embedded key, so a fingerprint is not an identifier of the certificate itself.
3. **Identity is the home directory's name.** `account` is the basename of the home directory the plugin walked (`/home/<name>`, `/root`, `/Users/<name>`, `/private/var/root`; macOS entries owned by a uid under 500 are skipped), not the login name, and accounts whose home is elsewhere (a directory-service or relocated home) are not walked. An `AuthorizedKeysFile` entry with `%u`, `%U` or another token needs the login name and is reported as unsupported rather than guessed. An account whose home the agent cannot open is `refused`, so a Linux listing from the unprivileged agent is usually `CONSTRAINED` (see Privileges).
4. **Blocking I/O on mounts is guarded by name.** Homes and key paths under a network filesystem named by the mount table (`yuzu::shared::is_network_fstype`, plus `webdav`/`afpfs`/`macfuse`/`osxfuse` on macOS; a home parent that is a link is checked at its target as well) are never opened, because an open on a dead hard mount pins a worker with no deadline. The list is by filesystem name, so a stacked filesystem or a bare `fuse` mount over a dead server still blocks (#4875), and a late mount after the run-start snapshot is not seen.
5. **Windows is planned, not read.** The Windows leg (per-profile `.ssh\authorized_keys`, `%ProgramData%\ssh\administrators_authorized_keys` and `sshd_config` via the profile walk, with the OpenSSH Server service state) reports one `unsupported` row, `windows:planned`; the Windows leg follows as its own PR. The effective policy (`sshd -T`, which evaluates `Match` and applies defaults) is not run on any OS; this plugin reports configured access only.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/remote_access_audit/src/remote_access_audit_config_parsers.hpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_keys_parsers.hpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_legs.hpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_linux.cpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_macos.cpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_plugin.cpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_posix_fs.hpp` · `agents/plugins/remote_access_audit/src/remote_access_audit_win.cpp`
- Definitions: `content/definitions/remote_access_audit.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_remote_access_audit.hpp`
- Tests: `tests/test_remote_access_audit_definition.py` · `tests/unit/test_remote_access_audit_config_parsers.cpp` · `tests/unit/test_remote_access_audit_keys_parsers.cpp` · `tests/unit/test_remote_access_audit_legs.cpp` · `tests/unit/test_remote_access_audit_local_dispatcher.cpp` · `tests/unit/test_remote_access_audit_posix_fs.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2026-10-17-remote_access_audit.added.md`
<!-- END GENERATED -->
