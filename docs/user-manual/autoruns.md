# Autoruns

The `autoruns` plugin enumerates **persistence sources** -- everything an
endpoint's OS will start automatically -- across Windows, Linux and macOS.
It is read-only: no action mutates host state, spawns a mutating process, or
writes to the registry/filesystem/launchd.

## Actions

| Action | What it does | OS call |
|---|---|---|
| `catalog` | Lists every `SourceId` this build knows about, with the support level THIS build declares for it (`kSourceCatalog`, versioned by `kAutorunSourceCatalogVersion`). | None -- a pure reflection of static data. |
| `list` | Runs every per-OS leg and emits a `source|` status line per catalog source, plus zero or more `autorun|` rows for sources that produced data. `sources=` filters to a comma-separated `SourceId` allow-list. | Yes -- see the per-source table below. |

Both actions run unconditionally on every build: the two legs that are not
the build's own OS resolve to `autoruns_legs.hpp`'s foreign-OS stub
(`unsupported|0|foreign_os`), so a `list` capture always names every source
in the catalog on every OS, and the capability matrix generator always sees
a complete three-OS shape.

## Row format

Two row shapes share one stream, discriminated by field 0:

```
source|<id>|<support>|<row_count>|<reason>
autorun|<source_id>|<catalog_version>|<location>|<entry>|<target>|<args>|<enabled>|<scope>|<user>|<signed>|<mtime>
```

A literal `|` inside any text field is folded to U+2502 (`│`), never
backslash-escaped, so every row has a fixed field count under a plain
`split('|')`. `catalog_version` lets a consumer that stored an `autorun|` row
tell "this row predates a `SourceId` rename/add/remove" from "this is simply
new data" -- always cross-check it against the catalog version `catalog`
reports before comparing row shapes across a fleet's mixed agent versions.

### `source|` status semantics -- "nothing there" vs "could not read"

The fifth field (`reason`; the fourth payload field after the `source`
discriminator) always distinguishes a source that was read and had nothing
versus one that could not be read at all:

- **`supported|0|absent`** -- the mechanism ran and genuinely found nothing
  (e.g. an XDG autostart dir that doesn't exist, `/etc/rc.local` absent).
  This is a complete, honest read, not a failure.
- **`constrained|0|absent`** -- the same ENOENT, but for a source the
  catalog treats as required (`/etc/crontab`, `/etc/anacrontab` on Linux):
  its absence is itself unusual enough to flag, not silently folded into
  "supported, nothing there".
- **`constrained|<n>|permission_denied`** / any other errno token -- a real
  read failure. Never conflated with `absent`: a caller that only checks
  `row_count == 0` cannot distinguish "empty" from "denied" without reading
  `reason`.
- **`constrained|<n>|<token>`** (Windows, non-errno) -- specific failure
  causes on this platform, each its own token rather than folded into a
  generic one, spanning COM, WMI, the registry, and plain file listing
  depending on the source. NOT a closed set: any other COM `HRESULT`
  Scheduled Tasks/WMI code paths can return falls through to `hr_token()`'s
  open-ended `hr_0x<hex>` token instead of one of the named ones below.
  Named tokens: `hr_cominit_failed` (Scheduled
  Tasks' `CoInitializeEx` itself failed before `ITaskService` could even
  start), `unresolved_ref` (WMI subscription enumeration returned a
  reference this leg could not resolve), `enumeration_incomplete` (a
  registry key's value enumeration, `RegEnumValueW`, stopped partway
  through), `enumeration_error` (the Startup-folder's `FindNextFileW`
  directory listing faulted partway through -- both `enumeration_*` tokens
  share the same "partial != complete" principle as the directory-walk
  caps below, just for different underlying mechanisms), `reg_open_failed`
  (a registry key open failed for a reason other than simple absence),
  `oversized`/`changed_during_read` (a registry VALUE read hit its size
  cap or the value mutated mid-read). `null_task`/`null_subfolder`/
  `unmodelled_action_type` are Scheduled Tasks-specific: a COM call
  returned a null interface pointer where a real one was expected, or a
  task action type this leg's schema doesn't decode -- reported as a
  constraint on that one task, never silently dropped or misread as "no
  actions." `win_startup_folder_user`-specific (#4219, `resolve_profile_
  shell_folder`): `startup_redirect_unresolved` (a `%TOKEN%` in the
  redirect value isn't a recognized user- or machine-scoped name, or an
  allowlisted machine token's lookup itself came back empty -- never a
  guessed path), `startup_redirect_bad_type` (the value's registry type is
  neither `REG_SZ` nor `REG_EXPAND_SZ`), `startup_redirect_key_unreadable`
  (the `User Shell Folders` key itself failed to open for a reason other
  than simple absence). A hive that can't be reached at all for a profile
  whose Startup redirect resolution was in play reports the SAME
  `<sid>:<reason>` shape the other three per-profile hive sources use (see
  the next bullet) -- the non-redirected fallback path is an unverifiable
  guess for a genuinely redirected profile once the hive itself can't be
  opened to check.
- **`unsupported|0|foreign_os`** -- this source belongs to an OS this build
  isn't running on (autoruns_legs.hpp's stub).
- **`constrained|0|btm_private_database_no_public_api`** (`mac_login_items`)
  -- the mechanism exists but this leg deliberately does not exercise it: no
  public read API for the private BTM database.
- **`constrained|<n>|<sid>:<reason>`** (`win_*_hku` sources, per profile,
  plus `win_startup_folder_user` when its redirect resolution was in play
  for that profile -- #4219) -- the hive couldn't be reached for that SID,
  with the specific constraint named rather than folded into one bucket:
  `not_found` (no such profile hive), `privilege_missing`
  (`SeBackupPrivilege`/`SeRestorePrivilege` couldn't be enabled on the
  process token), or `mount_failed` (`RegLoadKeyW` itself failed for the
  offline arm). A separate `warning|hive_unload_failed|...` line is
  emitted if the trailing `RegUnLoadKeyW` fails on the way out -- this is
  orthogonal to the per-source `source|` line and never folded into it.
- **`constrained|<n>|malformed`** (launchd plist walk, `mac_emond`,
  `lnx_etc_crontab`, `lnx_cron_d`, `lnx_user_crontabs`, `lnx_anacrontab`,
  `lnx_xdg_autostart_system`, `lnx_xdg_autostart_user`, `win_scheduled_tasks`,
  and any Windows registry-value source -- `win_run_hklm`/`_hkcu`,
  `win_runonce*`, `win_startup_approved`, `win_winlogon_shell`/`_userinit`,
  `win_appinit_dlls` -- when a value's data fails `ReadValueStatus` decoding)
  -- a file or registry value was read but could not be fully parsed. On
  macOS a plist could not be parsed (corrupt, or a valid plist truncated by
  `kMaxPlistBytes`). On the crontab-family sources, a crontab/anacrontab
  file had at least one rejected line (`parse_crontab`/`parse_anacrontab`'s
  `rejected_lines > 0`) while every other valid entry in that file is still
  kept, never dropping the whole file. On the XDG autostart sources (system
  and per-user), a `.desktop` file with no `[Desktop Entry]` group or an
  empty/absent `Exec` key (`parse_desktop_entry`'s `malformed` field) is
  skipped rather than reported as a real, runnable autostart entry with an
  empty target. On `win_scheduled_tasks`, a task's XML was read
  successfully but `parse_task_xml` could not make sense of it
  (truncated/corrupt XML, a rejected DTD, an unexpected root) -- distinct
  from `get_Xml()` itself failing, which carries its own, more specific
  token. On the Windows registry-value sources, a value existed with a
  declared numeric type but a size too small to hold it (`win_profiles.hpp`'s
  `ReadValueStatus::malformed`) -- distinct from the key/value simply not
  existing. Never silently folded into a `supported` status. `mac_emond`
  combines this with any directory-level constraint via a comma-joined
  reason. On `win_scheduled_tasks`, a task's XML over `parse_task_xml`'s
  1 MiB cap reports the distinct `oversized` token instead -- a different
  failure shape (a runaway/corrupt `get_Xml()` BSTR) than an ordinary
  syntax problem (#4184); a `<Task>` root outside the Task Scheduler
  namespace, or a document nested deeper than libxml2's own ~256-level
  parse ceiling, both still report plain `malformed`.
- **`constrained|<n>|narrow_search_path_coverage`** (`lnx_systemd_timers_user`
  only) -- a permanent, catalog-declared exception (`autoruns_catalog.hpp`'s
  third documented exception, alongside `mac_login_items`/`lnx_init_d`):
  the scanned `systemd --user` search-path set omits several standard roots
  (`~/.local/share/systemd/user`, `/run/systemd/user`,
  `/usr/local/{lib,share}/systemd/user`, `/usr/share/systemd/user`). Every
  reportable result for this one source carries this token, comma-joined
  with any other reason on the same line -- it never reports `supported`.
- **A real directory-enumeration I/O error, told apart from a clean
  end-of-directory** -- every directory-walking source (Linux and macOS
  alike) distinguishes this from "nothing more to read". Linux sources
  (built on the shared `list_dir` helper) still fold it into the SAME
  `row_cap` reason a capped listing already uses -- both mean "this listing
  is incomplete", and threading a separate token through every one of that
  helper's many call sites wasn't worth the churn. Every macOS
  directory-walking source instead surfaces a distinct
  **`constrained|<n>|readdir_error`** reason: `mac_system_launchdaemons`,
  `mac_system_launchagents`, `mac_launchdaemons`, `mac_launchagents`, and
  `mac_emond` (all built on the shared `walk_plist_dir`/`walk_plist_dir_handle`
  helpers), `mac_periodic`'s own directory walk, and `mac_user_launchagents`'s
  own two nested walks -- the outer `/Users` enumeration and each user's
  inner `LaunchAgents` walk, which as of #4186 are also disambiguated by
  suffix so an operator can tell which one actually hit its cap/error
  rather than both collapsing to the same ambiguous token once deduped:
  `row_cap:users`/`readdir_error:users` (the outer walk) vs.
  `row_cap:launchagents`/`readdir_error:launchagents` (a specific user's
  inner walk); a source hit by only one of the two walks still uses the
  plain, unsuffixed `row_cap`. Either way, a partial listing is never
  reported as a complete `supported` result.
- **A real per-entry metadata-read (`fstat`/`fstatat`) failure, distinct
  from the entry simply having vanished between listing and reading**
  (macOS `mac_periodic`'s directory walk and `mac_user_launchagents`'s
  per-home check, #4241) -- previously silently skipped the entry with no
  constraint at all, inconsistent with the adjacent `open()` failure
  handling in the same functions, which already constrained correctly.
  Now classified the same way: `permission_denied`, `symlink_refused`, or
  the generic `stat_failed` for any other errno; a benign `ENOENT` race
  (the entry vanished between `readdir()` and the stat call) is still not
  a constraint.

### Typed result status (CC-07)

Every `source|` line above is text output -- a consumer must parse each one
to notice a degradation. `list` also sets the plugin's typed ABI4 CC-07
result status (`YuzuResultStatus`/`YuzuResultCompleteness`) so a fleet-scale
consumer that only reads that typed field, never the text stream, still
learns of a real acquisition failure:

- **`UNDECLARED`** -- every source this run processed reported `supported`
  (or `unsupported`, the normal outcome for a foreign-OS stub leg) with no
  `constrained` status anywhere in the run.
- **`CONSTRAINED` / `PARTIAL` / `autoruns:degraded`** -- at least one source
  reported `constrained` (any reason). The `list` command itself still
  completed normally: this run is still `rc=0`, matching `catalog`'s own
  always-`rc=0` contract -- `rc` answers "did the command abort", not "did
  every source read cleanly". On Linux, `lnx_init_d` and
  `lnx_systemd_timers_user` are catalog-declared permanently `constrained`
  (see above), so every Linux `list` run always reports `CONSTRAINED` here
  regardless of any `sources=` filter -- both sources' filtered-out branches
  still emit their own catalog-declared `CONSTRAINED` status (reason
  `filtered`), which counts toward this aggregate the same as an unfiltered
  read would, so excluding them from `sources=` never produces a clean
  result. macOS is the same via `mac_login_items`, which isn't even
  filter-gated at all -- it always emits its one constrained status line
  (there is no real read to skip; see below). Windows has no
  *catalog-declared permanent* constraint the way Linux/macOS do, so
  whether a given run degrades depends entirely on live host state --
  `win_startup_folder_user`'s redirect-resolution logic is fixed (#4219;
  see its catalog row below), so a real LocalSystem-run agent now reads it
  SUPPORTED on a host with no genuine resolution failure.
- **`UNAVAILABLE` / `PARTIAL` / `autoruns:exception`** -- an exception
  escaped a leg (`execute()`'s catch clauses); the command itself aborted,
  `rc=1`.

Because this field is effectively constant on Linux and macOS (always
`CONSTRAINED`/`PARTIAL`), it cannot by itself signal a *new* degradation on
those platforms -- a fleet-scale consumer still needs to read the per-source
`source|` text lines to detect a genuinely new failure there. Windows's
field is *structurally* capable of varying with live host state, and in
practice does -- a real host reads SUPPORTED unless a specific source hits a
genuine acquisition failure.

## Versioned source catalog

Support: **S**upported (rung 1, direct read), **C**onstrained (reads, but
with a documented gap), **U**nsupported (foreign OS). Every source carries
all three OS columns even when native to one OS, so `catalog`/foreign-OS
stubs never special-case per-OS.

| SourceId | Name | W | L | M | Why |
|---|---|---|---|---|---|
| `win_run_hklm` | HKLM Run | S | U | U | Reg\*W, native + WOW6432Node views |
| `win_runonce_hklm` | HKLM RunOnce | S | U | U | Reg\*W, native + WOW6432Node views |
| `win_runonceex_hklm` | HKLM RunOnceEx | S | U | U | Reg\*W, native + WOW6432Node views |
| `win_run_hku` | HKU Run (every loaded/mountable hive) | S | U | U | per-profile `with_user_hive` ladder |
| `win_runonce_hku` | HKU RunOnce (every loaded/mountable hive) | S | U | U | per-profile `with_user_hive` ladder |
| `win_startup_approved` | Explorer StartupApproved\Run | S | U | U | Reg\*W, system + per-user |
| `win_winlogon_shell` | Winlogon Shell | S | U | U | Reg\*W |
| `win_winlogon_userinit` | Winlogon Userinit | S | U | U | Reg\*W |
| `win_appinit_dlls` | AppInit_DLLs | S | U | U | Reg\*W |
| `win_ifeo_debugger` | Image File Execution Options Debugger | S | U | U | Reg\*W |
| `win_startup_folder_common` | Startup folder (All Users) | S | U | U | file listing |
| `win_startup_folder_user` | Startup folder (current user) | S | U | U | file listing, per profile -- reads the profile's own `User Shell Folders\Startup` registry value (from the same per-user hive the HKU sources already open) when present, falling back to the literal `AppData\Roaming\...\Startup` suffix when absent/unreadable (e.g. a logged-out profile whose offline mount fails). `%USERPROFILE%`/`%AppData%`/`%LocalAppData%`/`%Username%` tokens in that value resolve against the ENUMERATED PROFILE's own path/name (`resolve_profile_shell_folder`, `autoruns_parsers.hpp`), never the agent's own LocalSystem environment (#4219). A small allowlist of genuinely machine-scoped tokens (`SystemDrive`, `SystemRoot`, `windir`, `ProgramData`, `ALLUSERSPROFILE`, `PUBLIC`, `ProgramFiles`, `ProgramFiles(x86)`) resolves via the agent's own environment, since those are identical for every user. Any other token, or an allowlisted one that can't be resolved, reports `constrained`/`startup_redirect_unresolved` rather than guessing. |
| `win_scheduled_tasks` | Scheduled Tasks | S | U | U | ITaskService COM |
| `win_wmi_subscriptions` | WMI permanent event subscriptions | S | U | U | bounded `root\subscription` query |
| `lnx_etc_crontab` | `/etc/crontab` | U | S | U | file read; absent is CONSTRAINED (required) |
| `lnx_cron_d` | `/etc/cron.d/*` | U | S | U | dir listing + file reads |
| `lnx_cron_periodic` | `/etc/cron.{hourly,daily,weekly,monthly}` | U | S | U | dir listing |
| `lnx_user_crontabs` | per-user crontabs | U | S | U | `/var/spool/cron{,/crontabs}` reads |
| `lnx_anacrontab` | `/etc/anacrontab` | U | S | U | file read; absent is CONSTRAINED (required) |
| `lnx_at_spool` | `/var/spool/at` (`at(1)` jobs) | U | S | U | dir listing |
| `lnx_systemd_timers_system` | systemd system timer units | U | S | U | tri-state; see below |
| `lnx_systemd_timers_user` | systemd user timer units | U | **C** | U | tri-state; see below -- always Constrained when reportable (`narrow_search_path_coverage`): the scanned search-path set omits several standard `systemd --user` unit roots |
| `lnx_xdg_autostart_system` | XDG autostart (`/etc/xdg/autostart`) | U | S | U | dir listing |
| `lnx_xdg_autostart_user` | XDG autostart (`~/.config/autostart`) | U | S | U | dir listing, per user |
| `lnx_rc_local` | `/etc/rc.local` | U | S | U | file read |
| `lnx_init_d` | `/etc/init.d/*` (SysV, listing only) | U | **C** | U | script names only -- no runlevel/`systemctl` wiring cross-check |
| `mac_launchdaemons` | `/Library/LaunchDaemons` | U | U | S | plist walk |
| `mac_launchagents` | `/Library/LaunchAgents` | U | U | S | plist walk |
| `mac_system_launchdaemons` | `/System/Library/LaunchDaemons` | U | U | S | plist walk |
| `mac_system_launchagents` | `/System/Library/LaunchAgents` | U | U | S | plist walk |
| `mac_user_launchagents` | `~/Library/LaunchAgents` | U | U | S | plist walk, per real home |
| `mac_login_items` | Login Items | U | U | **C** | private BTM database, no public read API |
| `mac_periodic` | `/etc/periodic` | U | U | S | dir listing (no content read) |
| `mac_emond` | `/etc/emond.d/rules` | U | U | S | plist walk |

## Real `source|` captures

Pasted verbatim from real runs, 2026-09-07 -- not constructed fixtures. The
macOS capture is against the actual built plugin (`autoruns.dylib` via
`LocalDispatcher`); the Linux capture is a standalone harness linking the
real `collect_linux` against the container's real filesystem, NOT the
shipped artifact dispatched end-to-end (this build's `.dylib` cannot run on
Linux -- see the container section below for the caveat). Windows values are
A1's the-rig probe results (quoted in the descriptor notes and
`docs/wave7/rig-checklist-autoruns-win.md`); no macOS-host or container-host
Windows run exists, and no real end-to-end Linux `list` dispatch (real
plugin, real dispatcher, real runner) has been performed yet -- tracked as a
gap in the checklist below.

**This Mac (macOS, `autoruns.dylib`, LocalDispatcher `list`):**

```
source|mac_launchdaemons|supported|2|launchd_plist_walk
source|mac_launchagents|supported|0|launchd_plist_walk
source|mac_system_launchdaemons|supported|422|launchd_plist_walk
source|mac_system_launchagents|supported|456|launchd_plist_walk
source|mac_user_launchagents|supported|1|launchd_plist_walk
source|mac_login_items|constrained|0|btm_private_database_no_public_api
source|mac_periodic|supported|0|periodic_dir_walk
source|mac_emond|supported|0|emond_rule_plist_walk
```

(every `win_*`/`lnx_*` source reads `unsupported|0|foreign_os` on this
build, as expected.)

**Real `ubuntu:24.04` Docker container (a standalone harness compiled against
the real `collect_linux`, run against the container's actual filesystem --
this build's plugin `.dylib` cannot run on Linux, so this is the leg's real
code against a real host, not the shipped artifact):**

```
source|lnx_etc_crontab|constrained|0|absent
source|lnx_cron_d|supported|2|-
source|lnx_cron_periodic|supported|2|-
source|lnx_user_crontabs|supported|0|absent
source|lnx_anacrontab|constrained|0|absent
source|lnx_at_spool|supported|0|absent
source|lnx_systemd_timers_system|unsupported|0|no_systemd
source|lnx_systemd_timers_user|unsupported|0|no_systemd
source|lnx_xdg_autostart_system|supported|0|absent
source|lnx_xdg_autostart_user|supported|0|-
source|lnx_rc_local|supported|0|absent
source|lnx_init_d|constrained|1|listing_only
```

This container has no init system, so it exercises the tri-state's `absent`
branch (`no_systemd`) for both systemd sources, not the rung-2
`systemctl list-timers` fallback -- that path needs a host with systemd
present but every one of its three unit dirs unreadable, which no available
host provided. It also confirms the `absent`-vs-required distinction:
`/etc/crontab` and `/etc/anacrontab` (required by the catalog) read
CONSTRAINED, while every other genuinely-empty source reads SUPPORTED.

## Windows: the per-profile HKU ladder

`win_run_hku`, `win_runonce_hku` and `win_startup_approved` each need to read
every reachable user's hive, not just HKLM. Per profile
(`win_profiles.hpp::with_user_hive`):

1. **Live hive first.** If the user is logged in, its hive is already
   mounted under `HKEY_USERS\<sid>` -- read it directly, no privilege
   elevation, no mount/unmount.
2. **Offline `RegLoadKeyW` fallback.** If not, the profile's
   `NTUSER.DAT` is mounted at a private mount point under
   `SeBackupPrivilege` + `SeRestorePrivilege`, enabled on the *process*
   token only for the duration of the offline arm, and serialised
   process-wide by `offline_hive_mutex()` so two offline reads never race
   the same mount point or contend the privilege-enable/mount/read/
   unmount/restore sequence against each other.
3. **`unload_failed` is surfaced, never dropped.** If the trailing
   `RegUnLoadKeyW` fails, a `warning|hive_unload_failed|...` line is
   emitted for that SID/mount name -- this is a real host-state leak (a
   stray mounted hive) an operator needs to know about, not swallowed
   into a generic "read OK" result.

A1's the-rig probe found `RegLoadAppKeyW` (a *different* API, used
elsewhere for Amcache) does not require `SeBackupPrivilege` at all; that
finding does not apply to this leg's `RegLoadKeyW`, which does.

## The one rung-2 fallback: `systemctl list-timers`

`lnx_systemd_timers_system`/`_user` are a **tri-state on
`/run/systemd/system`**, not a plain present/absent check:

- **absent** (`stat` returns `ENOENT`) -- reports `unsupported|0|no_systemd`.
  No systemd, nothing to enumerate.
- **undetermined** (`stat` fails some other way) -- reports
  `constrained|0|systemd_state_undetermined`. The host's systemd state
  itself couldn't be determined; this is not the same fact as "no systemd".
- **present** -- reads `/etc/systemd/system`, `/usr/lib/systemd/system` and
  `/lib/systemd/system` directly (rung 1). **Only when systemd is present
  but all three are unreadable** does the leg fall back to
  `systemctl list-timers --all --no-pager --no-legend` (rung 2,
  sink-manifest site `autoruns/collect_linux#1`) -- the single spawn in this
  entire leg. Rows from that fallback carry `enabled=unknown`: the text
  output carries no wants-symlink evidence, so enablement cannot be
  determined the same way the rung-1 directory read determines it.

  A rung-1-scanned timer row can ALSO carry `enabled=unknown`, even with a
  real wants-symlink read attempted: if a wants directory consulted for that
  timer hit a real I/O error partway through, or hit its entry cap, the
  matching symlink could be among what wasn't read -- reporting a confident
  `disabled` there would be the same false-negative "live persistence
  mechanism read as inert" defect this leg's directory-enumeration fixes
  exist to close. `unknown` here is a genuine "cannot tell", same meaning as
  the rung-2 case above, just a different cause.

  A timer row can also carry `enabled=unknown` for a third reason, with no
  failed read among the wants directories it actually checked at all: when
  `/home` itself couldn't be fully enumerated, the very SET of user wants
  directories to search is itself incomplete, not just an individual
  directory that was checked.

  A genuine wants-directory scan failure -- a non-`ENOENT` open failure, a
  real I/O error partway through the scan, or a capped scan with a real
  entry left unread -- also constrains the **source-level** status line for
  `lnx_systemd_timers_system` / `lnx_systemd_timers_user`, not just the
  affected row: it composes into the same `constrained` status (reason
  `wants_scan_incomplete`, alongside any other applicable reason such as
  `partial_permission_denied` or `row_cap`) that the source's own
  unit-listing-directory open failures already use, so an acquisition
  failure of this kind never reads as the plain, misleadingly-clean
  `supported|-` a cleanly-absent set of wants directories would produce.

## macOS: Login Items is constrained, `osascript` is rejected

`mac_login_items` always emits one constrained status line
(`constrained|0|btm_private_database_no_public_api`) and zero rows, never a
real read attempt. The list lives in a private per-user BTM (Background Task
Management) database with no public read API. The only route that exists at
all is `osascript` driving System Events -- a rung-3 governed-shell
acquisition under ADR-3002 Decision 5 -- and this leg does not perform it:
file truth only, zero process spawns anywhere in the macOS leg.

## `signed` column, macOS rows only

`apple_system` means the row's `location` falls under `/System/Library/` --
a **path judgement only**, matching a literal path prefix. It is **not** a
code-signature verification: this plugin never calls
`SecStaticCodeCheckValidity` or any other Security.framework API, so
`apple_system` means "Apple ships this location", not "this file's
signature was checked and is valid." Every other macOS row -- everything
under `/Library/`, a user's `~/Library/LaunchAgents`, `/etc/periodic`, and
`/etc/emond.d` -- is `not_checked`. Windows and Linux rows are always
`not_checked`; neither leg reads a signature. A future PR wiring a real
`SecStaticCodeCheckValidity` call adds new `signed` values -- it does not
repurpose `apple_system`/`not_checked` to mean something different than they
do today.

## Security, permissions, and approval

Both actions are classified `Security` / `ReadOnly` / `Mutability::None` /
`RiskTier::Low` / `ExecuteGate::None` (`plugin_action_catalogue_autoruns.hpp`)
-- no approval gate, matching the read-only fact-collection precedent
`vuln_scan.*` uses. `catalog` performs no OS call at all; `list` reads
registry values, files, and plist/task/WMI metadata -- nothing in either
action opens a write handle, spawns a mutating process, or changes any
persistence entry it reports on. This classification is pinned exactly by
`test_capability_catalogue.cpp`'s "autoruns.list and autoruns.catalog pin
their exact classification" case -- a drift from `Security` to a broader
securable, or from `ReadOnly`/`None`/`None`, fails that test.

## Real-hardware verification checklist

**Windows (the-rig, desktop-04dnsig)** -- full 10-step checklist lives in
`docs/wave7/rig-checklist-autoruns-win.md`; summarised here, numbered to
match that file:

1. Build the plugin under MSVC 2022 BuildTools and confirm it links against
   `advapi32`/`ole32`/`oleaut32`/`wbemuuid`/`taskschd` with no unresolved
   externals.
2. Run `catalog` via the local dispatcher test: one `source|` line per
   catalog entry, all Windows entries `windows: SUPPORTED`.
3. Run `list` unfiltered: all 14 `win_*` SourceIds each emit exactly one
   `source|` line, none `unsupported` (that value only comes from the
   foreign-OS stub on a non-Windows build).
4. HKLM Run/RunOnce/RunOnceEx: confirm both native-view and WOW6432Node row
   sets, cross-checked against a manual `reg query`.
5. Per-user Run/RunOnce/StartupApproved: confirm at least one logged-in
   profile reads via the live-hive path (no `warning|hive_unload_failed`),
   and a logged-out profile goes through the offline `RegLoadKeyW` arm and
   still unloads cleanly.
6. StartupApproved join: a scratch Run entry plus its StartupApproved blob
   reports `disabled` correctly, and a truncated (non-12-byte) blob reports
   `enabled=unmodelled` with a `constrained` status, never a dropped row.
7. Startup folders: a dropped `.lnk` in both the common and per-user
   Startup folders surfaces as its own row with unresolved target/args and
   a real `mtime`.
8. Scheduled Tasks: `win_scheduled_tasks` row count matches the
   ITaskService session's own recursive enumeration (A1's probe: 321-322
   tasks), hidden tasks included, never cross-checked against `schtasks.exe`
   (must never be spawned).
9. WMI subscriptions: exactly one `win_wmi_subscriptions` row per
   `__FilterToConsumerBinding` (A1's probe: one stock binding, `Next()`
   `WBEM_S_FALSE` after exactly 1).
10. Cleanup verification: every scratch registry key/task/binding/file
    created for steps 4-9 is removed and a follow-up `list` run confirms no
    stray rows remain.

**Linux container (`ubuntu:24.04`) and this Mac, both run 2026-09-07:**

1. Linux container: `lnx_systemd_timers_{system,user}` both read
   `no_systemd` (no init system present -- the tri-state's absent branch,
   not rung-2); `lnx_cron_d` and `lnx_cron_periodic` both produced real
   `autorun|` rows from the image's stock `e2scrub_all`/`dpkg`/`apt-compat`
   cron entries; `lnx_etc_crontab`/`lnx_anacrontab` correctly read
   `constrained|absent` (required sources, genuinely missing in this
   minimal image); `lnx_init_d` listed the stock `procps` SysV script,
   correctly `constrained|listing_only`. This ran through a standalone
   harness linking the real `collect_linux`, not the built `.dylib`
   dispatched end-to-end (that artifact cannot run on Linux at all).
2. This Mac (macOS, native `autoruns.dylib`, `LocalDispatcher`): all five
   launchd-plist sources supported with real row counts (422/456 system
   daemons/agents, 2/0/1 user-scope), `mac_login_items` constrained with
   zero rows, `mac_periodic`/`mac_emond` supported with zero rows (neither
   directory populated on this host) -- the "supported, nothing there" vs
   "constrained, no API" distinction holds for real; every `win_*`/`lnx_*`
   source correctly reads `unsupported|0|foreign_os` through the foreign-OS
   stub.
3. **Not yet run for real, tracked as a gap:** an end-to-end Linux `list`
   dispatch (real `autoruns.so`, real dispatcher, real
   `run_bounded_subprocess`) -- everything above for Linux is the leg's
   real code compiled standalone, not the shipped artifact; the rung-2
   `systemctl list-timers` fallback (needs a host with systemd present but
   every unit dir unreadable -- no available host provided this state); a
   Linux host with a populated `/etc/anacrontab`/per-user crontab/`at(1)`
   spool/systemd timer unit to confirm those `autorun|` row shapes for real
   (only the container's stock cron/init.d entries were exercised here);
   the-rig's own `meson compile`/link (tracked separately, concurrent with
   this package per the run context).
