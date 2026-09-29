# the-rig checklist — autoruns Windows leg (P12)

Real-hardware verification for `agents/plugins/autoruns/src/autoruns_win.cpp`.
Run on `the-rig` (desktop-04dnsig) once the plugin builds under MSVC 2022
BuildTools. Expected values below come from A1's probe
(`tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md`, 2026-09-06)
where the probe covered the same mechanism; everything else needs a fresh
capture on this host, since the probe did not exercise the registry Run-key
family, Startup folders, or the WMI subscription content this leg formats.

1. Build the plugin: `meson compile -C build-windows autoruns_plugin_lib`
   (or the full `meson compile -C build-windows`). Confirm it links against
   `advapi32`, `ole32`, `oleaut32`, `wbemuuid`, `taskschd` with no unresolved
   externals — `CLSID_TaskScheduler` / `IID_ITaskService` resolve from
   `taskschd.lib`.

2. Run `autoruns.dll`'s `catalog` action via the local dispatcher test
   (`test_autoruns_win_local.cpp`, `test_autoruns_local_dispatcher.cpp`).
   Expect one `source|` line per catalog entry (34 total), all Windows
   entries `windows: SUPPORTED` per `autoruns_catalog.hpp`.

3. Run `list` (no `sources=` filter). Confirm every one of the 14
   `win_*` SourceIds emits **exactly one** `source|` line: `win_run_hklm`,
   `win_runonce_hklm`, `win_runonceex_hklm`, `win_run_hku`,
   `win_runonce_hku`, `win_startup_approved`, `win_winlogon_shell`,
   `win_winlogon_userinit`, `win_appinit_dlls`, `win_ifeo_debugger`,
   `win_startup_folder_common`, `win_startup_folder_user`,
   `win_scheduled_tasks`, `win_wmi_subscriptions`. None should read
   `unsupported` (that value only comes from the foreign-OS stub, which a
   Windows build never reaches for these ids).

4. **HKLM Run/RunOnce/RunOnceEx.** Confirm both a native-view row set and a
   `[WOW6432Node]`-labelled row set are attempted (a real 64-bit box
   normally has entries in the native `Run` key; the WOW6432Node view is
   commonly empty — `source|...|supported|0|ok` there is expected, not a
   bug). Cross-check row count and target/args against `reg query
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"` run manually in
   the same admin session.

5. **Per-user Run/RunOnce/StartupApproved.** Confirm at least the
   `alex` (`S-1-5-21-...-1001`) profile is enumerated (present in every A1
   probe run) and its hive is reached `live` (already logged in during the
   capture) rather than via the offline `RegLoadKeyW` fallback — check for
   the absence of any `warning|hive_unload_failed` line. If a second,
   logged-out profile exists, confirm it goes through the offline arm and
   still unloads cleanly (no unload warning) exactly like A1's Amcache
   probe reported for `RegLoadAppKeyW`'s own hive handling.

6. **StartupApproved join.** Manually create one Run entry plus a matching
   `StartupApproved\Run` disabled blob for a scratch program, confirm the
   `win_startup_approved` row for that value name reports `disabled`
   (`parse_startup_approved_blob` byte0 `0x03`), and that removing the
   blob's expected 12-byte shape (truncate it) produces
   `enabled=unmodelled` plus `source|win_startup_approved|constrained|...`
   with a `malformed` or `oversized`/`changed_during_read` token, never a
   silently dropped row.

7. **Startup folders.** Drop a `.lnk` into
   `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` and into
   the test user's `...\Start Menu\Programs\Startup`. Confirm both surface
   as `win_startup_folder_common` / `win_startup_folder_user` rows with
   `target`/`args` empty (link targets are documented as NOT resolved) and
   a real `mtime` matching the file's last-write time.

7a. **Redirect-resolution verification, `win_startup_folder_user` under
    LocalSystem (#4219 fix).** The default path test above does NOT
    exercise this: the default (non-redirected) path resolves correctly
    either way. Read the test user's `HKCU\...\Explorer\User Shell
    Folders\Startup` value directly from a session running AS that user --
    it will very likely already contain a `REG_EXPAND_SZ` value like
    `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
    (Windows populates this on essentially every profile at creation, not
    only redirected ones). Then, from the LocalSystem-running agent, drop a
    `.lnk` into that same user's actual Startup folder and check the
    `win_startup_folder_user` result -- the fix now resolves `%USERPROFILE%`
    against the ENUMERATED PROFILE's own path (never LocalSystem's), so the
    expected outcome is the `.lnk` correctly appearing as a row, with
    `location` pointing at the real user's `AppData\Roaming\...\Startup`,
    and status `supported`. Treat the run as a regression if the status
    instead comes back `constrained` with `startup_redirect_unresolved` (or
    the row is silently missing) -- see
    `changelog.d/20260909-autoruns-plugin.added.md` and
    `agents/plugins/autoruns/src/autoruns_parsers.hpp`'s
    `resolve_profile_shell_folder` for the fixed resolution logic.

8. **Scheduled Tasks.** A1's probe (admin session, MTA):
   `CoInitializeEx` HRESULT `0x00000000`, `Connect` HRESULT `0x00000000`,
   `GetFolder` HRESULT `0x00000000`, **321** tasks recursively enumerated
   (LocalSystem session: **322**, drift between the two runs, not an
   apartment effect). Confirm this leg's `win_scheduled_tasks` row count is
   in that neighbourhood (exact count will have drifted further since
   2026-09-06) and that hidden tasks (`TASK_ENUM_HIDDEN`) are included —
   compare against Task Scheduler's own "Show Hidden Tasks" view, never
   against `schtasks.exe` output (this leg must never spawn it).

9. **WMI subscriptions.** A1's probe: `root\subscription` is not empty on
   this host — one stock binding (`BindingCount=1`), filter "SCM Event Log
   Filter", consumer "SCM Event Log Consumer" (`NTEventLogEventConsumer`),
   `Next()` returning `WBEM_S_FALSE` (0x00000001) after exactly 1 binding.
   Rows are now emitted one per `__FilterToConsumerBinding`, joined on the
   ref Name (P12 respec delta 1) — expect **exactly one** `win_wmi_subscriptions`
   row on this host, matching `BindingCount=1`. Confirm that row's `entry` is
   `SCM Event Log Filter` and `target` is empty (`NTEventLogEventConsumer`
   carries none of `CommandLineTemplate`/`ScriptText`/`ExecutablePath` —
   nothing to run, not a parse failure, per `parse_wmi_subscription_triple`'s
   own documented behaviour). Then register one throwaway
   `CommandLineEventConsumer` binding (now **two** bindings total) and
   confirm the source now emits **two** rows — one per binding, never
   collapsed to one — and the new row's `target` IS populated, before
   removing it.

10. **Cleanup.** Confirm no scratch registry values, Startup-folder files,
    or WMI subscriptions created for steps 4-9 survive the run (mirror A1's
    own probe-cleanup verification pattern in the probe-findings file).
