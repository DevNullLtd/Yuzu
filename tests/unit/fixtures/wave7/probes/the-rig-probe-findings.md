# the-rig probe findings (2026-09-06)

Host: the-rig (desktop-04dnsig). Checkout used: `D:\yuzu-dev\Yuzu` (`C:\Users\alex\yuzu-dev` does NOT
exist on this host, confirmed via `Test-Path`). Compiler: MSVC 2022 BuildTools,
`cl /std:c++latest /EHsc`, single TU (`probe_wave7.cpp`), no repo dependencies. Compiled clean under
`/W3`, no warnings.

## Identity of each run

- Admin SSH session: `whoami /all` first line -> `desktop-04dnsig\alex S-1-5-21-571721511-16201247-3531262703-1001`
  (SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege all already Enabled in this session).
- SYSTEM scheduled task: `whoami /all` first line -> `nt authority\system S-1-5-18`. Task registered
  with `New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest`
  (SYSTEM does not need S4U -- S4U is only required for a named, non-SYSTEM interactive-less account;
  it ran and reported `LastTaskResult: 0`), unregistered immediately after.

## Probe 1: RtlDecompressBufferEx (MAM prefetch decompression)

`GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlGetCompressionWorkSpaceSize")` and
`"RtlDecompressBufferEx"` both resolved to non-null addresses in every run (admin and LocalSystem).

| File | Session | RtlGetCompressionWorkSpaceSize NTSTATUS | RtlDecompressBufferEx NTSTATUS | Decompressed size | Bytes 4-7 |
|---|---|---|---|---|---|
| DOSKEY.EXE-DDFD0A8D.pf | admin | 0x00000000 | 0x00000000 | 6046 | SCCA |
| OUTPUT.EXE-EE9CBC0B.pf | admin | 0x00000000 | 0x00000000 | 9838 | SCCA |
| REG.EXE-6A8B6960.pf | admin | 0x00000000 | 0x00000000 | 10944 | SCCA |
| DOSKEY.EXE-DDFD0A8D.pf | LocalSystem | 0x00000000 | 0x00000000 | 6046 | SCCA |

All four decompression attempts returned `STATUS_SUCCESS` (0x00000000) for both
`RtlGetCompressionWorkSpaceSize` (workspace size 166495 bytes in every case, format
`COMPRESSION_FORMAT_XPRESS_HUFF` = 4, engine standard) and `RtlDecompressBufferEx`. Every decompressed
payload's bytes 4-7 read `SCCA` as expected for a valid prefetch header (version field at offset 0 =
31 in the REG.EXE payload, i.e. the Win10/11 prefetch format). Payloads are committed as
`<name>.pf.decompressed` next to their `.pf` source. RunCount field parsing itself is out of scope for
this probe (decompression evidence only, per spec); `REG.EXE-6A8B6960.pf` was selected as the run-count
>1 candidate because `reg.exe` was invoked 8+ times earlier in the same capture session before this
file's `LastWriteTime`.

## Probe 2: RegLoadAppKeyW (Amcache.hve)

`Copy-Item` of `C:\Windows\appcompat\Programs\Amcache.hve` succeeded as a **plain copy** in the admin
session (SeBackupPrivilege already Enabled) -- no sharing violation was hit, so the
`CreateFile(FILE_SHARE_READ|WRITE|DELETE, FILE_FLAG_BACKUP_SEMANTICS)` + `SeBackupPrivilege` fallback
path was never exercised; it was not needed to obtain the copy.

| Session | SeBackupPrivilege state | RegLoadAppKeyW LSTATUS | Root\InventoryApplicationFile subkeys |
|---|---|---|---|
| admin | Enabled (AdjustTokenPrivileges -> 1) | 0x00000000 | 8889 |
| admin | Disabled (AdjustTokenPrivileges -> 1) | 0x00000000 | 8889 |
| LocalSystem | Enabled | 0x00000000 | 8889 |
| LocalSystem | Disabled | 0x00000000 | 8889 |

**Key finding for P32's locking design: `RegLoadAppKeyW` does NOT require `SeBackupPrivilege`.** It
succeeded (LSTATUS 0x00000000 / `ERROR_SUCCESS`) with the privilege explicitly disabled via
`AdjustTokenPrivileges`, in both the admin session and under LocalSystem. `RegLoadAppKeyW` loads a
private, process-scoped hive copy and does not go through the backup/restore privilege check that
`RegLoadKey`/`RegRestoreKey` do.

The registry-export `amcache_inventory_application_file.txt` fixture was produced separately via
`reg load HKLM\YuzuAmcacheProbe <copy>` / `reg query .../Root\InventoryApplicationFile\<subkey>` /
`reg unload HKLM\YuzuAmcacheProbe` (5 real subkeys, all 18 values each). The rig was left clean after
every load: `reg query HKLM\YuzuAmcacheProbe` returns "unable to find the specified registry key"
after each unload -- verified after both the `reg load`/`reg unload` cycle and after the C++
`RegLoadAppKeyW` runs (which auto-release their process-private key on process exit, leaving no HKLM
residue at all).

## Probe 3: ITaskService and WMI root\subscription

`CoInitializeEx` -> `CoCreateInstance(CLSID_TaskScheduler, IID_ITaskService)` -> `Connect()` ->
`GetFolder("\\")` -> recursive `GetTasks(TASK_ENUM_HIDDEN)`:

| Session | COM apartment | CoInitializeEx HRESULT | Connect HRESULT | GetFolder HRESULT | Recursive task count |
|---|---|---|---|---|---|
| admin | COINIT_MULTITHREADED (repo's MTA, `yuzu::shared::win::ComInit`) | 0x00000000 | 0x00000000 | 0x00000000 | 321 |
| admin | COINIT_APARTMENTTHREADED | 0x00000000 | 0x00000000 | 0x00000000 | 321 |
| LocalSystem | COINIT_MULTITHREADED | 0x00000000 | 0x00000000 | 0x00000000 | 322 |
| LocalSystem | COINIT_APARTMENTTHREADED | 0x00000000 | 0x00000000 | 0x00000000 | 322 |

**MTA works for ITaskService on the-rig, in both the admin session and under LocalSystem** -- the
repo's `agents/shared/win_com.hpp:33-35` `COINIT_MULTITHREADED` choice is not a problem for
`ITaskService` here; both apartment models gave identical HRESULTs and counts in each session (the
+1 task count difference between admin and LocalSystem runs reflects real task-store state drift
between the two separate runs a few minutes apart, not an apartment-model effect).

`CoCreateInstance(CLSID_WbemLocator)` -> `ConnectServer(root\subscription)` -> `ExecQuery(SELECT * FROM
__FilterToConsumerBinding)` -> semisynchronous `Next(10000)`:

| Session | ConnectServer HRESULT | ExecQuery HRESULT | Next() final HRESULT | Bindings enumerated |
|---|---|---|---|---|
| admin | 0x00000000 | 0x00000000 | 0x00000001 (WBEM_S_FALSE, end of enumeration, returned=0) | 1 |
| LocalSystem | 0x00000000 | 0x00000000 | 0x00000001 | 1 |

`root\subscription` is **not empty** on the-rig: it holds one stock Windows binding -- filter "SCM
Event Log Filter", consumer "SCM Event Log Consumer" (an `NTEventLogEventConsumer`), bound together.
This is a built-in Windows subscription (Service Control Manager event logging), not something
registered for this capture; no `WMI subscription` was created and none needed reconstructing. Full
`Format-List *` output for all three CIM classes is committed at
`../autoruns/windows/subscription_triple.txt`.

## Rig cleanup (verified)

- `reg query HKLM\YuzuAmcacheProbe` -> "ERROR: The system was unable to find the specified registry
  key or value." (confirmed after every load/unload cycle, and after every `RegLoadAppKeyW` probe run).
- `Get-ScheduledTask -TaskName 'YuzuWave7*'` -> empty (both `YuzuWave7ProbeTemp` and
  `YuzuWave7WhoamiTemp` unregistered immediately after their single run).
- `D:\wave7_capture` (the entire scratch/staging directory used for this capture, including the
  Amcache.hve copy) removed: `Test-Path D:\wave7_capture` -> `False`.
- No HKLM/HKU keys were modified; no scheduled task or WMI subscription other than the two temporary
  probe launchers (both since removed) was created.
