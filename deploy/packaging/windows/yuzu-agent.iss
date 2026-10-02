; Yuzu Agent — Windows Installer (InnoSetup 6)
; Build: ISCC.exe yuzu-agent.iss
; Silent: YuzuAgentSetup-0.7.0.exe /VERYSILENT /SUPPRESSMSGBOXES /SERVER=myserver:50051 /TOKEN=abc123

#ifndef AppVersion
  #define AppVersion "0.7.0"
#endif

; Build output directory — override with /DBuildDir=...
#ifndef BuildDir
  #define BuildDir "..\..\..\build-windows"
#endif

[Setup]
AppId={{B7F3A2E1-9C4D-4F6A-8E2B-1D3C5A7F9E0B}
AppName=Yuzu Agent
AppVersion={#AppVersion}
AppVerName=Yuzu Agent {#AppVersion}
AppPublisher=Yuzu Project
AppPublisherURL=https://github.com/YuzuProject/yuzu
DefaultDirName={autopf}\Yuzu
DefaultGroupName=Yuzu
OutputBaseFilename=YuzuAgentSetup-{#AppVersion}
OutputDir=output
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayIcon={app}\bin\yuzu-agent.exe
SetupIconFile=yuzu.ico
WizardStyle=modern
DisableProgramGroupPage=yes
LicenseFile=..\..\..\LICENSE
CloseApplications=force
RestartApplications=no
; Upgrade: stop service before file replacement
CloseApplicationsFilter=yuzu-agent.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (all plugins)"
Name: "minimal"; Description: "Minimal installation (core plugins only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Yuzu Agent core"; Types: full minimal custom; Flags: fixed
Name: "plugins"; Description: "Agent plugins"; Types: full custom
Name: "plugins\system"; Description: "System info (OS, hardware, storage, users)"; Types: full custom
Name: "plugins\network"; Description: "Network (config, diagnostics, actions, WiFi, WoL)"; Types: full custom
Name: "plugins\security"; Description: "Security (antivirus, BitLocker, certificates, firewall, exploit-mitigation posture)"; Types: full custom
Name: "plugins\windows"; Description: "Windows (event logs, registry, WMI, updates, SCCM)"; Types: full custom
Name: "plugins\management"; Description: "Management (processes, services, software, scripts)"; Types: full custom
Name: "plugins\advanced"; Description: "Advanced (discovery, IOC, vuln scan, quarantine)"; Types: full custom

[Files]
; --- Core agent ---
Source: "{#BuildDir}\agents\core\yuzu-agent.exe"; DestDir: "{app}\bin"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\core\*.dll"; DestDir: "{app}\bin"; Components: core; Flags: ignoreversion

; --- Plugins: core (always installed) ---
Source: "{#BuildDir}\agents\plugins\status\status.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\agent_actions\agent_actions.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\agent_logging\agent_logging.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\tags\tags.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\diagnostics\diagnostics.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\content_dist\content_dist.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\device_identity\device_identity.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion

; --- Plugins: system ---
Source: "{#BuildDir}\agents\plugins\os_info\os_info.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\hardware\hardware.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\storage\storage.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\disk_space\disk_space.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\filesystem\filesystem.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\disk_actions\disk_actions.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\filesystem_posture\filesystem_posture.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\users\users.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\installed_apps\installed_apps.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\msi_packages\msi_packages.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\asset_tags\asset_tags.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\power_health\power_health.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\autoruns\autoruns.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
; app_usage's only data source is tar.dll (reads tar.db directly), which is
; itself gated on plugins\advanced alone (see that Source line below) --
; app_usage.dll must be gated on the SAME single component, not a narrower
; "and" of two: a custom install selecting Advanced without System has a
; working tar.dll but would otherwise silently skip app_usage.dll despite
; its dependency being present (governance Gate 7, cross-platform finding).
Source: "{#BuildDir}\agents\plugins\app_usage\app_usage.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\execution_artifacts\execution_artifacts.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\runtimes\runtimes.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\windows_optional_features\windows_optional_features.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\peripherals\peripherals.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\browser_policy\browser_policy.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\pkg_inventory\pkg_inventory.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion

; --- Plugins: network ---
Source: "{#BuildDir}\agents\plugins\network_config\network_config.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\network_diag\network_diag.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\network_actions\network_actions.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\netstat\netstat.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\wifi\wifi.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\wol\wol.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\http_client\http_client.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion

; --- Plugins: security ---
Source: "{#BuildDir}\agents\plugins\antivirus\antivirus.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\bitlocker\bitlocker.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\certificates\certificates.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\firewall\firewall.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\quarantine\quarantine.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\app_control\app_control.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\firmware_posture\firmware_posture.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\platform_security\platform_security.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\system_hardening\system_hardening.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\ioc\ioc.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\vuln_scan\vuln_scan.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion

; --- Plugins: windows ---
Source: "{#BuildDir}\agents\plugins\event_logs\event_logs.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\registry\registry.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\wmi\wmi.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\windows_updates\windows_updates.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\sccm\sccm.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion

; --- Plugins: management ---
Source: "{#BuildDir}\agents\plugins\processes\processes.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\services\services.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\software_actions\software_actions.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\script_exec\script_exec.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\interaction\interaction.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion

; --- Plugins: advanced ---
Source: "{#BuildDir}\agents\plugins\discovery\discovery.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\tar\tar.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\procfetch\procfetch.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\chargen\chargen.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\example\example.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion

[Dirs]
Name: "{app}\logs"; Permissions: admins-full system-full
Name: "{commonappdata}\Yuzu"; Permissions: admins-full system-full
; Trust-anchor directory for OTA update signature verification (#416/#3807).
; Its own directory, NOT {commonappdata}\Yuzu\certs: on a co-installed host that
; path is the server's CA directory, whose ownership requirements are
; incompatible with an agent-readable anchor. Plugin code signing is unaffected
; and still uses <cert-dir>\plugin-trust-bundle.pem.
;
; This Permissions entry ADDS ACEs and cannot disable inheritance, and it cannot
; remove anything, so on its own it does NOT keep unprivileged users out:
; ProgramData grants Users inheritable create rights, which would let a local
; user plant update-trust-bundle.pem here before an operator provisions it.
; SecureTrustAnchorDir (called from PrepareToInstall, in [Code]) is what
; actually enforces this: it creates and locks the directory, or refuses one that
; already exists without being secured — it never takes one over. It also runs
; FIRST, so by the time this entry is processed the directory already exists and
; is locked down, and all this adds is the two ACEs it already has.
;
; The agent service runs as LocalSystem, so it is covered by system-full and CAN
; write here - this keeps unprivileged local users out, not the agent itself.
; Inherent: a process able to replace the system binary can rewrite the file
; authorising the replacement. See "Signing update binaries" in
; docs/user-manual/server-admin.md.
Name: "{commonappdata}\Yuzu\agent-certs"; Permissions: admins-full system-full

[Run]
; The trust-anchor directory is NOT hardened from here (#416/#3807).
;
; Both the hardening and its verification live in SecureTrustAnchorDir, called
; from PrepareToInstall in [Code] -- read that function's comment for what it
; does and why. It sits there rather than here for two reasons, and the second
; is why it was moved:
;
;   - a [Run] failure is DISMISSIBLE, so an operator can click past it;
;   - a failure detected after the install has finished cannot undo it, and
;     Setup still exits 0. This installer is deployed unattended via
;     SCCM/Intune/GPO, so exit 0 is recorded as a successful deployment -- an
;     abort nobody is told about is not a fail-closed gate. PrepareToInstall
;     aborts before any file is copied and exits non-zero (verified: exit 7).
;
; It also runs well before the service starts below, so the directory is locked
; down the first time the agent reads it.

; Register and start the service after install
Filename: "{app}\bin\yuzu-agent.exe"; Parameters: "--install-service"; StatusMsg: "Registering Yuzu Agent service..."; Flags: runhidden waituntilterminated
; #1468: `binPath=` takes a SINGLE value -- sc.exe consumes only the next token, so the
; whole "exe + arguments" string must be one quoted token with the inner quotes escaped
; (\" -- written \"" here, since "" is a literal quote in an Inno parameters string).
; Written the old way (bare quoted exe, arguments trailing outside the value) sc.exe parsed
; --service/--server/... as unknown OPTIONS, printed its usage block and exited 1639
; ERROR_INVALID_COMMAND_LINE without touching the service -- and because Inno ignores [Run]
; exit codes, the install still reported success. The service kept the argument-less binPath
; CreateServiceW wrote ("<exe>" --service, service_win.hpp make_service_binpath), so the agent
; ran with no --server/--data-dir/--plugin-dir/--log-file and, with TLS on by default and no
; CA to pin, fail-closed on startup (#1303 posture) -- the service reached RUNNING and then
; stopped seconds later. `sc qc YuzuAgent` must show every argument below; pre-release.yml's
; install-windows job asserts exactly that so this cannot regress silently again.
; {sys}\sc.exe + no shellexec: ShellExecuteEx re-parses lpParameters, so the escaped quotes
; are only reliably preserved via CreateProcess (which takes the string verbatim); the full
; path removes the PATH lookup that shellexec was providing.
; GetExtraArgs supplies its own leading space, so it is appended without one.
Filename: "{sys}\sc.exe"; Parameters: "config YuzuAgent binPath= ""\""{app}\bin\yuzu-agent.exe\"" --service --server {code:GetServerAddress} --data-dir \""{commonappdata}\Yuzu\"" --plugin-dir \""{app}\plugins\"" --log-file \""{app}\logs\yuzu-agent.log\""{code:GetExtraArgs}"""; StatusMsg: "Configuring service..."; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start YuzuAgent"; StatusMsg: "Starting Yuzu Agent service..."; Flags: runhidden waituntilterminated; Check: ShouldStartService
; Configure the boot-window ETW AutoLogger so the kernel captures process
; start/stop from early boot to <data-dir>\procboot.etl; the TAR plugin drains it
; at startup to backfill processes that started AND exited before its live ETW
; session opened. Takes effect on the NEXT boot. Scoped to plugins\advanced (the
; component that ships tar.dll) — pointless without the consumer. Best-effort:
; -ErrorAction SilentlyContinue + trailing `exit 0` keep a failure here from
; aborting the install (live capture is unaffected). Leads with
; Remove-AutologgerConfig so an upgrade-over-install refreshes a changed recipe
; (New-AutologgerConfig will not overwrite an existing config). RECIPE MIRRORS
; scripts/install-agent-user.ps1 New-ProcBootAutologger — keep in sync (LogFileMode
; 0x2 = circular, 16 MB cap, System clock for FILETIME decode, FlushTimer 1 so the
; boot window reaches disk before the agent replays, keyword 0x10 = start/stop).
; PSModulePath reset: same as SecureTrustAnchorDir (#5176) -- $PSHOME\Modules only, no .NET call, so it
; also runs under Constrained Language Mode (#5196). The AutoLogger cmdlets load fine without it; it is
; here so every powershell.exe the installer starts sees Windows PowerShell's own modules.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$env:PSModulePath=$PSHOME+'\Modules'; Remove-AutologgerConfig -Name YuzuProcBoot -ErrorAction SilentlyContinue | Out-Null; New-AutologgerConfig -Name YuzuProcBoot -LogFileMode 0x2 -LocalFilePath '{commonappdata}\Yuzu\procboot.etl' -MaximumFileSize 16 -ClockType System -FlushTimer 1 -ErrorAction SilentlyContinue | Out-Null; Add-EtwTraceProvider -AutologgerName YuzuProcBoot -Guid '{{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}' -Level 4 -MatchAnyKeyword ([uint64]0x10) -ErrorAction SilentlyContinue | Out-Null; exit 0"""; StatusMsg: "Configuring boot process-capture AutoLogger..."; Flags: runhidden waituntilterminated; Components: plugins\advanced

[UninstallRun]
; #1822 fix means `sc stop` now genuinely stops a running process holding open
; handles (exe, log file, network stream) instead of a no-op against a service
; that was never actually startable, so a flat delay is no longer sufficient --
; poll for STOPPED (bounded to 15s, same pattern as PrepareToInstall's install-
; time poll) instead of a fixed 3s wait (Gate 3 release-deploy finding,
; governance re-run). Falls through regardless of outcome: --remove-service and
; file deletion below are safe even if the process is still exiting (marks for
; delete / falls back to delete-on-reboot for a locked exe), same as before.
; Deliberately NOT gated on StopResultCode the way PrepareToInstall's poll is
; (that skip matters there because installs may be scripted/repeated across a
; fleet -- worth optimizing the dominant case); this always polls, so a
; service-already-absent uninstall burns the full bounded 15s instead of
; short-circuiting. Accepted: uninstall is rarer, typically human-driven, and
; replicating an exact-match (not >=) errorlevel skip safely inside a single
; cmd.exe /c one-liner isn't worth the added scripting risk for that saving
; (Gate 4 unhappy-path + consistency-auditor finding, governance re-run).
Filename: "cmd.exe"; Parameters: "/c sc stop YuzuAgent >nul 2>&1 & for /l %i in (1,1,15) do (sc query YuzuAgent | find ""STOPPED"" >nul && exit /b 0 || timeout /t 1 /nobreak >nul)"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\bin\yuzu-agent.exe"; Parameters: "--remove-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
; Tear down the boot AutoLogger + its .etl on uninstall. Remove-AutologgerConfig
; drops only the boot-start config — it does NOT stop a session already running
; from a prior boot, so Stop-EtwTraceSession is needed or uninstall leaves the
; YuzuProcBoot session live until the next reboot, holding a scarce system ETW
; session slot and still writing the 16 MB circular .etl. Unconditional (harmless
; no-op if never configured). Mirror of
; scripts/install-agent-user.ps1 Remove-ProcBootAutologger — keep in sync.
; PSModulePath reset: same as SecureTrustAnchorDir (#5176) -- $PSHOME\Modules only, no .NET call, so it
; also runs under Constrained Language Mode (#5196). The AutoLogger cmdlets load fine without it; it is
; here so every powershell.exe the installer starts sees Windows PowerShell's own modules.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$env:PSModulePath=$PSHOME+'\Modules'; Remove-AutologgerConfig -Name YuzuProcBoot -ErrorAction SilentlyContinue | Out-Null; Stop-EtwTraceSession -Name YuzuProcBoot -ErrorAction SilentlyContinue | Out-Null; Remove-Item '{commonappdata}\Yuzu\procboot.etl' -Force -ErrorAction SilentlyContinue | Out-Null; exit 0"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveProcBootAutologger"

; gate-3 sre remediation (#3403 sockwho retirement): Inno Setup does not
; delete a file merely dropped from [Files] on an in-place upgrade, and
; PluginLoader::scan() (agents/core/src/plugin_loader.cpp) globs every
; plugin-dir file by extension with no denylist -- the default
; --plugin-allowlist is empty/unset, so a stale sockwho.dll left on disk
; after upgrading past this release would be silently re-loaded and its
; retired action would come back, not just linger as dead weight. Explicit
; delete closes that.
[InstallDelete]
Type: files; Name: "{app}\plugins\sockwho.dll"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"

[Code]
var
  ConfigPage: TInputQueryWizardPage;
  ServerAddress: string;
  EnrollmentToken: string;
  NoTLS: Boolean;
  StartService: Boolean;

function GetCommandlineParam(const ParamName: string): string;
var
  I: Integer;
  Param: string;
  Prefix: string;
begin
  Result := '';
  Prefix := '/' + ParamName + '=';
  for I := 1 to ParamCount do
  begin
    Param := ParamStr(I);
    if CompareText(Copy(Param, 1, Length(Prefix)), Prefix) = 0 then
    begin
      Result := Copy(Param, Length(Prefix) + 1, MaxInt);
      Exit;
    end;
  end;
end;

function HasCommandlineFlag(const FlagName: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    if CompareText(ParamStr(I), '/' + FlagName) = 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure InitializeWizard;
begin
  ConfigPage := CreateInputQueryPage(wpSelectComponents,
    'Yuzu Server Connection',
    'Configure how this agent connects to the Yuzu server.',
    'Enter the server address and optional enrollment token.');

  ConfigPage.Add('Server address (host:port):', False);
  ConfigPage.Add('Enrollment token (optional):', False);

  { Defaults — can be overridden via /SERVER= and /TOKEN= }
  ConfigPage.Values[0] := GetCommandlineParam('SERVER');
  if ConfigPage.Values[0] = '' then
    ConfigPage.Values[0] := 'localhost:50051';

  ConfigPage.Values[1] := GetCommandlineParam('TOKEN');

  NoTLS := HasCommandlineFlag('NOTLS');
  StartService := not HasCommandlineFlag('NOSTART');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ConfigPage.ID then
  begin
    ServerAddress := ConfigPage.Values[0];
    EnrollmentToken := ConfigPage.Values[1];
    if ServerAddress = '' then
    begin
      MsgBox('Server address is required.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  { Skip config page in silent mode — values come from command line }
  if (PageID = ConfigPage.ID) and WizardSilent then
    Result := True;
end;

function GetServerAddress(Param: string): string;
begin
  if WizardSilent then
  begin
    Result := GetCommandlineParam('SERVER');
    if Result = '' then
      Result := 'localhost:50051';
  end
  else
    Result := ServerAddress;
end;

function GetExtraArgs(Param: string): string;
begin
  Result := '';

  { Enrollment token }
  if WizardSilent then
    EnrollmentToken := GetCommandlineParam('TOKEN');
  if EnrollmentToken <> '' then
    Result := Result + ' --enrollment-token ' + EnrollmentToken;

  { No TLS }
  if WizardSilent then
    NoTLS := HasCommandlineFlag('NOTLS');
  if NoTLS then
    Result := Result + ' --no-tls';
end;

function ShouldStartService: Boolean;
begin
  if WizardSilent then
    Result := not HasCommandlineFlag('NOSTART')
  else
    Result := StartService;
end;

{ Embed S as a PowerShell single-quoted literal. Inside single quotes PowerShell
  expands nothing -- no $variable, no subexpression -- so the only characters
  needing care are the ones that END the literal: the ASCII quote and the
  typographic single quotes U+2018..U+201B, which PowerShell's tokenizer treats
  as the same delimiter. Each is escaped by doubling it.

  Note for anyone editing the comments in this file: a Pascal comment does NOT
  nest, so a closing brace written inside one ends it there and the prose after
  it is compiled as code. The .iss is only ever compiled by release.yml, never
  on a PR, so that mistake reaches the release build and nothing before it. }
function PsLit(const S: string): string;
var
  I: Integer;
begin
  Result := '';
  // A {tmp} path under a profile whose name contains U+2019 would otherwise
  // end the literal early, and the check would fail to parse.
  for I := 1 to Length(S) do
    if (S[I] = '''') or (S[I] = #$2018) or (S[I] = #$2019) or (S[I] = #$201A) or (S[I] = #$201B) then
      Result := Result + S[I] + S[I]
    else
      Result := Result + S[I];
  Result := '''' + Result + '''';
end;

const
  FileAttrDirectory = $10;
  FileAttrReparsePoint = $400;

{ True when Path itself (not what it may point to) is a junction or symbolic
  link. FindFirst on a path with no wildcard returns that entry's own
  attributes from its parent directory, so it never follows the link. Sets
  Found to False when the entry could not be read at all. }
function IsReparsePoint(const Path: string; var Found: Boolean): Boolean;
var
  R: TFindRec;
begin
  Result := False;
  Found := FindFirst(Path, R);
  if Found then
  begin
    Result := (R.Attributes and FileAttrReparsePoint) <> 0;
    FindClose(R);
  end;
end;

{ '' when Dir holds only plain files (and, with MustBeEmpty, nothing at all);
  otherwise why not. Lists Dir's direct entries only. A failure to list is a
  refusal: "." always exists, so FindFirst returning False is not emptiness. }
function NotFilesOnly(const Dir: string; MustBeEmpty: Boolean): string;
var
  R: TFindRec;
  More: Boolean;
begin
  Result := '';
  if not FindFirst(Dir + '\*', R) then
  begin
    Result := 'its contents could not be listed';
    Exit;
  end;
  try
    More := True;
    while More and (Result = '') do
    begin
      if (R.Name <> '.') and (R.Name <> '..') then
      begin
        if (R.Attributes and FileAttrReparsePoint) <> 0 then
        begin
          if (R.Attributes and FileAttrDirectory) <> 0 then
            Result := 'it contains a junction or directory link, which must be removed with ' +
                      'cmd /c rmdir (never Remove-Item -Recurse): ' + Dir + '\' + R.Name
          else
            Result := 'it contains a file link, which must be removed with cmd /c del: ' +
                      Dir + '\' + R.Name;
        end
        else if (R.Attributes and FileAttrDirectory) <> 0 then
          Result := 'it contains a subdirectory, and it may hold only files: ' +
                    Dir + '\' + R.Name
        else if MustBeEmpty then
          Result := 'a file appeared in it while it was being created, so it may not be ' +
                    'the installer''s; remove the directory and run the installer again: ' +
                    Dir + '\' + R.Name;
      end;
      if Result = '' then
        More := FindNext(R);
    end;
  finally
    FindClose(R);
  end;
end;

{ The operator-facing refusal, shared by every way the directory can fail.
  Attempted says whether the installer had tried to secure it. }
function NotSecuredMessage(const CertDir, Reason: string; Attempted: Boolean): string;
begin
  Result := 'The update trust-anchor directory is not secured:' + #13#10 +
            CertDir + #13#10#13#10 + Reason + #13#10#13#10 +
            'Only Administrators and SYSTEM may have access to it, both need full ' +
            'control, and it may hold only files. While anyone else can write there, ' +
            'they can install their own trust bundle and authorise their own agent ' +
            'updates; while SYSTEM cannot read it, the agent cannot verify updates at ' +
            'all. ';
  if Attempted then
    Result := Result + 'Securing it did not take effect -- security software may have ' +
              'blocked it. ';
  Result := Result + 'The installation has been stopped; the Yuzu Agent service, if ' +
            'installed, has not been touched.';
end;

{ Run the PowerShell permission check on CertDir. '' on PASS, otherwise the
  reason. Mode is 'root' (the directory itself), 'files' (before an existing
  directory's files are reset: each must be a plain file, not a hard link, and
  already owned by Administrators or SYSTEM -- the installer never takes
  ownership of a file, so it only ever repairs files an administrator placed;
  the DACL is not compared, since rc1..rc5 left such files with an empty one,
  which the reset repairs), or 'full' (the directory and every file, exactly).

  THE CHECK MUST COMPARE THE EXACT OWNER AND ACE SET, not a marker within the
  ACL text -- and the set must be exactly "Administrators and SYSTEM, each
  allowed full control". "Nobody else has access" is also true of an empty
  DACL, which is what the rc1..rc5 /T bug produced and what the rc1..rc5 check
  passed; a Deny entry or an inherit-only entry for either account is also not
  access. The earliest check tested for the inherited-ACE marker "(I)", which
  an explicit ACE does not carry -- so it passed a directory the attacker could
  still write to. Verified on Windows 11 26100: the install completed, reported
  the directory secured, and the attacker retained (OI)(CI)(F) plus ownership.

  It tests the reparse (1024) and directory (16) attributes BEFORE any Get-Acl,
  because Get-Acl through a link reads the link's target, and it never
  recurses. The comparison is on the SDDL string (owner BA or SY; the root
  exactly (A;OICI;FA;;;BA)(A;OICI;FA;;;SY), protected; every file exactly the
  inherited (A;ID;FA;;;..) pair). SDDL names accounts by SID alias, never by
  localised name -- icacls prints localised names, so matching
  "BUILTIN\Administrators" would silently fail open off an English build. It
  uses NO .NET method or static call: under WDAC script enforcement, or
  AppLocker script rules for a non-SYSTEM install, PowerShell runs in
  Constrained Language Mode, which refuses method calls on non-core types. The
  rc1..rc5 check called GetOwner()/Translate(), so there it could not run and
  the install aborted. Verified on Windows Server 2022 with AppLocker script
  rules enforced, installing as an elevated administrator: rc5 exit 7, this
  check exit 0 (#5196). Property reads, -match, -band and cmdlets are allowed.

  IT MUST NOT PIPE icacls INTO find. An earlier form did:

      /C icacls "<dir>" | find "(I)" >nul && exit 1 || exit 0

  and it FAILED OPEN in exactly the case the check exists for. cmd.exe binds
  && / || to the PIPELINE's exit code -- that is `find`'s, the last command --
  not icacls's, and only icacls's stdout is piped, not its errors. So when
  icacls could not run at all it produced no "(I)"-bearing output, `find`
  failed to match exactly as it does for a genuinely secured directory, and the
  script reported SUCCESS.

  So: no pipe, and no inference from absence of output. The check writes its
  verdict to a file and exits 0 ONLY on a clean result; it passes only when the
  exit code is 0 AND the file says PASS. Every way of NOT getting an answer --
  PowerShell would not launch, it exited non-zero, the ACL could not be read,
  the verdict could not be read back -- FAILS CLOSED, because an unverifiable
  ACL here is indistinguishable from a bad one.

  The script is passed with -Command, not -File: execution policy governs script
  FILES, so an AllSigned policy pushed by GPO would block a .ps1 here but does
  not affect -Command. It is built from plain literals so any braces stay
  literal -- Inno expands a brace-delimited constant only inside ExpandConstant,
  which is applied to the paths separately.

  Windows PowerShell 5.1 inherits PSModulePath from whatever started the
  installer. Started (via any intermediate process) from PowerShell 7, that
  path points it at PowerShell 7's copies of modules it loads on first use,
  such as Microsoft.PowerShell.Security, which 5.1 cannot load: Get-Acl failed,
  the check could not run, and the install aborted (#5176). So it resets it to
  Windows PowerShell's own modules first, using no cmdlet to build it. }
function RunAclCheck(const CertDir, Mode: string): string;
var
  ResultCode: Integer;
  ReasonFile, PsExe, Script, Reason: string;
  ReasonText: AnsiString;
begin
  Result := '';
  ReasonFile := ExpandConstant('{tmp}\yuzu-agent-certs-acl.txt');
  PsExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  DeleteFile(ReasonFile);
  Script :=
    '$env:PSModulePath=$PSHOME+''\Modules'';' +
    '$ErrorActionPreference=''Stop'';' +
    '$d=' + PsLit(CertDir) + ';' +
    '$out=' + PsLit(ReasonFile) + ';' +
    '$m=' + PsLit(Mode) + ';' +
    'function Fail($m){Set-Content -LiteralPath $out -Value $m -Encoding ASCII;exit 3};' +
    'try{$r=Get-Item -LiteralPath $d -Force}catch{Fail ''it could not be opened''};' +
    'if(($r.Attributes -band 1024) -ne 0){Fail ''it is a junction or symbolic link, not a directory''};' +
    '$c=@();' +
    'if($m -ne ''root''){' +
      'try{$c=@(Get-ChildItem -LiteralPath $d -Force)}catch{Fail ''its contents could not be listed''};' +
      'foreach($i in $c){' +
        'if(($i.Attributes -band 1024) -ne 0){Fail (''it contains a junction or symbolic link: '' + $i.FullName)};' +
        'if(($i.Attributes -band 16) -ne 0){Fail (''it contains a subdirectory, and it may hold only files: '' + $i.FullName)};' +
        'if($i.LinkType -eq ''HardLink''){Fail (''it contains a hard link: '' + $i.FullName)}' +
      '};' +
      'if($m -eq ''files''){' +
        'foreach($i in $c){' +
          'try{$s=[string](Get-Acl -LiteralPath $i.FullName).Sddl}catch{Fail (''the permissions could not be read on '' + $i.FullName)};' +
          'if($s -notmatch ''^O:(BA|SY)G:''){Fail (''it contains a file not owned by Administrators or SYSTEM, so it cannot be confirmed that an administrator placed it (inspect it; if it is yours, make Administrators its owner with icacls <file> /setowner *S-1-5-32-544 /L): '' + $i.FullName + '' '' + $s)}' +
        '};' +
        'Set-Content -LiteralPath $out -Value ''PASS'' -Encoding ASCII;exit 0' +
      '}' +
    '};' +
    '$t=@($d)+@($c|ForEach-Object{$_.FullName});' +
    'foreach($p in $t){' +
      'try{$s=[string](Get-Acl -LiteralPath $p).Sddl}catch{Fail (''the permissions could not be read on '' + $p)};' +
      'if($s -notmatch ''^O:(BA|SY)G:''){Fail (''it is owned by an account other than Administrators or SYSTEM: '' + $p + '' '' + $s)};' +
      'if($s -notmatch ''D:([A-Z]*)(\(.*)?$''){Fail (''its permission list could not be read: '' + $p + '' '' + $s)};' +
      '$f=$Matches[1];$l=[string]$Matches[2];' +
      'if($p -eq $d){' +
        'if($f -notmatch ''P''){Fail ''it still inherits permissions from ProgramData''};' +
        '$e=''^\(A;OICI;FA;;;(SY|BA)\)\(A;OICI;FA;;;(SY|BA)\)$''' +
      '}else{$e=''^\(A;(?:OICI)?ID;FA;;;(SY|BA)\)\(A;(?:OICI)?ID;FA;;;(SY|BA)\)$''};' +
      'if(($l -notmatch $e) -or ($Matches[1] -eq $Matches[2])){Fail (''its permission list is not exactly Administrators and SYSTEM, each with full control: '' + $p + '' '' + $s)}' +
    '};' +
    'Set-Content -LiteralPath $out -Value ''PASS'' -Encoding ASCII;' +
    'exit 0';

  if not Exec(PsExe,
              '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := 'the permission check could not be run, so it could not be verified';
    Exit;
  end;
  if LoadStringFromFile(ReasonFile, ReasonText) then
    Reason := Trim(String(ReasonText))
  else
    Reason := '';
  DeleteFile(ReasonFile);
  { Both conditions are required. A non-zero exit means the check ran and
    rejected the directory; a zero exit without the PASS verdict means it did
    not get far enough to reach one, which is not evidence of anything. }
  if (ResultCode <> 0) or (Reason <> 'PASS') then
  begin
    if Reason = '' then
      Reason := 'the check did not produce a result (exit code ' + IntToStr(ResultCode) + ')';
    Result := Reason;
  end;
end;

{ Establish the OTA trust-anchor directory, then PROVE it is secured.

  RUNS BEFORE ANYTHING IS INSTALLED, and that placement is the point. An earlier
  version hardened from [Run] and verified from CurStepChanged(ssPostInstall),
  which failed in two ways that only show up in a fleet deployment: a [Run]
  failure is DISMISSIBLE, and a refusal raised after the install has finished
  cannot undo it -- Setup still exits 0, so SCCM/Intune/GPO record a successful
  deployment of an agent whose trust anchor anyone can write to. Returning a
  message from PrepareToInstall instead aborts with a non-zero exit code and
  leaves nothing installed.

  IT NEVER TAKES OVER ANYTHING IT DID NOT CREATE OR AN ADMINISTRATOR DID NOT
  PLACE (#5255 review). %ProgramData% grants Users inheritable create rights, so
  a local user can create agent-certs, or a file in it, before or while the
  installer runs. Earlier versions took ownership and re-secured whatever was
  there, adopting it as trusted. So:
    - a junction or symbolic link at the path -> refuse, before anything runs.
      The installer never deletes anything here.
    - the directory already exists -> it must already be exactly secured, or
      the install is refused for the operator to inspect. rc1..rc5 left the
      directory itself secured (only its files were broken), and an endpoint
      that upgraded by OTA has no directory, so every legitimate state passes.
      It is not re-locked; its contents must be plain files already owned by
      Administrators or SYSTEM before their permissions are reset. Nothing ever
      takes ownership of a file, so a file someone else placed is refused on
      every run, never adopted on a retry.
    - it does not exist -> it is built and locked in the installer's private
      temporary folder, checked there, and moved into place, so it never exists
      unlocked; then it is checked again in place.
  Not covered: an already-open handle keeps its access (#5258), and the parent
  %ProgramData%\Yuzu is not locked down (#5257).

  NOTHING RECURSES, AND THE DIRECTORY MAY HOLD ONLY FILES. Nothing legitimate
  creates a subdirectory here (the agent's own credentials live in
  <data-dir>\certs; only the trust-bundle files are read from agent-certs).
  Every icacls carries /L so it acts on the path itself, never a link's target;
  takeown is not used, having no such switch. Attributes are read with
  FindFirst and Get-Item, which report a link's own attributes.

  WHY /setowner, /reset AND /inheritance:r /grant:r. /setowner makes
  Administrators the owner; /reset drops every explicit ACE; /inheritance:r
  /grant:r drops the inherited ones and grants exactly Administrators and
  SYSTEM. `icacls /grant:r` ALONE IS NOT ENOUGH and that is a bug that shipped:
  it replaces grants only for the SIDs it NAMES, so a third SID's explicit
  entry survives. The grant must never reach a file: (OI)(CI) is invalid on a
  file, and the rc1..rc5 `icacls ... /grant:r ... /T` left every existing file
  -- the operator's update-trust-bundle.pem on every reinstall -- with an empty
  protected DACL that locks SYSTEM out too, while reporting success. The
  file-level /reset ("<dir>\*") repairs exactly that.

  Verified on Windows Server 2022 (#5255), the outside target untouched in each
  refusal case. Returns '' on success, or the operator-facing reason to abort. }
function SecureTrustAnchorDir(): string;
var
  ResultCode: Integer;
  Ok, Found, Existed: Boolean;
  CertDir, Stage, Reason: string;
begin
  Result := '';
  CertDir := ExpandConstant('{commonappdata}\Yuzu\agent-certs');

  { 1. A link at the path is refused before anything else, creation included. }
  if IsReparsePoint(CertDir, Found) then
  begin
    Result := NotSecuredMessage(CertDir,
      'it is a junction or symbolic link, not a directory. Remove the link -- ' +
      'cmd /c rmdir for a junction or directory link, cmd /c del for a file link; ' +
      'either removes the link, never its target (never use Remove-Item -Recurse) ' +
      '-- then run the installer again', False);
    Exit;
  end;
  if not Found and (DirExists(CertDir) or FileExists(CertDir)) then
  begin
    Result := NotSecuredMessage(CertDir, 'it could not be inspected', False);
    Exit;
  end;

  Existed := Found;
  if Existed then
  begin
    { 2. It existed before this installation: it must already be secured. }
    if not DirExists(CertDir) then
      Reason := 'it is a file, not a directory'
    else
      Reason := RunAclCheck(CertDir, 'root');
    if Reason <> '' then
    begin
      Result := NotSecuredMessage(CertDir,
        'it already existed and is not secured (' + Reason + '). This installer ' +
        'does not take over a directory it did not secure: whatever is in it already ' +
        'decides which agent updates are trusted. Check what it contains. Move any ' +
        'update-trust-bundle.pem you placed there yourself to a safe place, delete the ' +
        'directory (remove any junction or link in it first with cmd /c rmdir or ' +
        'cmd /c del; never Remove-Item -Recurse), run the installer again, then copy ' +
        'the bundle back in', False);
      Exit;
    end;
  end;

  if Existed then
  begin
    { 3. An existing, secured directory is NOT re-locked: it has just passed the
      exact check, and re-applying the lock would re-propagate inheritance to its
      entries before they are checked. Its contents must be plain files (no
      link, subdirectory or hard link), each already owned by Administrators or
      SYSTEM -- nothing here takes ownership of a file -- and only then are the
      files reset to inherit exactly BA and SYSTEM, which repairs the rc1..rc5
      lock-out. Direct entries only. }
    Reason := NotFilesOnly(CertDir, False);
    if Reason = '' then
      Reason := RunAclCheck(CertDir, 'files');
    if Reason <> '' then
    begin
      Result := NotSecuredMessage(CertDir, Reason, False);
      Exit;
    end;
    Ok := Exec(ExpandConstant('{sys}\icacls.exe'),
               '"' + CertDir + '\*" /reset /L /C /Q',
               '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end
  else
  begin
    { 4. A new directory is built and locked where only this installer can
      reach it -- its private temporary folder -- checked there, and only then moved into
      place, so agent-certs never exists unlocked. [Dirs] creates the path
      later, which is too late. The move keeps the protected DACL; it fails if
      anything already holds the name, or across volumes, and either refuses.
      No /R, no /T, and /L on each icacls so it acts on the path itself (takeown
      has no such switch and is not used). Exit codes are not trusted; the
      checks after them are. }
    Stage := ExpandConstant('{tmp}\agent-certs.stage');
    if not ForceDirectories(Stage) or
       not ForceDirectories(ExpandConstant('{commonappdata}\Yuzu')) then
    begin
      Result := 'Could not create the update trust-anchor directory:' + #13#10 +
                CertDir + #13#10#13#10 +
                'The installation has been stopped rather than continue without it; the ' +
                'Yuzu Agent service, if installed, has not been touched.';
      Exit;
    end;
    Ok := Exec(ExpandConstant('{sys}\icacls.exe'),
               '"' + Stage + '" /setowner *S-1-5-32-544 /L /C /Q',
               '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Ok := Exec(ExpandConstant('{sys}\icacls.exe'),
               '"' + Stage + '" /reset /L /C /Q',
               '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Ok := Exec(ExpandConstant('{sys}\icacls.exe'),
               '"' + Stage + '" /inheritance:r /grant:r ' +
               '"*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /L /C /Q',
               '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Reason := RunAclCheck(Stage, 'root');
    if Reason = '' then
      Reason := NotFilesOnly(Stage, True);
    if Reason <> '' then
    begin
      Result := NotSecuredMessage(CertDir, 'it could not be prepared: ' + Reason, True);
      Exit;
    end;
    if not RenameFile(Stage, CertDir) then
    begin
      Result := NotSecuredMessage(CertDir,
        'the prepared directory could not be moved into place (something else ' +
        'already holds the name, or the temporary folder is on another drive). If ' +
        'TEMP is on another drive, set TEMP and TMP to a folder on the system drive, ' +
        'or run the installer as SYSTEM, then run it again', True);
      Exit;
    end;
    { 5. In place: still not a link, still exactly locked, still empty. }
    Reason := RunAclCheck(CertDir, 'root');
    if Reason = '' then
      Reason := NotFilesOnly(CertDir, True);
    if Reason <> '' then
    begin
      Result := NotSecuredMessage(CertDir, Reason, True);
      Exit;
    end;
  end;

  { 6. The full check: the directory and every file in it. }
  Reason := RunAclCheck(CertDir, 'full');
  if Reason <> '' then
    Result := NotSecuredMessage(CertDir, Reason, True);
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
var
  StopResultCode: Integer;
  ResultCode: Integer;
  i: Integer;
begin
  { Establish the OTA trust-anchor directory and prove it, BEFORE any file is
    copied -- and before the service is stopped, so a refusal leaves a running
    agent running. A non-empty return aborts the install with this message and
    a non-zero exit code, so an unattended deployment records the failure. }
  Result := SecureTrustAnchorDir();
  if Result <> '' then
    Exit;
  { Stop existing service before upgrade. #1822: sc stop now actually completes
    (the agent reports SERVICE_STOP_PENDING then SERVICE_STOPPED instead of
    never responding), so poll for STOPPED instead of a blind delay -- bounded
    so a slow/loaded machine still gets there without holding up install
    indefinitely if something else goes wrong.
    sc.exe's exit code IS the underlying Win32 error (confirmed empirically:
    1060 = ERROR_SERVICE_DOES_NOT_EXIST on a fresh install, no prior service).
    Skip the poll ONLY on 1060 -- a fresh install (the dominant case, no
    YuzuAgent service yet) would otherwise burn the full 15s poll for nothing
    every single time, a real regression against the old flat 2s wait. Any
    OTHER non-zero code (e.g. 1061 ERROR_SERVICE_CANNOT_ACCEPT_CTRL, hit if the
    service is mid-transition -- already STOP_PENDING from a hung prior
    uninstall, or still START_PENDING) still means a real service that will
    eventually reach STOPPED, so it must still poll -- treating every non-zero
    code like "doesn't exist" would silently reproduce the old blind-race
    behavior for exactly the case this fix targets (Gate 3 release-deploy
    finding, governance re-run). }
  Exec('sc.exe', 'stop YuzuAgent', '', SW_HIDE, ewWaitUntilTerminated, StopResultCode);
  if StopResultCode <> 1060 then
  begin
    for i := 1 to 15 do
    begin
      Exec('cmd.exe', '/c sc query YuzuAgent | find "STOPPED" >nul', '', SW_HIDE,
           ewWaitUntilTerminated, ResultCode);
      if ResultCode = 0 then
        Break;
      Sleep(1000);
    end;
    { The install itself still proceeds either way (Result stays '') -- a stuck
      prior service is not fatal, CloseApplications=force below will forcibly
      close a still-locking yuzu-agent.exe during file copy. But a poll that
      never observed STOPPED was previously indistinguishable, in the install
      log, from one that succeeded quickly -- at fleet scale (this installer
      runs unattended via SCCM/Intune/GPO) that meant a slow/stuck-shutdown
      machine looked identical to a clean upgrade in aggregate reporting. Log it
      so a fleet log-aggregation pipeline (via /LOG=) can flag it (Gate 6 sre
      finding, governance re-run). }
    if ResultCode <> 0 then
      Log('PrepareToInstall: prior YuzuAgent service did not reach STOPPED ' +
          'within the 15s poll window; proceeding with install regardless ' +
          '(CloseApplications=force will handle a still-locked executable).');
  end;

end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Ask about the data directory only when someone can answer. A plain MsgBox
      is NOT suppressed by /SUPPRESSMSGBOXES (only SuppressibleMsgBox is), so a
      silent uninstall (SCCM/Intune/GPO, /VERYSILENT) used to wait forever on an
      invisible dialog (#5147). Silent uninstalls keep the data directory, the
      same answer as the prompt's default button. }
    if not UninstallSilent then
      if MsgBox('Remove agent data directory?' + #13#10 +
                ExpandConstant('{commonappdata}\Yuzu') + #13#10#13#10 +
                'This includes agent identity, local storage, and cached state.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(ExpandConstant('{commonappdata}\Yuzu'), True, True, True);
      end;
  end;
end;
