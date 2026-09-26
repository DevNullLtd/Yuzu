; Yuzu Agent — Windows Installer (InnoSetup 6)
; Build: ISCC.exe yuzu-agent.iss
; Silent: YuzuAgentSetup-0.7.0.exe /VERYSILENT /SERVER=myserver:50051 /TOKEN=abc123

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
; SecureTrustAnchorDir (called from PrepareToInstall, in [Code]) rebuilds the
; DACL outright and is what actually enforces this — it also runs FIRST, so by
; the time this entry is processed the directory already exists and is locked
; down, and all this adds is the two ACEs it already has.
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
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-AutologgerConfig -Name YuzuProcBoot -ErrorAction SilentlyContinue | Out-Null; New-AutologgerConfig -Name YuzuProcBoot -LogFileMode 0x2 -LocalFilePath '{commonappdata}\Yuzu\procboot.etl' -MaximumFileSize 16 -ClockType System -FlushTimer 1 -ErrorAction SilentlyContinue | Out-Null; Add-EtwTraceProvider -AutologgerName YuzuProcBoot -Guid '{{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}' -Level 4 -MatchAnyKeyword ([uint64]0x10) -ErrorAction SilentlyContinue | Out-Null; exit 0"""; StatusMsg: "Configuring boot process-capture AutoLogger..."; Flags: runhidden waituntilterminated; Components: plugins\advanced

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
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-AutologgerConfig -Name YuzuProcBoot -ErrorAction SilentlyContinue | Out-Null; Stop-EtwTraceSession -Name YuzuProcBoot -ErrorAction SilentlyContinue | Out-Null; Remove-Item '{commonappdata}\Yuzu\procboot.etl' -Force -ErrorAction SilentlyContinue | Out-Null; exit 0"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveProcBootAutologger"

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
  expands nothing -- no $variable, no subexpression -- so the quote itself is the
  only character needing care, and it is escaped by doubling.

  Note for anyone editing the comments in this file: a Pascal comment does NOT
  nest, so a closing brace written inside one ends it there and the prose after
  it is compiled as code. The .iss is only ever compiled by release.yml, never
  on a PR, so that mistake reaches the release build and nothing before it. }
function PsLit(const S: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 1 to Length(S) do
    if S[I] = '''' then
      Result := Result + ''''''
    else
      Result := Result + S[I];
  Result := '''' + Result + '''';
end;

{ Harden the OTA trust-anchor directory, then PROVE it worked.

  RUNS BEFORE ANYTHING IS INSTALLED, and that placement is the point. An earlier
  version hardened from [Run] and verified from CurStepChanged(ssPostInstall),
  which failed in two ways that only show up in a fleet deployment: a [Run]
  failure is DISMISSIBLE, and a refusal raised after the install has finished
  cannot undo it -- Setup still exits 0, so SCCM/Intune/GPO record a successful
  deployment of an agent whose trust anchor anyone can write to. Returning a
  message from PrepareToInstall instead aborts with a non-zero exit code and
  leaves nothing installed.

  WHY THE DIRECTORY IS REBUILT RATHER THAN ADDED TO. %ProgramData% grants Users
  inheritable create rights, so an unprivileged local user can create
  agent-certs before the installer runs and set an explicit ACE for themselves
  on it -- and they own it, which carries WRITE_DAC permanently, so removing
  their ACE without taking ownership lets them put it straight back. Hence
  takeown (which also enables the privilege needed to recover a directory whose
  DACL grants Administrators nothing at all), then /reset to drop every explicit
  ACE, then /inheritance:r /grant:r to drop the inherited ones and grant exactly
  Administrators and SYSTEM. /T because a file the attacker planted carries its
  own ACL and its own owner.

  `icacls /grant:r` ALONE IS NOT ENOUGH and this is the bug that shipped: it
  replaces grants only for the SIDs it NAMES, so a third SID's explicit entry
  survives it untouched.

  THE CHECK MUST COMPARE THE EXACT OWNER AND ACE SET, not a marker within the
  ACL text. The previous check tested for the inherited-ACE marker "(I)", which
  an explicit ACE does not carry -- so it passed a directory the attacker could
  still write to. Verified on Windows 11 26100: the install completed, reported
  the directory secured, and the attacker retained (OI)(CI)(F) plus ownership.
  "No inherited ACEs" is a far weaker statement than "only Administrators and
  SYSTEM can write here", and only the latter is what this directory needs.

  Identities are compared as SIDs, never as names: icacls prints localised
  account names, so matching "BUILTIN\Administrators" would silently fail open
  off an English build.

  IT MUST NOT PIPE icacls INTO find. An earlier form did:

      /C icacls "<dir>" | find "(I)" >nul && exit 1 || exit 0

  and it FAILED OPEN in exactly the case the check exists for. cmd.exe binds
  && / || to the PIPELINE's exit code -- that is `find`'s, the last command --
  not icacls's, and only icacls's stdout is piped, not its errors. So when
  icacls could not run at all (blocked by AV/EDR, or unable to read the ACL) it
  produced no "(I)"-bearing output, `find` failed to match exactly as it does
  for a genuinely secured directory, and the script reported SUCCESS.

  So: no pipe, and no inference from absence of output. The check writes its
  verdict to a file and exits 0 ONLY on a clean result; the install proceeds
  only when the exit code is 0 AND the file says PASS. Every way of NOT getting
  an answer -- PowerShell would not launch, it exited non-zero, the ACL could
  not be read, the verdict could not be read back -- FAILS CLOSED, because an
  unverifiable ACL here is indistinguishable from a bad one and a wrong
  "secured" is worse than a refusal.

  The script is passed with -Command, not -File: execution policy governs script
  FILES, so an AllSigned policy pushed by GPO would block a .ps1 here but does
  not affect -Command.

  Returns '' on success, or the operator-facing reason to abort with. }
function SecureTrustAnchorDir(): string;
var
  ResultCode: Integer;
  Ok: Boolean;
  CertDir, ReasonFile, PsExe, Script, Reason: string;
  ReasonText: AnsiString;
begin
  Result := '';
  CertDir := ExpandConstant('{commonappdata}\Yuzu\agent-certs');
  ReasonFile := ExpandConstant('{tmp}\yuzu-agent-certs-acl.txt');
  PsExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');

  { [Dirs] creates this later, which is too late to be the thing we lock down.
    On a reinstall -- or an attacker pre-creation -- it already exists. }
  if not ForceDirectories(CertDir) then
  begin
    Result := 'Could not create the update trust-anchor directory:' + #13#10 +
              CertDir + #13#10#13#10 +
              'The installation has been stopped rather than continue without it.';
    Exit;
  end;

  { Best-effort by design: each is VERIFIED below rather than trusted, so a
    blocked step surfaces as a specific verification failure, which tells the
    operator more than this step's own exit code would. }
  Ok := Exec(ExpandConstant('{sys}\takeown.exe'),
             '/F "' + CertDir + '" /A /R /D Y',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Ok := Exec(ExpandConstant('{sys}\icacls.exe'),
             '"' + CertDir + '" /reset /T /C /Q',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Ok := Exec(ExpandConstant('{sys}\icacls.exe'),
             '"' + CertDir + '" /inheritance:r /grant:r ' +
             '"*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /T /C /Q',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  { Built from plain literals so any braces stay literal -- Inno expands a
    brace-delimited constant only inside ExpandConstant, which is applied to the
    paths separately above. }
  Script :=
    '$ErrorActionPreference=''Stop'';' +
    '$d=' + PsLit(CertDir) + ';' +
    '$out=' + PsLit(ReasonFile) + ';' +
    '$ok=@(''S-1-5-32-544'',''S-1-5-18'');' +
    'function Fail($m){Set-Content -LiteralPath $out -Value $m -Encoding ASCII;exit 3};' +
    'try{$a=Get-Acl -LiteralPath $d}catch{Fail (''the permissions could not be read: '' + $_.Exception.Message)};' +
    'if(-not $a.AreAccessRulesProtected){Fail ''it still inherits permissions from ProgramData''};' +
    '$t=@($d);' +
    'try{$t+=@(Get-ChildItem -LiteralPath $d -Recurse -Force|ForEach-Object{$_.FullName})}catch{Fail ''its contents could not be listed''};' +
    'foreach($p in $t){' +
      'try{$x=Get-Acl -LiteralPath $p}catch{Fail (''the permissions could not be read on '' + $p)};' +
      '$o=$x.GetOwner([System.Security.Principal.SecurityIdentifier]).Value;' +
      'if($ok -notcontains $o){Fail (''it is owned by '' + $o + '': '' + $p)};' +
      'foreach($r in $x.Access){' +
        'try{$s=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}' +
        'catch{Fail (''an account on its permission list could not be resolved: '' + $p)};' +
        'if($ok -notcontains $s){Fail (''access is granted to '' + $s + '': '' + $p)}' +
      '}' +
    '};' +
    'Set-Content -LiteralPath $out -Value ''PASS'' -Encoding ASCII;' +
    'exit 0';

  if not Exec(PsExe,
              '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := 'Could not run the permission check on:' + #13#10 + CertDir + #13#10#13#10 +
              'The update trust-anchor directory could not be verified, so the ' +
              'installation has been stopped rather than report it secured without ' +
              'having checked. Confirm manually that only Administrators and SYSTEM ' +
              'have access to it, then re-run the installer.';
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
    Result := 'The update trust-anchor directory is not secured:' + #13#10 +
              CertDir + #13#10#13#10 + Reason + #13#10#13#10 +
              'Only Administrators and SYSTEM may have access to it. While anyone ' +
              'else can write there, they can install their own trust bundle and ' +
              'authorise their own agent updates. Securing it did not take effect -- ' +
              'security software may have blocked it. The installation has been stopped.';
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
var
  StopResultCode: Integer;
  ResultCode: Integer;
  i: Integer;
begin
  Result := '';
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

  { Lock the OTA trust-anchor directory down and prove it, BEFORE any file is
    copied. A non-empty return aborts the install with this message and a
    non-zero exit code, so an unattended deployment records the failure. }
  Result := SecureTrustAnchorDir();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Ask about data directory }
    if MsgBox('Remove agent data directory?' + #13#10 +
              ExpandConstant('{commonappdata}\Yuzu') + #13#10#13#10 +
              'This includes agent identity, local storage, and cached state.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    begin
      DelTree(ExpandConstant('{commonappdata}\Yuzu'), True, True, True);
    end;
  end;
end;
