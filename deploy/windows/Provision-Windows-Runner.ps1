#Requires -RunAsAdministrator
<#
  Provision-Windows-Runner.ps1 — versioned, idempotent spec for a Yuzu native
  Windows CI build host. This is the Windows analog of
  deploy/docker/Dockerfile.ci-linux: the single source of truth for what a
  Windows runner's toolchain must contain. Run it on a fresh box (or re-run to
  reconcile) and you get a runner that matches every other Windows runner —
  no per-host archaeology.

  RUN IN AN ELEVATED PowerShell 7 (pwsh) SESSION over RDP / console. winget's
  source catalog does not work over headless SSH, so this is hand-run, not
  agent-run.

  What it does:
    - installs the pinned toolchain (Python+Meson+Ninja, Git, CMake, ccache,
      MSYS2, Erlang/OTP + rebar3, VS 2022 Build Tools C++ workload,
      PostgreSQL — ONE cluster per runner agent on :PostgresPort+agentIdx so
      concurrent jobs never share a WAL/buffer pool (#2094) — vcpkg @ pinned
      baseline);
    - sets machine env + PATH, INCLUDING the de-Shulgi-ified gateway contract
      (YUZU_ESCRIPT / YUZU_REBAR3 — scripts/build_gateway.py reads these instead
      of assuming a C:\Erlang junction + Chocolatey path) and the shared CI
      cache location (RUNNER_TOOL_CACHE -> one machine-level dir so the 4
      CCD-pinned runners share ONE vcpkg binary cache instead of fragmenting it
      4x; mirrors CCACHE_DIR);
    - emits a machine-readable toolchain manifest that
      deploy/windows/Assert-Toolchain.ps1 (the runner self-test) verifies at
      registration, so a mis-provisioned box fails in seconds, not 90 min into
      a build.

  After this, register the runners + the CCD-pin wrapper — see
  deploy/windows/README.md and deploy/windows/Start-PinnedRunner.ps1.
#>
[CmdletBinding()]
param(
  # --- pinned toolchain versions (the "spec"); bump deliberately ---
  [string]$PythonVersion   = '3.14.6',
  [string]$MesonVersion    = '1.11.1',   # CLAUDE.md build minimum
  [string]$ErlangVersion   = '28.4.2',
  [string]$Rebar3Version   = '3.24.0',
  [string]$PostgresVersion = '18.4',
  [ValidateSet('10.0.26100.0')][string]$WindowsSdkVersion = '10.0.26100.0',
  [string]$VcpkgBaseline   = '4b77da7fed37817f124936239197833469f1b9a8',  # == vcpkg.json builtin-baseline

  # --- machine layout (conventions; keep in sync with Start-PinnedRunner.ps1) ---
  [string]$CacheRoot       = 'D:\ci',     # ccache + shared tool_cache live here (fast data drive)
  [string]$Rebar3Dir       = 'C:\tools\rebar3',
  [string]$VcpkgRoot       = 'C:\vcpkg',
  [string]$Msys2Root       = 'C:\msys64',
  [int]   $PostgresPort    = 5433,
  [int]   $PostgresMaxConnections = 400,  # PgPool fan-out headroom: the default 100 exhausts (CH-9)
  [int]   $RunnerCount     = 4,           # agents on this box; agents 1..N-1 get per-agent PG clusters (#2094)
  [ValidateSet(16)][int] $BuildJobs       = 16,          # fixed 9970X CCD envelope: 8C/16T, consumed as meson compile -j
  [string]$ManifestPath    = 'C:\actions-runner\toolchain-manifest.json',

  # Escape hatch for the maintenance gate below. Provisioning restarts shared
  # services and rewrites machine env under whatever is running; the gate
  # refuses to start while any runner process is live. This switch only SKIPS
  # the check — it stops no runner and kills no job. Pass it only when you
  # accept that a live CI job on this box may be interrupted.
  [switch]$AllowActiveRunners
)
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# The committed contract is the reviewed version policy. Keep the familiar
# provisioning parameters for operator ergonomics, but refuse an ad-hoc
# override: update the contract in review first, then provision from it.
$toolchainContractPath = Join-Path $PSScriptRoot 'toolchain-contract.json'
$toolchainModulePath = Join-Path $PSScriptRoot 'Toolchain-Contract.psm1'
try {
  Import-Module $toolchainModulePath -Force -ErrorAction Stop
  $toolchainContract = Read-YuzuToolchainContract -Path $toolchainContractPath
} catch {
  Write-Host "FAIL: cannot load the toolchain contract/module ($($_.Exception.Message))" -ForegroundColor Red
  exit 1
}
if([string]$toolchainContract.schema -ne 'yuzu/windows-toolchain/v1'){
  Write-Host "FAIL: unsupported toolchain contract schema '$($toolchainContract.schema ?? '<unset>')'" -ForegroundColor Red
  exit 1
}
$requestedPins = [ordered]@{
  python=$PythonVersion
  meson=$MesonVersion
  erlang=$ErlangVersion
  rebar3=$Rebar3Version
  postgres=$PostgresVersion
  windows_sdk=$WindowsSdkVersion
  vcpkg_baseline=$VcpkgBaseline
}
foreach($pin in $requestedPins.GetEnumerator()){
  $expected = if($pin.Key -eq 'vcpkg_baseline'){
    [string]$toolchainContract.job_pins.vcpkg_baseline
  } else {
    [string]$toolchainContract.pins.($pin.Key)
  }
  if(-not [string]::Equals([string]$pin.Value, $expected, [StringComparison]::OrdinalIgnoreCase)){
    Write-Host "FAIL: requested $($pin.Key) '$($pin.Value)' differs from reviewed contract '$expected'; update toolchain-contract.json first." -ForegroundColor Red
    exit 1
  }
}

New-Item -ItemType Directory -Force 'C:\ProvisionLogs' | Out-Null
Start-Transcript -Path "C:\ProvisionLogs\provision-$(Get-Date -Format yyyyMMdd-HHmmss).log" | Out-Null

$script:failedSteps = @()
function Step([string]$name,[scriptblock]$body){
  # Every Step still runs regardless of an earlier one's failure (unchanged
  # semantics) - only the PROCESS exit code changes. Before this, a failed
  # Step printed red [FAIL] but the script always exited 0, so nothing
  # calling this non-interactively (a wrapper, a scheduled reconciliation
  # job) could tell success from failure - adversarial review v2 F3',
  # PR #2167. $script: is required: Step is a function, so a bare
  # $failedSteps assignment in the catch below would be local to that one
  # call and never accumulate across Step() invocations.
  # NOTE for anyone adding a stop-the-world condition here: do NOT signal it by
  # throwing something this catch is expected to recognise. That design (a
  # string-tagged exception) shipped and produced two blockers — one handler
  # swallowed the tag, another stripped it by re-wrapping. Abort the PROCESS
  # from where you detect it (see Assert-RunnersDrained); `exit` is not
  # catchable here, so it cannot be swallowed by this or any other handler.
  Write-Host "`n===== $name =====" -ForegroundColor Cyan
  try   { & $body; Write-Host "[OK]  $name" -ForegroundColor Green }
  catch {
    Write-Host "[FAIL] $name :: $($_.Exception.Message)" -ForegroundColor Red
    $script:failedSteps += $name
  }
}
function WG([string]$id,[string]$ver='',[string]$override='',[string]$scope='machine',[switch]$EnforceExitPolicy){
  $a=@('install','--id',$id,'-e','--source','winget','--accept-source-agreements','--accept-package-agreements','--disable-interactivity')
  if($ver)     { $a+=@('--version',$ver) }
  if($scope)   { $a+=@('--scope',$scope) }
  if($override){ $a+=@('--override',$override) }
  Write-Host ("winget " + ($a -join ' '))
  winget @a
  if($EnforceExitPolicy){
    $wingetExitCode = $LASTEXITCODE
    Invoke-YuzuInstallerExitPolicy -ExitCode $wingetExitCode -Context "winget install $id" `
      -RebootHandler { param($context,$exitCode) Stop-YuzuProvisioningForReboot "$context returned $exitCode" }
  }
}
function Stop-YuzuProvisioningForReboot([string]$context){
  Write-Host "REBOOT REQUIRED ($context): keep every runner drained, reboot this host, then rerun provisioning and Assert-Toolchain.ps1 before registration." -ForegroundColor Yellow
  try { Stop-Transcript | Out-Null } catch {}
  exit 3
}
function Add-MachinePath([string]$dir){
  if(-not (Test-Path $dir)){ return }
  $p=[Environment]::GetEnvironmentVariable('Path','Machine')
  if($p -notmatch [regex]::Escape($dir)){
    [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';')+';'+$dir), 'Machine')
    Write-Host "PATH (machine) += $dir"
  }
}
function Set-MachineEnv([string]$k,[string]$v){ [Environment]::SetEnvironmentVariable($k,$v,'Machine'); Write-Host "$k = $v" }
function Find-RealEscript {
  # The real erts escript.exe (NOT the top-level launcher stub — see
  # scripts/build_gateway.py for why). Search common OTP install roots.
  $roots = @('C:\Erlang') + (Get-ChildItem 'C:\Program Files' -Directory -EA SilentlyContinue |
            Where-Object { $_.Name -like 'Erlang*' -or $_.Name -like 'erl*' } | ForEach-Object FullName)
  foreach($r in $roots){
    $e = Get-ChildItem $r -Filter escript.exe -Recurse -EA SilentlyContinue |
         Where-Object { $_.DirectoryName -match 'erts-' } | Select-Object -First 1
    if($e){ return $e.FullName }
  }
  return $null
}
function Get-ActiveRunnerProcess {
  # OBSERVATION ONLY — no policy. Runner.Listener.exe polls GitHub for work and
  # spawns one Runner.Worker.exe per accepted job. Looking for the WORKER alone
  # is a point-in-time snapshot, not a lock: a listener that is idle at the
  # instant we look can accept a job a second later, while we are still copying
  # trees and restarting clusters. Including the LISTENER closes that window —
  # no listener, no job can start.
  # Throws if WMI/DCOM/permissions make the box unobservable. Callers decide
  # what that means; Assert-RunnersDrained treats it as fatal.
  @(Get-CimInstance Win32_Process `
      -Filter "Name = 'Runner.Listener.exe' OR Name = 'Runner.Worker.exe'" -EA Stop)
}
function Assert-RunnersDrained([string]$context){
  # THE gate. It EXITS the process rather than throwing, deliberately: `exit` is
  # not catchable by any enclosing try/catch (not Step()'s, not the per-agent
  # loop's, not the rollback recovery's), so a detection here cannot be
  # swallowed, re-wrapped, or downgraded by a handler between us and the top of
  # the script. The previous design threw a string-tagged exception that every
  # intervening catch had to recognise and re-throw; two of them didn't, and
  # both were shipped blockers. Do not convert this back to a throw.
  if($AllowActiveRunners){
    Write-Warning "-AllowActiveRunners: skipping the drain check ($context). Nothing is stopped — any live CI job on this box may be interrupted."
    return
  }
  $reason = $null
  try {
    $active = Get-ActiveRunnerProcess
    if($active.Count -gt 0){
      $detail = ($active | Sort-Object Name,ProcessId |
                 ForEach-Object { "$($_.Name)($($_.ProcessId))" }) -join ', '
      $reason = "$context while GitHub Actions runners are live on this box: $detail"
    }
  } catch {
    # Fail CLOSED: "I cannot tell whether this box is busy" is not permission to
    # mutate it. A gate that proceeds when it cannot observe is not a gate.
    $reason = "$context — the drain check itself failed ($($_.Exception.Message)), so this box cannot be shown to be idle"
  }
  if($null -eq $reason){ return }
  Write-Host "`n[ABORT] $reason" -ForegroundColor Red
  Write-Host ("Stop all $RunnerCount Start-PinnedRunner tasks/consoles, wait for in-flight jobs " +
              "to finish, then re-run. -AllowActiveRunners skips this check without stopping " +
              "anything — those jobs may then be interrupted.") -ForegroundColor Red
  Write-Host "Provisioning stopped: no further steps run." -ForegroundColor Red
  try {
    Stop-Transcript -EA Stop | Out-Null
  } catch {
    Write-Warning "Provisioning is still aborting, but the transcript could not be closed cleanly: $($_.Exception.Message)"
  }
  exit 2
}

function Test-PgServingNow([string]$bin,[int]$port){
  # Single-shot liveness probe — deliberately NOT Assert-PgServing's 90s wait
  # loop. Answers one question: is a postmaster serving this port RIGHT NOW?
  # Used on the rollback path to tell "the cluster is down, restarting it can
  # only help" from "the cluster is still up and a restart would drop live
  # connections".
  $ready = Join-Path $bin 'pg_isready.exe'
  if(-not (Test-Path $ready)){ return $false }
  & $ready -q -h 127.0.0.1 -p $port 2>$null
  return ($LASTEXITCODE -eq 0)
}
function Assert-PgServing([string]$bin,[int]$port,[string]$context){
  # Script-scoped so EVERY cluster restart can prove it came back — the main
  # PostgreSQL step's as well as the per-agent ones, which is why this is not
  # nested inside a single Step.
  $ready = Join-Path $bin 'pg_isready.exe'
  $psql  = Join-Path $bin 'psql.exe'
  if(-not (Test-Path $ready)){ throw "$context missing $ready" }
  if(-not (Test-Path $psql)){ throw "$context missing $psql" }
  $deadline=(Get-Date).AddSeconds(90)
  do {
    & $ready -q -h 127.0.0.1 -p $port 2>$null
    if($LASTEXITCODE -eq 0){ break }
    Start-Sleep 2
  } while((Get-Date) -lt $deadline)
  if($LASTEXITCODE -ne 0){ throw "$context cluster on :$port not ready in 90s" }
  $oldPassword = $env:PGPASSWORD
  $env:PGPASSWORD='postgres'
  try {
    $probe = (& $psql -U postgres -h 127.0.0.1 -p $port -tAc 'SELECT 1' 2>$null | Out-String).Trim()
    if($LASTEXITCODE -ne 0 -or $probe -ne '1'){
      throw "$context SELECT 1 failed on :$port"
    }
  } finally {
    if($null -eq $oldPassword){ Remove-Item Env:\PGPASSWORD -EA SilentlyContinue }
    else { $env:PGPASSWORD = $oldPassword }
  }
}

# ---- Maintenance gate: must precede EVERY Step ------------------------------
# Wee Tam's four runner agents share ONE OS identity on ONE box (CLAUDE.md
# standing invariant), so a service restart or machine-env rewrite here is a
# cross-JOB mutation, not a local one. Several steps below force-restart a
# shared PostgreSQL service and toolchain installs swap binaries under a running
# build, so check before any of them. This is the FIRST of several checks, not
# the only one: it can be minutes stale by the time a service actually restarts,
# so every Restart-Service re-asserts. It is a check, not a lock — an operator
# who starts a runner mid-run is not prevented, only detected at the next check.
Assert-RunnersDrained 'refusing to provision'

Step 'winget sanity' { "winget " + (winget --version) }

Step 'Python + Meson + Ninja + PyYAML' {
  # PyYAML is a HARD configure-time dep (embed_content.py); install it apt-style.
  $python = Resolve-YuzuPinnedPython -ExpectedVersion $PythonVersion `
    -CommandResolver { try { Resolve-YuzuEffectiveCommand -Name python } catch { '' } } `
    -VersionProbe { param([string]$path) & $path -c 'import platform; print(platform.python_version())' 2>$null } `
    -Installer { WG -id 'Python.Python.3.14' -ver $PythonVersion }
  $py = $python.Path
  if($py){
    & $py -m pip install --upgrade pip | Out-Null
    & $py -m pip install "meson==$MesonVersion" ninja pyyaml | Out-Null
  } else { throw 'python not found after install' }
}

Step 'Persistent per-runner CI telemetry databases' {
  $py = @(Get-Command python -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source
  $testDbScript = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')) 'scripts\test\test_db.py'
  if(-not $py){ throw 'python is required to initialize CI telemetry' }
  if(-not (Test-Path $testDbScript)){ throw "test DB schema tool missing at $testDbScript" }
  $oldDb = $env:YUZU_TEST_DB
  try {
    for($n=0; $n -lt $RunnerCount; $n++){
      $runnerName = "yuzu-weetam-windows-$n"
      $db = Join-Path (Join-Path "$CacheRoot\test-runs" $runnerName) 'test-runs.db'
      New-Item -ItemType Directory -Force (Split-Path $db) | Out-Null
      $env:YUZU_TEST_DB = $db
      & $py $testDbScript init
      if($LASTEXITCODE -ne 0){ throw "test-runs.db initialization failed for $runnerName at $db" }
      Write-Host "$runnerName telemetry: $db"
    }
  } finally {
    if($null -eq $oldDb){ Remove-Item Env:\YUZU_TEST_DB -EA SilentlyContinue }
    else { $env:YUZU_TEST_DB = $oldDb }
  }
}

Step 'Deploy versioned runner control scripts' {
  $controlRoot = Split-Path $ManifestPath
  New-Item -ItemType Directory -Force $controlRoot | Out-Null
  foreach($name in @('Start-PinnedRunner.ps1','Assert-Toolchain.ps1','Update-ToolchainManifest.ps1','Toolchain-Contract.psm1','toolchain-contract.json')){
    $source = Join-Path $PSScriptRoot $name
    if(-not (Test-Path $source)){ throw "runner control script missing at $source" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $controlRoot $name) -Force
  }
  "runner control scripts deployed to $controlRoot"
}

Step 'Git + CMake' {
  if(-not (Get-Command git   -EA SilentlyContinue)){ WG -id 'Git.Git' }
  if(-not (Get-Command cmake -EA SilentlyContinue)){ WG -id 'Kitware.CMake' }
}

Step 'ccache' {
  if(Get-Command ccache -EA SilentlyContinue){ 'already on PATH' } else { WG -id 'ccache.ccache' }
}

Step "MSYS2 (CI shell = $Msys2Root\usr\bin\bash.exe)" {
  if(-not (Test-Path "$Msys2Root\usr\bin\bash.exe")){ WG -id 'MSYS2.MSYS2' }
  if(Test-Path "$Msys2Root\usr\bin\bash.exe"){ 'bash present' } else { throw "MSYS2 not at $Msys2Root" }
}

Step "Erlang/OTP $ErlangVersion" {
  $erl = Get-ChildItem 'C:\Program Files\Erlang*','C:\Program Files\erl*' -Filter erl.exe -Recurse -EA SilentlyContinue | Select-Object -First 1
  if(-not $erl){ WG -id 'Erlang.ErlangOTP' -ver $ErlangVersion
                 $erl = Get-ChildItem 'C:\Program Files\Erlang*','C:\Program Files\erl*' -Filter erl.exe -Recurse -EA SilentlyContinue | Select-Object -First 1 }
  if($erl){ Add-MachinePath $erl.DirectoryName; "erl: $($erl.FullName)" } else { throw 'erl.exe not found after install' }
}

Step "rebar3 $Rebar3Version (de-Shulgi-ified: env vars, NOT a C:\Erlang junction)" {
  New-Item -ItemType Directory -Force $Rebar3Dir | Out-Null
  if(-not (Test-Path "$Rebar3Dir\rebar3")){
    Invoke-WebRequest -UseBasicParsing "https://github.com/erlang/rebar3/releases/download/$Rebar3Version/rebar3" -OutFile "$Rebar3Dir\rebar3"
  }
  Set-Content "$Rebar3Dir\rebar3.cmd" '@escript "%~dp0rebar3" %*' -Encoding Ascii
  Add-MachinePath $Rebar3Dir
  # scripts/build_gateway.py resolves the gateway toolchain from these env vars
  # (YUZU_ESCRIPT / YUZU_REBAR3), so we no longer replicate Shulgi's C:\Erlang
  # junction or the Chocolatey rebar3 path. THIS is the de-hardcoding fix (B1).
  $escript = Find-RealEscript
  if(-not $escript){ throw 'real erts escript.exe not found' }
  Set-MachineEnv 'YUZU_ESCRIPT' $escript
  Set-MachineEnv 'YUZU_REBAR3'  "$Rebar3Dir\rebar3"
  "escript: $escript ; rebar3: $Rebar3Dir\rebar3"
}

Step "VS 2022 Build Tools (C++ workload + Windows SDK $WindowsSdkVersion)" {
  $vsw="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $have = if(Test-Path $vsw){ (& $vsw -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1) } else { $null }
  $sdkComponent = 'Microsoft.VisualStudio.Component.Windows11SDK.26100'
  $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
  $sdkHeader = Join-Path $sdkRoot "Include\$WindowsSdkVersion\um\Windows.h"
  $sdkLib = Join-Path $sdkRoot "Lib\$WindowsSdkVersion\um\x64\kernel32.lib"
  $sdkRc = Join-Path $sdkRoot "bin\$WindowsSdkVersion\x64\rc.exe"
  if(-not $have){
    WG -id 'Microsoft.VisualStudio.2022.BuildTools' -scope '' `
       -override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --add $sdkComponent" `
       -EnforceExitPolicy
    $have = if(Test-Path $vsw){ (& $vsw -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1) } else { $null }
  }
  if(-not $have){ throw 'VS 2022 C++ Build Tools not found after install' }

  # An existing Build Tools instance may predate this contract. `winget
  # install` reports it as already installed and does not add a component, so
  # modify the selected instance explicitly when the pinned SDK is absent.
  if(-not (Test-Path -LiteralPath $sdkHeader) -or
     -not (Test-Path -LiteralPath $sdkLib) -or
     -not (Test-Path -LiteralPath $sdkRc)){
    $installer = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe"
    if(-not (Test-Path -LiteralPath $installer)){ throw "Visual Studio Installer not found at $installer" }
    $proc = Start-Process -FilePath $installer -ArgumentList @(
      'modify','--installPath',('"' + $have + '"'),'--add',$sdkComponent,'--quiet','--norestart'
    ) -Wait -PassThru
    Invoke-YuzuInstallerExitPolicy -ExitCode $proc.ExitCode -Context 'Visual Studio Installer modify' `
      -RebootHandler { param($context,$exitCode) Stop-YuzuProvisioningForReboot "$context returned $exitCode" }
  }
  if(-not (Test-Path -LiteralPath $sdkHeader)){ throw "pinned Windows SDK header missing: $sdkHeader" }
  if(-not (Test-Path -LiteralPath $sdkLib)){ throw "pinned Windows SDK library missing: $sdkLib" }
  if(-not (Test-Path -LiteralPath $sdkRc)){ throw "pinned Windows SDK resource compiler missing: $sdkRc" }
  "VS: $have ; Windows SDK: $WindowsSdkVersion"
}

Step "PostgreSQL $PostgresVersion (service :$PostgresPort, role yuzu, db yuzu_test)" {
  $major = $PostgresVersion.Split('.')[0]
  # Prefer an EXISTING install, whatever its layout: Wee Tam ships a zip install
  # at C:\pgsql\bin, a winget install lands in Program Files. Hardcoding the
  # Program Files path made the per-agent step throw "initdb not found" on Wee
  # Tam — why #2094 was never provisioned there. Fall back to the winget target
  # for a fresh box where psql does not exist yet (the agent-0 step installs it).
  $pgbin = @("C:\pgsql\bin","C:\Program Files\PostgreSQL\$major\bin") | Where-Object { Test-Path (Join-Path $_ 'psql.exe') } | Select-Object -First 1
  if(-not $pgbin){ $pgbin = "C:\Program Files\PostgreSQL\$major\bin" }
  if(-not (Test-Path "$pgbin\psql.exe")){
    WG -id "PostgreSQL.PostgreSQL.$major" -ver $PostgresVersion -scope '' `
       -override "--mode unattended --unattendedmodeui none --superpassword postgres --servicename postgresql-x64-$major-yuzu-ci --serverport $PostgresPort"
  }
  if(-not (Test-Path "$pgbin\psql.exe")){ throw "psql not found at $pgbin" }
  $svc = "postgresql-x64-$major-yuzu-ci"
  $deadline=(Get-Date).AddSeconds(90)
  while(((Get-Service $svc -EA SilentlyContinue).Status -ne 'Running') -and ((Get-Date) -lt $deadline)){ Start-Sleep 2 }
  $env:PGPASSWORD='postgres'
  # try/finally so Remove-Item runs on every exit path, including a throw from
  # the LASTEXITCODE checks below - same PGPASSWORD-leak class of bug the
  # per-agent block below was fixed for; agent-0 gets the identical guard for
  # sibling parity (Gate 4 consistency-auditor review of PR #2167).
  try {
    $psql="$pgbin\psql.exe"; $H=@('-U','postgres','-h','127.0.0.1','-p',"$PostgresPort")
    if((& $psql @H -tAc 'SELECT 1 FROM pg_roles WHERE rolname=''yuzu''') -ne '1'){
      & $psql @H -c 'CREATE ROLE yuzu LOGIN SUPERUSER PASSWORD ''yuzu'''
    }
    if((& $psql @H -tAc 'SELECT 1 FROM pg_database WHERE datname=''yuzu_test''') -ne '1'){
      & $psql @H -c 'CREATE DATABASE yuzu_test OWNER yuzu'
    }
    # Tune for the shared 4-runner instance: server-test suites across concurrent
    # CCD-pinned runners exhaust the default max_connections=100, so PgPool.acquire()
    # returns an empty lease (the CH-9 [pg][chaos] flake). logging_collector=on so a
    # future exhaustion is diagnosable (off by default leaves no log files). Both are
    # postmaster params -> restart to apply. Idempotent (ALTER SYSTEM -> auto.conf).
    # $LASTEXITCODE is checked explicitly - see the per-agent block below for why
    # $ErrorActionPreference='Continue' alone doesn't catch a failed psql.exe here.
    & $psql @H -c "ALTER SYSTEM SET max_connections = $PostgresMaxConnections"
    if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET max_connections failed" }
    & $psql @H -c 'ALTER SYSTEM SET logging_collector = on'
    if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET logging_collector failed" }
    # Disposable CI cluster -> durability OFF. Every [pg] test does CREATE DATABASE
    # ... TEMPLATE + DROP DATABASE WITH (FORCE), both fsync-heavy, and Windows fsync
    # is ~20x costlier than Linux (the 2026-07-14 Wee Tam 600s [pg]-shard TIMEOUTs).
    # A crash just re-runs the job. Removing these re-arms the timeout. All three
    # are sighup/user context, so applying them to a LIVE cluster needs only a
    # reload (`SELECT pg_reload_conf()`), no restart — the restart below is for
    # max_connections (postmaster) and applies these in passing.
    & $psql @H -c 'ALTER SYSTEM SET fsync = off'
    if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET fsync=off failed" }
    & $psql @H -c 'ALTER SYSTEM SET synchronous_commit = off'
    if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET synchronous_commit=off failed" }
    & $psql @H -c 'ALTER SYSTEM SET full_page_writes = off'
    if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET full_page_writes=off failed" }
  } finally {
    Remove-Item Env:\PGPASSWORD -EA SilentlyContinue
  }
  # Agent 0's cluster is shared with whatever else is on this box. The
  # script-start gate can be arbitrarily stale by now — every winget toolchain
  # install runs between it and here, real minutes on a cold box — so re-assert
  # immediately before dropping this service's live connections.
  Assert-RunnersDrained "refusing to restart $svc"
  Restart-Service $svc -Force -EA Stop
  $deadline=(Get-Date).AddSeconds(90)
  while(((Get-Service $svc -EA SilentlyContinue).Status -ne 'Running') -and ((Get-Date) -lt $deadline)){ Start-Sleep 2 }
  # The wait loop used to fall through silently on timeout, reporting the
  # cluster "ready" while the service was stopped. Match the per-agent step's
  # posture exactly: Running is necessary but not sufficient, so prove it
  # actually serves before calling this step OK.
  if((Get-Service $svc -EA SilentlyContinue).Status -ne 'Running'){
    throw "$svc did not return to Running within 90s of the restart"
  }
  Assert-PgServing $pgbin $PostgresPort "main PostgreSQL cluster"
  "PG $PostgresVersion on :$PostgresPort, role yuzu, db yuzu_test ready (max_connections=$PostgresMaxConnections, logging_collector=on)"
}

Step "PostgreSQL per-agent clusters — agents 1..$($RunnerCount-1), ports $($PostgresPort+1)..$($PostgresPort+$RunnerCount-1) (#2094)" {
  # One instance PER runner agent: concurrent jobs sharing one cluster
  # mutually DoS their [pg] server suites through the shared WAL/buffer pool
  # (the 2026-07-12 server-suite timeouts). Agent 0 keeps the winget-installed
  # service on :$PostgresPort (step above); agents 1..N-1 each get an initdb'd
  # cluster + Windows service here. scripts/ci/ensure-postgres.sh derives
  # "base port + agent index" from RUNNER_NAME at job time and probes before
  # switching, so no runner .env / wrapper / re-registration is needed —
  # provisioning these clusters IS the whole cutover.
  $major = $PostgresVersion.Split('.')[0]
  # Prefer an EXISTING install, whatever its layout: Wee Tam ships a zip install
  # at C:\pgsql\bin, a winget install lands in Program Files. Hardcoding the
  # Program Files path made the per-agent step throw "initdb not found" on Wee
  # Tam — why #2094 was never provisioned there. Fall back to the winget target
  # for a fresh box where psql does not exist yet (the agent-0 step installs it).
  $pgbin = @("C:\pgsql\bin","C:\Program Files\PostgreSQL\$major\bin") | Where-Object { Test-Path (Join-Path $_ 'psql.exe') } | Select-Object -First 1
  if(-not $pgbin){ $pgbin = "C:\Program Files\PostgreSQL\$major\bin" }
  if(-not (Test-Path "$pgbin\initdb.exe")){ throw "initdb not found at $pgbin — the main PostgreSQL step must succeed first" }
  $pw = Join-Path $env:TEMP 'yuzu-pg-pwfile.txt'
  Set-Content $pw 'postgres' -Encoding Ascii
  try {
    $failedAgents = @()
    for($n=1; $n -lt $RunnerCount; $n++){
      $port = $PostgresPort + $n
      $data = "$CacheRoot\pg\agent-$n"
      $svc  = "postgresql-x64-$major-yuzu-ci-$n"
      # Catch PER AGENT, not just per-call: one agent's failure (initdb,
      # service-not-ready, or an ALTER SYSTEM/reload check below) must not
      # abort provisioning for agents n+1..RunnerCount-1 - that would
      # silently leave them un-tuned with no signal beyond this one agent's
      # error, reproducing on a subset of runners the exact [pg]-shard
      # timeout this PR exists to fix, with no automated detection (Gate 4
      # unhappy-path UP-2/UP-3, PR #2167). Record and continue; the
      # accumulated failure list after the loop still throws once, naming
      # every failed agent, so this isn't silently swallowed either.
      try {
        if(-not (Test-Path "$data\PG_VERSION")){
          New-Item -ItemType Directory -Force $data | Out-Null
          # initdb/pg_ctl drop admin rights via a restricted token, so the
          # invoking user needs an EXPLICIT grant (its Administrators ACE no
          # longer applies); NETWORK SERVICE (S-1-5-20 — the same account the
          # EDB-installed agent-0 service runs as) owns the cluster at runtime.
          icacls $data /grant "$($env:USERNAME):(OI)(CI)F" | Out-Null
          icacls $data /grant '*S-1-5-20:(OI)(CI)F' | Out-Null
          & "$pgbin\initdb.exe" -D $data -U postgres -A password --pwfile=$pw -E UTF8 | Out-Null
          if(-not (Test-Path "$data\PG_VERSION")){ throw "initdb failed for $data" }
          # Durability off — disposable CI cluster (see the agent-0 tune block above).
          Add-Content "$data\postgresql.conf" "`n# yuzu CI per-agent cluster $n (#2094)`nlisten_addresses = '127.0.0.1'`nport = $port`nmax_connections = $PostgresMaxConnections`nlogging_collector = on`nfsync = off`nsynchronous_commit = off`nfull_page_writes = off`n"
        }
        if(-not (Get-Service $svc -EA SilentlyContinue)){
          & "$pgbin\pg_ctl.exe" register -N $svc -D $data -S auto -U 'NT AUTHORITY\NetworkService'
        }
        Start-Service $svc
        $deadline=(Get-Date).AddSeconds(90)
        do {
          & "$pgbin\pg_isready.exe" -q -h 127.0.0.1 -p $port 2>$null
          if($LASTEXITCODE -eq 0){ break }
          Start-Sleep 2
        } while((Get-Date) -lt $deadline)
        if($LASTEXITCODE -ne 0){ throw "cluster on :$port not ready in 90s (svc $svc, data $data)" }
        $env:PGPASSWORD='postgres'
        # $env:PGPASSWORD is process-scoped, not scriptblock-scoped, so every
        # exit out of this span - including a throw from the LASTEXITCODE
        # checks below - must go through Remove-Item, or the password stays
        # set (and inheritable by child processes) for every later Step in
        # this same PowerShell process. try/finally, not a bare Remove-Item
        # at the bottom, so a throw still cleans up.
        try {
          $psql="$pgbin\psql.exe"; $H=@('-U','postgres','-h','127.0.0.1','-p',"$port")
          if((& $psql @H -tAc 'SELECT 1 FROM pg_roles WHERE rolname=''yuzu''') -ne '1'){
            & $psql @H -c 'CREATE ROLE yuzu LOGIN SUPERUSER PASSWORD ''yuzu'''
          }
          if((& $psql @H -tAc 'SELECT 1 FROM pg_database WHERE datname=''yuzu_test''') -ne '1'){
            & $psql @H -c 'CREATE DATABASE yuzu_test OWNER yuzu'
          }
          # Durability off - applied UNCONDITIONALLY (not only inside the initdb
          # guard above) so re-provisioning an EXISTING per-agent cluster also
          # picks up the tuning; a cluster provisioned before this PR landed
          # would otherwise keep fsync=on forever and keep hitting the
          # [pg]-shard timeout on its port. Mirrors the agent-0 tune block
          # above. All three are sighup/user context -> reload suffices, no
          # restart needed. $LASTEXITCODE is checked explicitly:
          # $ErrorActionPreference='Continue' does not intercept a native
          # exe's nonzero exit on this PS 5.1 host, so an unchecked psql.exe
          # failure here would silently leave durability ON while the loop
          # still reports the agent "ready" - exactly the kind of swallowed
          # failure this PR's other fixes are closing elsewhere.
          & $psql @H -c 'ALTER SYSTEM SET fsync = off'
          if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET fsync=off failed on agent $n (:$port)" }
          & $psql @H -c 'ALTER SYSTEM SET synchronous_commit = off'
          if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET synchronous_commit=off failed on agent $n (:$port)" }
          & $psql @H -c 'ALTER SYSTEM SET full_page_writes = off'
          if($LASTEXITCODE -ne 0){ throw "ALTER SYSTEM SET full_page_writes=off failed on agent $n (:$port)" }
          & $psql @H -c 'SELECT pg_reload_conf()' | Out-Null
          if($LASTEXITCODE -ne 0){ throw "pg_reload_conf() failed on agent $n (:$port)" }
        } finally {
          Remove-Item Env:\PGPASSWORD -EA SilentlyContinue
        }
        Write-Host "agent ${n}: PG on :$port ready (svc $svc, data $data)"
      } catch {
        Write-Warning "agent ${n} provisioning FAILED: $($_.Exception.Message) - continuing to the next agent; re-run this script to retry agent $n (already-provisioned agents are untouched on re-run)"
        $failedAgents += $n
      }
    }
    if($failedAgents.Count -gt 0){
      throw "per-agent Postgres provisioning failed for agent(s) $($failedAgents -join ', ') - see the WARNING lines above; re-run this script to retry them"
    }
    "per-agent clusters 1..$($RunnerCount-1) ready on :$($PostgresPort+1)..:$($PostgresPort+$RunnerCount-1)"
  } finally {
    Remove-Item $pw -EA SilentlyContinue
  }
}

Step "PostgreSQL per-agent binary copies — a private postgres.exe per cluster (#2354)" {
  # THE residual [pg]-shard cost on Windows, root-caused 2026-07-22 (#2354).
  # Postgres-on-Windows is EXEC_BACKEND (fork-less): every connection
  # CreateProcess()es a fresh postgres.exe. All clusters shared ONE binary
  # (C:\pgsql\bin\postgres.exe), so every backend spawn across all 4 CCD-pinned
  # runner agents contended that single image file's FCB / image-section lock —
  # ~1000-1466 ms/spawn under box-wide concurrency. It is NOT Defender (proven
  # with real-time protection fully off) and NOT disk (zero disk reads measured):
  # a byte-identical COPY at a different path has its own FCB and spawns in
  # ~10-20 ms. Give each cluster a private copy of the whole install tree and
  # repoint its service at that copy; validated live ~50-70x under all-4-agent
  # churn. Complements the shared-DB+TRUNCATE test fixtures (which cut the spawn
  # COUNT); this removes the per-spawn cross-cluster contention.
  #
  # Idempotent: on re-run the ImagePath already points at the copy (no-op) and
  # robocopy refreshes the tree in place. Per-agent, catch-and-continue like the
  # per-agent-clusters step: one agent's failure records + continues, and the
  # accumulated list still throws once after the loop naming every failure.
  function Get-PgServiceImageParts([string]$image){
    $trimmed = $image.TrimStart()
    $exe = if($trimmed -match '^"([^"]+)"'){ $Matches[1] } else { ($trimmed -split '\s+',2)[0] }
    if(-not $exe){ throw "could not parse service executable from ImagePath '$image'" }
    $data = $null
    if($trimmed -match '(?i)(?:^|\s)-D\s*"([^"]+)"'){
      $data = $Matches[1]
    } elseif($trimmed -match '(?i)(?:^|\s)-D\s*([^\s"]+)'){
      $data = $Matches[1]
    }
    [pscustomobject]@{ Exe=$exe; DataDir=$data }
  }

  # The script-wide gate at the top already proved the box was drained. This
  # step is the longest-running mutation in the script (four whole-tree
  # robocopies + recursive icacls + four restarts), so re-assert rather than
  # trust a minutes-old observation: an operator can start a runner mid-run.
  Assert-RunnersDrained 'refusing PostgreSQL binary reconciliation'

  $major = $PostgresVersion.Split('.')[0]
  $pgbin = @("C:\pgsql\bin","C:\Program Files\PostgreSQL\$major\bin") | Where-Object { Test-Path (Join-Path $_ 'psql.exe') } | Select-Object -First 1
  if(-not $pgbin){ throw "psql not found — the main PostgreSQL step must succeed before per-agent binary copies" }
  $pgroot  = Split-Path $pgbin -Parent            # install ROOT (parent of bin): C:\pgsql or C:\Program Files\PostgreSQL\$major
  $agent0Svc = "postgresql-x64-$major-yuzu-ci"
  $agent0Reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$agent0Svc"
  $agent0Image = (Get-ItemProperty $agent0Reg -Name ImagePath -EA Stop).ImagePath
  $srcData = (Get-PgServiceImageParts $agent0Image).DataDir
  if(-not $srcData){
    throw "agent 0 service $agent0Svc ImagePath has no parseable -D data directory — refusing to copy the install tree without a proven live-data exclusion"
  }
  # robocopy /XD matches the directory by PATH STRING, so hand it a canonical
  # one: the registry value can carry a trailing separator, a relative segment
  # or 8.3 short names, any of which would silently fail to match and copy the
  # LIVE data dir into the private tree. Normalize once, here.
  $srcData = [IO.Path]::GetFullPath($srcData).TrimEnd('\')
  $pgrootFull = [IO.Path]::GetFullPath($pgroot).TrimEnd('\')
  if($srcData -like "$pgrootFull\*"){
    # Inside the tree being copied: the exclusion is load-bearing, so prove the
    # canonical path actually exists rather than excluding a name that matches
    # nothing on disk.
    if(-not (Test-Path -LiteralPath $srcData -PathType Container)){
      throw "agent 0 data dir '$srcData' (from $agent0Svc -D) is under the install root but does not exist — refusing to copy without a live-data exclusion that resolves"
    }
  }
  $failedAgents = @()
  for($n=0; $n -lt $RunnerCount; $n++){
    $svc    = if($n -eq 0){ "postgresql-x64-$major-yuzu-ci" } else { "postgresql-x64-$major-yuzu-ci-$n" }
    $port   = $PostgresPort + $n
    $dst    = Join-Path $CacheRoot "pgbin\agent-$n"
    $dstbin = Join-Path $dst 'bin'
    $newExe = Join-Path $dstbin 'pg_ctl.exe'
    try {
      if(-not (Get-Service $svc -EA SilentlyContinue)){
        throw "service $svc not found — provision its cluster first (agent 0: the main PostgreSQL step; agents 1..N-1: the per-agent-clusters step)"
      }
      # 1) Private binary tree: the whole install root EXCEPT the live data dir.
      #    Agent-0's data is $pgroot\data (excluded); agents 1..N-1 keep their
      #    data at $CacheRoot\pg\agent-$n, already outside $pgroot. robocopy
      #    exit 0-7 == success, 8+ == failure (capture before the next native
      #    call clobbers $LASTEXITCODE).
      New-Item -ItemType Directory -Force $dst | Out-Null
      robocopy $pgroot $dst /E /XD $srcData /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null
      $rc = $LASTEXITCODE
      if($rc -ge 8){ throw "robocopy $pgroot -> $dst failed (exit $rc)" }
      if(-not (Test-Path $newExe)){ throw "copy incomplete: $newExe missing after robocopy" }
      # NETWORK SERVICE (the account every cluster's service runs as — see the
      # per-agent-clusters step) must be able to read+execute the copied tree;
      # robocopy /COPY:DAT does not carry source ACLs, so grant it explicitly.
      icacls $dst /grant '*S-1-5-20:(OI)(CI)RX' /T /C /Q | Out-Null
      # 2) Repoint ONLY the service ImagePath's pg_ctl.exe path at the private
      #    copy; the -D datadir and every other arg are left byte-for-byte
      #    intact. pg_ctl launches postgres.exe from its own directory, so the
      #    copy's postgres.exe (its own FCB) is what serves.
      $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
      $curImage = (Get-ItemProperty $regPath -Name ImagePath -EA Stop).ImagePath
      $curExe   = (Get-PgServiceImageParts $curImage).Exe
      # Preserve the ORIGINAL value kind on both the repoint and the rollback.
      # Hardcoding ExpandString would rewrite a REG_SZ value as REG_EXPAND_SZ,
      # so a rollback of an ImagePath containing a literal '%' would not restore
      # the exact original this code claims to restore.
      $imageKind = (Get-Item $regPath).GetValueKind('ImagePath')
      if([string]::Equals($curExe, $newExe, 'OrdinalIgnoreCase')){
        # Path equality is not health: a prior interrupted provision can leave
        # the registry repointed while the service is dead. Prove the existing
        # no-op state serves before accepting it.
        Assert-PgServing $dstbin $port "agent $n existing private service"
        Write-Host "agent ${n}: ImagePath already points at the private copy ($dstbin) — serving verified, no-op"
      } else {
        # Replace the parsed executable token exactly once. String.Replace()
        # would also rewrite an argument containing the same path substring.
        $exeOffset = $curImage.IndexOf($curExe, [StringComparison]::OrdinalIgnoreCase)
        if($exeOffset -lt 0){ throw "parsed executable '$curExe' not found in ImagePath '$curImage'" }
        $newImage = $curImage.Substring(0,$exeOffset) + $newExe +
                    $curImage.Substring($exeOffset + $curExe.Length)
        # Last check before the only destructive act in the loop: this restart
        # drops every live connection on $svc. The gate above ran before the
        # robocopy/icacls of agent 0..n, which can take minutes.
        Assert-RunnersDrained "refusing to restart $svc"
        Set-ItemProperty $regPath -Name ImagePath -Value $newImage -Type $imageKind
        try {
          Restart-Service $svc -Force -EA Stop
          Assert-PgServing $dstbin $port "agent $n repointed service"
          Write-Host "agent ${n}: postgres.exe now private ($dstbin), svc $svc on :$port verified"
        } catch {
          # A bad copy must never leave the cluster wedged. Restore the exact
          # original ImagePath, restart from its bin dir, and prove SELECT 1;
          # distinguish a clean rollback from a failed recovery in the error.
          $forwardError = $_.Exception.Message
          try {
            Set-ItemProperty $regPath -Name ImagePath -Value $curImage -Type $imageKind -EA Stop
            # Do NOT assume the cluster is down. If Restart-Service itself threw,
            # it may have failed before stopping the old postmaster, which is
            # then still serving live connections on the ORIGINAL binary. Since
            # ImagePath is only read at process start, the registry restore
            # ALONE completes the rollback in that case — restarting would drop
            # connections that predate the gate above and were never authorised.
            $originalBin = Split-Path $curExe -Parent
            # Probe on EVERY forward failure. Restart-Service may have thrown
            # before stopping the old process, or it may have returned before
            # the later authenticated health check failed. Either way, a ready
            # service port is enough reason not to drop possibly-live sessions.
            $stillServing = Test-PgServingNow $originalBin $port
            if($stillServing){
              Write-Host "agent ${n}: $svc still has a ready service port — ImagePath restored for its next start; no recovery restart performed"
              $rollbackResult = 'restored ImagePath while the service port remained ready; no recovery restart was performed'
            } else {
              # Observation for the LOG ONLY — deliberately not Assert-
              # RunnersDrained, and deliberately swallowing its failure. This is
              # the one place a drain observation must not stop anything: the
              # restart below happens either way, so the answer only decides how
              # loudly we narrate it. Not being able to observe therefore changes
              # nothing here, unlike everywhere else in this script.
              $activeDuringRecovery = try { (Get-ActiveRunnerProcess).Count } catch { -1 }
              if(-not $AllowActiveRunners -and $activeDuringRecovery -ne 0){
                Write-Warning "agent ${n}: runners may be active during recovery (found: $activeDuringRecovery, -1 = could not determine); restarting $svc anyway — it is not serving, and leaving it that way would be worse"
              }
              # DRAIN-EXEMPT: recovery on a cluster PROVEN not to be serving —
              # the new binary came up unhealthy, or the restart killed the old
              # one and nothing is answering. Refusing would strand it broken,
              # worse for any job than the restart. The liveness probe above is
              # what earns this, not an assumption about how we got here.
              Restart-Service $svc -Force -EA Stop
              Assert-PgServing $originalBin $port "agent $n rollback service"
              $rollbackResult = 'restored and verified the original service after a recovery restart'
            }
          } catch {
            $rollbackError = $_.Exception.Message
            throw "repoint of $svc failed ($forwardError); rollback to '$curExe' ALSO FAILED verification ($rollbackError)"
          }
          throw "repoint of $svc failed ($forwardError); rollback to '$curExe' $rollbackResult"
        }
      }
    } catch {
      # Per-agent failures are isolated: log, record, carry on to the next agent.
      # A drain detection never reaches here — Assert-RunnersDrained exits the
      # process — so there is no stop-the-world case for this handler to
      # recognise, and nothing here can downgrade one.
      Write-Warning "agent ${n} binary-copy FAILED: $($_.Exception.Message) — continuing to the next agent; re-run this script to retry (idempotent)"
      $failedAgents += $n
    }
  }
  if($failedAgents.Count -gt 0){
    throw "per-agent binary copy failed for agent(s) $($failedAgents -join ', ') — see the WARNING lines above"
  }
  "per-agent private postgres.exe copies ready under $CacheRoot\pgbin\agent-0..$($RunnerCount-1)"
}

Step 'Windows Defender exclusions for CI hot paths (runner work + Postgres)' {
  # THE dominant [pg]-shard cost on Windows: Postgres has no fork(), so it
  # CreateProcess()es a fresh postgres.exe backend PER CONNECTION, and Defender
  # scans that binary on every spawn. Measured 570 ms/connection unexcluded vs
  # 36 ms excluded (~16x); the shard opens ~1000+ connections, so this is the
  # difference between the 900s TIMEOUT and finishing. postgres.exe joins the
  # cl/link/ninja/python process exclusions this box already carries for the
  # same reason. Also exclude the data dirs (CREATE DATABASE ... TEMPLATE file
  # writes) — a smaller, secondary win. Disposable test data on a CI runner.
  $major = $PostgresVersion.Split('.')[0]
  $pgbin = @("C:\pgsql\bin","C:\Program Files\PostgreSQL\$major\bin") | Where-Object { Test-Path (Join-Path $_ 'psql.exe') } | Select-Object -First 1
  # Path-scoped, not a bare filename: 'postgres.exe' alone excludes any
  # process with that name machine-wide. $pgbin is the one bin dir every
  # agent's service (agent-0 + agents 1..N-1) launches postgres.exe from.
  if($pgbin){
    Add-MpPreference -ExclusionProcess (Join-Path $pgbin 'postgres.exe') -EA SilentlyContinue   # per-connection backend spawn (the big one)
  } else {
    Write-Warning "pgbin not found - skipping the postgres.exe Defender exclusion; the [pg]-shard perf fix this step exists for is NOT applied on this runner"
  }
  # Each cluster now launches its OWN private copy (the per-agent binary-copy
  # step, #2354), so the single exclusion above — which only covers the original
  # C:\pgsql\bin path — misses the binary actually running. Exclude every copy's
  # postgres.exe too.
  for($n=0; $n -lt $RunnerCount; $n++){
    Add-MpPreference -ExclusionProcess (Join-Path $CacheRoot "pgbin\agent-$n\bin\postgres.exe") -EA SilentlyContinue
  }
  # The Catch2 test binaries drive the SQLite .db/-wal/-shm temp churn behind the
  # tar (~104x Linux) and server (~5-18x) suites. A PROCESS exclusion skips
  # scanning ALL of a binary's file I/O wherever it lands — including the
  # LOCAL SYSTEM-context C:\Windows\Temp that the per-runner _temp routing cannot
  # reach — so it is broader than the C:\Windows\Temp\yuzu* path exclusion below
  # and complements it. Bare names (not full paths): these binaries live under the
  # per-build tests dir (which varies) and are ours alone on a CI runner, unlike
  # 'postgres.exe' which must stay path-scoped.
  $testExes = @('yuzu_server_tests.exe','yuzu_agent_tests.exe','yuzu_tar_tests.exe')
  foreach($exe in $testExes){ Add-MpPreference -ExclusionProcess $exe -EA SilentlyContinue }
  $paths = @()
  # Each registered runner's work root contains both its GitHub RUNNER_TEMP
  # (`_temp`) and its checkout/build outputs. Wee Tam already carries these
  # four exact exclusions; codify them so reprovisioning cannot silently lose
  # the setting and reintroduce real-time scanning on every object/temp write.
  # Deliberately do NOT exclude all of user/system %TEMP% or D:\ci — only the
  # scoped yuzu* wildcard below. LOCAL SYSTEM-context tests (yuzu_test_kv_SYSTEM,
  # guardian, ...) resolve TEMP to C:\Windows\Temp, which Start-PinnedRunner.ps1's
  # per-runner _temp routing cannot reach (it sets TEMP on the Nathan runner
  # process, not the SYSTEM child), so those leaked SQLite .db/-wal/-shm temp
  # files were being real-time-scanned. Narrow yuzu* prefix, never the whole dir.
  $runnerWorkPaths = @(for($n=0; $n -lt $RunnerCount; $n++){
    Join-Path $CacheRoot "work-$n"
  })
  New-Item -ItemType Directory -Force $runnerWorkPaths | Out-Null
  $paths += $runnerWorkPaths
  $paths += 'C:\Windows\Temp\yuzu*'                           # SYSTEM-context test temp (see note above)
  if($pgbin){
    $paths += $pgbin                                          # bin dir: postgres.exe not scanned on launch
    $paths += (Join-Path (Split-Path $pgbin -Parent) 'data')  # agent-0 cluster data dir
  }
  $paths += (Join-Path $CacheRoot 'pg')                       # per-agent cluster data dirs (D:\ci\pg\agent-*)
  $paths += (Join-Path $CacheRoot 'pgbin')                    # per-agent private postgres.exe copies (#2354)
  foreach($p in $paths){ Add-MpPreference -ExclusionPath $p -EA SilentlyContinue }
  $activeExclusions = @((Get-MpPreference).ExclusionPath)
  $missingWorkPaths = @($runnerWorkPaths | Where-Object { $activeExclusions -notcontains $_ })
  if($missingWorkPaths.Count -gt 0){
    throw "Defender runner-work exclusions did not apply: $($missingWorkPaths -join ', ')"
  }
  # The private copies are the binaries that now actually serve every [pg]
  # connection (#2354), so THEIR exclusions carry what the original
  # C:\pgsql\bin one used to — and they go in with -EA SilentlyContinue above.
  # Verify fail-closed like the runner-work paths: a GPO that blocks new
  # exclusions must not leave provisioning reporting success while the
  # exclusion added specifically for these copies silently never applied.
  $pgbinRoot = Join-Path $CacheRoot 'pgbin'
  if($activeExclusions -notcontains $pgbinRoot){
    throw "Defender path exclusion did not apply: $pgbinRoot (private postgres.exe copies, #2354)"
  }
  $activeProcExclusions = @((Get-MpPreference).ExclusionProcess)
  $missingPgProc = @(for($n=0; $n -lt $RunnerCount; $n++){
    $procPath = Join-Path $CacheRoot "pgbin\agent-$n\bin\postgres.exe"
    if($activeProcExclusions -notcontains $procPath){ $procPath }
  })
  if($missingPgProc.Count -gt 0){
    throw "Defender process exclusions did not apply for the private postgres.exe copies: $($missingPgProc -join ', ')"
  }
  # Validate the effective child paths with Defender itself. A parent folder
  # exclusion is recursive, but this catches policy-merging or path-resolution
  # surprises that a Get-MpPreference string comparison would miss.
  $mpCmdRun = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -EA SilentlyContinue |
    Sort-Object LastWriteTime | Select-Object -Last 1
  if(-not $mpCmdRun){ throw 'MpCmdRun.exe not found — cannot validate runner temp exclusions' }
  $failedTempPaths = @()
  foreach($runnerWorkPath in $runnerWorkPaths){
    $runnerTemp = Join-Path $runnerWorkPath '_temp'
    New-Item -ItemType Directory -Force $runnerTemp | Out-Null
    & $mpCmdRun.FullName -CheckExclusion -Path $runnerTemp | Out-Host
    if($LASTEXITCODE -ne 0){ $failedTempPaths += $runnerTemp }
  }
  if($failedTempPaths.Count -gt 0){
    throw "Defender runner-temp exclusions are ineffective: $($failedTempPaths -join ', ')"
  }
  New-Item -ItemType Directory -Force $pgbinRoot | Out-Null
  & $mpCmdRun.FullName -CheckExclusion -Path $pgbinRoot | Out-Host
  if($LASTEXITCODE -ne 0){
    throw "Defender exclusion for the private postgres.exe tree is ineffective: $pgbinRoot"
  }
  $pgExcl = if($pgbin){ Join-Path $pgbin 'postgres.exe' } else { '(postgres.exe skipped - pgbin not found)' }
  # Include the private per-agent copies: they are the binaries that actually
  # serve every [pg] connection, so omitting them understates what is protected.
  $privateExcl = @(for($n=0; $n -lt $RunnerCount; $n++){ Join-Path $CacheRoot "pgbin\agent-$n\bin\postgres.exe" })
  $procExcl = @($pgExcl) + $privateExcl + $testExes
  "Defender exclusions added: process=" + ($procExcl -join ', ') + "; paths=" + ($paths -join ', ')
}

Step 'Scheduled sweep of leaked C:\Windows\Temp\yuzu* (NTFS dir-index hygiene)' {
  # Companion to the C:\Windows\Temp\yuzu* Defender exclusion above. That stops
  # the SCAN cost, but the leaked SYSTEM-context test temp still ACCUMULATES
  # there (18k+ entries observed 2026-07) — an unbounded directory bloats the
  # NTFS index so every later create in C:\Windows\Temp is slower. A daily sweep
  # keeps it bounded. Only entries older than 1 day are removed, so an in-flight
  # job's temp is never touched. Where-Object uses the property-comparison form
  # (no $_) so the whole command survives -Command string quoting untouched.
  $taskName = 'Yuzu-CI-Temp-Sweep'
  $sweep = "Get-ChildItem C:\Windows\Temp\yuzu* -Force -EA SilentlyContinue | " +
           "Where-Object LastWriteTime -lt (Get-Date).AddDays(-1) | " +
           "Remove-Item -Recurse -Force -EA SilentlyContinue"
  $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                 -Argument ('-NoProfile -NonInteractive -Command "' + $sweep + '"')
  $trigger   = New-ScheduledTaskTrigger -Daily -At 4am
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  "registered scheduled task '$taskName' (daily 04:00; purge C:\Windows\Temp\yuzu* older than 1 day)"
}

Step "vcpkg @ pinned baseline $($VcpkgBaseline.Substring(0,7))" {
  $git=(Get-Command git -EA SilentlyContinue).Source
  if(-not (Test-Path "$VcpkgRoot\.git")){
    & $git clone https://github.com/microsoft/vcpkg $VcpkgRoot
    if($LASTEXITCODE -ne 0){ throw "vcpkg clone failed with exit $LASTEXITCODE" }
  }
  & $git -C $VcpkgRoot fetch --depth 1 origin $VcpkgBaseline
  if($LASTEXITCODE -ne 0){ throw "vcpkg fetch failed with exit $LASTEXITCODE" }
  & $git -C $VcpkgRoot checkout --detach $VcpkgBaseline
  if($LASTEXITCODE -ne 0){ throw "vcpkg checkout failed with exit $LASTEXITCODE" }
  # Always reconcile the executable after moving HEAD. Checking only for its
  # existence leaves a binary built from the previous baseline on upgrades.
  & "$VcpkgRoot\bootstrap-vcpkg.bat" -disableMetrics
  if($LASTEXITCODE -ne 0){ throw "vcpkg bootstrap failed with exit $LASTEXITCODE" }
  "vcpkg bootstrapped at $VcpkgRoot"
}

Step 'machine env vars + PATH' {
  Set-MachineEnv 'VCPKG_ROOT'             $VcpkgRoot
  Set-MachineEnv 'CCACHE_DIR'             "$CacheRoot\ccache"
  Set-MachineEnv 'CCACHE_MAXSIZE'         '30G'
  Set-MachineEnv 'CCACHE_COMPRESS'        'true'
  Set-MachineEnv 'CCACHE_COMPRESSLEVEL'   '1'
  Set-MachineEnv 'YUZU_BUILD_JOBS'        "$BuildJobs"
  Set-MachineEnv 'YUZU_TEST_POSTGRES_DSN' "postgresql://yuzu:yuzu@127.0.0.1:$PostgresPort/yuzu_test"
  # Shared CI tool cache (P0): one machine-level dir so the 4 CCD-pinned runners
  # share ONE vcpkg binary cache instead of 4 per-runner copies. Each runner's
  # .env also pins RUNNER_TOOL_CACHE to this (see deploy/windows/README.md);
  # this machine env is the default for anything that reads it directly.
  New-Item -ItemType Directory -Force "$CacheRoot\ccache","$CacheRoot\tool_cache" | Out-Null
  Set-MachineEnv 'RUNNER_TOOL_CACHE'      "$CacheRoot\tool_cache"
  Add-MachinePath $VcpkgRoot
  # NOTE: deliberately NOT adding $Msys2Root\usr\bin to the machine PATH (it would
  # shadow Windows find/sort/etc.); Start-PinnedRunner.ps1 prepends it only inside
  # the runner's process env, and CI invokes bash by full path.
}

Step "emit toolchain manifest -> $ManifestPath" {
  function Ver([scriptblock]$b){ try { (& $b 2>&1 | Select-Object -First 1) -replace '\s+$','' } catch { $null } }
  $vsw="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $msvc = if(Test-Path $vsw){ (& $vsw -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1) } else { $null }
  $windowsSdkHeader = "${env:ProgramFiles(x86)}\Windows Kits\10\Include\$WindowsSdkVersion\um\Windows.h"
  $windowsSdkLib = "${env:ProgramFiles(x86)}\Windows Kits\10\Lib\$WindowsSdkVersion\um\x64\kernel32.lib"
  $windowsSdkRc = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\$WindowsSdkVersion\x64\rc.exe"
  $major = $PostgresVersion.Split('.')[0]
  # Same resolution as the PostgreSQL/per-agent-cluster/Defender-exclusion
  # steps above - each Step scriptblock gets its own scope, so $pgbin from
  # those earlier steps doesn't carry over here and must be re-resolved.
  # A hardcoded Program Files path (Wee Tam is a C:\pgsql zip install)
  # made Assert-Toolchain.ps1's self-test report [MISS] postgres after a
  # successful provision - adversarial review v2 F2'.
  $pgbin = @("C:\pgsql\bin","C:\Program Files\PostgreSQL\$major\bin") | Where-Object { Test-Path (Join-Path $_ 'psql.exe') } | Select-Object -First 1
  if(-not $pgbin){ $pgbin = "C:\Program Files\PostgreSQL\$major\bin" }
  $tools = @(
    @{ name='python';     path=@(Get-Command python -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source; version=(Ver { python --version }); required=$true }
    @{ name='meson';      path=@(Get-Command meson  -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source; version=(Ver { meson --version });  required=$true }
    @{ name='ninja';      path=@(Get-Command ninja  -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source; version=(Ver { ninja --version });  required=$true }
    @{ name='cmake';      path=@(Get-Command cmake  -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source; version=(Ver { cmake --version });  required=$true }
    @{ name='git';        path=@(Get-Command git    -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source; version=(Ver { git --version });    required=$true }
    @{ name='ccache';     path=@(Get-Command ccache -CommandType Application -EA SilentlyContinue | Select-Object -First 1).Source; version=(Ver { ccache --version }); required=$true }
    @{ name='escript';    path=[Environment]::GetEnvironmentVariable('YUZU_ESCRIPT','Machine'); version=(Ver { erl -version }); required=$true }
    @{ name='rebar3';     path=[Environment]::GetEnvironmentVariable('YUZU_REBAR3','Machine');  version=$Rebar3Version; required=$true }
    @{ name='msvc';       path=$msvc; version=$null; required=$true }
    @{ name='windows_sdk_header'; path=$windowsSdkHeader; version=$WindowsSdkVersion; required=$true }
    @{ name='windows_sdk_lib'; path=$windowsSdkLib; version=$WindowsSdkVersion; required=$true }
    @{ name='windows_sdk_rc'; path=$windowsSdkRc; version=$WindowsSdkVersion; required=$true }
    @{ name='msys2_bash'; path="$Msys2Root\usr\bin\bash.exe"; version=(Ver { & "$Msys2Root\usr\bin\bash.exe" --version }); required=$true }
    @{ name='postgres';   path=(Join-Path $pgbin 'psql.exe'); version=$PostgresVersion; required=$true }
  )
  $postgresClusters = @(for($n=0; $n -lt $RunnerCount; $n++){
    $clusterBin = Join-Path $CacheRoot "pgbin\agent-$n\bin"
    $clusterSvc = if($n -eq 0){ "postgresql-x64-$major-yuzu-ci" } else { "postgresql-x64-$major-yuzu-ci-$n" }
    [ordered]@{
      agent=$n
      service=$clusterSvc
      port=($PostgresPort + $n)
      bin=$clusterBin
      pg_ctl=(Join-Path $clusterBin 'pg_ctl.exe')
      postgres=(Join-Path $clusterBin 'postgres.exe')
      psql=(Join-Path $clusterBin 'psql.exe')
      pg_isready=(Join-Path $clusterBin 'pg_isready.exe')
    }
  })
  $manifestSource = [pscustomobject][ordered]@{
    schema    = [string]$toolchainContract.schema
    generated = (Get-Date).ToUniversalTime().ToString('o')
    host      = $env:COMPUTERNAME
    runner_count = $RunnerCount
    pins      = [ordered]@{ python=$PythonVersion; meson=$MesonVersion; erlang=$ErlangVersion; rebar3=$Rebar3Version; postgres=$PostgresVersion; windows_sdk=$WindowsSdkVersion; build_jobs=$BuildJobs; vcpkg_baseline=$VcpkgBaseline }
    env       = [ordered]@{
      VCPKG_ROOT=$VcpkgRoot; CCACHE_DIR="$CacheRoot\ccache"; RUNNER_TOOL_CACHE="$CacheRoot\tool_cache"
      YUZU_BUILD_JOBS="$BuildJobs"
      YUZU_ESCRIPT=[Environment]::GetEnvironmentVariable('YUZU_ESCRIPT','Machine')
      YUZU_REBAR3=[Environment]::GetEnvironmentVariable('YUZU_REBAR3','Machine')
      YUZU_TEST_POSTGRES_DSN="postgresql://yuzu:yuzu@127.0.0.1:$PostgresPort/yuzu_test"
    }
    telemetry = [ordered]@{
      root="$CacheRoot\test-runs"
      databases=@(for($n=0; $n -lt $RunnerCount; $n++){
        Join-Path (Join-Path "$CacheRoot\test-runs" "yuzu-weetam-windows-$n") 'test-runs.db'
      })
    }
    postgres_clusters = $postgresClusters
    tools     = $tools
  }
  $manifest = New-YuzuToolchainManifestDocument `
      -PriorManifest $manifestSource -Contract $toolchainContract -HostName $env:COMPUTERNAME
  New-Item -ItemType Directory -Force (Split-Path $ManifestPath) | Out-Null
  $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $ManifestPath -Encoding UTF8
  "wrote $ManifestPath ($($tools.Count) tools)"
}

Stop-Transcript | Out-Null
if($script:failedSteps.Count -gt 0){
  Write-Host "`n$($script:failedSteps.Count) step(s) FAILED: $($script:failedSteps -join ', ')" -ForegroundColor Red
  Write-Host "See the transcript in C:\ProvisionLogs\ for details. Steps are idempotent - re-run this script to retry." -ForegroundColor Red
  exit 1
}
Write-Host "`nDone. Transcript in C:\ProvisionLogs\. Open a NEW shell so machine PATH/env take effect." -ForegroundColor Yellow
Write-Host "Verify: pwsh -File deploy\windows\Assert-Toolchain.ps1 -ManifestPath $ManifestPath" -ForegroundColor Yellow
Write-Host "Next: register the 4 CCD-pinned runners — see deploy\windows\README.md + Start-PinnedRunner.ps1." -ForegroundColor Yellow
