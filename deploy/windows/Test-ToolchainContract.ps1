#Requires -Version 7
<#
  Hermetic contract tests for Toolchain-Contract.psm1 and the fail-closed seam
  in Assert-Toolchain.ps1. Most probes are injected; bounded child processes
  exercise the default adapter, timeout/kill behavior, and the real assertion
  script's incompatible-schema exit. No service or registry key is read, and
  no runner state is changed.

  Run anywhere with PowerShell 7:

    pwsh -NoProfile -File deploy/windows/Test-ToolchainContract.ps1
#>
[CmdletBinding()]
param(
  [string]$ContractPath = (Join-Path $PSScriptRoot 'toolchain-contract.json'),
  [string]$ModulePath = (Join-Path $PSScriptRoot 'Toolchain-Contract.psm1'),
  [string]$AssertPath = (Join-Path $PSScriptRoot 'Assert-Toolchain.ps1'),
  [string]$AssertVcpkgPath = (Join-Path $PSScriptRoot 'Assert-VcpkgCheckout.ps1'),
  [string]$ManifestUpdaterPath = (Join-Path $PSScriptRoot 'Update-ToolchainManifest.ps1'),
  [string]$ProvisionPath = (Join-Path $PSScriptRoot 'Provision-Windows-Runner.ps1'),
  [string]$BaselineWorkflowPath = (Join-Path $PSScriptRoot '..\..\.github\workflows\vcpkg-baseline-update.yml'),
  [string]$CiWorkflowPath = (Join-Path $PSScriptRoot '..\..\.github\workflows\ci.yml'),
  [string]$NightlyWorkflowPath = (Join-Path $PSScriptRoot '..\..\.github\workflows\nightly.yml'),
  [string]$ReleaseWorkflowPath = (Join-Path $PSScriptRoot '..\..\.github\workflows\release.yml')
)
$ErrorActionPreference = 'Stop'

Import-Module $ModulePath -Force
$contract = Read-YuzuToolchainContract -Path $ContractPath

$script:passed = 0
$script:failed = 0
function Check([string]$Name,[scriptblock]$Body){
  try {
    if(& $Body){
      Write-Host "  PASS  $Name" -ForegroundColor Green
      $script:passed++
    } else {
      Write-Host "  FAIL  $Name" -ForegroundColor Red
      $script:failed++
    }
  } catch {
    Write-Host "  FAIL  $Name :: $($_.Exception.Message)" -ForegroundColor Red
    $script:failed++
  }
}

function New-TestManifest {
  $tools = foreach($name in @($contract.required_tools)){
    [ordered]@{
      name = [string]$name
      path = "X:\fake\$name.exe"
      version = 'fixture-recorded-version'
      required = $true
    }
  }
  $sdkVersion = [string]$contract.pins.windows_sdk
  ($tools | Where-Object name -eq 'windows_sdk_header').path = "C:\Program Files (x86)\Windows Kits\10\Include\$sdkVersion\um\Windows.h"
  ($tools | Where-Object name -eq 'windows_sdk_lib').path = "C:\Program Files (x86)\Windows Kits\10\Lib\$sdkVersion\um\x64\kernel32.lib"
  ($tools | Where-Object name -eq 'windows_sdk_rc').path = "C:\Program Files (x86)\Windows Kits\10\bin\$sdkVersion\x64\rc.exe"
  @($tools | Where-Object name -like 'windows_sdk_*').ForEach({ $_.version = $sdkVersion })
  [pscustomobject][ordered]@{
    schema = [string]$contract.schema
    generated = '2026-07-28T12:00:00Z'
    host = 'HERMETIC'
    runner_count = 2
    pins = ($contract.pins | ConvertTo-Json -Depth 4 | ConvertFrom-Json)
    env = [pscustomobject][ordered]@{
      CCACHE_DIR = 'X:\fake\ccache'
      RUNNER_TOOL_CACHE = 'X:\fake\tool-cache'
      YUZU_ESCRIPT = 'X:\fake\escript.exe'
      YUZU_REBAR3 = 'X:\fake\rebar3.exe'
      YUZU_TEST_POSTGRES_DSN = 'postgresql://fixture.invalid/test'
    }
    telemetry = [pscustomobject]@{ databases = @('X:\fake\runner-0.db','X:\fake\runner-1.db') }
    postgres_clusters = @(
      [pscustomobject]@{
        agent=0; port=5433; service='postgresql-fixture-0'; bin='X:\fake\pg-0\bin'
        pg_ctl='X:\fake\pg-0\bin\pg_ctl.exe'; postgres='X:\fake\pg-0\bin\postgres.exe'
        psql='X:\fake\pg-0\bin\psql.exe'; pg_isready='X:\fake\pg-0\bin\pg_isready.exe'
      },
      [pscustomobject]@{
        agent=1; port=5434; service='postgresql-fixture-1'; bin='X:\fake\pg-1\bin'
        pg_ctl='X:\fake\pg-1\bin\pg_ctl.exe'; postgres='X:\fake\pg-1\bin\postgres.exe'
        psql='X:\fake\pg-1\bin\psql.exe'; pg_isready='X:\fake\pg-1\bin\pg_isready.exe'
      }
    )
    tools = @($tools)
  }
}

function Copy-TestManifest([psobject]$Manifest){
  $copy = $Manifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json
  if($copy.generated -is [datetime]){
    $copy.generated = $copy.generated.ToUniversalTime().ToString('o')
  }
  $copy
}

function Set-TestManifestTopology([psobject]$Manifest,[int]$RunnerCount){
  $Manifest.runner_count = $RunnerCount
  $Manifest.telemetry.databases = @(
    for($n=0; $n -lt $RunnerCount; $n++){ "X:\fake\runner-$n.db" }
  )
  $Manifest.postgres_clusters = @(
    for($n=0; $n -lt $RunnerCount; $n++){
      [pscustomobject]@{
        agent=$n; port=(5433 + $n); service="postgresql-fixture-$n"; bin="X:\fake\pg-$n\bin"
        pg_ctl="X:\fake\pg-$n\bin\pg_ctl.exe"; postgres="X:\fake\pg-$n\bin\postgres.exe"
        psql="X:\fake\pg-$n\bin\psql.exe"; pg_isready="X:\fake\pg-$n\bin\pg_isready.exe"
      }
    }
  )
  $Manifest
}

$probeState = [pscustomobject]@{ Calls = 0; RebarInvocationOk = $false }
$probeValues = @{
  'X:\fake\python.exe' = 'Python 3.14.6'
  'X:\fake\meson.exe' = '1.11.1'
  'X:\fake\escript.exe' = 'rebar 3.24.0 on Erlang/OTP 28 Erts 16.4'
  'X:\fake\postgres.exe' = 'psql (PostgreSQL) 18.4'
}
$expectedArguments = @{
  'X:\fake\python.exe' = '--version'
  'X:\fake\meson.exe' = '--version'
  'X:\fake\escript.exe' = "X:\fake\rebar3.exe`0version"
  'X:\fake\postgres.exe' = '--version'
}
$probeRunner = {
  param([string]$Executable,[string[]]$Arguments)
  $probeState.Calls++
  if(-not $probeValues.ContainsKey($Executable)){ throw "unexpected executable: $Executable" }
  $actualArguments = $Arguments -join "`0"
  if($actualArguments -ne $expectedArguments[$Executable]){
    throw "bad arguments for ${Executable}: $actualArguments"
  }
  if($Executable -eq 'X:\fake\escript.exe'){ $probeState.RebarInvocationOk = $true }
  $probeValues[$Executable]
}.GetNewClosure()

$commandPaths = @{
  python='X:\fake\python.exe'
  meson='X:\fake\meson.exe'
  git='X:\fake\git.exe'
}
$commandResolver = {
  param([string]$Command)
  if(-not $commandPaths.ContainsKey($Command)){ throw "unexpected command: $Command" }
  $commandPaths[$Command]
}.GetNewClosure()
$fileProbeReader = {
  param([string]$AnchorPath,[psobject]$Probe)
  if($AnchorPath -ne 'X:\fake\escript.exe' -or $Probe.name -ne 'Erlang OTP'){
    throw "bad file probe adapter: $AnchorPath / $($Probe.name)"
  }
  '28.4.2'
}

function Invoke-ManifestTest([psobject]$Manifest,[scriptblock]$Runner,[psobject]$ContractUnderTest){
  if(-not $Runner){ $Runner = $probeRunner }
  if(-not $ContractUnderTest){ $ContractUnderTest = $contract }
  Test-YuzuToolchainManifest -Manifest $Manifest -Contract $ContractUnderTest -ProbeRunner $Runner `
    -CommandResolver $commandResolver -FileProbeReader $fileProbeReader -ExpectedHost 'HERMETIC'
}

Write-Host "Testing toolchain contract: $ContractPath" -ForegroundColor Cyan

Check 'Visual Studio Installer exit codes classify success, reboot, and failure' {
  (Get-YuzuInstallerDisposition -ExitCode 0) -eq 'Complete' -and
  (Get-YuzuInstallerDisposition -ExitCode 1641) -eq 'RebootRequired' -and
  (Get-YuzuInstallerDisposition -ExitCode 3010) -eq 'RebootRequired' -and
  (Get-YuzuInstallerDisposition -ExitCode -1978334967) -eq 'RebootRequired' -and
  (Get-YuzuInstallerDisposition -ExitCode -1978334966) -eq 'RebootRequired' -and
  (Get-YuzuInstallerDisposition -ExitCode -1978334965) -eq 'RebootRequired' -and
  (Get-YuzuInstallerDisposition -ExitCode 1603) -eq 'Failed'
}
Check 'installer exit policy sends direct and WinGet reboot results to its handler' {
  $seen = [Collections.Generic.List[int]]::new()
  foreach($code in @(1641,3010,-1978334967)){
    $message = ''
    try {
      Invoke-YuzuInstallerExitPolicy -ExitCode $code -Context 'fixture' `
        -RebootHandler { param($context,$exitCode) $seen.Add($exitCode) }
    } catch { $message = $_.Exception.Message }
    if($message -notmatch 'reboot handler returned'){ return $false }
  }
  ($seen -join ',') -eq '1641,3010,-1978334967'
}
Check 'installer exit policy accepts zero and rejects a hard failure' {
  Invoke-YuzuInstallerExitPolicy -ExitCode 0 -Context 'fixture' -RebootHandler { throw 'not expected' }
  $message = ''
  try {
    Invoke-YuzuInstallerExitPolicy -ExitCode 1603 -Context 'fixture' -RebootHandler { throw 'not expected' }
  } catch { $message = $_.Exception.Message }
  $message -match 'fixture failed \(exit 1603\)'
}

$artifactWork = Join-Path ([IO.Path]::GetTempPath()) "yuzu_test_sdk_paths_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $artifactWork | Out-Null
try {
  $artifactTools = @('windows_sdk_header','windows_sdk_lib','windows_sdk_rc') | ForEach-Object {
    [pscustomobject]@{ name=$_; path=(Join-Path $artifactWork $_); version='10.0.26100.0'; required=$true }
  }
  foreach($tool in $artifactTools){ Set-Content -LiteralPath $tool.path -Value 'fixture' -Encoding Ascii }
  $result = Test-YuzuRequiredToolPaths -Tools $artifactTools
  Check 'all required SDK artifact files pass the live path adapter' {
    $result.Healthy -and @($result.Observations | Where-Object Exists).Count -eq 3
  }
  foreach($missingName in @('windows_sdk_header','windows_sdk_lib','windows_sdk_rc')){
    $missing = @($artifactTools | Where-Object name -eq $missingName)[0]
    Remove-Item -LiteralPath $missing.path
    $result = Test-YuzuRequiredToolPaths -Tools $artifactTools
    Check "deleting live $missingName fails with that artifact identity" {
      (-not $result.Healthy) -and
      @($result.Observations | Where-Object { $_.Required -and -not $_.Exists }).Count -eq 1 -and
      @($result.Observations | Where-Object { $_.Required -and -not $_.Exists })[0].Name -eq $missingName
    }
    Set-Content -LiteralPath $missing.path -Value 'fixture' -Encoding Ascii
  }
  $result = Test-YuzuRequiredToolPaths -Tools $artifactTools -PathTester { throw 'fixture access denied' }
  Check 'a live path probe error fails closed with its diagnostic cause' {
    (-not $result.Healthy) -and
    @($result.Observations | Where-Object { $_.Error -match 'fixture access denied' }).Count -eq 3
  }
} finally {
  Remove-Item -LiteralPath $artifactWork -Recurse -Force -ErrorAction SilentlyContinue
}

$valid = New-TestManifest
$result = Invoke-ManifestTest $valid
Check 'a complete matching manifest passes all executable probes' {
  $rebarProbe = @($result.Observations | Where-Object Name -eq 'rebar3')
  $result.Healthy -and @($result.Observations).Count -eq 11 -and $probeState.Calls -eq 4 -and
  $rebarProbe.Count -eq 1 -and $probeState.RebarInvocationOk
}

$jsonDateManifest = New-TestManifest
$jsonDateManifest.generated = '2026-08-14T09:20:25.3054480+00:00'
$jsonDateManifest = $jsonDateManifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$probeState.Calls = 0
$result = Invoke-ManifestTest $jsonDateManifest
Check 'a JSON-materialised ISO timestamp remains valid on day 13 or later' {
  $result.Healthy -and $probeState.Calls -eq 4
}

foreach($runnerCount in @(1,4)){
  $prior = Set-TestManifestTopology (Copy-TestManifest $valid) $runnerCount
  $prior.tools = @($prior.tools | Where-Object { $_.name -notlike 'windows_sdk_*' })
  $prior.pins.PSObject.Properties.Remove('windows_sdk')
  $prior.pins | Add-Member -NotePropertyName build_jobs -NotePropertyValue 16
  $expectedDatabases = @($prior.telemetry.databases)
  $expectedClusters = $prior.postgres_clusters | ConvertTo-Json -Depth 5
  $migrated = New-YuzuToolchainManifestDocument `
      -PriorManifest $prior -Contract $contract -HostName 'HERMETIC' `
      -GeneratedAt ([DateTimeOffset]'2026-08-11T12:00:00Z')
  $probeState.Calls = 0
  $result = Invoke-ManifestTest $migrated
  Check "manifest-only migration preserves a $runnerCount-runner topology and adds SDK evidence" {
    $result.Healthy -and $migrated.runner_count -eq $runnerCount -and
    @($migrated.telemetry.databases).Count -eq $runnerCount -and
    @($migrated.postgres_clusters).Count -eq $runnerCount -and
    (@($migrated.telemetry.databases) -join "`0") -eq ($expectedDatabases -join "`0") -and
    ($migrated.postgres_clusters | ConvertTo-Json -Depth 5) -eq $expectedClusters -and
    @($migrated.tools | Where-Object { $_.name -like 'windows_sdk_*' }).Count -eq 3 -and
    $migrated.pins.windows_sdk -eq '10.0.26100.0' -and
    $migrated.pins.build_jobs -eq 16
  }
}

$provisionerStyle = Set-TestManifestTopology (Copy-TestManifest $valid) 4
$provisionerStylePins = [ordered]@{}
foreach($pin in $provisionerStyle.pins.PSObject.Properties){
  $provisionerStylePins[$pin.Name] = $pin.Value
}
$provisionerStylePins.build_jobs = 16
$provisionerStyle.pins = $provisionerStylePins
$provisionerManifest = New-YuzuToolchainManifestDocument `
    -PriorManifest $provisionerStyle -Contract $contract -HostName 'HERMETIC'
Check 'manifest builder preserves build_jobs from provisioner ordered-dictionary pins' {
  $provisionerManifest.pins.build_jobs -eq 16
}

$badTopology = Set-TestManifestTopology (Copy-TestManifest $valid) 1
$badTopology.telemetry.databases = @('X:\fake\runner-0.db','X:\fake\runner-1.db')
Check 'manifest-only migration rejects a topology inconsistent with runner_count' {
  try {
    New-YuzuToolchainManifestDocument `
        -PriorManifest $badTopology -Contract $contract -HostName 'HERMETIC' | Out-Null
    $false
  } catch { $_.Exception.Message -match 'topology does not match runner_count' }
}

$updateWork = Join-Path ([IO.Path]::GetTempPath()) "yuzu-manifest-update-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $updateWork | Out-Null
try {
  $updateManifest = Join-Path $updateWork 'toolchain-manifest.json'
  $passingAssert = Join-Path $updateWork 'assert-pass.ps1'
  $failingAssert = Join-Path $updateWork 'assert-fail.ps1'
  Set-Content -LiteralPath $passingAssert -Value 'exit 0' -Encoding UTF8
  Set-Content -LiteralPath $failingAssert -Value 'exit 19' -Encoding UTF8
  Set-Content -LiteralPath $updateManifest -Value '{"state":"prior"}' -Encoding UTF8
  $installResult = Install-YuzuToolchainManifestCandidate `
      -Candidate ([pscustomobject]@{ state='candidate' }) `
      -ManifestPath $updateManifest -ContractPath $ContractPath -AssertPath $passingAssert
  Check 'a passing child assertion reaches atomic replacement and retains the prior manifest' {
    (Get-Content -LiteralPath $updateManifest -Raw) -match 'candidate' -and
    (Get-Content -LiteralPath $installResult.BackupPath -Raw) -match 'prior'
  }

  Set-Content -LiteralPath $updateManifest -Value '{"state":"prior-failure"}' -Encoding UTF8
  $failureMessage = ''
  try {
    Install-YuzuToolchainManifestCandidate `
        -Candidate ([pscustomobject]@{ state='must-not-install' }) `
        -ManifestPath $updateManifest -ContractPath $ContractPath -AssertPath $failingAssert | Out-Null
  } catch { $failureMessage = $_.Exception.Message }
  Check 'a failing child assertion preserves the prior manifest and removes its candidate' {
    $failureMessage -match 'exited 19' -and
    (Get-Content -LiteralPath $updateManifest -Raw) -match 'prior-failure' -and
    -not (Get-ChildItem -LiteralPath $updateWork -Filter '*.candidate')
  }

  Set-Content -LiteralPath $updateManifest -Value '{"state":"prior-race"}' -Encoding UTF8
  $raceMessage = ''
  try {
    Install-YuzuToolchainManifestCandidate `
        -Candidate ([pscustomobject]@{ state='must-not-install-after-race' }) `
        -ManifestPath $updateManifest -ContractPath $ContractPath -AssertPath $passingAssert `
        -BeforeReplace { throw '[RUNNER-ACTIVE] fixture worker appeared' } | Out-Null
  } catch { $raceMessage = $_.Exception.Message }
  Check 'a failed pre-replace worker recheck preserves the prior manifest and removes its candidate' {
    $raceMessage -match '^\[RUNNER-ACTIVE\]' -and
    (Get-Content -LiteralPath $updateManifest -Raw) -match 'prior-race' -and
    -not (Get-ChildItem -LiteralPath $updateWork -Filter '*.candidate')
  }
} finally {
  Remove-Item -LiteralPath $updateWork -Recurse -Force -ErrorAction SilentlyContinue
}

$missingSdkLib = Copy-TestManifest $valid
$missingSdkLib.tools = @($missingSdkLib.tools | Where-Object name -ne 'windows_sdk_lib')
$probeState.Calls = 0
$result = Invoke-ManifestTest $missingSdkLib
Check 'an omitted Windows SDK library fails before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "exactly one 'windows_sdk_lib' tool; found 0"
}

$wrongSdkVersion = Copy-TestManifest $valid
($wrongSdkVersion.tools | Where-Object name -eq 'windows_sdk_header').version = '10.0.22621.0'
$probeState.Calls = 0
$result = Invoke-ManifestTest $wrongSdkVersion
Check 'a stale Windows SDK artifact version fails before executable probes' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "windows_sdk_header.*10\.0\.22621\.0.*10\.0\.26100\.0"
}

$wrongSdkPath = Copy-TestManifest $valid
($wrongSdkPath.tools | Where-Object name -eq 'windows_sdk_rc').path = 'X:\fake\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe'
$probeState.Calls = 0
$result = Invoke-ManifestTest $wrongSdkPath
Check 'a Windows SDK artifact from another target directory fails before executable probes' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "windows_sdk_rc.*does not equal"
}

$wrongSdkRoot = Copy-TestManifest $valid
($wrongSdkRoot.tools | Where-Object name -eq 'windows_sdk_lib').path = 'D:\quarantine\Windows Kits\10\Lib\10.0.26100.0\um\x64\kernel32.lib'
$probeState.Calls = 0
$result = Invoke-ManifestTest $wrongSdkRoot
Check 'a Windows SDK artifact under an inactive root fails before executable probes' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "windows_sdk_lib.*does not equal"
}

# Exercise the exported function's real/default process adapter too. Injected
# fixture probes cannot detect a module-scope regression where the adapter
# loses access to its private implementation. The fake paths should fail to
# start normally; an unresolved helper name is a different, structural error.
$defaultManifestResult = Test-YuzuToolchainManifest -Manifest $valid -Contract $contract `
  -CommandResolver $commandResolver -FileProbeReader $fileProbeReader -ExpectedHost 'HERMETIC'
Check 'the host contract default probe adapter retains module scope' {
  $messages = $defaultManifestResult.Errors -join "`n"
  (-not $defaultManifestResult.Healthy) -and $messages -match 'version probe failed' -and
  $messages -notmatch "Invoke-YuzuContractProbe.*not recognized"
}

# The real PowerShell resolver returns every PATH match, ordered by precedence.
# A lower-priority duplicate must not be concatenated into the effective path.
$commandWork = Join-Path ([IO.Path]::GetTempPath()) "yuzu_test_commands_$([guid]::NewGuid().ToString('N'))"
$firstCommandDir = Join-Path $commandWork 'first'
$secondCommandDir = Join-Path $commandWork 'second'
New-Item -ItemType Directory -Path $firstCommandDir,$secondCommandDir | Out-Null
$oldPath = $env:PATH
try {
  $commandNames = @('python','meson','git')
  foreach($dir in @($firstCommandDir,$secondCommandDir)){
    foreach($name in $commandNames){
      $leaf = if($IsWindows){ "$name.cmd" } else { $name }
      $path = Join-Path $dir $leaf
      if($IsWindows){ Set-Content -LiteralPath $path -Value '@echo off' -Encoding Ascii }
      else {
        Set-Content -LiteralPath $path -Value "#!/bin/sh`nexit 0" -Encoding Ascii
        & chmod +x $path
      }
    }
  }
  $env:PATH = "$firstCommandDir$([IO.Path]::PathSeparator)$secondCommandDir$([IO.Path]::PathSeparator)$oldPath"
  $resolvedDuplicateGit = Resolve-YuzuEffectiveCommand -Name git
  $duplicateCommandManifest = Copy-TestManifest $valid
  foreach($name in $commandNames){
    $leaf = if($IsWindows){ "$name.cmd" } else { $name }
    ($duplicateCommandManifest.tools | Where-Object name -eq $name).path = Join-Path $firstCommandDir $leaf
  }
  $duplicateProbeRunner = {
    param([string]$Executable,[string[]]$Arguments)
    $leaf = [IO.Path]::GetFileNameWithoutExtension($Executable)
    if($leaf -eq 'python'){ return 'Python 3.14.6' }
    if($leaf -eq 'meson'){ return '1.11.1' }
    if($probeValues.ContainsKey($Executable)){ return $probeValues[$Executable] }
    throw "unexpected executable: $Executable"
  }.GetNewClosure()
  $result = Test-YuzuToolchainManifest -Manifest $duplicateCommandManifest -Contract $contract `
    -ProbeRunner $duplicateProbeRunner -FileProbeReader $fileProbeReader -ExpectedHost 'HERMETIC'
  Check 'the default command resolver selects the first PATH match when duplicates exist' {
    $result.Healthy
  }
  Check 'the shared effective-command resolver selects the first duplicate git' {
    $gitLeaf = if($IsWindows){ 'git.cmd' } else { 'git' }
    $resolvedDuplicateGit -eq (Join-Path $firstCommandDir $gitLeaf)
  }
} finally {
  $env:PATH = $oldPath
  Remove-Item -LiteralPath $commandWork -Recurse -Force -ErrorAction SilentlyContinue
}

$pinnedPythonState = @{ Installs=0; Resolves=0 }
$pinnedPython = Resolve-YuzuPinnedPython -ExpectedVersion '3.14.6' `
  -CommandResolver { $pinnedPythonState.Resolves++; 'X:\python-pinned.exe' }.GetNewClosure() `
  -VersionProbe { param([string]$path) '3.14.6' } `
  -Installer { $pinnedPythonState.Installs++ }.GetNewClosure()
Check 'pinned Python skips installation' {
  $pinnedPython.Path -eq 'X:\python-pinned.exe' -and -not $pinnedPython.Installed -and
  $pinnedPythonState.Resolves -eq 1 -and $pinnedPythonState.Installs -eq 0
}

$stalePythonState = @{ Installed=$false; Installs=0; Resolves=0 }
$stalePython = Resolve-YuzuPinnedPython -ExpectedVersion '3.14.6' `
  -CommandResolver {
    $stalePythonState.Resolves++
    if($stalePythonState.Installed){ 'X:\python-new.exe' } else { 'X:\python-old.exe' }
  }.GetNewClosure() `
  -VersionProbe { param([string]$path) if($path -like '*new*'){ '3.14.6' } else { '3.14.3' } } `
  -Installer { $stalePythonState.Installs++; $stalePythonState.Installed=$true }.GetNewClosure()
Check 'stale Python installs once and re-resolves the effective command' {
  $stalePython.Path -eq 'X:\python-new.exe' -and $stalePython.Installed -and
  $stalePythonState.Resolves -eq 2 -and $stalePythonState.Installs -eq 1
}

$stillStaleState = @{ Installs=0; Resolves=0 }
$stillStaleMessage = ''
try {
  Resolve-YuzuPinnedPython -ExpectedVersion '3.14.6' `
    -CommandResolver { $stillStaleState.Resolves++; 'X:\python-old.exe' }.GetNewClosure() `
    -VersionProbe { param([string]$path) '3.14.3' } `
    -Installer { $stillStaleState.Installs++ }.GetNewClosure() | Out-Null
} catch {
  $stillStaleMessage = $_.Exception.Message
}
Check 'Python that remains stale after installation fails closed' {
  $stillStaleState.Resolves -eq 2 -and $stillStaleState.Installs -eq 1 -and
  $stillStaleMessage -match "python is '3\.14\.3'; reviewed pin is '3\.14\.6'"
}

$missingToolProbes = Copy-TestManifest $contract
$missingToolProbes.tool_probes = @()
$probeState.Calls = 0
$result = Invoke-ManifestTest $valid $probeRunner $missingToolProbes
Check 'deleting the contract tool probes fails before executing anything' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "tool probe 'python'; found 0"
}

$duplicateProbeContract = Copy-TestManifest $contract
$duplicateProbeContract.tool_probes += Copy-TestManifest $duplicateProbeContract.tool_probes[0]
$probeState.Calls = 0
$result = Invoke-ManifestTest $valid $probeRunner $duplicateProbeContract
Check 'duplicate contract probes fail before executing anything' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "tool probe 'python'; found 2"
}

$missingSchema = Copy-TestManifest $valid
$missingSchema.PSObject.Properties.Remove('schema')
$probeState.Calls = 0
$result = Invoke-ManifestTest $missingSchema
Check 'a legacy manifest with no schema fails before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "manifest schema '<unset>'"
}

$unknownSchema = Copy-TestManifest $valid
$unknownSchema.schema = 'yuzu/windows-toolchain/v999'
$probeState.Calls = 0
$result = Invoke-ManifestTest $unknownSchema
Check 'an unknown manifest schema fails before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match 'v999'
}

$stalePin = Copy-TestManifest $valid
$stalePin.pins.python = '3.14.3'
$probeState.Calls = 0
$result = Invoke-ManifestTest $stalePin
Check 'a stale manifest pin fails against the repository contract' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "manifest pin 'python'"
}

$missingAcceptedPins = Copy-TestManifest $contract
$missingAcceptedPins.accepted_host_pins.PSObject.Properties.Remove('python')
$probeState.Calls = 0
$result = Invoke-ManifestTest $valid $probeRunner $missingAcceptedPins
Check 'deleting a host-pin compatibility list fails before executing anything' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "accepted host pin 'python'; found 0"
}

$targetNotAccepted = Copy-TestManifest $contract
$targetNotAccepted.accepted_host_pins.python = @('3.14.3')
$probeState.Calls = 0
$result = Invoke-ManifestTest $valid $probeRunner $targetNotAccepted
Check 'a provisioning target omitted from host compatibility fails before probes' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "target pin 'python' must appear in accepted_host_pins"
}

$duplicateAccepted = Copy-TestManifest $contract
$duplicateAccepted.accepted_host_pins.python = @('3.14.6','3.14.6')
$probeState.Calls = 0
$result = Invoke-ManifestTest $valid $probeRunner $duplicateAccepted
Check 'duplicate compatible host versions fail before executing probes' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "accepted host pin 'python' contains duplicate versions"
}

$unknownAccepted = Copy-TestManifest $contract
$unknownAccepted.accepted_host_pins | Add-Member -NotePropertyName invented -NotePropertyValue @('1.0')
$probeState.Calls = 0
$result = Invoke-ManifestTest $valid $probeRunner $unknownAccepted
Check 'unknown compatible host-pin names fail before executing probes' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "unsupported accepted host pin 'invented'"
}

$liveDriftValues = $probeValues.Clone()
$liveDriftValues['X:\fake\python.exe'] = 'Python 3.14.3'
$liveDriftRunner = {
  param([string]$Executable,[string[]]$Arguments)
  $liveDriftValues[$Executable]
}.GetNewClosure()
$result = Invoke-ManifestTest $valid $liveDriftRunner
Check 'a live Python drift fails even when the manifest claims the right pin' {
  (-not $result.Healthy) -and ($result.Errors -join "`n") -match "python version is '3.14.3'"
}

$transitionContract = Copy-TestManifest $contract
$transitionContract.accepted_host_pins.python = @('3.14.3','3.14.6')
$oldButAcceptedManifest = Copy-TestManifest $valid
$oldButAcceptedManifest.generated = '2026-07-28T12:00:00Z'
$oldButAcceptedManifest.pins.python = '3.14.3'
$result = Invoke-ManifestTest $oldButAcceptedManifest $liveDriftRunner $transitionContract
Check 'an explicitly accepted old host stays green during a two-phase pin rollout' {
  if(-not $result.Healthy){ Write-Host "        $($result.Errors -join '; ')" -ForegroundColor DarkYellow }
  $result.Healthy -and @($result.Errors).Count -eq 0
}

$badOutputValues = $probeValues.Clone()
$badOutputValues['X:\fake\meson.exe'] = 'not a version'
$badOutputRunner = {
  param([string]$Executable,[string[]]$Arguments)
  $badOutputValues[$Executable]
}.GetNewClosure()
$result = Invoke-ManifestTest $valid $badOutputRunner
Check 'unparseable probe output fails closed' {
  (-not $result.Healthy) -and ($result.Errors -join "`n") -match 'meson version probe returned an unrecognized value'
}

$throwingRunner = {
  param([string]$Executable,[string[]]$Arguments)
  if($Executable -eq 'X:\fake\escript.exe'){ throw 'simulated launch failure' }
  $probeValues[$Executable]
}.GetNewClosure()
$result = Invoke-ManifestTest $valid $throwingRunner
Check 'a probe execution error fails closed' {
  (-not $result.Healthy) -and ($result.Errors -join "`n") -match 'rebar3 version probe failed: simulated launch failure'
}

$duplicate = Copy-TestManifest $valid
$duplicate.tools += Copy-TestManifest $duplicate.tools[0]
$probeState.Calls = 0
$result = Invoke-ManifestTest $duplicate
Check 'duplicate tool identities fail before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "exactly one 'python' tool; found 2"
}

$incomplete = Copy-TestManifest $valid
$incomplete.telemetry.databases = @('X:\fake\runner-0.db')
$probeState.Calls = 0
$result = Invoke-ManifestTest $incomplete
Check 'a partial per-runner inventory fails before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match 'telemetry databases count 1 does not match runner_count 2'
}

$wrongHost = Copy-TestManifest $valid
$wrongHost.host = 'ANOTHER-HOST'
$probeState.Calls = 0
$result = Invoke-ManifestTest $wrongHost
Check 'a manifest copied from another host fails before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match "does not match this computer 'HERMETIC'"
}

$duplicateCluster = Copy-TestManifest $valid
$duplicateCluster.postgres_clusters[1].port = 5433
$probeState.Calls = 0
$result = Invoke-ManifestTest $duplicateCluster
Check 'duplicate per-agent PostgreSQL resources fail before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match 'PostgreSQL port values must be unique'
}

$aliasedPort = Copy-TestManifest $valid
$aliasedPort.postgres_clusters[1].port = '05433'
$probeState.Calls = 0
$result = Invoke-ManifestTest $aliasedPort
Check 'numerically aliased PostgreSQL ports fail before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match 'PostgreSQL port values must be unique'
}

$aliasedTelemetry = Copy-TestManifest $valid
$aliasedTelemetry.telemetry.databases[1] = 'X:\fake\.\runner-0.db'
$probeState.Calls = 0
$result = Invoke-ManifestTest $aliasedTelemetry
Check 'path-aliased telemetry databases fail before executing a probe' {
  (-not $result.Healthy) -and $probeState.Calls -eq 0 -and
  ($result.Errors -join "`n") -match 'telemetry database paths must be unique'
}

$wrongCommandPaths = $commandPaths.Clone()
$wrongCommandPaths.python = 'X:\stale\python.exe'
$wrongCommandResolver = {
  param([string]$Command)
  $wrongCommandPaths[$Command]
}.GetNewClosure()
$result = Test-YuzuToolchainManifest -Manifest $valid -Contract $contract -ProbeRunner $probeRunner `
  -CommandResolver $wrongCommandResolver -FileProbeReader $fileProbeReader -ExpectedHost 'HERMETIC'
Check 'an effective PATH command that differs from the recorded tool fails' {
  (-not $result.Healthy) -and ($result.Errors -join "`n") -match "effective command 'python' resolves to 'X:\\stale\\python.exe'"
}

$oldOtpReader = { param([string]$AnchorPath,[psobject]$Probe) '28.3.1' }
$result = Test-YuzuToolchainManifest -Manifest $valid -Contract $contract -ProbeRunner $probeRunner `
  -CommandResolver $commandResolver -FileProbeReader $oldOtpReader -ExpectedHost 'HERMETIC'
Check 'an installed Erlang OTP version below the claimed pin fails' {
  (-not $result.Healthy) -and ($result.Errors -join "`n") -match "Erlang OTP is '28.3.1'; expected '28.4.2'"
}

function Invoke-VcpkgFixture {
  param(
    [string]$Head,
    [string]$Status = '',
    [string]$MetadataRelease = '2026-07-28',
    [string]$ExecutableRelease,
    [psobject]$ContractUnderTest = $contract
  )
  $expectedPin = [string]$contract.job_pins.vcpkg_baseline
  if([string]::IsNullOrEmpty($Head)){ $Head = $expectedPin }
  if([string]::IsNullOrEmpty($ExecutableRelease)){
    $ExecutableRelease = "$MetadataRelease-0123456789abcdef0123456789abcdef01234567"
  }
  $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) 'yuzu-fixture-job-vcpkg'
  $fixtureExecutable = Join-Path $fixtureRoot 'vcpkg.exe'
  $state = [pscustomobject]@{ Calls = 0 }
  $runner = {
    param([string]$Executable,[string[]]$Arguments)
    $state.Calls++
    $joined = $Arguments -join "`0"
    if($Executable -eq 'X:\fake\git.exe' -and $joined -eq ("-C`0" + $fixtureRoot + "`0rev-parse`0HEAD")){
      return $Head
    }
    if($Executable -eq 'X:\fake\git.exe' -and $joined -eq ("-C`0" + $fixtureRoot + "`0status`0--porcelain`0--untracked-files=no")){
      return $Status
    }
    if($Executable -eq $fixtureExecutable -and $joined -eq 'version'){
      return "vcpkg package management program version $ExecutableRelease"
    }
    throw "unexpected job probe: $Executable / $joined"
  }.GetNewClosure()
  $metadataReader = { param([string]$Root) "VCPKG_TOOL_RELEASE_TAG=$MetadataRelease`n" }.GetNewClosure()
  $testResult = Test-YuzuVcpkgCheckout -Contract $ContractUnderTest `
    -VcpkgRoot $fixtureRoot -GitExecutable 'X:\fake\git.exe' -ProbeRunner $runner `
    -MetadataReader $metadataReader
  [pscustomobject]@{ Result=$testResult; Calls=$state.Calls }
}

$jobFixture = Invoke-VcpkgFixture
Check 'the job-scoped effective vcpkg checkout passes at the reviewed baseline' {
  $jobFixture.Result.Healthy -and $jobFixture.Calls -eq 3 -and
  @($jobFixture.Result.Observations).Count -eq 3
}

$jobFixture = Invoke-VcpkgFixture -Head '1111111111111111111111111111111111111111'
Check 'a job-scoped vcpkg checkout at the wrong HEAD fails closed' {
  (-not $jobFixture.Result.Healthy) -and
  ($jobFixture.Result.Errors -join "`n") -match "checkout HEAD is '1111111111111111111111111111111111111111'"
}

$jobFixture = Invoke-VcpkgFixture -Status ' M ports/grpc/portfile.cmake'
Check 'a modified job-scoped vcpkg tracked tree fails closed' {
  (-not $jobFixture.Result.Healthy) -and
  ($jobFixture.Result.Errors -join "`n") -match "tracked tree is 'M ports/grpc/portfile.cmake'"
}

$jobFixture = Invoke-VcpkgFixture -ExecutableRelease '2026-07-27-2222222222222222222222222222222222222222'
Check 'a stale effective vcpkg executable fails even at the pinned checkout' {
  (-not $jobFixture.Result.Healthy) -and
  ($jobFixture.Result.Errors -join "`n") -match "reports '2026-07-27-2222222222222222222222222222222222222222'; checkout metadata requires release '2026-07-28'"
}

$jobFixture = Invoke-VcpkgFixture -MetadataRelease '' -ExecutableRelease '2026-07-28-fixture'
Check 'missing vcpkg tool-release metadata fails closed' {
  (-not $jobFixture.Result.Healthy) -and
  ($jobFixture.Result.Errors -join "`n") -match 'has no VCPKG_TOOL_RELEASE_TAG'
}

$missingJobPin = Copy-TestManifest $contract
$missingJobPin.job_pins = [pscustomobject]@{}
$jobFixture = Invoke-VcpkgFixture -ContractUnderTest $missingJobPin
Check 'deleting the job-scoped baseline pin fails before executing a probe' {
  (-not $jobFixture.Result.Healthy) -and $jobFixture.Calls -eq 0 -and
  ($jobFixture.Result.Errors -join "`n") -match "job pin 'vcpkg_baseline'"
}

$defaultVcpkgResult = Test-YuzuVcpkgCheckout -Contract $contract `
  -VcpkgRoot (Join-Path ([IO.Path]::GetTempPath()) 'yuzu-missing-vcpkg') `
  -GitExecutable (Get-Process -Id $PID).Path `
  -MetadataReader { param([string]$Root) 'VCPKG_TOOL_RELEASE_TAG=fixture' }
Check 'the job vcpkg default probe adapter retains module scope' {
  $messages = $defaultVcpkgResult.Errors -join "`n"
  (-not $defaultVcpkgResult.Healthy) -and $messages -match 'checkout HEAD probe failed' -and
  $messages -notmatch "Invoke-YuzuContractProbe.*not recognized"
}

$module = Get-Module Toolchain-Contract
$pwshExecutable = (Get-Process -Id $PID).Path
$timeoutMessage = ''
try {
  & $module {
    param([string]$Executable)
    Invoke-YuzuContractProbe -Executable $Executable `
      -Arguments @('-NoProfile','-Command','Start-Sleep -Seconds 120') -TimeoutSeconds 1
  } $pwshExecutable | Out-Null
} catch {
  $timeoutMessage = $_.Exception.Message
}
Check 'a hung executable probe is killed at its one-second test deadline' {
  # Do not grade wall clock here: CI contention can deschedule a correct kill.
  # The exception proves the bounded branch; Meson's test timeout catches hangs.
  $timeoutMessage -match 'timed out after 1s'
}

# The parameter defaults remain duplicated for readability, so prove the real
# provisioner refuses accidental drift before any mutating Step runs.
$tokens = $null
$parseErrors = $null
$provisionAst = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path -LiteralPath $ProvisionPath).Path, [ref]$tokens, [ref]$parseErrors)
Check 'the provisioning script remains syntactically valid' { $parseErrors.Count -eq 0 }
$updaterTokens = $null
$updaterParseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path -LiteralPath $ManifestUpdaterPath).Path, [ref]$updaterTokens, [ref]$updaterParseErrors)
Check 'the manifest-only updater remains syntactically valid' {
  $updaterParseErrors.Count -eq 0
}
$vcpkgTokens = $null
$vcpkgParseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path -LiteralPath $AssertVcpkgPath).Path, [ref]$vcpkgTokens, [ref]$vcpkgParseErrors)
Check 'the job-scoped vcpkg assertion script remains syntactically valid' {
  $vcpkgParseErrors.Count -eq 0
}
$vcpkgAssertText = Get-Content -LiteralPath $AssertVcpkgPath -Raw
Check 'the vcpkg wrapper uses the shared first-match command resolver' {
  $vcpkgAssertText -match '(?m)^\s*\$git\s*=\s*Resolve-YuzuEffectiveCommand\s+-Name\s+git\s*$'
}
$provisionText = Get-Content -LiteralPath $ProvisionPath -Raw
$parameterByName = @{}
foreach($parameter in @($provisionAst.ParamBlock.Parameters)){
  $parameterByName[$parameter.Name.VariablePath.UserPath] = $parameter
}
Check 'the standalone assertion models runner-local MSYS2 PATH without leaking it' {
  $assertText = Get-Content -LiteralPath $AssertPath -Raw
  $probeAt = $assertText.IndexOf("command -v head")
  $setPathAt = $assertText.LastIndexOf('$env:Path = "$bashDir;$oldPath"', $probeAt)
  $restoreAt = $assertText.IndexOf('$env:Path = $oldPath', $probeAt)
  $setPathAt -ge 0 -and $probeAt -gt $setPathAt -and $restoreAt -gt $probeAt
}
Check 'the authenticated PostgreSQL probe uses the bounded process primitive' {
  $assertText = Get-Content -LiteralPath $AssertPath -Raw
  $psqlAt = $assertText.IndexOf('if($c.psql')
  $boundedAt = $assertText.IndexOf('Invoke-YuzuContractProbe', $psqlAt)
  $timeoutAt = $assertText.IndexOf('-TimeoutSeconds ([int]$contract.probe_timeout_seconds)', $boundedAt)
  $psqlAt -ge 0 -and $boundedAt -gt $psqlAt -and $timeoutAt -gt $boundedAt
}
Check 'provisioning parameter defaults equal every reviewed pin' {
  $mapping = [ordered]@{
    PythonVersion='python'; MesonVersion='meson'; ErlangVersion='erlang'
    Rebar3Version='rebar3'; PostgresVersion='postgres'; WindowsSdkVersion='windows_sdk'
    VcpkgBaseline='vcpkg_baseline'
  }
  foreach($entry in $mapping.GetEnumerator()){
    $parameter = $parameterByName[$entry.Key]
    $expected = if($entry.Value -eq 'vcpkg_baseline'){
      [string]$contract.job_pins.vcpkg_baseline
    } else {
      [string]$contract.pins.($entry.Value)
    }
    if(-not $parameter -or [string]$parameter.DefaultValue.SafeGetValue() -ne $expected){
      return $false
    }
  }
  $true
}
Check 'the provisioner compares every reviewed pin before its first Step' {
  $compareAt = $provisionText.IndexOf('$requestedPins.GetEnumerator()')
  $firstStepAt = $provisionText.IndexOf("Step 'winget sanity'")
  $presentPins = @(@('python','meson','erlang','rebar3','postgres','windows_sdk','vcpkg_baseline') |
    Where-Object {
      $pattern = '(?m)^\s*' + [regex]::Escape([string]$_) + '='
      $provisionText -match $pattern
    })
  $ok = $compareAt -ge 0 -and $firstStepAt -gt $compareAt -and $presentPins.Count -eq 7
  if(-not $ok){
    Write-Host "        compareAt=$compareAt firstStepAt=$firstStepAt pins=$($presentPins -join ',')" -ForegroundColor DarkYellow
  }
  $ok
}
Check 'a Visual Studio reboot-required result stops before manifest emission' {
  $stopFunctions = @($provisionAst.FindAll({
    param($ast)
    $ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $ast.Name -eq 'Stop-YuzuProvisioningForReboot'
  }, $true))
  if($stopFunctions.Count -ne 1){ return $false }
  $directExits = @($stopFunctions[0].Body.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.ExitStatementAst]
  })
  $manifestAt = $provisionText.IndexOf('Step "emit toolchain manifest')
  $directExits.Count -eq 1 -and $directExits[0].Pipeline.Extent.Text.Trim() -eq '3' -and
    $directExits[0].Extent.EndOffset -lt $manifestAt
}
Check 'fresh and existing Build Tools paths both apply installer exit policy' {
  $policyCalls = @($provisionAst.FindAll({
    param($ast)
    $ast -is [System.Management.Automation.Language.CommandAst] -and
    $ast.GetCommandName() -eq 'Invoke-YuzuInstallerExitPolicy'
  }, $true))
  $wgFunctions = @($provisionAst.FindAll({
    param($ast)
    $ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $ast.Name -eq 'WG'
  }, $true))
  if($wgFunctions.Count -ne 1){ return $false }
  $policyGuards = @($wgFunctions[0].Body.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.IfStatementAst] -and
    $_.Clauses.Count -eq 1 -and $_.Clauses[0].Item1.Extent.Text.Trim() -eq '$EnforceExitPolicy'
  })
  if($policyGuards.Count -ne 1){ return $false }
  $guardPolicyCalls = @($policyGuards[0].Clauses[0].Item2.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.PipelineAst] -and
    @($_.PipelineElements | Where-Object {
      $_ -is [System.Management.Automation.Language.CommandAst] -and
      $_.GetCommandName() -eq 'Invoke-YuzuInstallerExitPolicy'
    }).Count -eq 1
  })
  $freshCalls = @($provisionAst.FindAll({
    param($ast)
    $ast -is [System.Management.Automation.Language.CommandAst] -and
    $ast.GetCommandName() -eq 'WG' -and
    $ast.Extent.Text -match 'Microsoft\.VisualStudio\.2022\.BuildTools'
  }, $true))
  $modifyCalls = @($policyCalls | Where-Object {
    $_.Extent.Text -match "-Context\s+'Visual Studio Installer modify'"
  })
  $manifestAt = $provisionText.IndexOf('Step "emit toolchain manifest')
  $policyCalls.Count -eq 2 -and $guardPolicyCalls.Count -eq 1 -and
    $guardPolicyCalls[0].Extent.Text -match '-RebootHandler.*Stop-YuzuProvisioningForReboot' -and
    $freshCalls.Count -eq 1 -and $freshCalls[0].Extent.Text -match '-EnforceExitPolicy' -and
    $modifyCalls.Count -eq 1 -and
    $modifyCalls[0].Extent.Text -match '-RebootHandler.*Stop-YuzuProvisioningForReboot' -and
    $modifyCalls[0].Extent.EndOffset -lt $manifestAt
}
Check 'the provisioner reconciles Python before pip or later provisioning steps' {
  $pythonStepAt = $provisionText.IndexOf("Step 'Python + Meson + Ninja + PyYAML'")
  $telemetryStepAt = $provisionText.IndexOf("Step 'Persistent per-runner CI telemetry databases'", $pythonStepAt)
  $pythonStep = if($pythonStepAt -ge 0 -and $telemetryStepAt -gt $pythonStepAt){
    $provisionText.Substring($pythonStepAt, $telemetryStepAt - $pythonStepAt)
  } else { '' }
  $resolveAt = $pythonStep.IndexOf('Resolve-YuzuPinnedPython')
  $pipAt = $pythonStep.IndexOf('-m pip')
  $resolveAt -ge 0 -and $pipAt -gt $resolveAt
}
Check 'the emitted manifest carries the reviewed schema' {
  $provisionText -match '(?m)^\s*schema\s*=\s*\[string\]\$toolchainContract\.schema\s*$'
}
Check 'the deployed runner-control bundle contains contract, module, and assertion' {
  foreach($name in @('toolchain-contract.json','Toolchain-Contract.psm1','Assert-Toolchain.ps1','Update-ToolchainManifest.ps1')){
    if($provisionText -notmatch [regex]::Escape("'$name'")){ return $false }
  }
  $true
}
Check 'the manifest-only updater is drained, live-asserted, and atomic' {
  $updater = Get-Content -LiteralPath $ManifestUpdaterPath -Raw
  @([regex]::Matches($updater, "Assert-NoActiveRunnerJob '")).Count -eq 2 -and
    $updater -match "Name = 'Runner\.Worker\.exe'" -and
    $updater -notmatch "Name = 'Runner\.Listener\.exe'" -and
    $updater -match 'Install-YuzuToolchainManifestCandidate' -and
    $updater -notmatch 'Provision-Windows-Runner\.ps1'
}
Check 'Windows CI gates the effective checkout after Setup vcpkg and before install' {
  $ciText = Get-Content -LiteralPath $CiWorkflowPath -Raw
  $windowsJobAt = $ciText.IndexOf("`n  windows:")
  $manifestAt = $ciText.IndexOf('- name: Assert toolchain manifest', $windowsJobAt)
  $setupAt = $ciText.IndexOf('- name: Setup vcpkg', $windowsJobAt)
  $assertAt = $ciText.IndexOf('- name: Assert effective vcpkg checkout', $setupAt)
  $installAt = $ciText.IndexOf('- name: Install vcpkg packages', $setupAt)
  $nextManifestStepAt = $ciText.IndexOf("`n      - name:", $manifestAt + 1)
  $manifestStep = if($nextManifestStepAt -gt $manifestAt){ $ciText.Substring($manifestAt, $nextManifestStepAt - $manifestAt) } else { '' }
  $nextStepAt = $ciText.IndexOf("`n      - name:", $assertAt + 1)
  $assertStep = if($nextStepAt -gt $assertAt){ $ciText.Substring($assertAt, $nextStepAt - $assertAt) } else { '' }
  $manifestAt -gt $windowsJobAt -and $manifestAt -lt $setupAt -and
  $assertAt -gt $setupAt -and $installAt -gt $assertAt -and
  $manifestStep -match 'Assert-Toolchain\.ps1' -and
  $manifestStep -notmatch '(?im)^\s*(?:if|continue-on-error)\s*:|if\s*\(\s*Test-Path|\|\|\s*true\b' -and
  $assertStep -match 'Assert-VcpkgCheckout\.ps1' -and
  $assertStep -notmatch '(?im)^\s*if\s*:' -and $assertStep -notmatch 'if\s*\(\s*Test-Path'
}
Check 'Windows release gates the host manifest and effective vcpkg checkout' {
  $releaseText = Get-Content -LiteralPath $ReleaseWorkflowPath -Raw
  $windowsJobAt = $releaseText.IndexOf("`n  build-windows:")
  $manifestAt = $releaseText.IndexOf('- name: Assert toolchain manifest', $windowsJobAt)
  $setupAt = $releaseText.IndexOf('- name: Setup vcpkg', $windowsJobAt)
  $checkoutAt = $releaseText.IndexOf('- name: Assert effective vcpkg checkout', $setupAt)
  $installAt = $releaseText.IndexOf('- name: Install vcpkg packages', $setupAt)
  $nextManifestStepAt = $releaseText.IndexOf("`n      - name:", $manifestAt + 1)
  $manifestStep = if($nextManifestStepAt -gt $manifestAt){ $releaseText.Substring($manifestAt, $nextManifestStepAt - $manifestAt) } else { '' }
  $manifestAt -gt $windowsJobAt -and $manifestAt -lt $setupAt -and
  $checkoutAt -gt $setupAt -and $installAt -gt $checkoutAt -and
  $releaseText -match 'Assert-Toolchain\.ps1' -and
  $releaseText -match 'Assert-VcpkgCheckout\.ps1' -and
  $manifestStep -notmatch '(?im)^\s*(?:if|continue-on-error)\s*:|if\s*\(\s*Test-Path|\|\|\s*true\b'
}
Check 'Windows nightly requires the host manifest without an optional guard' {
  $nightlyText = Get-Content -LiteralPath $NightlyWorkflowPath -Raw
  $windowsJobAt = $nightlyText.IndexOf("`n  windows-asan:")
  $manifestAt = $nightlyText.IndexOf('- name: Assert toolchain manifest (self-hosted)', $windowsJobAt)
  $nextStepAt = $nightlyText.IndexOf("`n      - name:", $manifestAt + 1)
  $manifestStep = if($nextStepAt -gt $manifestAt){ $nightlyText.Substring($manifestAt, $nextStepAt - $manifestAt) } else { '' }
  $disabledFixture = "- name: Assert toolchain manifest (self-hosted)`n        if: false`n        run: ./deploy/windows/Assert-Toolchain.ps1"
  $suppressedFixture = "- name: Assert toolchain manifest (self-hosted)`n        continue-on-error: true`n        run: ./deploy/windows/Assert-Toolchain.ps1 || true"
  $manifestAt -gt $windowsJobAt -and $manifestStep -match 'Assert-Toolchain\.ps1' -and
    $manifestStep -notmatch '(?im)^\s*(?:if|continue-on-error)\s*:|optional|skipping manifest|if\s*\(\s*Test-Path|\|\|\s*true\b' -and
    $disabledFixture -match '(?im)^\s*if\s*:' -and
    $suppressedFixture -match '(?im)^\s*continue-on-error\s*:|\|\|\s*true\b'
}
Check 'the baseline updater covers every active tracked SHA reference' {
  $workflow = Get-Content -LiteralPath $BaselineWorkflowPath -Raw
  $filesMatch = [regex]::Match($workflow, '(?ms)^\s+files=\(\r?\n(?<body>.*?)^\s+\)')
  if(-not $filesMatch.Success){ return $false }
  $listed = @($filesMatch.Groups['body'].Value -split '\r?\n' |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
  $references = @(& git -C $repoRoot grep -l -- ([string]$contract.job_pins.vcpkg_baseline))
  if($LASTEXITCODE -ne 0){ return $false }
  $activeReferences = @($references | Where-Object { $_ -notlike 'docs/reviews/*' })
  $missing = @($activeReferences | Where-Object { $listed -notcontains $_ })
  $missing.Count -eq 0 -and $listed -contains 'deploy/windows/toolchain-contract.json'
}

# Exercise the real Assert script's schema seams in child processes. An unknown
# or missing schema must stop before any fake tool, service, registry, or PG
# probe.
$work = Join-Path ([IO.Path]::GetTempPath()) "yuzu_test_toolchain_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $missingManifestPath = Join-Path $work 'does-not-exist.json'
  $output = & pwsh -NoProfile -File $AssertPath -ManifestPath $missingManifestPath -ContractPath $ContractPath 2>&1 | Out-String
  $exitCode = $LASTEXITCODE
  Check 'Assert-Toolchain exits 1 when the host manifest is missing' {
    $exitCode -eq 1 -and $output -match 'FAIL: no manifest' -and $output -notmatch '-- tools --'
  }

  $badManifestPath = Join-Path $work 'bad-schema.json'
  $badManifest = Copy-TestManifest $valid
  $badManifest.schema = 'yuzu/windows-toolchain/v999'
  $badManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $badManifestPath -Encoding UTF8
  $output = & pwsh -NoProfile -File $AssertPath -ManifestPath $badManifestPath -ContractPath $ContractPath 2>&1 | Out-String
  $exitCode = $LASTEXITCODE
  Check 'Assert-Toolchain exits 1 at the incompatible-schema seam' {
    $exitCode -eq 1 -and $output -match "manifest schema 'yuzu/windows-toolchain/v999' is incompatible" -and
    $output -notmatch '-- tools --'
  }

  $legacyManifestPath = Join-Path $work 'legacy-schema.json'
  $legacyManifest = Copy-TestManifest $valid
  $legacyManifest.PSObject.Properties.Remove('schema')
  $legacyManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $legacyManifestPath -Encoding UTF8
  $output = & pwsh -NoProfile -File $AssertPath -ManifestPath $legacyManifestPath -ContractPath $ContractPath 2>&1 | Out-String
  $exitCode = $LASTEXITCODE
  Check 'Assert-Toolchain exits 1 at the schema-less seam (bridge retired)' {
    $exitCode -eq 1 -and $output -match "manifest schema '<unset>' is incompatible" -and
    $output -notmatch '-- tools --'
  }
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n$script:passed passed, $script:failed failed" -ForegroundColor Cyan
if($script:failed){ exit 1 }
exit 0
