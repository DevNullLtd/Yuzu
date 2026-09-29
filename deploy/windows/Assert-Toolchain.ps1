#Requires -Version 7
<#
  Assert-Toolchain.ps1 — runner self-test. Verifies that the toolchain manifest
  emitted by Provision-Windows-Runner.ps1 still holds: every required tool is
  present at its recorded path, every contract env var is set, and every
  per-agent PostgreSQL service points at its private binary tree and serves.

  Run it (a) at the end of provisioning, and (b) as a registration / preflight
  gate, so a mis-provisioned box fails in SECONDS rather than 90 minutes into a
  build. This is the catch for the cutover faults (toolchain off PATH, MSYS2
  /usr/bin missing, gateway escript/rebar3 unresolved).

  Exit 0 = healthy; exit 1 = an incompatible manifest, a version mismatch,
  or at least one required tool/env item missing.
#>
[CmdletBinding()]
param(
  [string]$ManifestPath = 'C:\actions-runner\toolchain-manifest.json',
  [string]$ContractPath = (Join-Path $PSScriptRoot 'toolchain-contract.json')
)
$ErrorActionPreference = 'Stop'

if(-not (Test-Path $ManifestPath)){
  Write-Host "FAIL: no manifest at $ManifestPath — run Provision-Windows-Runner.ps1 first." -ForegroundColor Red
  exit 1
}
try {
  $m = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
} catch {
  Write-Host "FAIL: manifest is not valid JSON: $ManifestPath ($($_.Exception.Message))" -ForegroundColor Red
  exit 1
}

$contractModule = Join-Path $PSScriptRoot 'Toolchain-Contract.psm1'
if(-not (Test-Path -LiteralPath $contractModule)){
  Write-Host "FAIL: toolchain contract module missing at $contractModule" -ForegroundColor Red
  exit 1
}
try {
  Import-Module $contractModule -Force -ErrorAction Stop
  $contract = Read-YuzuToolchainContract -Path $ContractPath
  $contractResult = Test-YuzuToolchainManifest -Manifest $m -Contract $contract -ExpectedHost $env:COMPUTERNAME
} catch {
  Write-Host "FAIL: could not validate the toolchain contract ($($_.Exception.Message))" -ForegroundColor Red
  exit 1
}

Write-Host "Toolchain contract: $ContractPath" -ForegroundColor Cyan
foreach($observation in @($contractResult.Observations)){
  $label = if($observation.Matched){ 'OK' } else { 'SEEN' }
  $color = if($observation.Matched){ 'Green' } else { 'Yellow' }
  Write-Host ("  [{0}] {1,-18} {2} (expected {3})" -f $label, $observation.Name, $observation.Actual, $observation.Expected) -ForegroundColor $color
}
if(-not $contractResult.Healthy){
  foreach($problem in @($contractResult.Errors)){
    Write-Host "  [MISS] $problem" -ForegroundColor Red
  }
  Write-Host "`nFAIL: manifest/tool versions do not satisfy the repository contract." -ForegroundColor Red
  exit 1
}

$fail = 0

function Get-ServiceExe([string]$image){
  $trimmed = $image.TrimStart()
  if($trimmed -match '^"([^"]+)"'){ return $Matches[1] }
  return ($trimmed -split '\s+',2)[0]
}

Write-Host "Toolchain manifest: $ManifestPath" -ForegroundColor Cyan
Write-Host ("  schema=$($m.schema)  host=$($m.host)  generated=$($m.generated)")

Write-Host "`n-- tools --"
$toolPaths = Test-YuzuRequiredToolPaths -Tools @($m.tools)
foreach($t in @($toolPaths.Observations)){
  if($t.Exists){
    Write-Host ("  [OK]   {0,-11} {1}  ({2})" -f $t.Name, $t.Path, ($t.Version ?? '?')) -ForegroundColor Green
  } elseif($t.Required){
    $detail = if($t.Error){ " ($($t.Error))" } else { '' }
    Write-Host ("  [MISS] {0,-11} {1}{2}" -f $t.Name, ($t.Path ?? '<unset>'), $detail) -ForegroundColor Red
    $fail++
  } else {
    Write-Host ("  [warn] {0,-11} {1} (optional)" -f $t.Name, ($t.Path ?? '<unset>')) -ForegroundColor Yellow
  }
}

# Contract env vars must be visible to a freshly-launched process. Check the live
# machine registry (what Start-PinnedRunner.ps1 refreshes into the runner).
Write-Host "`n-- env (machine) --"
foreach($k in $m.env.PSObject.Properties.Name){
  $live = [Environment]::GetEnvironmentVariable($k,'Machine')
  $expected = [string]$m.env.$k
  if($live -and [string]::Equals($live, $expected, [StringComparison]::Ordinal)){
    Write-Host ("  [OK]   {0,-22} {1}" -f $k, $live) -ForegroundColor Green
  } elseif($live){
    Write-Host ("  [MISS] {0,-22} actual {1}; expected {2}" -f $k, $live, $expected) -ForegroundColor Red
    $fail++
  } else {
    Write-Host ("  [MISS] {0,-22} (expected {1})" -f $k, $expected) -ForegroundColor Red
    $fail++
  }
}

Write-Host "`n-- persistent CI telemetry --"
if($m.telemetry -and $m.telemetry.databases){
  foreach($db in $m.telemetry.databases){
    if($db -and (Test-Path -LiteralPath $db)){
      Write-Host ("  [OK]   {0}" -f $db) -ForegroundColor Green
    } else {
      Write-Host ("  [MISS] {0} — re-run provisioning" -f ($db ?? '<unset>')) -ForegroundColor Red
      $fail++
    }
  }
  $liveDb = [Environment]::GetEnvironmentVariable('YUZU_TEST_DB','Process')
  if($liveDb){ Write-Host ("  active runner DB: {0}" -f $liveDb) -ForegroundColor Green }
  else { Write-Host "  active runner DB: not in this shell (wrapper sets it per runner)" -ForegroundColor Yellow }
} else {
  # Rollout-compatible for a manifest generated before schema v3 landed: the
  # ci-telemetry start step still initializes this runner's DB. Re-running the
  # provisioner upgrades the manifest and turns all four paths into hard checks.
  Write-Host "  [warn] manifest predates telemetry inventory — re-run provisioning" -ForegroundColor Yellow
}

Write-Host "`n-- per-agent PostgreSQL --"
$hasClusterContract = ($m.PSObject.Properties.Name -contains 'postgres_clusters') -and
                      (@($m.postgres_clusters).Count -gt 0)
if(-not $hasClusterContract){
  Write-Host "  [MISS] manifest predates the per-agent binary/service contract — re-run provisioning" -ForegroundColor Red
  $fail++
} else {
  if(-not $m.runner_count -or @($m.postgres_clusters).Count -ne [int]$m.runner_count){
    Write-Host ("  [MISS] manifest has {0} PostgreSQL cluster(s), expected runner_count={1} — re-run provisioning" -f @($m.postgres_clusters).Count, ($m.runner_count ?? '<unset>')) -ForegroundColor Red
    $fail++
  }
  $oldPassword = $env:PGPASSWORD
  $env:PGPASSWORD = 'yuzu'
  try {
    foreach($c in @($m.postgres_clusters)){
      $clusterOk = $true
      foreach($path in @($c.pg_ctl,$c.postgres,$c.psql,$c.pg_isready)){
        if(-not $path -or -not (Test-Path -LiteralPath $path)){
          Write-Host ("  [MISS] agent {0}: required binary {1}" -f $c.agent, ($path ?? '<unset>')) -ForegroundColor Red
          $clusterOk = $false
          $fail++
        }
      }

      $svc = Get-Service -Name $c.service -EA SilentlyContinue
      if(-not $svc){
        Write-Host ("  [MISS] agent {0}: service {1} not registered" -f $c.agent, $c.service) -ForegroundColor Red
        $clusterOk = $false
        $fail++
      } elseif($svc.Status -ne 'Running'){
        Write-Host ("  [MISS] agent {0}: service {1} is {2}, expected Running" -f $c.agent, $c.service, $svc.Status) -ForegroundColor Red
        $clusterOk = $false
        $fail++
      }

      try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($c.service)"
        $image = (Get-ItemProperty $regPath -Name ImagePath -EA Stop).ImagePath
        $registeredExe = Get-ServiceExe $image
        if(-not [string]::Equals($registeredExe, $c.pg_ctl, 'OrdinalIgnoreCase')){
          Write-Host ("  [MISS] agent {0}: ImagePath executable is {1}, expected {2}" -f $c.agent, $registeredExe, $c.pg_ctl) -ForegroundColor Red
          $clusterOk = $false
          $fail++
        }
      } catch {
        Write-Host ("  [MISS] agent {0}: cannot read {1} ImagePath ({2})" -f $c.agent, $c.service, $_.Exception.Message) -ForegroundColor Red
        $clusterOk = $false
        $fail++
      }

      if($c.pg_isready -and (Test-Path -LiteralPath $c.pg_isready)){
        & $c.pg_isready -q -h 127.0.0.1 -p $c.port 2>$null
        if($LASTEXITCODE -ne 0){
          Write-Host ("  [MISS] agent {0}: PostgreSQL on :{1} is not ready" -f $c.agent, $c.port) -ForegroundColor Red
          $clusterOk = $false
          $fail++
        }
      }
      if($c.psql -and (Test-Path -LiteralPath $c.psql)){
        $probeError = $null
        try {
          $probe = (Invoke-YuzuContractProbe -Executable $c.psql `
            -Arguments @('-w','-U','yuzu','-d','yuzu_test','-h','127.0.0.1','-p',[string]$c.port,'-tAc','SELECT 1') `
            -TimeoutSeconds ([int]$contract.probe_timeout_seconds)).Trim()
        } catch {
          $probe = ''
          $probeError = $_.Exception.Message
        }
        if($probe -ne '1'){
          $detail = if($probeError){ ": $probeError" } else { '' }
          Write-Host ("  [MISS] agent {0}: authenticated SELECT 1 failed on :{1}{2}" -f $c.agent, $c.port, $detail) -ForegroundColor Red
          $clusterOk = $false
          $fail++
        }
      }
      if($clusterOk){
        Write-Host ("  [OK]   agent {0}: {1} -> {2}, :{3} serving" -f $c.agent, $c.service, $c.pg_ctl, $c.port) -ForegroundColor Green
      }
    }
  } finally {
    if($null -eq $oldPassword){ Remove-Item Env:\PGPASSWORD -EA SilentlyContinue }
    else { $env:PGPASSWORD = $oldPassword }
  }
}

# MSYS2 coreutils must be reachable the way the CI bash scripts use them
# (full path); this is the `head: command not found` regression guard.
$bash = ($m.tools | Where-Object name -eq 'msys2_bash').path
if($bash -and (Test-Path $bash)){
  # Provisioning deliberately keeps MSYS2 out of machine PATH so its
  # find/sort/etc. do not shadow Windows tools. Start-PinnedRunner prepends the
  # recorded bash directory inside each runner process; model that exact child
  # environment here without leaking it into the maintenance shell.
  $oldPath = $env:Path
  try {
    $bashDir = Split-Path -Parent $bash
    $env:Path = "$bashDir;$oldPath"
    $head = & $bash --noprofile --norc -c 'command -v head' 2>$null
  } finally {
    $env:Path = $oldPath
  }
  if($head){ Write-Host "`n  [OK]   msys2 bash resolves coreutils (head=$head)" -ForegroundColor Green }
  else     { Write-Host "`n  [MISS] msys2 bash cannot resolve 'head'" -ForegroundColor Red; $fail++ }
}

if($fail -eq 0){
  Write-Host "`nPASS: toolchain healthy." -ForegroundColor Green
  exit 0
} else {
  Write-Host "`nFAIL: $fail required item(s) missing — fix before registering this runner." -ForegroundColor Red
  exit 1
}
