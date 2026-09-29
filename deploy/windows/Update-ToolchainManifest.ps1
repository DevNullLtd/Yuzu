#Requires -Version 7
<#
  Refresh a Windows runner's host-generated manifest without provisioning or
  reconciling the host.  This is the safe rollout path for an already-installed
  reviewed toolchain change on hosts whose runner topology differs from Wee Tam.

  The prior manifest remains the topology source (runner count, telemetry DBs,
  and per-runner PostgreSQL clusters).  Reviewed pins and artifact paths come
  from toolchain-contract.json.  A temporary candidate must pass the complete
  live Assert-Toolchain gate before it atomically replaces the prior manifest.
#>
[CmdletBinding()]
param(
  [string]$ManifestPath = 'C:\actions-runner\toolchain-manifest.json',
  [string]$ContractPath = (Join-Path $PSScriptRoot 'toolchain-contract.json'),
  [string]$AssertPath = (Join-Path $PSScriptRoot 'Assert-Toolchain.ps1')
)
$ErrorActionPreference = 'Stop'

function Assert-NoActiveRunnerJob([string]$Context){
  try {
    $active = @(Get-CimInstance Win32_Process `
        -Filter "Name = 'Runner.Worker.exe'" -ErrorAction Stop)
  } catch {
    throw "[RUNNER-UNOBSERVABLE] worker check failed at $Context ($($_.Exception.Message))"
  }
  if($active.Count -gt 0){
    $detail = ($active | Sort-Object ProcessId |
        ForEach-Object { "$($_.Name)($($_.ProcessId))" }) -join ', '
    throw "[RUNNER-ACTIVE] GitHub Actions job live at ${Context}: $detail"
  }
}
try {
  Assert-NoActiveRunnerJob 'start'
} catch {
  Write-Error "refusing to update the manifest ($($_.Exception.Message))"
  exit 2
}

if(-not (Test-Path -LiteralPath $ManifestPath)){
  Write-Error "prior manifest not found: $ManifestPath"
  exit 1
}
try {
  Import-Module (Join-Path $PSScriptRoot 'Toolchain-Contract.psm1') -Force
  $contract = Read-YuzuToolchainContract -Path $ContractPath
  $prior = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
  $candidate = New-YuzuToolchainManifestDocument `
      -PriorManifest $prior -Contract $contract -HostName $env:COMPUTERNAME
} catch {
  Write-Error "could not construct a manifest candidate ($($_.Exception.Message))"
  exit 1
}

try {
  # Unlike provisioning, this script does not restart services or alter the
  # toolchain. An idle listener may remain online: a job racing this atomic
  # replacement sees either the old fail-closed manifest or the fully asserted
  # candidate. A live Worker still invalidates the maintenance observation.
  $result = Install-YuzuToolchainManifestCandidate `
      -Candidate $candidate -ManifestPath $ManifestPath `
      -ContractPath $ContractPath -AssertPath $AssertPath `
      -BeforeReplace { Assert-NoActiveRunnerJob 'before atomic replacement' }
  Write-Host "Updated manifest atomically: $ManifestPath" -ForegroundColor Green
  Write-Host "Previous manifest retained: $($result.BackupPath)" -ForegroundColor Yellow
} catch {
  Write-Error "manifest update failed; prior manifest retained ($($_.Exception.Message))"
  if($_.Exception.Message -match '^\[RUNNER-(?:ACTIVE|UNOBSERVABLE)\]'){ exit 2 }
  exit 1
}
