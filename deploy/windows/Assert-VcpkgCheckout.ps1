#Requires -Version 7
<#
  Fail-closed assertion for the job-scoped vcpkg checkout that Windows CI
  actually executes. This deliberately does not read the host manifest:
  lukka/run-vcpkg creates the effective checkout under GITHUB_WORKSPACE, and
  its baseline can roll forward in a PR without reprovisioning the runner.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$VcpkgRoot,
  [string]$ContractPath = (Join-Path $PSScriptRoot 'toolchain-contract.json')
)
$ErrorActionPreference = 'Stop'

try {
  Import-Module (Join-Path $PSScriptRoot 'Toolchain-Contract.psm1') -Force -ErrorAction Stop
  $contract = Read-YuzuToolchainContract -Path $ContractPath
  $git = Resolve-YuzuEffectiveCommand -Name git
  $result = Test-YuzuVcpkgCheckout -Contract $contract -VcpkgRoot $VcpkgRoot -GitExecutable $git
} catch {
  Write-Host "FAIL: could not evaluate effective vcpkg checkout ($($_.Exception.Message))" -ForegroundColor Red
  exit 1
}

foreach($observation in @($result.Observations)){
  $label = if($observation.Matched){ 'OK' } else { 'SEEN' }
  Write-Host "  [$label] $($observation.Name): $($observation.Actual) (expected $($observation.Expected))"
}
if(-not $result.Healthy){
  foreach($errorMessage in @($result.Errors)){
    Write-Host "  [MISS] $errorMessage" -ForegroundColor Red
  }
  Write-Host 'FAIL: effective vcpkg checkout does not satisfy the repository contract' -ForegroundColor Red
  exit 1
}

Write-Host 'PASS: effective vcpkg checkout satisfies the repository contract' -ForegroundColor Green
exit 0
