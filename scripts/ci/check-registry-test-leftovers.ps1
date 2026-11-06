<#
.SYNOPSIS
  Reports YuzuTest-* registry keys the Windows test phase left behind (#6488).

.DESCRIPTION
  The registry plugin's tests create scratch keys under HKLM\SOFTWARE (and Wow6432Node) and HKCU\Software
  (HKU\.DEFAULT for LOCAL SYSTEM) and each fixture removes its own; this is the tripwire that notices one that did
  not. It scans only the direct children named YuzuTest-* of those roots (the local dispatcher's
  Software\YuzuTest\RegistryPr17Ld_<salt> keys, test_registry_local_dispatcher.cpp:228,248, are outside it). The
  fixtures name their keys YuzuTest-<Scope>-<salt>... (tests/unit/test_helpers.hpp,
  registry_scratch_prefix), so the scan judges ONE job: with-test-slot.sh lets two test phases share a box at once and
  the runner agents share one OS identity, so a machine-wide YuzuTest-* scan would call a concurrent job's live keys
  a leak.

    - a key named YuzuTest-<Scope>-* is this job's leak: ::error per key, exit 1.
    - any other YuzuTest-* key is a ::warning only (an orphan of a cancelled or crashed job, a concurrent job's live
      key, the nightly windows-asan leg's unscoped keys): it never fails this job.

  It REPORTS and never deletes: a leftover can be a registry link, and every tree delete follows links (the plugin's
  own rule), so removal is left to a human.

  Run by .github/workflows/ci.yml three times per Windows job: twice before the suite in a self-test that plants a probe
  key under each scanned root and proves both decisions (exit 1 naming the keys, exit 0 with a warning), then once
  after the suite step with the job's own scope.
  Keep this file ASCII only (Windows PowerShell 5.1 misreads BOM-less UTF-8).

.PARAMETER Scope
  The registry-name-safe job scope the fixtures were given through YUZU_TEST_REGISTRY_SCOPE. Mandatory and never
  empty: an empty scope would make every YuzuTest-* key this job's.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Scope
)

$prefix = "YuzuTest-$Scope-"
$roots = 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\Wow6432Node', 'HKCU:\Software'
$failed = @()
$all = @(foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }   # a root this OS does not have holds nothing
    try { Get-ChildItem -LiteralPath $root -ErrorAction Stop | Where-Object { $_.PSChildName -like 'YuzuTest-*' } }
    catch { $failed += $root; Write-Host "::error::could not list $root so its leftovers are unknown: $($_.Exception.Message)" }
})
$mine, $others = $all.Where({ $_.PSChildName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) }, 'Split')
foreach ($k in $others) { Write-Host "::warning::registry key from another job or a cancelled run, not removed: $($k.Name)" }
foreach ($k in $mine) { Write-Host "::error::leftover registry key $($k.Name)" }
if ($mine.Count -gt 0 -or $failed.Count -gt 0) { exit 1 }
Write-Host 'no YuzuTest-* keys left by this job'
exit 0
