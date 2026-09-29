<#
  Start-PinnedRunner.ps1 — supervise ONE GitHub Actions runner, hard-pinned to a
  single Threadripper 9970X CCD (a 32 MB L3 domain) so a build (ninja/cl.exe)
  never migrates across an L3 boundary.

  Canonical, version-controlled copy. The provisioning spec is
  deploy/windows/Provision-Windows-Runner.ps1; registration is in
  deploy/windows/README.md.

  CCD map (9970X = 4 CCDs x 8C/16T, 32 MB L3 each):
     Index  CCD  logical CPUs   affinity mask
       0     0    0-15          0x000000000000FFFF
       1     1    16-31         0x00000000FFFF0000
       2     2    32-47         0x0000FFFF00000000
       3     3    48-63         0xFFFF000000000000
     mask = 0xFFFF << (16 * Index)

  Affinity is set on THIS process; run.cmd and every descendant
  (Runner.Listener -> Runner.Worker -> cmd/pwsh -> ninja -> cl.exe) inherit it.
  Launch via a scheduled task / console, NOT `svc.cmd install` — the service
  control manager starts the runner with full affinity, breaking the pin.

  Persistent model: run.cmd runs continuously (job after job). This wrapper just
  restarts it if it ever exits (crash, runner auto-update, manual stop).
  Ephemeral/JIT re-arm is deferred — tracked in issue #1595.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateRange(0,3)][int]$Index,
  [string]$RunnerRoot = "C:\actions-runner\r$Index",
  [string]$RunnerWork = "D:\ci\work-$Index",
  # Shared CI tool cache (P0): all runners point RUNNER_TOOL_CACHE at ONE
  # machine-level dir so ${{ runner.tool_cache }} (hence VCPKG_DEFAULT_BINARY_CACHE
  # in ci.yml) is shared, not fragmented per-runner. Mirrors CCACHE_DIR=D:\ci\ccache.
  [string]$ToolCache  = 'D:\ci\tool_cache',
  # Persistent CI telemetry is deliberately per runner (no cross-agent SQLite
  # writer contention) and outside every checkout/branch-clean boundary.
  [string]$TelemetryRoot = 'D:\ci\test-runs'
)
$ErrorActionPreference = 'Continue'

# --- pin: 16-thread mask for CCD #Index; children inherit at creation ---
[int64]$mask = [int64]0xFFFF -shl (16 * $Index)
$first = 16 * $Index
[System.Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity = [IntPtr]$mask
Write-Host ("[r{0}] pinned to CCD{0}  cpus {1}-{2}  mask=0x{3:X16}" -f $Index,$first,($first+15),$mask)

# Refresh the process environment from the live machine registry. The Task
# Scheduler service hands tasks a CACHED env block, so a runner launched this
# way misses PATH/vars added after the service last refreshed (Python, Meson,
# ninja, cmake, ccache, VCPKG_ROOT, YUZU_ESCRIPT/YUZU_REBAR3, the Postgres DSN).
# Without this the CI "Assert toolchain available" step fails. run.cmd -> jobs
# inherit this env.
foreach($e in [Environment]::GetEnvironmentVariables('Machine').GetEnumerator()){
  if($e.Key -ieq 'Path'){ continue }
  [Environment]::SetEnvironmentVariable($e.Key, $e.Value, 'Process')
}
$userPath = [Environment]::GetEnvironmentVariable('Path','User')
# Prepend MSYS2 /usr/bin: the Windows CI jobs use `bash --noprofile`, whose
# scripts call coreutils (head/grep/sed/find/sort). MSYS2 tools take precedence
# in the bash context; MSVC (prepended by msvc-dev-cmd at job time) still wins
# for cl/link. Without this, "Assert toolchain available" dies on `head`.
$env:Path = 'C:\msys64\usr\bin;' + [Environment]::GetEnvironmentVariable('Path','Machine') + $(if($userPath){ ";$userPath" } else { '' })
Write-Host "[r$Index] env refreshed (MSYS2 /usr/bin + machine registry)"

# Route native MSVC/CMake/Python TEMP+TMP and MSYS2 TMPDIR into this runner's
# own GitHub work temp directory. Its parent work root is the narrow Defender
# exclusion; using the profile-wide or system-wide temp directory would both
# restore scan overhead and mix temporary files from all four CCD runners.
$runnerTemp = Join-Path $RunnerWork '_temp'
New-Item -ItemType Directory -Force $runnerTemp | Out-Null
[Environment]::SetEnvironmentVariable('TEMP', $runnerTemp, 'Process')
[Environment]::SetEnvironmentVariable('TMP', $runnerTemp, 'Process')
[Environment]::SetEnvironmentVariable('TMPDIR', ($runnerTemp -replace '\\','/'), 'Process')
Write-Host "[r$Index] TEMP/TMP/TMPDIR = $runnerTemp (per-runner, Defender-excluded)"

# Shared vcpkg binary cache (P0). The runner reads RUNNER_TOOL_CACHE at Listener
# startup; this is belt-and-suspenders alongside the runner's .env. Pointing all
# four runners here means ONE warm vcpkg binary cache, not four per-runner copies
# (~1.9 GB each). ccache already shares via CCACHE_DIR. (The vcpkg binary cache is
# content-addressed, so concurrent writes across the 4 runners are safe.)
[Environment]::SetEnvironmentVariable('RUNNER_TOOL_CACHE', $ToolCache, 'Process')
New-Item -ItemType Directory -Force $ToolCache | Out-Null
Write-Host "[r$Index] RUNNER_TOOL_CACHE = $ToolCache (shared)"

# One durable test-runs.db per runner agent. Provision-Windows-Runner.ps1
# initializes all four schemas; ci-telemetry.py idempotently initializes as a
# recovery net and appends one job + suite record on every ci.yml leg.
$runnerName = "yuzu-weetam-windows-$Index"
$telemetryDb = Join-Path (Join-Path $TelemetryRoot $runnerName) 'test-runs.db'
New-Item -ItemType Directory -Force (Split-Path $telemetryDb) | Out-Null
[Environment]::SetEnvironmentVariable('YUZU_TEST_DB', $telemetryDb, 'Process')
Write-Host "[r$Index] YUZU_TEST_DB = $telemetryDb (persistent, per-runner)"

# Provisioning owns the build-width contract. Consume the refreshed machine
# value rather than carrying a second wrapper default that can silently drift.
# This wrapper is specific to the 9970X's fixed 16-thread CCD envelope.
if($env:YUZU_BUILD_JOBS -ne '16'){
  Write-Error "[r$Index] YUZU_BUILD_JOBS must be provisioned as 16 (got '$($env:YUZU_BUILD_JOBS ?? '<unset>')')"
  exit 1
}
Write-Host "[r$Index] YUZU_BUILD_JOBS = $env:YUZU_BUILD_JOBS (provisioned machine contract)"

# Registration-time self-test: assert the toolchain manifest (if present) before
# taking jobs, so a mis-provisioned box is flagged loudly at startup instead of
# 90 min into a build. WARN, don't block — the in-job "Assert toolchain
# available" step hard-fails a genuinely broken build, and we'd rather a
# slightly-stale manifest not strand a runner offline. (Assert-Toolchain.ps1
# deploys alongside this wrapper — see deploy/windows/README.md.)
$selftest = Join-Path $PSScriptRoot 'Assert-Toolchain.ps1'
$manifest = 'C:\actions-runner\toolchain-manifest.json'
if((Test-Path $selftest) -and (Test-Path $manifest)){
  & $selftest -ManifestPath $manifest
  if($LASTEXITCODE -ne 0){ Write-Warning "[r$Index] toolchain self-test FAILED — starting anyway; fix provisioning (see deploy/windows/README.md)." }
} else {
  Write-Host "[r$Index] toolchain self-test skipped (manifest/selftest not present)"
}

$run = Join-Path $RunnerRoot 'run.cmd'
while ($true) {
  if (-not (Test-Path (Join-Path $RunnerRoot '.runner'))) {
    Write-Warning "[r$Index] $RunnerRoot not configured yet (no .runner) — waiting 30s"
    Start-Sleep -Seconds 30
    continue
  }
  Write-Host "[r$Index] starting persistent run.cmd ..."
  & $run
  Write-Host "[r$Index] run.cmd exited ($LASTEXITCODE) — restarting in 5s"
  Start-Sleep -Seconds 5
}
