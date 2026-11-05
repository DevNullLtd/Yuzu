<#
.SYNOPSIS
  Stops real-time ETW sessions that a dead Yuzu test process left behind (#7175).

.DESCRIPTION
  The echo plugin's registry source starts a system-wide real-time ETW session named YuzuEchoRegistryEtw-<pid>
  (agents/plugins/echo/src/echo_registry_source.cpp, registry_etw_session_name). A real-time session outlives its
  process until something stops it, so a test process that is killed (a meson timeout), crashes, or is cancelled leaves
  its session running. The four runner agents on Wee Tam share one OS identity on one box, so a leaked session is shared,
  accumulating state that nothing else cleans up. On 2026-11-05 `logman query -ets` there showed one such session for a
  dead pid while the Windows MSVC debug leg's `echo unit tests` failed on every run waiting for its own ETW event; the
  leg passed after the session was stopped (#7173, #7135). Whether the leak is the cause is not established; this is the
  preventive guard.

  What it does, in order:
    1. Lists the sessions with `logman query -ets` and logs the total (the system limit is 64) and the Yuzu count, so a
       slow build-up shows in the job log. At -WarnAt or more sessions it also emits a ::warning.
    2. For each session named Yuzu<letters>Etw-<digits> whose pid is not a running process, re-checks the pid and stops
       the session by EXACT name with `logman stop <name> -ets`. A session whose pid is alive is never touched, so a job
       running on one of the other runner slots keeps its session. A pid that was reused by an unrelated live process
       leaves its session in place (the safe direction; it is stopped once that process exits).
    3. Never fails the job: a listing or stop error is a ::warning and the script exits 0. It cannot make the test
       phase red; only -SelfTest can exit non-zero.

  Only names matching ^Yuzu[A-Za-z]*Etw-[0-9]+$ (case-sensitive, ASCII) are candidates. System, Defender and every
  other session are never matched.

  Run by .github/workflows/ci.yml in the Windows job: once before the test phase, once after it under always() (a
  killed or cancelled test process leaves its session behind at once), and in -SelfTest mode before either, which
  drives the same code with fake listing, liveness and stop functions and touches no real session.
  Keep this file ASCII only (Windows PowerShell 5.1 misreads BOM-less UTF-8).

.PARAMETER SelfTest
  Run the decision logic against canned `logman` output with injected liveness and stop functions. Throws (a
  non-zero exit under the CI shell) on a failed expectation, else exits 0. Starts no session and stops none.

.PARAMETER WarnAt
  Total session count at or above which a ::warning is emitted (default 48 of the 64-session system limit).

.PARAMETER Phase
  Free text naming the call site ("pre-test", "post-test"), used only in the log lines.
#>
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [ValidateRange(1, 64)]
    [int]$WarnAt = 48,
    [string]$Phase = 'run'
)

Set-StrictMode -Version 2.0

$SessionLimit = 64
# GitHub annotation prefix for the notes below. -SelfTest swaps it for plain text so a self-test never raises an
# annotation on the job.
$script:WarnPrefix = '::warning::'

# Parse `logman query -ets` output. Returns @{ Total = <int>; Yuzu = @(@{ Name; ProcessId }) }.
# A data row is "<name><2+ spaces>Trace<spaces><status>"; the name may contain spaces, so match from the right.
# Yuzu candidates are anchored at both ends: a look-alike (NotYuzu..., a non-numeric suffix) is not one.
function Read-EtwSessionList {
    param([string[]]$Lines)
    $total = 0
    $yuzu = @()
    foreach ($line in $Lines) {
        if (-not ($line -match '^(?<name>\S.*?)\s{2,}Trace\s+\S+\s*$')) { continue }
        $total++
        $name = $Matches['name'].Trim()
        if ($name -cmatch '^Yuzu[A-Za-z]*Etw-(?<pid>[0-9]+)$') {
            $parsed = 0
            if ([int]::TryParse($Matches['pid'], [ref]$parsed)) {
                $yuzu += [pscustomobject]@{ Name = $name; ProcessId = $parsed }
            } else {
                # too large to be a pid: not parseable, so not provably dead; leave it alone
                $yuzu += [pscustomobject]@{ Name = $name; ProcessId = -1 }
            }
        }
    }
    [pscustomobject]@{ Total = $total; Yuzu = $yuzu }
}

# A liveness probe that throws counts as ALIVE: the one wrong answer that can hurt is a false "dead", so every doubt
# resolves to leaving the session alone.
function Test-AliveSafe {
    param([scriptblock]$Probe, [int]$ProcessId)
    try { [bool](& $Probe $ProcessId) } catch { $true }
}

# The whole flow with its three outside-world functions injected, so -SelfTest drives it without touching the box.
#   -Query   : returns the lines of `logman query -ets`; throws on failure.
#   -IsAlive : param([int]$ProcessId) -> $true when a process with that id is running.
#   -Stop    : param([string]$Name) -> $true when the session was stopped.
function Invoke-EtwSessionCleanup {
    param(
        [scriptblock]$Query,
        [scriptblock]$IsAlive,
        [scriptblock]$Stop,
        [int]$WarnAt,
        [string]$Phase
    )
    $result = [pscustomobject]@{ Listed = $false; Total = 0; YuzuCount = 0; Warned = $false; Stopped = @(); Skipped = @(); Failed = @() }
    try {
        $lines = @(& $Query)
    } catch {
        Write-Host "${script:WarnPrefix}ETW session cleanup ($Phase): could not list sessions, nothing stopped: $($_.Exception.Message)"
        return $result
    }
    $list = Read-EtwSessionList -Lines $lines
    $result.Listed = $true
    $result.Total = $list.Total
    $result.YuzuCount = @($list.Yuzu).Count
    Write-Host "ETW sessions ($Phase): $($list.Total) total (system limit $SessionLimit), $(@($list.Yuzu).Count) Yuzu"
    if ($list.Total -eq 0) {
        # a successful `logman` listing always has at least the kernel loggers; zero means the output was not understood
        Write-Host "${script:WarnPrefix}ETW session cleanup ($Phase): no session rows parsed from the logman output, nothing stopped"
        return $result
    }
    if ($list.Total -ge $WarnAt) {
        $result.Warned = $true
        Write-Host "${script:WarnPrefix}ETW session count $($list.Total) is at or above $WarnAt of the $SessionLimit-session system limit"
    }
    foreach ($s in $list.Yuzu) {
        if ($s.ProcessId -lt 0 -or (Test-AliveSafe -Probe $IsAlive -ProcessId $s.ProcessId)) {
            $result.Skipped += $s.Name
            Write-Host "  keep $($s.Name): pid $($s.ProcessId) is running or not provably dead"
            continue
        }
        # re-check at the last moment: the pid is only worth acting on while it is still dead
        if (Test-AliveSafe -Probe $IsAlive -ProcessId $s.ProcessId) { $result.Skipped += $s.Name; continue }
        $stopped = $false
        try { $stopped = [bool](& $Stop $s.Name) } catch { $stopped = $false }
        if ($stopped) {
            $result.Stopped += $s.Name
            Write-Host "${script:WarnPrefix}stopped leaked ETW session $($s.Name): pid $($s.ProcessId) is not running ($Phase)"
        } else {
            $result.Failed += $s.Name
            Write-Host "${script:WarnPrefix}could not stop leaked ETW session $($s.Name) (pid $($s.ProcessId) is not running); leaving it ($Phase)"
        }
    }
    $result
}

function Test-Expect {
    param([bool]$Condition, [string]$What)
    if (-not $Condition) { throw "ETW cleanup self-test failed: $What" }
}

if ($SelfTest) {
    $script:WarnPrefix = 'selftest note: '
    $header = @(
        'Data Collector Set                      Type                          Status',
        '-------------------------------------------------------------------------------',
        'Circular Kernel Context Logger          Trace                         Running',
        'YuzuEchoRegistryEtw-111                 Trace                         Running',
        'YuzuEchoRegistryEtw-222                 Trace                         Running',
        'YuzuTarFileEtw-333                      Trace                         Running',
        'NotYuzuEchoRegistryEtw-444              Trace                         Running',
        'yuzuEchoRegistryEtw-555                 Trace                         Running',
        'YuzuEchoRegistryEtw-abc                 Trace                         Running',
        'YuzuEchoRegistryEtw-99999999999999      Trace                         Running',
        'Microsoft Defender ETW Session          Trace                         Running',
        '',
        'The command completed successfully.'
    )
    $script:alive = @(222)          # 111 and 333 are dead; 222 belongs to a live job on another slot
    $script:stopCalls = @()
    $isAlive = { param([int]$ProcessId) $script:alive -contains $ProcessId }
    $stopOk = { param([string]$Name) $script:stopCalls += $Name; $true }

    # arm 1: dead sessions of the Yuzu shape are stopped by exact name; live, look-alike and foreign ones are not
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($r.Listed) 'arm 1 did not list'
    Test-Expect ($r.Total -eq 9) "arm 1 total sessions: expected 9, got $($r.Total)"
    Test-Expect ($r.YuzuCount -eq 4) "arm 1 Yuzu sessions: expected 4, got $($r.YuzuCount)"
    Test-Expect (($r.Stopped -join ',') -eq 'YuzuEchoRegistryEtw-111,YuzuTarFileEtw-333') "arm 1 stopped: $($r.Stopped -join ',')"
    Test-Expect (($script:stopCalls -join ',') -eq 'YuzuEchoRegistryEtw-111,YuzuTarFileEtw-333') "arm 1 stop calls: $($script:stopCalls -join ',')"
    Test-Expect ($r.Skipped -contains 'YuzuEchoRegistryEtw-222') 'arm 1 stopped a session whose pid is alive'
    Test-Expect ($r.Skipped -contains 'YuzuEchoRegistryEtw-99999999999999') 'arm 1 stopped a session whose pid is not parseable'
    Test-Expect ($script:stopCalls -notcontains 'NotYuzuEchoRegistryEtw-444') 'arm 1 matched a look-alike name'
    Test-Expect ($script:stopCalls -notcontains 'yuzuEchoRegistryEtw-555') 'arm 1 matched a differently-cased name'

    # arm 2: a stop that fails is reported, never thrown, and the next session is still tried
    $script:stopCalls = @()
    $stopFirstFails = { param([string]$Name) $script:stopCalls += $Name; $Name -ne 'YuzuEchoRegistryEtw-111' }
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopFirstFails -WarnAt 48 -Phase 'selftest'
    Test-Expect (($r.Failed -join ',') -eq 'YuzuEchoRegistryEtw-111') "arm 2 failed: $($r.Failed -join ',')"
    Test-Expect (($r.Stopped -join ',') -eq 'YuzuTarFileEtw-333') "arm 2 stopped: $($r.Stopped -join ',')"

    # arm 3: a pid that comes alive between the first check and the stop is left alone
    $script:stopCalls = @()
    $script:checks = 0
    $flips = { param([int]$ProcessId) $script:checks++; ($ProcessId -eq 111 -and $script:checks -ge 2) -or $ProcessId -eq 222 }
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $flips -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($script:stopCalls -notcontains 'YuzuEchoRegistryEtw-111') 'arm 3 stopped a session whose pid came alive'

    # arm 4: a listing failure stops nothing and does not throw
    $script:stopCalls = @()
    $r = Invoke-EtwSessionCleanup -Query { throw 'logman not found' } -IsAlive $isAlive -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect (-not $r.Listed -and $script:stopCalls.Count -eq 0) 'arm 4 acted on a failed listing'

    # arm 5: output that parses to zero rows stops nothing
    # (the input holds a Yuzu name in a shape the parser must not accept: one space before 'Trace')
    $r = Invoke-EtwSessionCleanup -Query { @('Error: Access is denied.', 'YuzuEchoRegistryEtw-111 Trace Running') } -IsAlive $isAlive -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($r.Total -eq 0 -and $script:stopCalls.Count -eq 0) 'arm 5 acted on unparseable output'

    # arm 6: a Stop that throws is a failure for THAT session only; the next session is still tried
    $script:stopCalls = @()
    $stopThrowsFirst = { param([string]$Name) $script:stopCalls += $Name; if ($Name -eq 'YuzuEchoRegistryEtw-111') { throw 'access denied' }; $true }
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopThrowsFirst -WarnAt 48 -Phase 'selftest'
    Test-Expect (($r.Failed -join ',') -eq 'YuzuEchoRegistryEtw-111' -and ($r.Stopped -join ',') -eq 'YuzuTarFileEtw-333') "arm 6 throwing stop: failed=$($r.Failed -join ',') stopped=$($r.Stopped -join ',')"

    # arm 7: a liveness probe that throws counts as alive, so nothing is stopped
    $script:stopCalls = @()
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive { param([int]$ProcessId) throw 'probe failed' } -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($script:stopCalls.Count -eq 0 -and $r.Skipped.Count -eq 4) "arm 7 stopped a session whose liveness could not be decided: $($script:stopCalls -join ',')"

    # arm 8: the session-count warning fires at -WarnAt and not below it
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopOk -WarnAt 9 -Phase 'selftest'
    Test-Expect ($r.Warned) 'arm 8 did not warn at exactly -WarnAt'
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopOk -WarnAt 10 -Phase 'selftest'
    Test-Expect (-not $r.Warned) 'arm 8 warned below -WarnAt'

    Write-Host 'ETW session cleanup self-test: all arms hold'
    exit 0
}

# Real mode: never throw out of here. The test phase must not be made red by housekeeping.
try {
    $query = {
        $out = & logman query -ets 2>&1
        if ($LASTEXITCODE -ne 0) { throw "logman query -ets exited $LASTEXITCODE" }
        $out | ForEach-Object { "$_" }
    }
    # Only Get-Process's own "no process with this id" error means dead; any other failure means alive (leave it).
    $isAliveReal = {
        param([int]$ProcessId)
        try { $null = Get-Process -Id $ProcessId -ErrorAction Stop; $true }
        catch [Microsoft.PowerShell.Commands.ProcessCommandException] { $false }
        catch { $true }
    }
    $stopReal = {
        param([string]$Name)
        & logman stop $Name -ets *> $null
        $LASTEXITCODE -eq 0
    }
    $null = Invoke-EtwSessionCleanup -Query $query -IsAlive $isAliveReal -Stop $stopReal -WarnAt $WarnAt -Phase $Phase
} catch {
    Write-Host "${script:WarnPrefix}ETW session cleanup ($Phase) failed unexpectedly, test phase continues: $($_.Exception.Message)"
}
exit 0
