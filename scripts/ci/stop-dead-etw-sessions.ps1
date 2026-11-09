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
    3. Never fails the job: a listing or stop error is a ::warning and the script exits 0. Every `logman` call runs
       in a child process with a 45 s timeout (killed on expiry) inside a 180 s budget for the whole run, so a wedged
       ETW service costs the step at most about 3 minutes and then warns; the workflow's 5-minute step cap is only a
       backstop. A listing with fewer than 3 session rows (a healthy box always has the kernel loggers) is treated as
       not understood and stops nothing. A stop that fails is re-checked against a fresh listing: a session that has
       gone (a concurrent job stopped it first) is logged as gone, not as a failure. The totals are also appended to
       the file named by $env:GITHUB_STEP_SUMMARY when it is set. logman is run from the Windows system directory
       only; if it is not there nothing is stopped. Only -SelfTest can exit non-zero.

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
  One of run (default), pre-test or post-test: names the call site in the log lines and the step summary.
#>
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [ValidateRange(1, 64)]
    [int]$WarnAt = 48,
    [ValidateSet('run', 'pre-test', 'post-test')]
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
        if ($name -cmatch '^Yuzu[A-Za-z]*Etw-(?<pid>[0-9]+)\z') {
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

# Total wall-clock budget for every logman call of one run, and the cap on a single call. A call that outlives its
# slice is killed; the caller treats that as a failure and warns.
$script:Clock = [System.Diagnostics.Stopwatch]::StartNew()
$script:BudgetSec = 180
$script:CallSec = 45

# Run an executable with a timeout, no shell: returns @{ TimedOut; Code; Lines }. `Arguments` is one string; the only
# values ever placed in it are the fixed words `query`/`stop`/`-ets` and a session name that already passed the
# anchored ASCII grammar, so there is nothing to quote.
function Invoke-NativeBounded {
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSec)
    $remaining = $script:BudgetSec - [int]$script:Clock.Elapsed.TotalSeconds
    if ($remaining -le 0) { return [pscustomobject]@{ TimedOut = $true; Code = -1; Lines = @() } }
    $limit = [Math]::Min($TimeoutSec, $remaining)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($limit * 1000)) {
            try { $p.Kill() } catch { }
            return [pscustomobject]@{ TimedOut = $true; Code = -1; Lines = @() }
        }
        $p.WaitForExit()   # the process is fully reaped; the bounded Wait below is what waits for the readers
        # the child has exited; a reader only stays pending if something else still holds the pipe, so bound the wait
        if (-not ($out.Wait(5000) -and $err.Wait(5000))) {
            return [pscustomobject]@{ TimedOut = $true; Code = -1; Lines = @() }
        }
        $text = $out.Result
        [pscustomobject]@{ TimedOut = $false; Code = $p.ExitCode; Lines = @($text -split "\r?\n") }
    } finally { $p.Dispose() }
}

# The system directory's logman.exe, or $null. There is deliberately NO fallback to a bare `logman.exe`: with
# UseShellExecute=false CreateProcess would then search the current directory, which in CI is the checkout.
function Get-LogmanPath {
    if (-not $env:SystemRoot) { return $null }
    $candidate = Join-Path $env:SystemRoot 'System32\logman.exe'
    if (Test-Path -LiteralPath $candidate) { $candidate } else { $null }
}

# A liveness probe that throws counts as ALIVE: the one wrong answer that can hurt is a false "dead", so every doubt
# resolves to leaving the session alone.
function Test-AliveSafe {
    param([scriptblock]$Probe, [int]$ProcessId)
    try {
        $r = @(& $Probe $ProcessId)
        if ($r.Count -ne 1) { $true } else { [bool]$r[0] }   # a probe that answers nothing, or twice, is not an answer
    } catch { $true }
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
        [string]$Phase,
        [int]$MinRows = 3
    )
    $result = [pscustomobject]@{ Listed = $false; Total = 0; YuzuCount = 0; Warned = $false; Stopped = @(); Skipped = @(); Failed = @(); Gone = @() }
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
    if ($list.Total -lt $MinRows) {
        # a healthy box always lists its kernel loggers; fewer rows than that means the output was not understood
        Write-Host "${script:WarnPrefix}ETW session cleanup ($Phase): only $($list.Total) session row(s) parsed from the logman output (expected at least $MinRows), listing not understood, nothing stopped"
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
        if ($script:Clock.Elapsed.TotalSeconds -ge $script:BudgetSec) {
            $result.Failed += $s.Name
            Write-Host "${script:WarnPrefix}ETW session cleanup ($Phase): the $script:BudgetSec s run budget is spent, not attempting to stop $($s.Name)"
            continue
        }
        $stopped = $false
        try { $stopped = [bool](& $Stop $s.Name) } catch { $stopped = $false }
        if ($stopped) {
            $result.Stopped += $s.Name
            Write-Host "${script:WarnPrefix}stopped leaked ETW session $($s.Name): pid $($s.ProcessId) is not running ($Phase)"
        } else {
            # a concurrent job may have stopped it first: look again before calling it a failure
            $gone = $false
            try {
                $again = Read-EtwSessionList -Lines @(& $Query)
                $gone = ($again.Total -ge $MinRows) -and (@($again.Yuzu | Where-Object { $_.Name -eq $s.Name }).Count -eq 0)
            } catch { $gone = $false }
            if ($gone) {
                $result.Gone += $s.Name
                Write-Host "  $($s.Name) is already gone (stopped by a concurrent job)"
            } else {
                $result.Failed += $s.Name
                Write-Host "${script:WarnPrefix}could not stop leaked ETW session $($s.Name) (pid $($s.ProcessId) is not running); leaving it ($Phase)"
            }
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
        'YuzuEchoProcEtw-333                      Trace                         Running',
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
    Test-Expect (($r.Stopped -join ',') -eq 'YuzuEchoRegistryEtw-111,YuzuEchoProcEtw-333') "arm 1 stopped: $($r.Stopped -join ',')"
    Test-Expect (($script:stopCalls -join ',') -eq 'YuzuEchoRegistryEtw-111,YuzuEchoProcEtw-333') "arm 1 stop calls: $($script:stopCalls -join ',')"
    Test-Expect ($r.Skipped -contains 'YuzuEchoRegistryEtw-222') 'arm 1 stopped a session whose pid is alive'
    Test-Expect ($r.Skipped -contains 'YuzuEchoRegistryEtw-99999999999999') 'arm 1 stopped a session whose pid is not parseable'
    Test-Expect ($script:stopCalls -notcontains 'NotYuzuEchoRegistryEtw-444') 'arm 1 matched a look-alike name'
    Test-Expect ($script:stopCalls -notcontains 'yuzuEchoRegistryEtw-555') 'arm 1 matched a differently-cased name'

    # arm 2: a stop that fails is reported, never thrown, and the next session is still tried
    $script:stopCalls = @()
    $stopFirstFails = { param([string]$Name) $script:stopCalls += $Name; $Name -ne 'YuzuEchoRegistryEtw-111' }
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopFirstFails -WarnAt 48 -Phase 'selftest'
    Test-Expect (($r.Failed -join ',') -eq 'YuzuEchoRegistryEtw-111') "arm 2 failed: $($r.Failed -join ',')"
    Test-Expect (($r.Stopped -join ',') -eq 'YuzuEchoProcEtw-333') "arm 2 stopped: $($r.Stopped -join ',')"

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
    Test-Expect (($r.Failed -join ',') -eq 'YuzuEchoRegistryEtw-111' -and ($r.Stopped -join ',') -eq 'YuzuEchoProcEtw-333') "arm 6 throwing stop: failed=$($r.Failed -join ',') stopped=$($r.Stopped -join ',')"

    # arm 7: a liveness probe that throws counts as alive, so nothing is stopped
    $script:stopCalls = @()
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive { param([int]$ProcessId) throw 'probe failed' } -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($script:stopCalls.Count -eq 0 -and $r.Skipped.Count -eq 4) "arm 7 stopped a session whose liveness could not be decided: $($script:stopCalls -join ',')"

    # arm 8: the session-count warning fires at -WarnAt and not below it
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopOk -WarnAt 9 -Phase 'selftest'
    Test-Expect ($r.Warned) 'arm 8 did not warn at exactly -WarnAt'
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopOk -WarnAt 10 -Phase 'selftest'
    Test-Expect (-not $r.Warned) 'arm 8 warned below -WarnAt'

    # arm 9: a stop that fails because a concurrent job already stopped the session is "gone", not a failure
    $script:stopCalls = @()
    $script:qcalls = 0
    $queryGoneAfterFirst = { $script:qcalls++; if ($script:qcalls -eq 1) { $header } else { @($header | Where-Object { $_ -notlike 'YuzuEchoRegistryEtw-111 *' }) } }
    $stopAlwaysFails = { param([string]$Name) $script:stopCalls += $Name; $false }
    $r = Invoke-EtwSessionCleanup -Query $queryGoneAfterFirst -IsAlive $isAlive -Stop $stopAlwaysFails -WarnAt 48 -Phase 'selftest'
    Test-Expect (($r.Gone -join ',') -eq 'YuzuEchoRegistryEtw-111') "arm 9 gone: $($r.Gone -join ',')"
    Test-Expect (($r.Failed -join ',') -eq 'YuzuEchoProcEtw-333') "arm 9 failed: $($r.Failed -join ',')"

    # arm 10: a listing with fewer rows than a healthy box has is not understood: nothing is stopped
    $script:stopCalls = @()
    $r = Invoke-EtwSessionCleanup -Query { @('YuzuEchoRegistryEtw-111                 Trace                         Running', 'Circular Kernel Context Logger          Trace                         Running') } -IsAlive $isAlive -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($r.Total -eq 2 -and $script:stopCalls.Count -eq 0) 'arm 10 acted on a listing with too few rows'

    # arm 11: a probe that answers nothing is not an answer: alive
    $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive { param([int]$ProcessId) } -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($r.Stopped.Count -eq 0) 'arm 11 stopped a session on an empty liveness answer'

    # arm 12: the bounded native runner kills a call that outlives its slice and reports an exit code and output
    # otherwise (this host process itself is the child; no session is touched)
    $hostExe = (Get-Process -Id $PID).Path
    $t0 = [int]$script:Clock.Elapsed.TotalSeconds
    $slow = Invoke-NativeBounded -FilePath $hostExe -Arguments '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60' -TimeoutSec 3
    Test-Expect ($slow.TimedOut) 'arm 12 did not time out a sleeping child'
    Test-Expect (([int]$script:Clock.Elapsed.TotalSeconds - $t0) -lt 90) 'arm 12 waited for the sleeping child'
    $fast = Invoke-NativeBounded -FilePath $hostExe -Arguments '-NoProfile -NonInteractive -Command "Write-Output hello; exit 3"' -TimeoutSec 120
    Test-Expect ((-not $fast.TimedOut) -and $fast.Code -eq 3 -and ($fast.Lines -contains 'hello')) "arm 12 fast child: timedout=$($fast.TimedOut) code=$($fast.Code) lines=$($fast.Lines -join '|')"

    # arm 13: once the run budget is spent no stop is attempted and each session is reported as failed
    $script:stopCalls = @()
    $savedBudget = $script:BudgetSec
    $script:BudgetSec = 0
    try {
        $r = Invoke-EtwSessionCleanup -Query { $header } -IsAlive $isAlive -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    } finally { $script:BudgetSec = $savedBudget }
    Test-Expect ($script:stopCalls.Count -eq 0 -and (($r.Failed -join ',') -eq 'YuzuEchoRegistryEtw-111,YuzuEchoProcEtw-333')) "arm 13 budget: stops=$($script:stopCalls -join ',') failed=$($r.Failed -join ',')"
    # ... and the native runner itself refuses to start a process once the budget is spent
    $script:BudgetSec = 0
    try { $spent = Invoke-NativeBounded -FilePath $hostExe -Arguments '-NoProfile -NonInteractive -Command exit 0' -TimeoutSec 60 } finally { $script:BudgetSec = $savedBudget }
    Test-Expect ($spent.TimedOut) 'arm 13 started a process with the budget spent'

    # arm 14: a re-list that returns too few rows to trust is NOT evidence that the session is gone
    $script:stopCalls = @()
    $script:qcalls = 0
    $queryGarbageSecond = { $script:qcalls++; if ($script:qcalls -eq 1) { $header } else { @('garbage') } }
    $r = Invoke-EtwSessionCleanup -Query $queryGarbageSecond -IsAlive $isAlive -Stop $stopAlwaysFails -WarnAt 48 -Phase 'selftest'
    Test-Expect ($r.Gone.Count -eq 0 -and ($r.Failed -join ',') -eq 'YuzuEchoRegistryEtw-111,YuzuEchoProcEtw-333') "arm 14 gone=$($r.Gone -join ',') failed=$($r.Failed -join ',')"

    # arm 15: the row-count canary boundary: exactly 3 rows is understood, so a dead session in it IS stopped
    $script:stopCalls = @()
    $threeRows = @('Circular Kernel Context Logger          Trace                         Running',
                   'Microsoft Defender ETW Session          Trace                         Running',
                   'YuzuEchoRegistryEtw-111                 Trace                         Running')
    $r = Invoke-EtwSessionCleanup -Query { $threeRows } -IsAlive $isAlive -Stop $stopOk -WarnAt 48 -Phase 'selftest'
    Test-Expect ($r.Total -eq 3 -and ($r.Stopped -join ',') -eq 'YuzuEchoRegistryEtw-111') "arm 15 boundary: total=$($r.Total) stopped=$($r.Stopped -join ',')"

    Write-Host 'ETW session cleanup self-test: all arms hold'
    exit 0
}

# Real mode: never throw out of here. The test phase must not be made red by housekeeping.
try {
    $logman = Get-LogmanPath
    if (-not $logman) { throw 'logman.exe was not found in the Windows system directory, nothing stopped' }
    $query = {
        $r = Invoke-NativeBounded -FilePath $logman -Arguments 'query -ets' -TimeoutSec $script:CallSec
        if ($r.TimedOut) { throw 'logman query -ets timed out or the run budget was exhausted' }
        if ($r.Code -ne 0) { throw "logman query -ets exited $($r.Code)" }
        $r.Lines
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
        # the name is spliced into a command line: refuse anything outside the grammar, whatever the caller did
        if ($Name -cnotmatch '^Yuzu[A-Za-z]*Etw-[0-9]+\z') { return $false }
        $r = Invoke-NativeBounded -FilePath $logman -Arguments "stop $Name -ets" -TimeoutSec $script:CallSec
        (-not $r.TimedOut) -and $r.Code -eq 0
    }
    $r = Invoke-EtwSessionCleanup -Query $query -IsAlive $isAliveReal -Stop $stopReal -WarnAt $WarnAt -Phase $Phase
    if ($env:GITHUB_STEP_SUMMARY) {
        try {
            $line = if ($r.Listed) { "- ETW sessions ($Phase): $($r.Total) total, $($r.YuzuCount) Yuzu, stopped $($r.Stopped.Count), kept $($r.Skipped.Count), gone $($r.Gone.Count), failed $($r.Failed.Count)" } else { "- ETW sessions ($Phase): listing failed, nothing stopped" }
            Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $line
        } catch { }
    }
} catch {
    Write-Host "${script:WarnPrefix}ETW session cleanup ($Phase) failed unexpectedly, test phase continues: $($_.Exception.Message)"
}
exit 0
