<#
win-quarantine-precedence-probe.ps1 - #3284 ground truth: once
win_quarantine's BlockAllInbound/BlockAllOutbound rules are live, does an
AllowIn_<ip>/AllowOut_<ip> whitelist rule still let that address through?
Runs entirely ON the target host over an elevated SSH session.

============================================================================
 DO NOT RUN AGAINST A HOST YOU CANNOT PHYSICALLY REACH IF IT GOES WRONG.
============================================================================
-Execute applies win_quarantine's real rule set. If Allow does NOT win
precedence on this build, the host's network drops to loopback only -
including the SSH session driving this script. Two independent scheduled-
task watchdogs exist to undo that.

THE ONE HARD RULE: a Block rule is never applied until BOTH watchdogs have
been registered AND OBSERVED to actually remove a real rule when triggered.
`Get-ScheduledTask` reporting `Ready` proves only that Task Scheduler
accepted the registration, not that the action works. So before anything
that blocks traffic runs: register both -> create one harmless
YuzuQuarantine_Probe ALLOW rule -> Start-ScheduledTask the primary NOW ->
wait for it to report done -> assert the probe rule is GONE (the only proof
that counts) -> repeat for the backstop -> only then re-arm both and
proceed. Either proving run failing to remove the rule aborts the whole run
right there - see Test-WatchdogProving / Invoke-Abort below.

-DryRun (default, never destructive): capture profile policy -> preflight ->
register -> prove both -> unregister -> exit. Never writes a Block rule,
leaves zero residue, safe to re-run.

On profile defaults, precisely: the proving runs FIRE the watchdog's real
recovery body, which does write the profile policy - it restores the values
captured at entry, so on an unchanged host every write is a no-op and the
policy the operator invoked the probe on is what survives. An earlier version
wrote a hardcoded Block/Allow there, which silently and permanently rewrote
the policy of any host whose profiles differed, and did so BEFORE -Execute
captured its "pre-state" - making the restored-verbatim claim unachievable on
exactly the hardened hosts that most needed it. The capture therefore happens
before the watchdogs are armed, and is the single source of truth for the
recovery body, the normal teardown and the emergency path alike.

Proving fires the SHIPPED recovery body rather than a rule-only stand-in on
purpose: a failsafe proven by proxy is not proven.

-Execute (the real probe): requires a clean -DryRun first. Re-launches
itself DETACHED (Start-Process -WindowStyle Hidden) before anything
destructive, so losing the driving SSH session the instant
BlockAllOutbound goes live cannot interrupt the measure-then-teardown
sequence. Reconnect afterwards and read the transcript path this prints.

Idempotency: refuses to start at all if the session isn't elevated, or if
any `YuzuQuarantine_*` rule or `YuzuQuarantine_Watchdog_*` task already
exists - a second run against a dirty host ABORTS rather than layering
rules (clean up by hand, or just re-run -DryRun, which never locks anything).

Physical-path requirement (do not weaken this): the load-bearing whitelisted
measurement MUST be an address reachable over a physical NIC (gateway or
LAN peer), never the Tailscale 100.64.0.0/10 overlay - Windows Firewall
filters the WireGuard/DERP transport on the physical adapter same as
anything else, so a failed 100.x connection after BlockAllOutbound proves
only "the unwhitelisted tunnel transport got blocked," not the precedence
question. braga's address (-BragaTailscaleAddress) is whitelisted and
measured for convenience only; its result is always INFORMATIONAL and never
feeds the verdict. No physical target resolvable => no verdict (INCONCLUSIVE)
- see Resolve-PhysicalTargets.

Exit codes: 0 completed, teardown verified clean (verdict may still be
INCONCLUSIVE - a valid outcome, not a failure). 1 unhandled exception
(emergency cleanup attempted). 2 preflight refused to start; nothing was
touched. 3 a watchdog proving run failed; aborted before any Block rule,
cleanup attempted. 4 post-run verification found residue - HOST MAY NEED
MANUAL ATTENTION, said loudly on purpose.

Manual recovery if reading this because something went wrong (any admin
PowerShell on the box, e.g. a console/RDP session that doesn't depend on
the blocked network - or just wait: the watchdogs self-clear within
5 / 15 minutes of being armed, unattended):
  Get-NetFirewallRule -DisplayName 'YuzuQuarantine_*' | Remove-NetFirewallRule
  Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
  Get-ScheduledTask -TaskName 'YuzuQuarantine_Watchdog_*' | Unregister-ScheduledTask -Confirm:$false
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    # Default path - the absence of -Execute already means dry-run; this is
    # just the self-documenting spelling of that.
    [Parameter(ParameterSetName = 'DryRun')]
    [switch]$DryRun,

    # The only way to reach the destructive path. Its own mandatory
    # parameter set makes `-DryRun -Execute` together a binding error.
    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [switch]$Execute,

    # Optional override for the physical-path LAN-peer target; unset means
    # auto-discover via the gateway interface's ARP table. Never required -
    # the gateway alone satisfies the physical-path requirement.
    [Parameter()]
    [string]$LanPeerAddress,

    # braga's Tailscale address, INFORMATIONAL-only (see header). Unset
    # means braga is skipped - never guessed at or hardcoded.
    [Parameter()]
    [string]$BragaTailscaleAddress,

    # Which containment shape to measure.
    #   LegacyBlockRules   - what win_quarantine shipped: named BlockAllInbound/
    #                        BlockAllOutbound rules with Allow rules layered over
    #                        them. Answers "does a Block RULE beat an Allow RULE".
    #   ProfileDefaultBlock- the branch-A redesign: no named Block rules at all,
    #                        block via the PROFILE DEFAULT policy, with the same
    #                        Allow rules. Answers the DIFFERENT question branch A
    #                        actually rests on: "does an Allow RULE beat a
    #                        PROFILE-DEFAULT block". Documented as yes; unmeasured
    #                        until this scenario exists, and every loopback and
    #                        whitelist reachability guarantee under the redesign
    #                        depends on it, so it gets measured rather than assumed.
    [Parameter()]
    [ValidateSet('LegacyBlockRules', 'ProfileDefaultBlock')]
    [string]$Scenario = 'LegacyBlockRules',

    # INTERNAL, set only by this script's own detached self-relaunch for
    # -Execute (see MAIN below). Do not pass by hand.
    [Parameter()]
    [switch]$Detached,

    # INTERNAL - keeps the transcript filename stable across that relaunch.
    [Parameter()]
    [string]$Stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -- Constants ------------------------------------------------------------
$RulePrefix       = 'YuzuQuarantine_'
$ProbeRuleName    = "${RulePrefix}Probe"
$WatchdogPrimary  = "${RulePrefix}Watchdog_Primary"
$WatchdogBackstop = "${RulePrefix}Watchdog_Backstop"
$RunnerTask       = "${RulePrefix}Runner"
$IsDryRun         = ($PSCmdlet.ParameterSetName -eq 'DryRun')
$CandidatePorts   = 53, 443, 80, 22, 7547, 8080
# Discovery is capped and fast-timed on purpose - see Test-TcpPort.
$MaxPeerCandidates = 8
$ProbeTimeoutMs    = 1000
$ControlTarget    = '1.1.1.1'   # non-whitelisted control; must NOT be reachable post-block

# ProgramData, not $env:TEMP: the -Execute pass relaunches as SYSTEM, whose
# $env:TEMP is C:\Windows\TEMP, so a user-temp path would split the parent's
# reported transcript location from where the child actually writes it.
$WorkDir        = Join-Path $env:ProgramData 'YuzuQuarantineProbe'
$RecoveryScript = Join-Path $WorkDir 'watchdog-recovery.ps1'
$TranscriptPath = Join-Path $WorkDir "transcript-$Stamp.txt"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

# -- Small helpers --------------------------------------------------------

function Write-Log {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg"
}
function Write-Verdict {
    param([string]$Step, [bool]$Ok, [string]$Detail = '')
    $tag = if ($Ok) { 'PASS' } else { 'FAIL' }
    Write-Log "[$tag] $Step $(if ($Detail) { "- $Detail" })"
}

# netsh, not New-NetFirewallRule: this is the exact tool win_quarantine's
# C++ (agents/plugins/quarantine/src/quarantine_plugin.cpp) shells out to.
# Using anything else risks measuring a different code path than production.
function Get-YuzuQuarantineRuleNames {
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($dir in 'in', 'out') {
        $out = & netsh.exe advfirewall firewall show rule name=all dir=$dir 2>$null
        foreach ($line in $out) {
            if ($line -match '^Rule Name:\s*(.+?)\s*$') {
                $val = $Matches[1]
                if ($val.StartsWith($RulePrefix) -and -not $names.Contains($val)) {
                    $names.Add($val)
                }
            }
        }
    }
    return $names
}

# Recovers: re-run finds nothing to delete - safe to call any number of
# times, including when nothing exists.
function Remove-YuzuQuarantineRules {
    $names = Get-YuzuQuarantineRuleNames
    foreach ($n in $names) {
        & netsh.exe advfirewall firewall delete rule name=$n 2>$null | Out-Null
    }
    return $names
}

# Recovers: none needed - read-only.
function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Recovers: unregistering a task that isn't there is a silent no-op.
function Remove-WatchdogTasks {
    foreach ($t in $WatchdogPrimary, $WatchdogBackstop, $RunnerTask) {
        Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# The watchdog's own action body - written to disk, executed by Task
# Scheduler as SYSTEM if this script dies before its own teardown runs.
# Deliberately minimal: two native cmdlets, no netsh shellout, no
# dependency on anything this script defined in-process (the watchdog runs
# in its own powershell.exe, it cannot see these functions) - the fewer
# moving parts a last-resort failsafe has, the more likely it is to still
# work when everything else already didn't.
function Write-RecoveryScript {
    param([Parameter(Mandatory)]$CapturedProfiles)

    # Restore the EXACT captured per-profile policy, never a hardcoded default.
    # Writing Block/Allow here meant the watchdog - which the dry run
    # deliberately FIRES twice to prove it works - permanently rewrote the
    # policy of any host whose profiles differed, and did it BEFORE -Execute
    # captured its "pre-state", so the restored-verbatim claim could never have
    # been true on such a host. The dry run advertises itself as never touching
    # profile defaults; now that is actually so.
    $lines = @("`$ErrorActionPreference = 'SilentlyContinue'",
               "Get-NetFirewallRule -DisplayName 'YuzuQuarantine_*' | Remove-NetFirewallRule")
    foreach ($row in $CapturedProfiles) {
        $lines += ("Set-NetFirewallProfile -Name {0} -DefaultInboundAction {1} -DefaultOutboundAction {2}" -f `
                   $row.Name, $row.DefaultInboundAction, $row.DefaultOutboundAction)
    }
    $lines | Set-Content -Path $RecoveryScript -Encoding ASCII
}

# Recovers: called from every abort path AND the natural end. Idempotent -
# every step here is itself safe to run against a host with nothing to
# clean up.
function Invoke-EmergencyCleanup {
    param([string]$Reason)
    Write-Log "EMERGENCY CLEANUP: $Reason"

    # ORDER IS LOAD-BEARING. This used to delete the Yuzu Allow rules and
    # unregister BOTH watchdogs without restoring the profile policy - so an
    # exception thrown any time after the Block/Block write left the host on a
    # block-both default, with its loopback/whitelist exceptions deleted and
    # every armed recovery removed. That is strictly MORE isolating than doing
    # nothing, and it disarmed the exact mechanism that exists to undo it.
    #
    # So: restore the captured policy FIRST and verify it. Only once the host
    # is demonstrably off the quarantine policy do the watchdogs come down. If
    # the restore fails or cannot be verified, the watchdogs STAY ARMED and the
    # recovery script stays on disk - a noisy, self-healing exit beats a quiet,
    # stranded one.
    $policyRestored = $true
    if ($script:PreProfileCaptured) {
        foreach ($row in $script:PreProfileCaptured) {
            try {
                Set-NetFirewallProfile -Name $row.Name `
                    -DefaultInboundAction $row.DefaultInboundAction `
                    -DefaultOutboundAction $row.DefaultOutboundAction -ErrorAction Stop
            } catch {
                $policyRestored = $false
                Write-Log "  FAILED to restore $($row.Name) profile policy: $($_.Exception.Message)"
            }
        }
        if ($policyRestored) { Write-Log '  profile policy restored to its captured values' }
    }

    $leftoverRules = @(Remove-YuzuQuarantineRules)
    if ($leftoverRules.Count -gt 0) {
        Write-Log "  removed rules: $($leftoverRules -join ', ')"
    }

    if (-not $policyRestored) {
        Write-Log '  LEAVING BOTH WATCHDOGS ARMED: the profile policy could not be restored, so'
        Write-Log '  the host may still be contained. They will clear it within 5 / 15 minutes.'
        Write-Log '  DO NOT unregister them by hand until Get-NetFirewallProfile looks correct.'
        return
    }

    Remove-WatchdogTasks
    Remove-Item -Path $RecoveryScript -ErrorAction SilentlyContinue
}

function Invoke-Abort {
    param([string]$Reason, [int]$Code)
    Write-Verdict 'ABORT' $false $Reason
    Invoke-EmergencyCleanup -Reason $Reason
    Write-Log "Transcript: $TranscriptPath"
    try { Stop-Transcript | Out-Null } catch {}
    exit $Code
}

# Registers primary (+5m) and backstop (+15m). Recovers: re-registering
# under the same name with -Force overwrites cleanly; preflight already
# refused to start if these names existed unexpectedly.
function Register-Watchdogs {
    # The capture must already have happened - the recovery body restores it.
    if (-not $script:PreProfileCaptured) {
        throw 'internal: Register-Watchdogs called before the profile policy was captured'
    }
    Write-RecoveryScript -CapturedProfiles $script:PreProfileCaptured
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$RecoveryScript`""

    $trigP = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    Register-ScheduledTask -TaskName $WatchdogPrimary -Action $action -Trigger $trigP `
        -Principal $principal -Settings $settings -Force | Out-Null

    $trigB = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15)
    Register-ScheduledTask -TaskName $WatchdogBackstop -Action $action -Trigger $trigB `
        -Principal $principal -Settings $settings -Force | Out-Null

    Write-Log "registered $WatchdogPrimary (+5m) and $WatchdogBackstop (+15m)"
}

function Set-FreshTrigger {
    param([string]$TaskName, [int]$Minutes)
    $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Minutes)
    Set-ScheduledTask -TaskName $TaskName -Trigger $trig | Out-Null
}

# THE proving run. Ready/registered is not proof; the probe rule's actual
# removal is. Returns $true only if the task fired and the rule it should
# have deleted is observably gone.
function Test-WatchdogProving {
    param([string]$TaskName)

    Remove-YuzuQuarantineRules | Out-Null   # start from a clean slate for this cycle
    & netsh.exe advfirewall firewall add rule name="$ProbeRuleName" dir=in action=allow enable=yes remoteip=127.0.0.1 | Out-Null
    if (-not (Get-NetFirewallRule -DisplayName $ProbeRuleName -ErrorAction SilentlyContinue)) {
        Write-Log "  could not even create the probe rule ahead of proving $TaskName"
        return $false
    }

    # Task Scheduler reports LastRunTime truncated to whole seconds while
    # Get-Date carries sub-second precision, so a task that fires inside the
    # SAME second as $before reports a LastRunTime strictly LESS than it and a
    # `-lt $before` wait can never satisfy - the proving run then fails on a
    # working watchdog, purely on sub-second luck. Watch for the value to
    # CHANGE from its pre-start reading instead: immune to that granularity,
    # and it still cannot be satisfied by a stale historical run.
    $baselineRun = (Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo).LastRunTime
    $before = Get-Date
    Start-ScheduledTask -TaskName $TaskName

    $deadline = $before.AddSeconds(30)
    $info = $null
    do {
        Start-Sleep -Seconds 1
        $info = Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
    } while ($info.LastRunTime -eq $baselineRun -and (Get-Date) -lt $deadline)

    if ($info.LastRunTime -eq $baselineRun) {
        Write-Log "  $TaskName did not report a run within 30s"
        return $false
    }

    # The real assertion - the one the acceptance criteria names literally.
    # LastTaskResult is only a "has it finished" signal above; it is NOT
    # trusted as proof the action worked, only the rule's absence is.
    Start-Sleep -Seconds 1   # let the delete's own netsh call finish flushing
    $stillThere = Get-NetFirewallRule -DisplayName $ProbeRuleName -ErrorAction SilentlyContinue
    if ($stillThere) {
        Write-Log "  $TaskName ran (LastTaskResult=$($info.LastTaskResult)) but $ProbeRuleName is still present"
        return $false
    }
    return $true
}

# -- Physical-path target resolution (EXECUTE path only) -----------------
# Never returns a Tailscale/overlay address as the primary target. Returns
# $null (not a guess) when nothing physical is reachable.
function Resolve-PhysicalTargets {
    $result = [ordered]@{
        GatewayIp = $null; GatewayIfIndex = $null; GatewayPort = $null
        LanPeerIp = $null; LanPeerIfIndex = $null; LanPeerPort = $null
    }

    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object -Property RouteMetric | Select-Object -First 1
    if (-not $route) {
        Write-Log '  no default route with a resolvable gateway found'
        return $result
    }
    $result.GatewayIp = $route.NextHop
    $result.GatewayIfIndex = $route.ifIndex
    Write-Log "  default gateway $($route.NextHop) via ifIndex $($route.ifIndex)"

    foreach ($p in $CandidatePorts) {
        if (Test-TcpPort -IpAddress $route.NextHop -Port $p) {
            $result.GatewayPort = $p
            Write-Log "  gateway has an open port at :$p"
            break
        }
    }

    $peerCandidates = @()
    if ($LanPeerAddress) {
        $peerCandidates = @($LanPeerAddress)
    } elseif (-not $result.GatewayPort) {
        # Only scan for a LAN peer when the gateway did NOT yield a usable
        # target: Get-PhysicalWhitelistTarget prefers the gateway anyway, so
        # scanning with one in hand is pure cost against a live watchdog clock.
        # Capped at $MaxPeerCandidates for the same reason.
        $peerCandidates = Get-NetNeighbor -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue |
            Where-Object {
                $_.State -in @('Reachable', 'Stale', 'Permanent') -and
                $_.IPAddress -ne $route.NextHop -and
                $_.IPAddress -notmatch '^(224\.|239\.|255\.|ff0|fe80)' -and
                $_.IPAddress -notmatch '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.'   # exclude the 100.64.0.0/10 overlay
            } | Select-Object -ExpandProperty IPAddress -First $MaxPeerCandidates
    }
    foreach ($peer in $peerCandidates) {
        foreach ($p in $CandidatePorts) {
            if (Test-TcpPort -IpAddress $peer -Port $p) {
                $result.LanPeerIp = $peer
                $result.LanPeerIfIndex = $route.ifIndex
                $result.LanPeerPort = $p
                Write-Log "  LAN peer $peer has an open port at :$p"
                break
            }
        }
        if ($result.LanPeerIp) { break }
    }
    if (-not $result.LanPeerIp) {
        Write-Log '  no reachable LAN peer found (gateway-only is still a valid physical-path target)'
    }
    return $result
}

# Bounded TCP reachability probe for DISCOVERY ONLY. Test-NetConnection
# waits ~20s on an unreachable port, which is unusable for scanning a LAN:
# 52 neighbours x 6 candidate ports is over an hour, and the watchdogs armed
# before that phase expire silently while it runs - leaving the destructive
# step unprotected. This returns within $TimeoutMs. The baseline and the
# measured verdict deliberately keep Test-NetConnection -Detailed.
function Test-TcpPort {
    param([string]$IpAddress, [int]$Port, [int]$TimeoutMs = $ProbeTimeoutMs)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($IpAddress, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Get-PhysicalWhitelistTarget {
    param($Targets)
    if ($Targets.GatewayPort) {
        return @{ Ip = $Targets.GatewayIp; Port = $Targets.GatewayPort; IfIndex = $Targets.GatewayIfIndex; Label = 'gateway' }
    }
    if ($Targets.LanPeerPort) {
        return @{ Ip = $Targets.LanPeerIp; Port = $Targets.LanPeerPort; IfIndex = $Targets.LanPeerIfIndex; Label = 'lan-peer' }
    }
    return $null
}

# =======================================================================
#  MAIN
# =======================================================================

# -Execute must run detached so losing this SSH session the instant
# BlockAllOutbound goes live cannot interrupt the measure-then-teardown
# sequence. Recovers: the relaunched child is entirely self-contained; if
# even the relaunch fails, nothing destructive has happened yet.
if ($Execute -and -not $Detached) {
    if (-not (Test-Elevated)) {
        Write-Log 'ABORT: session is not elevated - refusing to relaunch. Nothing was touched.'
        exit 2
    }
    Write-Log "Relaunching detached for the -Execute pass (stamp $Stamp)..."
    $self = $MyInvocation.MyCommand.Path
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
        '-File', "`"$self`"", '-Execute', '-Detached', '-Stamp', $Stamp
    )
    $argList += @('-Scenario', $Scenario)
    if ($LanPeerAddress) { $argList += @('-LanPeerAddress', $LanPeerAddress) }
    if ($BragaTailscaleAddress) { $argList += @('-BragaTailscaleAddress', $BragaTailscaleAddress) }
    # Start-Process would place the child in THIS logon session, and Windows
    # OpenSSH tears the entire session process tree down when the connection
    # closes - so an SSH-driven -Execute killed its own "detached" child the
    # instant the driving session ended, mid-probe and before teardown (observed
    # on Windows 11 26200: the run stopped dead at target resolution). A one-shot
    # SYSTEM scheduled task is genuinely session-independent, and it is the same
    # mechanism the watchdogs already prove live on this host on every run.
    $runnerPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $runnerSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $runnerAction    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($argList -join ' ')
    Register-ScheduledTask -TaskName $RunnerTask -Action $runnerAction -Principal $runnerPrincipal -Settings $runnerSettings -Force | Out-Null
    Start-ScheduledTask -TaskName $RunnerTask
    Write-Log "Detached via scheduled task $RunnerTask. Reconnect and read: $TranscriptPath"
    Write-Log 'If the SSH session drops now, that is expected - the probe continues without it.'
    exit 0
}

Start-Transcript -Path $TranscriptPath -Force | Out-Null
try {
    Write-Log "win-quarantine-precedence-probe starting. Mode: $(if ($IsDryRun) { 'DRY-RUN' } else { 'EXECUTE' })  Scenario: $Scenario"

    # -- Preflight -----------------------------------------------------
    if (-not (Test-Elevated)) {
        Invoke-Abort -Reason 'session is not elevated' -Code 2
    }
    $existingRules = @(Get-YuzuQuarantineRuleNames)
    if ($existingRules.Count -gt 0) {
        Invoke-Abort -Reason "pre-existing rules found: $($existingRules -join ', ') - clean up before re-running" -Code 2
    }
    $existingTasks = @(@($WatchdogPrimary, $WatchdogBackstop) | Where-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue })
    if ($existingTasks.Count -gt 0) {
        Invoke-Abort -Reason "pre-existing watchdog task(s) found: $($existingTasks -join ', ')" -Code 2
    }
    Write-Verdict 'preflight' $true 'elevated, no pre-existing YuzuQuarantine_* state'

    # -- Register + PROVE both watchdogs (gates everything below) -------
    # CAPTURE FIRST, register second. The watchdogs' recovery body replays
    # these exact values, and the proving runs FIRE that body - so capturing
    # afterwards would record a state the harness had already overwritten.
    $script:PreProfileCaptured =
        Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction
    Write-Log '--- captured pre-probe profile policy (restored by teardown AND by both watchdogs) ---'
    $script:PreProfileCaptured | Format-Table | Out-String | Write-Host

    Register-Watchdogs

    $primaryProved = Test-WatchdogProving -TaskName $WatchdogPrimary
    Write-Verdict "watchdog proving: $WatchdogPrimary" $primaryProved
    if (-not $primaryProved) {
        Invoke-Abort -Reason "$WatchdogPrimary failed its proving run" -Code 3
    }

    $backstopProved = Test-WatchdogProving -TaskName $WatchdogBackstop
    Write-Verdict "watchdog proving: $WatchdogBackstop" $backstopProved
    if (-not $backstopProved) {
        Invoke-Abort -Reason "$WatchdogBackstop failed its proving run" -Code 3
    }

    Write-Log 'Both watchdogs PROVED: registration alone is not trusted, an observed rule removal is, and both delivered one.'

    if ($IsDryRun) {
        # Dry run's entire job was proving the failsafe. Stop here - no
        # Block rule has been written and none ever will be on this path.
        Remove-WatchdogTasks
        Remove-Item -Path $RecoveryScript -ErrorAction SilentlyContinue
        $residualRules = @(Get-YuzuQuarantineRuleNames)
        $residualTasks = @(@($WatchdogPrimary, $WatchdogBackstop) | Where-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue })
        $clean = ($residualRules.Count -eq 0 -and $residualTasks.Count -eq 0)
        Write-Verdict 'post-dry-run residue check' $clean $(if (-not $clean) { "rules=$($residualRules -join ',') tasks=$($residualTasks -join ',')" })
        Write-Log "DRY RUN COMPLETE. Watchdog mechanism proven live on this host. No Block rule was written."
        Write-Log "Transcript: $TranscriptPath"
        Stop-Transcript | Out-Null
        exit $(if ($clean) { 0 } else { 4 })
    }

    # ====================== EXECUTE-ONLY FROM HERE ======================
    # Re-arm both watchdogs - their one-shot triggers were just consumed by
    # proving. This is the live window: if this script dies from here on,
    # the primary undoes everything within 5 minutes, the backstop within 15.
    Set-FreshTrigger -TaskName $WatchdogPrimary -Minutes 5
    Set-FreshTrigger -TaskName $WatchdogBackstop -Minutes 15
    Write-Log 'Watchdogs re-armed with fresh triggers (+5m / +15m from now).'

    # -- Capture pre-state (restored verbatim in teardown) ---------------
    # Reuse the capture taken before the watchdogs were armed. Re-reading here
    # would observe whatever the proving runs left behind, not the state the
    # operator invoked the probe on.
    $preProfile = $script:PreProfileCaptured
    Write-Log '--- pre-state: Get-NetFirewallProfile ---'
    $preProfile | Format-Table | Out-String | Write-Host
    Write-Log '--- pre-state: netsh advfirewall show allprofiles ---'
    & netsh.exe advfirewall show allprofiles | Out-String | Write-Host

    # -- Dropped-packet logging -------------------------------------------
    & netsh.exe advfirewall set allprofiles logging droppedconnections enable | Out-Null
    $logPaths = (Get-NetFirewallProfile | Select-Object -ExpandProperty LogFileName -Unique)
    Write-Log "drop logging enabled. Log path(s): $($logPaths -join ', ')"

    # -- Resolve physical-path targets BEFORE applying anything ----------
    Write-Log 'Resolving physical-path whitelist target (gateway / LAN peer)...'
    $targets = Resolve-PhysicalTargets
    $physical = Get-PhysicalWhitelistTarget -Targets $targets

    if (-not $physical) {
        Write-Log 'NO PHYSICAL-PATH TARGET COULD BE ESTABLISHED. No rules will be applied. Verdict is INCONCLUSIVE.'
        & netsh.exe advfirewall set allprofiles logging droppedconnections disable | Out-Null
        Remove-WatchdogTasks
        Remove-Item -Path $RecoveryScript -ErrorAction SilentlyContinue
        Write-Log 'VERDICT: INCONCLUSIVE - no physical-path whitelisted target reachable on this host.'
        Write-Log "Transcript: $TranscriptPath"
        Stop-Transcript | Out-Null
        exit 0
    }
    Write-Log "Physical-path target: $($physical.Label) $($physical.Ip):$($physical.Port) via ifIndex $($physical.IfIndex)"

    # Baseline - same target, same port, BEFORE any Block rule exists.
    $baseline = Test-NetConnection -ComputerName $physical.Ip -Port $physical.Port -InformationLevel Detailed -WarningAction SilentlyContinue
    Write-Verdict 'baseline reachability (pre-rules)' ([bool]$baseline.TcpTestSucceeded)

    # -- Apply the EXACT rule set win_quarantine builds today ------------
    # Recovers: Remove-YuzuQuarantineRules (netsh delete, same mechanism as
    # win_unquarantine) undoes every rule added in this block; either
    # watchdog undoes it unattended if this script cannot.
    # RE-ARM IMMEDIATELY BEFORE THE DESTRUCTIVE STEP. The earlier re-arm sits
    # before target resolution, whose duration is not bounded by anything this
    # script controls; if resolution outlives the triggers, both watchdogs fire
    # harmlessly on a host with no rules and the Block set below then goes live
    # with NO recovery armed at all - stranding the host. The protection window
    # must cover the destructive step, so it is opened here, last thing before it.
    Set-FreshTrigger -TaskName $WatchdogPrimary -Minutes 5
    Set-FreshTrigger -TaskName $WatchdogBackstop -Minutes 15
    Write-Log 'Watchdogs re-armed immediately before applying Block rules (+5m / +15m).'

    if ($Scenario -eq 'LegacyBlockRules') {
        Write-Log 'Applying win_quarantine rule set (netsh, argv matches quarantine_plugin.cpp exactly)...'
        & netsh.exe advfirewall firewall add rule name="${RulePrefix}BlockAllInbound" dir=in action=block enable=yes protocol=any | Out-Null
        & netsh.exe advfirewall firewall add rule name="${RulePrefix}BlockAllOutbound" dir=out action=block enable=yes protocol=any | Out-Null
    } else {
        # Branch-A shape: no named Block rule anywhere. Containment comes from
        # the profile default policy, which a rule is documented to outrank -
        # that documented claim is exactly what this scenario exists to test.
        # Recovers: the teardown below restores $preProfile verbatim, and BOTH
        # watchdogs' recovery script already resets the profile defaults to
        # Block/Allow independently of this process.
        Write-Log 'Applying branch-A shape: profile-default block, no named Block rules...'
        & netsh.exe advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
    }
    & netsh.exe advfirewall firewall add rule name="${RulePrefix}AllowLoopbackIn" dir=in action=allow enable=yes remoteip=127.0.0.1 | Out-Null
    & netsh.exe advfirewall firewall add rule name="${RulePrefix}AllowLoopbackOut" dir=out action=allow enable=yes remoteip=127.0.0.1 | Out-Null
    & netsh.exe advfirewall firewall add rule name="${RulePrefix}AllowLoopbackIn6" dir=in action=allow enable=yes remoteip=::1 | Out-Null
    & netsh.exe advfirewall firewall add rule name="${RulePrefix}AllowLoopbackOut6" dir=out action=allow enable=yes remoteip=::1 | Out-Null

    $whitelist = @($physical.Ip)
    if ($BragaTailscaleAddress) { $whitelist += $BragaTailscaleAddress }
    foreach ($ip in $whitelist) {
        & netsh.exe advfirewall firewall add rule name="${RulePrefix}AllowIn_${ip}" dir=in action=allow enable=yes remoteip=$ip | Out-Null
        & netsh.exe advfirewall firewall add rule name="${RulePrefix}AllowOut_${ip}" dir=out action=allow enable=yes remoteip=$ip | Out-Null
    }
    Write-Log "Rule set applied. Whitelisted: $($whitelist -join ', ')$(if ($BragaTailscaleAddress) { ' (braga entry is INFORMATIONAL only)' })"

    # -- Measurements (all on-box) ----------------------------------------
    $physicalResult = Test-NetConnection -ComputerName $physical.Ip -Port $physical.Port -InformationLevel Detailed -WarningAction SilentlyContinue
    $controlResult  = Test-NetConnection -ComputerName $ControlTarget -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue

    $loopbackPort = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -eq 22 | Select-Object -First 1 -ExpandProperty LocalPort)
    if (-not $loopbackPort) {
        $loopbackPort = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty LocalPort)
    }
    $loopbackResult = if ($loopbackPort) {
        Test-NetConnection -ComputerName '127.0.0.1' -Port $loopbackPort -InformationLevel Detailed -WarningAction SilentlyContinue
    } else { $null }
    # #3429 should-fix: the IPv4 loopback rules above proved "loopback stayed
    # reachable" for 127.0.0.1 only -- this measures the ::1 Allow rules
    # added alongside them so the same claim is actually verified for IPv6,
    # not just assumed to mirror the v4 result.
    $loopback6Result = if ($loopbackPort) {
        Test-NetConnection -ComputerName '::1' -Port $loopbackPort -InformationLevel Detailed -WarningAction SilentlyContinue
    } else { $null }

    $bragaResult = $null
    if ($BragaTailscaleAddress) {
        $bragaResult = Test-NetConnection -ComputerName $BragaTailscaleAddress -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue
    }

    Write-Log "=== MEASUREMENTS (post-rule-set) ==="
    Write-Log "  physical whitelisted $($physical.Ip):$($physical.Port) [ifIndex $($physical.IfIndex)] -> TcpTestSucceeded=$($physicalResult.TcpTestSucceeded)"
    Write-Log "  non-whitelisted control $ControlTarget:443 -> TcpTestSucceeded=$($controlResult.TcpTestSucceeded) (expected: False)"
    Write-Log "  loopback 127.0.0.1:$loopbackPort -> TcpTestSucceeded=$($loopbackResult.TcpTestSucceeded)"
    Write-Log "  loopback [::1]:$loopbackPort -> TcpTestSucceeded=$($loopback6Result.TcpTestSucceeded)"
    if ($bragaResult) {
        Write-Log "  [INFORMATIONAL ONLY, overlay-confounded] braga $BragaTailscaleAddress:443 -> TcpTestSucceeded=$($bragaResult.TcpTestSucceeded)"
    }

    Start-Sleep -Seconds 2   # let the log drain before scanning it
    $dropHits = @()
    foreach ($lp in ($logPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
        $dropHits += Select-String -Path $lp -Pattern ([regex]::Escape($physical.Ip)) -ErrorAction SilentlyContinue
    }
    Write-Log "  drop-log entries mentioning $($physical.Ip): $($dropHits.Count)"

    # -- Sleep, then teardown ---------------------------------------------
    Write-Log 'Holding for ~60s before teardown...'
    Start-Sleep -Seconds 60

    # Recovers: this IS the recovery. Restores exactly the profile defaults
    # captured above, removes every rule this run added, disables logging,
    # unregisters both watchdogs now that they are no longer needed.
    Write-Log 'Tearing down...'
    $removed = Remove-YuzuQuarantineRules
    foreach ($row in $preProfile) {
        Set-NetFirewallProfile -Name $row.Name -DefaultInboundAction $row.DefaultInboundAction -DefaultOutboundAction $row.DefaultOutboundAction
    }
    & netsh.exe advfirewall set allprofiles logging droppedconnections disable | Out-Null
    Remove-WatchdogTasks
    Remove-Item -Path $RecoveryScript -ErrorAction SilentlyContinue

    $postProfile = Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction
    $residualRules = @(Get-YuzuQuarantineRuleNames)
    $residualTasks = @(@($WatchdogPrimary, $WatchdogBackstop) | Where-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue })
    $clean = ($residualRules.Count -eq 0 -and $residualTasks.Count -eq 0)

    Write-Log '--- post-state: Get-NetFirewallProfile ---'
    $postProfile | Format-Table | Out-String | Write-Host
    Write-Verdict 'teardown residue check' $clean $(if (-not $clean) { "rules=$($residualRules -join ',') tasks=$($residualTasks -join ',')" })
    if (-not $clean) {
        Write-Log 'TEARDOWN DID NOT FULLY VERIFY CLEAN - SAY SO IN THE DOC. DO NOT REPORT A CLEAN RUN.'
    }

    $verdictLine = if ($physicalResult.TcpTestSucceeded -and -not $controlResult.TcpTestSucceeded) {
        if ($Scenario -eq 'LegacyBlockRules') {
            'BLOCK OVERRIDES ALLOW = FALSE (the Allow rule won: whitelisted physical target stayed reachable while the non-whitelisted control was blocked)'
        } else {
            'ALLOW RULE OVERRIDES PROFILE-DEFAULT BLOCK = TRUE (branch-A premise HOLDS: the whitelisted physical target stayed reachable under a profile-default block while the non-whitelisted control was cut off)'
        }
    } elseif (-not $physicalResult.TcpTestSucceeded -and -not $controlResult.TcpTestSucceeded) {
        if ($Scenario -eq 'LegacyBlockRules') {
            'BLOCK OVERRIDES ALLOW = TRUE (the Block rule won: even the whitelisted physical target was cut off)'
        } else {
            'ALLOW RULE OVERRIDES PROFILE-DEFAULT BLOCK = FALSE (branch-A premise FAILS: the whitelisted physical target was cut off even with no named Block rule present - the redesign would strand a quarantined host, DO NOT SHIP IT)'
        }
    } else {
        "AMBIGUOUS (physical=$($physicalResult.TcpTestSucceeded) control=$($controlResult.TcpTestSucceeded) - control should have been blocked and was not; treat as INCONCLUSIVE, do not assert a precedence claim)"
    }
    Write-Log "VERDICT: $verdictLine"
    Write-Log "Transcript: $TranscriptPath"
    Stop-Transcript | Out-Null
    exit $(if ($clean) { 0 } else { 4 })
}
catch {
    Write-Log "UNHANDLED EXCEPTION: $($_.Exception.Message)"
    Write-Log $_.ScriptStackTrace
    Invoke-EmergencyCleanup -Reason 'unhandled exception'
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
