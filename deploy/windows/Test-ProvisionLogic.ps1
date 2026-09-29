#Requires -Version 7
<#
  Test-ProvisionLogic.ps1 — hand-run regression tests for the decision logic in
  Provision-Windows-Runner.ps1.

  Provisioning is the one script here that cannot be exercised in CI: it is
  elevated, Windows-only, and its whole job is mutating live shared state on the
  runner box. Reviews of it are therefore static, and PR #2359's review round 2
  landed a blocker (a drain check that was a point-in-time snapshot, gating on
  the wrong process, placed after an unguarded service restart) that no static
  read had caught in round 1. This file exists so the guard rails that came out
  of that round have an executable check.

  Scope, honestly: this covers the maintenance gate, the -D data-dir handling,
  the ImagePath rewrite, and a set of structural invariants over the script's
  own AST. It does NOT execute provisioning — nothing here proves a real
  robocopy, service repoint or cluster restart works. Round 3 of the PR #2359
  review found two live blockers while an earlier version of this suite reported
  all-green, because one assertion compared the first gate call against the
  first restart and so passed trivially; treat green here as "the specific
  regressions below are absent", never as "provisioning is correct".

  It is SAFE TO RUN ANYWHERE: no elevation, no machine state. Function bodies
  are extracted from the real script via the AST (never copied, so they cannot
  drift), Get-CimInstance is mocked, the registry work uses a throwaway HKCU key
  that is deleted afterwards, and the end-to-end suite runs the real script
  prologue truncated just before the first Step.

  Run it after ANY change to the maintenance gate, the -D data-dir handling, or
  the service ImagePath rewrite:

      pwsh -File deploy\windows\Test-ProvisionLogic.ps1

  Exit 0 = all passed. Exit 1 = at least one failure.
#>
[CmdletBinding()]
param(
  # Path to the script under test; defaults to its sibling in this directory.
  [string]$ScriptPath = (Join-Path $PSScriptRoot 'Provision-Windows-Runner.ps1'),
  # Skip suite 4 (spawns child pwsh processes; ~5s).
  [switch]$SkipEndToEnd
)
$ErrorActionPreference = 'Stop'

if(-not (Test-Path -LiteralPath $ScriptPath)){ throw "script under test not found: $ScriptPath" }
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path

$toks = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$toks, [ref]$errs)
if($errs.Count){
  Write-Host "PARSE ERRORS in $ScriptPath" -ForegroundColor Red
  $errs | ForEach-Object { Write-Host "  $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
  exit 1
}

# Pull the real definitions into this session. Anything renamed or deleted in
# the script fails here rather than silently testing a stale copy.
# NOTE: Assert-RunnersDrained is deliberately NOT imported. It exits the process
# on detection (that is the point — see suite 4), so calling it in-process would
# kill this harness. Its behaviour is tested end-to-end in suite 5, against a
# real child pwsh, which is a stronger test than an in-process stub anyway.
foreach($name in @('Get-ActiveRunnerProcess','Get-PgServiceImageParts')){
  $fn = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
  if(-not $fn){ throw "function $name not found in the script under test" }
  Invoke-Expression $fn[0].Extent.Text
}

$script:pass = 0; $script:fail = 0
function Check([string]$what,[scriptblock]$body){
  try {
    if(& $body){ Write-Host "  PASS  $what" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  FAIL  $what" -ForegroundColor Red;   $script:fail++ }
  } catch {
    Write-Host "  FAIL  $what :: $($_.Exception.Message)" -ForegroundColor Red; $script:fail++
  }
}

Write-Host "Testing: $ScriptPath" -ForegroundColor DarkGray

# --- 1. Maintenance gate -----------------------------------------------------
# The round-2 blocker: gating on Runner.Worker.exe alone is a snapshot, because
# an idle Runner.Listener.exe accepts a job seconds later while the binary step
# is still copying trees. Gating on the LISTENER is what closes the window.
Write-Host "`nRunner observation (Get-ActiveRunnerProcess)" -ForegroundColor Cyan
$script:mockProcs  = @()
$script:lastFilter = ''
$script:cimShouldThrow = $false
function Get-CimInstance { param($ClassName,$Filter,$EA)
  $script:lastFilter = $Filter
  if($script:cimShouldThrow){ throw 'simulated WMI/DCOM failure' }
  $script:mockProcs | Where-Object { $Filter -like "*'$($_.Name)'*" }
}
$RunnerCount = 4
$AllowActiveRunners = $false

Check 'queries for BOTH process names (worker alone would be a snapshot)' {
  $script:mockProcs = @(); Get-ActiveRunnerProcess | Out-Null
  ($script:lastFilter -match 'Runner\.Listener\.exe') -and ($script:lastFilter -match 'Runner\.Worker\.exe')
}

Check 'drained box observes nothing' {
  $script:mockProcs = @(); (Get-ActiveRunnerProcess).Count -eq 0
}

Check 'an active WORKER is observed' {
  $script:mockProcs = @([pscustomobject]@{ Name='Runner.Worker.exe'; ProcessId=4242 })
  @(Get-ActiveRunnerProcess)[0].ProcessId -eq 4242
}

Check 'an idle LISTENER is observed (the round-2 TOCTOU fix)' {
  $script:mockProcs = @([pscustomobject]@{ Name='Runner.Listener.exe'; ProcessId=1111 })
  @(Get-ActiveRunnerProcess)[0].ProcessId -eq 1111
}

Check 'every live process is observed, not just the first' {
  $script:mockProcs = @(
    [pscustomobject]@{ Name='Runner.Worker.exe';   ProcessId=9 },
    [pscustomobject]@{ Name='Runner.Listener.exe'; ProcessId=7 },
    [pscustomobject]@{ Name='Runner.Listener.exe'; ProcessId=3 })
  (Get-ActiveRunnerProcess).Count -eq 3
}

# The probe reports observation failure rather than hiding it; the GATE is what
# turns that into a refusal (suite 5). Keeping the policy out of the probe is
# what lets the rollback path use the same function without being aborted by it.
Check 'an unobservable box surfaces as a throw, not an empty result' {
  $script:cimShouldThrow = $true
  try { Get-ActiveRunnerProcess | Out-Null; $false }
  catch { $_.Exception.Message -match 'simulated WMI/DCOM failure' }
  finally { $script:cimShouldThrow = $false }
}

# --- 2. robocopy /XD exclusion canonicalisation ------------------------------
# /XD matches the directory by PATH STRING. $srcData comes from parsing a
# registry value, so a non-canonical form silently fails to match and copies the
# LIVE agent-0 data dir into the private tree.
Write-Host "`nrobocopy /XD exclusion canonicalisation" -ForegroundColor Cyan
$norm = { param($p) [IO.Path]::GetFullPath($p).TrimEnd('\') }

Check 'trailing separator stripped'  { (& $norm 'C:\pgsql\data\')        -eq 'C:\pgsql\data' }
Check 'relative segment collapsed'   { (& $norm 'C:\pgsql\bin\..\data')  -eq 'C:\pgsql\data' }
Check 'already-canonical unchanged'  { (& $norm 'C:\pgsql\data')         -eq 'C:\pgsql\data' }

Check 'under-install-root test matches after normalisation' {
  (& $norm 'C:\pgsql\data\') -like "$(& $norm 'C:\pgsql')\*"
}
Check 'data dir OUTSIDE the install root is not treated as excluded-in-tree' {
  -not ((& $norm 'D:\ci\pg\agent-1') -like "$(& $norm 'C:\pgsql')\*")
}

# --- 3. ImagePath rewrite + value-kind preservation --------------------------
# Real registry, throwaway HKCU key (no elevation, no machine state).
Write-Host "`nImagePath rewrite + registry value kind" -ForegroundColor Cyan
$testKey = "HKCU:\Software\YuzuProvisionTest-$([guid]::NewGuid().ToString('N'))"
New-Item -Path $testKey -Force | Out-Null
try {
  # A REG_SZ ImagePath carrying a literal '%' — the case a hardcoded
  # -Type ExpandString would silently fail to restore on rollback.
  $orig = '"C:\pgsql\bin\pg_ctl.exe" runservice -N "svc" -D "C:\pgsql\data\100%pure"'
  New-ItemProperty -Path $testKey -Name ImagePath -Value $orig -PropertyType String -Force | Out-Null

  $curImage  = (Get-ItemProperty $testKey -Name ImagePath).ImagePath
  $curExe    = (Get-PgServiceImageParts $curImage).Exe
  $imageKind = (Get-Item $testKey).GetValueKind('ImagePath')
  $newExe    = 'D:\ci\pgbin\agent-0\bin\pg_ctl.exe'

  Check 'original kind read as REG_SZ'      { $imageKind -eq [Microsoft.Win32.RegistryValueKind]::String }
  Check 'exe parsed out of quoted ImagePath'{ $curExe -eq 'C:\pgsql\bin\pg_ctl.exe' }

  $exeOffset = $curImage.IndexOf($curExe, [StringComparison]::OrdinalIgnoreCase)
  $newImage  = $curImage.Substring(0,$exeOffset) + $newExe + $curImage.Substring($exeOffset + $curExe.Length)

  Check 'rewrite repoints the exe and leaves -D byte-identical' {
    $newImage -eq '"D:\ci\pgbin\agent-0\bin\pg_ctl.exe" runservice -N "svc" -D "C:\pgsql\data\100%pure"'
  }

  Set-ItemProperty $testKey -Name ImagePath -Value $newImage -Type $imageKind
  Check 'repoint preserves REG_SZ kind' {
    (Get-Item $testKey).GetValueKind('ImagePath') -eq [Microsoft.Win32.RegistryValueKind]::String
  }

  Set-ItemProperty $testKey -Name ImagePath -Value $curImage -Type $imageKind
  Check 'rollback restores the exact original bytes' {
    (Get-ItemProperty $testKey -Name ImagePath).ImagePath -eq $orig
  }
  Check 'rollback preserves REG_SZ kind' {
    (Get-Item $testKey).GetValueKind('ImagePath') -eq [Microsoft.Win32.RegistryValueKind]::String
  }

  # Control: prove the pre-#2359 hardcoded ExpandString was genuinely wrong here,
  # so this is a regression test and not a style preference.
  Set-ItemProperty $testKey -Name ImagePath -Value $curImage -Type ExpandString
  Check 'CONTROL: -Type ExpandString would NOT have restored the original' {
    (Get-Item $testKey).GetValueKind('ImagePath') -ne [Microsoft.Win32.RegistryValueKind]::String
  }

  # Control: the offset rewrite vs .Replace() on an argument that contains the
  # executable path as a substring.
  $collide  = '"C:\pgsql\bin\pg_ctl.exe" runservice -D "C:\pgsql\bin\pg_ctl.exe.d"'
  $cExe     = (Get-PgServiceImageParts $collide).Exe
  $off      = $collide.IndexOf($cExe, [StringComparison]::OrdinalIgnoreCase)
  $spliced  = $collide.Substring(0,$off) + $newExe + $collide.Substring($off + $cExe.Length)
  Check 'CONTROL: offset rewrite hits only the first occurrence, .Replace() does not' {
    ($spliced -eq "`"$newExe`" runservice -D `"C:\pgsql\bin\pg_ctl.exe.d`"") -and
    ($collide.Replace($cExe,$newExe) -ne $spliced)
  }
} finally {
  Remove-Item -Path $testKey -Recurse -Force -EA SilentlyContinue
}

# --- 4. Structural invariants ------------------------------------------------
# Suites 1-3 prove the extracted logic is correct; they cannot prove the script
# still USES it. A revert of `-Type $imageKind` back to `-Type ExpandString`
# passes all of suite 3. These assertions read the script's own AST, so the
# round-2 findings cannot be undone silently.
Write-Host "`nStructural invariants (AST of the script under test)" -ForegroundColor Cyan
$text = Get-Content -LiteralPath $ScriptPath -Raw
function Find-Call([string]$name){
  @($ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $name }, $true) |
    Sort-Object { $_.Extent.StartLineNumber })
}

$imagePathWrites = @(Find-Call 'Set-ItemProperty' | Where-Object { $_.Extent.Text -match 'ImagePath' })
Check 'both ImagePath writes (repoint + rollback) are present' { $imagePathWrites.Count -eq 2 }
Check 'no ImagePath write hardcodes a registry value kind' {
  -not @($imagePathWrites | Where-Object { $_.Extent.Text -match '-Type\s+(ExpandString|String|MultiString|\[)' })
}
Check 'every ImagePath write passes the captured original kind' {
  @($imagePathWrites | Where-Object { $_.Extent.Text -match '-Type\s+\$imageKind' }).Count -eq $imagePathWrites.Count
}
# ...and that the captured kind is READ FROM THE KEY. Without this, assigning a
# literal to $imageKind passes every check above while restoring the wrong kind.
Check 'the captured kind is read from the service key, not a literal' {
  $text -match '\$imageKind\s*=\s*\(Get-Item\s+\$regPath\)\.GetValueKind\('
}

$gateCalls = Find-Call 'Assert-RunnersDrained'
$stepCalls = Find-Call 'Step'
$restarts  = Find-Call 'Restart-Service'
Check 'the gate is asserted at least 3x (top of script, step entry, pre-restart)' { $gateCalls.Count -ge 3 }
Check 'the top-level gate precedes the FIRST Step' {
  $gateCalls.Count -and $stepCalls.Count -and
  ($gateCalls[0].Extent.StartLineNumber -lt $stepCalls[0].Extent.StartLineNumber)
}
# Position alone is not enough: Step() catches and continues, so a gate nested
# inside any scriptblock cannot stop the mutations below it. That was half the
# round-2 blocker. Assert the first gate call is genuinely at script top level.
Check 'the top-level gate is NOT nested inside a scriptblock (Step would swallow it)' {
  if(-not $gateCalls.Count){ return $false }
  $node = $gateCalls[0].Parent
  while($node){
    if($node -is [System.Management.Automation.Language.ScriptBlockExpressionAst]){ return $false }
    $node = $node.Parent
  }
  $true
}
# Round-3 finding, correctly made: the previous version of this compared the
# FIRST gate call against the FIRST restart. The top-level gate is always
# textually first, so it passed trivially — green while two blockers were live
# in the code it had just "tested". Pair EVERY restart with its own nearby gate
# instead, and require any deliberate exception to be marked in the source.
# NB: this is a TEXTUAL smoke guard, not a control-flow proof. It catches a
# literal revert of either gate, which is what it is for. It would NOT catch a
# gate call sitting in a dead branch, gating a different service, or merely
# adjacent by coincidence. Do not cite it as a safety proof.
Check 'EVERY Restart-Service is immediately preceded by a gate or a DRAIN-EXEMPT marker' {
  if(-not $restarts.Count){ return $false }
  $srcLines   = $text -split "`r?`n"
  $gateLines  = @($gateCalls | ForEach-Object { $_.Extent.StartLineNumber })
  $ungated    = @()
  foreach($r in $restarts){
    $line    = $r.Extent.StartLineNumber
    # Look back a short window: the gate must be adjacent to the restart it
    # protects, not merely somewhere earlier in the file.
    $window  = [Math]::Max(1, $line - 12)
    $covered = @($gateLines | Where-Object { $_ -ge $window -and $_ -lt $line }).Count -gt 0
    if(-not $covered){
      $exempt = $false
      for($i = $window; $i -lt $line; $i++){
        if($srcLines[$i-1] -match 'DRAIN-EXEMPT'){ $exempt = $true; break }
      }
      if(-not $exempt){ $ungated += $line }
    }
  }
  if($ungated.Count){ Write-Host "        ungated Restart-Service at line(s): $($ungated -join ', ')" -ForegroundColor DarkYellow }
  $ungated.Count -eq 0
}
# THE load-bearing invariant, and the reason rounds 3 and 4 cannot recur. The
# gate signals "stop" with `exit`, which no try/catch can intercept, instead of
# a string-tagged exception that every intervening handler had to recognise and
# re-throw. Two handlers didn't, and both were shipped blockers: Step() swallowed
# it (round 3), and the rollback recovery catch re-wrapped it and stripped the
# tag (round 4). If this assertion ever fails, that entire class is back.
Check 'the gate stops the process with exit, never with a throw a handler could eat' {
  $gate = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -eq 'Assert-RunnersDrained' }, $true)
  if(-not $gate){ return $false }
  $body = $gate[0].Extent.Text
  ($body -match '\bexit\s+\d') -and ($body -notmatch '(?m)^\s*throw\b')
}
# Corollary: no handler should be pattern-matching on a drain signal any more,
# because there is no signal to match — the process is already gone. A revival
# of the tag protocol anywhere is a regression to the round-3/4 design.
Check 'no handler pattern-matches a drain signal (the tag protocol stays dead)' {
  ($text -notmatch 'kDrainTag') -and ($text -notmatch 'RUNNERS-ACTIVE')
}
# Round-4 blocker 1: the DRAIN-EXEMPT restart must be earned by a liveness probe,
# not by an assumption that a failed forward path implies a dead cluster.
# Restart-Service can throw in its STOP phase with the original postmaster still
# serving.
Check 'the DRAIN-EXEMPT restart is conditional on a proven-not-serving cluster' {
  ($text -match 'function Test-PgServingNow') -and
  ($text -match '\$stillServing\s*=\s*Test-PgServingNow') -and
  ($text -notmatch '\$restartCompleted')
}
# Every cluster restart proves it came back — the main PostgreSQL step's as well
# as the per-agent ones. That is why Assert-PgServing is script-scoped rather
# than nested in one Step (round-4 should-fix).
Check 'the main PostgreSQL restart verifies the cluster actually serves' {
  ($text -match '(?m)^function Assert-PgServing') -and
  ($text -match 'Assert-PgServing \$pgbin \$PostgresPort')
}
Check 'the -D data dir is canonicalised before robocopy /XD' {
  $text -match '\$srcData\s*=\s*\[IO\.Path\]::GetFullPath\(\$srcData\)\.TrimEnd'
}
Check 'the private postgres.exe Defender exclusions are verified fail-closed' {
  ($text -match 'Defender path exclusion did not apply') -and
  ($text -match 'Defender process exclusions did not apply')
}

# --- 5. Maintenance gate, end to end -----------------------------------------
# The round-2 blocker was as much about WHERE the gate sits as what it checks:
# Step() catches and continues, and an unconditional PostgreSQL Restart-Service
# runs early in the script. Assert the gate aborts the PROCESS before step 1.
if(-not $SkipEndToEnd){
  Write-Host "`nMaintenance gate, end to end (real prologue, mocked Get-CimInstance)" -ForegroundColor Cyan
  $work = Join-Path ([IO.Path]::GetTempPath()) "yuzu_test_provgate_$([guid]::NewGuid().ToString('N'))"
  New-Item -ItemType Directory -Force $work | Out-Null
  try {
    # The real prologue resolves the reviewed contract beside $PSScriptRoot.
    # Its disposable copy must preserve that runtime layout or the child
    # processes stop at contract loading before reaching the drain gate.
    $sourceRoot = Split-Path $ScriptPath
    $contractPath = Join-Path $sourceRoot 'toolchain-contract.json'
    $modulePath = Join-Path $sourceRoot 'Toolchain-Contract.psm1'
    if(-not (Test-Path -LiteralPath $contractPath)){ throw "toolchain contract not found: $contractPath" }
    if(-not (Test-Path -LiteralPath $modulePath)){ throw "toolchain contract module not found: $modulePath" }
    Copy-Item -LiteralPath $contractPath -Destination (Join-Path $work 'toolchain-contract.json')
    Copy-Item -LiteralPath $modulePath -Destination (Join-Path $work 'Toolchain-Contract.psm1')

    $text = Get-Content -LiteralPath $ScriptPath -Raw
    $cut  = $text.IndexOf("Step 'winget sanity'")
    if($cut -lt 0){ throw "could not locate the first Step in the script under test" }
    $prologue = $text.Substring(0,$cut)

    # Non-elevated harness: drop the admin requirement, redirect the transcript.
    $prologue = $prologue -replace '(?m)^#Requires -RunAsAdministrator\r?\n',''
    $prologue = $prologue.Replace("'C:\ProvisionLogs'", "'$work\logs'")
    $prologue = $prologue.Replace('"C:\ProvisionLogs\provision-', "`"$work\logs\provision-")

    $mock = @'
function Get-CimInstance { param($ClassName,$Filter,$EA)
  if($env:YUZU_GATETEST_THROW){ throw 'simulated WMI/DCOM failure' }
  if($env:YUZU_GATETEST_PROCS){
    $env:YUZU_GATETEST_PROCS.Split(';') | ForEach-Object {
      $p=$_.Split(','); [pscustomobject]@{ Name=$p[0]; ProcessId=[int]$p[1] }
    } | Where-Object { $Filter -like "*'$($_.Name)'*" }
  }
}
'@
    $marker = '# ---- Maintenance gate'
    if($prologue -notmatch [regex]::Escape($marker)){ throw "maintenance-gate marker not found in the prologue" }
    $prologue = $prologue.Replace($marker, "$mock`n$marker")

    $harness = Join-Path $work 'gate-harness.ps1'
    ($prologue + "`nWrite-Host 'REACHED-STEP-1'`nStop-Transcript | Out-Null`nexit 0`n") |
      Set-Content -LiteralPath $harness -Encoding UTF8

    function Case([string]$what,[string]$procs,[string[]]$extraArgs,[int]$wantExit,[bool]$wantReached,[switch]$CimThrows){
      $env:YUZU_GATETEST_PROCS = $procs
      if($CimThrows){ $env:YUZU_GATETEST_THROW = '1' }
      try {
        $out  = & pwsh -NoProfile -File $harness @extraArgs 2>&1 | Out-String
        $code = $LASTEXITCODE
      } finally {
        Remove-Item Env:\YUZU_GATETEST_PROCS -EA SilentlyContinue
        Remove-Item Env:\YUZU_GATETEST_THROW -EA SilentlyContinue
      }
      $reached = [bool]($out -match 'REACHED-STEP-1')
      if(($code -eq $wantExit) -and ($reached -eq $wantReached)){
        Write-Host "  PASS  $what (exit=$code, reachedStep1=$reached)" -ForegroundColor Green; $script:pass++
      } else {
        Write-Host "  FAIL  $what (exit=$code want=$wantExit, reachedStep1=$reached want=$wantReached)" -ForegroundColor Red
        Write-Host (($out -split "`n" | Select-Object -First 12) -join "`n")
        $script:fail++
      }
    }

    # THE round-3 regression test, now against the real gate rather than a
    # simulated tagged throw: call Assert-RunnersDrained from INSIDE a Step,
    # where Step()'s catch would previously have swallowed it, and prove the
    # process dies before any later step. This is the case that shipped broken.
    $midHarness = Join-Path $work 'gate-harness-mid.ps1'
    ($prologue + @"
`nStep 'mid-script drain detection' { Assert-RunnersDrained 'mid-script check' }
Write-Host 'REACHED-AFTER-STEP'
Stop-Transcript | Out-Null
exit 0
"@) | Set-Content -LiteralPath $midHarness -Encoding UTF8
    function MidCase([string]$what,[string]$procs,[bool]$cimThrows,[int]$wantExit,[bool]$wantReached){
      $env:YUZU_GATETEST_PROCS = $procs
      if($cimThrows){ $env:YUZU_GATETEST_THROW = '1' }
      try {
        $out  = & pwsh -NoProfile -File $midHarness 2>&1 | Out-String
        $code = $LASTEXITCODE
      } finally {
        Remove-Item Env:\YUZU_GATETEST_PROCS -EA SilentlyContinue
        Remove-Item Env:\YUZU_GATETEST_THROW -EA SilentlyContinue
      }
      $reached = [bool]($out -match 'REACHED-AFTER-STEP')
      if(($code -eq $wantExit) -and ($reached -eq $wantReached)){
        Write-Host "  PASS  $what (exit=$code, laterStepsRan=$reached)" -ForegroundColor Green; $script:pass++
      } else {
        Write-Host "  FAIL  $what (exit=$code want=$wantExit, laterStepsRan=$reached want=$wantReached)" -ForegroundColor Red
        Write-Host (($out -split "`n" | Select-Object -First 12) -join "`n")
        $script:fail++
      }
    }
    MidCase 'gate INSIDE a Step kills the process; Step() cannot swallow it' 'Runner.Worker.exe,77' $false 2 $false
    MidCase 'gate inside a Step, box drained -> later steps run normally'    ''                     $false 0 $true
    MidCase 'gate inside a Step, box UNOBSERVABLE -> fails closed, exit 2'   ''                     $true  2 $false

    Case 'drained box proceeds to step 1'             ''                                         @()                      0 $true
    Case 'live WORKER   -> exit 2, step 1 never runs' 'Runner.Worker.exe,4242'                   @()                      2 $false
    Case 'idle LISTENER -> exit 2, step 1 never runs' 'Runner.Listener.exe,1111'                 @()                      2 $false
    Case 'both live     -> exit 2, step 1 never runs' 'Runner.Listener.exe,1;Runner.Worker.exe,2' @()                     2 $false
    Case '-AllowActiveRunners proceeds anyway'        'Runner.Worker.exe,4242'                   @('-AllowActiveRunners') 0 $true
    Case 'unobservable box -> fails closed at the top gate' '' @() 2 $false -CimThrows
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
  }
}

Write-Host "`n$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if($script:fail){'Red'}else{'Green'})
exit $(if($script:fail){1}else{0})
