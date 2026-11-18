<#
.SYNOPSIS
    Copy the Microsoft Visual C++ runtime DLLs the Windows agent imports into
    the agent payloads (app-local deployment).

.DESCRIPTION
    yuzu-agent.exe, yuzu_agent_core.dll, every plugin and every vcpkg DLL are
    built with MSVC and import vcruntime140.dll, vcruntime140_1.dll and
    msvcp140.dll; yuzu-agent.exe also imports msvcp140_atomic_wait.dll
    (first shipped in redistributable 14.28). Up to v0.15.0 neither the release zip nor
    YuzuAgentSetup carried them, so the agent ran only where some other product
    had installed the Visual C++ Redistributable.

    This script copies them from the build machine's own Visual Studio
    redistributable directory, the same toolset that compiled the binaries,
    into each -Destination directory (the zip's bin\ and the installer's
    payload directory build-windows\msvc-runtime, which yuzu-agent.iss installs
    into {app}\bin). It copies vcruntime140.dll, vcruntime140_1.dll,
    msvcp140.dll and msvcp140_atomic_wait.dll, which must all be present, plus
    every other vcruntime140_*.dll and msvcp140_*.dll in that directory, so a
    later import of one of them is already covered. Any other runtime DLL a
    binary starts to import (concrt140.dll, vccorlib140.dll) is caught by
    scripts/ci/check-windows-payload-imports.py, which release.yml runs next.

    The redistributable directory is resolved, in order, from -RedistDir, from
    $env:VCToolsRedistDir (which ilammy/msvc-dev-cmd exports in CI), and
    otherwise from vswhere and the install's
    VC\Auxiliary\Build\Microsoft.VCRedistVersion.default.txt. A source that is
    given but does not hold exactly one x64\Microsoft.VC14*.CRT directory
    fails; it never falls through to the next one. This script never runs
    vcvars64.bat (docs/windows-build.md).

    Microsoft permits these files to be redistributed with an application,
    including in the application's own directory ("app-local"), under the
    Distributable Code terms of the Visual Studio licence; see NOTICE.

    Before copying, it removes every vcruntime140*.dll and msvcp140*.dll
    already in a destination, so a reused directory cannot ship a stale one.
    When $env:GITHUB_STEP_SUMMARY is set (a GitHub Actions step), it appends
    the staged DLL names and file versions to the step summary, which records
    the runtime each release shipped.

.PARAMETER Destination
    One or more directories to copy the DLLs into (created if absent).

.PARAMETER RedistDir
    A Visual Studio redistributable version directory,
    ...\VC\Redist\MSVC\<version>. Defaults to $env:VCToolsRedistDir.

.PARAMETER ToolsVersion
    The MSVC toolset version that built the binaries (14.44.35207). Defaults to
    $env:VCToolsVersion. When known, its major.minor must equal the pin in
    -PinFile, and the redistributable's major.minor must be at least the
    toolset's: a newer toolset can need runtime exports an older
    redistributable lacks. When unknown, the script fails in GitHub Actions
    ($env:GITHUB_ACTIONS is 'true'), where a release build always sets it;
    in a local build outside an MSVC environment both comparisons are skipped
    with a warning.

.PARAMETER PinFile
    The file holding the pinned toolset major.minor (msvc-toolset.pin next to
    this script by default): one non-comment line such as 14.44. agent
    self-update replaces only yuzu-agent.exe, never the app-local runtime
    (#8219), so a release built by a newer toolset than the pin could ship an
    executable that the runtime already on a device cannot run. The file says
    how to change the pin.

.NOTES
    PowerShell 7+ (pwsh.exe) only, like every Yuzu-authored script
    (docs/windows-build.md). Every check runs before anything is copied. A
    copy that then fails (a later destination after an earlier one was
    written, or a hash that differs) throws, so the calling release step
    fails and nothing is published; it does not undo what was already
    copied. Ends with `exit 0`, so a caller can test $LASTEXITCODE.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Destination,
    [string] $RedistDir = $env:VCToolsRedistDir,
    [string] $ToolsVersion = $env:VCToolsVersion,
    [string] $PinFile = (Join-Path $PSScriptRoot 'msvc-toolset.pin')
)

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error ("This script requires PowerShell 7+. Detected " +
                 $PSVersionTable.PSVersion.ToString() +
                 ". Use pwsh.exe, not powershell.exe.")
    exit 1
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Required = @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'msvcp140_atomic_wait.dll')

function Get-CrtDir([string] $VersionDir, [string] $From) {
    $x64 = Join-Path $VersionDir 'x64'
    if (-not (Test-Path -LiteralPath $x64 -PathType Container)) {
        throw "stage-msvc-runtime: $From gives '$VersionDir', which has no x64 directory"
    }
    $crt = @(Get-ChildItem -LiteralPath $x64 -Directory |
             Where-Object { $_.Name -match '^Microsoft\.VC14\d\.CRT$' })
    if ($crt.Count -ne 1) {
        throw ("stage-msvc-runtime: $From gives '$VersionDir', where x64 holds " +
               "$($crt.Count) Microsoft.VC14*.CRT directories (need exactly one)")
    }
    return $crt[0].FullName
}

function Find-VersionDirFromVswhere {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw ("stage-msvc-runtime: VCToolsRedistDir is not set and vswhere.exe is not at '$vswhere'. " +
               "Run from an MSVC environment (ilammy/msvc-dev-cmd in CI, setup_msvc_env.sh locally) " +
               "or pass -RedistDir.")
    }
    $install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $install) {
        throw "stage-msvc-runtime: vswhere found no Visual Studio install with the MSVC x64 tools"
    }
    $install = @($install)[0].Trim()
    $versionFile = Join-Path $install 'VC\Auxiliary\Build\Microsoft.VCRedistVersion.default.txt'
    if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
        throw "stage-msvc-runtime: '$versionFile' is missing, so the redistributable version is unknown"
    }
    $version = (Get-Content -LiteralPath $versionFile -TotalCount 1).Trim()
    if ($version -notmatch '^\d+\.\d+\.\d+$') {
        throw "stage-msvc-runtime: '$versionFile' holds '$version', not a version"
    }
    return Join-Path $install "VC\Redist\MSVC\$version"
}

function Get-MajorMinor([string] $Text) {
    if ($Text -match '^(\d+)\.(\d+)') { return [version]"$($Matches[1]).$($Matches[2])" }
    return $null
}

function Read-ToolsetPin([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "stage-msvc-runtime: the toolset pin file '$Path' is missing"
    }
    $values = @(Get-Content -LiteralPath $Path |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -and -not $_.StartsWith('#') })
    if ($values.Count -ne 1 -or $values[0] -notmatch '^\d+\.\d+$') {
        throw ("stage-msvc-runtime: '$Path' must hold exactly one major.minor line (such as 14.44); " +
               "found: $($values -join ', ')")
    }
    return [version]$values[0]
}

if ($RedistDir) {
    $from = if ($PSBoundParameters.ContainsKey('RedistDir')) { '-RedistDir' } else { 'VCToolsRedistDir' }
    $versionDir = $RedistDir.TrimEnd('\', '/')
} else {
    $from = 'vswhere'
    $versionDir = Find-VersionDirFromVswhere
}
$crtDir = Get-CrtDir $versionDir $from
Write-Host "Visual C++ runtime source ($from): $crtDir"

$redistVersion = Get-MajorMinor (Split-Path -Leaf $versionDir)
$toolsMajorMinor = Get-MajorMinor $ToolsVersion
if ($toolsMajorMinor) {
    $pin = Read-ToolsetPin $PinFile
    if ($toolsMajorMinor -ne $pin) {
        throw ("stage-msvc-runtime: the binaries were built by MSVC toolset $ToolsVersion ($toolsMajorMinor), " +
               "but $(Split-Path -Leaf $PinFile) pins $pin. Agent self-update replaces only yuzu-agent.exe, " +
               "never the app-local runtime (#8219), so the release toolset moves only by a reviewed change " +
               "to the pin; see the comment in '$PinFile'")
    }
    Write-Host "MSVC toolset $ToolsVersion matches the pin $pin"
    if (-not $redistVersion) {
        throw "stage-msvc-runtime: cannot read a version from '$versionDir' to compare with toolset $ToolsVersion"
    }
    if ($redistVersion -lt $toolsMajorMinor) {
        throw ("stage-msvc-runtime: redistributable $redistVersion is older than the toolset " +
               "$toolsMajorMinor that built the binaries")
    }
    Write-Host "Redistributable $redistVersion, toolset $toolsMajorMinor"
} elseif ($env:GITHUB_ACTIONS -eq 'true') {
    throw ("stage-msvc-runtime: toolset version unknown (VCToolsVersion is not set) in GitHub Actions; " +
           "the release build must run in an MSVC environment so the toolset pin can be checked")
} else {
    Write-Warning ("stage-msvc-runtime: toolset version unknown (VCToolsVersion is not set); the toolset pin " +
                   "and the redistributable/toolset comparison are skipped. A release build always sets it.")
}

foreach ($name in $Required) {
    if (-not (Test-Path -LiteralPath (Join-Path $crtDir $name) -PathType Leaf)) {
        throw "stage-msvc-runtime: $name is not in '$crtDir'"
    }
}
$dlls = @(Get-ChildItem -LiteralPath $crtDir -File |
          Where-Object { $_.Name -match '^(vcruntime140|msvcp140)(_[a-z0-9_]+)?\.dll$' } |
          Sort-Object Name)

foreach ($dll in $dlls) {
    if ($IsWindows) {
        $sig = Get-AuthenticodeSignature -LiteralPath $dll.FullName
        if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or
            $sig.SignerCertificate.Subject -cnotmatch '(^|,\s*)O=Microsoft Corporation(\s*,|$)') {
            throw "stage-msvc-runtime: $($dll.FullName) is not validly signed by Microsoft ($($sig.Status))"
        }
    }
}

foreach ($dest in $Destination) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    # A reused directory (a local build-windows\msvc-runtime) may hold runtime
    # DLLs from an earlier run that this redistributable no longer has.
    Get-ChildItem -LiteralPath $dest -File |
        Where-Object { $_.Name -like 'vcruntime140*.dll' -or $_.Name -like 'msvcp140*.dll' } |
        Remove-Item -Force
    foreach ($dll in $dlls) {
        $target = Join-Path $dest $dll.Name
        Copy-Item -LiteralPath $dll.FullName -Destination $target -Force
        $want = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash
        $got = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($want -ne $got) { throw "stage-msvc-runtime: the copy of $($dll.Name) in '$dest' differs from its source" }
    }
    Write-Host ("Staged into ${dest}: " + (($dlls | ForEach-Object {
        $v = $_.VersionInfo.FileVersion
        if ($v) { "$($_.Name) $v" } else { $_.Name }
    }) -join ', '))
}

if ($env:GITHUB_STEP_SUMMARY) {
    $summary = @('### Visual C++ runtime shipped app-local', '',
                 "Source: ``$crtDir``; toolset: $(if ($ToolsVersion) { $ToolsVersion } else { 'unknown' })", '',
                 '| DLL | File version |', '|---|---|')
    foreach ($dll in $dlls) {
        $v = $dll.VersionInfo.FileVersion
        $summary += "| $($dll.Name) | $(if ($v) { $v } else { 'none recorded' }) |"
    }
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value ($summary + '') -Encoding utf8
}
exit 0
