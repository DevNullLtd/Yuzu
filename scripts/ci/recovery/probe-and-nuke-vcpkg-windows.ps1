# Probe-And-Nuke-VcpkgState.ps1
#
# Inventory + selective wipe of candidate corrupt-vcpkg-state locations on
# yuzu-local-windows, then post-nuke inventory to confirm the runner is
# actually clean.
#
# Output is structured plain-ASCII with stable section markers + KEY: value
# fields per stanza, designed to be grep'd. Each run begins with a
# "########### RUN <iso> ###########" banner so multiple appends to the
# same .out file stay distinguishable.
#
# Usage from pwsh on the runner:
#   pwsh $HOME\Probe-And-Nuke-VcpkgState.ps1 >> $HOME\Nuke-File.out 2>&1
#
# Run it from an interactive shell (the runner's interactive user) NOT from a service
# context — the LOCALAPPDATA probe distinguishes interactive-user
# vs LOCAL SYSTEM profile by hard-coding both paths, but everything else
# uses absolute paths so it doesn't matter who runs it.

$ErrorActionPreference = 'Continue'  # keep going even if one path errors

$RunStart = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'

Write-Output ''
Write-Output ('########### Probe-And-Nuke-VcpkgState RUN ' + $RunStart + ' ###########')
Write-Output ''
Write-Output 'HOST: ' + $env:COMPUTERNAME
Write-Output 'PWSH: ' + $PSVersionTable.PSVersion.ToString()
Write-Output 'WHOAMI: ' + (whoami).Trim()
Write-Output ''

# --- Path inventory function -------------------------------------------------
function Probe-Path {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Note = ''
    )
    Write-Output '--- PATH ---'
    Write-Output ('PATH: ' + $Path)
    if ($Note) { Write-Output ('NOTE: ' + $Note) }

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Output 'EXISTS: no'
        return
    }

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    Write-Output 'EXISTS: yes'
    Write-Output ('IS_DIRECTORY: ' + [bool]($item.PSIsContainer))

    if ($item.PSIsContainer) {
        $allFiles = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue
        $count = ($allFiles | Measure-Object).Count
        $bytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $bytes) { $bytes = 0 }
        Write-Output ('FILE_COUNT: ' + $count)
        Write-Output ('TOTAL_BYTES: ' + $bytes)
        if ($count -gt 0) {
            $newest = $allFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-Output ('NEWEST_MTIME: ' + $newest.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ssK'))
            Write-Output ('NEWEST_FILE: ' + $newest.FullName)
        } else {
            Write-Output 'NEWEST_MTIME: NULL'
        }

        $topDirs = Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty Name |
                   Sort-Object
        if ($topDirs) {
            Write-Output ('SUBDIRS_TOP_LEVEL: ' + ($topDirs -join ','))
        } else {
            Write-Output 'SUBDIRS_TOP_LEVEL: NONE'
        }

        $topFiles = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name |
                    Sort-Object
        if ($topFiles) {
            Write-Output ('FILES_TOP_LEVEL: ' + ($topFiles -join ','))
        } else {
            Write-Output 'FILES_TOP_LEVEL: NONE'
        }
    } else {
        Write-Output ('FILE_BYTES: ' + $item.Length)
        Write-Output ('MTIME: ' + $item.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ssK'))
    }
}

# --- Nuke function -----------------------------------------------------------
function Nuke-Path {
    param([Parameter(Mandatory)][string] $Path)
    Write-Output ('NUKING: ' + $Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Output 'RESULT: NOT_FOUND'
        return
    }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Output 'RESULT: REMOVED'
    } catch {
        Write-Output ('RESULT: FAILED ' + $_.Exception.Message)
    }
}

# --- Path roster -------------------------------------------------------------
# Workspace state: project-local vcpkg artifacts under clean:false
$WorkspaceRoot = 'C:\actions-runner\_work\Yuzu\Yuzu'

# vcpkg tool dir (managed by lukka/run-vcpkg) and its substate
$VcpkgRoot = Join-Path $WorkspaceRoot 'vcpkg'

# Project-local manifest-mode install
$VcpkgInstalled    = Join-Path $WorkspaceRoot 'vcpkg_installed'
$VcpkgInstalledWin = Join-Path $VcpkgInstalled 'x64-windows'

# vcpkg's classic-mode dirs (may be populated even in manifest mode for some tools)
$VcpkgInstalledClassic = Join-Path $VcpkgRoot 'installed'
$VcpkgBuildtrees       = Join-Path $VcpkgRoot 'buildtrees'
$VcpkgPackages         = Join-Path $VcpkgRoot 'packages'
$VcpkgDownloads        = Join-Path $VcpkgRoot 'downloads'

# Runner-tool-cache binary cache (the one ci.yml's VCPKG_DEFAULT_BINARY_CACHE points at)
$BinaryCache = 'C:\actions-runner\_work\_tool\yuzu-vcpkg-binary-cache-windows'

# Sentinel files written by scripts/ci/vcpkg-triplet-sentinel.sh
$SentinelCurrent = Join-Path $VcpkgInstalled '.x64-windows-cachekey.sha256'
$SentinelLegacy  = Join-Path $VcpkgInstalled '.x64-windows-triplet.sha256'

# Default vcpkg user-archives cache locations (interactive user vs LOCAL SYSTEM)
$LocalAppdataUser        = Join-Path $env:USERPROFILE 'AppData\Local\vcpkg'
$LocalAppdataLocalSystem = 'C:\Windows\System32\config\systemprofile\AppData\Local\vcpkg'

$AllPaths = @(
    @{ Path = $VcpkgInstalled;          Note = 'project manifest-mode install root'; Nuke = $true  },
    @{ Path = $VcpkgInstalledWin;       Note = 'x64-windows tree (where .pc files live)'; Nuke = $true  },
    @{ Path = $SentinelCurrent;         Note = 'current cache-key sentinel'; Nuke = $true  },
    @{ Path = $SentinelLegacy;          Note = 'legacy triplet-only sentinel'; Nuke = $true  },
    @{ Path = $VcpkgRoot;               Note = 'vcpkg tool dir (DO NOT NUKE — would force re-clone)'; Nuke = $false },
    @{ Path = $VcpkgInstalledClassic;   Note = 'vcpkg classic-mode install (substate)'; Nuke = $true  },
    @{ Path = $VcpkgBuildtrees;         Note = 'port build state (substate)';          Nuke = $true  },
    @{ Path = $VcpkgPackages;           Note = 'pre-stage zips (substate)';             Nuke = $true  },
    @{ Path = $VcpkgDownloads;          Note = 'source tarballs (safe to keep, just slows next build)'; Nuke = $false },
    @{ Path = $BinaryCache;             Note = 'runner-tool-cache binary cache zips'; Nuke = $true  },
    @{ Path = $LocalAppdataUser;        Note = 'interactive-user vcpkg default cache (probably empty)'; Nuke = $true  },
    @{ Path = $LocalAppdataLocalSystem; Note = 'LOCAL SYSTEM vcpkg default cache (THIS IS THE INTERESTING ONE)'; Nuke = $true  }
)

# --- INVENTORY (BEFORE) ------------------------------------------------------
Write-Output '=== INVENTORY (BEFORE) ==='
foreach ($entry in $AllPaths) {
    Probe-Path -Path $entry.Path -Note $entry.Note
}
Write-Output ''

# --- Special probe: is the .pc file actually present? -----------------------
Write-Output '--- SPECIAL PROBE ---'
$PcPath = Join-Path $VcpkgInstalledWin 'lib\pkgconfig\absl_absl_check.pc'
Write-Output ('PROBE: absl_absl_check.pc')
Write-Output ('PROBE_PATH: ' + $PcPath)
if (Test-Path -LiteralPath $PcPath) {
    Write-Output 'PROBE_RESULT: PRESENT'
} else {
    Write-Output 'PROBE_RESULT: ABSENT'
}

# Also list everything in the pkgconfig dir if it exists, so we can see
# WHAT vcpkg has half-extracted there.
$PkgConfigDir = Join-Path $VcpkgInstalledWin 'lib\pkgconfig'
Write-Output ('PROBE: pkgconfig dir contents')
Write-Output ('PROBE_PATH: ' + $PkgConfigDir)
if (Test-Path -LiteralPath $PkgConfigDir) {
    $pcFiles = Get-ChildItem -LiteralPath $PkgConfigDir -File -Force -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty Name | Sort-Object
    Write-Output ('PROBE_RESULT: ' + ($pcFiles.Count) + ' files')
    foreach ($f in $pcFiles) { Write-Output ('  ' + $f) }
} else {
    Write-Output 'PROBE_RESULT: pkgconfig dir does not exist'
}

# Also check LOCAL SYSTEM's archive subdir specifically
$LSArchives = Join-Path $LocalAppdataLocalSystem 'archives'
Write-Output ('PROBE: LOCAL SYSTEM vcpkg archives')
Write-Output ('PROBE_PATH: ' + $LSArchives)
if (Test-Path -LiteralPath $LSArchives) {
    $zips = Get-ChildItem -LiteralPath $LSArchives -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*.zip' }
    Write-Output ('PROBE_RESULT: ' + ($zips | Measure-Object).Count + ' zips')
    $totalBytes = ($zips | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $totalBytes) { $totalBytes = 0 }
    Write-Output ('PROBE_TOTAL_BYTES: ' + $totalBytes)
} else {
    Write-Output 'PROBE_RESULT: archives dir does not exist'
}
Write-Output ''

# --- Disk free before --------------------------------------------------------
$diskBefore = Get-PSDrive -Name C | Select-Object -ExpandProperty Free
Write-Output ('DISK_FREE_BEFORE_BYTES: ' + $diskBefore)
Write-Output ''

# --- NUKE --------------------------------------------------------------------
Write-Output '=== NUKE ==='
foreach ($entry in $AllPaths) {
    if ($entry.Nuke) {
        Nuke-Path -Path $entry.Path
    } else {
        Write-Output ('SKIPPING: ' + $entry.Path + '  (preserved by policy)')
    }
}
Write-Output ''

# --- INVENTORY (AFTER) -------------------------------------------------------
Write-Output '=== INVENTORY (AFTER) ==='
foreach ($entry in $AllPaths) {
    if ($entry.Nuke) {
        Probe-Path -Path $entry.Path -Note $entry.Note
    }
}
Write-Output ''

# --- Disk free after ---------------------------------------------------------
$diskAfter = Get-PSDrive -Name C | Select-Object -ExpandProperty Free
Write-Output ('DISK_FREE_AFTER_BYTES: ' + $diskAfter)
Write-Output ('DISK_FREED_BYTES: ' + ($diskAfter - $diskBefore))
Write-Output ''

Write-Output '########### END ###########'
Write-Output ''
