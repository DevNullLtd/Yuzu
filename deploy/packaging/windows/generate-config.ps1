# generate-config.ps1 - Generate yuzu-server.cfg with PBKDF2-SHA256 hashed credentials
#
# Run by the Windows server installer (yuzu-server.iss, PrepareToInstall), only
# ever into a directory the installer has locked to Administrators and SYSTEM and
# verified (#5196/#5210). The file is created inside that directory and inherits
# its permissions; the installer verifies the whole tree afterwards.
#
# Usage (as the installer runs it):
#   $env:YUZU_SETUP_ADMIN_USER / $env:YUZU_SETUP_ADMIN_PASS          (required)
#   $env:YUZU_SETUP_OPERATOR_USER / $env:YUZU_SETUP_OPERATOR_PASS    (optional pair)
#   the installer reads this file as text and runs it as a script block, with
#   -ConfigPath "<locked dir>\yuzu-server.cfg" -ReasonPath "<file>"
#
# Credentials come from the environment, not the command line: a password
# containing a double quote broke the old -AdminPass "..." quoting, and a
# command line is visible to process listings while the step runs (#5196).
#
# FAILS CLOSED. Any error exits non-zero and, when -ReasonPath is given, writes
# a one-line reason there for the installer to show and log. Nothing here may
# turn a failure into a warning: a config written but left readable, or not
# written at all, must stop the install (#5196).
#
# Windows PowerShell 5.1 (.NET Framework 4.7.2+). ASCII only outside comments:
# 5.1 reads a BOM-less script in the ANSI code page (docs/windows-build.md).
#
# NEEDS FULL LANGUAGE MODE. Hashing (Rfc2898DeriveBytes) is .NET, which
# Constrained Language Mode refuses (WDAC script enforcement, or AppLocker
# script rules for an install run by an administrator rather than SYSTEM). The
# installer checks the language mode BEFORE loading this script and stops with
# its own message; a credential-less upgrade never runs this script at all.
#
# FRESH INSTALLS ONLY, in effect: the file it writes only SEEDS the first
# administrator into an empty auth database (#5274), so the installer refuses
# a password on an upgrade (exit code 11) and never runs this script then. The
# operator entry is not provisioned on a PostgreSQL auth store today (#5343).

param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$ReasonPath = ""
)

# First statement, so that nothing below can fail silently: without it a .NET
# Framework older than 4.7.2 (no Rfc2898DeriveBytes hash-algorithm overload)
# wrote an empty hash and still exited 0.
$ErrorActionPreference = 'Stop'

# Use Windows PowerShell's own modules, then the machine-wide path (#5176). Built without any cmdlet, so
# nothing here depends on the path it is fixing.
$env:PSModulePath = $PSHOME + '\Modules;' + [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')

function Fail([string]$Message) {
    if ($ReasonPath) {
        try { [System.IO.File]::WriteAllText($ReasonPath, $Message) } catch { }
    }
    [Console]::Error.WriteLine("generate-config: $Message")
    exit 3
}

function Test-Username([string]$Name, [string]$What) {
    if ([string]::IsNullOrEmpty($Name)) { Fail "$What username is empty" }
    # The config format is username:role:salt:hash, one entry per line.
    if ($Name -match '[:\x00-\x1f\x7f]') { Fail "$What username may not contain ':' or control characters" }
}

# The server's password policy (server/core/src/password_policy.hpp) caps a
# password at 1024 BYTES of UTF-8 -- what PBKDF2 hashes, and what
# Rfc2898DeriveBytes(string, ...) encodes the string as. .Length counts UTF-16
# code units, so the maximum is measured on the encoded bytes. The minimum stays
# 12 characters (never fewer than 12 bytes, so never below the server's minimum).
function Test-Password([string]$Password, [string]$What) {
    if ([string]::IsNullOrEmpty($Password) -or $Password.Length -lt 12) { Fail "$What password must be at least 12 characters" }
    if ([System.Text.Encoding]::UTF8.GetByteCount($Password) -gt 1024) { Fail "$What password must be at most 1024 bytes as UTF-8" }
}

function New-PBKDF2Entry([string]$Username, [string]$Password, [string]$Role) {
    $salt = [byte[]]::new(16)
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($salt) } finally { $rng.Dispose() }

    # PBKDF2-SHA256, 100000 iterations, 32-byte output (matches server auth.cpp)
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Password, $salt, 100000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $hash = $pbkdf2.GetBytes(32) } finally { $pbkdf2.Dispose() }
    if ($null -eq $hash -or $hash.Length -ne 32) { Fail 'password hashing produced no output' }

    $saltHex = -join ($salt | ForEach-Object { $_.ToString('x2') })
    $hashHex = -join ($hash | ForEach-Object { $_.ToString('x2') })
    return "${Username}:${Role}:${saltHex}:${hashHex}"
}

$tmp = $null
try {
    $adminUser = $env:YUZU_SETUP_ADMIN_USER
    $adminPass = $env:YUZU_SETUP_ADMIN_PASS
    $opUser = $env:YUZU_SETUP_OPERATOR_USER
    $opPass = $env:YUZU_SETUP_OPERATOR_PASS

    Test-Username $adminUser 'admin'
    Test-Password $adminPass 'admin'

    $lines = @(
        '# Yuzu Server Configuration',
        '# Version: 1',
        '# Format: username:role:salt:hash',
        '# Generated by Yuzu Server installer',
        ''
    )
    $lines += New-PBKDF2Entry $adminUser $adminPass 'admin'

    if (-not [string]::IsNullOrEmpty($opUser)) {
        Test-Username $opUser 'operator'
        if ($opUser -eq $adminUser) { Fail 'operator username must differ from the admin username' }
        Test-Password $opPass 'operator'
        $lines += New-PBKDF2Entry $opUser $opPass 'user'
    }

    $dir = [System.IO.Path]::GetDirectoryName($ConfigPath)
    if (-not [System.IO.Directory]::Exists($dir)) { Fail "the data directory does not exist: $dir" }

    # Create the new file under a fresh name, unshared, in the locked
    # directory, so it inherits exactly Administrators and SYSTEM and nobody
    # else can open it. No explicit security descriptor: a protected per-file
    # DACL would fail the installer's tree check, which requires every
    # descendant to inherit. Then swap it in under the real name: anyone still
    # holding a handle to an old file keeps the old file.
    $tmp = [System.IO.Path]::Combine($dir, '.yuzu-server.cfg.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($lines -join "`r`n") + "`r`n")
    $stream = New-Object System.IO.FileStream($tmp, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None,
        4096, [System.IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }

    if ([System.IO.File]::Exists($ConfigPath)) {
        # [NullString]::Value, not $null: PowerShell turns $null into "" for a
        # .NET string parameter, and "" is not a legal backup path. Replace keeps
        # the REPLACED file's permissions, so the installer resets the file to
        # inherit afterwards (icacls /reset /L) and then verifies it.
        [System.IO.File]::Replace($tmp, $ConfigPath, [NullString]::Value)
    } else {
        [System.IO.File]::Move($tmp, $ConfigPath)
    }
    $tmp = $null

    # Its permissions are verified by the installer's tree check, not here.
    if ((Get-Item -LiteralPath $ConfigPath).Length -ne $bytes.Length) { Fail 'the configuration file was not written completely' }
} catch {
    Fail ('the configuration could not be written: ' + $_.Exception.Message)
} finally {
    if ($tmp -and [System.IO.File]::Exists($tmp)) {
        try { [System.IO.File]::Delete($tmp) } catch { }
    }
}

Write-Host "Configuration written to: $ConfigPath"
exit 0
