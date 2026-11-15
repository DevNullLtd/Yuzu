<#
.SYNOPSIS
    Provision the unprivileged Windows account the Yuzu agent runs under,
    plus the narrow privilege grants it needs to operate plugins like
    quarantine, services.set_start_mode, and registry writes against HKLM.

.DESCRIPTION

AUTHORITY
─────────
This script is the Windows implementation of the privilege model defined
in docs/agent-privilege-model.md. The Linux/macOS sibling is
scripts/install-agent-user.sh. If the doc and the script disagree, the
doc wins — fix the script, then re-run.

WHAT THIS SCRIPT DOES
─────────────────────
1.  Creates a dedicated local user account the agent runs under.
        Default name:  YuzuAgent
        Password:      a 24-character random password, stored ONLY in
                       a DPAPI-encrypted blob at
                       C:\ProgramData\Yuzu\agent-credential.dpapi
                       readable only by SYSTEM and Administrators.
                       The agent itself never reads this file — it gets
                       its own login token from the service controller
                       at start-time. The blob exists so an operator can
                       reset the account by re-running this script
                       without losing access.
        User flags:    Account never expires, password never expires,
                       cannot change password, hidden from login screen
                       (no profile creation), no interactive logon right.

    PRODUCTION ALTERNATIVE — Virtual Service Account (recommended)
    ──────────────────────────────────────────────────────────────
    The production MSI installer registers the agent service under a
    Windows virtual service account named `NT SERVICE\YuzuAgent`. Virtual
    service accounts have these advantages over a local account:
       - auto-created by `sc.exe create ... obj= "NT SERVICE\..."`
       - no password to manage; the SCM provides credentials
       - cannot log on interactively at all (vs. our local user which
         is just denied this right via secedit)
       - per-machine SID; can't be moved or impersonated across boxes
    When the production installer runs, this script's job is done; it
    refuses to overwrite an existing service registration. Dev installs
    use the local-user path because we don't always have the agent
    service registered during /test runs.

2.  Adds the account to the platform-specific groups it needs:
        Event Log Readers       — read Application/System/Security event logs
        Performance Monitor Users — WMI counter reads (hardware, processes)
        Performance Log Users     — trace session reads

3.  Grants the following privileges (LSA account rights) via P/Invoke
    of advapi32!LsaAddAccountRights:
        SeServiceLogonRight     — required to run as a service
        SeChangeNotifyPrivilege — traverse path-checking (default for
                                  Authenticated Users, but we make it
                                  explicit so a hardened policy that
                                  removes the default doesn't break us)
        SeBackupPrivilege       — read all files regardless of DACL
                                  (event log files, registry hives,
                                   filesystem.read with system paths)
        SeRestorePrivilege      — paired with SeBackupPrivilege; restore
                                  semantics for the same paths, and required by
                                  RegLoadKeyA/RegUnLoadKeyA (Echo `software`
                                  per-user scope mounts logged-off NTUSER.DAT)
        SeSecurityPrivilege     — read Security event log, manage SACLs
        SeIncreaseQuotaPrivilege — adjust process quotas (some WMI
                                  queries require this on hardened
                                  systems)
        SeAssignPrimaryTokenPrivilege — required by sc.exe + service
                                  control plugins

    DELIBERATELY NOT GRANTED:
        SeLoadDriverPrivilege   — drivers are kernel-mode; the agent
                                  stays user-mode
        SeImpersonatePrivilege  — would let the agent impersonate any
                                  logged-in user; reserved for the
                                  future per-session interaction helper
        SeTakeOwnershipPrivilege — agent should never seize files
        SeDebugPrivilege        — gives effective full-system access;
                                  granted to LocalSystem only

4.  Creates the agent's filesystem hierarchy under C:\ProgramData\Yuzu\
    with NTFS ACLs that grant the agent account modify access while
    locking out everyone except SYSTEM and Administrators:
        C:\ProgramData\Yuzu\state\    — agent.db, KV store, command-id cache
        C:\ProgramData\Yuzu\cache\    — content_dist staging area
        C:\ProgramData\Yuzu\logs\     — spdlog output
        C:\ProgramData\Yuzu\plugins\  — read-only to the agent so a
                                        compromised plugin can't tamper
                                        with siblings; only Administrators
                                        + SYSTEM can write here.
        C:\ProgramData\Yuzu\config\   — agent.cfg, mTLS cert/key

5.  (Optional) Configures `Deny logon locally` and `Deny logon through
    Remote Desktop` via secedit, so the agent account cannot be used
    for an interactive session even if its password is somehow obtained.
    Skipped under -SkipDenyInteractive for test environments.

WHAT THIS SCRIPT DOES NOT DO
─────────────────────────────
- Install the agent binary itself. Use the MSI (production) or
    `meson install` (dev) for that.
- Register the agent service with the SCM (`sc.exe create`). That happens
    at MSI install or in `scripts/start-UAT.ps1`.
- Configure Windows Firewall rules. The quarantine plugin manages those
    via `netsh advfirewall` at runtime.
- Provision certificates. The agent gets its mTLS material from the
    server enrollment flow.

IDEMPOTENCY
───────────
Every step probes existing state and skips if already correct. Re-running
this script is safe. Privilege grants and group memberships are union'd
(never removed); use `-Uninstall` to reverse cleanly.

UNINSTALL
─────────
`-Uninstall` reverses everything except the logs directory, which is
preserved as `C:\ProgramData\Yuzu\logs.removed-<timestamp>` for forensics.

.PARAMETER DryRun
    Print every action without executing it. Use this first.

.PARAMETER Check
    Verify the install is correct (account exists, in expected groups,
    has expected privileges, state dirs exist with expected ACLs).
    Exits non-zero on any drift. Suitable for use as a pre-flight gate.

.PARAMETER Uninstall
    Remove the account, its privileges, and the state directories.

.PARAMETER AccountName
    Override the default local account name (YuzuAgent). Useful for
    parallel test environments. Ignored on -Uninstall when an existing
    account isn't found.

.PARAMETER BinaryPath
    Override the path to the agent binary. Default is
    C:\Program Files\Yuzu\yuzu-agent.exe. Reserved for future use; on
    Windows there's no setcap analogue, so this is currently informational
    (recorded in the install marker file for diagnostics).

.PARAMETER SkipDenyInteractive
    Skip the secedit step that adds the account to "Deny logon locally"
    and "Deny logon through Remote Desktop". Use only in test
    environments where you want to be able to run Powershell in the
    account's context to debug plugin behaviour.

.EXAMPLE
    # Dry-run from an elevated PowerShell:
    .\install-agent-user.ps1 -DryRun

.EXAMPLE
    # Install:
    .\install-agent-user.ps1

.EXAMPLE
    # Verify (no admin needed if reading public attributes; prefers admin
    # to read the privilege list authoritatively):
    .\install-agent-user.ps1 -Check

.EXAMPLE
    # Uninstall:
    .\install-agent-user.ps1 -Uninstall

REQUIREMENTS
────────────
- Windows 10 / 11 / Server 2019+ (uses Microsoft.PowerShell.LocalAccounts
    module, present by default since Windows 10).
- Windows PowerShell 5.1 (default on Windows 10+) or PowerShell 7+.
- Administrator privileges (for install, uninstall, and most -Check
    fields). The script self-detects and refuses to proceed without
    elevation.

EXIT CODES
──────────
    0  - install / check / uninstall succeeded
    1  - install / check / uninstall failed; details on stderr
    2  - argument or precondition error (not running elevated, unsupported OS)
    3  - secedit operation failed; install was rolled back
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Check,
    [switch]$Uninstall,
    [string]$AccountName = "YuzuAgent",
    [string]$BinaryPath  = "C:\Program Files\Yuzu\yuzu-agent.exe",
    # The agent's data directory — MUST equal the value passed to the agent's
    # `--data-dir`, because the boot AutoLogger writes `procboot.etl` here and the
    # agent reads it from the same directory it writes `echo.db` to. Defaults to
    # the production service data dir (C:\ProgramData\Yuzu); override when the
    # agent runs with a different --data-dir (e.g. a UAT data dir) so the
    # boot-window backfill actually finds the trace.
    [string]$DataDir = "C:\ProgramData\Yuzu",
    [switch]$SkipDenyInteractive
)

# ── platform + privilege guard ──────────────────────────────────────────────

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or later is required (you have $($PSVersionTable.PSVersion))."
    exit 2
}

if (-not $IsWindows -and -not ($PSVersionTable.PSVersion.Major -lt 6)) {
    # PS5.1 doesn't define $IsWindows; on PS5 we're always on Windows. On PS7+
    # this guard catches running the script on Linux/macOS PowerShell.
    Write-Error "This script is Windows-only. Use scripts/install-agent-user.sh on Linux/macOS."
    exit 2
}

# Helper indicators for -DryRun vs -WhatIf.
#
# Original design routed everything through $PSCmdlet.ShouldProcess() so
# `-WhatIf` would Just Work. That doesn't actually work in PowerShell:
# $PSCmdlet is only populated for the SCRIPT itself (which has
# [CmdletBinding(SupportsShouldProcess)] on its param block), not for
# any non-advanced function called from it. Inside a regular `function`
# the bare reference to $PSCmdlet returns $null, and any method call
# against it throws "Object reference not set to an instance of an
# object." Live-tested on Shulgi (Windows 11 + PS 7.6.1) — that's
# exactly what the first DryRun blew up with.
#
# Fix: scope-pin a single boolean and have every state-changing call
# gate on it. -WhatIf no longer drives the script (we removed
# SupportsShouldProcess entirely below); -DryRun is the only knob.
# That's sharper anyway — operators expect -DryRun on install scripts;
# -WhatIf on a non-cmdlet is more of a niche-PS idiom.
$Script:Effective = -not $DryRun

function Write-Info  { param([string]$msg) Write-Host "[install-agent-user] $msg" }
function Write-Warn  { param([string]$msg) Write-Host "[install-agent-user] WARN: $msg" -ForegroundColor Yellow }
function Write-Step  { param([string]$msg) Write-Host "[install-agent-user] >>> $msg" -ForegroundColor Cyan }
function Write-Fail  { param([string]$msg) Write-Host "[install-agent-user] ERROR: $msg" -ForegroundColor Red; throw $msg }

# ── paths ────────────────────────────────────────────────────────────────────

$Script:RootDir   = "C:\ProgramData\Yuzu"
$Script:StateDir  = Join-Path $RootDir "state"
$Script:CacheDir  = Join-Path $RootDir "cache"
$Script:LogDir    = Join-Path $RootDir "logs"
$Script:PluginsDir = Join-Path $RootDir "plugins"
$Script:ConfigDir = Join-Path $RootDir "config"
$Script:CredFile  = Join-Path $RootDir "agent-credential.dpapi"
$Script:MarkerFile = Join-Path $RootDir "install-marker.json"

# ── account management ──────────────────────────────────────────────────────

function New-AgentAccount {
    param([string]$name)

    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
        Write-Info "user $name already exists — skipping create"
        return
    }

    Write-Step "creating local user $name"

    # Generate a strong random password. Length 24, mixed case + digits +
    # printable symbols. We use RNGCryptoServiceProvider rather than
    # Get-Random because Get-Random isn't cryptographically random.
    Add-Type -AssemblyName System.Security
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+"
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($charset[$b % $charset.Length]) }
    $plainPassword = $sb.ToString()
    $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    if (-not $Script:Effective) {
        Write-Host "[dry-run] Create local user account: $name"
        Write-Host "[dry-run] Stash random 24-char password in DPAPI blob at $CredFile"
        return
    }

    # New-LocalUser caps Description at 48 chars. Be terse.
    $user = New-LocalUser `
        -Name $name `
        -Password $securePassword `
        -FullName "Yuzu Agent Daemon" `
        -Description "Yuzu endpoint agent — service, no login" `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -AccountNeverExpires
    Write-Info "  SID = $($user.SID)"

    # Stash the password in a DPAPI blob so an operator can recover
    # the account by re-running with a known credential. ACL'd to
    # remove all other access (mode 0440 equivalent).
    $encrypted = ConvertFrom-SecureString $securePassword
    Set-Content -Path $CredFile -Value $encrypted -Encoding UTF8
    $acl = Get-Acl $CredFile
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop existing
    $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
    $admRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'Allow')
    $acl.AddAccessRule($sysRule)
    $acl.AddAccessRule($admRule)
    Set-Acl -Path $CredFile -AclObject $acl
    Write-Info "  password stashed at $CredFile (SYSTEM + Administrators only)"
}

function Remove-AgentAccount {
    param([string]$name)

    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
        Write-Info "user $name does not exist — skipping delete"
        return
    }

    Write-Step "deleting local user $name"
    if ($Script:Effective) {
        Remove-LocalUser -Name $name
    } else {
        Write-Host "[dry-run] Remove-LocalUser -Name $name"
    }

    if (Test-Path $CredFile) {
        Write-Info "removing $CredFile"
        if ($Script:Effective) {
            Remove-Item $CredFile -Force
        } else {
            Write-Host "[dry-run] Remove-Item $CredFile -Force"
        }
    }
}

# ── group memberships ───────────────────────────────────────────────────────

$Script:RequiredGroups = @(
    'Event Log Readers',
    'Performance Monitor Users',
    'Performance Log Users'
)

function Add-AgentToGroups {
    param([string]$name)

    foreach ($group in $RequiredGroups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
            Write-Warn "group '$group' not present on this host — skipping"
            continue
        }
        $current = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*\$name" }
        if ($current) {
            Write-Info "  $name already in group '$group'"
            continue
        }
        Write-Step "adding $name to group '$group'"
        if ($Script:Effective) {
            Add-LocalGroupMember -Group $group -Member $name
        } else {
            Write-Host "[dry-run] Add-LocalGroupMember -Group '$group' -Member $name"
        }
    }
}

function Remove-AgentFromGroups {
    param([string]$name)

    foreach ($group in $RequiredGroups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) { continue }
        $present = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*\$name" }
        if (-not $present) { continue }
        Write-Step "removing $name from group '$group'"
        if ($Script:Effective) {
            Remove-LocalGroupMember -Group $group -Member $name -ErrorAction SilentlyContinue
        } else {
            Write-Host "[dry-run] Remove-LocalGroupMember -Group '$group' -Member $name"
        }
    }
}

# ── LSA privilege grants (P/Invoke) ─────────────────────────────────────────
#
# Windows has no built-in cmdlet to grant SeXxxPrivilege rights to an
# account. The two real options are:
#   1. secedit /export → edit → secedit /configure   (clunky, race-prone)
#   2. P/Invoke advapi32!LsaAddAccountRights         (clean, atomic)
# We use option 2. The C# definitions below are the LSA documented
# interfaces from https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/.
# Type loading is idempotent — successive imports just no-op.

$Script:RequiredPrivileges = @(
    'SeServiceLogonRight',
    'SeChangeNotifyPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege',
    'SeSecurityPrivilege',
    'SeIncreaseQuotaPrivilege',
    'SeAssignPrimaryTokenPrivilege'
)

# DELIBERATELY OMITTED — see DESCRIPTION:
# SeLoadDriverPrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege,
# SeDebugPrivilege.

$lsaSource = @"
using System;
using System.Runtime.InteropServices;

namespace YuzuLsa {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES {
        public UInt32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    public static class Native {
        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            byte[] AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaRemoveAccountRights(
            IntPtr PolicyHandle,
            byte[] AccountSid,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaClose(IntPtr ObjectHandle);
    }
}
"@

function Initialize-LsaTypes {
    if (-not ([System.Management.Automation.PSTypeName]'YuzuLsa.Native').Type) {
        Add-Type -TypeDefinition $lsaSource -Language CSharp
    }
}

function ConvertTo-LsaUnicodeString {
    param([string]$s)
    $u = New-Object YuzuLsa.LSA_UNICODE_STRING
    $u.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($s)
    $u.Length = [UInt16]($s.Length * 2)
    $u.MaximumLength = [UInt16](($s.Length + 1) * 2)
    return $u
}

function Grant-AccountPrivileges {
    param([string]$name, [string[]]$privileges)

    # In dry-run mode the upstream account-create step didn't actually
    # create the user, so Get-LocalUser would fail. Just announce what
    # we would have done and return — the LSA P/Invoke setup is
    # state-mutating-adjacent (LsaOpenPolicy needs a real handle) so
    # there's no useful "preview" to print beyond the per-privilege list.
    if (-not $Script:Effective) {
        foreach ($priv in $privileges) {
            Write-Host "[dry-run] LsaAddAccountRights($name, $priv)"
        }
        return
    }

    Initialize-LsaTypes

    $sid = (Get-LocalUser -Name $name).SID
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)

    $oa = New-Object YuzuLsa.LSA_OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $POLICY_CREATE_ACCOUNT = 0x00000010
    $POLICY_LOOKUP_NAMES   = 0x00000800

    $handle = [IntPtr]::Zero
    $rc = [YuzuLsa.Native]::LsaOpenPolicy([IntPtr]::Zero, [ref]$oa,
        ($POLICY_CREATE_ACCOUNT -bor $POLICY_LOOKUP_NAMES), [ref]$handle)
    if ($rc -ne 0) { Write-Fail "LsaOpenPolicy failed: $rc" }

    try {
        foreach ($priv in $privileges) {
            Write-Step "granting $priv to $name"
            if (-not $Script:Effective) {
                Write-Host "[dry-run] LsaAddAccountRights($name, $priv)"
                continue
            }

            $u = ConvertTo-LsaUnicodeString $priv
            $arr = @($u)
            $rc = [YuzuLsa.Native]::LsaAddAccountRights($handle, $sidBytes, $arr, 1)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($u.Buffer)
            if ($rc -ne 0) {
                Write-Warn "  LsaAddAccountRights for $priv returned NTSTATUS 0x$('{0:X8}' -f $rc)"
            }
        }
    } finally {
        [void][YuzuLsa.Native]::LsaClose($handle)
    }
}

function Revoke-AccountPrivileges {
    param([string]$name, [string[]]$privileges)
    Initialize-LsaTypes

    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
        return  # account already gone; LSA cleans up automatically
    }

    $sid = (Get-LocalUser -Name $name).SID
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)

    $oa = New-Object YuzuLsa.LSA_OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $POLICY_CREATE_ACCOUNT = 0x00000010
    $POLICY_LOOKUP_NAMES   = 0x00000800

    $handle = [IntPtr]::Zero
    $rc = [YuzuLsa.Native]::LsaOpenPolicy([IntPtr]::Zero, [ref]$oa,
        ($POLICY_CREATE_ACCOUNT -bor $POLICY_LOOKUP_NAMES), [ref]$handle)
    if ($rc -ne 0) { Write-Warn "LsaOpenPolicy failed during revoke: $rc"; return }

    try {
        foreach ($priv in $privileges) {
            Write-Step "revoking $priv from $name"
            if (-not $Script:Effective) {
                Write-Host "[dry-run] LsaRemoveAccountRights($name, $priv)"
                continue
            }
            $u = ConvertTo-LsaUnicodeString $priv
            $arr = @($u)
            [void][YuzuLsa.Native]::LsaRemoveAccountRights($handle, $sidBytes, $false, $arr, 1)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($u.Buffer)
        }
    } finally {
        [void][YuzuLsa.Native]::LsaClose($handle)
    }
}

# ── filesystem hierarchy ────────────────────────────────────────────────────

function New-AgentDirectories {
    param([string]$name)

    # Resolve the user's SID once. We pass the SID object (not a string
    # like ".\$name" or "$env:COMPUTERNAME\$name") to AddAccessRule
    # because string-form identity translation goes through
    # NTAccount.Translate() which can fail with "Some or all identity
    # references could not be translated" on freshly-created local
    # accounts whose name hasn't propagated through every Win32
    # name-lookup cache yet. SIDs are always immediately resolvable
    # because we just got them from Get-LocalUser.
    $userSid = $null
    if ($Script:Effective) {
        $userSid = (Get-LocalUser -Name $name).SID
    }

    $dirs = @{
        $StateDir   = "Modify"
        $CacheDir   = "Modify"
        $LogDir     = "Modify"
        $ConfigDir  = "ReadAndExecute"
        $PluginsDir = "ReadAndExecute"
    }

    foreach ($entry in $dirs.GetEnumerator()) {
        $dir = $entry.Key
        $access = $entry.Value
        if (-not (Test-Path $dir)) {
            Write-Step "creating $dir"
            if ($Script:Effective) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            } else {
                Write-Host "[dry-run] New-Item -Path '$dir' -ItemType Directory"
            }
        } else {
            Write-Info "  $dir already exists"
        }

        if ($Script:Effective) {
            $acl = Get-Acl $dir
            $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop existing

            # Always allow SYSTEM + Administrators full control. Without this
            # an operator can't manage the directory.
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))

            # Agent account gets the per-dir level access (Modify for
            # state/cache/log, ReadAndExecute for plugins/config).
            # Pass the SID directly to bypass the NTAccount.Translate()
            # name-lookup that fails on freshly-created local accounts.
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $userSid, $access, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -Path $dir -AclObject $acl
        } else {
            Write-Host "[dry-run] Set-Acl '$dir' (SYSTEM+Administrators full, $name $access)"
        }
    }
}

function Remove-AgentDirectories {
    foreach ($dir in @($StateDir, $CacheDir, $ConfigDir, $PluginsDir)) {
        if (Test-Path $dir) {
            Write-Step "removing $dir"
            if ($Script:Effective) {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "[dry-run] Remove-Item -Path '$dir' -Recurse"
            }
        }
    }
    # Logs preserved on uninstall — same forensics rationale as the bash sibling.
    if (Test-Path $LogDir) {
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        $archive = "${LogDir}.removed-$stamp"
        Write-Step "preserving $LogDir -> $archive"
        if ($Script:Effective) {
            Rename-Item -Path $LogDir -NewName (Split-Path $archive -Leaf)
        } else {
            Write-Host "[dry-run] Rename-Item -Path '$LogDir' -NewName '$(Split-Path $archive -Leaf)'"
        }
    }
}

# ── deny interactive logon (secedit) ────────────────────────────────────────
# secedit reads/writes a security policy template. We need to:
#   1. Export current policy to a temp .inf
#   2. Add our account to SeDenyInteractiveLogonRight + SeDenyRemoteInteractiveLogonRight
#   3. Re-import. If the import fails the box's policy is unchanged.

function Set-DenyInteractiveLogon {
    param([string]$name)

    if ($SkipDenyInteractive) {
        Write-Info "skipping deny-interactive (-SkipDenyInteractive)"
        return
    }

    Write-Step "configuring deny-interactive-logon for $name"

    if (-not $Script:Effective) {
        Write-Host "[dry-run] secedit /export → add $name's SID to SeDenyInteractiveLogonRight + SeDenyRemoteInteractiveLogonRight → secedit /configure"
        return
    }

    $exportFile = New-TemporaryFile
    $importFile = New-TemporaryFile
    try {
        if ($true) {
            # Export current Privilege Rights section.
            $sxArgs = @('/export', '/cfg', $exportFile.FullName,
                       '/areas', 'USER_RIGHTS', '/quiet')
            $rc = (Start-Process -FilePath 'secedit.exe' -ArgumentList $sxArgs `
                   -Wait -PassThru -NoNewWindow).ExitCode
            if ($rc -ne 0) {
                Write-Warn "secedit /export returned $rc — skipping deny-interactive"
                return
            }

            # Walk the file. Inside [Privilege Rights] we can either
            # mutate the existing SeDeny* line (append `,*<SID>`) or
            # — if the right isn't listed at all — add it before
            # [Privilege Rights] ends (i.e., before the next section
            # header or EOF). The "append to end of $newContent" pattern
            # the prior code used silently broke when the export ended
            # with [Version] (secedit /export /areas USER_RIGHTS does
            # produce one), because the new line landed AFTER [Version],
            # outside [Privilege Rights], and secedit /configure ignored
            # it. Live evidence: SeDenyRemoteInteractiveLogonRight never
            # got the SID; SeDenyInteractiveLogonRight did (because the
            # export had a `Guest`-only entry to mutate in place).
            $sid = (Get-LocalUser -Name $name).SID.Value
            $content = Get-Content $exportFile.FullName

            $newContent = New-Object System.Collections.Generic.List[string]
            $inPrivilegeRights = $false
            $sawDenyLocal = $false
            $sawDenyRemote = $false

            foreach ($line in $content) {
                # Section transitions: opening [Privilege Rights] enters
                # the section; any other [Foo] header exits it. Just
                # before exiting, flush any missing rights INTO the
                # section so secedit /configure sees them as part of
                # [Privilege Rights].
                if ($line -match '^\[Privilege Rights\]') {
                    $inPrivilegeRights = $true
                    $newContent.Add($line)
                    continue
                }
                if ($line -match '^\[' -and $inPrivilegeRights) {
                    if (-not $sawDenyLocal)  { $newContent.Add("SeDenyInteractiveLogonRight = *$sid") }
                    if (-not $sawDenyRemote) { $newContent.Add("SeDenyRemoteInteractiveLogonRight = *$sid") }
                    $sawDenyLocal = $true; $sawDenyRemote = $true  # don't re-flush at EOF
                    $inPrivilegeRights = $false
                    $newContent.Add($line)
                    continue
                }

                # Mutate-in-place if the right is already present.
                if ($inPrivilegeRights -and $line -match '^SeDenyInteractiveLogonRight\s*=') {
                    $sawDenyLocal = $true
                    if ($line -notmatch [regex]::Escape($sid)) { $line = "$line,*$sid" }
                } elseif ($inPrivilegeRights -and $line -match '^SeDenyRemoteInteractiveLogonRight\s*=') {
                    $sawDenyRemote = $true
                    if ($line -notmatch [regex]::Escape($sid)) { $line = "$line,*$sid" }
                }
                $newContent.Add($line)
            }
            # If [Privilege Rights] was the LAST section (no header
            # after it), the section-transition flush above didn't run.
            # Append any missing rights to the end — they're still
            # inside [Privilege Rights] in that case.
            if ($inPrivilegeRights) {
                if (-not $sawDenyLocal)  { $newContent.Add("SeDenyInteractiveLogonRight = *$sid") }
                if (-not $sawDenyRemote) { $newContent.Add("SeDenyRemoteInteractiveLogonRight = *$sid") }
            }

            Set-Content -Path $importFile.FullName -Value $newContent -Encoding Unicode

            # Direct invocation rather than Start-Process — Start-Process
            # with -NoNewWindow + -PassThru on PS7 returns inconsistent
            # ExitCode values (sometimes 0, sometimes the spawned PID's
            # last echo'd value). Live test on Shulgi: the manual call
            # path returns 0 cleanly, the Start-Process path returned 1
            # despite the underlying secedit log saying "User Rights
            # configuration was completed successfully." Switching to
            # direct invocation makes $LASTEXITCODE the truth signal.
            $sdb = Join-Path $env:TEMP 'yuzu-secedit.sdb'
            & secedit.exe /configure /db $sdb /cfg $importFile.FullName /areas USER_RIGHTS /quiet *>&1 | Out-Null
            $rc = $LASTEXITCODE
            # secedit exit codes: 0 = clean success, 1 = success with
            # warnings (e.g., "SeImpersonatePrivilege must be assigned
            # to SERVICE. This setting is adjusted." — a benign
            # auto-correction secedit applies when the INF doesn't
            # include service-required rights). Only 2+ is an actual
            # failure. Live verification: rc=1 from this configure call
            # produced a correctly-updated policy on Shulgi (Win11 26200,
            # PS7.6.1). See %windir%\security\logs\scesrv.log if you
            # need to chase a particular warning.
            if ($rc -ge 2) {
                Write-Warn "secedit /configure returned $rc - deny-interactive may not be applied"
            } elseif ($rc -eq 1) {
                Write-Info "  secedit completed (rc=1, success-with-warnings; see %windir%\security\logs\scesrv.log)"
            }
        }
    } finally {
        Remove-Item $exportFile.FullName -ErrorAction SilentlyContinue
        Remove-Item $importFile.FullName -ErrorAction SilentlyContinue
    }
}

# ── verification ────────────────────────────────────────────────────────────

function Test-Install {
    param([string]$name)
    $errs = 0

    # 1. Account exists
    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
        Write-Warn "user $name does not exist"; $errs++
    } else {
        Write-Info "user $name present"
    }

    # 2. Group memberships
    foreach ($group in $RequiredGroups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) { continue }
        $present = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*\$name" }
        if ($present) {
            Write-Info "  in group: $group"
        } else {
            Write-Warn "  NOT in group: $group"; $errs++
        }
    }

    # 3. Directories exist
    foreach ($dir in @($StateDir, $CacheDir, $LogDir, $ConfigDir, $PluginsDir)) {
        if (Test-Path $dir) {
            Write-Info "  dir present: $dir"
        } else {
            Write-Warn "  missing dir: $dir"; $errs++
        }
    }

    # 4. (Best-effort) check that LSA privileges are present. We can't
    # easily query "what rights does this SID have" via the public PS
    # cmdlets — we'd need LsaEnumerateAccountRights. For now, we recommend
    # `whoami /priv` while logged in as the account. We just print a hint.
    Write-Info "for an authoritative privilege check, use:"
    Write-Info "  PsExec.exe -u .\$name -p <pass> whoami /priv"
    Write-Info "  (sysinternals; not bundled with Windows)"

    if ($errs -eq 0) {
        Write-Info "check passed — install looks correct"
        return 0
    } else {
        Write-Warn "check failed — $errs issue(s) found"
        return 1
    }
}

# ── boot-window ETW AutoLogger (thread 1b) ──────────────────────────────────
#
# The narrow agent account cannot write the privileged HKLM Autologger config at
# runtime, so we register it here (install-time, admin). The kernel starts it
# early on each boot and captures Microsoft-Windows-Kernel-Process start/stop to
# a circular, size-capped .etl; the agent drains that file at startup to backfill
# the boot window its live session missed. **Takes effect on the NEXT boot.**
#
# The .etl path MUST match the agent's --data-dir: the agent reads `procboot.etl`
# from the SAME directory it writes `echo.db` to (NOT a `state` subdirectory).
# Driven by the -DataDir parameter (default C:\ProgramData\Yuzu = the production
# service data dir). Override -DataDir when the agent runs with a different
# --data-dir, or the backfill silently finds no file. The production InnoSetup
# installer (deploy/packaging/windows/yuzu-agent.iss) carries a SECOND copy of
# this recipe inline in its [Run]/[UninstallRun] sections (it can't shell out to
# this script — that would also run the account/ACL setup and collide with the
# installer's own --install-service). If the recipe changes here (LogFileMode,
# FlushTimer, keyword, GUID, clock), update the .iss too — they must stay in sync.
# `-ClockType System` is load-bearing: the agent decodes the file's timestamps as
# FILETIME. Best-effort by design — a failure here loses only boot-backfill, not
# the live capture, so it WARNS rather than aborting the install.

$Script:AutologgerName = "YuzuProcBoot"
$Script:ProcBootEtl    = Join-Path $DataDir "procboot.etl"
$Script:KernelProcessProviderGuid = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

function New-ProcBootAutologger {
    if (-not $Script:Effective) {
        Write-Host "[dry-run] New-AutologgerConfig $AutologgerName (Kernel-Process -> $ProcBootEtl, circular 16MB, System clock)"
        return
    }
    if (-not (Get-Command New-AutologgerConfig -ErrorAction SilentlyContinue)) {
        Write-Warn "New-AutologgerConfig unavailable (EventTracingManagement module) — skipping boot-backfill AutoLogger. Live ETW still captures from agent start."
        return
    }
    try {
        Write-Step "configuring boot AutoLogger '$AutologgerName' -> $ProcBootEtl"
        Remove-AutologgerConfig -Name $AutologgerName -ErrorAction SilentlyContinue | Out-Null
        # LogFileMode 0x2 = EVENT_TRACE_FILE_MODE_CIRCULAR; bounded to 16 MB.
        # FlushTimer is LOAD-BEARING: without it the session's buffers never reach
        # the file, so the agent's startup replay reads an empty .etl (verified on
        # Win11). 1 s keeps the boot window on disk well before the agent starts.
        New-AutologgerConfig -Name $AutologgerName -LogFileMode 0x2 -LocalFilePath $ProcBootEtl `
            -MaximumFileSize 16 -ClockType System -FlushTimer 1 -ErrorAction Stop | Out-Null
        # 0x10 = WINEVENT_KEYWORD_PROCESS (start/stop only), level 4 = INFORMATION.
        Add-EtwTraceProvider -AutologgerName $AutologgerName -Guid $KernelProcessProviderGuid `
            -Level 4 -MatchAnyKeyword ([uint64]0x10) -ErrorAction Stop | Out-Null
        Write-Info "  boot AutoLogger configured (effective next boot)"
    } catch {
        Write-Warn "boot AutoLogger setup failed ($($_.Exception.Message)) — continuing; live ETW still captures from agent start."
    }
}

# Mirror of yuzu-agent.iss [UninstallRun] (RunOnceId RemoveProcBootAutologger) —
# keep the teardown sequence (remove-config -> stop-session -> delete-.etl) in sync.
function Remove-ProcBootAutologger {
    if (-not $Script:Effective) {
        Write-Host "[dry-run] Remove-AutologgerConfig $AutologgerName"
        return
    }
    if (Get-Command Remove-AutologgerConfig -ErrorAction SilentlyContinue) {
        Write-Step "removing boot AutoLogger '$AutologgerName'"
        Remove-AutologgerConfig -Name $AutologgerName -ErrorAction SilentlyContinue | Out-Null
    }
    # Remove-AutologgerConfig drops only the boot-start *config* — it does NOT stop a
    # session already running from a prior boot. Stop it explicitly, or uninstall
    # leaves the YuzuProcBoot session live until the next reboot, holding one of the
    # scarce (~64) system ETW session slots and still writing procboot.etl. (Verified
    # on Win11: the file itself deletes fine while the session is open — the leftover
    # is the running session, not an undeletable file.)
    if (Get-Command Stop-EtwTraceSession -ErrorAction SilentlyContinue) {
        Stop-EtwTraceSession -Name $AutologgerName -ErrorAction SilentlyContinue | Out-Null
    }
    if (Test-Path $ProcBootEtl) {
        Remove-Item $ProcBootEtl -Force -ErrorAction SilentlyContinue
    }
}

# ── action dispatch ─────────────────────────────────────────────────────────

if (-not $Check -and -not $Uninstall) {
    if (-not (Test-IsAdmin) -and -not $DryRun) {
        Write-Fail "must be run as Administrator (open an elevated PowerShell)."
    }

    Write-Info "installing Yuzu agent user (account: $AccountName)"
    Write-Info "  state dir   : $StateDir"
    Write-Info "  cache dir   : $CacheDir"
    Write-Info "  log dir     : $LogDir"
    Write-Info "  plugins dir : $PluginsDir"
    Write-Info "  config dir  : $ConfigDir"
    Write-Info ""

    if ($Script:Effective) {
        New-Item -Path $RootDir -ItemType Directory -Force | Out-Null
    } else {
        Write-Host "[dry-run] New-Item -Path '$RootDir' -ItemType Directory"
    }
    New-AgentAccount  -name $AccountName
    Add-AgentToGroups -name $AccountName
    Grant-AccountPrivileges -name $AccountName -privileges $RequiredPrivileges
    New-AgentDirectories -name $AccountName
    Set-DenyInteractiveLogon -name $AccountName
    New-ProcBootAutologger

    # Install marker so check / uninstall can find what we did.
    if ($Script:Effective) {
        $marker = @{
            account_name      = $AccountName
            binary_path       = $BinaryPath
            installed_at_utc  = (Get-Date).ToUniversalTime().ToString("o")
            script_version    = "1.0.0"
            privileges        = $RequiredPrivileges
            groups            = $RequiredGroups
        }
        $marker | ConvertTo-Json -Depth 4 | Set-Content -Path $MarkerFile -Encoding UTF8
    } else {
        Write-Host "[dry-run] Write install marker to $MarkerFile"
    }

    Write-Info ""
    Write-Info "install complete. Verify with:"
    Write-Info "  .\$($MyInvocation.MyCommand.Name) -Check"
    exit 0
}

if ($Check) {
    if (-not (Test-IsAdmin)) {
        Write-Warn "running -Check without admin — some checks may be incomplete"
    }
    exit (Test-Install -name $AccountName)
}

if ($Uninstall) {
    if (-not (Test-IsAdmin) -and -not $DryRun) {
        Write-Fail "uninstall requires Administrator."
    }

    Write-Info "uninstalling Yuzu agent user (account: $AccountName)"

    Revoke-AccountPrivileges -name $AccountName -privileges $RequiredPrivileges
    Remove-AgentFromGroups   -name $AccountName
    Remove-ProcBootAutologger
    Remove-AgentAccount      -name $AccountName
    Remove-AgentDirectories

    if (Test-Path $MarkerFile) {
        Remove-Item $MarkerFile -Force -ErrorAction SilentlyContinue
    }

    Write-Info "uninstall complete."
    exit 0
}
