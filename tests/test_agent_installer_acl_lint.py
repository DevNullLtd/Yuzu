#!/usr/bin/env python3
r"""Regression net for the Windows agent installer's trust-anchor lockdown (#5196).

The .iss is compiled only by release.yml, never on a PR, so a regression in
SecureTrustAnchorDir would first be seen in a release build. These checks read
the source text; stdlib only, no Windows, no Inno Setup.

What they pin, each verified on Windows Server 2022:

- Nothing recurses (#5255 review). No takeown carries /R (or /D, which only
  matters with /R), no icacls carries /T, and every icacls carries /L, in the
  installer and in the manual procedure. A recursive takeown/icacls follows a
  junction a local user planted in the directory, out of it. /T on the GRANT
  was also the #5196 bug: (OI)(CI) is invalid on a file, and `icacls /T` gave
  every existing file an empty protected DACL, locking SYSTEM out of the
  operator's update-trust-bundle.pem while reporting success.
- The installer never takes over a directory it did not secure: a reparse
  point at the root is refused BEFORE its first command, and an existing
  directory must already pass the root-only check BEFORE ForceDirectories /
  the lock. After the directory-level lock, a fail-closed root-only check must
  pass BEFORE the contents check, and the contents check (only plain files; a
  newly created directory empty) BEFORE the file-level steps. The verification
  script and the manual check the reparse (1024) and directory (16) attributes
  and never use -Recurse; the manual is one `& { }` block that throws at its
  checks, so a failed check (or a broken paste) runs nothing after it.
- The verification script must make no .NET method or static call. Under WDAC /
  AppLocker, PowerShell runs in Constrained Language Mode, which refuses them,
  and the rc1..rc5 check (GetOwner/Translate) aborted every install there.
- The verification compares the SDDL exactly, and the user manual's copy uses
  the same expressions, so the two cannot drift apart again.
- PsLit doubles every character PowerShell treats as a single quote.
- The script contains no double quote, which would end the -Command argument.
- The abort messages of both installers (agent and server) say `sc.exe`: in
  Windows PowerShell 5.1 `sc` is an alias for Set-Content, so `sc start
  YuzuAgent` would silently write a file. No string literal in either [Code]
  section tells an operator to run a bare `sc start|stop|query|config|qc|delete`.
- Every Exec names its program by path ({sys}\...), never a bare `sc.exe` /
  `cmd.exe` / `find.exe`, which Windows looks up on a search path that includes
  Setup's own directory.
- An installation that took down a running agent and then did not complete
  starts it again (#5250): PrepareToInstall reads the service state before the
  stop and records a service that was RUNNING or START_PENDING (or that
  accepted the stop); the flag is only ever SET, so a second PrepareToInstall
  pass (Back from the Restart Manager page) cannot clear it. ssPostInstall
  records completion, and DeinitializeSetup, only when the first is set and the
  second is not, waits for a pending stop to finish, runs sc.exe start
  YuzuAgent, waits to observe the state, and logs "started again" ONLY under an
  observed RUNNING -- never on sc.exe's exit code (1056 comes back from a
  service that is still STOP_PENDING). An Exec that could not run is never
  logged as an sc.exe exit code. Every abort raised after the installer tried
  to secure the directory says what that attempt left there (a non-empty
  Outcome). These checks read the [Code] text with its comments removed, so a
  commented-out call does not satisfy them.
- No line in either [Code] section starts (after blanks) with `[` or `#`, and
  none contains `{#` or ends in ` \`. Inno reads a line starting with `[` as a
  section header even inside a { } comment -- efc4f162c failed to compile with
  "Invalid section tag" for a comment line starting with `[Run]`, and a comment
  line that is exactly `[Run]` would silently move the code after it into
  [Run]. A line starting with `#` is an ISPP directive, `{#` is ISPP inline
  expansion, and a trailing ` \` is ISPP line spanning.

Each check also runs against a mutated copy of the source and must fail there,
so a check that has stopped matching anything cannot pass silently.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ISS = ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss"
SERVER_ISS = ROOT / "deploy" / "packaging" / "windows" / "yuzu-server.iss"
MANUAL = ROOT / "docs" / "user-manual" / "server-admin.md"

ROOT_ACES = r"\(A;OICI;FA;;;(SY|BA)\)\(A;OICI;FA;;;(SY|BA)\)$"
CHILD_ACES = r"\(A;(?:OICI)?ID;FA;;;(SY|BA)\)\(A;(?:OICI)?ID;FA;;;(SY|BA)\)$"


def pascal_script(iss: str) -> str:
    """Evaluate the `Script := '...' + PsLit(..) + ...;` expression to the
    PowerShell text the installer passes to -Command."""
    start = iss.index("Script :=") + len("Script :=")
    end = iss.index("'exit 0';", start) + len("'exit 0'")
    expr, out, i = iss[start:end], [], 0
    while i < len(expr):
        c = expr[i]
        if c == "'":
            j, buf = i + 1, []
            while True:
                if expr[j] == "'":
                    if j + 1 < len(expr) and expr[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(expr[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        elif expr.startswith("PsLit(", i):
            close = expr.index(")", i)
            out.append("'<" + expr[i + 6:close] + ">'")
            i = close + 1
        elif c in " +\r\n\t":
            i += 1
        else:
            raise ValueError(f"unexpected {c!r} in Script expression: {expr[i:i + 40]!r}")
    return "".join(out)


def secure_fn(iss: str) -> str:
    a = iss.index("function SecureTrustAnchorDir(): string;")
    return iss[a:iss.index("\nend;", a)]


def exec_args(iss: str, tool: str) -> list:
    """The argument expression of every Exec of {sys}\\<tool>.exe in SecureTrustAnchorDir."""
    pat = r"Exec\(ExpandConstant\('\{sys\}\\" + tool + r"\.exe'\),\s*(.*?),\s*'', SW_HIDE"
    return re.findall(pat, secure_fn(iss), re.S)


def grant_exec_args(iss: str) -> str:
    m = re.search(r"'\"' \+ (?:CertDir|Stage) \+ '\" /inheritance:r /grant:r ' \+\s*'([^']*)'", iss)
    if not m:
        raise AssertionError("the icacls /inheritance:r /grant:r Exec was not found")
    return m.group(1)


def manual_block(md: str) -> str:
    a = md.index("& {\n    $ErrorActionPreference = 'Stop'\n    $d = 'C:\\ProgramData\\Yuzu\\agent-certs'")
    return md[a:md.index("```", a)]


def manual_commands(md: str, tool: str) -> list:
    lines = []
    for l in manual_block(md).splitlines():
        l = re.sub(r"^\s*if \([^)]*\) \{", "", l)
        for part in l.split(";"):
            part = part.strip().rstrip("}").strip()
            if part.startswith(tool + " "):
                lines.append(part)
    return lines


def manual_grant_line(md: str) -> str:
    lines = [l for l in manual_commands(md, "icacls") if "/grant:r" in l]
    if len(lines) != 1:
        raise AssertionError(f"expected one manual grant line, found {len(lines)}")
    return lines[0]


def manual_verify(md: str) -> str:
    block = manual_block(md)
    return block[block.index("foreach ($i in @(Get-Item"):]


def pslit_body(iss: str) -> str:
    a = iss.index("function PsLit(")
    return iss[a:iss.index("end;", a)]


def code_section(iss: str) -> str:
    """The [Code] section's raw text (everything after the `[Code]` line)."""
    m = re.search(r"^\[Code\][ \t]*\r?$", iss, re.M)
    if not m:
        raise AssertionError("no [Code] section")
    return iss[m.end():]


def strip_pascal_comments(code: str) -> str:
    """Pascal source with { }, (* *) and // comments removed, string literals
    kept intact (a brace inside a string, such as '{sys}', is not a comment)."""
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c == "'":
            j = i + 1
            while j < n:
                if code[j] == "'":
                    if j + 1 < n and code[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            out.append(code[i:j + 1])
            i = j + 1
        elif c == "{":
            j = code.find("}", i)
            i = n if j < 0 else j + 1
            out.append(" ")
        elif code.startswith("(*", i):
            j = code.find("*)", i)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif code.startswith("//", i):
            j = code.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def routine(code: str, header: str) -> str:
    """The text of one routine, from its header to its closing `end;`."""
    a = code.find(header)
    if a < 0:
        return ""
    return code[a:code.find("\nend;", a)]


def section_tag_problems(name: str, iss: str) -> list:
    found = []
    for n, line in enumerate(code_section(iss).splitlines(), 1):
        s = line.strip()
        if s[:1] in ("[", "#"):
            found.append(f"{name} [Code] line {n} starts with {s[:1]!r} (Inno section tag / ISPP directive): {s[:60]}")
        if "{#" in line:
            found.append(f"{name} [Code] line {n} contains '{{#' (ISPP inline expansion): {s[:60]}")
        if line.rstrip("\r").endswith(" \\"):
            found.append(f"{name} [Code] line {n} ends with ' \\' (ISPP line spanning): {s[:60]}")
    return found


def bare_sc_problems(name: str, iss: str) -> list:
    found = []
    if re.search(r"(?i)\bsc\s+start\b", iss):
        found.append(f"{name}: an abort message says `sc start`, which is Set-Content in Windows PowerShell 5.1; use sc.exe")
    for lit in re.findall(r"'(?:[^'\n]|'')*'", strip_pascal_comments(code_section(iss))):
        if re.search(r"(?i)(?<![\w.\\])sc\s+(start|stop|query|config|qc|delete)\b", lit):
            found.append(f"{name}: a [Code] string tells the operator to run a bare `sc` (Set-Content in PowerShell 5.1): {lit[:80]}")
    if re.search(r"Exec\('(?:sc|cmd|find|powershell|icacls)\.exe'", iss):
        found.append(f"{name}: an Exec names its program without a path; use ExpandConstant('{{sys}}\\...')")
    return found


def in_order(body: str, *needles) -> bool:
    pos = -1
    for n in needles:
        nxt = body.find(n, pos + 1)
        if nxt < 0:
            return False
        pos = nxt
    return True


def problems(iss: str, md: str, server: str = "") -> list:
    found = []
    code = re.sub(r"\{[^}]*\}|\(\*.*?\*\)|//[^\n]*|^;[^\n]*", "", iss, flags=re.S | re.M)
    if re.search(r"(?i)takeown", code) or re.search(r"(?i)takeown", pascal_script(iss)):
        found.append("the installer runs takeown, which has no /L and may act on a link's target")
    if not any("Stage" in a and "/setowner *S-1-5-32-544" in a for a in exec_args(iss, "icacls")):
        found.append("the installer no longer sets the new directory's owner with icacls /setowner")
    if any(re.search(r"CertDir \+ '\" /(setowner|inheritance:r|reset)", a) for a in exec_args(iss, "icacls")):
        found.append("the installer re-locks agent-certs in place instead of preparing a new one elsewhere")
    for args in exec_args(iss, "icacls"):
        if re.search(r"/T\b", args):
            found.append(f"installer icacls recurses (/T): {args}")
        if not re.search(r"/L\b", args):
            found.append(f"installer icacls lacks /L: {args}")
    if manual_commands(md, "takeown"):
        found.append("the manual procedure runs takeown")
    for line in manual_commands(md, "icacls"):
        if re.search(r"\s/T\b", line):
            found.append(f"manual icacls recurses: {line}")
        if not re.search(r"\s/L\b", line):
            found.append(f"manual icacls lacks /L: {line}")
    body = secure_fn(iss)
    first_exec = body.index("Exec(")
    root_check = body.find("IsReparsePoint(CertDir")
    if root_check < 0 or root_check > first_exec:
        found.append("the root reparse-point check does not run before the first command")
    def seq(*needles):
        pos = -1
        for n in needles:
            nxt = body.find(n, pos + 1)
            if nxt < 0:
                return False
            pos = nxt
        return True
    if not seq("RunAclCheck(CertDir, 'root')", "if Existed then", "NotFilesOnly(CertDir, False)",
               "RunAclCheck(CertDir, 'files')", "CertDir + '\\*\" /reset"):
        found.append("an existing directory is not checked (secured, plain files, owned) before its files are reset")
    if not seq("ForceDirectories(Stage)", "Stage + '\" /inheritance:r /grant:r", "RunAclCheck(Stage, 'root')",
               "NotFilesOnly(Stage, True)", "RenameFile(Stage, CertDir)", "RunAclCheck(CertDir, 'root')",
               "NotFilesOnly(CertDir, True)", "RunAclCheck(CertDir, 'full')"):
        found.append("a new directory is not prepared, checked, moved and re-checked in that order")
    prep = iss[iss.index("function PrepareToInstall("):]
    if not (0 <= prep.find("SecureTrustAnchorDir()") < prep.find("'stop YuzuAgent'")):
        found.append("the trust-anchor check no longer runs before the service is stopped")
    script = pascal_script(iss)
    if '"' in script:
        found.append("Script contains a double quote")
    if "::" in script:
        found.append("Script makes a .NET static call (refused in Constrained Language Mode)")
    calls = re.findall(r"\.[A-Za-z_]\w*\(", script)
    if calls:
        found.append(f"Script makes .NET method calls {calls} (refused in Constrained Language Mode)")
    if "-Recurse" in script:
        found.append("Script uses -Recurse")
    for needle, why in (("if($i.LinkType -eq 'HardLink')", "hard-link check"),
                        ("if($m -eq 'files')", "file-ownership gate"),
                        ("if(($r.Attributes -band 1024) -ne 0)", "root reparse-point check"),
                        ("if(($i.Attributes -band 1024) -ne 0)", "child reparse-point check"),
                        ("if(($i.Attributes -band 16) -ne 0)", "child subdirectory check"),
                        ("'^O:(BA|SY)G:'", "owner check"),
                        ("if($f -notmatch 'P')", "protected-root check"),
                        ("'^" + ROOT_ACES + "'", "exact root ACE set"),
                        ("'^" + CHILD_ACES + "'", "exact child ACE set"),
                        ("($Matches[1] -eq $Matches[2])", "two distinct accounts")):
        if needle not in script:
            found.append(f"Script lost its {why}: {needle}")
    code = [l for l in manual_block(md).splitlines() if not l.lstrip().startswith("#")]
    if any("-Recurse" in l for l in code):
        found.append("manual procedure uses -Recurse")
    block = manual_block(md)
    lock_fn = block[block.index("function Test-Locked"):block.index("if (Test-Path -LiteralPath $d) {")]
    if "($s -match 'D:P[A-Z]*" + ROOT_ACES + "') -and ($Matches[1] -ne $Matches[2])" not in lock_fn or "-band 1024" not in lock_fn:
        found.append("manual Test-Locked no longer checks the exact root ACE set and the reparse attribute")
    for needle, why in (("if (-not (Test-Locked $d)) { throw", "refusal of an existing unsecured directory"),
                        ("if (-not (Test-Locked $stage)) { throw", "lock gate on the prepared directory"),
                        ("if ($bad) { throw", "files-only check"),
                        ("if (Test-Path -LiteralPath $d) { throw", "check that nothing took the name before the move"),
                        ("if (-not (Test-Locked $d) -or @(Get-ChildItem -LiteralPath $d -Force)) { throw", "re-check after the move"),
                        ("if ($i.LinkType -eq 'HardLink') { throw", "hard-link check"),
                        ("-notmatch '^O:(BA|SY)G:') { throw", "file-ownership check")):
        if needle not in manual_block(md):
            found.append(f"manual procedure lost its {why}")
    verify = manual_verify(md)
    for needle, why in (("($i.Attributes -band 1024) -ne 0", "reparse-point check"),
                        ("($i.Attributes -band 16) -ne 0", "subdirectory check"),
                        ("'^O:(BA|SY)G:'", "owner check"),
                        ("'D:P[A-Z]*" + ROOT_ACES + "'", "exact root ACE set"),
                        ("'D:[A-Z]*" + CHILD_ACES + "'", "exact child ACE set"),
                        ("($Matches[1] -ne $Matches[2])", "two distinct accounts")):
        if needle not in verify:
            found.append(f"manual verify lost its {why}: {needle}")
    pas = strip_pascal_comments(code_section(iss))
    prep5250 = routine(pas, "function PrepareToInstall(")
    if not in_order(prep5250, "PriorState := AgentServiceState();", "'stop YuzuAgent'",
                    "StoppedRunningService := True;"):
        found.append("PrepareToInstall no longer reads the service state before the stop and records a service it took down (#5250)")
    flag_if = re.search(r"\bif\b((?:(?!\bif\b).)*?)\bthen\s*StoppedRunningService := True;", prep5250, re.S)
    if not flag_if or "(PriorState = 'RUNNING')" not in flag_if.group(1) \
            or "(PriorState = 'START_PENDING')" not in flag_if.group(1):
        found.append("PrepareToInstall no longer counts a RUNNING or START_PENDING service as one it took down (sc.exe stop gives 1061/1053 there) (#5250)")
    if re.search(r"StoppedRunningService\s*:=(?!\s*True\s*;)", pas):
        found.append("StoppedRunningService is assigned something other than True: a second PrepareToInstall pass would clear it (#5250)")
    if "if AgentStateIs('STOPPED') then" not in routine(pas, "function AgentServiceState("):
        found.append("AgentServiceState no longer reads the STOPPED state (#5250)")
    step = pas.find("procedure CurStepChanged(")
    if step < 0 or not re.search(r"if CurStep = ssPostInstall then\s+InstallCompleted := True;", pas[step:pas.find("\nend;", step)]):
        found.append("ssPostInstall no longer records that the installation completed (#5250)")
    body5250 = routine(pas, "procedure DeinitializeSetup(")
    start_exec = "Exec(ExpandConstant('{sys}\\sc.exe'), 'start YuzuAgent'"
    if not in_order(body5250, "if StoppedRunningService and not InstallCompleted then", start_exec):
        found.append("DeinitializeSetup no longer starts a service this run stopped when the installation did not complete (#5250)")
    if not in_order(body5250, "if StoppedRunningService and not InstallCompleted then",
                    "while ((State = 'STOP_PENDING') or (State = 'START_PENDING'))", "AgentServiceState()",
                    start_exec, "AgentServiceState()"):
        found.append("DeinitializeSetup no longer waits for a pending stop before sc.exe start and reads the state after it (#5250)")
    waits = re.search(r"\(I < (\d+)\)", body5250)
    if not waits or int(waits.group(1)) < 30:
        found.append("DeinitializeSetup waits less than 30s for a pending stop to finish before sc.exe start (#5250)")
    after = re.search(r"for I := 1 to (\d+) do\s+begin\s+State := AgentServiceState\(\);", body5250[body5250.find(start_exec):] if start_exec in body5250 else "")
    if not after or int(after.group(1)) < 5:
        found.append("DeinitializeSetup no longer polls (>=5s) for RUNNING after sc.exe start (#5250)")
    said = body5250.find("has been started again")
    guard = body5250.rfind("if State = 'RUNNING' then", 0, said) if said >= 0 else -1
    if said < 0 or guard < 0 or re.search(r"\b(else|end)\b", body5250[guard + len("if State = 'RUNNING' then"):said]):
        found.append("DeinitializeSetup says the service was started again without having observed it RUNNING (#5250)")
    if re.search(r"\b1056\b", body5250):
        found.append("DeinitializeSetup treats sc.exe's 1056 as the service running; 1056 also comes back from a STOP_PENDING service (#5250)")
    if "ScOutcome(StartRan, StartCode)" not in body5250[said:] if said >= 0 else True:
        found.append("DeinitializeSetup's failure line no longer separates 'sc.exe could not run' from an sc.exe exit code (#5250)")
    sco = routine(pas, "function ScOutcome(")
    if not in_order(sco, "if Ran then", "'sc.exe exit code '", "else", "'sc.exe could not be run: '"):
        found.append("ScOutcome no longer separates 'sc.exe could not run' from an sc.exe exit code (#5250)")
    for prog in ("cmd", "sc", "find"):
        if f"ExpandConstant('{{sys}}\\{prog}.exe')" not in routine(pas, "function AgentStateIs("):
            found.append(f"AgentStateIs no longer runs {prog}.exe from the system directory (#5250)")
    if re.search(r"NotSecuredMessage\([^;]*,\s*True,\s*''\)", secure_fn(iss), re.S):
        found.append("an abort raised after securing was attempted does not say what it left at the path (#5250)")
    found += bare_sc_problems("yuzu-agent.iss", iss)
    found += section_tag_problems("yuzu-agent.iss", iss)
    if server:
        found += bare_sc_problems("yuzu-server.iss", server)
        found += section_tag_problems("yuzu-server.iss", server)
    body = pslit_body(iss)
    for ch in ("''''", "#$2018", "#$2019", "#$201A", "#$201B"):
        if f"(S[I] = {ch})" not in body:
            found.append(f"PsLit no longer tests for {ch}")
    if "Result := Result + S[I] + S[I]" not in body:
        found.append("PsLit no longer doubles the quote characters it matches")
    return found


class InstallerAclLint(unittest.TestCase):
    def setUp(self):
        self.iss = ISS.read_text(encoding="utf-8")
        self.md = MANUAL.read_text(encoding="utf-8")
        self.server = SERVER_ISS.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.iss, self.md, self.server), [])

    def test_mutations_are_caught(self):
        grant = grant_exec_args(self.iss)
        mutations = {
            "grant /T": ("iss", grant, grant.replace("/C /Q", "/T /C /Q")),
            "manual grant /T": ("md", manual_grant_line(self.md),
                                manual_grant_line(self.md).replace(" /C /Q", " /T /C /Q")),
            "method call": ("iss", "$s=[string](Get-Acl -LiteralPath $p).Sddl",
                            "$s=(Get-Acl -LiteralPath $p).GetSecurityDescriptorSddlForm(15)"),
            "static call": ("iss", "'$env:PSModulePath=$PSHOME+''\\Modules'';'",
                            "'$env:PSModulePath=[Environment]::GetEnvironmentVariable(''X'');'"),
            "root ACEs loosened": ("iss", "'^\\(A;OICI;FA;;;(SY|BA)\\)\\(A;OICI;FA;;;(SY|BA)\\)$'",
                                   "'^\\(A;OICI;FA;;;(SY|BA)\\)'"),
            "manual verify drifted": ("md", "-and ($s -match $e) -and ($Matches[1] -ne $Matches[2])", "-and ($s -match $e) -and ($true)"),
            "manual lock test loosened": ("md", "($s -match 'D:P[A-Z]*\\(A;OICI;FA;;;(SY|BA)\\)\\(A;OICI;FA;;;(SY|BA)\\)$') -and ($Matches[1] -ne $Matches[2])", "($s -match 'D:P') -and ($Matches[1] -ne $Matches[2])"),
            "takeown reintroduced": ("iss", "    Ok := Exec(ExpandConstant('{sys}\\icacls.exe'),\n               '\"' + Stage + '\" /setowner", "    Ok := Exec(ExpandConstant('{sys}\\takeown.exe'), '/F x', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);\n    Ok := Exec(ExpandConstant('{sys}\\icacls.exe'),\n               '\"' + Stage + '\" /setowner"),
            "existing directory not checked": ("iss", "      Reason := RunAclCheck(CertDir, 'root');\n    if Reason <> '' then\n    begin\n      Result := NotSecuredMessage(CertDir,\n        'it already existed", "      Reason := '';\n    if Reason <> '' then\n    begin\n      Result := NotSecuredMessage(CertDir,\n        'it already existed"),
            "prepared-directory gate dropped": ("iss", "    Reason := RunAclCheck(Stage, 'root');", "    Reason := '';"),
            "in-place re-check dropped": ("iss", "    Reason := RunAclCheck(CertDir, 'root');\n    if Reason = '' then\n      Reason := NotFilesOnly(CertDir, True);", "    Reason := '';"),
            "file-ownership gate dropped": ("iss", "      Reason := RunAclCheck(CertDir, 'files');", "      Reason := '';"),
            "re-lock in place restored": ("iss", "    Reason := NotFilesOnly(CertDir, False);", "    Ok := Exec(ExpandConstant('{sys}\\icacls.exe'), '\"' + CertDir + '\" /reset /L /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);\n    Reason := NotFilesOnly(CertDir, False);"),
            "hard-link check dropped": ("iss", "'if($i.LinkType -eq ''HardLink''){Fail (''it contains a hard link: '' + $i.FullName)}' +", "'' +"),
            "check after service stop": ("iss", "  Result := SecureTrustAnchorDir();\n  if Result <> '' then\n    Exit;\n", ""),
            "manual takes ownership of files": ("md", "        if ($c) { icacls \"$d\\*\" /reset /L /C /Q | Out-Null }", "        if ($c) { takeown /F \"$d\\*\" /A | Out-Null; icacls \"$d\\*\" /reset /L /C /Q | Out-Null }"),
            "manual stops throwing": ("md", "if ($bad) { throw", "if ($bad) { Write-Output"),
            "manual re-check after move dropped": ("md", "if (-not (Test-Locked $d) -or @(Get-ChildItem -LiteralPath $d -Force)) { throw", "if ($false) { throw"),
            "installer reset /T": ("iss", "'\"' + Stage + '\" /reset /L /C /Q'", "'\"' + Stage + '\" /reset /T /L /C /Q'"),
            "installer icacls without /L": ("iss", "'\"' + CertDir + '\\*\" /reset /L /C /Q'", "'\"' + CertDir + '\\*\" /reset /C /Q'"),
            "manual takeown back": ("md", "icacls $stage /setowner '*S-1-5-32-544' /L /C /Q | Out-Null", "takeown /F $stage /A | Out-Null"),
            "manual icacls without /L": ("md", "icacls $stage /reset /L /C /Q", "icacls $stage /reset /C /Q"),
            "Script recurses": ("iss", "@(Get-ChildItem -LiteralPath $d -Force)", "@(Get-ChildItem -LiteralPath $d -Recurse -Force)"),
            "Script root reparse check dropped": ("iss", "'if(($r.Attributes -band 1024) -ne 0){Fail ''it is a junction or symbolic link, not a directory''};' +", "'' +"),
            "root check after first command": ("iss", "  if IsReparsePoint(CertDir, Found) then", "  if False then"),
            "contents check dropped": ("iss", "    Reason := NotFilesOnly(CertDir, False);", "    Reason := '';"),
            "manual verify reparse check dropped": ("md", "if ((($i.Attributes -band 1024) -ne 0) -or", "if ((0 -ne 0) -or"),
            "PsLit U+2019 dropped": ("iss", " or (S[I] = #$2019)", ""),
            "PsLit ASCII quote dropped": ("iss", "if (S[I] = '''') or ", "if "),
            "abort text says sc start": ("iss", "'installed, has not been touched.';", "'installed, has not been touched; run sc start YuzuAgent.';"),
            "PsLit stops doubling": ("iss", "Result := Result + S[I] + S[I]", "Result := Result + S[I]"),
            "service not restarted on abort": ("iss", "  if StoppedRunningService and not InstallCompleted then", "  if False then"),
            "service restarted after a completed install": ("iss", "if StoppedRunningService and not InstallCompleted then", "if StoppedRunningService then"),
            "stop of a running service not recorded": ("iss", "    StoppedRunningService := True;\n", ""),
            "flag cleared again (non-sticky)": ("iss", "    StoppedRunningService := True;\n", "    StoppedRunningService := True\n  else\n    StoppedRunningService := False;\n"),
            "flag back to the stop exit code alone": ("iss", "  if (StopRan and (StopResultCode = 0)) or (PriorState = 'RUNNING') or\n     (PriorState = 'START_PENDING') then\n    StoppedRunningService := True;", "  StoppedRunningService := (StopResultCode = 0);"),
            "START_PENDING not counted": ("iss", " or\n     (PriorState = 'START_PENDING') then", " then"),
            "state not read before the stop": ("iss", "  PriorState := AgentServiceState();\n", "  PriorState := 'UNKNOWN';\n"),
            "started again on sc.exe 0/1056": ("iss", "    if State = 'RUNNING' then\n    begin\n      if StartRan then", "    if StartRan and ((StartCode = 0) or (StartCode = 1056)) then\n    begin\n      if StartRan then"),
            "started again without a RUNNING guard": ("iss", "    if State = 'RUNNING' then\n    begin\n      if StartRan then", "    if True then\n    begin\n      if StartRan then"),
            "no wait for a pending stop": ("iss", "    while ((State = 'STOP_PENDING') or (State = 'START_PENDING')) and (I < 45) do", "    while False and (I < 45) do"),
            "pending-stop wait too short": ("iss", "(I < 45)", "(I < 1)"),
            "no poll for RUNNING after the start": ("iss", "      for I := 1 to 10 do\n      begin\n        State := AgentServiceState();", "      for I := 1 to 1 do\n      begin\n        State := AgentServiceState();"),
            "Exec failure logged as an sc.exe exit code": ("iss", "' after the start (' + ScOutcome(StartRan, StartCode) + '). '", "' after the start (sc.exe exit code ' + IntToStr(StartCode) + '). '"),
            "ScOutcome stops separating": ("iss", "    Result := 'sc.exe could not be run: '", "    Result := 'sc.exe exit code '"),
            "restart commented out": ("iss", "      StartRan := Exec(ExpandConstant('{sys}\\sc.exe'), 'start YuzuAgent', '', SW_HIDE,\n                       ewWaitUntilTerminated, StartCode);", "      (* StartRan := Exec(ExpandConstant('{sys}\\sc.exe'), 'start YuzuAgent', '', SW_HIDE,\n                       ewWaitUntilTerminated, StartCode); *)\n      StartRan := True;"),
            "sc.exe stop without a path": ("iss", "Exec(ExpandConstant('{sys}\\sc.exe'), 'stop YuzuAgent'", "Exec('sc.exe', 'stop YuzuAgent'"),
            "state query cmd.exe without a path": ("iss", "Exec(ExpandConstant('{sys}\\cmd.exe'), '/c \"\"'", "Exec('cmd.exe', '/c \"\"'"),
            "[Run] comment line in [Code] (efc4f162c line 933)": ("iss", "after every file was installed and each\n    entry of the Run section -- including", "after every file was installed and every\n    [Run] entry -- including"),
            "# line in [Code]": ("iss", "    a non-zero exit code, so an unattended deployment records the failure. }", "    a non-zero exit code, so an unattended deployment records the failure.\n    #5250 }"),
            "{# in [Code]": ("iss", "fails (#5250). Only ever set", "fails {#5250}. Only ever set"),
            "server abort text says sc start": ("server", "or run: sc.exe start YuzuServer';", "or run: sc start YuzuServer';"),
            "server message says bare sc config": ("server", "(sc.exe config YuzuServer start= disabled)", "(sc config YuzuServer start= disabled)"),
            "server [Code] line starts with [": ("server", "// Appended to every abort message while", "[Run] entries never see this.\n// Appended to every abort message while"),
            "completion never recorded": ("iss", "    InstallCompleted := True;", "    Log('done');"),
            "restart Exec dropped": ("iss", "Exec(ExpandConstant('{sys}\\sc.exe'), 'start YuzuAgent'", "Exec(ExpandConstant('{sys}\\sc.exe'), 'query YuzuAgent'"),
            "attempted abort without outcome": ("iss", "True, NotCreated);", "True, '');"),
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                srcs = {"iss": self.iss, "md": self.md, "server": self.server}
                self.assertIn(old, srcs[which], f"mutation anchor for {name!r} not found")
                srcs[which] = srcs[which].replace(old, new, 1)
                self.assertNotEqual(problems(srcs["iss"], srcs["md"], srcs["server"]), [],
                                    f"{name!r} was not caught")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
