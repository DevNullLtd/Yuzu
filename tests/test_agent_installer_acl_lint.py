#!/usr/bin/env python3
"""Regression net for the Windows agent installer's trust-anchor lockdown (#5196).

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
- The abort messages say `sc.exe start`: in Windows PowerShell 5.1 `sc` is an
  alias for Set-Content, so `sc start YuzuAgent` would silently write a file.

Each check also runs against a mutated copy of the source and must fail there,
so a check that has stopped matching anything cannot pass silently.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ISS = ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss"
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


def problems(iss: str, md: str) -> list:
    found = []
    if exec_args(iss, "takeown"):
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
    if re.search(r"(?i)\bsc\s+start\b", iss):
        found.append("an abort message says `sc start`, which is Set-Content in Windows PowerShell 5.1; use sc.exe")
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

    def test_source_is_clean(self):
        self.assertEqual(problems(self.iss, self.md), [])

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
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                src = self.iss if which == "iss" else self.md
                self.assertIn(old, src, f"mutation anchor for {name!r} not found")
                mutated = src.replace(old, new, 1)
                iss, md = (mutated, self.md) if which == "iss" else (self.iss, mutated)
                self.assertNotEqual(problems(iss, md), [], f"{name!r} was not caught")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
