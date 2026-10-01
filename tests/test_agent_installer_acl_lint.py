#!/usr/bin/env python3
"""Regression net for the Windows agent installer's trust-anchor lockdown (#5196).

The .iss is compiled only by release.yml, never on a PR, so a regression in
SecureTrustAnchorDir would first be seen in a release build. These checks read
the source text; stdlib only, no Windows, no Inno Setup.

What they pin, each verified on Windows Server 2022:

- The icacls GRANT must not use /T. (OI)(CI) is invalid on a file, and
  `icacls /T` then gives every existing file an empty protected DACL, locking
  SYSTEM out of the operator's update-trust-bundle.pem while reporting success.
  The same line in the user manual's manual procedure is held to the same rule.
- The verification script must make no .NET method or static call. Under WDAC /
  AppLocker, PowerShell runs in Constrained Language Mode, which refuses them,
  and the rc1..rc5 check (GetOwner/Translate) aborted every install there.
- The verification compares the SDDL exactly, and the user manual's copy uses
  the same expressions, so the two cannot drift apart again.
- PsLit doubles every character PowerShell treats as a single quote.
- The script contains no double quote, which would end the -Command argument.

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


def grant_exec_args(iss: str) -> str:
    m = re.search(r"'\"' \+ CertDir \+ '\" /inheritance:r /grant:r ' \+\s*'([^']*)'", iss)
    if not m:
        raise AssertionError("the icacls /inheritance:r /grant:r Exec was not found")
    return m.group(1)


def manual_grant_line(md: str) -> str:
    lines = [l for l in md.splitlines()
             if l.startswith('icacls "C:\\ProgramData\\Yuzu\\agent-certs"') and "/grant:r" in l]
    if len(lines) != 1:
        raise AssertionError(f"expected one manual grant line, found {len(lines)}")
    return lines[0]


def manual_verify(md: str) -> str:
    a = md.index('$d = "C:\\ProgramData\\Yuzu\\agent-certs"\nforeach')
    return md[a:md.index("```", a)]


def pslit_body(iss: str) -> str:
    a = iss.index("function PsLit(")
    return iss[a:iss.index("end;", a)]


def problems(iss: str, md: str) -> list:
    found = []
    if re.search(r"/T\b", grant_exec_args(iss)):
        found.append("installer grant uses /T")
    if re.search(r"\s/T\b", manual_grant_line(md)):
        found.append("manual grant uses /T")
    script = pascal_script(iss)
    if '"' in script:
        found.append("Script contains a double quote")
    if "::" in script:
        found.append("Script makes a .NET static call (refused in Constrained Language Mode)")
    calls = re.findall(r"\.[A-Za-z_]\w*\(", script)
    if calls:
        found.append(f"Script makes .NET method calls {calls} (refused in Constrained Language Mode)")
    for needle, why in (("'^O:(BA|SY)G:'", "owner check"),
                        ("if($f -notmatch 'P')", "protected-root check"),
                        ("'^" + ROOT_ACES + "'", "exact root ACE set"),
                        ("'^" + CHILD_ACES + "'", "exact child ACE set"),
                        ("($Matches[1] -eq $Matches[2])", "two distinct accounts")):
        if needle not in script:
            found.append(f"Script lost its {why}: {needle}")
    verify = manual_verify(md)
    for needle, why in (("'^O:(BA|SY)G:'", "owner check"),
                        ("'D:P[A-Z]*" + ROOT_ACES + "'", "exact root ACE set"),
                        ("'D:[A-Z]*" + CHILD_ACES + "'", "exact child ACE set"),
                        ("($Matches[1] -ne $Matches[2])", "two distinct accounts")):
        if needle not in verify:
            found.append(f"manual verify lost its {why}: {needle}")
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
            "manual verify drifted": ("md", "($Matches[1] -ne $Matches[2])", "($true)"),
            "PsLit U+2019 dropped": ("iss", " or (S[I] = #$2019)", ""),
            "PsLit ASCII quote dropped": ("iss", "if (S[I] = '''') or ", "if "),
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
