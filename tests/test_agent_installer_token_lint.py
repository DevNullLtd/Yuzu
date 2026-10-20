#!/usr/bin/env python3
"""Regression net for the Windows agent installer's enrollment-token-by-file change.

The .iss is compiled only by release.yml, never on a PR, so a regression here
would first be seen in a release build. These checks read the source text;
stdlib only, no Windows, no Inno Setup. Mirrors the structure of the sibling
test_agent_installer_acl_lint.py and reuses its text-parsing helpers.

What they pin:

- The registered service command line (`sc.exe config YuzuAgent binPath=`)
  carries `--enrollment-token-file`, never a bare `--enrollment-token <value>`.
- No other [Code] string literal appends a bare `--enrollment-token` either
  (GetExtraArgs no longer has a token branch at all).
- WriteEnrollmentTokenFile writes the token to a staged temp file, restricts
  it to Administrators and SYSTEM with a FILE-level grant (no `(OI)(CI)`,
  invalid on a file; `/L`, never `/T`), checks the icacls exit code, and only
  then moves it into place with RenameFile — in that order — and never passes
  the token to `Log(`.
- PrepareToInstall resolves and writes the token file strictly between
  securing the trust-anchor directory and stopping the service, so a refusal
  leaves a running agent running and nothing installed.
- `[UninstallDelete]` removes the token file on uninstall.

Each check also runs against a mutated copy of the source and must fail
there, so a check that has stopped matching anything cannot pass silently.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ISS = ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss"

sys.path.insert(0, str(Path(__file__).parent))
from test_agent_installer_acl_lint import (  # noqa: E402
    code_section,
    strip_pascal_comments,
    routine,
    in_order,
)


def run_line(iss: str) -> str:
    """The [Run] line that configures the YuzuAgent service binPath."""
    m = re.search(r'^Filename: "\{sys\}\\sc\.exe"; Parameters: "config YuzuAgent binPath=.*$',
                  iss, re.M)
    if not m:
        raise AssertionError("the sc.exe config [Run] line was not found")
    return m.group(0)


def prepare_to_install(code: str) -> str:
    return routine(code, "function PrepareToInstall(")


def uninstall_delete_section(iss: str) -> str:
    m = re.search(r"\[UninstallDelete\]\r?\n(.*?)\r?\n\r?\n", iss, re.S)
    if not m:
        raise AssertionError("no [UninstallDelete] section")
    return m.group(1)


def problems(iss: str) -> list:
    found = []
    code = code_section(iss)
    clean = strip_pascal_comments(code)

    # 1. The service command line carries --enrollment-token-file, never a bare
    #    --enrollment-token <value>.
    rl = run_line(iss)
    if "--enrollment-token-file" not in rl:
        found.append("the sc.exe config [Run] line no longer carries --enrollment-token-file")
    if re.search(r"--enrollment-token(?!-file)\b", rl):
        found.append("the sc.exe config [Run] line still carries a bare --enrollment-token")

    # 2. No [Code] string literal appends a bare --enrollment-token anywhere else.
    for lit in re.findall(r"'(?:[^'\n]|'')*'", clean):
        if re.search(r"--enrollment-token(?!-file)\b", lit):
            found.append(f"a [Code] string still appends a bare --enrollment-token: {lit[:80]}")

    # 3. WriteEnrollmentTokenFile: present and in the right order.
    wfn = routine(clean, "function WriteEnrollmentTokenFile(")
    if not wfn:
        found.append("WriteEnrollmentTokenFile is missing")
    else:
        if not in_order(wfn,
                         "IsReparsePoint(Dest",
                         "SaveStringsToUTF8FileWithoutBOM(",
                         '/inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" /L /C /Q',
                         "ResultCode <> 0",
                         "RenameFile(TokenTmp, Dest)"):
            found.append("WriteEnrollmentTokenFile's stage/grant/check/move steps are out of order")
        for args in re.findall(r"Exec\(ExpandConstant\('\{sys\}\\icacls\.exe'\),\s*(.*?),\s*'', SW_HIDE",
                               wfn, re.S):
            if "/L" not in args:
                found.append(f"an icacls Exec in WriteEnrollmentTokenFile has no /L: {args[:80]}")
            if re.search(r"(?<!\w)/T(?!\w)", args):
                found.append(f"an icacls Exec in WriteEnrollmentTokenFile carries /T: {args[:80]}")
        if re.search(r"Log\([^;]*\bToken\b", wfn):
            found.append("WriteEnrollmentTokenFile passes Token to Log(")

    # 4. PrepareToInstall: SecureTrustAnchorDir, then the token-file write, then
    #    the service stop -- in that order.
    pti = prepare_to_install(clean)
    if not in_order(pti, "SecureTrustAnchorDir()", "WriteEnrollmentTokenFile(",
                    "'stop YuzuAgent'"):
        found.append("PrepareToInstall does not resolve/write the token file between securing "
                     "the trust-anchor directory and stopping the service")

    # 5. [UninstallDelete] removes the token file.
    if r"{commonappdata}\Yuzu\enrollment-token" not in uninstall_delete_section(iss):
        found.append("[UninstallDelete] no longer removes the enrollment-token file")

    return found


class InstallerTokenFileLint(unittest.TestCase):
    def setUp(self):
        self.iss = ISS.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.iss), [])

    def test_mutations_are_caught(self):
        grant = '/inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" /L /C /Q'
        mutations = {
            "token back on binPath": (
                '--log-file \\""{app}\\logs\\yuzu-agent.log\\"" --enrollment-token-file',
                '--log-file \\""{app}\\logs\\yuzu-agent.log\\"" --enrollment-token XYZ '
                '--enrollment-token-file',
            ),
            "GetExtraArgs token branch restored": (
                "function GetExtraArgs(Param: string): string;\nbegin\n  Result := '';\n\n  "
                "{ No TLS }",
                "function GetExtraArgs(Param: string): string;\nbegin\n  Result := '';\n\n  "
                "{ Enrollment token }\n  if EnrollmentToken <> '' then\n    Result := Result + "
                "' --enrollment-token ' + EnrollmentToken;\n\n  { No TLS }",
            ),
            "/T added to the file grant": (grant, grant.replace("/L /C /Q", "/T /L /C /Q")),
            "/L dropped from the file grant": (grant, grant.replace(" /L", "")),
            "grant widened to Authenticated Users": (
                '"*S-1-5-18:F"', '"*S-1-5-18:F" "*S-1-5-11:F"'),
            "exit-code check dropped": (
                "if not Ok or (ResultCode <> 0) then", "if not Ok then"),
            "PrepareToInstall never calls WriteEnrollmentTokenFile": (
                "  Token := ResolveEnrollmentToken(Result);\n  if Result <> '' then\n    Exit;\n"
                "  if Token <> '' then\n  begin\n    Result := WriteEnrollmentTokenFile(Token);\n"
                "    if Result <> '' then\n      Exit;\n  end;\n",
                "",
            ),
            "UninstallDelete entry removed": (
                'Type: files; Name: "{commonappdata}\\Yuzu\\enrollment-token"\n', ""),
            "Log(Token) added": (
                "  Result := '';\n  Dest := ExpandConstant('{commonappdata}\\Yuzu\\enrollment-token');",
                "  Result := '';\n  Log('token=' + Token);\n  Dest := "
                "ExpandConstant('{commonappdata}\\Yuzu\\enrollment-token');",
            ),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old, self.iss, f"mutation anchor for {name!r} not found")
                self.assertNotEqual(problems(self.iss.replace(old, new, 1)), [],
                                    f"{name!r} was not caught")


if __name__ == "__main__":
    unittest.main()
