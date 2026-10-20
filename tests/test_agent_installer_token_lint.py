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
- WriteEnrollmentTokenFile creates the staged file EMPTY, locks it to
  Administrators and SYSTEM with a FILE-level grant (no `(OI)(CI)`, invalid on
  a file; `/L`, never `/T`), checks the icacls exit code, and only then writes
  the token -- no reference to the token precedes the lock. The previous token
  file is deleted only after its replacement is staged and locked, and the
  staged file is moved into place with RenameFile, in that order. The token is
  never passed to `Log(`.
- ResolveEnrollmentToken strips a UTF-8 byte order mark from a /TOKEN_FILE=
  file before the bytes are converted (PowerShell 5.1 `-Encoding UTF8` and
  Notepad write one; converted through the ANSI code page it would no longer
  be recognisable to the agent).
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


def first_token_ref(fn: str) -> int:
    """Offset of the first reference to the `Token` parameter in the routine
    body, ignoring string literals (messages may say "token"); -1 if none."""
    body = fn[fn.index("begin"):]
    off = fn.index("begin")
    for m in re.finditer(r"'(?:[^'\n]|'')*'|\bToken\b", body):
        if m.group(0) == "Token":
            return off + m.start()
    return -1


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

    # 3. WriteEnrollmentTokenFile: present and in the right order -- reparse check,
    #    EMPTY staged file, file-level grant, exit-code check, only then the token
    #    write, the previous file deleted only after that, then the move.
    grant = '/inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" /L /C /Q'
    wfn = routine(clean, "function WriteEnrollmentTokenFile(")
    if not wfn:
        found.append("WriteEnrollmentTokenFile is missing")
    else:
        if not in_order(wfn,
                         "IsReparsePoint(Dest",
                         "SaveStringToFile(TokenTmp, '', False)",
                         grant,
                         "ResultCode <> 0",
                         "SaveStringsToUTF8FileWithoutBOM(TokenTmp",
                         "DeleteFile(Dest)",
                         "RenameFile(TokenTmp, Dest)"):
            found.append("WriteEnrollmentTokenFile's stage/lock/check/write/replace/move steps "
                         "are out of order")
        ref = first_token_ref(wfn)
        if ref >= 0 and ref < wfn.find(grant):
            found.append("WriteEnrollmentTokenFile references Token before the file is locked")
        for args in re.findall(r"Exec\(ExpandConstant\('\{sys\}\\icacls\.exe'\),\s*(.*?),\s*'', SW_HIDE",
                               wfn, re.S):
            if "/L" not in args:
                found.append(f"an icacls Exec in WriteEnrollmentTokenFile has no /L: {args[:80]}")
            if re.search(r"(?<!\w)/T(?!\w)", args):
                found.append(f"an icacls Exec in WriteEnrollmentTokenFile carries /T: {args[:80]}")
        if re.search(r"Log\([^;]*\bToken\b", wfn):
            found.append("WriteEnrollmentTokenFile passes Token to Log(")

    # 3b. ResolveEnrollmentToken strips a UTF-8 BOM from the raw bytes of a token file.
    rfn = routine(clean, "function ResolveEnrollmentToken(")
    if not rfn:
        found.append("ResolveEnrollmentToken is missing")
    elif not all(f"= ${b}" in rfn for b in ("EF", "BB", "BF")):
        found.append("ResolveEnrollmentToken no longer strips a UTF-8 BOM (EF BB BF) from a "
                     "/TOKEN_FILE= file")

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


def move_block(iss: str, start: str, end: str, before: str) -> str:
    """Move the text from `start` up to `end` so it sits just before `before`."""
    a, b = iss.index(start), iss.index(end)
    rest = iss[:a] + iss[b:]
    c = rest.index(before)
    return rest[:c] + iss[a:b] + rest[c:]


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
            "token written when the staged file is created, before the lock": (
                "SaveStringToFile(TokenTmp, '', False)", "SaveStringToFile(TokenTmp, Token, False)"),
            "token write block moved before the lock": lambda iss: move_block(
                iss, "  { 5. Only now", "  { 6. Replace", "  { 4. Lock"),
            "previous file deleted before the replacement is staged": lambda iss: move_block(
                iss, "  { 6. Replace", "  { 7. Move", "  { 3. Stage"),
            "UTF-8 BOM strip removed": (
                "(Ord(Content[1]) = $EF)", "(Ord(Content[1]) = $EE)"),
            "Log(Token) added": (
                "  Result := '';\n  Dest := ExpandConstant('{commonappdata}\\Yuzu\\enrollment-token');",
                "  Result := '';\n  Log('token=' + Token);\n  Dest := "
                "ExpandConstant('{commonappdata}\\Yuzu\\enrollment-token');",
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                if callable(mutation):
                    mutated = mutation(self.iss)
                else:
                    old, new = mutation
                    self.assertIn(old, self.iss, f"mutation anchor for {name!r} not found")
                    mutated = self.iss.replace(old, new, 1)
                self.assertNotEqual(mutated, self.iss, f"{name!r} changed nothing")
                self.assertNotEqual(problems(mutated), [], f"{name!r} was not caught")


if __name__ == "__main__":
    unittest.main()
