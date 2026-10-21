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
- WriteEnrollmentTokenFile stages the token in a directory created fresh BESIDE
  the destination (same folder, so the final move is always a same-volume
  rename, never a copy that would take the destination's inherited
  permissions): the directory is given Administrators as owner, restricted to
  Administrators and SYSTEM, and verified by a read-back (RunAclCheck) and an
  emptiness check BEFORE any file is created in it; the staged file is then
  created EMPTY (inheriting the locked directory), given Administrators as
  owner, and the directory is read back AGAIN (RunAclCheck 'full': the folder is
  Users-creatable, so the state the token is written into is verified, before
  the file-level grant replaces the inherited pair that check requires); then a
  FILE-level grant (no `(OI)(CI)`, invalid on a file; `/L`, never `/T`), each
  exit code is checked, and only then is the token written -- no reference to
  the token precedes the lock. The previous token file is deleted
  only after its replacement is staged and locked, then the staged file is
  moved into place with RenameFile and the staging directory removed. The
  token is never passed to `Log(`. DropTokenStaging deletes the staged file and
  then removes its directory (a stale `.stage` blocks every later install).
- The token must have the shape the server issues (64 lowercase hex): the
  installer checks it between resolving and writing it.
- ResolveEnrollmentToken checks for a UTF-8 byte order mark in a /TOKEN_FILE=
  file and deletes it from the raw bytes before they are converted
  (PowerShell 5.1 `-Encoding UTF8` and Notepad write one; converted through
  the ANSI code page it would no longer be recognisable to the agent).
- PrepareToInstall resolves, shape-checks and writes the token file strictly
  between securing the trust-anchor directory and the FIRST service stop (there
  are two `stop YuzuAgent` Execs; a write between them would pass a check
  against the last), so a refusal leaves a running agent running and nothing
  installed.
- `[UninstallDelete]` removes the token file on uninstall, and a leftover
  `enrollment-token.stage` folder when it holds only the staged file.

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

    # 3. WriteEnrollmentTokenFile: present and in the right order -- link check,
    #    a FRESH staging directory beside the destination, owner + exact lock on
    #    the directory, a read-back and an emptiness check, only then an EMPTY
    #    staged file, its owner and file-level grant (each exit code checked),
    #    only then the token write, the previous file deleted after that, then
    #    the move and the staging directory's removal.
    file_grant = '/inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" /L /C /Q'
    wfn = routine(clean, "function WriteEnrollmentTokenFile(")
    if not wfn:
        found.append("WriteEnrollmentTokenFile is missing")
    else:
        if not in_order(wfn,
                         "IsReparsePoint(Dest",
                         "CreateDir(HoldDir)",
                         "HoldDir + '\" /setowner *S-1-5-32-544 /L /C /Q'",
                         "HoldDir + '\" /inheritance:r /grant:r '",
                         "RunAclCheck(HoldDir, 'root')",
                         "NotFilesOnly(HoldDir, True)",
                         "SaveStringToFile(HoldFile, '', False)",
                         "HoldFile + '\" /setowner *S-1-5-32-544 /L /C /Q'",
                         "ResultCode <> 0",
                         "RunAclCheck(HoldDir, 'full')",
                         file_grant,
                         "ResultCode <> 0",
                         "SaveStringsToUTF8FileWithoutBOM(HoldFile",
                         "DeleteFile(Dest)",
                         "RenameFile(HoldFile, Dest)",
                         "RemoveDir(HoldDir)"):
            found.append("WriteEnrollmentTokenFile's link-check/fresh-staging-dir/dir-lock/"
                         "read-back/stage/file-lock/write/replace/move/cleanup steps are missing "
                         "or out of order")
        ref = first_token_ref(wfn)
        if ref >= 0 and (ref < wfn.find(file_grant) or ref < wfn.find("RunAclCheck(HoldDir, 'root')")):
            found.append("WriteEnrollmentTokenFile references Token before the staging directory "
                         "and the file are locked")
        for args in re.findall(r"Exec\(ExpandConstant\('\{sys\}\\icacls\.exe'\),\s*(.*?),\s*'', SW_HIDE",
                               wfn, re.S):
            if "/L" not in args:
                found.append(f"an icacls Exec in WriteEnrollmentTokenFile has no /L: {args[:80]}")
            if re.search(r"(?<!\w)/T(?!\w)", args):
                found.append(f"an icacls Exec in WriteEnrollmentTokenFile carries /T: {args[:80]}")
            if "HoldFile" in args and re.search(r"\((OI|CI)\)", args):
                found.append(f"the file-level icacls grant carries (OI)/(CI), invalid on a file: {args[:80]}")
            if "/grant:r" in args and sorted(re.findall(r"\*S-[\d-]+", args)) != [
                    "*S-1-5-18", "*S-1-5-32-544"]:
                found.append(f"an icacls grant is not exactly Administrators and SYSTEM: {args[:80]}")
            if "HoldDir" in args and "/grant:r" in args and args.count("(OI)(CI)F") != 2:
                found.append(f"the staging-directory grant is not inheritable full control: {args[:80]}")
        if re.search(r"Log\([^;]*\bToken\b", wfn):
            found.append("WriteEnrollmentTokenFile passes Token to Log(")
        # Every refusal after the staging directory exists cleans it up.
        if wfn.count("DropTokenStaging(HoldFile, HoldDir)") < 8:
            found.append("a refusal path of WriteEnrollmentTokenFile no longer removes the "
                         "staging directory")
        if "ExtractFileDrive" in wfn:
            found.append("WriteEnrollmentTokenFile compares drive letters again: the staging "
                         "directory is beside the destination, so the move is a same-volume "
                         "rename by construction")
        # The location itself is pinned, not only the absence of a drive-letter
        # comparison: both paths are built from the destination, so moving the
        # staging directory to the temp folder (a possible cross-volume copy that
        # takes the destination's inherited permissions) fails here even when no
        # other predicate changes.
        if ("HoldDir := Dest + '.stage';" not in wfn
                or "HoldFile := HoldDir + '\\enrollment-token';" not in wfn):
            found.append("WriteEnrollmentTokenFile no longer stages beside the destination "
                         "(the move must be a same-volume rename)")

    # 3-bis. DropTokenStaging deletes the staged file, then removes its directory: losing
    #    either leaves a stale `.stage` that blocks every later install.
    dfn = routine(clean, "procedure DropTokenStaging(")
    if not dfn or not in_order(dfn, "DeleteFile(HoldFile)", "RemoveDir(HoldDir)"):
        found.append("DropTokenStaging no longer deletes the staged file and then removes its "
                     "directory")

    # 3a. The token's shape is checked (64 lowercase hex) before it is written.
    sfn = routine(clean, "function EnrollmentTokenShapeProblem(")
    if not sfn:
        found.append("EnrollmentTokenShapeProblem is missing")
    elif (not in_order(sfn, "Length(Token) <> 64", "(C >= '0') and (C <= '9')",
                       "(C >= 'a') and (C <= 'f')", "Result :=")
          or "'A'" in sfn or "'F'" in sfn):
        found.append("EnrollmentTokenShapeProblem no longer requires exactly 64 lowercase hex "
                     "characters")

    # 3b. ResolveEnrollmentToken strips a UTF-8 BOM from the raw bytes of a token file.
    rfn = routine(clean, "function ResolveEnrollmentToken(")
    if not rfn:
        found.append("ResolveEnrollmentToken is missing")
    elif (not all(f"= ${b}" in rfn for b in ("EF", "BB", "BF"))
          or not in_order(rfn, "(Ord(Content[3]) = $BF)", "Delete(Content, 1, 3)",
                          "String(Content)")):
        found.append("ResolveEnrollmentToken no longer strips a UTF-8 BOM (EF BB BF) from the "
                     "raw bytes of a /TOKEN_FILE= file before converting them")

    # 4. PrepareToInstall: SecureTrustAnchorDir, then resolve, shape-check and
    #    write the token file, all before the FIRST service stop.
    pti = prepare_to_install(clean)
    if not in_order(pti, "SecureTrustAnchorDir()", "ResolveEnrollmentToken(",
                    "EnrollmentTokenShapeProblem(", "WriteEnrollmentTokenFile("):
        found.append("PrepareToInstall does not resolve, shape-check and write the token file "
                     "after securing the trust-anchor directory")
    first_stop = pti.find("'stop YuzuAgent'")
    if not (0 <= pti.find("WriteEnrollmentTokenFile(") < first_stop):
        found.append("PrepareToInstall writes the token file after the first service stop")

    # 5. [UninstallDelete] removes the token file, and a leftover staging folder
    #    (the staged file, then the directory only if it is empty: dirifempty never
    #    follows a link a user planted at that name).
    ud_lines = [ln.strip() for ln in uninstall_delete_section(iss).splitlines()]
    for entry in ('Type: files; Name: "{commonappdata}\\Yuzu\\enrollment-token"',
                  'Type: files; Name: "{commonappdata}\\Yuzu\\enrollment-token.stage'
                  '\\enrollment-token"',
                  'Type: dirifempty; Name: "{commonappdata}\\Yuzu\\enrollment-token.stage"'):
        if entry not in ud_lines:
            found.append(f"[UninstallDelete] no longer has: {entry}")

    return found


def delete_block(iss: str, start: str, end: str) -> str:
    """Remove the text from `start` up to (not including) `end`."""
    return iss[:iss.index(start)] + iss[iss.index(end):]


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
        token_block = (
            "  Token := ResolveEnrollmentToken(Result);\n  if Result <> '' then\n    Exit;\n"
            "  if Token <> '' then\n  begin\n    Result := EnrollmentTokenShapeProblem(Token);\n"
            "    if Result <> '' then\n      Exit;\n    Result := WriteEnrollmentTokenFile(Token);\n"
            "    if Result <> '' then\n      Exit;\n  end;\n")
        first_stop = ("  PriorState := AgentServiceState();\n  StopRan := Exec(ExpandConstant('{sys}\\sc.exe'), "
                      "'stop YuzuAgent', '', SW_HIDE,\n                  ewWaitUntilTerminated, "
                      "StopResultCode);\n")
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
            "(OI)(CI) on the file grant": (
                '"*S-1-5-32-544:F" "*S-1-5-18:F" /L /C /Q', '"*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:F" /L /C /Q'),
            "grant widened to Authenticated Users": (
                '"*S-1-5-18:F" /L /C /Q', '"*S-1-5-18:F" "*S-1-5-11:F" /L /C /Q'),
            "staging-directory grant widened": (
                "HoldDir + '\" /inheritance:r /grant:r ' +\n"
                "             '\"*S-1-5-32-544:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\" /L /C /Q'",
                "HoldDir + '\" /inheritance:r /grant:r ' +\n"
                "             '\"*S-1-5-32-544:(OI)(CI)F\" \"*S-1-5-11:(OI)(CI)F\" /L /C /Q'"),
            "file grant exit-code check dropped": (
                "  if not Ok or (ResultCode <> 0) then\n  begin\n    DropTokenStaging(HoldFile, HoldDir);\n"
                "    Result := 'The enrollment token file could not be restricted",
                "  if not Ok then\n  begin\n    DropTokenStaging(HoldFile, HoldDir);\n"
                "    Result := 'The enrollment token file could not be restricted"),
            "file /setowner dropped": (
                "'\"' + HoldFile + '\" /setowner *S-1-5-32-544 /L /C /Q'", "'\"' + HoldFile + '\" /L /C /Q'"),
            "directory /setowner dropped": (
                "'\"' + HoldDir + '\" /setowner *S-1-5-32-544 /L /C /Q'", "'\"' + HoldDir + '\" /L /C /Q'"),
            "directory read-back dropped": (
                "  Reason := RunAclCheck(HoldDir, 'root');\n", "  Reason := '';\n"),
            "second directory read-back dropped": (
                "  Reason := RunAclCheck(HoldDir, 'full');\n", "  Reason := '';\n"),
            "second read-back moved after the file-level grant": lambda iss: move_block(
                iss, "  { Read the directory back again", "  Ok := Exec(ExpandConstant('{sys}\\icacls.exe'),\n"
                "             '\"' + HoldFile + '\" /inheritance:r /grant:r",
                "  { 6. Only now"),
            "directory emptiness check dropped": (
                "    Reason := NotFilesOnly(HoldDir, True);\n", "    Reason := '';\n"),
            "staging directory no longer created fresh": (
                "if not CreateDir(HoldDir) then", "if not ForceDirectories(HoldDir) then"),
            "link check on the destination dropped": (
                "  if IsReparsePoint(Dest, Found) then", "  if False then"),
            "staging cleanup dropped from a refusal": (
                "    DropTokenStaging(HoldFile, HoldDir);\n    Result := 'Could not write the staged",
                "    Result := 'Could not write the staged"),
            "staging directory not removed": (
                "  RemoveDir(HoldDir);\nend;\n\n{ True when sc.exe", "end;\n\n{ True when sc.exe"),
            "drive-letter comparison restored": (
                "  HoldDir := Dest + '.stage';",
                "  HoldDir := ExpandConstant('{tmp}\\enrollment-token.stage');\n"
                "  if CompareText(ExtractFileDrive(HoldDir), ExtractFileDrive(Dest)) <> 0 then Exit;"),
            "staging moved to the temp folder (location only)": (
                "  HoldDir := Dest + '.stage';",
                "  HoldDir := ExpandConstant('{tmp}\\enrollment-token.stage');"),
            "shape check removed from PrepareToInstall": (
                "    Result := EnrollmentTokenShapeProblem(Token);\n    if Result <> '' then\n      Exit;\n", ""),
            "shape check accepts uppercase": (
                "(C >= 'a') and (C <= 'f')", "(C >= 'a') and (C <= 'F')"),
            "shape check length dropped": (
                "Bad := Length(Token) <> 64;", "Bad := False;"),
            "PrepareToInstall never calls WriteEnrollmentTokenFile": (token_block, ""),
            "token resolved and written between the two service stops": lambda iss: (
                iss.replace(token_block, "", 1).replace(first_stop, first_stop + token_block, 1)),
            "UninstallDelete entry removed": (
                'Type: files; Name: "{commonappdata}\\Yuzu\\enrollment-token"\n', ""),
            "UninstallDelete staging file entry removed": (
                'Type: files; Name: "{commonappdata}\\Yuzu\\enrollment-token.stage\\enrollment-token"\n', ""),
            "UninstallDelete staging directory entry removed": (
                'Type: dirifempty; Name: "{commonappdata}\\Yuzu\\enrollment-token.stage"\n', ""),
            "DropTokenStaging stops deleting the staged file": (
                "begin\n  DeleteFile(HoldFile);\n  RemoveDir(HoldDir);\nend;", "begin\n  RemoveDir(HoldDir);\nend;"),
            "DropTokenStaging stops removing the directory": (
                "begin\n  DeleteFile(HoldFile);\n  RemoveDir(HoldDir);\nend;", "begin\n  DeleteFile(HoldFile);\nend;"),
            "token written when the staged file is created, before the lock": (
                "SaveStringToFile(HoldFile, '', False)", "SaveStringToFile(HoldFile, Token, False)"),
            "token write block moved before the lock": lambda iss: move_block(
                iss, "  { 6. Only now", "  { 7. Replace", "  { 5. Make Administrators"),
            "previous file deleted before the replacement is staged": lambda iss: move_block(
                iss, "  { 7. Replace", "  { 8. Move", "  { 4. Stage"),
            "UTF-8 BOM strip removed": (
                "(Ord(Content[1]) = $EF)", "(Ord(Content[1]) = $EE)"),
            "UTF-8 BOM deletion removed": ("Delete(Content, 1, 3);", "I := 0;"),
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
