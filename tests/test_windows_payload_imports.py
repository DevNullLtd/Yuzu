#!/usr/bin/env python3
r"""The Windows agent payloads ship the Visual C++ runtime, and a release that
does not fails before anything is published.

Up to v0.15.0 every Windows binary imported vcruntime140.dll,
vcruntime140_1.dll and msvcp140.dll (yuzu-agent.exe also
msvcp140_atomic_wait.dll), and neither the release zip nor YuzuAgentSetup
carried them. The release runner has the VC++ runtime in System32, so its
smoke run passed. This file pins the fix; stdlib only (PyYAML and pwsh are
used when present), no Windows.

What it pins:

- scripts/ci/check-windows-payload-imports.py, run behaviourally over
  synthetic PE images: a payload whose binaries import the C++ runtime fails
  even when the system directory holds it (the runner's trap) and passes once
  bin\ carries it; a missing third-party DLL (also via delay-load) fails; a
  debug runtime import fails; an unreadable binary, an empty import table, no
  yuzu-agent.exe or no plugin fails; API sets and OS DLLs pass. Its .iss mode
  is run against the REAL yuzu-agent.iss over a synthetic build tree, so a
  Source line it cannot model fails here, not at release time.
- release.yml's build-windows job: "Package archive" stages the runtime with
  deploy/packaging/windows/stage-msvc-runtime.ps1 into the zip's bin/ and into
  build-windows/msvc-runtime before Compress-Archive, and checks its exit
  code; one gating "Check the DLL import closure of both payloads" step runs
  the checker over the zip and the installer payload, after Package archive
  and before the installer is compiled, with --build-dir equal to ISCC's
  /DBuildDir.
- yuzu-agent.iss installs {#BuildDir}\msvc-runtime\*.dll into {app}\bin under
  core, without skipifsourcedoesntexist (an unstaged build fails ISCC).
- stage-msvc-runtime.ps1 requires the four DLLs, never names vcvars, ends in
  `exit 0`; run behaviourally under pwsh over a fake redistributable tree
  (copy set, refusals, the release's `& script; $LASTEXITCODE` idiom).
- build-installer.sh stages the runtime too.

Each lexical check also runs against a mutated copy of the sources and must
fail there.
"""

import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
ISS = ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss"
STAGE = ROOT / "deploy" / "packaging" / "windows" / "stage-msvc-runtime.ps1"
BUILD_SH = ROOT / "deploy" / "packaging" / "windows" / "build-installer.sh"
CHECKER = ROOT / "scripts" / "ci" / "check-windows-payload-imports.py"

_spec = importlib.util.spec_from_file_location("check_windows_payload_imports", CHECKER)
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)

CHECK_STEP = "Check the DLL import closure of both payloads"
RUNTIME_LINE = 'Source: "{#BuildDir}\\msvc-runtime\\*.dll"; DestDir: "{app}\\bin"; Components: core; Flags: ignoreversion'
STAGE_CALL = '& ./deploy/packaging/windows/stage-msvc-runtime.ps1 -Destination "${staging}/bin", "build-windows/msvc-runtime"'
STAGE_CHECK = 'if ($LASTEXITCODE -ne 0) { Write-Error "stage-msvc-runtime.ps1 failed"; exit 1 }'
CHECK_MUST = (
    "python scripts/ci/check-windows-payload-imports.py `",
    "--zip yuzu-agent-windows-x64.zip `",
    "--iss deploy/packaging/windows/yuzu-agent.iss `",
    "--build-dir build-windows `",
    '--system-dir "$env:SystemRoot\\System32"',
    "if ($LASTEXITCODE -ne 0) { Write-Error",
)
REQUIRED_CRT = ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_atomic_wait.dll")


# ── a minimal PE32+ writer (just enough for an import table) ────────────────

def make_pe(imports=(), delay=(), garbage=False) -> bytes:
    if garbage:
        return b"MZ" + b"\0" * 100
    va, raw = 0x1000, 0x200
    imp_size = (len(imports) + 1) * 20 if imports else 0
    dly_size = (len(delay) + 1) * 32 if delay else 0
    names_off = imp_size + dly_size
    names = b""
    name_rvas = []
    for n in list(imports) + list(delay):
        name_rvas.append(va + names_off + len(names))
        names += n.encode("ascii") + b"\0"
    sec = bytearray(names_off + len(names))
    sec[names_off:] = names
    for i, _ in enumerate(imports):
        struct.pack_into("<IIIII", sec, 20 * i, 0, 0, 0, name_rvas[i], 0x1)
    for j, _ in enumerate(delay):
        struct.pack_into("<IIIIIIII", sec, imp_size + 32 * j, 1, name_rvas[len(imports) + j], 0, 0, 0, 0, 0, 0)
    sec = bytes(sec) + b"\0" * (-len(sec) % 0x200)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<I", opt, 108, 16)
    if imports:
        struct.pack_into("<II", opt, 112 + 8 * 1, va, imp_size)
    if delay:
        struct.pack_into("<II", opt, 112 + 8 * 13, va + imp_size, dly_size)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, len(opt), 0x22)
    shdr = b".idata\0\0" + struct.pack("<IIIIIIHHI", len(sec), va, len(sec), raw, 0, 0, 0, 0, 0xC0000040)
    head = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + shdr
    return head + b"\0" * (raw - len(head)) + sec


OS_DLLS = ("kernel32.dll", "advapi32.dll", "ws2_32.dll")
# The runner's System32: the OS DLLs AND an installed VC++ runtime.
RUNNER_SYSTEM32 = OS_DLLS + REQUIRED_CRT


def crt_pe(name):
    if name.startswith("msvcp"):
        return make_pe(["vcruntime140.dll", "kernel32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"])
    return make_pe(["kernel32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"])


AGENT = make_pe(["yuzu_agent_core.dll", "kernel32.dll", "msvcp140.dll", "msvcp140_atomic_wait.dll",
                 "vcruntime140.dll", "vcruntime140_1.dll", "api-ms-win-crt-heap-l1-1-0.dll"])
CORE = make_pe(["kernel32.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"])
PLUGIN = make_pe(["yuzu_agent_core.dll", "fmt.dll", "advapi32.dll", "msvcp140.dll", "vcruntime140.dll"])
FMT = make_pe(["kernel32.dll", "msvcp140.dll", "vcruntime140.dll"])


class _Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_payload_imports_")
        self.tmp = Path(self._tmp.name)
        self.sysdir = self.tmp / "System32"
        self.sysdir.mkdir()
        for n in RUNNER_SYSTEM32:
            (self.sysdir / n).write_bytes(b"")

    def tearDown(self):
        self._tmp.cleanup()

    def run_check(self, *args):
        argv = list(args) + ["--system-dir", str(self.sysdir)]
        r = subprocess.run([sys.executable, "-I", str(CHECKER)] + argv, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr


class CheckerZip(_Tmp):
    def make_zip(self, files):
        path = self.tmp / "yuzu-agent-windows-x64.zip"
        with zipfile.ZipFile(path, "w") as z:
            for rel, data in files.items():
                z.writestr("yuzu-agent-9.9.9-windows-x64/" + rel, data)
        return path

    def base(self, with_crt):
        files = {"bin/yuzu-agent.exe": AGENT, "bin/yuzu_agent_core.dll": CORE, "bin/fmt.dll": FMT,
                 "plugins/os_info.dll": PLUGIN}
        if with_crt:
            files.update({f"bin/{n}": crt_pe(n) for n in REQUIRED_CRT})
        return files

    def test_v0150_shape_fails_although_system32_has_the_runtime(self):
        code, out = self.run_check("--zip", str(self.make_zip(self.base(False))))
        self.assertEqual(code, 1, out)
        for n in REQUIRED_CRT:
            self.assertIn(f"Visual C++ runtime DLL {n} is imported but not in bin", out)

    def test_runtime_in_bin_passes(self):
        code, out = self.run_check("--zip", str(self.make_zip(self.base(True))))
        self.assertEqual(code, 0, out)
        self.assertIn("C++ runtime in bin\\: msvcp140.dll, msvcp140_atomic_wait.dll, vcruntime140.dll, vcruntime140_1.dll", out)

    def test_one_runtime_dll_missing_fails(self):
        files = self.base(True)
        del files["bin/msvcp140_atomic_wait.dll"]
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("msvcp140_atomic_wait.dll is imported but not in bin", out)
        self.assertNotIn("vcruntime140.dll is imported", out)

    def test_runtime_dll_imported_by_a_plugin_only(self):
        files = self.base(True)
        files["plugins/x.dll"] = make_pe(["kernel32.dll", "concrt140.dll"])
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("concrt140.dll is imported but not in bin\\ (needed by plugins\\x.dll)", out)

    def test_third_party_dll_missing_and_delay_load(self):
        files = self.base(True)
        files["plugins/x.dll"] = make_pe(["kernel32.dll", "libxml2.dll"], delay=["zlib1.dll"])
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("DLL libxml2.dll is imported but not in bin", out)
        self.assertIn("DLL zlib1.dll is imported but not in bin", out)
        files["bin/libxml2.dll"] = make_pe(["kernel32.dll"])
        files["bin/zlib1.dll"] = make_pe(["kernel32.dll"])
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 0, out)

    def test_plugin_dependency_in_plugins_dir_is_not_enough(self):
        files = self.base(True)
        files["plugins/x.dll"] = make_pe(["kernel32.dll", "helper.dll"])
        files["plugins/helper.dll"] = make_pe(["kernel32.dll"])
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("helper.dll is imported but not in bin", out)

    def test_debug_runtime_fails_even_when_shipped(self):
        files = self.base(True)
        files["plugins/x.dll"] = make_pe(["kernel32.dll", "MSVCP140D.dll"])
        files["bin/msvcp140d.dll"] = make_pe(["kernel32.dll"])
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("debug C++ runtime MSVCP140D.dll", out)

    def test_unreadable_and_empty_binaries_fail(self):
        for name, data, msg in (("garbage", make_pe(garbage=True), "not a readable PE image"),
                                ("noimports", make_pe([]), "no imports read")):
            with self.subTest(name):
                files = self.base(True)
                files[f"plugins/{name}.dll"] = data
                code, out = self.run_check("--zip", str(self.make_zip(files)))
                self.assertEqual(code, 1, out)
                self.assertIn(msg, out)

    def test_empty_payloads_fail(self):
        files = self.base(True)
        del files["bin/yuzu-agent.exe"]
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("bin\\yuzu-agent.exe is missing", out)
        files = self.base(True)
        del files["plugins/os_info.dll"]
        code, out = self.run_check("--zip", str(self.make_zip(files)))
        self.assertEqual(code, 1, out)
        self.assertIn("plugins\\ holds no plugin DLL", out)


class CheckerIss(_Tmp):
    """The .iss mode, against the REAL yuzu-agent.iss over a synthetic build tree."""

    def build_tree(self, stage_runtime=True):
        bd = self.tmp / "build-windows"
        files = chk.iss_files_section(ISS.read_text(encoding="utf-8"))
        for line in files.splitlines():
            m = re.match(r'^\s*Source:\s*"\{#BuildDir\}\\([^"]+)"', line)
            if not m:
                continue
            rel = m.group(1).replace("\\", "/")
            if rel == "agents/core/*.dll":
                (bd / "agents/core").mkdir(parents=True, exist_ok=True)
                (bd / "agents/core/yuzu_agent_core.dll").write_bytes(CORE)
                (bd / "agents/core/fmt.dll").write_bytes(FMT)
            elif rel == "msvc-runtime/*.dll":
                if stage_runtime:
                    (bd / "msvc-runtime").mkdir(parents=True, exist_ok=True)
                    for n in REQUIRED_CRT:
                        (bd / "msvc-runtime" / n).write_bytes(crt_pe(n))
            elif "*" in rel:
                self.fail(f"the .iss has a wildcard Source line this test does not model: {rel}")
            else:
                f = bd / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(AGENT if f.name == "yuzu-agent.exe" else PLUGIN)
        return bd

    def test_real_iss_with_runtime_staged_passes(self):
        bd = self.build_tree(True)
        code, out = self.run_check("--iss", str(ISS), "--build-dir", str(bd))
        self.assertEqual(code, 0, out)
        self.assertIn("C++ runtime in bin\\: msvcp140.dll", out)

    def test_real_iss_without_runtime_staged_fails(self):
        bd = self.build_tree(False)
        code, out = self.run_check("--iss", str(ISS), "--build-dir", str(bd))
        self.assertEqual(code, 1, out)
        self.assertIn("msvc-runtime", out)
        self.assertIn("matches no file", out)

    def test_iss_model_refusals(self):
        bd = self.build_tree(True)
        text = ISS.read_text(encoding="utf-8")
        cases = {
            "bin file under a deselectable component": (RUNTIME_LINE, RUNTIME_LINE.replace("Components: core", "Components: plugins\\system"), "not core"),
            "an unmodelled flag": (RUNTIME_LINE, RUNTIME_LINE.replace("ignoreversion", "ignoreversion skipifsourcedoesntexist"), "unsupported parameter or flag"),
            "runtime line dropped": (RUNTIME_LINE + "\n", "", "is imported but not in bin"),
        }
        for name, (old, new, msg) in cases.items():
            with self.subTest(name):
                self.assertTrue(old in text, f"anchor for {name!r} not found")
                mutant = self.tmp / f"mutant-{abs(hash(name))}.iss"
                mutant.write_text(text.replace(old, new, 1), encoding="utf-8")
                code, out = self.run_check("--iss", str(mutant), "--build-dir", str(bd))
                self.assertEqual(code, 1, out)
                self.assertIn(msg, out)


# ── lexical wiring ──────────────────────────────────────────────────────────

def job_block(text, job):
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", text, re.S | re.M)
    return m.group(1) if m else ""


def step_block(job, name):
    m = re.search(rf"^([ ]*)- name: {re.escape(name)}\n.*?(?=^\1- |\Z)", job, re.S | re.M)
    return m.group(0) if m else ""


def code_lines(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("#", ";")))


def wiring_problems(release, iss, stage, build_sh):
    found = []
    win = job_block(release, "build-windows")
    if not win:
        return ["release.yml: build-windows job not found"]
    pkg = step_block(win, "Package archive")
    pkg_code = code_lines(pkg)
    if STAGE_CALL not in pkg_code:
        found.append("Package archive: does not stage the runtime into the zip's bin/ and build-windows/msvc-runtime")
    elif STAGE_CHECK not in pkg_code:
        found.append("Package archive: the runtime staging exit code is not checked")
    elif not (pkg_code.find(STAGE_CALL) < pkg_code.find(STAGE_CHECK) < pkg_code.find("Compress-Archive")):
        found.append("Package archive: the runtime is not staged (and checked) before Compress-Archive")
    if "continue-on-error" in pkg:
        found.append("Package archive: must gate (no continue-on-error)")

    if win.count(f"- name: {CHECK_STEP}") != 1:
        found.append(f"build-windows: expected exactly one `{CHECK_STEP}` step")
    chk_step = step_block(win, CHECK_STEP)
    if chk_step:
        if "continue-on-error" in chk_step:
            found.append(f"`{CHECK_STEP}` must gate (no continue-on-error)")
        if re.search(r"^\s*if:", chk_step, re.M):
            found.append(f"`{CHECK_STEP}` must run unconditionally (no `if:`)")
        if not re.search(r"^\s*timeout-minutes:\s*\d+\s*$", chk_step, re.M):
            found.append(f"`{CHECK_STEP}` has no step timeout")
        code = code_lines(chk_step)
        for must in CHECK_MUST:
            if must not in code:
                found.append(f"`{CHECK_STEP}` lost: {must}")
        pos = win.find(f"- name: {CHECK_STEP}")
        if not (0 <= win.find("- name: Package archive") < pos):
            found.append(f"`{CHECK_STEP}` must run after Package archive")
        for later in ("- name: Build Windows installers", "- name: Sign installers", "- name: Attest Windows provenance",
                      "- name: Upload archive artifact"):
            if not (0 <= pos < win.find(later)):
                found.append(f"`{CHECK_STEP}` must run before `{later[8:]}`")
    # --build-dir is the directory ISCC packs from.
    if '"/DBuildDir=${{ github.workspace }}\\build-windows"' not in win:
        found.append("Build Windows installers: /DBuildDir is no longer workspace\\build-windows; update --build-dir")

    iss_code = code_lines(iss)
    if sum(1 for l in iss_code.splitlines() if l.strip() == RUNTIME_LINE) != 1:
        found.append("yuzu-agent.iss: the msvc-runtime Source line (core, {app}\\bin, no skipifsourcedoesntexist) is missing")
    if re.search(r"msvc-runtime[^\n]*skipifsourcedoesntexist", iss_code, re.I):
        found.append("yuzu-agent.iss: the runtime line may be skipped when unstaged")

    stage_code = re.sub(r"<#.*?#>", "", stage, flags=re.S)
    stage_code = "\n".join(l for l in stage_code.splitlines() if not l.lstrip().startswith("#"))
    m = re.search(r"^\$Required = @\(([^)]*)\)", stage_code, re.M)
    req = set(re.findall(r"'([^']+)'", m.group(1))) if m else set()
    for n in REQUIRED_CRT:
        if n not in req:
            found.append(f"stage-msvc-runtime.ps1: {n} is not required")
    if re.search(r"vcvars", stage_code, re.I):
        found.append("stage-msvc-runtime.ps1 names vcvars (docs/windows-build.md: never vcvars64.bat)")
    if "$env:VCToolsRedistDir" not in stage_code:
        found.append("stage-msvc-runtime.ps1 no longer reads VCToolsRedistDir")
    if not re.search(r"^exit 0\s*$", stage_code.rstrip().splitlines()[-1] if stage_code.strip() else "", re.M):
        found.append("stage-msvc-runtime.ps1 must end with `exit 0` (release.yml tests $LASTEXITCODE)")
    if "Get-AuthenticodeSignature" not in stage_code:
        found.append("stage-msvc-runtime.ps1 no longer checks the Microsoft signature on Windows")

    if not re.search(r'^\s*"\$PWSH" -NoProfile -ExecutionPolicy Bypass -File "\$WIN_STAGE" -Destination "\$WIN_RUNTIME_DIR"\s*$',
                     build_sh, re.M):
        found.append("build-installer.sh no longer stages the runtime")
    return found


class Wiring(unittest.TestCase):
    def setUp(self):
        self.srcs = {"release": RELEASE.read_text(encoding="utf-8"), "iss": ISS.read_text(encoding="utf-8"),
                     "stage": STAGE.read_text(encoding="utf-8"), "build_sh": BUILD_SH.read_text(encoding="utf-8")}

    def test_source_is_clean(self):
        self.assertEqual(wiring_problems(**self.srcs), [])

    def test_mutations_are_caught(self):
        mutations = {
            "staging dropped": ("release", STAGE_CALL + "\n", ""),
            "staging commented out": ("release", STAGE_CALL, "# " + STAGE_CALL),
            "zip destination dropped": ("release", STAGE_CALL, STAGE_CALL.replace('"${staging}/bin", ', "")),
            "installer destination dropped": ("release", STAGE_CALL, STAGE_CALL.replace(', "build-windows/msvc-runtime"', "")),
            "staging exit unchecked": ("release", STAGE_CHECK, "$null = 0"),
            "staging after Compress-Archive": ("release", STAGE_CALL + "\n          " + STAGE_CHECK + "\n\n          Compress-Archive -Path \"${staging}\" -DestinationPath \"yuzu-agent-windows-x64.zip\"",
                                               "Compress-Archive -Path \"${staging}\" -DestinationPath \"yuzu-agent-windows-x64.zip\"\n          " + STAGE_CALL + "\n          " + STAGE_CHECK),
            "check step removed": ("release", f"      - name: {CHECK_STEP}\n", "      - name: Something else\n"),
            "check step non-gating": ("release", f"      - name: {CHECK_STEP}\n        shell: pwsh\n", f"      - name: {CHECK_STEP}\n        shell: pwsh\n        continue-on-error: true\n"),
            "check step conditional": ("release", f"      - name: {CHECK_STEP}\n        shell: pwsh\n", f"      - name: {CHECK_STEP}\n        if: ${{{{ false }}}}\n        shell: pwsh\n"),
            "check step loses the zip": ("release", "            --zip yuzu-agent-windows-x64.zip `\n", ""),
            "check step loses the installer payload": ("release", "            --iss deploy/packaging/windows/yuzu-agent.iss `\n", ""),
            "check step exit unchecked": ("release", 'if ($LASTEXITCODE -ne 0) { Write-Error "a shipped binary', 'if ($false) { Write-Error "a shipped binary'),
            "check step after the installer": ("release", "      - name: Sign installers (Authenticode)\n", f"      - name: Sign installers (Authenticode)\n        run: echo\n\n      - name: {CHECK_STEP}\n"),
            "ISCC BuildDir moved": ("release", '"/DBuildDir=${{ github.workspace }}\\build-windows"', '"/DBuildDir=${{ github.workspace }}\\build-win"'),
            "iss runtime line dropped": ("iss", RUNTIME_LINE, "; removed"),
            "iss runtime line skippable": ("iss", RUNTIME_LINE, RUNTIME_LINE.replace("ignoreversion", "ignoreversion skipifsourcedoesntexist")),
            "iss runtime line deselectable": ("iss", RUNTIME_LINE, RUNTIME_LINE.replace("Components: core", "Components: plugins")),
            "stage stops requiring atomic_wait": ("stage", ", 'msvcp140_atomic_wait.dll')", ")"),
            "stage calls vcvars": ("stage", "function Find-VersionDirFromVswhere {", "function Find-VersionDirFromVswhere {\n    & cmd /c vcvars64.bat"),
            "stage loses exit 0": ("stage", "\nexit 0\n", "\n"),
            "stage drops the signature check": ("stage", "Get-AuthenticodeSignature", "Get-Item"),
            "build-installer stops staging": ("build_sh", '"$PWSH" -NoProfile -ExecutionPolicy Bypass -File "$WIN_STAGE" -Destination "$WIN_RUNTIME_DIR"', "true"),
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                srcs = dict(self.srcs)
                self.assertTrue(old in srcs[which], f"mutation anchor for {name!r} not found")
                srcs[which] = srcs[which].replace(old, new, 1)
                self.assertNotEqual(wiring_problems(**srcs), [], f"{name!r} was not caught")


# ── the staging script under pwsh ───────────────────────────────────────────

def find_pwsh():
    exe = shutil.which("pwsh")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", "'ok'"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return exe if r.returncode == 0 and "ok" in r.stdout else None


_PWSH = find_pwsh()
_REQUIRE_PWSH = os.environ.get("YUZU_REQUIRE_PWSH_TEST") == "1"


class _PrereqCheck(unittest.TestCase):
    def test_pwsh_present_when_required(self):
        if not _REQUIRE_PWSH:
            self.skipTest("YUZU_REQUIRE_PWSH_TEST is not set")
        self.assertTrue(_PWSH, "YUZU_REQUIRE_PWSH_TEST=1 but no working pwsh on PATH")


@unittest.skipUnless(_PWSH, "no working pwsh on PATH")
class StageScriptBehaviour(_Tmp):
    def redist(self, version="14.44.35112", files=REQUIRED_CRT + ("msvcp140_1.dll", "vcruntime140_threads.dll",
                                                                  "concrt140.dll", "vccorlib140.dll"), crt_dirs=("Microsoft.VC143.CRT",)):
        vdir = self.tmp / "Redist" / "MSVC" / version
        for d in crt_dirs:
            crt = vdir / "x64" / d
            crt.mkdir(parents=True)
            for n in files:
                (crt / n).write_bytes(n.encode())
        (vdir / "x64" / "Microsoft.VC143.OpenMP").mkdir(parents=True, exist_ok=True)
        return vdir

    def run_stage(self, args, env_extra=None, wrapper=False):
        env = {k: v for k, v in os.environ.items() if k not in ("VCToolsRedistDir", "VCToolsVersion")}
        env.update(env_extra or {})
        if wrapper:
            # As release.yml calls it: a pwsh step (stop on error) that runs the
            # script with & and then tests $LASTEXITCODE.
            dests = ", ".join(f"'{d}'" for d in args["dest"])
            script = self.tmp / "step.ps1"
            script.write_text("$ErrorActionPreference = 'stop'\n"
                              f"& '{STAGE}' -Destination {dests} {args.get('extra', '')}\n"
                              "if ($LASTEXITCODE -ne 0) { Write-Error 'stage failed'; exit 1 }\n"
                              "Write-Host 'AFTER-STAGE'\n", encoding="utf-8")
            cmd = [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)]
        else:
            # As build-installer.sh calls it: one destination, by -File.
            cmd = [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(STAGE), "-Destination", *args["dest"]]
            cmd += args.get("argv", [])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
        # pwsh renders an error in colour and wraps it behind "| " gutters:
        # flatten that so a message can be matched as one line.
        out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
        out = re.sub(r"[ \t]*\n[ \t]*(?:\|[ \t]*)?", " ", out)
        return r.returncode, out

    def test_copies_the_runtime_family_to_every_destination(self):
        vdir = self.redist()
        d1, d2 = self.tmp / "zip" / "bin", self.tmp / "build-windows" / "msvc-runtime"
        code, out = self.run_stage({"dest": [str(d1), str(d2)], "extra": f"-RedistDir '{vdir}'"}, wrapper=True)
        self.assertEqual(code, 0, out)
        want = sorted(REQUIRED_CRT + ("msvcp140_1.dll", "vcruntime140_threads.dll"))
        for d in (d1, d2):
            self.assertEqual(sorted(p.name for p in d.iterdir()), want, out)
            self.assertEqual((d / "msvcp140.dll").read_bytes(), b"msvcp140.dll")

    def test_env_redist_dir_and_release_idiom(self):
        vdir = self.redist()
        d1 = self.tmp / "out"
        code, out = self.run_stage({"dest": [str(d1)]}, {"VCToolsRedistDir": str(vdir) + os.sep,
                                                          "VCToolsVersion": "14.44.35207"}, wrapper=True)
        self.assertEqual(code, 0, out)
        self.assertIn("AFTER-STAGE", out)
        self.assertIn("(VCToolsRedistDir)", out)
        self.assertTrue((d1 / "vcruntime140_1.dll").is_file())

    def test_refusals(self):
        cases = {
            "required DLL missing": (dict(files=REQUIRED_CRT[:3]), {}, "msvcp140_atomic_wait.dll is not in"),
            "two CRT directories": (dict(crt_dirs=("Microsoft.VC142.CRT", "Microsoft.VC143.CRT")), {}, "need exactly one"),
            "no CRT directory": (dict(crt_dirs=()), {}, "need exactly one"),
            "redistributable older than the toolset": ({}, {"VCToolsVersion": "14.45.35000"}, "older than the toolset"),
        }
        for name, (kw, env, msg) in cases.items():
            with self.subTest(name):
                sub = self.tmp / re.sub(r"\W+", "_", name)
                sub.mkdir()
                old_tmp, self.tmp = self.tmp, sub
                try:
                    vdir = self.redist(**kw)
                    dest = sub / "out"
                    code, out = self.run_stage({"dest": [str(dest)], "extra": f"-RedistDir '{vdir}'"},
                                               env, wrapper=True)
                finally:
                    self.tmp = old_tmp
                self.assertNotEqual(code, 0, out)
                self.assertNotIn("AFTER-STAGE", out)
                self.assertIn(msg, out)
                self.assertFalse(dest.exists() and any(dest.iterdir()), f"{name}: copied something before refusing")

    def test_single_destination_by_file_as_build_installer_does(self):
        vdir = self.redist()
        dest = self.tmp / "msvc-runtime"
        code, out = self.run_stage({"dest": [str(dest)], "argv": ["-RedistDir", str(vdir)]})
        self.assertEqual(code, 0, out)
        self.assertTrue((dest / "msvcp140_atomic_wait.dll").is_file(), out)

    def test_explicit_but_wrong_source_never_falls_through(self):
        code, out = self.run_stage({"dest": [str(self.tmp / "out")]},
                                   {"VCToolsRedistDir": str(self.tmp / "nowhere")}, wrapper=True)
        self.assertNotEqual(code, 0, out)
        self.assertIn("has no x64 directory", out)
        self.assertIn("VCToolsRedistDir gives", out)
        self.assertNotIn("vswhere", out)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
