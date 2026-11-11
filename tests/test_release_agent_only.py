#!/usr/bin/env python3
"""Regression net for agent-only Windows and macOS releases (ADR-0035 ladder steps 2 and 3).

The server is supported on Linux only. release.yml runs only on a tag, so a
regression in its Windows or macOS job, or a disagreement between the archive
names its jobs produce and the names later steps expect, would first show up
in a real release, after an hour of builds. These checks read the source text
instead. Stdlib only; no network, no Windows, no macOS.

What they pin:

- The `build-windows` and `build-macos` jobs of release.yml each configure
  with exactly one literal `-Dserver=disabled` (step 3's feature option),
  never name the deprecated `build_server` in code, never set `server` to
  anything else and never run `meson configure`. Their vcpkg install carries
  `--x-no-default-features` and asks for no `server` feature, so the
  server-only ports (libpq, xmlsec, drogon) are never installed and their
  DLLs cannot reach the archive (the ci.yml/codeql/nightly twin of this pin
  is scripts/ci/test_runner_health_check.py; change both together). Their
  non-comment lines name no `yuzu-server`,
  `YuzuServerSetup`, `yuzu-server.iss` or `install-server-postgres.sh`,
  except the one exact line of the Windows archive check that FAILS on
  `yuzu-server.exe`.
- build-windows has exactly one gating "Verify the agent runs from the
  packaged archive" step (no continue-on-error, a step timeout), after
  Package archive and before the installers, attestation and upload, and it
  keeps each of its checks (VERIFY_MUST). build-macos signs and notarizes
  `build-macos/agents/core/yuzu-agent` and checks the notarization verdict.
- The release job's `gh release create` list attaches no `YuzuServerSetup`;
  scripts/check-release-artifacts.sh requires none and its FORBIDDEN_GLOBS
  refuses it and both old archive names.
- The old Windows and macOS archive names (`yuzu-windows-x64`,
  `yuzu-macos-arm64`, which held the server) appear nowhere in release.yml's
  code (the release-notes text may name them, to tell users about the rename)
  or in scripts/check-release-artifacts.sh.
- ONE set of platform archive names, agreed by every place that names them:
  the archive each build job writes (`tar czf` / `Compress-Archive`), uploads
  (`upload-artifact` `path:`) and attests (`subject-path`); the release job's
  attach list; check-release-artifacts.sh's REQUIRED_ARCHIVES; and every
  platform SBOM, whose stem must match an archive (release.yml `output-file`
  against SBOM_BASES). scripts/build-agent-bundle.sh must request, and prefer,
  the current Windows and macOS names (it also accepts the old ones, for a
  hand-run against an older tag), and must use the resolved names for
  verification and extraction.

Each check is also run against a mutated copy of the sources and must fail
there, so a check that stops matching anything cannot pass silently.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CHECK = ROOT / "scripts" / "check-release-artifacts.sh"
BUNDLE = ROOT / "scripts" / "build-agent-bundle.sh"

OLD_ARCHIVES = ("yuzu-windows-x64", "yuzu-macos-arm64")
SERVER_TOKENS = ("yuzu-server", "YuzuServerSetup", "yuzu-server.iss", "install-server-postgres.sh")
ARCHIVE_RE = r"yuzu-[a-z0-9-]+\.(?:zip|tar\.gz)"
# The one line allowed to name the server in build-windows: the packaged-archive
# check that FAILS the job if yuzu-server.exe is in the agent archive. Matched
# whole, so an inverted or weakened copy of it is not exempt.
ABSENCE_CHECK = re.compile(
    r'^\s*if \(Test-Path \(Join-Path \$bin "yuzu-server\.exe"\)\) '
    r'\{ Write-Error "yuzu-server\.exe found in the agent archive"; exit 1 \}\s*$')
VERIFY_STEP = "Verify the agent runs from the packaged archive"
# What the Verify step must keep doing (a weakened copy must fail this test).
VERIFY_MUST = (
    'Expand-Archive -Path "yuzu-agent-windows-x64.zip"',
    'if (-not (Test-Path $agent)) { Write-Error',
    'if ($built -lt 1 -or $packed -ne $built) { Write-Error',
    '$env:PATH = "$env:SystemRoot\\System32;$env:SystemRoot"',
    '-ArgumentList "--help"',
    'if (-not $p.WaitForExit(60000)) { $p.Kill(); Write-Error',
    'if ($p.ExitCode -ne 0) { Write-Error',
)
OLD_NAME_RE = re.compile(r"(?<![a-z0-9-])(?:" + "|".join(map(re.escape, OLD_ARCHIVES)) + r")\b")


def job_block(text: str, job: str) -> str:
    """The body of a top-level job in release.yml, up to the next job."""
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", text, re.S | re.M)
    if not m:
        raise AssertionError(f"job {job!r} not found in release.yml")
    return m.group(1)


def code_lines(text: str) -> str:
    """Drop whole-line comments (YAML, shell and PowerShell all use #)."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def without_forbidden_list(text: str) -> str:
    """check-release-artifacts.sh with its FORBIDDEN_GLOBS array and refusal
    message removed: that list names the retired assets on purpose."""
    text = re.sub(r"^FORBIDDEN_GLOBS=\(.*?^\)", "", text, flags=re.S | re.M)
    return "\n".join(l for l in text.splitlines() if "release must not carry" not in l)


def step_block(job: str, name: str) -> str:
    """One step of a job, from its `- name:` line to the next step."""
    m = re.search(rf"^([ ]*)- name: {re.escape(name)}\n.*?(?=^\1- |\Z)", job, re.S | re.M)
    return m.group(0) if m else ""


def without_release_notes(text: str) -> str:
    """release.yml with the release-notes heredoc removed: the notes may name
    the old archives deliberately, to tell users about the rename."""
    return re.sub(r"<<NOTES_EOF\n.*?^\s*NOTES_EOF\s*$", "", text, flags=re.S | re.M)


def bash_array(text: str, name: str) -> list:
    m = re.search(rf"^{name}=\((.*?)^\)", text, re.S | re.M)
    if not m:
        raise AssertionError(f"{name} not found")
    return re.findall(r'^\s*"([^"]+)"', m.group(1), re.M)


def literal(names) -> set:
    return {n for n in names if "$" not in n and "*" not in n}


def problems(release: str, check: str, bundle: str) -> list:
    found = []

    # 1. The Windows and macOS jobs build and ship the agent only.
    for job in ("build-windows", "build-macos"):
        try:
            body = code_lines(job_block(release, job))
        except AssertionError as e:
            found.append(str(e))
            continue
        setups = re.findall(r"meson setup .*?(?=\n\s*\n|\n\s*- name:|\Z)", body, re.S)
        if len(setups) != 1:
            found.append(f"{job}: expected one `meson setup`, found {len(setups)}")
        for s in setups:
            n = len(re.findall(r"-Dserver=disabled(?![\w=-])", s))
            if n != 1:
                found.append(f"{job}: its meson setup carries {n} `-Dserver=disabled`, expected exactly 1")
        # The switch appears once in the job, only as `disabled`, never from an
        # expression; the deprecated boolean is gone from code; nothing
        # reconfigures the build dir later.
        if len(re.findall(r"-Dserver=", body)) != 1:
            found.append(f"{job}: `-Dserver=` must appear exactly once (in its meson setup, as disabled)")
        if re.search(r"-Dserver=(?!disabled(?![\w=-]))", body):
            found.append(f"{job}: sets -Dserver to something other than the literal disabled")
        if "build_server" in body:
            found.append(f"{job}: names the deprecated `build_server` in code; use -Dserver=disabled")
        if re.search(r"\bmeson\s+configure\b", body):
            found.append(f"{job}: runs `meson configure`, which could re-enable the server")
        # The vcpkg install is the agent-only profile: no server ports.
        installs = re.findall(r"vcpkg(?:\.exe)?\"? install\b.*?(?=\n\s*\n|\n\s*- name:|\Z)", body, re.S)
        if len(installs) != 1:
            found.append(f"{job}: expected one vcpkg install, found {len(installs)}")
        for inst in installs:
            if "--x-no-default-features" not in inst:
                found.append(f"{job}: its vcpkg install lacks --x-no-default-features, so it installs the server ports")
            if re.search(r"--x-feature=server\b", inst):
                found.append(f"{job}: its vcpkg install asks for the server feature")
        scan = "\n".join(l for l in body.splitlines() if not ABSENCE_CHECK.match(l))
        for tok in SERVER_TOKENS:
            if tok in scan:
                found.append(f"{job}: a non-comment line names {tok} (the Windows/macOS release is agent-only, ADR-0035)")

    # 1b. The Windows packaged-archive check gates, in the right place.
    try:
        win = job_block(release, "build-windows")
    except AssertionError:
        win = ""
    verify = step_block(win, VERIFY_STEP)
    if win.count(f"- name: {VERIFY_STEP}") > 1:
        found.append(f"build-windows: more than one `{VERIFY_STEP}` step")
    if not verify:
        found.append(f"build-windows: the `{VERIFY_STEP}` step is missing")
    else:
        if "continue-on-error" in verify:
            found.append(f"build-windows: `{VERIFY_STEP}` must gate (no continue-on-error)")
        if re.search(r"^\s*if:", verify, re.M):
            found.append(f"build-windows: `{VERIFY_STEP}` must run unconditionally (no `if:`)")
        if not re.search(r"^\s*timeout-minutes:\s*\d+\s*$", verify, re.M):
            found.append(f"build-windows: `{VERIFY_STEP}` has no step timeout")
        if not any(ABSENCE_CHECK.match(l) for l in verify.splitlines()):
            found.append(f"build-windows: `{VERIFY_STEP}` no longer fails on yuzu-server.exe in the archive")
        for must in VERIFY_MUST:
            if must not in verify:
                found.append(f"build-windows: `{VERIFY_STEP}` lost: {must}")
        pos = win.find(f"- name: {VERIFY_STEP}")
        pkg = win.find("- name: Package archive")
        if not (0 <= pkg < pos):
            found.append(f"build-windows: `{VERIFY_STEP}` must run after `Package archive`")
        for later in ("- name: Build Windows installers", "- name: Sign installers", "- name: Attest Windows provenance",
                      "- name: Upload archive artifact"):
            if not (0 <= pos < win.find(later)):
                found.append(f"build-windows: `{VERIFY_STEP}` must run before `{later[8:]}`")

    # 1c. macOS signs and notarizes the agent's real path and checks the verdict.
    try:
        mac = code_lines(job_block(release, "build-macos"))
    except AssertionError:
        mac = ""
    if "for binary in build-macos/agents/core/yuzu-agent; do" not in mac:
        found.append("build-macos: the codesign loop does not sign build-macos/agents/core/yuzu-agent")
    if not re.search(r'zip -j "\$\{NOTARIZE_ZIP\}" \\\n\s*build-macos/agents/core/yuzu-agent\n', mac):
        found.append("build-macos: the notarization zip does not hold build-macos/agents/core/yuzu-agent")
    if 'if [ "${STATUS}" != "Accepted" ]; then' not in mac:
        found.append("build-macos: the notarization verdict is not checked")

    # 2. The release job attaches no server installer.
    m = re.search(r'gh release create "\$\{GITHUB_REF_NAME\}".*?(?=\n\s*fi\b)', release, re.S)
    attach = m.group(0) if m else ""
    if not attach:
        found.append("release.yml: `gh release create` attach list not found")
    if "YuzuServerSetup" in attach:
        found.append("release.yml: the release job still attaches YuzuServerSetup")

    # A required asset the release no longer builds would fail every release;
    # the retired assets must be refused instead.
    check_code = code_lines(without_forbidden_list(check))
    if "YuzuServerSetup" in check_code:
        found.append("check-release-artifacts.sh still requires or names YuzuServerSetup outside FORBIDDEN_GLOBS")
    try:
        forbidden = set(bash_array(check, "FORBIDDEN_GLOBS"))
    except AssertionError:
        forbidden = set()
    for pat in ("YuzuServerSetup-*",) + tuple(f"{o}.*" for o in OLD_ARCHIVES):
        if pat not in forbidden:
            found.append(f"check-release-artifacts.sh FORBIDDEN_GLOBS does not refuse {pat}")

    # 3. The old archive names are gone from the code.
    for where, text in (("release.yml", code_lines(without_release_notes(release))),
                        ("check-release-artifacts.sh", check_code)):
        for line in text.splitlines():
            if OLD_NAME_RE.search(line):
                found.append(f"{where}: still names an old archive: {line.strip()}")

    # 4. One set of archive names everywhere.
    produced = literal(re.findall(rf'(?:tar czf|-DestinationPath)\s+"({ARCHIVE_RE})"', release))
    uploaded = literal(re.findall(rf"^\s+path:\s+({ARCHIVE_RE})\s*$", release, re.M))
    attested = set()
    for block in re.findall(r"subject-path:\s*\|\n((?:\s{12,}\S.*\n)+)", release):
        attested |= literal(re.findall(rf"^\s+({ARCHIVE_RE})\s*$", block, re.M))
    attached = literal(re.findall(rf"artifacts/({ARCHIVE_RE})", attach))
    try:
        required = set(bash_array(check, "REQUIRED_ARCHIVES"))
        sbom_bases = set(bash_array(check, "SBOM_BASES"))
    except AssertionError as e:
        found.append(f"check-release-artifacts.sh: {e}")
        required, sbom_bases = set(), set()
    sets = {"produced (tar czf / Compress-Archive)": produced, "uploaded (upload-artifact path)": uploaded,
            "attested (subject-path)": attested, "attached (gh release create)": attached,
            "required (REQUIRED_ARCHIVES)": required}
    reference = required or attached
    for label, s in sets.items():
        if s != reference:
            found.append(f"archive names disagree: {label} = {sorted(s)} vs {sorted(reference)}")
    for os_tag in ("windows-x64", "macos-arm64"):
        if f"yuzu-agent-{os_tag}" not in {re.sub(r"\.(zip|tar\.gz)$", "", n) for n in reference}:
            found.append(f"no yuzu-agent-{os_tag} archive in the agreed set {sorted(reference)}")
    stems = {re.sub(r"\.(zip|tar\.gz)$", "", n) for n in reference}
    platform_sboms = literal(re.findall(r"output-file:\s+(yuzu-[a-z0-9-]+)\.(?:cdx|spdx)\.json", release))
    platform_sboms = {s for s in platform_sboms if not s.endswith("-image")}
    platform_bases = {b for b in sbom_bases if not b.endswith("-image")}
    if platform_sboms != stems:
        found.append(f"release.yml platform SBOM stems {sorted(platform_sboms)} do not match the archives {sorted(stems)}")
    if platform_bases != stems:
        found.append(f"SBOM_BASES platform entries {sorted(platform_bases)} do not match the archives {sorted(stems)}")

    # 5. The bundle script requests and prefers the current names.
    requested = literal(re.findall(rf"-p '({ARCHIVE_RE})'", bundle))
    current = {n for n in requested if not OLD_NAME_RE.search(n)}
    if not current or not current <= reference:
        found.append(f"build-agent-bundle.sh requests {sorted(current)}, not all in {sorted(reference)}")
    for os_tag, ext in (("windows-x64", "zip"), ("macos-arm64", "tar.gz")):
        new = f"yuzu-agent-{os_tag}.{ext}"
        if new not in requested:
            found.append(f"build-agent-bundle.sh does not request {new}")
        pick = re.search(rf"\"\$\(pick '{re.escape(new)}'\)\"; \[ -n \"\$(\w+)\" \] \|\| \1=", bundle)
        if not pick:
            found.append(f"build-agent-bundle.sh does not try {new} before the old name")
    # ...and actually USES the resolved names (not a hard-coded old one).
    bundle_code = code_lines(bundle)
    for must in ('ARCHIVES="yuzu-linux-x64.tar.gz $WIN_ZIP $MAC_TGZ"',
                 'extract_payload windows-x64 "$WIN_ZIP" zip',
                 'extract_payload macos-arm64 "$MAC_TGZ" tar',
                 '[ -n "$WIN_ZIP" ] || die "no Windows archive on $TAG"',
                 '[ -n "$MAC_TGZ" ] || die "no macOS archive on $TAG"'):
        if must not in bundle_code:
            found.append(f"build-agent-bundle.sh lost: {must}")
    return found


class ReleaseAgentOnly(unittest.TestCase):
    def setUp(self):
        self.release = RELEASE.read_text(encoding="utf-8")
        self.check = CHECK.read_text(encoding="utf-8")
        self.bundle = BUNDLE.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.release, self.check, self.bundle), [])

    def test_mutations_are_caught(self):
        mutations = {
            "windows server flag dropped": ("release", "-Dbuild_tests=false `\n            -Dserver=disabled", "-Dbuild_tests=false"),
            "macos server flag dropped": ("release", "            -Dserver=disabled \\\n            -Db_lto=true", "            -Db_lto=true"),
            "windows server flag doubled": ("release", "-Dserver=disabled\n", "-Dserver=disabled `\n            -Dserver=disabled\n"),
            "windows server flag auto": ("release", "-Dbuild_tests=false `\n            -Dserver=disabled", "-Dbuild_tests=false `\n            -Dserver=auto"),
            "macos back to deprecated boolean": ("release", "            -Dserver=disabled \\\n            -Db_lto=true", "            -Dbuild_server=false \\\n            -Db_lto=true"),
            "windows deprecated boolean alongside": ("release", "-Dbuild_tests=false `\n            -Dserver=disabled", "-Dbuild_tests=false `\n            -Dbuild_server=false `\n            -Dserver=disabled"),
            "windows server from expression": ("release", "-Dbuild_tests=false `\n            -Dserver=disabled", "-Dbuild_tests=false `\n            -Dserver=${{ inputs.server }}"),
            # Step 3: the vcpkg install is agent-only (no server ports).
            "windows vcpkg opt-out dropped": ("release", '--x-manifest-root="${{ github.workspace }}" `\n            --x-no-default-features\n', '--x-manifest-root="${{ github.workspace }}"\n'),
            "macos vcpkg opt-out dropped": ("release", "--x-manifest-root=${{ github.workspace }} \\\n            --x-no-default-features\n", "--x-manifest-root=${{ github.workspace }}\n"),
            "macos vcpkg server feature asked": ("release", "--x-manifest-root=${{ github.workspace }} \\\n            --x-no-default-features\n", "--x-manifest-root=${{ github.workspace }} \\\n            --x-no-default-features \\\n            --x-feature=server\n"),
            "windows server copy back": ("release", '          Copy-Item "build-windows/agents/core/yuzu-agent.exe"', '          Copy-Item "build-windows/server/core/yuzu-server.exe" "${staging}/bin/"\n          Copy-Item "build-windows/agents/core/yuzu-agent.exe"'),
            "macos server copy back": ("release", "          cp build-macos/agents/core/yuzu-agent \"${STAGING}/bin/\"", "          cp build-macos/server/core/yuzu-server \"${STAGING}/bin/\"\n          cp build-macos/agents/core/yuzu-agent \"${STAGING}/bin/\""),
            "server installer back": ("release", '"deploy\\packaging\\windows\\yuzu-agent.iss"', '"deploy\\packaging\\windows\\yuzu-server.iss"'),
            "postgres helper back in macOS tarball": ("release", '          tar czf "yuzu-agent-macos-arm64.tar.gz"', '          cp scripts/install-server-postgres.sh "${STAGING}/scripts/"\n          tar czf "yuzu-agent-macos-arm64.tar.gz"'),
            "server installer attached": ("release", "              artifacts/YuzuAgentSetup-*.exe \\\n", "              artifacts/YuzuAgentSetup-*.exe \\\n              artifacts/YuzuServerSetup-*.exe \\\n"),
            "windows archive typo in package step": ("release", '-DestinationPath "yuzu-agent-windows-x64.zip"', '-DestinationPath "yuzu-agent-window-x64.zip"'),
            "macos upload path typo": ("release", "path: yuzu-agent-macos-arm64.tar.gz", "path: yuzu-agent-macos-arm4.tar.gz"),
            "windows attest subject typo": ("release", "            yuzu-agent-windows-x64.zip\n            YuzuAgentSetup-*.exe", "            yuzu-agentwindows-x64.zip\n            YuzuAgentSetup-*.exe"),
            "attach list old name": ("release", "artifacts/yuzu-agent-macos-arm64.tar.gz", "artifacts/yuzu-macos-arm64.tar.gz"),
            "windows SBOM stem old": ("release", "output-file: yuzu-agent-windows-x64.cdx.json", "output-file: yuzu-windows-x64.cdx.json"),
            "required archive old name": ("check", '  "yuzu-agent-windows-x64.zip"', '  "yuzu-windows-x64.zip"'),
            "required archive dropped": ("check", '  "yuzu-agent-macos-arm64.tar.gz"\n', ""),
            "SBOM base typo": ("check", '  "yuzu-agent-macos-arm64"\n', '  "yuzu-agent-macos-arm"\n'),
            "server installer required again": ("check", '  "YuzuAgentSetup-*.exe"\n', '  "YuzuAgentSetup-*.exe"\n  "YuzuServerSetup-*.exe"\n'),
            "bundle new name typo": ("bundle", "-p 'yuzu-agent-windows-x64.zip'", "-p 'yuzu-agent-windows-x86.zip'"),
            # Step-1 conventions (C-1): an override or a reconfigure is caught.
            "windows =enabled appended": ("release", "-Dbuild_tests=false `\n            -Dserver=disabled", "-Dbuild_tests=false `\n            -Dserver=disabled `\n            -Dserver=enabled"),
            "macos =enabled appended": ("release", "            -Dserver=disabled \\\n            -Db_lto=true", "            -Dserver=disabled \\\n            -Dserver=enabled \\\n            -Db_lto=true"),
            "windows meson configure": ("release", "      - name: Build\n        run: meson compile -C build-windows", "      - name: Reconfigure\n        run: meson configure build-windows -Dbuild_tests=true\n\n      - name: Build\n        run: meson compile -C build-windows"),
            # The packaged-archive check (qe-1).
            "verify step removed": ("release", "      - name: Verify the agent runs from the packaged archive", "      - name: Something else"),
            "verify exit check dropped": ("release", "          if ($p.ExitCode -ne 0) { Write-Error", "          if ($false) { Write-Error"),
            "verify PATH restriction dropped": ("release", '          $env:PATH = "$env:SystemRoot\\System32;$env:SystemRoot"\n', ""),
            "verify agent-present check dropped": ("release", '          if (-not (Test-Path $agent)) { Write-Error "yuzu-agent.exe missing from the archive"; exit 1 }\n', ""),
            "verify server check inverted": ("release", 'if (Test-Path (Join-Path $bin "yuzu-server.exe")) { Write-Error', 'if (-not (Test-Path (Join-Path $bin "yuzu-server.exe"))) { Write-Error'),
            "verify plugin count dropped": ("release", "          if ($built -lt 1 -or $packed -ne $built) { Write-Error", "          if ($false) { Write-Error"),
            "verify made non-gating": ("release", "      - name: Verify the agent runs from the packaged archive\n        shell: pwsh\n", "      - name: Verify the agent runs from the packaged archive\n        shell: pwsh\n        continue-on-error: true\n"),
            "verify made conditional": ("release", "      - name: Verify the agent runs from the packaged archive\n        shell: pwsh\n", "      - name: Verify the agent runs from the packaged archive\n        if: ${{ false }}\n        shell: pwsh\n"),
            "package step renamed": ("release", "      - name: Package archive\n        shell: pwsh", "      - name: Package the zip\n        shell: pwsh"),
            "verify timeout dropped": ("release", "        shell: pwsh\n        timeout-minutes: 5\n", "        shell: pwsh\n"),
            "verify moved after installers": ("release", "      - name: Sign installers (Authenticode)", "      - name: Sign installers (Authenticode)\n        run: echo\n\n      - name: Verify the agent runs from the packaged archive"),
            "macos codesign path reverted": ("release", "for binary in build-macos/agents/core/yuzu-agent; do", "for binary in build-macos/yuzu-agent; do"),
            "macos notarize verdict unchecked": ("release", 'if [ "${STATUS}" != "Accepted" ]; then', 'if false; then'),
            # The bundle actually uses the resolved names (qe-2).
            "bundle ARCHIVES hard-coded old": ("bundle", 'ARCHIVES="yuzu-linux-x64.tar.gz $WIN_ZIP $MAC_TGZ"', 'ARCHIVES="yuzu-linux-x64.tar.gz yuzu-windows-x64.zip $MAC_TGZ"'),
            "bundle extract hard-coded old": ("bundle", 'extract_payload windows-x64 "$WIN_ZIP" zip', "extract_payload windows-x64 yuzu-windows-x64.zip zip"),
            "bundle die guard dropped": ("bundle", '[ -n "$MAC_TGZ" ] || die "no macOS archive on $TAG"\n', ""),
            # The artifact gate refuses retired assets (UP-6).
            "forbidden list loses server installer": ("check", '  "YuzuServerSetup-*"\n', ""),
            "forbidden list loses old macOS name": ("check", '  "yuzu-macos-arm64.*"\n', ""),
            "bundle prefers old name": ("bundle", "WIN_ZIP=\"$(pick 'yuzu-agent-windows-x64.zip')\"; [ -n \"$WIN_ZIP\" ] || WIN_ZIP=\"$(pick 'yuzu-windows-x64.zip')\"",
                                        "WIN_ZIP=\"$(pick 'yuzu-windows-x64.zip')\"; [ -n \"$WIN_ZIP\" ] || WIN_ZIP=\"$(pick 'yuzu-agent-windows-x64.zip')\""),
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                srcs = {"release": self.release, "check": self.check, "bundle": self.bundle}
                self.assertIn(old, srcs[which], f"mutation anchor for {name!r} not found")
                srcs[which] = srcs[which].replace(old, new, 1)
                self.assertNotEqual(problems(srcs["release"], srcs["check"], srcs["bundle"]), [],
                                    f"{name!r} was not caught")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
