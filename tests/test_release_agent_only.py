#!/usr/bin/env python3
"""Regression net for agent-only Windows and macOS releases (ADR-0035 ladder step 2).

The server is supported on Linux only. release.yml runs only on a tag, so a
regression in its Windows or macOS job, or a disagreement between the archive
names its jobs produce and the names later steps expect, would first show up
in a real release, after an hour of builds. These checks read the source text
instead. Stdlib only; no network, no Windows, no macOS.

What they pin:

- The `build-windows` and `build-macos` jobs of release.yml each configure
  with exactly one `-Dbuild_server=false` (ladder step 3 renames the switch to
  the `server` feature option; change this test with it), and their
  non-comment lines name no `yuzu-server`, `YuzuServerSetup`,
  `yuzu-server.iss` or `install-server-postgres.sh`.
- The release job's `gh release create` list attaches no `YuzuServerSetup`,
  and scripts/check-release-artifacts.sh does not require one.
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
  hand-run against an older tag).

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
# check that FAILS the job if yuzu-server.exe is in the agent archive.
ABSENCE_CHECK = "yuzu-server.exe found in the agent archive"
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
            n = len(re.findall(r"-Dbuild_server=false\b", s))
            if n != 1:
                found.append(f"{job}: its meson setup carries {n} `-Dbuild_server=false`, expected exactly 1")
        scan = "\n".join(l for l in body.splitlines() if ABSENCE_CHECK not in l)
        for tok in SERVER_TOKENS:
            if tok in scan:
                found.append(f"{job}: a non-comment line names {tok} (the Windows/macOS release is agent-only, ADR-0035)")

    # 2. The release job attaches no server installer.
    m = re.search(r'gh release create "\$\{GITHUB_REF_NAME\}".*?(?=\n\s*fi\b)', release, re.S)
    attach = m.group(0) if m else ""
    if not attach:
        found.append("release.yml: `gh release create` attach list not found")
    if "YuzuServerSetup" in attach:
        found.append("release.yml: the release job still attaches YuzuServerSetup")

    # A required asset the release no longer builds would fail every release.
    if "YuzuServerSetup" in code_lines(check):
        found.append("check-release-artifacts.sh still requires or names YuzuServerSetup, which no release builds")

    # 3. The old archive names are gone from the code.
    for where, text in (("release.yml", code_lines(without_release_notes(release))),
                        ("check-release-artifacts.sh", code_lines(check))):
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
            "windows server flag dropped": ("release", "-Dbuild_tests=false `\n            -Dbuild_server=false", "-Dbuild_tests=false"),
            "macos server flag dropped": ("release", "            -Dbuild_server=false \\\n            -Db_lto=true", "            -Db_lto=true"),
            "windows server flag doubled": ("release", "-Dbuild_server=false\n", "-Dbuild_server=false `\n            -Dbuild_server=false\n"),
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
