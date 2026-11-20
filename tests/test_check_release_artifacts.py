#!/usr/bin/env python3
"""Regression net for scripts/check-release-artifacts.sh (#5242).

The release job runs that script before SHA256SUMS and `gh release create`.
Its expected SBOM set must include the three chisel images now that
docker-publish-chisel is in the release job's needs; while it was not, rc2,
rc4 and rc6 published without some of those SBOMs and nothing went red.

These tests read the script's own SBOM_BASES, check it names every chisel
image, run the real script against a synthetic complete artifacts directory
(it must pass), then remove each expected SBOM in turn (it must fail and name
the file). Since S8 every .deb/.rpm/.exe/.pkg also needs its own SBOM pair,
and an SBOM that belongs to no artifact of the release is refused. Stdlib
only; needs a POSIX bash, so it skips on Windows.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-release-artifacts.sh"
VERSION = "0.14.0-rc9"

ARCHIVES = ["yuzu-linux-x64.tar.gz", "yuzu-gateway-linux-x64.tar.gz",
            "yuzu-agent-windows-x64.zip", "yuzu-agent-macos-arm64.tar.gz"]
PACKAGES = ["yuzu-server_0.14.0-rc9_amd64.deb", "yuzu-server-0.14.0-0.1.rc9.x86_64.rpm",
            "YuzuAgentSetup-0.14.0_rc9.exe",
            "YuzuAgent-0.14.0_rc9-arm64.pkg"]
CHISEL = ["yuzu-server-chisel-image", "yuzu-gateway-chisel-image", "yuzu-agent-chisel-image"]


def script_sbom_bases() -> list:
    """The SBOM_BASES array as the script declares it, so this test cannot
    drift from it."""
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"^SBOM_BASES=\((.*?)^\)", text, re.S | re.M).group(1)
    return re.findall(r'^\s*"([^"]+)"', block, re.M)


def script_gate_report_images() -> list:
    """The GATE_REPORT_IMAGES array as the script declares it (WP15/S9)."""
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"^GATE_REPORT_IMAGES=\((.*?)^\)", text, re.S | re.M).group(1)
    return re.findall(r'^\s*"([^"]+)"', block, re.M)


LABELS = ["none", "push-started", "verified", "signed-attested", "tagging", "tagged"]


def journal_text(img: str, attempt: int, upto: str = "tagged", digest: str = "a" * 64) -> str:
    """A legal publish journal (scripts/ci/image-publish.sh) ending at `upto`."""
    repo = f"ghcr.io/o/{img}"
    tags = f"{repo}:0.14.0-rc9"
    lines = {"none": "publish: none",
             "push-started": f"publish: push-started {repo}",
             "verified": f"publish: verified {repo}@sha256:{digest}",
             "signed-attested": f"publish: signed-attested {repo}@sha256:{digest}",
             "tagging": f"publish: tagging {tags} sha256:{digest}",
             "tagged": f"publish: tagged {tags} sha256:{digest}"}
    return "".join(lines[l] + "\n" for l in LABELS[:LABELS.index(upto) + 1])


def write_reports(d: Path, img: str, attempt: int, verdict: str = "pass", scanner: str = "trivy",
                  upto=None) -> None:
    """One attempt's gate reports; with `upto`, its publish journal too. A
    passing Trivy attempt gets a `tagged` journal unless upto says otherwise
    (`upto=""`: no journal)."""
    stem = f"{scanner}-{img}.attempt-{attempt}"
    (d / f"{stem}.json").write_text(json.dumps({"ArtifactName": img}))
    (d / f"{stem}.txt").write_text("table\n")
    (d / f"{stem}.gate.txt").write_text(f"image: {img}\nrun attempt: {attempt}\ngate: {verdict}\n")
    if upto is None and scanner == "trivy" and verdict == "pass":
        upto = "tagged"
    if upto:
        (d / f"publish-{img}.attempt-{attempt}.txt").write_text(journal_text(img, attempt, upto, f"{attempt:x}" * 64))


def make_artifacts(d: Path) -> None:
    for name in ARCHIVES + PACKAGES:
        (d / name).write_bytes(b"x")
    for base in script_sbom_bases() + [package_stem(p) for p in PACKAGES]:
        for fmt in ("cdx.json", "spdx.json"):
            (d / f"{base}.{fmt}").write_text(json.dumps({"name": base}))
    for img in script_gate_report_images():
        write_reports(d, img, 1)


def package_stem(name: str) -> str:
    return name.rsplit(".", 1)[0]


# Not on Windows: there `bash` resolves to the WSL stub, which refuses to run as
# LOCAL SYSTEM on the CI runners (ci.yml). Linux CI and Docs Lint cover it.
@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class CheckReleaseArtifacts(unittest.TestCase):
    def run_script(self, d: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), str(d), VERSION],
                              capture_output=True, text=True)

    def test_script_expects_every_chisel_sbom(self):
        self.assertTrue(set(CHISEL) <= set(script_sbom_bases()), script_sbom_bases())

    def test_complete_set_passes(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            r = self.run_script(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_each_missing_sbom_fails(self):
        for base in script_sbom_bases():
            for fmt in ("cdx.json", "spdx.json"):
                with self.subTest(sbom=f"{base}.{fmt}"), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                    d = Path(t)
                    make_artifacts(d)
                    (d / f"{base}.{fmt}").unlink()
                    r = self.run_script(d)
                    self.assertNotEqual(r.returncode, 0, f"{base}.{fmt} missing but the gate passed")
                    self.assertIn(f"missing SBOM: {base}.{fmt}", r.stderr)

    def test_each_missing_package_sbom_fails(self):
        for pkg in PACKAGES:
            for fmt in ("cdx.json", "spdx.json"):
                sbom = f"{package_stem(pkg)}.{fmt}"
                with self.subTest(sbom=sbom), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                    d = Path(t)
                    make_artifacts(d)
                    (d / sbom).unlink()
                    r = self.run_script(d)
                    self.assertNotEqual(r.returncode, 0, f"{sbom} missing but the gate passed")
                    self.assertIn(f"missing SBOM for {pkg}: {sbom}", r.stderr)

    def test_orphan_sbom_is_refused(self):
        # An SBOM for a package this release does not carry (a leftover from an
        # earlier build) would be signed into SHA256SUMS: refuse it.
        # Both formats, and a stem of each package kind, so neither the
        # *.spdx.json glob nor one extension's lookup can quietly drop out.
        for orphan in ("yuzu-agent_0.14.0-rc8_amd64.cdx.json", "yuzu-agent_0.14.0-rc8_amd64.spdx.json",
                       "yuzu-server-0.14.0-0.1.rc8.x86_64.spdx.json", "YuzuAgentSetup-0.14.0_rc8.cdx.json",
                       "YuzuAgent-0.14.0_rc8-arm64.spdx.json"):
            with self.subTest(orphan=orphan), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / orphan).write_text("{}")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, f"orphan SBOM {orphan} present but the gate passed")
                self.assertIn(f"file={orphan}::SBOM describes no artifact of this release", r.stderr)

    def test_retired_assets_are_refused(self):
        # ADR-0035 step 2: a server installer or an old-name Windows/macOS
        # archive or SBOM must fail the gate, not be hashed into SHA256SUMS.
        for stray in ("YuzuServerSetup-0.14.0_rc9.exe", "yuzu-windows-x64.zip",
                      "yuzu-macos-arm64.tar.gz", "yuzu-windows-x64.cdx.json"):
            with self.subTest(stray=stray), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / stray).write_bytes(b"x")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, f"{stray} present but the gate passed")
                self.assertIn(f"release must not carry {stray}", r.stderr)



@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class GateReports(unittest.TestCase):
    """WP15/S9: the six pre-release images' gate reports are release assets."""

    def run_script(self, d: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), str(d), VERSION],
                              capture_output=True, text=True)

    def test_expects_a_report_for_every_image_with_a_release_sbom(self):
        images = {b[:-len("-image")] for b in script_sbom_bases() if b.endswith("-image")}
        self.assertEqual(set(script_gate_report_images()), images)

    def test_each_missing_report_fails(self):
        for img in script_gate_report_images():
            for suffix in ("json", "txt", "gate.txt"):
                with self.subTest(report=f"trivy-{img}.attempt-1.{suffix}"), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                    d = Path(t)
                    make_artifacts(d)
                    (d / f"trivy-{img}.attempt-1.{suffix}").unlink()
                    r = self.run_script(d)
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn(f"trivy-{img}.attempt-1.{suffix}", r.stdout + r.stderr)

    def test_an_image_with_no_report_at_all_fails(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            for f in [*d.glob("trivy-yuzu-postgres.*"), *d.glob("publish-yuzu-postgres.*")]:
                f.unlink()
            r = self.run_script(d)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("missing image vulnerability gate report: trivy-yuzu-postgres.attempt-<N>", r.stderr)

    def test_a_report_without_a_pass_fails(self):
        # The published attempt's journal sits beside a refusal: illegal.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            (d / "trivy-yuzu-server.attempt-1.gate.txt").write_text("gate: FAIL: fixable CRITICAL\n")
            self.assertNotEqual(self.run_script(d).returncode, 0)

    def test_any_failing_gate_line_fails_even_beside_a_pass(self):
        # A second scanner's verdict appended to the same file, or its own
        # file (grype-*), must be read: `gate: pass` alone is not enough.
        for name, text in (
                ("trivy-yuzu-server.attempt-1.gate.txt", "gate: pass\ngrype gate: FAIL: fixable CRITICAL\n"),
                ("trivy-yuzu-server.attempt-1.gate.txt", "gate: pass\ngate: FAIL: fixable CRITICAL\n"),
                ("trivy-yuzu-server.attempt-1.gate.txt", "gate: FAIL: x\ngate: pass\n"),
                ("trivy-yuzu-server.attempt-1.gate.txt", "gate: pass\ngate: skipped\n"),
                ("grype-yuzu-gateway.attempt-1.gate.txt", "gate: FAIL: fixable CRITICAL\n"),
                ("grype-yuzu-gateway.attempt-1.gate.txt", "image: x\n")):
            with self.subTest(name=name, text=text), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / name).write_text(text)
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn(name, r.stderr)

    def test_a_passing_second_scanner_report_is_accepted(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            (d / "grype-yuzu-gateway.attempt-1.gate.txt").write_text("image: yuzu-gateway\ngate: pass\n")
            (d / "grype-yuzu-gateway.attempt-1.json").write_text("{}")
            r = self.run_script(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_second_scanner_json_must_parse(self):
        if shutil.which("jq") is None:
            self.skipTest("jq not installed (the script skips the JSON check too)")
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            (d / "grype-yuzu-gateway.attempt-1.json").write_text("{not json")
            self.assertNotEqual(self.run_script(d).returncode, 0)

    def test_only_the_published_attempts_json_is_judged(self):
        # G8P6-unhappy-path-2: a truncated report of an attempt that is not the
        # published one (a scan killed by its deadline) is that attempt's
        # evidence, reported and kept; refusing it would fail every re-run. The
        # published attempt's reports must parse.
        if shutil.which("jq") is None:
            self.skipTest("jq not installed (the script skips the JSON check too)")
        for broken, scanner, want_rc in ((1, "trivy", 0), (1, "grype", 0), (2, "trivy", 1), (2, "grype", 1)):
            with self.subTest(attempt=broken, scanner=scanner), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / "publish-yuzu-postgres.attempt-1.txt").unlink()
                write_reports(d, "yuzu-postgres", 1, "FAIL: cancelled (SIGTERM) before this image was judged")
                write_reports(d, "yuzu-postgres", 2)
                if scanner == "grype":
                    (d / f"grype-yuzu-postgres.attempt-{broken}.gate.txt").write_text(
                        "gate: pass\n" if broken == 2 else "gate: FAIL: x\n")
                name = f"{scanner}-yuzu-postgres.attempt-{broken}.json"
                (d / name).write_text('{"SchemaVersion": 2, "Results": [')
                r = self.run_script(d)
                self.assertEqual(r.returncode, want_rc, r.stdout + r.stderr)
                self.assertIn(name, r.stderr)
                if want_rc == 0:
                    self.assertIn("kept as that attempt's evidence", r.stderr)
                else:
                    self.assertIn("gate report of the published attempt is not valid JSON", r.stderr)

    def test_journal_refusals_reach_the_log_under_actions(self):
        # G8P6-consistency-auditor-1: image-publish.sh's diagnostics go to
        # stderr (an ::error:: annotation under Actions), which this script
        # does not capture, so the reason a journal was refused is in the log.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            (d / "publish-yuzu-postgres.attempt-1.txt").write_text("publish: tagged x\n")
            r = subprocess.run(["bash", str(SCRIPT), str(d), VERSION], capture_output=True, text=True,
                               env={**os.environ, "GITHUB_ACTIONS": "true"})
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("::error::publish-yuzu-postgres.attempt-1.txt is not a legal publish journal", r.stderr)
            (d / "publish-yuzu-postgres.attempt-1.txt").write_text(journal_text("yuzu-postgres", 1))
            (d / "trivy-yuzu-postgres.attempt-1.gate.txt").write_text("gate: FAIL: x\n")
            r = subprocess.run(["bash", str(SCRIPT), str(d), VERSION], capture_output=True, text=True,
                               env={**os.environ, "GITHUB_ACTIONS": "true"})
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("has a publish journal but its gate did not pass", r.stderr)

    # ── The publish journal decides which attempt is published ──
    def test_refused_earlier_attempt_is_kept_beside_the_passing_one(self):
        # postgres refused in attempt 1, published by attempt 2 ("Re-run failed
        # jobs"); the other legs published in attempt 1 and were not re-run.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            (d / "publish-yuzu-postgres.attempt-1.txt").unlink()
            write_reports(d, "yuzu-postgres", 1, "FAIL: fixable CRITICAL")
            write_reports(d, "yuzu-postgres", 2)
            r = self.run_script(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("yuzu-postgres: published by attempt 2", r.stdout)

    def test_cancelled_or_refused_earlier_attempt_with_only_a_verdict_is_accepted(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            for f in d.glob("*yuzu-postgres.attempt-1.*"):
                f.unlink()
            (d / "trivy-yuzu-postgres.attempt-1.gate.txt").write_text(
                "gate: FAIL: cancelled (SIGTERM) before this image was judged\n")
            write_reports(d, "yuzu-postgres", 3)
            r = self.run_script(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_higher_attempt_that_never_tagged_leaves_the_published_one(self):
        # G8P4-security-guardian-2: the highest attempt is not necessarily the
        # published image. A later refusal, or a later attempt stopped before
        # its tags moved, leaves attempt 1 published (attempt 10 > 9
        # numerically, not as text).
        for low, high, verdict, upto in ((1, 2, "FAIL: fixable CRITICAL", ""),
                                         (9, 10, "pass", ""),
                                         (1, 2, "pass", "push-started"),
                                         (1, 2, "pass", "signed-attested")):
            with self.subTest(high=high, verdict=verdict, upto=upto), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                for f in d.glob("*yuzu-postgres.attempt-1.*"):
                    f.unlink()
                write_reports(d, "yuzu-postgres", low)
                write_reports(d, "yuzu-postgres", high, verdict, upto=upto)
                r = self.run_script(d)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn(f"yuzu-postgres: published by attempt {low}", r.stdout)

    def test_a_higher_attempt_stopped_while_tagging_fails(self):
        for low_upto in ("tagged", "verified"):
            with self.subTest(low=low_upto), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / "publish-yuzu-postgres.attempt-1.txt").write_text(
                    journal_text("yuzu-postgres", 1, low_upto, "1" * 64))
                write_reports(d, "yuzu-postgres", 2, upto="tagging")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("stopped while moving its tags", r.stderr)

    def test_no_tagged_attempt_fails(self):
        for upto in ("", "none", "signed-attested"):
            with self.subTest(upto=upto), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / "publish-yuzu-postgres.attempt-1.txt").unlink()
                if upto:
                    (d / "publish-yuzu-postgres.attempt-1.txt").write_text(journal_text("yuzu-postgres", 1, upto))
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("no attempt's publish journal ends 'publish: tagged'", r.stderr)

    def test_an_illegal_journal_fails(self):
        good = journal_text("yuzu-postgres", 1)
        ls = good.splitlines()
        for label, text in (("swapped", "\n".join(ls[:2] + [ls[3], ls[2]] + ls[4:]) + "\n"),
                            ("no intent", "\n".join(l for l in ls if "push-started" not in l) + "\n"),
                            ("no tagging", "\n".join(l for l in ls if "tagging" not in l) + "\n"),
                            ("two digests", good.replace("a" * 64, "b" * 64, 1)),
                            ("other repo", good.replace("ghcr.io/o/yuzu-postgres:", "ghcr.io/o/yuzu-server:")),
                            ("truncated", good[:-1]),
                            ("empty", "")):
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / "publish-yuzu-postgres.attempt-1.txt").write_text(text)
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("not a legal publish journal", r.stderr)

    def test_the_published_attempt_needs_all_three_reports(self):
        for suffix in ("json", "txt"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                write_reports(d, "yuzu-postgres", 2)
                (d / f"trivy-yuzu-postgres.attempt-2.{suffix}").write_text("")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(f"trivy-yuzu-postgres.attempt-2.{suffix}", r.stderr)

    def test_a_gate_report_not_named_per_attempt_is_refused(self):
        for stray in ("trivy-yuzu-server.gate.txt", "trivy-yuzu-server.json", "grype-yuzu-gateway.gate.txt",
                      "trivy-yuzu-server.attempt-0.gate.txt", "trivy-yuzu-server.attempt-x.gate.txt",
                      "trivy-yuzu-server.attempt-1.html", "publish-yuzu-server.txt",
                      "publish-yuzu-server.attempt-1.json"):
            with self.subTest(stray=stray), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / stray).write_text("gate: pass\n")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn(f"{stray} is not a gate report named", r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
