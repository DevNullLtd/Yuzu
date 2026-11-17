#!/usr/bin/env python3
"""Tests for the release image vulnerability gate (WP15/S9).

scripts/ci/image-vuln-gate.sh runs a pinned Trivy on each image and must fail
CLOSED: a fixable CRITICAL, a Trivy error, a wrong Trivy version, a missing
ignore file, or an ignore entry without a reason or an expiry all fail it. The
cases here run the real script with a stub `trivy` (TRIVY_BIN) that records
its arguments and answers as told, so no Docker, network or Trivy DB is needed.

The last two cases are lexical tripwires on the workflows: every
docker-publish job in release.yml runs the gate BEFORE its push, and
pre-release.yml scans every published image. They read the YAML as text; they
prove the order of steps, not that the steps run.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "ci" / "image-vuln-gate.sh"
IGNORE = ROOT / ".trivyignore.yaml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
PRE_RELEASE = ROOT / ".github" / "workflows" / "pre-release.yml"

PUBLISHED = [
    "yuzu-server", "yuzu-gateway", "yuzu-postgres", "yuzu-server-chisel",
    "yuzu-gateway-chisel", "yuzu-agent-chisel", "yuzu-agent-bundle-chisel",
]

STUB = textwrap.dedent(
    """\
    import os, sys
    args = sys.argv[1:]
    with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as f:
        f.write(" ".join(args) + "\\n")
    mode = os.environ.get("STUB_MODE", "clean")
    if args == ["--version"]:
        print("Version: " + ("0.69.4" if mode == "wrong-version" else "0.70.0"))
        sys.exit(0)
    image = args[-1]
    gate = "--exit-code" in args
    bad = os.environ.get("STUB_BAD_IMAGE", "")
    if bad and image != bad:
        sys.exit(0)
    if gate and mode == "findings":
        print("CRITICAL finding table")
        sys.exit(3)
    if gate and mode == "gate-error":
        sys.exit(1)
    if not gate and mode == "report-error":
        sys.exit(1)
    if "--output" in args:
        open(args[args.index("--output") + 1], "w").write("report\\n")
    sys.exit(0)
    """
)


def have_bash():
    return os.name != "nt" and shutil.which("bash") is not None


@unittest.skipUnless(have_bash(), "the gate is a bash script")
class GateBehaviour(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_vuln_gate_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / "trivy"
        self.stub.write_text(f"#!{sys.executable}\n" + STUB, encoding="utf-8")
        self.stub.chmod(self.stub.stat().st_mode | stat.S_IXUSR)
        self.log = self.tmp / "calls.log"

    def run_gate(self, *images, mode="clean", ignore=IGNORE, bad_image="", extra=()):
        env = dict(os.environ)
        env.update(
            TRIVY_BIN=str(self.stub),
            STUB_LOG=str(self.log),
            STUB_MODE=mode,
            STUB_BAD_IMAGE=bad_image,
            YUZU_TRIVYIGNORE=str(ignore),
            RUNNER_TEMP=str(self.tmp),
        )
        env.pop("GITHUB_ACTIONS", None)
        return subprocess.run(
            ["bash", str(GATE), *extra, *images],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def calls(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def write_ignore(self, body):
        p = self.tmp / "ignore.yaml"
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    def test_clean_image_passes_and_gate_scan_is_fixable_critical_only(self):
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        gate = [c for c in self.calls() if "--exit-code" in c]
        self.assertEqual(len(gate), 1, self.calls())
        g = gate[0].split()
        self.assertEqual(g[g.index("--severity") + 1], "CRITICAL")
        self.assertIn("--ignore-unfixed", g)
        self.assertEqual(g[g.index("--exit-code") + 1], "3")
        self.assertEqual(g[g.index("--ignorefile") + 1], str(IGNORE))
        self.assertEqual(g[-1], "img:1")

    def test_report_scan_covers_high_and_critical(self):
        r = self.run_gate("img:1", extra=("--report-dir", str(self.tmp / "rep")))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rep = [c for c in self.calls() if "--exit-code" not in c and c != "--version"]
        self.assertEqual(len(rep), 1, self.calls())
        self.assertIn("--severity HIGH,CRITICAL", rep[0])
        self.assertTrue((self.tmp / "rep" / "trivy-img.txt").is_file())

    def test_fixable_critical_fails(self):
        r = self.run_gate("img:1", mode="findings")
        self.assertEqual(r.returncode, 1)
        self.assertIn("fixable CRITICAL", r.stderr)

    def test_trivy_error_in_gate_scan_fails_closed(self):
        r = self.run_gate("img:1", mode="gate-error")
        self.assertEqual(r.returncode, 1)
        self.assertIn("treated as a failure", r.stderr)

    def test_trivy_error_in_report_scan_fails_closed(self):
        r = self.run_gate("img:1", mode="report-error")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not scan", r.stderr)

    def test_one_bad_image_fails_but_every_image_is_scanned(self):
        r = self.run_gate("a:1", "b:1", "c:1", mode="findings", bad_image="b:1")
        self.assertEqual(r.returncode, 1)
        scanned = {c.split()[-1] for c in self.calls() if "--exit-code" in c}
        self.assertEqual(scanned, {"a:1", "b:1", "c:1"})

    def test_wrong_trivy_version_is_refused(self):
        r = self.run_gate("img:1", mode="wrong-version")
        self.assertEqual(r.returncode, 1)
        self.assertFalse([c for c in self.calls() if c.endswith("img:1")])

    def test_missing_ignore_file_is_refused(self):
        r = self.run_gate("img:1", ignore=self.tmp / "absent.yaml")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.calls(), [])

    def test_entry_without_expiry_is_refused(self):
        p = self.write_ignore("""\
            vulnerabilities:
              - id: CVE-2000-0001
                statement: not reachable
            """)
        r = self.run_gate("img:1", ignore=p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("needs both", r.stderr)

    def test_entry_without_statement_is_refused(self):
        p = self.write_ignore("""\
            vulnerabilities:
              - id: CVE-2000-0001
                expired_at: 2027-01-01
            """)
        r = self.run_gate("img:1", ignore=p)
        self.assertEqual(r.returncode, 1)

    def test_complete_entries_are_accepted(self):
        p = self.write_ignore("""\
            vulnerabilities:
              - id: CVE-2000-0001
                paths:
                  - "usr/bin/x"
                statement: >-
                  not reachable
                expired_at: 2027-01-01
              - id: CVE-2000-0002
                statement: not reachable either
                expired_at: 2027-01-02
            """)
        r = self.run_gate("img:1", ignore=p)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_repo_ignore_file_is_well_formed(self):
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_image_is_a_usage_error(self):
        r = self.run_gate()
        self.assertEqual(r.returncode, 2)


def job_block(text, job):
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S)
    if not m:
        raise AssertionError(f"job {job} not found")
    # Comments are prose (they mention --push and the gate); only steps count.
    return "\n".join(ln for ln in m.group(1).splitlines() if not ln.lstrip().startswith("#"))


class WorkflowWiring(unittest.TestCase):
    def test_every_publish_job_gates_before_its_push(self):
        text = RELEASE.read_text(encoding="utf-8")
        jobs = re.findall(r"^  (docker-publish[A-Za-z0-9_-]*):\n", text, re.M)
        self.assertEqual(
            sorted(jobs),
            ["docker-publish", "docker-publish-agent-bundle",
             "docker-publish-chisel", "docker-publish-postgres"],
            "a new publish job needs the gate before its push (and this list)",
        )
        for job in jobs:
            body = job_block(text, job)
            gate = body.find("scripts/ci/image-vuln-gate.sh")
            self.assertNotEqual(gate, -1, f"{job}: no image-vuln-gate step")
            pushes = [i for i in (body.find("push: true"), body.find("docker push"),
                                  body.find("--push")) if i != -1]
            self.assertTrue(pushes, f"{job}: no push found")
            self.assertLess(gate, min(pushes), f"{job}: the gate must run before the push")

    def test_cached_publish_builds_refresh_packages_every_attempt(self):
        # The Big Tam publish jobs build with a persistent local cache; without
        # a per-attempt YUZU_PACKAGE_REFRESH the upgrade / chisel-cut layer is
        # served from an earlier release's cache and the image goes stale.
        text = RELEASE.read_text(encoding="utf-8")
        arg = "YUZU_PACKAGE_REFRESH=${{ github.run_id }}-${{ github.run_attempt }}"
        for job in ("docker-publish", "docker-publish-postgres", "docker-publish-chisel"):
            body = job_block(text, job)
            builds = body.count("docker/build-push-action@")
            self.assertGreaterEqual(builds, 2, job)
            self.assertEqual(body.count(arg), builds, f"{job}: every build must pass {arg}")
        for name in ("Dockerfile.server", "Dockerfile.gateway", "Dockerfile.postgres",
                     "Dockerfile.server.chisel", "Dockerfile.gateway.chisel",
                     "Dockerfile.agent.chisel"):
            df = (ROOT / "deploy" / "docker" / name).read_text(encoding="utf-8")
            self.assertIn("ARG YUZU_PACKAGE_REFRESH=", df, name)
            self.assertIn('"package refresh: ${YUZU_PACKAGE_REFRESH}"', df, name)

    def test_pre_release_scans_every_published_image(self):
        body = job_block(PRE_RELEASE.read_text(encoding="utf-8"), "security-scan")
        self.assertIn("scripts/ci/image-vuln-gate.sh", body)
        for name in PUBLISHED:
            self.assertGreaterEqual(body.count(name), 2, f"{name}: not pulled and scanned")


if __name__ == "__main__":
    unittest.main()
