#!/usr/bin/env python3
"""Tests for the release image vulnerability gate (WP15/S9).

scripts/ci/image-vuln-gate.sh runs a pinned Trivy on each image and must fail
CLOSED: a fixable CRITICAL, a Trivy error, a wrong Trivy version, a missing
ignore file, or an ignore entry without a reason or an expiry all fail it. The
cases here run the real script with a stub `trivy` (TRIVY_BIN) that records
its arguments and answers as told, so no Docker, network or Trivy DB is needed.

scripts/ci/image-identity.sh (pin a build by image ID, then prove the pushed
image has the scanned image's layers) runs against a stub `docker` the same way.

The WorkflowWiring cases are lexical tripwires on the workflows: every
docker-publish job in release.yml pins its build by ID, scans that ID BEFORE its
push, and checks the pushed digest before signing; pre-release.yml scans every
published image. They read the YAML as text; they prove the order of steps, not
that the steps run.
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
IDENTITY = ROOT / "scripts" / "ci" / "image-identity.sh"
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
    if image in os.environ.get("STUB_MISSING_IMAGES", "").split(","):
        # Like trivy: with `--image-src docker` an image missing from the local
        # daemon is an error; without it trivy falls back to containerd,
        # podman and then a registry, and scans (and passes) whatever it finds.
        src = args[args.index("--image-src") + 1] if "--image-src" in args else ""
        sys.exit(1 if src == "docker" else 0)
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

    def run_gate(self, *images, mode="clean", ignore=IGNORE, bad_image="", extra=(), missing=""):
        env = dict(os.environ)
        env.update(
            TRIVY_BIN=str(self.stub),
            STUB_LOG=str(self.log),
            STUB_MODE=mode,
            STUB_BAD_IMAGE=bad_image,
            STUB_MISSING_IMAGES=missing,
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

    def test_every_scan_is_local_docker_only(self):
        r = self.run_gate("img:1", "sha256:" + "a" * 64)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        scans = [c.split() for c in self.calls() if c != "--version"]
        self.assertEqual(len(scans), 4, self.calls())
        for a in scans:
            self.assertIn("--image-src", a, a)
            self.assertEqual(a[a.index("--image-src") + 1], "docker", a)

    def test_missing_local_image_fails_not_scanned_from_a_registry(self):
        r = self.run_gate("yuzu-hc-verify/server:gone", missing="yuzu-hc-verify/server:gone")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not scan", r.stderr)

    def test_image_id_report_gets_a_distinct_name(self):
        rep = self.tmp / "rep"
        r = self.run_gate("sha256:" + "b" * 64, extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((rep / ("trivy-image-" + "b" * 12 + ".txt")).is_file())

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


DOCKER_STUB = textwrap.dedent(
    """\
    import json, os, sys
    a = sys.argv[1:]
    if os.environ.get("STUB_DOCKER_FAIL"):
        sys.exit(1)
    if a[:2] == ["image", "inspect"]:
        ref = a[-1]
        if ref == "gone:1":
            sys.exit(1)
        fmt = a[a.index("--format") + 1]
        if fmt == "{{.Id}}":
            print("sha256:" + "1" * 64)
        else:
            print(json.dumps(["sha256:" + "a" * 64, "sha256:" + "b" * 64]))
        sys.exit(0)
    if a[:3] == ["buildx", "imagetools", "inspect"]:
        print(os.environ["STUB_REMOTE_JSON"])
        sys.exit(0)
    sys.exit(2)
    """
)
LAYERS = "sha256:" + "a" * 64 + ",sha256:" + "b" * 64


def cfg(*ids):
    return {"architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": list(ids)}}


@unittest.skipUnless(have_bash(), "image-identity.sh is a bash script")
class ImageIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_image_identity_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        stub = self.tmp / "docker"
        stub.write_text(f"#!{sys.executable}\n" + DOCKER_STUB, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)

    def run_id(self, *args, remote=None, fail=False):
        import json
        env = dict(os.environ)
        env["PATH"] = f"{self.tmp}{os.pathsep}{env.get('PATH', '')}"
        env["STUB_REMOTE_JSON"] = json.dumps(remote) if remote is not None else "null"
        env.pop("GITHUB_ACTIONS", None)
        if fail:
            env["STUB_DOCKER_FAIL"] = "1"
        return subprocess.run(["bash", str(IDENTITY), *args], env=env,
                              capture_output=True, text=True, timeout=60)

    def test_pin_prints_id_and_layers(self):
        r = self.run_id("pin", "yuzu-hc-verify/server:x")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines(), ["id=sha256:" + "1" * 64, "layers=" + LAYERS])

    def test_pin_of_a_missing_image_fails(self):
        self.assertEqual(self.run_id("pin", "gone:1").returncode, 1)

    def test_pushed_image_with_the_scanned_layers_passes(self):
        r = self.run_id("verify-pushed", "ghcr.io/o/i@sha256:" + "c" * 64, LAYERS,
                        remote=cfg("sha256:" + "a" * 64, "sha256:" + "b" * 64))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_pushed_image_with_other_layers_fails(self):
        r = self.run_id("verify-pushed", "ghcr.io/o/i@sha256:" + "c" * 64, LAYERS,
                        remote=cfg("sha256:" + "a" * 64, "sha256:" + "d" * 64))
        self.assertEqual(r.returncode, 1)
        self.assertIn("NOT the image that was scanned", r.stderr)

    def test_index_uses_its_linux_amd64_image(self):
        remote = {"linux/amd64": cfg("sha256:" + "a" * 64, "sha256:" + "b" * 64),
                  "linux/arm64": cfg("sha256:" + "e" * 64)}
        r = self.run_id("verify-pushed", "ghcr.io/o/i@sha256:" + "c" * 64, LAYERS, remote=remote)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_ambiguous_index_fails(self):
        remote = {"linux/arm64": cfg("sha256:" + "a" * 64), "linux/s390x": cfg("sha256:" + "b" * 64)}
        r = self.run_id("verify-pushed", "ghcr.io/o/i@sha256:" + "c" * 64, LAYERS, remote=remote)
        self.assertEqual(r.returncode, 1)

    def test_registry_error_fails(self):
        r = self.run_id("verify-pushed", "ghcr.io/o/i@sha256:" + "c" * 64, LAYERS, fail=True)
        self.assertEqual(r.returncode, 1)

    def test_tag_reference_is_refused(self):
        r = self.run_id("verify-pushed", "ghcr.io/o/i:1.0.0", LAYERS, remote=cfg("sha256:" + "a" * 64))
        self.assertEqual(r.returncode, 1)

    def test_empty_expected_layers_is_refused(self):
        r = self.run_id("verify-pushed", "ghcr.io/o/i@sha256:" + "c" * 64, "",
                        remote=cfg("sha256:" + "a" * 64))
        self.assertEqual(r.returncode, 1)


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

    def test_publish_jobs_scan_the_pinned_id_and_check_the_push(self):
        text = RELEASE.read_text(encoding="utf-8")
        for job in ("docker-publish", "docker-publish-postgres", "docker-publish-chisel",
                    "docker-publish-agent-bundle"):
            body = job_block(text, job)
            pin = body.find("scripts/ci/image-identity.sh pin")
            gate = body.find("scripts/ci/image-vuln-gate.sh")
            push = min(i for i in (body.find("push: true"), body.find("docker push")) if i != -1)
            check = body.find("scripts/ci/image-identity.sh verify-pushed")
            sign = min(i for i in (body.find("uses: anchore/sbom-action"),
                                   body.find("uses: actions/attest-build-provenance"),
                                   body.find("cosign sign --yes")) if i != -1)
            self.assertTrue(-1 < pin < gate < push < check < sign,
                            f"{job}: need pin < gate < push < verify-pushed < sbom/attest/sign")
            gate_step = body[body.rfind("- name:", 0, gate):gate]
            self.assertIn("IMAGE: ${{ steps.built.outputs.id }}", gate_step,
                          f"{job}: the gate must scan the pinned image ID, not a tag")
            self.assertIn("LAYERS: ${{ steps.built.outputs.layers }}",
                          body[body.rfind("- name:", 0, check):check], job)
        for job in ("docker-publish", "docker-publish-postgres", "docker-publish-chisel"):
            body = job_block(text, job)
            tags = re.findall(r"yuzu-hc-verify/[^\n]+", body)
            self.assertTrue(tags, job)
            for t in tags:
                self.assertIn("${{ github.run_id }}-${{ github.run_attempt }}", t,
                              f"{job}: shared-daemon scan tag {t} must be salted per run attempt")

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
