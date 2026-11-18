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

import datetime
import json
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
NOT_COVERED = ROOT / "scripts" / "ci" / "image-vuln-gate-not-covered.txt"
CHECKS = ROOT / "scripts" / "ci" / "image-vuln-gate-checks.py"

STUB = textwrap.dedent(
    """\
    import datetime, json, os, sys
    args = sys.argv[1:]
    env_trivy = sorted(k for k in os.environ if k.startswith("TRIVY_"))
    with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as f:
        f.write(" ".join(args) + "\\n")
    with open(os.environ["STUB_LOG"] + ".env", "a", encoding="utf-8") as f:
        f.write(json.dumps({"trivy_env": env_trivy, "tmpdir": os.environ.get("TMPDIR", "")}) + "\\n")
    mode = os.environ.get("STUB_MODE", "clean")
    if args == ["--version"]:
        print("Version: " + ("0.69.4" if mode == "wrong-version" else "0.70.0"))
        sys.exit(0)
    def opt(name):
        return args[args.index(name) + 1] if name in args else ""
    if args[0] == "image" and "--download-db-only" in args:
        if mode == "db-error":
            sys.exit(1)
        db = os.path.join(opt("--cache-dir"), "db")
        os.makedirs(db, exist_ok=True)
        meta = os.path.join(db, "metadata.json")
        state = os.environ.get("STUB_DB", "fresh")
        if state == "missing":
            if os.path.exists(meta):
                os.remove(meta)
            sys.exit(0)
        if state == "garbage":
            open(meta, "w").write("not json")
            sys.exit(0)
        now = datetime.datetime.now(datetime.timezone.utc)
        age = {"fresh": 2, "stale": 100, "future": -5}[state]
        t = (now - datetime.timedelta(hours=age)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        open(meta, "w").write(json.dumps({"Version": 2, "UpdatedAt": t, "DownloadedAt": t}))
        sys.exit(0)
    if args[0] == "convert":
        if mode == "convert-error":
            sys.exit(1)
        open(opt("--output"), "w").write("table\\n")
        sys.exit(0)
    image = args[-1]
    gate = "--exit-code" in args
    if image in os.environ.get("STUB_MISSING_IMAGES", "").split(","):
        # Like trivy: with `--image-src docker` an image missing from the local
        # daemon is an error; without it trivy falls back to containerd,
        # podman and then a registry, and scans (and passes) whatever it finds.
        sys.exit(1 if opt("--image-src") == "docker" else 0)
    bad = os.environ.get("STUB_BAD_IMAGE", "")
    is_bad = not bad or image == bad
    if gate and is_bad and mode == "findings":
        print("CRITICAL finding table")
        sys.exit(3)
    if gate and is_bad and mode == "gate-error":
        sys.exit(1)
    if not gate and is_bad and mode == "report-error":
        sys.exit(1)
    if not gate:
        pkgs = os.environ.get("STUB_OS_PKGS", "5")
        if pkgs == "none":
            report = {"Metadata": {"ImageID": "sha256:" + "9" * 64}, "Results": []}
        else:
            report = {"Metadata": {"ImageID": "sha256:" + "9" * 64,
                                   "OS": {"Family": "debian", "Name": "12.15"}},
                      "Results": [{"Target": image, "Class": "os-pkgs", "Type": "debian",
                                   "Packages": [{"Name": "p%d" % i} for i in range(int(pkgs))]}]}
        open(opt("--output"), "w").write(json.dumps(report))
    sys.exit(0)
    """
)


def have_bash():
    return os.name != "nt" and shutil.which("bash") is not None


def days(n):
    return (datetime.date.today() + datetime.timedelta(days=n)).isoformat()


def entry(**over):
    """One well-formed ignore entry, as YAML lines at the file's indentation."""
    f = {"id": "CVE-2000-0001", "paths": ['"usr/bin/x"'], "statement": "not reachable",
         "expired_at": days(30), "approved_by": "some-login"}
    f.update(over)
    out = [f"  - id: {f['id']}"]
    for k in ("paths", "purls"):
        if f.get(k):
            out.append(f"    {k}:")
            out += [f"      - {v}" for v in f[k]]
    for k in ("statement", "expired_at", "approved_by"):
        if f.get(k) is not None:
            out.append(f"    {k}: {f[k]}")
    return "\n".join(out) + "\n"


@unittest.skipUnless(have_bash(), "the gate is a bash script")
class GateBehaviour(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_vuln_gate_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / "trivy"
        self.stub.write_text(f"#!{sys.executable}\n" + STUB, encoding="utf-8")
        self.stub.chmod(self.stub.stat().st_mode | stat.S_IXUSR)
        self.log = self.tmp / "calls.log"

    def run_gate(self, *images, mode="clean", ignore=IGNORE, bad_image="", extra=(), missing="",
                 db="fresh", os_pkgs="5", env_extra=None):
        env = dict(os.environ)
        for k in list(env):
            if k.startswith("TRIVY_"):
                del env[k]
        env.update(
            TRIVY_BIN=str(self.stub),
            STUB_LOG=str(self.log),
            STUB_MODE=mode,
            STUB_BAD_IMAGE=bad_image,
            STUB_MISSING_IMAGES=missing,
            STUB_DB=db,
            STUB_OS_PKGS=os_pkgs,
            YUZU_TRIVYIGNORE=str(ignore),
            RUNNER_TEMP=str(self.tmp),
        )
        env.update(env_extra or {})
        env.pop("GITHUB_ACTIONS", None)
        env.pop("GITHUB_STEP_SUMMARY", None)
        return subprocess.run(
            ["bash", str(GATE), *extra, *images],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def calls(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def scans(self):
        """The image scans: not --version, not the DB download, not convert."""
        return [c.split() for c in self.calls()
                if c.startswith("image ") and "--download-db-only" not in c]

    def write_ignore(self, body):
        p = self.tmp / "ignore.yaml"
        p.write_text(body, encoding="utf-8")
        return p

    # ── the scans ──
    def test_clean_image_passes_and_gate_scan_is_fixable_critical_only(self):
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        gate = [c for c in self.scans() if "--exit-code" in c]
        self.assertEqual(len(gate), 1, self.calls())
        g = gate[0]
        self.assertEqual(g[g.index("--severity") + 1], "CRITICAL")
        self.assertIn("--ignore-unfixed", g)
        self.assertEqual(g[g.index("--exit-code") + 1], "3")
        self.assertEqual(g[g.index("--ignorefile") + 1], str(IGNORE))
        self.assertEqual(g[-1], "img:1")

    def test_report_scan_covers_high_and_critical_with_accepted_findings(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        report = [c for c in self.scans() if "--exit-code" not in c]
        self.assertEqual(len(report), 1, self.calls())
        a = report[0]
        self.assertEqual(a[a.index("--severity") + 1], "HIGH,CRITICAL")
        self.assertIn("--show-suppressed", a)
        self.assertEqual(a[a.index("--format") + 1], "json")
        self.assertNotIn("--quiet", a, "the record scan's log names the OS and warns on no packages")
        for suffix in (".json", ".txt", ".gate.txt"):
            self.assertTrue((rep / f"trivy-img{suffix}").is_file(), suffix)
        gate_txt = (rep / "trivy-img.gate.txt").read_text(encoding="utf-8")
        for field in ("image id: sha256:" + "9" * 64, "trivy: 0.70.0", "trivy db: UpdatedAt ",
                      "os packages scanned: 5", "coverage: covered", "gate: pass"):
            self.assertIn(field, gate_txt)

    def test_every_scan_is_local_docker_only_and_uses_the_one_db(self):
        r = self.run_gate("img:1", "sha256:" + "a" * 64)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        scans = self.scans()
        self.assertEqual(len(scans), 4, self.calls())
        for a in scans:
            self.assertEqual(a[a.index("--image-src") + 1], "docker", a)
            self.assertIn("--skip-db-update", a)
        downloads = [c for c in self.calls() if "--download-db-only" in c]
        self.assertEqual(len(downloads), 1, self.calls())
        self.assertIn("--db-repository mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2",
                      downloads[0])

    def test_missing_local_image_fails_not_scanned_from_a_registry(self):
        r = self.run_gate("yuzu-hc-verify/server:gone", missing="yuzu-hc-verify/server:gone")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not scan", r.stderr)

    def test_image_id_report_gets_a_distinct_name(self):
        rep = self.tmp / "rep"
        r = self.run_gate("sha256:" + "b" * 64, extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((rep / ("trivy-image-" + "b" * 12 + ".txt")).is_file())

    def test_name_prefix_names_the_report_and_is_not_scanned(self):
        rep = self.tmp / "rep"
        r = self.run_gate("yuzu-server=sha256:" + "c" * 64, extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((rep / "trivy-yuzu-server.json").is_file())
        self.assertEqual({a[-1] for a in self.scans()}, {"sha256:" + "c" * 64})

    def test_two_images_with_one_name_are_refused(self):
        r = self.run_gate("ghcr.io/a/x:1", "ghcr.io/b/x:2")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("two images named", r.stderr)

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

    def test_table_conversion_error_fails_closed(self):
        r = self.run_gate("img:1", mode="convert-error")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not scan", r.stderr)

    def test_one_bad_image_fails_but_every_image_is_scanned(self):
        r = self.run_gate("a:1", "b:1", "c:1", mode="findings", bad_image="b:1")
        self.assertEqual(r.returncode, 1)
        scanned = {a[-1] for a in self.scans() if "--exit-code" in a}
        self.assertEqual(scanned, {"a:1", "b:1", "c:1"})

    def test_wrong_trivy_version_is_refused(self):
        r = self.run_gate("img:1", mode="wrong-version")
        self.assertEqual(r.returncode, 1)
        self.assertFalse(self.scans())

    def test_no_image_is_a_usage_error(self):
        r = self.run_gate()
        self.assertEqual(r.returncode, 2)

    # ── K2: an image whose OS packages Trivy cannot see is not a pass ──
    def test_zero_os_packages_fails_unless_listed(self):
        r = self.run_gate("ghcr.io/o/yuzu-foo:1", os_pkgs="0")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("NOT scanned", r.stderr)

    def test_no_os_detected_fails_unless_listed(self):
        r = self.run_gate("ghcr.io/o/yuzu-foo:1", os_pkgs="none")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_bare_image_id_with_zero_packages_cannot_match_the_list(self):
        r = self.run_gate("sha256:" + "d" * 64, os_pkgs="0")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_listed_image_with_zero_packages_passes_as_not_covered(self):
        rep = self.tmp / "rep"
        for arg in ("yuzu-server-chisel=sha256:" + "e" * 64,
                    "ghcr.io/devnullltd/yuzu-gateway-chisel:9.9.9"):
            with self.subTest(arg=arg):
                r = self.run_gate(arg, os_pkgs="0", extra=("--report-dir", str(rep)))
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("NOT COVERED by OS package scanning", r.stdout)
        self.assertIn("coverage: not-covered",
                      (rep / "trivy-yuzu-server-chisel.gate.txt").read_text(encoding="utf-8"))

    def test_listed_image_that_has_packages_warns_but_passes(self):
        r = self.run_gate("yuzu-server-chisel=img:1", os_pkgs="3")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("remove it from the list", r.stdout)

    def test_package_count_is_printed(self):
        r = self.run_gate("img:1", os_pkgs="7")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("7 OS packages scanned", r.stdout)

    # ── K4: the DB is downloaded once, and must be fresh ──
    def test_fresh_db_passes_and_its_updated_at_is_printed(self):
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("trivy_db_updated_at=", r.stdout)
        self.assertIn("trivy_db_age_hours=", r.stdout)

    def test_stale_db_fails_before_any_scan(self):
        r = self.run_gate("img:1", db="stale")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("more than 72", r.stderr)
        self.assertFalse(self.scans())

    def test_db_of_unknown_age_fails(self):
        for state in ("missing", "garbage", "future"):
            with self.subTest(db=state):
                r = self.run_gate("img:1", db=state)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertFalse(self.scans())

    def test_db_download_error_fails(self):
        r = self.run_gate("img:1", mode="db-error")
        self.assertEqual(r.returncode, 1)
        self.assertFalse(self.scans())

    # ── CH-ENV / UP-7: the environment cannot steer Trivy ──
    def test_inherited_trivy_variables_are_cleared(self):
        cache = self.tmp / "mycache"
        r = self.run_gate("img:1", env_extra={
            "TRIVY_DB_REPOSITORY": "127.0.0.1:9/evil", "TRIVY_SEVERITY": "LOW",
            "TRIVY_INSECURE": "true", "TRIVY_IGNOREFILE": "/dev/null",
            "TRIVY_SKIP_FILES": "usr/lib/*", "TRIVY_CACHE_DIR": str(cache)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        envs = [json.loads(ln) for ln in Path(str(self.log) + ".env").read_text().splitlines()]
        for e in envs:
            self.assertEqual(e["trivy_env"], [], "Trivy saw an inherited TRIVY_* variable")
        # TRIVY_CACHE_DIR is honoured, as --cache-dir.
        for a in self.scans():
            self.assertEqual(a[a.index("--cache-dir") + 1], str(cache))
        self.assertTrue((cache / "db" / "metadata.json").is_file())

    def test_trivy_gets_an_empty_config_and_a_private_tmpdir(self):
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        envs = [json.loads(ln) for ln in Path(str(self.log) + ".env").read_text().splitlines()]
        for call, e in zip(self.calls(), envs):
            if call == "--version":
                continue  # the version check runs before the work directory exists
            self.assertTrue(e["tmpdir"].startswith(str(self.tmp / "yuzu-image-vuln-gate.")), (call, e))
        for a in self.scans():
            self.assertIn("--config", a)
        self.assertEqual(list(self.tmp.glob("yuzu-image-vuln-gate.*")), [], "WORK not removed")

    # ── the ignore file (SG-F4, C3) ──
    def test_missing_ignore_file_is_refused(self):
        r = self.run_gate("img:1", ignore=self.tmp / "absent.yaml")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.calls(), [])

    def assert_refused(self, body, why=""):
        r = self.run_gate("img:1", ignore=self.write_ignore(body))
        self.assertEqual(r.returncode, 1, f"accepted ({why}): {r.stdout}{r.stderr}")
        self.assertEqual(self.calls(), [], "Trivy ran on a refused ignore file")
        return r

    def test_entry_without_expiry_is_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry(expired_at=None))

    def test_entry_without_statement_is_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry(statement=None))

    def test_entry_without_approver_is_refused(self):
        r = self.assert_refused("vulnerabilities:\n" + entry(approved_by=None))
        self.assertIn("approved_by", r.stderr)

    def test_approver_must_be_a_login(self):
        self.assert_refused("vulnerabilities:\n" + entry(approved_by='"two words"'))

    def test_entry_without_scope_is_refused(self):
        r = self.assert_refused("vulnerabilities:\n" + entry(paths=None))
        self.assertIn("never a bare id", r.stderr)

    def test_expiry_beyond_92_days_is_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry(expired_at=days(120)))

    def test_flow_style_entry_is_refused(self):
        # Counted as one id by the old grep, with no statement or expiry: it passed.
        self.assert_refused("vulnerabilities:\n  - {id: CVE-2000-0001}\n" + entry(id="CVE-2000-0002"))

    def test_decoy_expiry_inside_a_statement_is_refused(self):
        body = ("vulnerabilities:\n  - id: CVE-2000-0001\n    paths:\n      - \"a\"\n"
                "    statement: >-\n      looks fine\n      expired_at: " + days(10) + "\n"
                "    approved_by: some-login\n")
        self.assert_refused(body, "the only expired_at is inside the folded statement")

    def test_unknown_key_and_other_sections_are_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry() + "    severity: LOW\n", "unknown key")
        self.assert_refused("vulnerabilities:\n" + entry() + "misconfigurations:\n  - id: AVD-1\n",
                            "second section")

    def test_anchor_alias_and_trailing_comment_are_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry(approved_by="&a some-login"))
        self.assert_refused("vulnerabilities:\n" + entry(expired_at=days(10) + "  # renew"))

    def test_duplicate_key_is_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry() + "    statement: again\n")

    def test_complete_entries_are_accepted(self):
        body = ("# comment\nvulnerabilities:\n" + entry()
                + "  - id: CVE-2000-0002\n    purls:\n      - \"pkg:golang/stdlib\"\n"
                  "    statement: >-\n      not reachable,\n      with evidence\n"
                  "    expired_at: " + days(92) + "\n    approved_by: some-login\n")
        r = self.run_gate("img:1", ignore=self.write_ignore(body))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_expired_entry_is_valid_and_noted(self):
        r = self.run_gate("img:1", ignore=self.write_ignore("vulnerabilities:\n" + entry(expired_at=days(-1))))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("no longer honours it", r.stdout)

    def test_entry_close_to_expiry_warns(self):
        r = self.run_gate("img:1", ignore=self.write_ignore("vulnerabilities:\n" + entry(expired_at=days(5))))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("warning:", r.stdout)

    def test_repo_ignore_file_is_well_formed(self):
        r = subprocess.run([sys.executable, "-I", str(CHECKS), "ignore-file", str(IGNORE)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_not_covered_list_names_only_published_chisel_images(self):
        names = [ln.split(":", 1)[0].strip() for ln in NOT_COVERED.read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertTrue(names)
        for n in names:
            self.assertIn(n, PUBLISHED, n)
            self.assertTrue(n.endswith("-chisel"), f"{n}: only FROM-scratch chisel images are expected here")


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


def jobs_of(text):
    """{job name: its steps text, comments removed} for every job of a workflow
    (only under `jobs:`, so the `on:` keys are never mistaken for jobs)."""
    body = text[text.index("\njobs:\n") + len("\njobs:\n"):]
    names = re.findall(r"^  ([A-Za-z0-9_-]+):\n", body, re.M)
    return {n: job_block(body, n) for n in names}


def job_block(text, job):
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S)
    if not m:
        raise AssertionError(f"job {job} not found")
    # Comments are prose (they mention --push and the gate); only steps count.
    return "\n".join(ln for ln in m.group(1).splitlines() if not ln.lstrip().startswith("#"))


# What pushes an image to a registry, wherever it appears in a job's steps:
# build-push-action's `push:` input set to anything but false, a `docker push`,
# a buildx/bundle-script `--push`, or a registry-side copy or retag.
PUSH_MARKERS = re.compile(
    r"^\s*push:\s*(?!false\b)\S"
    r"|\bdocker\s+(?:image\s+)?push\b"
    r"|(?:^|\s)--push(?:\s|$)"
    r"|\bimagetools\s+create\b"
    r"|\b(?:crane|skopeo|oras|regctl)\s+(?:push|copy|cp|tag|image\s+copy)\b",
    re.M,
)

# Every job that pushes an image. release.yml's publish jobs must gate before
# the push; anything else must be listed here with why it is not a release
# image. A job matching a push marker in neither list fails the test.
GATED_PUSH_JOBS = {
    ("release.yml", "docker-publish"),
    ("release.yml", "docker-publish-postgres"),
    ("release.yml", "docker-publish-chisel"),
    ("release.yml", "docker-publish-agent-bundle"),
}
NOT_RELEASE_IMAGES = {
    ("ci-runner-image.yml", "build-ci-linux"):
        "internal CI build image (Dockerfile.ci-linux), never a release artifact",
    ("ci-runner-image.yml", "build-ci-gateway"):
        "internal CI build image (Dockerfile.ci-gateway), never a release artifact",
    ("close-linked-issues.yml", "close"):
        "not an image: `--push` is the script's git push-range argument",
}


class WorkflowWiring(unittest.TestCase):
    def test_every_job_that_pushes_an_image_is_known(self):
        found = set()
        for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
            for job, body in jobs_of(wf.read_text(encoding="utf-8")).items():
                if PUSH_MARKERS.search(body):
                    found.add((wf.name, job))
        unknown = found - GATED_PUSH_JOBS - set(NOT_RELEASE_IMAGES)
        self.assertFalse(unknown, "a job pushes an image but is neither gated nor listed as "
                                  f"not a release image: {sorted(unknown)}")
        stale = (GATED_PUSH_JOBS | set(NOT_RELEASE_IMAGES)) - found
        self.assertFalse(stale, f"listed as pushing, but no push marker found: {sorted(stale)}")

    def test_push_markers_find_the_shapes_that_push(self):
        for shape in ("          push: true", "          push: ${{ inputs.publish }}",
                      "          docker push \"$IMAGE\"", "            --push \\",
                      "  docker buildx imagetools create -t a:latest a:1",
                      "  crane copy a b", "  skopeo copy docker://a docker://b"):
            self.assertTrue(PUSH_MARKERS.search(shape), shape)
        for shape in ("          push: false", "  # nothing pushed", "  git push origin x"):
            self.assertFalse(PUSH_MARKERS.search(shape), shape)

    def test_every_publish_job_gates_before_its_push(self):
        jobs = jobs_of(RELEASE.read_text(encoding="utf-8"))
        for wf, job in sorted(GATED_PUSH_JOBS):
            self.assertEqual(wf, "release.yml")
            body = jobs[job]
            gate = body.find("scripts/ci/image-vuln-gate.sh")
            self.assertNotEqual(gate, -1, f"{job}: no image-vuln-gate step")
            pushes = [m.start() for m in PUSH_MARKERS.finditer(body)]
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

    def test_publish_jobs_keep_the_gate_report_as_evidence(self):
        # K7: each gate writes its reports, names the image (so the not-covered
        # list can match it), records verify-pushed, and uploads them for 90
        # days; the release job attaches them inside SHA256SUMS.
        text = RELEASE.read_text(encoding="utf-8")
        names = {"docker-publish": "yuzu-${{ matrix.image }}",
                 "docker-publish-postgres": "yuzu-postgres",
                 "docker-publish-chisel": "yuzu-${{ matrix.image }}-chisel",
                 "docker-publish-agent-bundle": "yuzu-agent-bundle-chisel"}
        for job, name in names.items():
            body = job_block(text, job)
            gate = body.find("scripts/ci/image-vuln-gate.sh")
            gate_step = body[body.rfind("- name:", 0, gate):body.find("- name:", gate)]
            self.assertIn(f"NAME: {name}\n", gate_step, job)
            self.assertIn('--report-dir "$RUNNER_TEMP/image-vuln-gate" "$NAME=$IMAGE"', gate_step, job)
            check = body.find("scripts/ci/image-identity.sh verify-pushed")
            check_step = body[body.rfind("- name:", 0, check):body.find("- name:", check)]
            self.assertIn('>> "$RUNNER_TEMP/image-vuln-gate/trivy-$NAME.gate.txt"', check_step, job)
            up = body.find("- name: Upload image vulnerability gate report")
            self.assertGreater(up, check, job)
            up_step = body[up:body.find("- name:", up + 1)]
            self.assertIn("path: ${{ runner.temp }}/image-vuln-gate/", up_step, job)
            self.assertIn("retention-days: 90", up_step, job)
            self.assertIn("if-no-files-found: error", up_step, job)
        rel = job_block(text, "release")
        self.assertIn("-name 'trivy-*.json'", rel)
        self.assertIn("*.spdx.json trivy-* > SHA256SUMS", rel)
        self.assertIn("artifacts/trivy-* \\", rel)

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

    def test_runtime_package_index_failures_fail_the_build(self):
        # K5: `apt-get update` exits 0 when an index (the security pocket)
        # cannot be fetched, and the upgrade then ships without it.
        for name in ("Dockerfile.server", "Dockerfile.postgres"):
            df = (ROOT / "deploy" / "docker" / name).read_text(encoding="utf-8")
            runtime = df[df.rindex("\nFROM "):]
            runtime = "\n".join(ln for ln in runtime.splitlines() if not ln.lstrip().startswith("#"))
            updates = re.findall(r"apt-get update[^\n;&]*", runtime)
            self.assertTrue(updates, name)
            for u in updates:
                self.assertIn("--error-on=any", u, f"{name}: {u}")

    def test_pre_release_scans_every_published_image(self):
        body = job_block(PRE_RELEASE.read_text(encoding="utf-8"), "security-scan")
        self.assertIn("scripts/ci/image-vuln-gate.sh", body)
        for name in PUBLISHED:
            self.assertGreaterEqual(body.count(name), 2, f"{name}: not pulled and scanned")


if __name__ == "__main__":
    unittest.main()
