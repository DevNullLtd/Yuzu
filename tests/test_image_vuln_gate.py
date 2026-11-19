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
    def report(target, family, name, pkgs, vulns, eosl=False):
        os_ = {"Family": family, "Name": name}
        if eosl:
            os_["EOSL"] = True
        return {"SchemaVersion": 2, "ArtifactName": target,
                "Metadata": {"ImageID": "sha256:" + "9" * 64, "OS": os_},
                "Results": [{"Target": target, "Class": "os-pkgs", "Type": family,
                             "Packages": [{"Name": "p%d" % i} for i in range(pkgs)],
                             "Vulnerabilities": [{"VulnerabilityID": "CVE-2000-%04d" % i} for i in range(vulns)]}]}
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
        age = {"fresh": 2, "stale": 100, "future": -5, "predownloaded": 2}[state]
        t = (now - datetime.timedelta(hours=age)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        dl = t if state == "predownloaded" else now.strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        open(meta, "w").write(json.dumps({"Version": 2, "UpdatedAt": t, "DownloadedAt": dl}))
        sys.exit(0)
    if args[0] == "convert":
        if mode == "convert-error":
            sys.exit(1)
        # As Trivy 0.70.0 does (checked 2026-11-18): without --scanners vuln,
        # `convert --format table` writes a 0-byte table for a report with no
        # findings (or no Results); with it, a "Report Summary" table. The
        # empty-table mode writes nothing either way.
        rep = json.load(open(args[-1]))
        vulns = sum(len(r.get("Vulnerabilities") or []) for r in rep.get("Results") or [])
        out = ""
        if mode != "empty-table" and (vulns or opt("--scanners") == "vuln"):
            out = "\\nReport Summary\\n\\n| Target | Type | Vulnerabilities |\\n| %s | os | %d |\\n" % (
                rep.get("ArtifactName", "?"), vulns)
        open(opt("--output"), "w").write(out)
        sys.exit(0)
    if args[0] == "rootfs":
        # The advisory canary: detect the OS the way Trivy does from the files
        # the checker wrote; STUB_CANARY=none means the DB has no advisories.
        root = args[-1]
        def read(rel):
            p = os.path.join(root, rel)
            return open(p).read() if os.path.exists(p) else None
        fam, name = "", ""
        if read("etc/debian_version") is not None:
            fam, name = "debian", read("etc/debian_version").strip()
        elif read("etc/lsb-release") is not None:
            fam = "ubuntu"
            name = [l.split("=", 1)[1] for l in read("etc/lsb-release").splitlines()
                    if l.startswith("DISTRIB_RELEASE=")][0]
        elif read("etc/alpine-release") is not None:
            fam, name = "alpine", read("etc/alpine-release").strip()
        n = 0 if os.environ.get("STUB_CANARY") == "none" else 3
        open(opt("--output"), "w").write(json.dumps(report(root, fam, name, 2, n)))
        sys.exit(0)
    image = args[-1]
    gate = "--exit-code" in args
    if mode in ("hang", "hang-stubborn") and not gate:
        # A scan that does not finish: the cancellation tests signal the gate
        # while it waits here, and check this process is gone afterwards.
        # hang-stubborn also ignores SIGTERM, as a busy Trivy can be slow to.
        import signal, time
        if mode == "hang-stubborn":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        open(os.environ["STUB_LOG"] + ".pid", "w").write(str(os.getpid()))
        time.sleep(60)
        sys.exit(0)
    if image in os.environ.get("STUB_MISSING_IMAGES", "").split(","):
        # Like trivy: with `--image-src docker` an image missing from the local
        # daemon is an error; without it trivy falls back to containerd,
        # podman and then a registry, and scans (and passes) whatever it finds.
        sys.exit(1 if opt("--image-src") == "docker" else 0)
    bad = os.environ.get("STUB_BAD_IMAGE", "")
    is_bad = not bad or image == bad
    # A finding the ignore file Trivy is given accepts is suppressed.
    fid = os.environ.get("STUB_FINDING_ID", "")
    ign = opt("--ignorefile")
    suppressed = bool(fid) and bool(ign) and ("- id: " + fid) in open(ign).read()
    if gate and is_bad and mode == "findings" and not suppressed:
        print("CRITICAL finding table")
        sys.exit(3)
    if gate and is_bad and mode == "gate-error":
        sys.exit(1)
    if not gate and is_bad and mode == "report-error":
        sys.exit(1)
    if not gate:
        pkgs = os.environ.get("STUB_OS_PKGS", "5")
        fam, _, name = os.environ.get("STUB_OS", "debian:12.15").partition(":")
        if pkgs == "none":
            rep = {"SchemaVersion": 2, "ArtifactName": image,
                   "Metadata": {"ImageID": "sha256:" + "9" * 64}, "Results": []}
        else:
            rep = report(image, fam, name, int(pkgs), 0, os.environ.get("STUB_EOSL") == "1")
        open(opt("--output"), "w").write(json.dumps(rep))
    sys.exit(0)
    """
)
DB_DIGEST = "sha256:" + "d" * 64

def have_bash():
    return os.name != "nt" and shutil.which("bash") is not None


def days(n):
    # UTC, as the checker reads it (G8P5-unhappy-path-7: a local date is a day
    # off in a timezone far from UTC).
    today = datetime.datetime.now(datetime.timezone.utc).date()
    return (today + datetime.timedelta(days=n)).isoformat()


def entry(**over):
    """One well-formed ignore entry, as YAML lines at the file's indentation."""
    f = {"id": "CVE-2000-0001", "paths": ['"usr/bin/x"'], "statement": "not reachable",
         "expired_at": days(30), "approved_by": "some-login", "approved_on": days(-1),
         "approval_ref": '"#1234"'}
    f.update(over)
    out = [f"  - id: {f['id']}"]
    for k in ("paths", "purls"):
        if f.get(k):
            out.append(f"    {k}:")
            out += [f"      - {v}" for v in f[k]]
    for k in ("statement", "expired_at", "approved_by", "approved_on", "approval_ref"):
        if f.get(k) is not None:
            out.append(f"    {k}: {f[k]}")
    return "\n".join(out) + "\n"


def nc_line(name="yuzu-server-chisel", by="some-login", on=None, ref="#1234", exp=None,
            reason="chiselled FROM scratch, no package database"):
    """One not-covered list line."""
    on = days(-1) if on is None else on
    exp = days(30) if exp is None else exp
    return f"{name}: approved_by={by} approved_on={on} approval_ref={ref} expires={exp} reason={reason}\n"


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
                 db="fresh", os_pkgs="5", env_extra=None, gate=GATE):
        env = dict(os.environ)
        for k in list(env):
            if k.startswith("TRIVY_") or k.startswith("STUB_"):
                del env[k]
        env.pop("GITHUB_ACTIONS", None)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.update(
            TRIVY_BIN=str(self.stub),
            STUB_LOG=str(self.log),
            STUB_MODE=mode,
            STUB_BAD_IMAGE=bad_image,
            STUB_MISSING_IMAGES=missing,
            STUB_DB=db,
            STUB_OS_PKGS=os_pkgs,
            YUZU_TRIVYIGNORE=str(ignore),
            YUZU_GATE_TEST_DB_DIGEST=DB_DIGEST,
            RUNNER_TEMP=str(self.tmp),
        )
        env.update(env_extra or {})
        for k, v in list(env.items()):
            if v is None:
                del env[k]
        return subprocess.run(
            ["bash", str(gate), *extra, *images],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def calls(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def scans(self):
        """The image scans: not --version, not the DB download, not convert."""
        return [c.split() for c in self.calls()
                if c.startswith("image ") and "--download-db-only" not in c]

    def canaries(self):
        return [c.split() for c in self.calls() if c.startswith("rootfs ")]

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
        # Trivy reads the checker's canonical copy, never the repository file.
        ign = g[g.index("--ignorefile") + 1]
        self.assertNotEqual(ign, str(IGNORE))
        self.assertTrue(ign.endswith("/trivyignore.yaml"), ign)
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
        for field in ("image id: sha256:" + "9" * 64, "trivy: 0.70.0",
                      "trivy db: mirror.gcr.io/aquasec/trivy-db@" + DB_DIGEST + ", UpdatedAt ",
                      "os packages scanned: 5", "coverage: covered",
                      "advisory data: debian 12.15: 3 advisories matched by the canary", "gate: pass"):
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
        # Pinned by digest: what is recorded is what was downloaded.
        self.assertIn("--db-repository mirror.gcr.io/aquasec/trivy-db@" + DB_DIGEST, downloads[0])

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

    def test_clean_image_table_is_not_empty(self):
        # G8P5-unhappy-path-1: the table conversion names --scanners vuln, so
        # a clean image's .txt is a summary, never 0 bytes (which
        # check-release-artifacts.sh refuses after the push).
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", extra=("--report-dir", str(rep), "--attempt", "1"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conv = [c.split() for c in self.calls() if c.startswith("convert ")]
        self.assertTrue(conv)
        for c in conv:
            self.assertEqual(c[c.index("--scanners") + 1], "vuln", c)
        self.assertGreater((rep / "trivy-img.attempt-1.txt").stat().st_size, 0)

    def test_an_empty_table_fails_before_any_push(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", mode="empty-table", extra=("--report-dir", str(rep), "--attempt", "1"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gate: FAIL: Trivy could not scan the image",
                      (rep / "trivy-img.attempt-1.gate.txt").read_text(encoding="utf-8"))

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
        r = self.run_gate("img:1", env_extra={
            "TRIVY_DB_REPOSITORY": "127.0.0.1:9/evil", "TRIVY_SEVERITY": "LOW",
            "TRIVY_INSECURE": "true", "TRIVY_IGNOREFILE": "/dev/null",
            "TRIVY_SKIP_FILES": "usr/lib/*"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        envs = [json.loads(ln) for ln in Path(str(self.log) + ".env").read_text().splitlines()]
        for e in envs:
            self.assertEqual(e["trivy_env"], [], "Trivy saw an inherited TRIVY_* variable")

    def test_inherited_cache_dir_is_ignored(self):
        # SG-F3 / G8-SG-3: a preseeded cache (its metadata fresh, its DB
        # anything) must never be scanned with: the gate downloads into a
        # fresh directory of its own and leaves the inherited one alone.
        cache = self.tmp / "preseeded"
        (cache / "db").mkdir(parents=True)
        meta = cache / "db" / "metadata.json"
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        meta.write_text(json.dumps({"Version": 2, "UpdatedAt": stamp, "DownloadedAt": stamp,
                                    "NextUpdate": "2999-01-01T00:00:00Z"}))
        before = meta.read_bytes()
        r = self.run_gate("img:1", env_extra={"TRIVY_CACHE_DIR": str(cache)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("TRIVY_CACHE_DIR=" + str(cache) + " is ignored", r.stdout)
        downloads = [c.split() for c in self.calls() if "--download-db-only" in c]
        self.assertEqual(len(downloads), 1)
        for a in downloads + self.scans() + self.canaries():
            d = a[a.index("--cache-dir") + 1]
            self.assertNotEqual(d, str(cache))
            self.assertTrue(d.startswith(str(self.tmp / "yuzu-image-vuln-gate.")), d)
        self.assertEqual(meta.read_bytes(), before)
        self.assertEqual(sorted(os.listdir(cache)), ["db"])

    def test_db_not_downloaded_by_this_run_is_refused(self):
        r = self.run_gate("img:1", db="predownloaded")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("before this run started", r.stderr)
        self.assertFalse(self.scans())

    def test_trivy_bin_is_refused_on_github_actions(self):
        r = self.run_gate("img:1", env_extra={"GITHUB_ACTIONS": "true"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("TRIVY_BIN is for local runs", r.stdout + r.stderr)
        self.assertEqual(self.calls(), [])

    def test_test_db_digest_hook_needs_trivy_bin(self):
        r = self.run_gate("img:1", env_extra={"TRIVY_BIN": None})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("test hook", r.stdout + r.stderr)

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
                + "  - id: CVE-2000-0002\n    purls:\n      - \"pkg:golang/stdlib@1.24.6\"\n"
                  "    statement: >-\n      not reachable,\n      with evidence\n"
                  "    expired_at: " + days(92) + "\n    approved_by: some-login\n"
                  "    approved_on: " + days(0) + "\n"
                  "    approval_ref: https://github.com/o/r/pull/77\n")
        r = self.run_gate("img:1", ignore=self.write_ignore(body))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_expired_entry_is_valid_and_noted(self):
        r = self.run_gate("img:1", ignore=self.write_ignore("vulnerabilities:\n" + entry(expired_at=days(-1))))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("not in force", r.stdout)

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


    # ── G8-SG-1: an acceptance's scope must be concrete ──
    def test_wildcard_or_empty_scope_is_refused(self):
        # Trivy matches `paths` as doublestar globs and an OS package has an
        # empty path, so each of these would hide the CVE in every package.
        for shape in ('"**"', '"*"', '""', '"{,x}"', '"?"', '"[]"', '"/"', '"usr/**"',
                      '"usr/local/bin/*"', '"usr/local/bin/gosu "', '" usr/local/bin/gosu"',
                      '"usr//bin/gosu"', '"./usr/bin/gosu"', '"usr/../bin/gosu"',
                      '"/usr/local/bin/gosu"', '"usr/local/bin/gosu/"', '"a b"', '"usr/bin/!x"',
                      "''", "usr/bin/gosu\"x"):
            with self.subTest(paths=shape):
                self.log.unlink(missing_ok=True)
                self.assert_refused("vulnerabilities:\n" + entry(paths=[shape]), shape)

    def test_scope_refusals_name_the_reason(self):
        # The glob and leading-slash checks are each stated, not only caught
        # by the component allowlist behind them.
        r = self.assert_refused("vulnerabilities:\n" + entry(paths=['"**"']))
        self.assertIn("glob character", r.stderr)
        self.log.unlink(missing_ok=True)
        r = self.assert_refused("vulnerabilities:\n" + entry(paths=['"/usr/local/bin/gosu"']))
        self.assertIn("starts with '/'", r.stderr)

    def test_unversioned_or_wildcard_purl_is_refused(self):
        for shape in ('"pkg:deb/debian/apt"', '"pkg:deb/debian"', '"pkg:deb/"', '"pkg:deb/debian/*"',
                      '"pkg:deb/debian/apt@*"', '"pkg:deb/debian/apt@"', '"notapurl"', '""',
                      '"pkg:deb/debian/apt@2.6.1#sub"', '"pkg:deb/debian/apt@2.6 .1"',
                      '"pkg:deb/debian/[ap]t@2.6.1"', '"pkg:/apt@1"'):
            with self.subTest(purls=shape):
                self.log.unlink(missing_ok=True)
                self.assert_refused("vulnerabilities:\n" + entry(paths=None, purls=[shape]), shape)

    def test_concrete_scopes_are_accepted(self):
        body = ("vulnerabilities:\n"
                + entry(id="CVE-2000-0001", paths=['"usr/local/bin/gosu"', '"opt/app/lib/x-1.2.jar"'])
                + entry(id="CVE-2000-0002", paths=None,
                        purls=['"pkg:deb/debian/apt@2.6.1?arch=amd64"', '"pkg:golang/stdlib@1.24.6"',
                               "pkg:npm/%40scope/name@1.0.0"]))
        r = self.run_gate("img:1", ignore=self.write_ignore(body))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    # ── G8-SG-2 / G8-SG-4: Trivy reads only the validated canonical copy ──
    def test_trivy_reads_only_the_canonical_copy_of_the_entries_in_force(self):
        body = ("vulnerabilities:\n" + entry(id="CVE-2000-0001")
                + entry(id="CVE-2000-0002", expired_at=days(-3)))
        r = self.run_gate("img:1", ignore=self.write_ignore(body))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        src = str(self.tmp / "ignore.yaml")
        for c in self.calls():
            self.assertNotIn(src, c, "Trivy was given the source ignore file")
        g = [c for c in self.scans() if "--exit-code" in c][0]
        ign = Path(g[g.index("--ignorefile") + 1])
        self.assertTrue(ign.name.endswith(".yaml"), ign)

    def test_plain_format_ignore_file_is_refused(self):
        # Trivy reads a non-YAML extension as one id per line, unscoped.
        p = self.tmp / "ignore.txt"
        p.write_text("CVE-2000-0001\n", encoding="utf-8")
        self.assert_refused_path(p)
        p.write_text("vulnerabilities:\n" + entry(), encoding="utf-8")
        r = self.run_gate("img:1", ignore=p)  # a valid file is still only ever read via the copy
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = [c for c in self.scans() if "--exit-code" in c][0]
        self.assertTrue(g[g.index("--ignorefile") + 1].endswith("trivyignore.yaml"))

    def assert_refused_path(self, path):
        r = self.run_gate("img:1", ignore=path)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(self.calls(), [], "Trivy ran on a refused ignore file")

    def test_quoted_dates_and_unquoted_hash_ref_are_refused(self):
        self.assert_refused("vulnerabilities:\n" + entry(expired_at='"' + days(10) + '"'))
        self.assert_refused("vulnerabilities:\n" + entry(approved_on="'" + days(-1) + "'"))
        # YAML reads an unquoted #1234 as a comment, i.e. no value.
        self.assert_refused("vulnerabilities:\n" + entry(approval_ref="#1234"))

    # ── G8-CO-3: an approval names its date and pull request ──
    def test_approval_record_is_required_and_well_formed(self):
        for over in ({"approval_ref": None}, {"approved_on": None},
                     {"approval_ref": '"#0"'}, {"approval_ref": '"#12a"'}, {"approval_ref": '"1234"'},
                     {"approval_ref": "https://github.com/o/r/issues/1"},
                     {"approval_ref": "http://github.com/o/r/pull/1"},
                     {"approved_on": days(2)}, {"approved_on": "2026-13-01"},
                     {"approval_ref": "pending"}):  # pending with an approved_on is contradictory
            with self.subTest(**{k: str(v) for k, v in over.items()}):
                self.log.unlink(missing_ok=True)
                self.assert_refused("vulnerabilities:\n" + entry(**over), str(over))

    def test_pending_acceptance_is_honoured_only_outside_a_release(self):
        body = "vulnerabilities:\n" + entry(id="CVE-2000-0042", approved_on=None, approval_ref="pending")
        ign = self.write_ignore(body)
        env = {"STUB_FINDING_ID": "CVE-2000-0042"}
        r = self.run_gate("img:1", ignore=ign, mode="findings", env_extra=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("approval_ref is pending; honoured here", r.stdout)
        r = self.run_gate("img:1", ignore=ign, mode="findings", env_extra=env, extra=("--release",))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("NOT IN FORCE", r.stdout)
        self.assertIn("fixable CRITICAL", r.stderr)

    def test_approved_acceptance_is_honoured_by_a_release(self):
        ign = self.write_ignore("vulnerabilities:\n" + entry(id="CVE-2000-0042"))
        r = self.run_gate("img:1", ignore=ign, mode="findings", extra=("--release",),
                          env_extra={"STUB_FINDING_ID": "CVE-2000-0042"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_expired_acceptance_is_not_honoured(self):
        ign = self.write_ignore("vulnerabilities:\n" + entry(id="CVE-2000-0042", expired_at=days(-1)))
        r = self.run_gate("img:1", ignore=ign, mode="findings", env_extra={"STUB_FINDING_ID": "CVE-2000-0042"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    # ── G8-UP-1: an OS release with no advisory data is not a pass ──
    def test_end_of_service_life_os_fails(self):
        r = self.run_gate("img:1", env_extra={"STUB_EOSL": "1"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("end of service life", r.stderr)

    def test_os_family_without_a_canary_fails(self):
        r = self.run_gate("img:1", env_extra={"STUB_OS": "redhat:9.4"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("not one the gate can prove has advisory data", r.stderr)

    def test_os_release_with_no_advisories_fails(self):
        # debian:sid-slim with real Trivy 0.70.0: 77 packages, 0 findings,
        # "covered"; the canary of the same release matches nothing. (sid is
        # now refused earlier as a pre-release; a released-looking version
        # with no advisory bucket still reaches the canary.)
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", extra=("--report-dir", str(rep)),
                          env_extra={"STUB_OS": "debian:99.1", "STUB_CANARY": "none"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("no advisory data", r.stderr)
        gate_txt = (rep / "trivy-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("gate: FAIL: no advisory data for the OS release", gate_txt)
        c = self.canaries()
        self.assertEqual(len(c), 1)
        self.assertIn("--skip-db-update", c[0])

    def test_canary_runs_once_per_os_release_and_not_for_unscanned_images(self):
        r = self.run_gate("a=img:1", "b=img:2", "yuzu-server-chisel=img:3",
                          env_extra={"STUB_OS": "ubuntu:26.04"})
        # yuzu-server-chisel has packages here, so it is covered and checked too.
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(len(self.canaries()), 1, self.calls())
        self.log.unlink()
        r = self.run_gate("yuzu-server-chisel=img:3", os_pkgs="0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.canaries(), [])

    # ── C2 / G8-RD-2: a refusal leaves a report ──
    def assert_fail_reports(self, rep, names, why):
        for n in names:
            t = (rep / f"trivy-{n}.gate.txt").read_text(encoding="utf-8")
            self.assertRegex(t, r"(?m)^gate: FAIL: ", n)
            self.assertIn(why, t, n)

    def test_refused_ignore_file_still_writes_a_failing_report_per_image(self):
        rep = self.tmp / "rep"
        r = self.run_gate("a=img:1", "b=img:2", extra=("--report-dir", str(rep)),
                          ignore=self.write_ignore("vulnerabilities:\n" + entry(paths=['"**"'])))
        self.assertEqual(r.returncode, 1)
        self.assert_fail_reports(rep, ("a", "b"), "gate stopped before this image was judged")

    def test_stale_db_and_download_failure_write_failing_reports(self):
        for kw in ({"db": "stale"}, {"mode": "db-error"}, {"mode": "wrong-version"}):
            with self.subTest(**kw):
                rep = self.tmp / ("rep-" + "-".join(kw.values()))
                r = self.run_gate("img:1", extra=("--report-dir", str(rep)), **kw)
                self.assertEqual(r.returncode, 1)
                self.assert_fail_reports(rep, ("img",), "gate stopped")

    def test_image_level_failures_write_failing_reports(self):
        for kw, why in (({"mode": "findings"}, "gate: FAIL: fixable CRITICAL"),
                        ({"mode": "report-error"}, "gate: FAIL: Trivy could not scan the image"),
                        ({"mode": "gate-error"}, "gate: FAIL: Trivy exited 1"),
                        ({"os_pkgs": "0"}, "gate: FAIL: OS packages not scanned")):
            with self.subTest(why=why):
                rep = self.tmp / ("rep-" + str(abs(hash(why))))
                r = self.run_gate("img:1", extra=("--report-dir", str(rep)), **kw)
                self.assertEqual(r.returncode, 1)
                self.assertIn(why, (rep / "trivy-img.gate.txt").read_text(encoding="utf-8"))

    def test_release_mode_does_not_honour_a_pending_not_covered_listing(self):
        # A release refuses a chisel image as unscanned while its not-covered
        # listing is pending. The gate reads the list beside itself, so run a
        # copy of the gate in a scratch tree whose list holds a pending line
        # (hermetic: independent of the repository list's current state).
        ci = self.tmp / "tree" / "scripts" / "ci"
        ci.mkdir(parents=True)
        for f in (GATE, CHECKS):
            shutil.copy2(f, ci / f.name)
        (ci / NOT_COVERED.name).write_text(nc_line(on="-", ref="pending"), encoding="utf-8")
        gate = ci / GATE.name
        r = self.run_gate("yuzu-server-chisel=img:3", os_pkgs="0", extra=("--release",), gate=gate)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("approval_ref is pending", r.stderr)
        # The same listing is honoured outside a release (local runs, the QA rescan).
        r = self.run_gate("yuzu-server-chisel=img:3", os_pkgs="0", gate=gate)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


    # ── G8P3-unhappy-path-1: a pre-release OS version is not covered ──
    def test_pre_release_os_fails_without_a_canary(self):
        # Trivy trims alpine 3.24.0_alpha... to 3.24 and debian 13.0~rc1 to 13,
        # so the canary of the released set matches and the image read as
        # covered (chaos- and unhappy-path-verified with Trivy 0.70.0).
        for os_ in ("alpine:3.24.0_alpha20260101", "debian:13.0~rc1", "debian:forky/sid"):
            with self.subTest(os=os_):
                self.log.unlink(missing_ok=True)
                rep = self.tmp / ("rep-" + os_.replace(":", "-").replace("/", "-").replace("~", "-"))
                r = self.run_gate("img:1", extra=("--report-dir", str(rep)), env_extra={"STUB_OS": os_})
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("no advisory data for a pre-release", r.stderr)
                gate_txt = (rep / "trivy-img.gate.txt").read_text(encoding="utf-8")
                self.assertIn("gate: FAIL: no advisory data for a pre-release OS release", gate_txt)
                self.assertEqual(self.canaries(), [])

    # ── G8P3-security-guardian-1: a one-word `paths` item is refused ──
    def test_paths_naming_a_trivy_target_or_type_is_refused(self):
        # The chaos case: paths ["Python"] hid CVE-2020-14343 (PyYAML 5.3.1)
        # in a real Trivy 0.70.0 --release run, because Trivy matches `paths`
        # against the aggregate "Python" target too.
        for name in ('"Python"', "python", '"Node.js"', "Java", "gobinary", "os-pkgs", "lang-pkgs",
                     "debian", ".NET", '"python-pkg"'):
            with self.subTest(paths=name):
                self.log.unlink(missing_ok=True)
                r = self.assert_refused("vulnerabilities:\n" + entry(paths=[name]), name)
                self.assertIn("is a Trivy result target, class or type name", r.stderr)

    def test_paths_without_a_slash_is_refused(self):
        for name in ('"gosu"', "METADATA", '"x.jar"'):
            with self.subTest(paths=name):
                self.log.unlink(missing_ok=True)
                r = self.assert_refused("vulnerabilities:\n" + entry(paths=[name]), name)
                self.assertIn("has no '/'", r.stderr)

    # ── G8P3-security-guardian-2: reports are named per run attempt ──
    def test_attempt_names_the_reports_and_a_rerun_adds_beside_them(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", mode="findings", extra=("--report-dir", str(rep), "--attempt", "1"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        r = self.run_gate("img:1", extra=("--report-dir", str(rep), "--attempt", "2"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        names = sorted(p.name for p in rep.iterdir())
        self.assertEqual(names, [f"trivy-img.attempt-{n}.{s}" for n in (1, 2) for s in ("gate.txt", "json", "txt")])
        a1 = (rep / "trivy-img.attempt-1.gate.txt").read_text(encoding="utf-8")
        a2 = (rep / "trivy-img.attempt-2.gate.txt").read_text(encoding="utf-8")
        self.assertIn("run attempt: 1\n", a1)
        self.assertIn("gate: FAIL: fixable CRITICAL", a1)
        self.assertIn("run attempt: 2\n", a2)
        self.assertIn("gate: pass", a2)

    def test_attempt_is_validated(self):
        for extra in (("--attempt", "0", "--report-dir", "r"), ("--attempt", "x", "--report-dir", "r"),
                      ("--attempt", "12345", "--report-dir", "r"), ("--attempt", "1")):
            with self.subTest(extra=extra):
                r = self.run_gate("img:1", extra=extra)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(self.calls(), [])

    # ── G8P3-release-deploy-3: a cancelled gate still writes its report ──
    def start_gate(self, *images, extra=(), mode="hang"):
        env = dict(os.environ)
        for k in list(env):
            if k.startswith("TRIVY_") or k.startswith("STUB_") or k.startswith("GITHUB_"):
                del env[k]
        env.update(TRIVY_BIN=str(self.stub), STUB_LOG=str(self.log), STUB_MODE=mode,
                   YUZU_TRIVYIGNORE=str(IGNORE), YUZU_GATE_TEST_DB_DIGEST=DB_DIGEST,
                   RUNNER_TEMP=str(self.tmp))
        return subprocess.Popen(["bash", str(GATE), *extra, *images], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_sigterm_and_sigint_write_a_cancelled_report(self):
        import signal
        import time
        for sig, rc, label in ((signal.SIGTERM, 143, "SIGTERM"), (signal.SIGINT, 130, "SIGINT")):
            with self.subTest(sig=label):
                pidfile = Path(str(self.log) + ".pid")
                pidfile.unlink(missing_ok=True)
                rep = self.tmp / ("rep-" + label)
                p = self.start_gate("a=img:1", extra=("--report-dir", str(rep), "--attempt", "3"))
                deadline = time.monotonic() + 30
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(pidfile.exists(), "the stub scan never started")
                time.sleep(0.2)
                started = time.monotonic()
                p.send_signal(sig)
                out, err = p.communicate(timeout=30)
                self.assertLess(time.monotonic() - started, 15, "the trap waited for the scan to finish")
                self.assertEqual(p.returncode, rc, out + err)
                t = (rep / "trivy-a.attempt-3.gate.txt").read_text(encoding="utf-8")
                self.assertIn(f"gate: FAIL: cancelled ({label}) before this image was judged", t)
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)  # the scan was stopped, not left running
                self.assertEqual(list(self.tmp.glob("yuzu-image-vuln-gate.*")), [], "WORK not removed")

    # ── G8P4-security-guardian-1: the runner's SIGINT, then its SIGTERM ──
    def test_runner_cancel_sigint_then_sigterm_still_writes_the_report(self):
        # The Actions runner cancels with SIGINT and sends SIGTERM about 7.5 s
        # later. Here the scan ignores SIGTERM and the second signal comes
        # after 1 s, while the gate is still stopping its child: the gate must
        # have written its report before that wait, must not die of the second
        # signal, and must finish well inside the runner's 7.5 s.
        import signal
        import time
        pidfile = Path(str(self.log) + ".pid")
        rep = self.tmp / "rep"
        report = rep / "trivy-a.attempt-2.gate.txt"
        p = self.start_gate("a=img:1", extra=("--report-dir", str(rep), "--attempt", "2"), mode="hang-stubborn")
        self.addCleanup(lambda: p.poll() is None and p.kill())
        deadline = time.monotonic() + 30
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(pidfile.exists(), "the stub scan never started")
        time.sleep(0.2)
        started = time.monotonic()
        p.send_signal(signal.SIGINT)
        while not report.exists() and time.monotonic() - started < 1:
            time.sleep(0.02)
        self.assertTrue(report.exists(), "no report within 1 s of the SIGINT")
        self.assertIsNone(p.poll(), "the gate exited before the second signal; the stub did not hold it")
        time.sleep(max(0.0, 1 - (time.monotonic() - started)))
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertLess(time.monotonic() - started, 7.5, "the gate outlived the runner's SIGTERM window")
        self.assertEqual(p.returncode, 130, out + err)
        t = report.read_text(encoding="utf-8")
        self.assertIn("gate: FAIL: cancelled (SIGINT) before this image was judged", t)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)  # the SIGTERM-proof scan was killed
        self.assertEqual(list(self.tmp.glob("yuzu-image-vuln-gate.*")), [], "WORK not removed")

    # ── G8P4-unhappy-path-1: the gate's own overall budget ──
    def test_budget_ends_the_gate_with_a_report(self):
        import time
        rep = self.tmp / "rep"
        started = time.monotonic()
        p = self.start_gate("a=img:1", "b=img:2", extra=("--budget", "3", "--report-dir", str(rep)),
                            mode="hang-stubborn")
        out, err = p.communicate(timeout=60)
        self.assertLess(time.monotonic() - started, 15, "the budget did not end the gate")
        self.assertEqual(p.returncode, 1, out + err)
        for n in ("a", "b"):
            t = (rep / f"trivy-{n}.gate.txt").read_text(encoding="utf-8")
            self.assertIn("gate: FAIL: gate stopped before this image was judged: "
                          "the gate ran out of its 3s budget", t)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(Path(str(self.log) + ".pid").read_text()), 0)
        self.assertEqual(list(self.tmp.glob("yuzu-image-vuln-gate.*")), [], "WORK not removed")

    def test_budget_is_validated(self):
        for b in ("0", "x", "3601", "-5", "12345"):
            with self.subTest(budget=b):
                r = self.run_gate("img:1", extra=("--budget", b))
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(self.calls(), [])

    def test_every_long_call_runs_under_a_deadline(self):
        # Lexical: every `child` call names its deadline, and Trivy's scans
        # carry an explicit --timeout (its default is 5 minutes).
        text = GATE.read_text(encoding="utf-8")
        code = [ln.split(" #", 1)[0] for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        calls = [m for ln in code for m in re.findall(r"(?:^|[\s!&|])child (.*)", ln)]
        self.assertGreaterEqual(len(calls), 6, calls)
        for c in calls:
            self.assertRegex(c, r'^("\$[A-Z_]+_DEADLINE"|\$\(\([A-Z_]+_DEADLINE \+ [0-9]+\)\)) ', c)
        self.assertIn('SCAN_TIMEOUT=(--timeout "$((SCAN_DEADLINE - 10))s")', text)
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for scan in self.scans() + self.canaries():
            self.assertIn("--timeout", scan)


@unittest.skipUnless(have_bash(), "uses the gate's checker the same way the gate does")
class Checks(unittest.TestCase):
    """image-vuln-gate-checks.py subcommands, called directly."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_vuln_checks_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_checks(self, *args):
        return subprocess.run([sys.executable, "-I", str(CHECKS), *map(str, args)],
                              capture_output=True, text=True, timeout=30)

    def trivy_report(self, pkgs, family="ubuntu", name="26.04", eosl=False):
        os_ = {"Family": family, "Name": name}
        if eosl:
            os_["EOSL"] = True
        d = {"SchemaVersion": 2, "ArtifactName": "x", "Metadata": {"OS": os_},
             "Results": [{"Class": "os-pkgs", "Packages": [{"Name": "p"}] * pkgs}]}
        p = self.tmp / f"r{pkgs}.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return p

    def nc(self, *lines):
        p = self.tmp / "nc.txt"
        p.write_text("# header\n" + "".join(lines), encoding="utf-8")
        return p

    # ── G8-QE-1: the not-covered lookup is an exact match ──
    def test_not_covered_lookup_is_exact(self):
        nc = self.nc(nc_line("yuzu-server-chisel"))
        rep = self.trivy_report(0)
        self.assertEqual(self.run_checks("coverage", rep, "yuzu-server-chisel", nc).returncode, 0)
        for name in ("yuzu-server", "yuzu-server-chisel-x", "server-chisel", "chisel", "yuzu-server-chise",
                     "xyuzu-server-chisel", "yuzu-server-chisel.", ""):
            with self.subTest(name=name):
                r = self.run_checks("coverage", rep, name, nc)
                self.assertEqual(r.returncode, 1, f"{name!r} matched a listing: {r.stdout}")
                self.assertIn("verdict=unscanned", r.stdout)

    def test_not_covered_list_refuses_a_duplicate_line(self):
        nc = self.nc(nc_line("yuzu-a"), nc_line("yuzu-a"))
        r = self.run_checks("not-covered", nc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("listed twice", r.stderr)

    def test_not_covered_reason_has_a_minimum_length(self):
        self.assertEqual(self.run_checks("not-covered", self.nc(nc_line(reason="x" * 19))).returncode, 1)
        self.assertEqual(self.run_checks("not-covered", self.nc(nc_line(reason="x" * 20))).returncode, 0)

    def test_not_covered_fields_are_validated(self):
        for kw in ({"by": "two words"}, {"by": "-bad"}, {"ref": "#0"}, {"ref": "1234"},
                   {"ref": "pending"},  # with an approved_on date
                   {"on": "-"},  # no date on an approved listing
                   {"on": days(3)}, {"exp": days(93)}, {"exp": "someday"}, {"name": "Yuzu-Server"}):
            with self.subTest(**kw):
                self.assertEqual(self.run_checks("not-covered", self.nc(nc_line(**kw))).returncode, 1, kw)
        bad_order = "yuzu-a: approval_ref=#1 approved_by=x approved_on=2026-01-01 expires=2026-12-01 reason=" + "y" * 30 + "\n"
        self.assertEqual(self.run_checks("not-covered", self.nc(bad_order)).returncode, 1)

    def test_not_covered_listing_in_force_rules(self):
        rep = self.trivy_report(0)
        expired = self.nc(nc_line(exp=days(-1)))
        r = self.run_checks("coverage", rep, "yuzu-server-chisel", expired)
        self.assertEqual(r.returncode, 1)
        self.assertIn("expired", r.stderr)
        pending = self.nc(nc_line(on="-", ref="pending"))
        self.assertEqual(self.run_checks("coverage", rep, "yuzu-server-chisel", pending).returncode, 0)
        r = self.run_checks("coverage", rep, "yuzu-server-chisel", pending, "--require-approved")
        self.assertEqual(r.returncode, 1)
        approved = self.nc(nc_line())
        self.assertEqual(self.run_checks("coverage", rep, "yuzu-server-chisel", approved,
                                         "--require-approved").returncode, 0)

    def test_vulnerability_id_format(self):
        def body(i):
            return "vulnerabilities:\n" + entry(id=i)
        for good in ("CVE-2025-12345", "CVE-2025-1234", "GHSA-2v3c-4x5h-6m7p"):
            p = self.tmp / "ok.yaml"
            p.write_text(body(good), encoding="utf-8")
            self.assertEqual(self.run_checks("ignore-file", p).returncode, 0, good)
        for bad in ("CVE-2025-123", "cve-2025-12345", "CVE-25-12345", "GHSA-xxxx", "CVE-2025-1234x"):
            p = self.tmp / "bad.yaml"
            p.write_text(body(bad), encoding="utf-8")
            self.assertEqual(self.run_checks("ignore-file", p).returncode, 1, bad)

    def test_coverage_reads_only_a_trivy_report(self):
        # A grype report (matches/source) must be refused, never read as "no
        # OS packages" or as covered.
        g = self.tmp / "grype.json"
        g.write_text(json.dumps({"matches": [], "source": {"type": "image"}, "distro": {"name": "debian"}}))
        r = self.run_checks("coverage", g, "x", self.nc(nc_line()))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not a Trivy JSON report", r.stderr)
        d = json.loads(self.trivy_report(5).read_text())
        d["SchemaVersion"] = 1
        old = self.tmp / "old.json"
        old.write_text(json.dumps(d))
        self.assertEqual(self.run_checks("coverage", old, "x", self.nc(nc_line())).returncode, 1)

    def test_eosl_and_unknown_family_fail_coverage(self):
        nc = self.nc(nc_line())
        r = self.run_checks("coverage", self.trivy_report(5, "debian", "11.11", eosl=True), "x", nc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("verdict=eosl", r.stdout)
        r = self.run_checks("coverage", self.trivy_report(5, "rocky", "9.4"), "x", nc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("verdict=unsupported-os", r.stdout)
        r = self.run_checks("coverage", self.trivy_report(5, "debian", "12.15"), "x", nc)
        self.assertEqual(r.returncode, 0)
        self.assertIn("verdict=covered", r.stdout)

    def test_canary_rootfs_has_the_files_trivy_detects(self):
        # Checked with real Trivy 0.70.0 on 2026-11-18: these roots are
        # detected as the named release; debian 12.15/13.7, ubuntu 24.04/26.04
        # and alpine 3.22-3.24 match 73-306 advisories, while debian forky/sid,
        # debian 99.1, ubuntu 99.10 and alpine 3.24_alpha20251016 match none.
        expect = {"debian": ("etc/debian_version", "var/lib/dpkg/status"),
                  "ubuntu": ("etc/lsb-release", "var/lib/dpkg/status"),
                  "alpine": ("etc/alpine-release", "lib/apk/db/installed")}
        for fam, files in expect.items():
            with self.subTest(family=fam):
                root = self.tmp / f"c-{fam}"
                self.assertEqual(self.run_checks("canary-rootfs", root, fam, "1.2").returncode, 0)
                for f in files:
                    self.assertTrue((root / f).is_file(), f)
                self.assertIn("openssl", (root / files[1]).read_text())
                # an existing directory is never reused
                self.assertEqual(self.run_checks("canary-rootfs", root, fam, "1.2").returncode, 1)
        self.assertEqual(self.run_checks("canary-rootfs", self.tmp / "c-x", "rocky", "9").returncode, 1)
        self.assertEqual(self.run_checks("canary-rootfs", self.tmp / "c-y", "debian", "1\n2").returncode, 1)

    def test_canary_check(self):
        def rep(fam, name, n):
            p = self.tmp / f"c{n}.json"
            p.write_text(json.dumps({"SchemaVersion": 2, "ArtifactName": "c",
                                     "Metadata": {"OS": {"Family": fam, "Name": name}},
                                     "Results": [{"Class": "os-pkgs", "Vulnerabilities": [{}] * n}]}))
            return p
        self.assertEqual(self.run_checks("canary-check", rep("debian", "12.15", 3), "debian", "12.15").returncode, 0)
        self.assertEqual(self.run_checks("canary-check", rep("debian", "12.15", 0), "debian", "12.15").returncode, 1)
        # The canary was detected as another release: not a proof.
        self.assertEqual(self.run_checks("canary-check", rep("debian", "12", 3), "debian", "12.15").returncode, 1)

    def test_db_age_refuses_a_db_downloaded_before_the_run(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        t = (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        m = self.tmp / "metadata.json"
        m.write_text(json.dumps({"UpdatedAt": t, "DownloadedAt": t}))
        self.assertEqual(self.run_checks("db-age", m).returncode, 0)
        self.assertEqual(self.run_checks("db-age", m, "--downloaded-after", int(now.timestamp())).returncode, 1)
        self.assertEqual(self.run_checks("db-age", m, "--downloaded-after",
                                         int(now.timestamp()) - 7200).returncode, 0)
        m.write_text(json.dumps({"UpdatedAt": t}))
        self.assertEqual(self.run_checks("db-age", m, "--downloaded-after", 1).returncode, 1)

    def test_resolve_digest_refuses_a_malformed_reference(self):
        for ref in ("mirror.gcr.io/aquasec/trivy-db", "http://x/y:2", "a b/c:2"):
            self.assertEqual(self.run_checks("resolve-digest", ref).returncode, 1, ref)

    # ── G8P3-unhappy-path-2: the digest lookup has an overall deadline ──
    def test_resolve_digest_gives_up_at_its_deadline_on_a_trickling_registry(self):
        # A registry that answers one byte at a time never trips a per-read
        # timeout; only the overall deadline ends the lookup.
        import socket
        import threading
        import time
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        stop = threading.Event()
        self.addCleanup(stop.set)
        self.addCleanup(srv.close)

        def trickle():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(4096)  # the ClientHello
                    conn.sendall(b"\x16\x03\x03\x40\x00")  # a 16 KiB handshake record...
                    while not stop.is_set():
                        conn.sendall(b"\x00")  # ...sent one byte at a time
                        time.sleep(0.2)
                except OSError:
                    return

        threading.Thread(target=trickle, daemon=True).start()
        ref = f"127.0.0.1:{srv.getsockname()[1]}/aquasec/trivy-db:2"
        started = time.monotonic()
        r = subprocess.run([sys.executable, "-I", str(CHECKS), "resolve-digest", ref, "--deadline", "2"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("no answer within the 2s deadline", r.stderr)
        self.assertLess(time.monotonic() - started, 10)

    def test_resolve_digest_deadline_is_bounded(self):
        for d in ("0", "3601", "x"):
            r = self.run_checks("resolve-digest", "ghcr.io/aquasecurity/trivy-db:2", "--deadline", d)
            self.assertNotEqual(r.returncode, 0, d)

    # ── G8P3-unhappy-path-1: every pre-release spelling ──
    def test_pre_release_os_versions_are_refused(self):
        for fam, name in (("alpine", "3.24.0_alpha20260101"), ("alpine", "3.23.0_rc1"),
                          ("alpine", "3.23.0_beta2"), ("alpine", "3.23.0_pre1"), ("alpine", "3.23.0_git20260101"),
                          ("alpine", "3.24_RC3"), ("debian", "13.0~rc1"), ("debian", "14.0~alpha1"),
                          ("debian", "forky/sid"), ("debian", "trixie/testing"), ("ubuntu", "26.10-rc1"),
                          ("ubuntu", "26.10.beta"), ("ubuntu", "26.10+dev"), ("alpine", "edge"),
                          ("debian", "13~"), ("ubuntu", "26.10-snapshot1")):
            with self.subTest(os=f"{fam} {name}"):
                r = self.run_checks("coverage", self.trivy_report(5, fam, name), "x", self.nc(nc_line()))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("verdict=pre-release", r.stdout)
                self.assertIn("no advisory data for a pre-release", r.stderr)

    def test_os_version_must_be_a_released_number(self):
        for fam, name in (("debian", "12.0+deb12u1"), ("debian", "13.7.1.2"), ("ubuntu", "26.04 LTS"),
                          ("alpine", "3.23.8a"), ("debian", "v13")):
            with self.subTest(os=f"{fam} {name}"):
                r = self.run_checks("coverage", self.trivy_report(5, fam, name), "x", self.nc(nc_line()))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("verdict=unsupported-os", r.stdout)
        for fam, name in (("debian", "13.7"), ("debian", "12"), ("ubuntu", "26.04"), ("alpine", "3.23.8")):
            with self.subTest(os=f"{fam} {name}"):
                r = self.run_checks("coverage", self.trivy_report(5, fam, name), "x", self.nc(nc_line()))
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("verdict=covered", r.stdout)

    # ── G8P3-release-deploy-1: the pre-tag pending check ──
    def test_pending_check(self):
        ign = self.tmp / "ign.yaml"
        ign.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0001"), encoding="utf-8")
        ok_nc = self.nc(nc_line())
        r = self.run_checks("pending", ign, ok_nc)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pend = self.tmp / "pend.yaml"
        pend.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0002", approved_on=None, approval_ref="pending"),
                        encoding="utf-8")
        r = self.run_checks("pending", pend, ok_nc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("CVE-2000-0002: approval_ref is pending", r.stderr)
        p_nc = self.tmp / "pnc.txt"
        p_nc.write_text(nc_line(on="-", ref="pending"), encoding="utf-8")
        r = self.run_checks("pending", ign, p_nc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("yuzu-server-chisel: approval_ref is pending", r.stderr)
        # An expired entry is not pending, but it is not in force either: a
        # release would fail on what it accepted (G8P4-release-deploy-1).
        old = self.tmp / "old.yaml"
        old.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0003", approved_on=None, approval_ref="pending",
                                                     expired_at=days(-1)), encoding="utf-8")
        r = self.run_checks("pending", old, ok_nc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("CVE-2000-0003: expired on", r.stderr)
        self.assertNotIn("approval_ref is pending", r.stderr)
        # Expiring today or tomorrow can lapse mid-release: refused too.
        for n in (0, 1):
            soon = self.tmp / f"soon{n}.yaml"
            soon.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0004", expired_at=days(n)), encoding="utf-8")
            r = self.run_checks("pending", soon, ok_nc)
            self.assertEqual(r.returncode, 1, n)
            self.assertIn("CVE-2000-0004: expires on", r.stderr)
        later = self.tmp / "later.yaml"
        later.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0005", expired_at=days(2)), encoding="utf-8")
        r = self.run_checks("pending", later, ok_nc)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning:", r.stdout)
        # The same for a not-covered listing: expired, expiring, and a warning.
        for exp, rc, text in ((days(-1), 1, "yuzu-server-chisel: expired on"),
                              (days(1), 1, "yuzu-server-chisel: expires on"),
                              (days(10), 0, "warning:")):
            with self.subTest(listing_expires=exp):
                r = self.run_checks("pending", ign, self.nc(nc_line(exp=exp)))
                self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
                self.assertIn(text, r.stdout + r.stderr)
        bad = self.tmp / "bad.yaml"
        bad.write_text("vulnerabilities:\n" + entry(paths=['"**"']), encoding="utf-8")
        self.assertEqual(self.run_checks("pending", bad, ok_nc).returncode, 1)
        bad_nc = self.tmp / "bnc.txt"
        bad_nc.write_text("junk\n", encoding="utf-8")
        self.assertEqual(self.run_checks("pending", ign, bad_nc).returncode, 1)

    def test_emitted_copy_is_the_entries_in_force_only(self):
        src = self.tmp / "src.yaml"
        src.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0001")
                       + entry(id="CVE-2000-0002", approved_on=None, approval_ref="pending")
                       + entry(id="CVE-2000-0003", expired_at=days(-1)), encoding="utf-8")
        out = self.tmp / "out.yaml"
        r = self.run_checks("ignore-file", src, "--emit", out, "--require-approved")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = out.read_text()
        self.assertIn("- id: CVE-2000-0001", text)
        self.assertNotIn("CVE-2000-0002", text)
        self.assertNotIn("CVE-2000-0003", text)
        self.assertIn("in_force=1", r.stdout)
        self.assertIn("pending_not_honoured=1", r.stdout)
        self.assertNotIn("approved_by", text)
        r = self.run_checks("ignore-file", src, "--emit", out)
        self.assertIn("- id: CVE-2000-0002", out.read_text())


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
    """{job name: its body text, comment lines removed} for every job under the
    top-level `jobs:` key, whatever the jobs' indentation and with or without a
    trailing comment on the job key (only under `jobs:`, so the `on:` keys are
    never mistaken for jobs)."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", ln))
    except StopIteration:
        return {}
    jobs, cur, indent = {}, None, None
    for ln in lines[start + 1:]:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue  # comments are prose (they mention --push and the gate)
        ind = len(ln) - len(ln.lstrip(" "))
        if ind == 0:
            break
        if indent is None:
            indent = ind
        m = re.match(r"""^\s*["']?([A-Za-z0-9_-]+)["']?\s*:\s*(#.*)?$""", ln)
        if ind == indent and m:
            cur = m.group(1)
            jobs[cur] = []
        elif cur is not None:
            jobs[cur].append(ln)
    return {k: "\n".join(v) for k, v in jobs.items()}


def job_block(text, job):
    jobs = jobs_of(text)
    if job not in jobs:
        raise AssertionError(f"job {job} not found")
    return jobs[job]


# What pushes an image to a registry, wherever it appears in a job's steps:
# build-push-action's `push:` input set to anything but false; a docker,
# podman, buildah or nerdctl push (manifest push included, and one reached
# through a variable named for it: $DOCKER, ${CONTAINER_ENGINE}); a buildx/bundle-script `--push` (or
# `--push=true`); an `--output`/`-o`/`outputs:` of type=registry or with
# push=true; a registry-side copy or retag (imagetools create, crane, skopeo,
# oras, regctl, cosign copy).
PUSH_MARKERS = re.compile(
    r"^\s*push:\s*(?!false\b)\S"
    r"|\b(?:docker|podman|buildah|nerdctl)\s+(?:image\s+|manifest\s+)?push\b"
    r"|\$\{?(?i:[A-Za-z0-9_]*(?:docker|podman|buildah|nerdctl|engine|container)[A-Za-z0-9_]*)\}?\"?"
    r"\s+(?:image\s+|manifest\s+)?push\b"
    r"|(?:^|\s)--push(?:=(?!false\b)\S*)?(?=\s|$)"
    r"|(?:(?:^|\s)-o|--output|\boutputs:)[=\s]*[^\n#]*\b(?:type=registry|push=true)\b"
    r"|\bimagetools\s+create\b"
    r"|\b(?:crane|skopeo|oras|regctl)\s+(?:push|copy|cp|tag|mutate|image\s+copy)\b"
    r"|\bcosign\s+copy\b",
    re.M,
)

LOCAL_USES = re.compile(r"""^\s*(?:-\s+)?uses:\s*["']?(\./[^\s"'@]+)""", re.M)
REMOTE_WORKFLOW = re.compile(r"""^\s*uses:\s*["']?[^./\s"'][^\s"']*/\.github/workflows/""", re.M)
SCRIPT_REF = re.compile(r"""(?:^|[\s"'=])\.?/?(scripts/[A-Za-z0-9_./-]+\.(?:sh|bash|py))\b""", re.M)


def _code_lines(text):
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def pushes(body, seen=None):
    """Whether a job body pushes an image, following what it runs from this
    repository: local composite actions (`uses: ./.github/actions/...`), local
    reusable workflows (`uses: ./.github/workflows/x.yml`, any of whose jobs
    pushes) and repository scripts it names. A REMOTE reusable workflow cannot
    be read, so it counts as pushing (list the job if it does not)."""
    seen = set() if seen is None else seen
    if PUSH_MARKERS.search(body) or REMOTE_WORKFLOW.search(body):
        return True
    for ref in LOCAL_USES.findall(body):
        path = (ROOT / ref).resolve()
        if path in seen:
            continue
        seen.add(path)
        if path.is_dir():
            cands = [path / "action.yml", path / "action.yaml"]
        else:
            cands = [path]
        for c in cands:
            if not c.is_file():
                continue
            text = c.read_text(encoding="utf-8")
            if "/.github/workflows/" in str(c).replace("\\", "/"):
                if any(pushes(b, seen) for b in jobs_of(text).values()):
                    return True
            elif pushes(_code_lines(text), seen):
                return True
    for ref in SCRIPT_REF.findall(body):
        path = (ROOT / ref).resolve()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        if pushes(_code_lines(path.read_text(encoding="utf-8", errors="replace")), seen):
            return True
    return False


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
    ("release.yml", "attach-bundle-gate-report"):
        "runs only scripts/ci/image-publish.sh `published`, which reads files; the script is followed "
        "because its `tag` subcommand moves tags",
}


GH_STUB = textwrap.dedent(
    """\
    import hashlib, json, os, sys
    a = sys.argv[1:]
    st_path = os.environ["STUB_GH_STATE"]
    st = json.load(open(st_path))
    with open(os.environ["STUB_GH_LOG"], "a") as f:
        f.write(json.dumps(a) + "\\n")
    def save():
        json.dump(st, open(st_path, "w"))
    def by_id(i):
        return next((x for x in st["assets"] if str(x["id"]) == str(i)), None)
    repo = os.environ["GH_REPO"]
    if a[0] == "api":
        path = [x for x in a[1:] if x.startswith("repos/")][0]
        if path == f"repos/{repo}/releases/tags/{st['tag']}":
            print(st["release_id"]); sys.exit(0)
        if path.startswith(f"repos/{repo}/releases/{st['release_id']}/assets"):
            for x in st["assets"]:
                print("\\t".join([str(x["id"]), x["name"], x["state"], str(x["size"]), x.get("digest", "")]))
            sys.exit(0)
        if path.startswith(f"repos/{repo}/releases/assets/"):
            x = by_id(path.rsplit("/", 1)[1])
            if x is None:
                sys.exit(1)
            if "DELETE" in a:
                st["assets"].remove(x); save(); sys.exit(0)
            if x.get("download_fails"):
                sys.exit(1)
            sys.stdout.buffer.write(bytes.fromhex(x["data"])); sys.exit(0)
        sys.exit(2)
    if a[:2] == ["release", "upload"]:
        names = {x["name"] for x in st["assets"]}
        for f in a[3:]:
            if f in names:
                print(f"HTTP 422: already_exists {f}", file=sys.stderr); sys.exit(1)
            data = open(f, "rb").read()
            st["next_id"] += 1
            if f == os.environ.get("STUB_GH_INTERRUPT"):
                st["assets"].append({"id": st["next_id"], "name": f, "state": "starter", "size": 0,
                                     "data": data[: len(data) // 2].hex()})
                save(); print("upload interrupted", file=sys.stderr); sys.exit(1)
            st["assets"].append({"id": st["next_id"], "name": f, "state": "uploaded", "size": len(data),
                                 "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "data": data.hex()})
            save()
        sys.exit(0)
    sys.exit(2)
    """
)
COSIGN_STUB = textwrap.dedent(
    """\
    import hashlib, json, sys
    a = sys.argv[1:]
    def opt(n):
        return a[a.index(n) + 1]
    valued = {"--bundle", "--certificate-identity", "--certificate-oidc-issuer"}
    pos = [x for i, x in enumerate(a[1:], 1) if not x.startswith("--") and a[i - 1] not in valued]
    blob = pos[0]
    sha = hashlib.sha256(open(blob, "rb").read()).hexdigest()
    if a[0] == "sign-blob":
        json.dump({"sha256": sha, "identity": "workflow"}, open(opt("--bundle"), "w")); sys.exit(0)
    if a[0] == "verify-blob":
        try:
            b = json.load(open(opt("--bundle")))
        except Exception:
            sys.exit(1)
        ok = b.get("sha256") == sha and opt("--certificate-identity").endswith("release.yml@refs/tags/v1.2.3")
        sys.exit(0 if ok else 1)
    sys.exit(2)
    """
)
BUNDLE_IMAGE = "ghcr.io/o/yuzu-agent-bundle-chisel"
DIGEST_E = "sha256:" + "e" * 64
PUBLISH = ROOT / "scripts" / "ci" / "image-publish.sh"


def journal(upto, digest=DIGEST_E, attempt=2, repo=BUNDLE_IMAGE, tags=None):
    """A legal publish journal ending at label `upto` (None: no journal)."""
    if upto is None:
        return None
    tags = tags or f"{repo}:1.2.3"
    seq = [("none", "publish: none"),
           ("push-started", f"publish: push-started {repo}:candidate-77-{attempt}"),
           ("verified", f"publish: verified {repo}@{digest}"),
           ("signed-attested", f"publish: signed-attested {repo}@{digest}"),
           ("tagging", f"publish: tagging {tags} {digest}"),
           ("tagged", f"publish: tagged {tags} {digest}")]
    out = []
    for label, line in seq:
        out.append(line)
        if label == upto:
            return "\n".join(out) + "\n"
    raise ValueError(upto)


def attach_block():
    """The attach job's `Sign and attach` run block, exactly as release.yml has it."""
    body = job_block(RELEASE.read_text(encoding="utf-8"), "attach-bundle-gate-report")
    step = body[body.index("- name: Sign and attach"):]
    lines = step.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "run: |") + 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    out = []
    for ln in lines[start:]:
        if ln.strip() and len(ln) - len(ln.lstrip()) < indent:
            break
        out.append(ln[indent:])
    return "\n".join(out) + "\n"


@unittest.skipUnless(have_bash() and shutil.which("cmp") and shutil.which("sha256sum"), "runs the bash block")
class AttachBundleReport(unittest.TestCase):
    """release.yml's attach-bundle-gate-report `Sign and attach` block, run as
    written against stub gh and cosign (G8P4-chaos-injector-1,
    G8P4-security-guardian-2)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_attach_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        for name, body in (("gh", GH_STUB), ("cosign", COSIGN_STUB)):
            p = bin_ / name
            p.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
            p.chmod(0o755)
        self.bin = bin_
        self.script = self.tmp / "attach.sh"
        self.script.write_text(attach_block(), encoding="utf-8")
        self.state = self.tmp / "state.json"
        self.state.write_text(json.dumps({"tag": "v1.2.3", "release_id": 42, "next_id": 100, "assets": []}))
        self.log = self.tmp / "gh.log"
        self.work = self.tmp / "work"
        (self.work / "bundle-gate").mkdir(parents=True)
        (self.tmp / "rt").mkdir()
        self.write_report()

    def write_report(self, result="pass", upto="tagged", attempt=2, digest=DIGEST_E, text=None):
        d = self.work / "bundle-gate"
        stem = f"yuzu-agent-bundle-chisel.attempt-{attempt}"
        (d / f"trivy-{stem}.json").write_text('{"SchemaVersion": 2}\n')
        (d / f"trivy-{stem}.txt").write_text("table\n")
        lines = ["image: yuzu-agent-bundle-chisel (sha256:1)", f"run attempt: {attempt}", f"gate: {result}",
                 "scanned at: 2026-11-18T00:00:00Z"]
        (d / f"trivy-{stem}.gate.txt").write_text("\n".join(lines) + "\n")
        j = d / f"publish-{stem}.txt"
        body = text if text is not None else journal(upto, digest=digest, attempt=attempt)
        if body is None:
            j.unlink(missing_ok=True)
        else:
            j.write_text(body)

    def run_attach(self, interrupt=""):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "STUB_"))}
        env.update(PATH=f"{self.bin}{os.pathsep}{env.get('PATH', '')}", GH_REPO="o/r", GH_TOKEN="x",
                   SIGN_REPOSITORY="o/r", SIGN_REF="refs/tags/v1.2.3", GITHUB_REF_NAME="v1.2.3",
                   PUBLISH=str(PUBLISH), RUNNER_TEMP=str(self.tmp / "rt"),
                   STUB_GH_STATE=str(self.state), STUB_GH_LOG=str(self.log), STUB_GH_INTERRUPT=interrupt)
        return subprocess.run(["bash", str(self.script)], cwd=self.work, env=env,
                              capture_output=True, text=True, timeout=60)

    def assets(self):
        return {a["name"]: a for a in json.loads(self.state.read_text())["assets"]}

    def gh_calls(self):
        return [json.loads(ln) for ln in self.log.read_text().splitlines()] if self.log.exists() else []

    def deletes(self):
        return [c for c in self.gh_calls() if "DELETE" in c]

    def uploads(self):
        return [c for c in self.gh_calls() if c[:2] == ["release", "upload"]]

    def local(self, name):
        return (self.work / "bundle-gate" / name).read_bytes()

    def preload(self, name, data, state="uploaded", size=None, digest=None, **extra):
        st = json.loads(self.state.read_text())
        st["next_id"] += 1
        a = {"id": st["next_id"], "name": name, "state": state,
             "size": len(data) if size is None else size,
             "digest": ("sha256:" + __import__("hashlib").sha256(data).hexdigest()) if digest is None else digest,
             "data": data.hex()}
        a.update(extra)
        st["assets"].append(a)
        self.state.write_text(json.dumps(st))
        return a["id"]

    SUMS = "yuzu-agent-bundle-chisel-image-vuln-gate.attempt-2.SHA256SUMS"
    FILES = (["trivy-yuzu-agent-bundle-chisel.attempt-2." + s for s in ("gate.txt", "json", "txt")]
             + ["publish-yuzu-agent-bundle-chisel.attempt-2.txt"])

    def complete_first_run(self):
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.log.unlink()
        return r

    def test_attaches_every_report_with_a_signed_list(self):
        self.complete_first_run()
        a = self.assets()
        self.assertEqual(sorted(a), sorted(self.FILES + [self.SUMS, self.SUMS + ".sigstore"]))
        for f in self.FILES + [self.SUMS]:
            self.assertEqual(bytes.fromhex(a[f]["data"]), self.local(f), f)

    def test_rerun_with_the_same_files_keeps_everything(self):
        self.complete_first_run()
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.deletes(), [])
        self.assertEqual(self.uploads(), [])
        self.assertIn("identical; kept", r.stdout)
        self.assertIn("verifies; kept", r.stdout)

    def test_an_interrupted_upload_is_replaced_on_the_rerun(self):
        # The wedge: the first run's upload dies part-way, leaving an asset in
        # GitHub's `starter` state. The re-run must finish the job.
        json_name = self.FILES[1]
        r = self.run_attach(interrupt=json_name)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.assets()[json_name]["state"], "starter")
        stale = self.assets()[json_name]["id"]
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(["api", "-X", "DELETE", f"repos/o/r/releases/assets/{stale}"], self.deletes())
        a = self.assets()
        self.assertEqual(a[json_name]["state"], "uploaded")
        self.assertEqual(bytes.fromhex(a[json_name]["data"]), self.local(json_name))
        self.assertEqual(sorted(a), sorted(self.FILES + [self.SUMS, self.SUMS + ".sigstore"]))

    def test_an_open_sigstore_is_signed_again(self):
        self.complete_first_run()
        st = json.loads(self.state.read_text())
        for x in st["assets"]:
            if x["name"].endswith(".sigstore"):
                x["state"] = "open"
                old = x["id"]
        self.state.write_text(json.dumps(st))
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c[-1] for c in self.deletes()], [f"repos/o/r/releases/assets/{old}"])
        self.assertEqual(self.uploads(), [["release", "upload", "v1.2.3", self.SUMS + ".sigstore"]])

    def test_an_asset_not_matching_its_own_size_or_digest_is_replaced(self):
        name = self.FILES[2]
        data = self.local(name)
        for kw in ({"size": len(data)}, {"digest": "sha256:" + "0" * 64}):
            with self.subTest(**kw):
                self.state.write_text(json.dumps({"tag": "v1.2.3", "release_id": 42, "next_id": 100, "assets": []}))
                self.log.unlink(missing_ok=True)
                stored = data[:-1] if "size" in kw else data
                old = self.preload(name, stored, **kw)
                r = self.run_attach()
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("do not match GitHub's size or digest", r.stdout)
                self.assertEqual([c[-1] for c in self.deletes()], [f"repos/o/r/releases/assets/{old}"])
                self.assertEqual(bytes.fromhex(self.assets()[name]["data"]), data)

    def test_a_completed_asset_that_differs_is_refused_and_nothing_is_deleted(self):
        # One interrupted upload AND one completed-but-different asset: the
        # refusal is decided first, so not even the incomplete one is deleted.
        self.preload(self.FILES[1], b"partial", state="starter", size=0, digest="")
        self.preload(self.FILES[2], b"another attempt's table\n")
        r = self.run_attach()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("with different content; refusing to replace it", r.stdout + r.stderr)
        self.assertEqual(self.deletes(), [])
        self.assertEqual(self.uploads(), [])

    def test_a_completed_sigstore_that_does_not_verify_is_refused(self):
        self.complete_first_run()
        st = json.loads(self.state.read_text())
        for x in st["assets"]:
            if x["name"].endswith(".sigstore"):
                bad = json.dumps({"sha256": "0" * 64}).encode()
                x.update(data=bad.hex(), size=len(bad),
                         digest="sha256:" + __import__("hashlib").sha256(bad).hexdigest())
        self.state.write_text(json.dumps(st))
        r = self.run_attach()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("does not verify", r.stdout + r.stderr)
        self.assertEqual(self.deletes(), [])
        self.assertEqual(self.uploads(), [])

    def test_a_failed_download_is_not_read_as_an_incomplete_upload(self):
        self.preload(self.FILES[0], self.local(self.FILES[0]), download_fails=True)
        r = self.run_attach()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not download", r.stdout + r.stderr)
        self.assertEqual(self.deletes(), [])
        self.assertEqual(self.uploads(), [])

    def test_every_attempt_is_attached_and_the_journal_decides(self):
        # The report is tied to the push by the journal (G8P5-security-guardian-1):
        # (gate result, journal end, attach exit status).
        cases = (
            ("pass", "tagged", 0),
            ("pass", None, 0),                    # gate passed, cancelled before the journal opened
            ("pass", "push-started", 0),          # a candidate, never tagged
            ("pass", "signed-attested", 0),
            ("pass", "tagging", 1),               # attached, then refused: a tag may name either digest
            ("FAIL: fixable CRITICAL", None, 0),  # a refusal: nothing pushed
            ("FAIL: fixable CRITICAL", "none", 1),  # a journal beside a failed gate is illegal
            ("FAIL: cancelled (SIGINT) before this image was judged", "tagged", 1),
        )
        for result, upto, rc in cases:
            with self.subTest(result=result, upto=upto):
                self.state.write_text(json.dumps({"tag": "v1.2.3", "release_id": 42, "next_id": 100, "assets": []}))
                self.log.unlink(missing_ok=True)
                self.write_report(result=result, upto=upto)
                r = self.run_attach()
                self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
                legal = not (result != "pass" and upto is not None)
                if legal:
                    names = set(self.assets())
                    self.assertIn("trivy-yuzu-agent-bundle-chisel.attempt-2.gate.txt", names)
                    self.assertEqual("publish-yuzu-agent-bundle-chisel.attempt-2.txt" in names, upto is not None)
                else:
                    self.assertEqual(self.gh_calls(), [], "an illegal journal reached the release")

    def test_an_illegal_journal_is_refused_before_anything_is_uploaded(self):
        good = journal("tagged")
        ls = good.splitlines()
        for label, text in (("two steps swapped", "\n".join(ls[:2] + [ls[3], ls[2]] + ls[4:]) + "\n"),
                            ("two digests", journal("tagged").replace("e" * 64, "f" * 64, 1)),
                            ("tagged without tagging", "\n".join(l for l in good.splitlines()
                                                                if "tagging" not in l) + "\n"),
                            ("no intent line", "\n".join(l for l in good.splitlines()
                                                         if "push-started" not in l) + "\n"),
                            ("truncated last line", good[:-1]),
                            ("failure label", "publish: none\npublish: failed\n")):
            with self.subTest(label=label):
                self.state.write_text(json.dumps({"tag": "v1.2.3", "release_id": 42, "next_id": 100, "assets": []}))
                self.log.unlink(missing_ok=True)
                self.write_report(text=text)
                r = self.run_attach()
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("not a legal publish journal", r.stdout + r.stderr)
                self.assertEqual(self.gh_calls(), [])

    def test_zero_artifacts_fail(self):
        for f in (self.work / "bundle-gate").iterdir():
            f.unlink()
        r = self.run_attach()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("no gate report", r.stdout)

    def test_earlier_attempts_are_attached_beside_later_ones(self):
        # G8P5-consistency-auditor-2: attempt 1 refused, attempt 2 published,
        # attempt 3 refused after a re-run; every attempt's files are attached.
        self.write_report(result="FAIL: fixable CRITICAL", upto=None, attempt=1)
        self.write_report(result="FAIL: cancelled (SIGTERM) before this image was judged", upto=None, attempt=3)
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("attempt 2 published", r.stdout)
        names = set(self.assets())
        for n in (1, 2, 3):
            self.assertIn(f"trivy-yuzu-agent-bundle-chisel.attempt-{n}.gate.txt", names)
            self.assertIn(f"yuzu-agent-bundle-chisel-image-vuln-gate.attempt-{n}.SHA256SUMS", names)
            self.assertIn(f"yuzu-agent-bundle-chisel-image-vuln-gate.attempt-{n}.SHA256SUMS.sigstore", names)

    def test_an_unexpected_file_is_refused(self):
        (self.work / "bundle-gate" / "trivy-yuzu-server.attempt-1.gate.txt").write_text("gate: pass\n")
        r = self.run_attach()
        self.assertEqual(r.returncode, 1)
        self.assertIn("unexpected file", r.stdout)
        self.assertEqual(self.gh_calls(), [])


class WorkflowWiring(unittest.TestCase):
    def test_every_job_that_pushes_an_image_is_known(self):
        found = set()
        for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
            for job, body in jobs_of(wf.read_text(encoding="utf-8")).items():
                if pushes(body):
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
                      "  crane copy a b", "  skopeo copy docker://a docker://b",
                      # G8-QE-2: the shapes the first tripwire missed
                      "  docker buildx build --push=true -t a .", "  docker buildx build -o type=registry .",
                      "  docker buildx build --output=type=image,name=a,push=true .",
                      "          outputs: type=image,push=true", "  docker manifest push a:1",
                      "          outputs: type=image,name=ghcr.io/${{ steps.owner.outputs.value }}/x,"
                      "push-by-digest=true,name-canonical=true,push=true",
                      "  podman push a:1", "  buildah push a:1", "  cosign copy a b",
                      '  "$DOCKER" push a:1', "  ${DOCKER} push a:1", "  $docker image push a:1",
                      "  $CONTAINER_ENGINE push a:1",
                      "  nerdctl push a:1", "  regctl image copy a b"):
            self.assertTrue(PUSH_MARKERS.search(shape), shape)
        for shape in ("          push: false", "  # nothing pushed", "  git push origin x",
                      "  docker buildx build --push=false .", "  cache-to: type=registry,ref=a",
                      "  docker buildx build --load ."):
            self.assertFalse(PUSH_MARKERS.search(shape), shape)

    def test_job_discovery_ignores_indentation_and_trailing_comments(self):
        text = ("on: push\njobs:\n    a:   # first\n        steps:\n          - run: echo\n"
                "    'b':\n        steps:\n          - run: docker push x\n")
        jobs = jobs_of(text)
        self.assertEqual(set(jobs), {"a", "b"})
        self.assertFalse(pushes(jobs["a"]))
        self.assertTrue(pushes(jobs["b"]))

    def test_pushes_follows_local_actions_workflows_and_scripts(self):
        tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_push_follow_", dir=ROOT / "tests"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        rel = tmp.relative_to(ROOT).as_posix()
        (tmp / "act").mkdir()
        (tmp / "act" / "action.yml").write_text("runs:\n  using: composite\n  steps:\n"
                                                "    - run: docker push x\n      shell: bash\n")
        (tmp / "wf.yml").write_text("on: workflow_call\njobs:\n  p:\n    steps:\n"
                                    "      - uses: docker/build-push-action@abc\n        with:\n"
                                    "          push: true\n")
        (tmp / "quiet.sh").write_text("#!/bin/sh\n# docker push in a comment\necho hi\n")
        self.assertTrue(pushes(f"      - uses: ./{rel}/act"))
        self.assertTrue(pushes(f"    uses: ./{rel}/wf.yml"))
        self.assertTrue(pushes("    uses: octo/repo/.github/workflows/publish.yml@v1"))
        self.assertFalse(pushes("      - uses: actions/checkout@v4"))
        # A repository script is followed: build-agent-bundle.sh pushes with --push.
        self.assertTrue(pushes("        run: bash scripts/build-agent-bundle.sh"))
        self.assertFalse(pushes('        run: bash scripts/ci/detect-code-change.sh "$PUSH_BEFORE_SHA" push'))
        self.assertFalse(pushes(f"        run: bash ./{rel}/quiet.sh"))

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
        # The frozen order (docs/ci-architecture.md "The publish journal"):
        # pin < gate < open < push-started < push < verified < SBOM/attest/sign
        # < signed-attested < tag re-check < tag < upload of the reports.
        text = RELEASE.read_text(encoding="utf-8")
        for job in ("docker-publish", "docker-publish-postgres", "docker-publish-chisel",
                    "docker-publish-agent-bundle"):
            body = job_block(text, job)
            pos = {
                "pin": body.find("scripts/ci/image-identity.sh pin"),
                "gate": body.find("scripts/ci/image-vuln-gate.sh"),
                "open": body.find("scripts/ci/image-publish.sh open"),
                "intent": body.find("scripts/ci/image-publish.sh push-started"),
                "push": min((m.start() for m in PUSH_MARKERS.finditer(body)), default=-1),
                "verified": body.find("scripts/ci/image-publish.sh verified"),
                "sbom": body.find("uses: anchore/sbom-action"),
                "attest": body.find("uses: actions/attest-build-provenance"),
                "sign": body.find("cosign sign --yes"),
                "signed": body.find("scripts/ci/image-publish.sh signed-attested"),
                "recheck": body.find("scripts/ci/check-release-tag-sha.sh"),
                "tag": body.find("scripts/ci/image-publish.sh tag"),
                "upload": body.find("- name: Upload image vulnerability gate report"),
            }
            self.assertTrue(all(v != -1 for v in pos.values()), f"{job}: {pos}")
            chain = ["pin", "gate", "open", "intent", "push", "verified", "sbom", "signed", "recheck", "tag", "upload"]
            for x, y in zip(chain, chain[1:]):
                self.assertLess(pos[x], pos[y], f"{job}: {x} must come before {y}")
            self.assertLess(max(pos["sbom"], pos["attest"], pos["sign"]), pos["signed"], job)
            self.assertGreater(min(pos["sbom"], pos["attest"], pos["sign"]), pos["verified"], job)
            self.assertEqual(body.count("scripts/ci/image-publish.sh tag"), 1, job)
            self.assertNotIn("imagetools create", body, f"{job}: tags move only through image-publish.sh tag")
            gate_step = body[body.rfind("- name:", 0, pos["gate"]):pos["gate"]]
            self.assertIn("IMAGE: ${{ steps.built.outputs.id }}", gate_step,
                          f"{job}: the gate must scan the pinned image ID, not a tag")
            self.assertIn("LAYERS: ${{ steps.built.outputs.layers }}",
                          body[body.rfind("- name:", 0, pos["verified"]):pos["verified"]], job)
            # No release tag is pushed by the push itself (G8P5-security-guardian-1).
            self.assertNotRegex(body, r"\n\s+push: true\b", job)
            self.assertNotRegex(body, r"\n\s+tags: \$\{\{ steps\.meta\.outputs\.tags \}\}", job)
            self.assertNotRegex(body, r"docker push \"\$IMAGE\"", job)
        for job in ("docker-publish", "docker-publish-postgres", "docker-publish-chisel"):
            body = job_block(text, job)
            self.assertRegex(body, r"\n\s+outputs: type=image,name=ghcr\.io/[^\n]*,push-by-digest=true,"
                                   r"name-canonical=true,push=true\n", job)
            tags = re.findall(r"yuzu-hc-verify/[^\n]+", body)
            self.assertTrue(tags, job)
            for t in tags:
                self.assertIn("${{ github.run_id }}-${{ github.run_attempt }}", t,
                              f"{job}: shared-daemon scan tag {t} must be salted per run attempt")
        bundle = job_block(text, "docker-publish-agent-bundle")
        self.assertIn('candidate="$REPO:candidate-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', bundle)
        self.assertLess(bundle.index("image-publish.sh push-started"), bundle.index('docker push "$candidate"'))

    def test_no_step_but_the_gate_writes_a_gate_report(self):
        # gate.txt belongs to the gate script alone; the publish state is the
        # journal's, and no job output carries it.
        text = _code_lines(RELEASE.read_text(encoding="utf-8"))
        self.assertNotRegex(text, r">>?\s*\S*\.gate\.txt")
        for gone in ("pushed_ref", "gate_attempt", "PUSHED_REF", "verify-pushed: ok"):
            self.assertNotIn(gone, text)

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
            self.assertIn('exec scripts/ci/image-vuln-gate.sh --release --attempt "$GITHUB_RUN_ATTEMPT"',
                          gate_step, job)
            self.assertIn('--report-dir "$RUNNER_TEMP/image-vuln-gate" "$NAME=$IMAGE"', gate_step, job)
            for sub in ("open", "push-started", "verified", "signed-attested", "tag"):
                at = body.find(f"scripts/ci/image-publish.sh {sub} ")
                st = body[body.rfind("- name:", 0, at):body.find("- name:", at)]
                self.assertIn(f"NAME: {name}\n", st, f"{job} {sub}")
                # G8P6-chaos-injector-1: the writer is the step's process, so
                # the runner's PID-only SIGINT/SIGTERM reaches its trap.
                self.assertIn(f'exec scripts/ci/image-publish.sh {sub} "$RUNNER_TEMP/image-vuln-gate" "$NAME" '
                              '"$GITHUB_RUN_ATTEMPT"', st, f"{job} {sub}")
            # Every writer call, anywhere in the job, is exec'd.
            for m in re.finditer(r"image-publish\.sh (open|push-started|verified|signed-attested|tag) ", body):
                line = body[body.rfind("\n", 0, m.start()) + 1:m.start()]
                self.assertRegex(line, r"^\s+(run: )?exec scripts/ci/$", f"{job}: {m.group(0)} is not exec'd")
            up = body.find("- name: Upload image vulnerability gate report")
            self.assertGreater(up, body.find("scripts/ci/image-publish.sh tag "), job)
            retry = body.find("- name: Retry the image vulnerability gate report upload")
            self.assertGreater(retry, up, job)
            for start in (up, retry):
                up_step = body[start:body.find("- name:", start + 1)]
                self.assertIn("path: ${{ runner.temp }}/image-vuln-gate/", up_step, job)
                self.assertIn("retention-days: 90", up_step, job)
                self.assertIn("if-no-files-found: error", up_step, job)
                # G8P3-security-guardian-2: one artifact per run attempt, never
                # overwritten, so a re-run cannot erase a refusal's evidence.
                self.assertRegex(up_step,
                                 r"\n\s+name: [^\n]+-image-vuln-gate-attempt-\$\{\{ github\.run_attempt \}\}\n", job)
                self.assertNotRegex(up_step, r"\n\s+overwrite:\s*true", job)
            # G8P6-architect-4: the retry runs only when the first upload failed.
            retry_step = body[retry:body.find("- name:", retry + 1)]
            self.assertIn("if: always() && steps.upload_gate.outcome == 'failure'\n", retry_step, job)
        rel = job_block(text, "release")
        self.assertIn("-name 'trivy-*.json'", rel)
        self.assertIn('*.spdx.json "${gate_reports[@]}" > SHA256SUMS', rel)
        self.assertIn('"${GATE_REPORTS[@]}" \\', rel)
        # Every attempt's reports and journals (G8P5-consistency-auditor-2).
        dl = rel[rel.index("- name: Download every attempt's gate reports and publish journals"):]
        dl = dl[:dl.index("- name:", 10)]
        self.assertIn("pattern: '*-image-vuln-gate-attempt-*'", dl)
        self.assertIn("merge-multiple: true", dl)
        self.assertIn("rm -rf ./*-image-vuln-gate-attempt-*/", rel)

    def test_release_gate_runs_in_release_mode_and_its_report_survives_a_refusal(self):
        # C2 / G8-RD-2: the upload runs whenever the gate ran, pass or fail,
        # behind an explicit status function (a bare `if:` is success() only).
        text = RELEASE.read_text(encoding="utf-8")
        cond = ("if: always() && (steps.gate.outcome == 'success' || steps.gate.outcome == 'failure' "
                "|| steps.gate.outcome == 'cancelled')")
        for job in sorted(j for _, j in GATED_PUSH_JOBS):
            body = job_block(text, job)
            gate = body.find("scripts/ci/image-vuln-gate.sh")
            gate_step = body[body.rfind("- name:", 0, gate):body.find("- name:", gate)]
            self.assertIn("id: gate\n", gate_step, job)
            self.assertIn("image-vuln-gate.sh --release ", gate_step, job)
            up = body.find("- name: Upload image vulnerability gate report")
            up_step = body[up:body.find("- name:", up + 1)]
            self.assertIn(cond, up_step, job)
            self.assertIn("id: upload_gate", up_step, job)
        pre = job_block(PRE_RELEASE.read_text(encoding="utf-8"), "security-scan")
        self.assertNotIn("--release", pre, "post-release QA is detective: it reports pending approvals")

    def test_failure_path_conditions_lead_with_a_status_function(self):
        # CLAUDE.md CI invariant: an `if:` testing a step outcome or job result
        # with no status function has an implicit success() ANDed on.
        for wf in (RELEASE, PRE_RELEASE, ROOT / ".github" / "workflows" / "cache-prune.yml"):
            for m in re.finditer(r"^\s*if:\s*(.+)$", wf.read_text(encoding="utf-8"), re.M):
                c = m.group(1)
                if re.search(r"\.(outcome|result)\b", c) and re.search(r"'failure'|!= 'success'", c):
                    self.assertRegex(c, r"^\$?\{?\{?\s*(always\(\)|failure\(\)|success\(\) \|\| failure\(\))",
                                     f"{wf.name}: {c}")

    def test_bundle_gate_report_is_attached_to_the_release(self):
        # G8-CO-4: the bundle's reports outlive the 90-day artifact, every
        # attempt's (G8P5-consistency-auditor-2), read through the journal.
        text = RELEASE.read_text(encoding="utf-8")
        bundle = job_block(text, "docker-publish-agent-bundle")
        self.assertNotRegex(bundle, r"\n    outputs:", "job outputs carry no publish state")
        att = job_block(text, "attach-bundle-gate-report")
        self.assertIn("needs: [release, docker-publish-agent-bundle]", att)
        self.assertIn("if: always() && needs.release.result == 'success' && "
                      "needs.docker-publish-agent-bundle.result != 'skipped'", att)
        self.assertIn("contents: write", att)
        dl = att[att.index("uses: actions/download-artifact@"):]
        dl = dl[:dl.index("- name:")]
        self.assertIn("pattern: yuzu-agent-bundle-chisel-image-vuln-gate-attempt-*", dl)
        self.assertIn("merge-multiple: true", dl)
        self.assertNotIn("name:", dl)
        self.assertIn('bash "$PUBLISH" published . "$name"', att)
        self.assertIn('sums="${name}-image-vuln-gate.attempt-${n}.SHA256SUMS"', att)
        for needle in ('cosign sign-blob --yes "$sums"', "cosign verify-blob", "--certificate-identity",
                       'gh release upload "$GITHUB_REF_NAME" "${upload[@]}"', "cmp -s"):
            self.assertIn(needle, att)
        # Add, never replace (G8P3-security-guardian-2): no --clobber upload.
        self.assertNotRegex(att, r"gh release upload[^\n]*--clobber")
        self.assertNotRegex(att, r"\bdocker\s+(?:build|buildx|run|push)",
                            "the job that holds contents: write builds nothing")
        # It checks out only the journal reader.
        co = att[att.index("uses: actions/checkout@"):]
        co = co[:co.index("- name:")]
        self.assertIn("sparse-checkout: |\n            scripts/ci/image-publish.sh\n", co)
        self.assertIn("sparse-checkout-cone-mode: false", co)
        self.assertIn("persist-credentials: false", co)
        self.assertEqual(att.count("actions/checkout@"), 1)

    def test_report_globs_take_every_scanners_reports(self):
        # A second scanner's reports (grype-*) reach the release exactly like
        # Trivy's: flattened, hashed into SHA256SUMS, uploaded, not attested.
        rel = job_block(RELEASE.read_text(encoding="utf-8"), "release")
        for needle in ("-name 'trivy-*.json'", "-name 'trivy-*.txt'", "-name 'grype-*.json'",
                       "-name 'grype-*.txt'", "gate_reports=(trivy-* grype-* publish-*)",
                       "GATE_REPORTS=(artifacts/trivy-* artifacts/grype-* artifacts/publish-*)",
                       "|trivy-*|grype-*|publish-*) continue ;;",
                       "../gate-reports/trivy-* ../gate-reports/grype-* ../gate-reports/publish-*"):
            self.assertIn(needle, rel)
        self.assertNotIn("artifacts/trivy-* \\", rel)
        pre = PRE_RELEASE.read_text(encoding="utf-8")
        up = pre[pre.index("- name: Upload scan results"):]
        up = up[:up.index("retention-days")]
        self.assertIn("trivy-*\n", up)
        self.assertIn("grype-*\n", up)

    def test_big_tam_publish_jobs_hold_the_cache_lock_before_any_build(self):
        # G8-chaos-1: cache-prune skips a cache dir whose lock is held.
        text = RELEASE.read_text(encoding="utf-8")
        for job in ("docker-publish", "docker-publish-postgres", "docker-publish-chisel"):
            body = job_block(text, job)
            lock = body.find("scripts/ci/buildcache-lock.sh hold")
            build = body.find("docker/build-push-action@")
            self.assertTrue(-1 < lock < build, job)
            lock_step = body[body.rfind("- name:", 0, lock):lock]
            cache = re.search(r"CACHE_DIR: (\S.*)", lock_step).group(1)
            self.assertIn(f"cache-from: type=local,src={cache}\n", body, job)
            self.assertIn(f"cache-to: type=local,dest={cache},mode=max", body, job)

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

    def test_gate_budget_fits_inside_every_job_that_runs_it(self):
        # G8P4-unhappy-path-1: the gate stops itself (with reports) before the
        # job's timeout. Each call's budget plus BUDGET_MARGIN must fit the
        # job's timeout-minutes.
        default = gate_default_budget()
        texts = {p.name: p.read_text(encoding="utf-8") for p in (RELEASE, PRE_RELEASE)}
        violations, checked = gate_budget_violations(texts, default)
        self.assertEqual(violations, [])
        self.assertEqual(sorted(checked), sorted(["docker-publish", "docker-publish-postgres", "docker-publish-chisel",
                                                  "docker-publish-agent-bundle", "security-scan"]))

    def test_budget_check_kills_mutants_of_the_pre_release_call(self):
        # G8P5-quality-engineer-3 / G8P5-build-ci-1: mutants aimed at the CALL
        # in pre-release.yml (its code line, not the comment above it, which
        # also says "--budget 1200"), on in-memory copies.
        default = gate_default_budget()
        text = PRE_RELEASE.read_text(encoding="utf-8")
        lines = text.split("\n")
        call = [i for i, ln in enumerate(lines)
                if "image-vuln-gate.sh" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(len(call), 1, "pre-release.yml should call the gate once")
        i = call[0]
        self.assertIn("--budget 1200", lines[i])
        self.assertTrue(any("--budget 1200" in ln and ln.lstrip().startswith("#") for ln in lines[:i]),
                        "the decoy comment the first mutant hit is gone; re-aim this test")
        indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
        mutants = {
            "raised to 1600": lines[i].replace("--budget 1200", "--budget 1600"),
            "dropped": lines[i].replace("--budget 1200 ", ""),
            "1600 on a continuation line": lines[i].replace("--budget 1200 ", "\\\n" + indent + "  --budget 1600 "),
            # G8P6-build-ci-3: a budget the check cannot read.
            "a variable": lines[i].replace("--budget 1200", '--budget "$B"'),
            "a variable with =": lines[i].replace("--budget 1200", "--budget=$B"),
        }
        others = {RELEASE.name: RELEASE.read_text(encoding="utf-8")}
        for label, mutated in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(mutated, lines[i])
                copy = "\n".join(lines[:i] + [mutated] + lines[i + 1:])
                violations, _ = gate_budget_violations({**others, PRE_RELEASE.name: copy}, default)
                self.assertTrue([v for v in violations if v.startswith("pre-release.yml:security-scan")],
                                f"mutant '{label}' of pre-release.yml line {i + 1} survived")


    def test_budget_check_reads_a_step_level_timeout(self):
        # G8P6-build-ci-3: a step-level timeout-minutes tighter than the job's
        # bounds the gate too; a mutant adding one to each gate step must fail.
        default = gate_default_budget()
        texts = {p.name: p.read_text(encoding="utf-8") for p in (RELEASE, PRE_RELEASE)}
        hit = 0
        for wf, text in texts.items():
            lines = text.split("\n")
            for i, ln in enumerate(lines):
                if "image-vuln-gate.sh" not in ln or ln.lstrip().startswith("#"):
                    continue
                step = max(j for j in range(i) if lines[j].startswith("      - "))
                for label, extra in (("5", "        timeout-minutes: 5"), ("an expression", "        timeout-minutes: ${{ inputs.t }}")):
                    with self.subTest(workflow=wf, line=i + 1, timeout=label):
                        copy = "\n".join(lines[:step + 1] + [extra] + lines[step + 1:])
                        violations, _ = gate_budget_violations({**texts, wf: copy}, default)
                        self.assertTrue(violations, f"a step timeout of {label} on {wf} line {i + 1} survived")
                hit += 1
        self.assertEqual(hit, 5, "expected the gate called once per publish job and once in pre-release.yml")


# The time the job needs besides the gate's budget: on pre-release.yml the
# checkout and the seven pulls before the gate (docs/ci-architecture.md sizes
# them at 10 minutes), plus the gate's own kill grace and cleanup.
BUDGET_MARGIN = 600


def gate_default_budget():
    return int(re.search(r"^GATE_BUDGET=(\d+)$", GATE.read_text(encoding="utf-8"), re.M).group(1))


def gate_budget_violations(texts, default):
    """[violation], [job] over {workflow name: text}: every image-vuln-gate.sh
    call, its shell continuation lines joined, must have its --budget (or the
    script's default) plus BUDGET_MARGIN within the tighter of its job's and its
    step's timeout-minutes, and a --budget must be a literal number (a variable
    cannot be checked; G8P6-build-ci-3)."""
    violations, checked = [], []
    for wf, text in texts.items():
        for job, body in jobs_of(text).items():
            if "image-vuln-gate.sh" not in _code_lines(body):
                continue
            checked.append(job)
            job_minutes = int(re.search(r"^    timeout-minutes: (\d+)", body, re.M).group(1))
            for step in re.split(r"(?m)^      - ", body)[1:]:
                code = re.sub(r"\\\n\s*", " ", _code_lines(step))
                calls = re.findall(r"image-vuln-gate\.sh([^\n]*)", code)
                if not calls:
                    continue
                minutes = job_minutes
                sm = re.search(r"^(?:        )?timeout-minutes:\s*(\S+)", step, re.M)
                if sm:
                    if not sm.group(1).isdigit():
                        violations.append(f"{wf}:{job}: step timeout-minutes {sm.group(1)} is not a number")
                        continue
                    minutes = min(minutes, int(sm.group(1)))
                for c in calls:
                    m = re.search(r"--budget(?:=|\s+)(\S+)", c)
                    if m and not m.group(1).isdigit():
                        violations.append(f"{wf}:{job}: --budget {m.group(1)} is not a literal number")
                        continue
                    budget = int(m.group(1)) if m else default
                    if budget + BUDGET_MARGIN > minutes * 60:
                        violations.append(f"{wf}:{job}: budget {budget}s + {BUDGET_MARGIN}s > timeout {minutes} min")
    return violations, checked

if __name__ == "__main__":
    unittest.main()
