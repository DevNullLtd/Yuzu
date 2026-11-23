#!/usr/bin/env python3
"""Tests for the release image vulnerability gate (WP15/S9).

scripts/ci/image-vuln-gate.sh runs a pinned Trivy and a pinned grype on each
image and must fail CLOSED: a fixable CRITICAL from either, a scanner error, a
wrong scanner version, a missing ignore file, or an ignore entry without a
reason or an expiry all fail it. The cases here run the real script with a
stub `trivy` (TRIVY_BIN), a stub `grype` (GRYPE_BIN) and a stub `docker` on
PATH, each recording its arguments and answering as told, so no Docker,
network or vulnerability DB is needed.

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
GRYPE_IGNORE = ROOT / ".grypeignore.yaml"
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

# grype, as the gate drives it: `--version`, `db import`, `db status -o json`,
# a record scan (`-o json=F -o table=F docker-archive:A`) and a gate scan
# (`--only-fixed --fail-on critical`). STUB_GRYPE_MODE picks the answer.
GRYPE_STUB = textwrap.dedent(
    """\
    import json, os, sys
    args = sys.argv[1:]
    log = os.environ["STUB_GRYPE_LOG"]
    with open(log, "a", encoding="utf-8") as f:
        f.write(" ".join(args) + "\\n")
    with open(log + ".env", "a", encoding="utf-8") as f:
        f.write(json.dumps({"grype_env": sorted(k for k in os.environ if k.startswith("GRYPE_")),
                            "env": {k: os.environ[k] for k in os.environ if k.startswith("GRYPE_")},
                            "cwd": os.getcwd(), "home": os.environ.get("HOME", ""),
                            "tmpdir": os.environ.get("TMPDIR", "")}) + "\\n")
    mode = os.environ.get("STUB_GRYPE_MODE", "clean")
    if args == ["--version"]:
        print("grype " + ("0.120.0" if mode == "wrong-version" else "0.121.3"))
        sys.exit(0)
    cache = os.environ.get("GRYPE_DB_CACHE_DIR", "")
    if args[:2] == ["db", "import"]:
        if mode == "import-error":
            sys.exit(1)
        if mode == "import-hang":
            import time
            open(log + ".pid", "w").write(str(os.getpid()))
            time.sleep(60)
            sys.exit(0)
        os.makedirs(os.path.join(cache, "6"), exist_ok=True)
        open(os.path.join(cache, "6", "vulnerability.db"), "w").write(open(args[2]).read())
        sys.exit(0)
    if args[:2] == ["db", "providers"]:
        built = os.environ["STUB_GRYPE_BUILT"]
        rows = [{"name": n, "version": "1", "dateCaptured": built}
                for n in ("nvd", "alpine", "debian", "ubuntu", "rhel")]
        # STUB_GRYPE_PROVIDERS picks the providers' state on its own (comma
        # separated), so it combines with any scan mode; else the mode does.
        pmodes = (os.environ.get("STUB_GRYPE_PROVIDERS") or mode).split(",")
        if "provider-stale" in pmodes:
            rows[0]["dateCaptured"] = "2001-01-01T00:00:00Z"
        if "provider-unreadable" in pmodes:
            rows[0]["dateCaptured"] = "last tuesday"
        if "provider-future" in pmodes:
            rows[0]["dateCaptured"] = "2999-01-01T00:00:00Z"
        if "provider-os-stale" in pmodes:
            rows[2]["dateCaptured"] = "2001-01-01T00:00:00Z"  # debian
        if "provider-os-missing" in pmodes:
            rows = [r for r in rows if r["name"] != "debian"]
        if "provider-missing" in pmodes:
            rows = [r for r in rows if r["name"] != "nvd"]
        print(json.dumps(rows))
        sys.exit(0)
    if args[:2] == ["db", "status"]:
        db = os.path.join(cache, "6", "vulnerability.db")
        st = {"schemaVersion": os.environ["STUB_GRYPE_SCHEMA"], "built": os.environ["STUB_GRYPE_BUILT"],
              "path": db, "valid": os.path.exists(db)}
        if mode == "status-mismatch":
            st["built"] = "2001-01-01T00:00:00Z"
        if mode == "status-invalid":
            st["valid"] = False
        print(json.dumps(st))
        sys.exit(0 if st["valid"] else 1)
    target = args[-1]
    if not target.startswith("docker-archive:") or not os.path.exists(target.split(":", 1)[1]):
        sys.exit(1)
    def opt(name):
        return args[args.index(name) + 1] if name in args else ""
    cfg = opt("-c")
    fid = os.environ.get("STUB_GRYPE_FINDING", "CVE-2001-0001")
    suppressed = bool(cfg) and json.dumps(fid) in open(cfg).read()
    if "--fail-on" in args:
        if mode == "gate-error":
            sys.exit(1)
        if mode == "disagree":
            sys.exit(0)
        if mode == "findings" and not suppressed:
            print("CRITICAL finding table")
            sys.exit(2)
        sys.exit(0)
    if mode == "report-error":
        sys.exit(1)
    outs = dict(a.split("=", 1) for a in args if a.startswith(("json=", "table=", "cyclonedx-json=")))
    distro = os.environ.get("STUB_GRYPE_DISTRO", "debian:12.15")
    fam, _, ver = distro.partition(":")
    match = {"vulnerability": {"id": fid, "severity": "Critical", "fix": {"state": "fixed"}},
             "artifact": {"name": "erlang", "version": "28.5.0.2", "type": "binary"}}
    rep = {"descriptor": {"name": "grype", "version": "0.121.3"},
           "source": {"type": "image", "target": {"imageID": "sha256:" + "9" * 64}},
           "distro": {"name": fam, "version": ver} if fam else {},
           "matches": [match] if mode in ("findings", "disagree") and not suppressed else [],
           "ignoredMatches": [match] if mode == "findings" and suppressed else []}
    if mode == "not-grype":
        rep = {"SchemaVersion": 2}
    open(outs["json"], "w").write(json.dumps(rep))
    open(outs["table"], "w").write("" if mode == "empty-table" else "NAME INSTALLED TYPE VULNERABILITY\\n")
    comps = [{"name": "erlang", "version": "28.5.0.8", "type": "application",
              "purl": "pkg:generic/erlang@28.5.0.8"}]
    if mode == "no-erlang":
        comps = []
    if mode == "erlang-misread":  # grype reads the ERTS version instead of OTP's
        comps = [{"name": "erlang", "version": "16.4.0.7", "purl": "pkg:generic/erlang@16.4.0.7"}]
    if mode == "os-erlang":  # an OS package of the same name is not the runtime
        # Same name AND the expected version: only the purl tells it apart.
        comps = [{"name": "erlang", "version": "28.5.0.8", "purl": "pkg:apk/alpine/erlang@28.5.0.8"}]
    if "cyclonedx-json" in outs:
        open(outs["cyclonedx-json"], "w").write(json.dumps({"bomFormat": "CycloneDX", "components": comps}))
    sys.exit(0)
    """
)

# docker, as the gate drives it for grype: `image inspect --format {{.Id}} IMG`
# and `save -o FILE ID`. An image in STUB_MISSING_IMAGES is not in the daemon.
GATE_DOCKER_STUB = textwrap.dedent(
    """\
    import os, sys
    args = sys.argv[1:]
    with open(os.environ["STUB_DOCKER_LOG"], "a", encoding="utf-8") as f:
        f.write(" ".join(args) + "\\n")
    mode = os.environ.get("STUB_DOCKER_MODE", "ok")
    if args[:2] == ["image", "inspect"] and os.environ.get("STUB_DOCKER_NO_STALE_ARCHIVE") == "1":
        # The previous image's `docker save` archive must be gone before the
        # next image is resolved: archives are full images, on a shared runner.
        import glob
        stale = glob.glob(os.path.join(os.environ["RUNNER_TEMP"], "yuzu-image-vuln-gate.*", "image.tar"))
        if stale:
            sys.stderr.write("stale archive: %s\\n" % stale)
            sys.exit(1)
    if args[:2] == ["image", "inspect"]:
        if args[-1] in os.environ.get("STUB_MISSING_IMAGES", "").split(","):
            sys.exit(1)
        print("not-an-id" if mode == "garbage-id" else "sha256:" + "9" * 64)
        sys.exit(0)
    if args[0] == "save":
        if mode == "save-error":
            sys.exit(1)
        open(args[args.index("-o") + 1], "w").write("archive of " + args[-1])
        sys.exit(0)
    sys.exit(2)
    """
)
GRYPE_DB_ARCHIVE = "vulnerability-db_v6.1.10_2026-11-20T00:20:17Z_1795155660.tar.zst"
GRYPE_DB_SCHEMA = "v6.1.10"


def grype_db_fixture(root, built_hours_ago=2, body=b"grype db", tamper=False, listing_over=None):
    """A directory holding latest.json and the archive it names (the gate's
    YUZU_GATE_TEST_GRYPE_DB_DIR). Returns (dir, built)."""
    import hashlib
    d = Path(root)
    d.mkdir(parents=True, exist_ok=True)
    built = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(hours=built_hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (d / GRYPE_DB_ARCHIVE).write_bytes(body + (b"x" if tamper else b""))
    listing = {"status": "active", "schemaVersion": GRYPE_DB_SCHEMA, "built": built,
               "path": GRYPE_DB_ARCHIVE, "checksum": "sha256:" + hashlib.sha256(body).hexdigest()}
    listing.update(listing_over or {})
    (d / "latest.json").write_text(json.dumps(listing), encoding="utf-8")
    return d, built

def repo_grype_ignore(tmp):
    """The repository's .grypeignore.yaml with any `provider_waivers:` section
    removed, written under `tmp`. The gate cases default to it, so a provider
    waiver committed under the stalled-provider runbook (or one left to expire)
    changes no test's outcome but the repository-file checks that are meant to
    see it."""
    p = Path(tmp) / "repo-grypeignore.yaml"
    p.write_text(strip_provider_waivers(GRYPE_IGNORE.read_text(encoding="utf-8")), encoding="utf-8")
    return p


def strip_provider_waivers(text):
    out, skip = [], False
    for ln in text.split("\n"):
        if ln and not ln[0].isspace() and not ln.startswith("#"):
            skip = ln.rstrip() == "provider_waivers:"
        if not skip:
            out.append(ln)
    return "\n".join(out)


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


def waiver(**over):
    """One well-formed provider waiver, as YAML lines under `provider_waivers:`."""
    f = {"provider": "nvd", "statement": "the NVD feed has not refreshed since the upstream API outage",
         "expired_at": days(7), "approved_by": "some-login", "approved_on": days(-1), "approval_ref": '"#1234"'}
    f.update(over)
    out = [f"  - provider: {f['provider']}"]
    for k in ("statement", "expired_at", "approved_by", "approved_on", "approval_ref"):
        if f.get(k) is not None:
            out.append(f"    {k}: {f[k]}")
    return "\n".join(out) + "\n"


def gate_lines(text):
    """The lines image-publish.sh's gates_pass counts as a verdict."""
    return [ln for ln in text.splitlines() if re.search(r"(^|\s)gate:", ln)]


@unittest.skipUnless(have_bash(), "the gate is a bash script")
class GateBehaviour(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_vuln_gate_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / "trivy"
        self.stub.write_text(f"#!{sys.executable}\n" + STUB, encoding="utf-8")
        self.stub.chmod(self.stub.stat().st_mode | stat.S_IXUSR)
        self.log = self.tmp / "calls.log"
        self.grype = self.tmp / "grype"
        self.grype.write_text(f"#!{sys.executable}\n" + GRYPE_STUB, encoding="utf-8")
        self.grype.chmod(self.grype.stat().st_mode | stat.S_IXUSR)
        self.glog = self.tmp / "grype.log"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(f"#!{sys.executable}\n" + GATE_DOCKER_STUB, encoding="utf-8")
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        self.dlog = self.tmp / "docker.log"
        self.gdb, self.gdb_built = grype_db_fixture(self.tmp / "grype-db-src")

    def grype_env(self, grype_mode="clean", grype_ignore=None, distro="debian:12.15", gdb=None,
                  built=None):
        if grype_ignore is None:
            grype_ignore = repo_grype_ignore(self.tmp)
        return dict(
            GRYPE_BIN=str(self.grype),
            STUB_GRYPE_LOG=str(self.glog),
            STUB_GRYPE_MODE=grype_mode,
            STUB_GRYPE_DISTRO=distro,
            STUB_GRYPE_BUILT=built or self.gdb_built,
            STUB_GRYPE_SCHEMA=GRYPE_DB_SCHEMA,
            STUB_DOCKER_LOG=str(self.dlog),
            YUZU_GRYPEIGNORE=str(grype_ignore),
            YUZU_GATE_TEST_GRYPE_DB_DIR=str(gdb or self.gdb),
        )

    def run_gate(self, *images, mode="clean", ignore=IGNORE, bad_image="", extra=(), missing="",
                 db="fresh", os_pkgs="5", env_extra=None, gate=GATE, grype_mode="clean",
                 grype_ignore=None, distro=None):
        env = dict(os.environ)
        for k in list(env):
            if k.startswith("TRIVY_") or k.startswith("STUB_") or k.startswith("GRYPE_"):
                del env[k]
        env.pop("GITHUB_ACTIONS", None)
        env.pop("GITHUB_STEP_SUMMARY", None)
        # grype detects the OS the Trivy stub reports unless told otherwise.
        distro = os.environ.get("STUB_OS", "debian:12.15") if distro is None else distro
        if env_extra and "STUB_OS" in env_extra and distro == "debian:12.15":
            distro = env_extra["STUB_OS"]
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
            PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            **self.grype_env(grype_mode, grype_ignore, distro),
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

    def gcalls(self):
        return self.glog.read_text(encoding="utf-8").splitlines() if self.glog.exists() else []

    def gscans(self):
        """grype's image scans (not --version, not db)."""
        return [c.split() for c in self.gcalls() if c != "--version" and not c.startswith("db ")]

    def dcalls(self):
        return self.dlog.read_text(encoding="utf-8").splitlines() if self.dlog.exists() else []

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
        r = self.run_gate("img:1", grype_ignore=GRYPE_IGNORE, env_extra={"GITHUB_ACTIONS": "true"})
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
        self.assertEqual(names, sorted(f"{sc}-img.attempt-{n}.{s}" for sc in ("grype", "trivy") for n in (1, 2)
                                       for s in ("gate.txt", "json", "txt")))
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
            if k.startswith(("TRIVY_", "STUB_", "GITHUB_", "GRYPE_")):
                del env[k]
        env.update(TRIVY_BIN=str(self.stub), STUB_LOG=str(self.log), STUB_MODE=mode,
                   YUZU_TRIVYIGNORE=str(IGNORE), YUZU_GATE_TEST_DB_DIGEST=DB_DIGEST,
                   RUNNER_TEMP=str(self.tmp), PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
                   **self.grype_env())
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
        # run_grype's own `child "$limit" ...` passes on the deadline its
        # callers name; every run_grype call is held to the same rule.
        inner = [c for c in calls if c.startswith('"$limit" env -C ')]
        self.assertEqual(len(inner), 1, calls)
        calls = [c for c in calls if c not in inner]
        calls += [m for ln in code for m in re.findall(r"(?:^|[\s!&|])run_grype (.*)", ln)]
        self.assertGreaterEqual(len(calls), 12, calls)
        for c in calls:
            self.assertRegex(c, r'^("\$[A-Z_]+_DEADLINE"|\$\(\([A-Z_]+_DEADLINE \+ [0-9]+\)\)) ', c)
        self.assertIn('SCAN_TIMEOUT=(--timeout "$((SCAN_DEADLINE - 10))s")', text)
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for scan in self.scans() + self.canaries():
            self.assertIn("--timeout", scan)


    # ── grype, the second scanner (WP15) ──
    def grype_entry(self, **over):
        f = {"id": "CVE-2001-0001", "package_name": "erlang", "package_version": "28.5.0.2",
             "package_type": "binary", "statement": "not reachable", "expired_at": days(30),
             "approved_by": "some-login", "approved_on": days(-1), "approval_ref": '"#1234"'}
        f.update(over)
        out = [f"  - id: {f['id']}"]
        for k in ("package_name", "package_version", "package_type", "statement", "expired_at",
                  "approved_by", "approved_on", "approval_ref"):
            if f.get(k) is not None:
                out.append(f"    {k}: {f[k]}")
        return "\n".join(out) + "\n"

    def write_grype_ignore(self, body, waivers=None, name="grypeignore.yaml"):
        p = self.tmp / name
        p.write_text("vulnerabilities:\n" + body + ("provider_waivers:\n" + waivers if waivers is not None else ""),
                     encoding="utf-8")
        return p

    def test_grype_scans_a_docker_save_of_the_local_id(self):
        r = self.run_gate("img:1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.dcalls()[0], "image inspect --format {{.Id}} img:1")
        save = self.dcalls()[1].split()
        self.assertEqual(save[0], "save")
        self.assertEqual(save[-1], "sha256:" + "9" * 64, "grype must read the image ID, not the tag")
        archive = save[save.index("-o") + 1]
        self.assertTrue(archive.startswith(str(self.tmp / "yuzu-image-vuln-gate.")), archive)
        scans = self.gscans()
        self.assertEqual(len(scans), 2, self.gcalls())
        record, gate = scans
        for a in scans:
            self.assertEqual(a[-1], "docker-archive:" + archive, "never `docker:`, which pulls a missing image")
            cfg = a[a.index("-c") + 1]
            self.assertTrue(cfg.endswith("/grype-config.yaml") and cfg != str(GRYPE_IGNORE), cfg)
        self.assertTrue(any(x.startswith("json=") for x in record) and any(x.startswith("table=") for x in record))
        self.assertNotIn("--only-fixed", record, "the record keeps every match")
        self.assertIn("--only-fixed", gate)
        self.assertEqual(gate[gate.index("--fail-on") + 1], "critical")

    def test_grype_finding_fails_the_image_even_when_trivy_is_clean(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", grype_mode="findings", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("grype found a fixable CRITICAL", r.stderr)
        self.assertIn("gate: pass", (rep / "trivy-img.gate.txt").read_text(encoding="utf-8"))
        g = (rep / "grype-img.gate.txt").read_text(encoding="utf-8")
        for field in ("gate: FAIL: fixable CRITICAL", "grype: 0.121.3", "image id: sha256:" + "9" * 64,
                      "grype db: https://grype.anchore.io/databases/v6/" + GRYPE_DB_ARCHIVE + " (sha256:",
                      "schema " + GRYPE_DB_SCHEMA, "distro: debian 12.15"):
            self.assertIn(field, g)
        for suffix in (".json", ".txt"):
            self.assertTrue((rep / f"grype-img{suffix}").is_file(), suffix)

    def test_grype_must_catalogue_the_gateways_otp_runtime(self):
        rep = self.tmp / "rep-ok"
        r = self.run_gate("yuzu-gateway=img:1", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("required components: erlang 28.5.0.8",
                      (rep / "grype-yuzu-gateway.gate.txt").read_text(encoding="utf-8"))
        rec = [a for a in self.gscans() if "--fail-on" not in a][0]
        self.assertTrue(any(x.startswith("cyclonedx-json=") for x in rec), rec)
        rep = self.tmp / "rep-none"
        r = self.run_gate("yuzu-gateway=img:1", grype_mode="no-erlang", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gate: FAIL: grype did not catalogue erlang",
                      (rep / "grype-yuzu-gateway.gate.txt").read_text(encoding="utf-8"))
        r = self.run_gate("yuzu-gateway=img:1", grype_mode="os-erlang")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("did not catalogue erlang", r.stdout + r.stderr)
        r = self.run_gate("yuzu-gateway=img:1", grype_mode="erlang-misread")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("erlang 16.4.0.7 (expected 28.5.0.8)", r.stdout + r.stderr)
        # An image with no required component is not held to it.
        r = self.run_gate("yuzu-server=img:1", grype_mode="no-erlang")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_stale_os_provider_refuses_only_images_on_that_os(self):
        rep = self.tmp / "rep-deb"
        r = self.run_gate("img:1", grype_mode="provider-os-stale", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gate: FAIL: grype DB provider debian is stale",
                      (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))
        r = self.run_gate("img:1", grype_mode="provider-os-stale", env_extra={"STUB_OS": "alpine:3.23.8"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_pass_beside_a_record_with_an_unaccepted_fixable_critical_fails(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", grype_mode="disagree", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gate: FAIL: grype's record and gate scans disagree",
                      (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_grype_errors_fail_closed(self):
        for mode, why in (("gate-error", "FAIL: grype exited 1"), ("report-error", "could not scan"),
                          ("not-grype", "could not scan"), ("empty-table", "could not scan")):
            with self.subTest(mode=mode):
                rep = self.tmp / ("rep-" + mode)
                r = self.run_gate("img:1", grype_mode=mode, extra=("--report-dir", str(rep)))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_grype_never_scans_an_image_missing_from_the_daemon(self):
        rep = self.tmp / "rep"
        r = self.run_gate("gone:1", missing="gone:1", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([c for c in self.dcalls() if c.startswith("save")], [])
        self.assertEqual(self.gscans(), [])
        self.assertIn("FAIL: not an image in the local Docker daemon",
                      (rep / "grype-gone.gate.txt").read_text(encoding="utf-8"))

    def test_an_early_grype_failure_is_not_reported_again_as_stopped(self):
        # Without --report-dir the early-fail paths must still mark the image as
        # judged, or the exit trap adds a false "gate stopped" summary row.
        for kw in ({"missing": "gone:1"}, {"env_extra": {"STUB_DOCKER_MODE": "save-error"}}):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                summ = self.tmp / "summary.md"
                summ.unlink(missing_ok=True)
                extra_env = dict(kw.get("env_extra", {}), GITHUB_STEP_SUMMARY=str(summ))
                r = self.run_gate("gone:1", missing=kw.get("missing", ""), env_extra=extra_env)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                rows = [ln for ln in summ.read_text(encoding="utf-8").splitlines() if "(grype)" in ln]
                self.assertEqual(len(rows), 1, rows)
                self.assertNotIn("gate stopped", rows[0])

    def test_an_export_failure_or_a_non_id_answer_fails(self):
        for dmode, why in (("save-error", "could not export"), ("garbage-id", "not an image in the local")):
            with self.subTest(docker=dmode):
                rep = self.tmp / ("rep-" + dmode)
                r = self.run_gate("img:1", extra=("--report-dir", str(rep)), env_extra={"STUB_DOCKER_MODE": dmode})
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_each_image_archive_is_removed_before_the_next_image(self):
        r = self.run_gate("a=img:1", "b=img:2", env_extra={"STUB_DOCKER_NO_STALE_ARCHIVE": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(len([c for c in self.dcalls() if c.startswith("save ")]), 2, self.dcalls())

    def test_a_trivy_failure_still_runs_grype_for_the_record(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", mode="report-error", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL: Trivy could not scan", (rep / "trivy-img.gate.txt").read_text(encoding="utf-8"))
        self.assertIn("gate: pass", (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_wrong_grype_version_is_refused_before_any_scan(self):
        r = self.run_gate("img:1", grype_mode="wrong-version")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("is not grype 0.121.3", r.stderr)
        self.assertEqual(self.scans(), [])
        self.assertEqual(self.gscans(), [])

    def test_grype_bin_is_refused_on_github_actions_and_the_db_hook_needs_it(self):
        r = self.run_gate("img:1", grype_ignore=GRYPE_IGNORE, env_extra={"GITHUB_ACTIONS": "true", "TRIVY_BIN": None})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("GRYPE_BIN is for local runs", r.stdout + r.stderr)
        r = self.run_gate("img:1", env_extra={"GRYPE_BIN": None})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("YUZU_GATE_TEST_GRYPE_DB_DIR is a test hook", r.stdout + r.stderr)

    def test_grype_environment_is_the_gates_own(self):
        hostile = {"GRYPE_EXCLUDE": "**", "GRYPE_IGNORE_STATES": "fixed", "GRYPE_DB_CACHE_DIR": "/nowhere",
                   "GRYPE_CONFIG": "/etc/x.yaml", "GRYPE_DB_AUTO_UPDATE": "true"}
        r = self.run_gate("img:1", env_extra=hostile)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        envs = [json.loads(ln) for ln in Path(str(self.glog) + ".env").read_text().splitlines()]
        want = {"GRYPE_CHECK_FOR_APP_UPDATE": "false", "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "72h", "GRYPE_DB_REQUIRE_UPDATE_CHECK": "false",
                "GRYPE_DB_VALIDATE_AGE": "true"}
        self.assertEqual(len(envs), len(self.gcalls()))
        for call, e in zip(self.gcalls(), envs):
            self.assertEqual({k: v for k, v in e["env"].items() if k != "GRYPE_DB_CACHE_DIR"}, want, e)
            self.assertTrue(e["env"]["GRYPE_DB_CACHE_DIR"].startswith(str(self.tmp / "yuzu-image-vuln-gate.")))
            # TMPDIR moves into the work directory after the version checks, as for Trivy.
            for k in ("cwd", "home") + (("tmpdir",) if call != "--version" else ()):
                self.assertTrue(e[k].startswith(str(self.tmp / "yuzu-image-vuln-gate.")), (k, call, e))
        self.assertEqual(list(self.tmp.glob("yuzu-image-vuln-gate.*")), [], "WORK not removed")

    def run_with_db(self, grype_mode="clean", **fixture):
        gdb, built = grype_db_fixture(self.tmp / ("gdb-" + str(len(list(self.tmp.glob("gdb-*"))))), **fixture)
        env = self.grype_env(grype_mode, gdb=gdb, built=built)
        return self.run_gate("img:1", env_extra=env)

    def test_grype_db_must_be_fresh_verified_and_the_one_imported(self):
        cases = {
            "stale listing": ({"built_hours_ago": 100}, "clean", "more than 72"),
            "future listing": ({"built_hours_ago": -5}, "clean", "in the future"),
            "tampered archive": ({"tamper": True}, "clean", "does not match the listing"),
            "not active": ({"listing_over": {"status": "deprecated"}}, "clean", "is not 'active'"),
            "schema v5": ({"listing_over": {"schemaVersion": "v5.0.1"}}, "clean", "is not v6"),
            "path escapes": ({"listing_over": {"path": "../vulnerability-db_v6.1.10_x_1.tar.zst"}}, "clean",
                             "bare vulnerability-db_v6 archive name"),
            "bad checksum": ({"listing_over": {"checksum": "md5:00"}}, "clean", "is not sha256"),
            "import fails": ({}, "import-error", "could not import"),
            "status mismatch": ({}, "status-mismatch", "not the DB this run verified"),
            "status invalid": ({}, "status-invalid", "not valid"),
            "provider stale": ({}, "provider-stale", "provider nvd"),
            "provider missing": ({}, "provider-missing", "provider 'nvd' is not in the DB"),
        }
        for label, (fixture, gmode, why) in cases.items():
            with self.subTest(label):
                self.glog.unlink(missing_ok=True)
                r = self.run_with_db(gmode, **fixture)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, r.stdout + r.stderr)
                self.assertEqual(self.gscans(), [], "no image is scanned with an unverified or stale DB")

    def test_grype_acceptance_is_honoured_by_scope_and_only_when_approved(self):
        ok = self.write_grype_ignore(self.grype_entry())
        rep = self.tmp / "rep-accepted"
        r = self.run_gate("img:1", grype_mode="findings", grype_ignore=ok,
                          extra=("--release", "--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = (rep / "grype-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("matches: 0 not accepted, of them fixable CRITICAL: 0", g)
        self.assertIn("accepted (ignoredMatches): 1, of them fixable CRITICAL: 1", g)
        # A pending approval is not honoured by a release, and is outside one.
        pend = self.write_grype_ignore(self.grype_entry(approved_on=None, approval_ref="pending"))
        r = self.run_gate("img:1", grype_mode="findings", grype_ignore=pend, extra=("--release",))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("NOT IN FORCE", r.stdout)
        r = self.run_gate("img:1", grype_mode="findings", grype_ignore=pend)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # An expired acceptance is not in force.
        old = self.write_grype_ignore(self.grype_entry(expired_at=days(-1)))
        r = self.run_gate("img:1", grype_mode="findings", grype_ignore=old)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_grype_ignore_file_missing_or_malformed_is_refused_before_any_scan(self):
        cases = {
            "absent": self.tmp / "absent.yaml",
            "no version": self.write_grype_ignore(self.grype_entry(package_version=None)),
        }
        for label, path in cases.items():
            with self.subTest(label):
                self.log.unlink(missing_ok=True)
                r = self.run_gate("img:1", grype_ignore=path)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(self.scans(), [])
                self.assertEqual(self.gscans(), [])

    def test_grype_must_detect_the_os_trivy_scanned(self):
        for distro in ("", "alpine:3.23.8"):
            with self.subTest(distro=distro or "none"):
                rep = self.tmp / ("rep-" + (distro.replace(":", "-") or "none"))
                r = self.run_gate("img:1", distro=distro, extra=("--report-dir", str(rep)))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("FAIL: grype did not detect the OS (debian)",
                              (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_no_os_cross_check_for_an_image_listed_as_not_covered(self):
        ci = self.tmp / "tree" / "scripts" / "ci"
        ci.mkdir(parents=True)
        for f in (GATE, CHECKS):
            shutil.copy2(f, ci / f.name)
        (ci / NOT_COVERED.name).write_text(nc_line(), encoding="utf-8")
        r = self.run_gate("yuzu-server-chisel=img:3", os_pkgs="0", distro="", gate=ci / GATE.name)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_required_component_versions_are_the_otp_each_gateway_dockerfile_pins(self):
        # A builder bump must update the gate's table (and so re-run the real
        # gate by hand); a table naming another OTP than the image ships would
        # refuse every gateway release leg.
        text = GATE.read_text(encoding="utf-8")
        table = dict(re.findall(r'^\s+\[([a-z0-9-]+)\]="erlang=([0-9.]+)"$', text, re.M))
        self.assertEqual(set(table), {"yuzu-gateway", "yuzu-gateway-chisel"}, table)
        df = (ROOT / "deploy" / "docker" / "Dockerfile.gateway").read_text(encoding="utf-8")
        m = re.search(r"^FROM hexpm/erlang:([0-9.]+)-alpine-[0-9.]+@sha256:[0-9a-f]{64} AS deps$", df, re.M)
        self.assertIsNotNone(m, "Dockerfile.gateway's hexpm/erlang builder line changed shape")
        self.assertEqual(table["yuzu-gateway"], m.group(1))
        chisel = (ROOT / "deploy" / "docker" / "Dockerfile.gateway.chisel").read_text(encoding="utf-8")
        m = re.search(r"^# erlang:28 = OTP ([0-9.]+) ", chisel, re.M)
        self.assertIsNotNone(m, "Dockerfile.gateway.chisel no longer states its builder's OTP")
        self.assertEqual(table["yuzu-gateway-chisel"], m.group(1))

    def test_a_cancel_during_the_grype_db_import_reports_and_leaves_nothing(self):
        import signal
        import time
        rep = self.tmp / "rep"
        env = dict(os.environ)
        for k in list(env):
            if k.startswith(("TRIVY_", "STUB_", "GITHUB_", "GRYPE_")):
                del env[k]
        env.update(TRIVY_BIN=str(self.stub), STUB_LOG=str(self.log), STUB_MODE="clean",
                   YUZU_TRIVYIGNORE=str(IGNORE), YUZU_GATE_TEST_DB_DIGEST=DB_DIGEST, RUNNER_TEMP=str(self.tmp),
                   PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}", **self.grype_env("import-hang"))
        pidfile = Path(str(self.glog) + ".pid")
        p = subprocess.Popen(["bash", str(GATE), "--report-dir", str(rep), "a=img:1"], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 30
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(pidfile.exists(), "the stub import never started")
        time.sleep(0.2)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 143, out + err)
        for sc in ("trivy", "grype"):
            self.assertIn("gate: FAIL: cancelled (SIGTERM) before this image was judged",
                          (rep / f"{sc}-a.gate.txt").read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)  # the import was stopped, not left running
        self.assertEqual(list(self.tmp.glob("yuzu-image-vuln-gate.*")), [], "WORK not removed")

    def test_budget_and_cancel_reports_cover_grype_too(self):
        rep = self.tmp / "rep"
        p = self.start_gate("a=img:1", extra=("--budget", "3", "--report-dir", str(rep)), mode="hang-stubborn")
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 1, out + err)
        g = (rep / "grype-a.gate.txt").read_text(encoding="utf-8")
        self.assertIn("gate: FAIL: gate stopped before this image was judged: the gate ran out of its 3s budget", g)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(Path(str(self.log) + ".pid").read_text()), 0)


@unittest.skipUnless(have_bash(), "the gate is a bash script")
class GrypeMutants(unittest.TestCase):
    """Each grype rule the gate adds (WP15) must be load-bearing: a copy of the
    gate (and its checker) with that one rule mutated away must give the WRONG
    answer on the scenario that rule exists for, while the real gate gives the
    right one. A mutant that still fails the scenario closed would mean the
    scenario does not test the rule. The original text must be present exactly
    once, so a rewrite of the gate re-aims this test instead of passing it."""

    setUp = GateBehaviour.setUp
    grype_env = GateBehaviour.grype_env
    run_gate = GateBehaviour.run_gate
    grype_entry = GateBehaviour.grype_entry
    write_grype_ignore = GateBehaviour.write_grype_ignore

    def mutant(self, label, gate_edits=(), checks_edits=()):
        ci = self.tmp / ("mutant-" + re.sub(r"[^a-z0-9]+", "-", label.lower())) / "scripts" / "ci"
        ci.mkdir(parents=True)
        for src, edits in ((GATE, gate_edits), (CHECKS, checks_edits)):
            text = src.read_text(encoding="utf-8")
            for old, new in edits:
                self.assertEqual(text.count(old), 1, f"{label}: re-aim this mutant, {old!r} is not in {src.name} once")
                text = text.replace(old, new)
            (ci / src.name).write_text(text, encoding="utf-8")
        shutil.copy2(NOT_COVERED, ci / NOT_COVERED.name)
        return ci / GATE.name

    def assert_killed(self, label, scenario, gate_edits=(), checks_edits=()):
        real = scenario(GATE)
        self.assertEqual(real.returncode, 1, f"{label}: the real gate must refuse this scenario\n"
                         + real.stdout + real.stderr)
        mutated = scenario(self.mutant(label, gate_edits, checks_edits))
        self.assertEqual(mutated.returncode, 0, f"mutant '{label}' survived: the scenario does not test the rule\n"
                         + mutated.stdout + mutated.stderr)

    def test_mutants_of_the_grype_rules_are_killed(self):
        findings = lambda gate: self.run_gate("img:1", grype_mode="findings", gate=gate)  # noqa: E731
        no_os = lambda gate: self.run_gate("img:1", distro="", gate=gate)  # noqa: E731

        def with_db(gmode="clean", **fixture):
            def run(gate):
                n = len(list(self.tmp.glob("gdb-*")))
                gdb, built = grype_db_fixture(self.tmp / f"gdb-{n}", **fixture)
                return self.run_gate("img:1", gate=gate, env_extra=self.grype_env(gmode, gdb=gdb, built=built))
            return run

        def pending_in_release(gate):
            ign = self.write_grype_ignore(self.grype_entry(approved_on=None, approval_ref="pending"))
            return self.run_gate("img:1", grype_mode="findings", grype_ignore=ign, extra=("--release",), gate=gate)

        cases = [
            # With the disagreement check also off: it independently refuses a
            # pass beside an unaccepted fixable CRITICAL in the record.
            ("grype exit 2 read as a pass", findings,
             [('--fail-on critical -o table \\\n        "docker-archive:$ARCHIVE" 2>"$WORK/grype.err" || rc=$?',
               '--fail-on critical -o table \\\n        "docker-archive:$ARCHIVE" 2>"$WORK/grype.err" || true'),
              ('           elif [ "$fcrit" != 0 ]; then', '           elif false; then')], []),
            ("grype not run on a Trivy-covered image", findings,
             [('    grype_scan "$name" "$image" "$want_family"\n', "")], []),
            ("DB archive checksum not checked", with_db(tamper=True),
             [('echo "${gdb_sum#sha256:}  $WORK/$gdb_path" | sha256sum -c --quiet - \\',
               'echo "${gdb_sum#sha256:}  $WORK/$gdb_path" | cat >/dev/null \\')], []),
            ("imported DB status not checked", with_db("status-mismatch"),
             [('if ! gstat="$("${CHECKS[@]}" grype-db-status "$WORK/grype-db-status.json" --built "$gdb_built" '
               '--schema "$gdb_schema")"; then',
               'if ! gstat="$(true)"; then')], []),
            ("DB age not checked", with_db(built_hours_ago=100),
             [], [("    if age_h > MAX_DB_AGE_HOURS:\n        return \"stale\"", "    if False:\n        return \"stale\"")]),
            ("OS cross-check dropped", no_os,
             [('if [ -n "$want_family" ] && [ "$distro" != "$want_family" ]; then',
               'if false; then')], []),
            ("required component not checked", lambda gate: self.run_gate("yuzu-gateway=img:1",
                                                                          grype_mode="no-erlang", gate=gate),
             [('           elif [ "$comps_ok" != 1 ]; then', '           elif false; then')], []),
            ("scan disagreement ignored", lambda gate: self.run_gate("img:1", grype_mode="disagree", gate=gate),
             [('           elif [ "$fcrit" != 0 ]; then', '           elif false; then')], []),
            ("provider freshness not checked", with_db("provider-stale"),
             [('if ! gprov="$("${CHECKS[@]}" grype-db-providers "$WORK/grype-db-providers.json" --waivers '
               '"$GRYPE_WAIVERS" \\\n        "${GRYPE_REQUIRED_PROVIDERS[@]}")"; then', 'if ! gprov="$(true)"; then')], []),
            ("OS provider freshness not checked", lambda gate: self.run_gate("img:1", grype_mode="provider-os-stale",
                                                                             gate=gate),
             [('           elif [ -n "$want_family" ] && ! pinfo="$("${CHECKS[@]}" grype-db-providers',
               '           elif false && ! pinfo="$("${CHECKS[@]}" grype-db-providers')], []),
            ("pending grype acceptance honoured in a release", pending_in_release,
             [('[ "$RELEASE" = 0 ] || gign_flags+=(--require-approved)', ':')], []),
        ]
        for label, scenario, gate_edits, checks_edits in cases:
            with self.subTest(mutant=label):
                self.assert_killed(label, scenario, gate_edits, checks_edits)


@unittest.skipUnless(have_bash(), "the gate is a bash script")
class ProviderWaiver(unittest.TestCase):
    """A provider waiver in .grypeignore.yaml admits ONE grype DB provider whose
    capture is merely older than 72 hours, says so in the reports, and waives
    nothing else."""

    setUp = GateBehaviour.setUp
    grype_env = GateBehaviour.grype_env
    run_gate = GateBehaviour.run_gate
    grype_entry = GateBehaviour.grype_entry
    write_grype_ignore = GateBehaviour.write_grype_ignore
    calls = GateBehaviour.calls
    write_ignore = GateBehaviour.write_ignore
    gcalls = GateBehaviour.gcalls
    gscans = GateBehaviour.gscans
    scans = GateBehaviour.scans

    def waived(self, *waivers, name="grypeignore.yaml"):
        return self.write_grype_ignore("", waivers="".join(waivers), name=name)

    def test_a_waiver_admits_a_stale_nvd_and_every_report_says_degraded(self):
        rep = self.tmp / "rep"
        summ = self.tmp / "summary.md"
        r = self.run_gate("yuzu-server=img:1", grype_mode="provider-stale", grype_ignore=self.waived(waiver()),
                          extra=("--release", "--attempt", "1", "--report-dir", str(rep)),
                          env_extra={"GITHUB_STEP_SUMMARY": str(summ)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = (rep / "grype-yuzu-server.attempt-1.gate.txt").read_text(encoding="utf-8")
        self.assertEqual(gate_lines(g), ["gate: pass"], g)
        line = [ln for ln in g.splitlines() if ln.startswith("provider waiver: ")]
        self.assertEqual(len(line), 1, g)
        for part in ("provider nvd captured 2001-01-01T00:00:00Z", "hours old (over the 72-hour limit)",
                     "grypeignore.yaml:3", f"expires {days(7)}", "approved_by some-login",
                     "approval_ref #1234", f"approved_on {days(-1)}"):
            self.assertIn(part, line[0])
        self.assertIn("DEGRADED: provider waiver in force (nvd)", g)
        self.assertIn("1 provider waiver(s) in force", g)
        s = summ.read_text(encoding="utf-8")
        self.assertIn("**DEGRADED: provider waiver in force** for grype DB provider(s) nvd", s)
        self.assertIn("| pass (DEGRADED: provider waiver in force: nvd) |", s)
        self.assertIn("DEGRADED: provider waiver in force for grype DB provider(s) nvd", r.stdout)
        # Trivy's verdict is untouched, and the publish journal still opens on it.
        self.assertNotIn("waiver", (rep / "trivy-yuzu-server.attempt-1.gate.txt").read_text(encoding="utf-8"))
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        o = subprocess.run(["bash", str(PUBLISH), "open", str(rep), "yuzu-server", "1"],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)

    def test_without_a_waiver_the_report_says_none_was_used(self):
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = (rep / "grype-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("provider waiver: none used", g)
        self.assertNotIn("DEGRADED", g + r.stdout)
        # A waiver in force for a provider that is current is not used either.
        r = self.run_gate("img:1", grype_ignore=self.waived(waiver()), extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = (rep / "grype-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("provider waiver: none used", g)
        self.assertNotIn("DEGRADED", g + r.stdout)

    def test_an_os_provider_waiver_degrades_only_the_images_on_that_os(self):
        rep = self.tmp / "rep"
        r = self.run_gate("deb=img:1", grype_mode="provider-os-stale",
                          grype_ignore=self.waived(waiver(provider="debian")), extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = (rep / "grype-deb.gate.txt").read_text(encoding="utf-8")
        self.assertIn("DEGRADED: provider waiver in force (debian)", g)
        self.assertIn("provider waiver: provider debian captured", g)
        r = self.run_gate("alp=img:1", grype_mode="provider-os-stale",
                          grype_ignore=self.waived(waiver(provider="debian")), extra=("--report-dir", str(rep)),
                          env_extra={"STUB_OS": "alpine:3.23.8"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("provider waiver: none used", (rep / "grype-alp.gate.txt").read_text(encoding="utf-8"))

    def test_a_waiver_for_another_provider_admits_nothing(self):
        for pmode, wprov, why in (("provider-stale", "debian", "provider nvd"),
                                  ("provider-stale", "alpine", "provider nvd"),
                                  ("provider-os-stale", "nvd", "grype DB provider debian is stale"),
                                  ("provider-os-stale", "ubuntu", "grype DB provider debian is stale")):
            with self.subTest(stale=pmode, waived=wprov):
                rep = self.tmp / f"rep-{pmode}-{wprov}"
                r = self.run_gate("img:1", grype_mode=pmode, grype_ignore=self.waived(waiver(provider=wprov)),
                                  extra=("--report-dir", str(rep)))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, r.stdout + r.stderr + (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_a_waiver_waives_nothing_but_a_stale_provider(self):
        nvd = self.waived(waiver(), waiver(provider="debian"))

        def with_db(gmode="clean", **fixture):
            n = len(list(self.tmp.glob("gdb-*")))
            gdb, built = grype_db_fixture(self.tmp / f"gdb-{n}", **fixture)
            env = self.grype_env(gmode, grype_ignore=nvd, gdb=gdb, built=built)
            return dict(env_extra=env)

        stale = {"STUB_GRYPE_PROVIDERS": "provider-stale,provider-os-stale"}
        cases = {
            "a missing provider": (dict(grype_mode="provider-missing"), "provider 'nvd' is not in the DB"),
            "a missing OS provider": (dict(grype_mode="provider-os-missing"), "grype DB provider debian is stale"),
            "an unreadable capture time": (dict(grype_mode="provider-unreadable"), "is not an RFC 3339 time"),
            "a capture time in the future": (dict(grype_mode="provider-future"), "is in the future"),
            "a stale DB listing": (with_db(built_hours_ago=100), "more than 72"),
            "a tampered DB archive": (with_db(tamper=True), "does not match the listing"),
            "an imported DB that is not the listed one": (with_db("status-mismatch"), "not the DB this run verified"),
            "an invalid imported DB": (with_db("status-invalid"), "not valid"),
            "a retired DB schema": (with_db(listing_over={"status": "deprecated"}), "is not 'active'"),
            "a stale Trivy DB": (dict(db="stale"), "more than 72"),
            "a Trivy DB not downloaded by this run": (dict(db="predownloaded"), "before this run started"),
            "a grype finding": (dict(grype_mode="findings", env_extra=stale), "FAIL: fixable CRITICAL"),
            "a Trivy finding": (dict(mode="findings", env_extra=stale), "FAIL: fixable CRITICAL"),
            "grype not detecting the OS": (dict(distro="", env_extra=stale), "grype did not detect the OS"),
            "OS packages not scanned": (dict(os_pkgs="0", env_extra=stale), "OS packages not scanned"),
            "the gateway's erlang not catalogued": (dict(grype_mode="no-erlang", env_extra=stale,
                                                          image="yuzu-gateway=img:1"), "did not catalogue erlang"),
        }
        for label, (kw, why) in cases.items():
            with self.subTest(label):
                kw = dict(kw)
                image = kw.pop("image", "img:1")
                rep = self.tmp / ("rep-" + re.sub(r"[^a-z0-9]+", "-", label))
                kw.setdefault("grype_ignore", nvd)
                r = self.run_gate(image, extra=("--release", "--report-dir", str(rep)), **kw)
                self.assertEqual(r.returncode, 1, label + "\n" + r.stdout + r.stderr)
                reports = "".join(f.read_text(encoding="utf-8") for f in rep.glob("*.gate.txt"))
                self.assertIn(why, r.stdout + r.stderr + reports)

    def test_an_invalid_or_expired_waiver_refuses_the_whole_file_before_any_scan(self):
        cases = {
            "expired": (waiver(expired_at=days(-2)), "expired on"),
            "more than 14 days out": (waiver(expired_at=days(16)), "the maximum for a provider waiver is 14"),
            "unknown provider": (waiver(provider="rhel"), "provider must be one of"),
            "duplicate provider": (waiver() + waiver(), "duplicate provider waiver"),
            "no statement": (waiver(statement=None), "no `statement`"),
            "no approver": (waiver(approved_by=None), "approved_by must be"),
        }
        for label, (body, why) in cases.items():
            with self.subTest(label):
                self.log.unlink(missing_ok=True)
                self.glog.unlink(missing_ok=True)
                rep = self.tmp / ("rep-" + re.sub(r"[^a-z0-9]+", "-", label))
                # Fresh providers: the waiver is refused even when nothing needs it.
                r = self.run_gate("img:1", grype_ignore=self.waived(body), extra=("--report-dir", str(rep)))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("is not in the shape the gate accepts", r.stdout + r.stderr)
                self.assertIn(why, r.stdout + r.stderr)
                self.assertEqual(self.scans(), [])
                self.assertEqual(self.gscans(), [])
                self.assertIn("gate: FAIL: gate stopped before this image was judged",
                              (rep / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_a_pending_waiver_is_not_honoured_by_a_release(self):
        pend = self.waived(waiver(approved_on=None, approval_ref="pending"))
        rrep = self.tmp / "rep-release"
        r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=pend,
                          extra=("--release", "--report-dir", str(rrep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("NOT IN FORCE", r.stdout)
        self.assertIn("provider nvd", r.stderr)
        # The durable report records the waiver that was not honoured.
        self.assertIn("0 provider waiver(s) in force, 1 pending approval (1 not honoured)",
                      (rrep / "grype-img.gate.txt").read_text(encoding="utf-8"))
        rep = self.tmp / "rep"
        r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=pend, extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        g = (rep / "grype-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("approval_ref pending, approved_on -", g)
        self.assertIn("DEGRADED: provider waiver in force (nvd)", g)

    def test_no_flag_or_variable_enables_a_waiver(self):
        # On GitHub Actions the acceptance file can only be the repository's.
        other = self.waived(waiver())
        r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=other,
                          env_extra={"GITHUB_ACTIONS": "true"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("YUZU_GRYPEIGNORE is for local runs and tests", r.stdout + r.stderr)
        r = self.run_gate("img:1", grype_ignore=GRYPE_IGNORE, env_extra={"GITHUB_ACTIONS": "true"})
        self.assertNotIn("YUZU_GRYPEIGNORE is for local runs", r.stdout + r.stderr)
        # The same for Trivy's file.
        r = self.run_gate("img:1", ignore=self.write_ignore("vulnerabilities:\n"), grype_ignore=GRYPE_IGNORE,
                          env_extra={"GITHUB_ACTIONS": "true"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("YUZU_TRIVYIGNORE is for local runs and tests", r.stdout + r.stderr)
        # A path that cannot be resolved is refused, never let through.
        fake = self.tmp / "nort"
        fake.mkdir()
        (fake / "realpath").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        (fake / "realpath").chmod(0o755)
        r = self.run_gate("img:1", grype_ignore=other,
                          env_extra={"GITHUB_ACTIONS": "true",
                                     "PATH": f"{fake}{os.pathsep}{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("YUZU_GRYPEIGNORE is for local runs and tests", r.stdout + r.stderr)
        # No option of the gate's names a waiver.
        for opt in ("--provider-waiver", "--waive", "--waivers"):
            with self.subTest(opt=opt):
                r = self.run_gate("img:1", extra=(opt, "nvd"))
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        text = GATE.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^\s+--[a-z-]+\)", text, re.M),
                         ["        --report-dir)", "        --attempt)", "        --budget)", "        --release)"])

    def test_the_suite_does_not_depend_on_a_committed_waiver(self):
        # The gate cases read a copy of the repository file without its
        # provider_waivers section, so committing (or leaving) one changes no
        # outcome but the repository-file checks.
        text = "# c\nvulnerabilities:\n" + self.grype_entry() + "provider_waivers:\n" + waiver() \
            + waiver(provider="debian")
        stripped = strip_provider_waivers(text)
        self.assertNotIn("provider", stripped.replace("provider_waivers", "").replace("package", ""))
        self.assertIn("- id: CVE-2001-0001", stripped)
        self.assertIsNone(re.search(r"^provider_waivers:", stripped, re.M))
        # The section before `vulnerabilities:`, with a trailing comment.
        before = "provider_waivers:\n" + waiver() + "# a comment\nvulnerabilities:\n" + self.grype_entry()
        out = strip_provider_waivers(before)
        self.assertIsNone(re.search(r"^provider_waivers:|^  - provider:", out, re.M))
        # (a column-0 comment inside the section goes with it)
        self.assertTrue(out.startswith("vulnerabilities:\n  - id: CVE-2001-0001"), out)
        self.assertIsNone(re.search(r"^provider_waivers:", repo_grype_ignore(self.tmp).read_text(encoding="utf-8"),
                                    re.M))

    def test_an_nvd_waiver_that_lapses_during_the_run_fails_the_later_images(self):
        # Simulate the waiver lapsing after the run-wide nvd check (a run
        # crossing UTC midnight on its expiry day): the generated waivers file
        # is emptied once the run's nvd waiver has been read.
        lapse = ('[ "${#GRYPE_DB_WAIVERS[@]}" -eq 0 ] || echo "    DEGRADED: provider waiver in force for $(waived_desc): '
                 'every image judged while it is in force uses it"\n')
        def gate_copy(label, extra_edits=()):
            return GrypeMutants.mutant(self, label, [(lapse, lapse + 'echo "[]" > "$GRYPE_WAIVERS"\n'),
                                                     *extra_edits], [])
        rep = self.tmp / "rep-lapse"
        r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=self.waived(waiver()),
                          gate=gate_copy("lapse"), extra=("--report-dir", str(rep)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        g = (rep / "grype-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("gate: FAIL: provider waiver lapsed during the run", g)
        self.assertIn("provider waiver: lapsed during this run (nvd)", g)
        self.assertNotIn("DEGRADED", g)
        # Without the per-image re-check, the lapsed waiver would still admit it.
        m = gate_copy("lapse-no-recheck", [('    if [ "${#GRYPE_DB_WAIVERS[@]}" -gt 0 ] && ! "${CHECKS[@]}" '
                                            'grype-db-providers "$WORK/grype-db-providers.json" \\',
                                            '    if false && ! "${CHECKS[@]}" '
                                            'grype-db-providers "$WORK/grype-db-providers.json" \\')])
        r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=self.waived(waiver(), name="w2.yaml"),
                          gate=m)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # With an OS-provider waiver too, only the nvd waiver is named as
        # lapsed, the debian one the image used is still listed, and nothing
        # calls the failed image degraded.
        rep2 = self.tmp / "rep-lapse-os"
        r = self.run_gate("img:1", grype_ignore=self.waived(waiver(), waiver(provider="debian"), name="w3.yaml"),
                          gate=gate_copy("lapse-os"), extra=("--report-dir", str(rep2)),
                          env_extra={"STUB_GRYPE_PROVIDERS": "provider-stale,provider-os-stale"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        g = (rep2 / "grype-img.gate.txt").read_text(encoding="utf-8")
        self.assertIn("gate: FAIL: provider waiver lapsed during the run", g)
        self.assertIn("provider waiver: lapsed during this run (nvd), so it did not admit", g)
        self.assertNotIn("DEGRADED", g)
        self.assertNotIn("DEGRADED: provider waiver in force: grype DB provider debian", r.stdout)
        # A waivers file that cannot be read again is not called a lapse.
        rep3 = self.tmp / "rep-unreadable"
        broken = GrypeMutants.mutant(self, "unreadable", [(lapse, lapse + 'echo "{" > "$GRYPE_WAIVERS"\n')], [])
        r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=self.waived(waiver(), name="w4.yaml"),
                          gate=broken, extra=("--report-dir", str(rep3)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gate: FAIL: provider waivers unreadable",
                      (rep3 / "grype-img.gate.txt").read_text(encoding="utf-8"))

    def test_an_image_never_judged_is_not_reported_degraded(self):
        import subprocess as sp
        rep = self.tmp / "rep"
        env = dict(os.environ)
        for k in list(env):
            if k.startswith(("TRIVY_", "STUB_", "GITHUB_", "GRYPE_")):
                del env[k]
        env.update(TRIVY_BIN=str(self.stub), STUB_LOG=str(self.log), STUB_MODE="hang-stubborn",
                   YUZU_TRIVYIGNORE=str(IGNORE), YUZU_GATE_TEST_DB_DIGEST=DB_DIGEST, RUNNER_TEMP=str(self.tmp),
                   PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
                   **self.grype_env("provider-stale", grype_ignore=self.waived(waiver())))
        p = sp.Popen(["bash", str(GATE), "--budget", "6", "--report-dir", str(rep), "a=img:1"], env=env,
                     stdout=sp.PIPE, stderr=sp.PIPE, text=True)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 1, out + err)
        g = (rep / "grype-a.gate.txt").read_text(encoding="utf-8")
        self.assertIn("gate: FAIL: gate stopped before this image was judged", g)
        self.assertIn("provider waiver: in force for this run (nvd), but the image was not judged", g)
        self.assertNotIn("DEGRADED", g)

    def test_the_waivable_providers_are_the_gates_providers(self):
        ck = CHECKS.read_text(encoding="utf-8")
        waivable = re.search(r'^WAIVABLE_PROVIDERS = \(([^)]*)\)$', ck, re.M).group(1)
        canary = re.search(r'^CANARY_FAMILIES = \(([^)]*)\)$', ck, re.M).group(1)
        self.assertEqual(sorted(re.findall(r'"([a-z]+)"', waivable)),
                         sorted(["nvd"] + re.findall(r'"([a-z]+)"', canary)))
        req = re.search(r"^GRYPE_REQUIRED_PROVIDERS=\(([^)]*)\)$", GATE.read_text(encoding="utf-8"), re.M).group(1)
        self.assertEqual(req.split(), ["nvd"])
        self.assertIn("MAX_WAIVER_DAYS = 14\n", ck)


@unittest.skipUnless(have_bash(), "the gate is a bash script")
class ProviderWaiverMutants(unittest.TestCase):
    """Each provider-waiver rule is load-bearing: the gate (or its checker)
    with that one rule mutated away gives the wrong answer on the scenario the
    rule exists for, while the real one gives the right answer."""

    setUp = GateBehaviour.setUp
    grype_env = GateBehaviour.grype_env
    run_gate = GateBehaviour.run_gate
    grype_entry = GateBehaviour.grype_entry
    write_grype_ignore = GateBehaviour.write_grype_ignore
    mutant = GrypeMutants.mutant
    assert_killed = GrypeMutants.assert_killed
    waived = ProviderWaiver.waived

    def checks_mutant(self, label, edits):
        return self.mutant(label, (), edits).parent / CHECKS.name

    def test_mutants_of_the_waiver_rules_are_killed(self):
        def gate_with(gmode, *ws, release=False):
            def run(gate):
                ign = self.waived(*ws, name=f"w{len(list(self.tmp.glob('w*.yaml')))}.yaml")
                return self.run_gate("img:1", grype_mode=gmode, grype_ignore=ign, gate=gate,
                                     extra=("--release",) if release else ())
            return run

        cases = [
            ("a waiver admits a missing provider", gate_with("provider-missing", waiver()), [],
             [("        if r is None:\n", "        if r is None and name in waivers:\n            continue\n"
               "        if r is None:\n")]),
            ("a waiver admits an unreadable capture time", gate_with("provider-unreadable", waiver()), [],
             [('        elif kind == "stale" and name in waivers:', '        elif name in waivers:')]),
            ("a waiver admits a capture time in the future", gate_with("provider-future", waiver()), [],
             [('        elif kind == "stale" and name in waivers:',
               '        elif kind in ("stale", "future") and name in waivers:')]),
            ("one provider's waiver admits another", gate_with("provider-stale", waiver(provider="debian")), [],
             [('        elif kind == "stale" and name in waivers:', '        elif kind == "stale" and waivers:'),
              ("            w = waivers[name]\n", "            w = next(iter(waivers.values()))\n")]),
            ("an expired waiver honoured", gate_with("provider-stale", waiver(expired_at=days(-1))), [],
             [("        if left < 0:\n            errors.append(f\"{tag}: expired on",
               "        if False:\n            errors.append(f\"{tag}: expired on"),
              ("        if exp >= today():\n            out[w[\"provider\"]] = w",
               "        if True:\n            out[w[\"provider\"]] = w")]),
            ("a waiver more than 14 days out honoured", gate_with("provider-stale", waiver(expired_at=days(15))), [],
             [("        if left > MAX_WAIVER_DAYS:", "        if False:")]),
            ("a pending waiver honoured in a release",
             gate_with("provider-stale", waiver(approved_on=None, approval_ref="pending"), release=True), [],
             [("        if pending and require_approved:\n            excluded.append(w)\n",
               "        if False:\n            excluded.append(w)\n")]),
        ]
        for label, scenario, gate_edits, checks_edits in cases:
            with self.subTest(mutant=label):
                self.assert_killed(label, scenario, gate_edits, checks_edits)
        # The real gate must ADMIT the scenario the waiver exists for: the
        # reverse direction (a waiver that stopped working) also fails a test.
        real = gate_with("provider-stale", waiver())(GATE)
        self.assertEqual(real.returncode, 0, real.stdout + real.stderr)
        dead = self.mutant("waiver never applied", (), [
            ('        elif kind == "stale" and name in waivers:', '        elif False:')])
        self.assertEqual(gate_with("provider-stale", waiver())(dead).returncode, 1)
        real = gate_with("provider-os-stale", waiver(provider="debian"))(GATE)
        self.assertEqual(real.returncode, 0, real.stdout + real.stderr)
        dead = self.mutant("OS provider waiver not read per image", [
            ('                   --waivers "$GRYPE_WAIVERS" "$want_family")"; then', '                   "$want_family")"; then')])
        self.assertEqual(gate_with("provider-os-stale", waiver(provider="debian"))(dead).returncode, 1)

    def test_no_other_check_yields_to_a_waiver(self):
        # A regression that let a waiver in force switch off any OTHER check
        # must fail ProviderWaiver.test_a_waiver_waives_nothing_but_a_stale_provider.
        # Each mutant below skips one check whenever the run holds an nvd
        # waiver; the scenario is that test's case for the check.
        W = 'grep -q nvd "$GRYPE_WAIVERS"'
        ign = self.waived(waiver(), waiver(provider="debian"), name="nothing.yaml")
        stale = {"STUB_GRYPE_PROVIDERS": "provider-stale,provider-os-stale"}

        def db(gmode="clean", **fixture):
            n = len(list(self.tmp.glob("gdb-*")))
            gdb, built = grype_db_fixture(self.tmp / f"gdb-{n}", **fixture)
            return dict(env_extra=self.grype_env(gmode, grype_ignore=ign, gdb=gdb, built=built))

        cases = [
            ("grype finding admitted", dict(grype_mode="findings", env_extra=stale),
             ('    fi\n    case "$rc" in\n', f'    fi\n    ! {W} || rc=0\n    case "$rc" in\n'),
             ('           elif [ "$fcrit" != 0 ]; then', f'           elif [ "$fcrit" != 0 ] && ! {W}; then')),
            ("Trivy finding admitted", dict(mode="findings", env_extra=stale),
             ('        --exit-code 3 --format table "$image" || rc=$?\n',
              f'        --exit-code 3 --format table "$image" || rc=$?\n    ! {W} || rc=0\n')),
            ("component check skipped", dict(grype_mode="no-erlang", env_extra=stale, image="yuzu-gateway=img:1"),
             ('           elif [ "$comps_ok" != 1 ]; then', f'           elif [ "$comps_ok" != 1 ] && ! {W}; then')),
            ("OS cross-check skipped", dict(distro="", env_extra=stale),
             ('           elif [ -n "$want_family" ] && [ "$distro" != "$want_family" ]; then',
              f'           elif [ -n "$want_family" ] && [ "$distro" != "$want_family" ] && ! {W}; then')),
            ("coverage failure ignored", dict(os_pkgs="0", env_extra=stale),
             ('    [ "$cov_ok" = 1 ] || failed=1\n', f'    [ "$cov_ok" = 1 ] || {W} || failed=1\n')),
            ("DB checksum skipped", db(tamper=True),
             ('    || die "the grype DB archive $gdb_path does not match',
              f'    || {W} || die "the grype DB archive $gdb_path does not match')),
            ("imported DB status skipped", db("status-mismatch"),
             ("    die \"grype's status of the imported DB is not the DB",
              f"    {W} || die \"grype's status of the imported DB is not the DB")),
            ("Trivy DB age skipped", dict(db="predownloaded"),
             ('    die "the Trivy vulnerability DB is stale, unreadable',
              f'    {W} || die "the Trivy vulnerability DB is stale, unreadable')),
        ]
        for label, kw, *edits in cases:
            with self.subTest(mutant=label):
                kw = dict(kw)
                image = kw.pop("image", "img:1")
                kw.setdefault("grype_ignore", ign)
                scenario = lambda gate, kw=kw, image=image: self.run_gate(image, gate=gate, **kw)  # noqa: E731
                self.assert_killed(label, scenario, edits, [])

    def test_mutants_of_the_file_rules_are_killed(self):
        def checks(path, args):
            return subprocess.run([sys.executable, "-I", str(path), *map(str, args)],
                                  capture_output=True, text=True, timeout=30)
        cases = [
            ("unknown provider accepted", waiver(provider="rhel"),
             [("        if prov not in WAIVABLE_PROVIDERS:\n", "        if False:\n")]),
            ("duplicate provider accepted", waiver() + waiver(),
             [("        if prov in seen:\n", "        if False:\n")]),
            ("waiver without a statement accepted", waiver(statement=None),
             [('        if "statement" not in w:\n', "        if False:\n")]),
            ("waiver without an approval accepted", waiver(approved_by=None, approved_on=None, approval_ref=None),
             [("        pending = check_approval(tag, w.get(\"approved_by\"), w.get(\"approved_on\"), "
               "w.get(\"approval_ref\"), errors)", "        pending = False")]),
        ]
        for label, body, edits in cases:
            with self.subTest(mutant=label):
                ign = self.waived(body, name="f-" + re.sub(r"[^a-z]+", "-", label) + ".yaml")
                self.assertEqual(checks(CHECKS, ["grype-ignore-file", ign]).returncode, 1, label)
                self.assertEqual(checks(self.checks_mutant(label, edits), ["grype-ignore-file", ign]).returncode, 0,
                                 f"mutant '{label}' survived")

    def test_mutants_of_the_reports_are_killed(self):
        def degraded_reports(gate):
            rep = self.tmp / ("rep-" + str(len(list(self.tmp.glob("rep-*")))))
            summ = rep.with_suffix(".md")
            r = self.run_gate("img:1", grype_mode="provider-stale", grype_ignore=self.waived(waiver()), gate=gate,
                              extra=("--report-dir", str(rep)), env_extra={"GITHUB_STEP_SUMMARY": str(summ)})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            return (rep / "grype-img.gate.txt").read_text(encoding="utf-8"), summ.read_text(encoding="utf-8")

        g, s = degraded_reports(GATE)
        self.assertIn("DEGRADED: provider waiver in force (nvd)", g)
        self.assertIn("DEGRADED: provider waiver in force", s)
        g, _ = degraded_reports(self.mutant("waiver not in the report", [
            ('        echo "grype db: $GRYPE_DB_REF"\n        waiver_lines\n', '        echo "grype db: $GRYPE_DB_REF"\n')]))
        self.assertNotIn("DEGRADED", g)
        _, s = degraded_reports(self.mutant("waiver not in the summary", [
            ('    if [ "${#GRYPE_DB_WAIVERS[@]}" -gt 0 ]; then\n        summary "**DEGRADED',
             '    if false; then\n        summary "**DEGRADED'),
            ('        summary "| $n (grype) | - | distro ${distro:-none} | $gres (DEGRADED: provider waiver in force: '
             '$wdesc) |"', '        summary "| $n (grype) | - | distro ${distro:-none} | $gres |"'),
            ('    summary "**DEGRADED: provider waiver in force** for grype DB provider(s) $wsum', '    summary "x $wsum')]))
        self.assertNotIn("DEGRADED", s)
        # The Actions-only refusal of another acceptance file.
        def actions(gate):
            return self.run_gate("img:1", grype_ignore=self.waived(waiver(), name="act.yaml"), gate=gate,
                                 env_extra={"GITHUB_ACTIONS": "true"})
        self.assertIn("YUZU_GRYPEIGNORE is for local runs", actions(GATE).stderr + actions(GATE).stdout)
        m = self.mutant("YUZU_GRYPEIGNORE honoured on Actions", [
            ('    [ -n "$2" ] || return 0\n', '    return 0\n'),
            ('    GRYPE_IGNORE_FILE="$ROOT/.grypeignore.yaml"\n', '')])
        r = actions(m)
        self.assertNotIn("YUZU_GRYPEIGNORE is for local runs", r.stdout + r.stderr)


@unittest.skipUnless(have_bash(), "image-publish.sh is a bash script")
class PublishNeedsBothScanners(unittest.TestCase):
    """image-publish.sh opens a journal only when Trivy's AND grype's gate.txt
    for the attempt both exist and record exactly `gate: pass` (WP15)."""

    def open_with(self, scanners, verdict="gate: pass"):
        d = Path(tempfile.mkdtemp(prefix="yuzu_test_publish_open_"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for sc in scanners:
            (d / f"{sc}-yuzu-gateway.attempt-1.gate.txt").write_text(f"image: x\n{verdict}\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        r = subprocess.run(["bash", str(PUBLISH), "open", str(d), "yuzu-gateway", "1"],
                           env=env, capture_output=True, text=True, timeout=60)
        return r, (d / "publish-yuzu-gateway.attempt-1.txt").exists()

    def test_both_passing_opens_the_journal(self):
        r, opened = self.open_with(("trivy", "grype"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(opened)

    def test_a_missing_scanner_report_refuses(self):
        for present, missing in ((("trivy",), "grype"), (("grype",), "trivy")):
            with self.subTest(missing=missing):
                r, opened = self.open_with(present)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn(f"no {missing}-yuzu-gateway.attempt-1.gate.txt", r.stdout + r.stderr)
                self.assertFalse(opened)

    def test_a_grype_refusal_refuses(self):
        d_r, opened = self.open_with(("trivy",))
        self.assertFalse(opened)
        r, opened = self.open_with(("trivy", "grype"), verdict="gate: FAIL: fixable CRITICAL")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(opened)


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
        r = self.run_checks("pending", ign, ok_nc, repo_grype_ignore(self.tmp))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pend = self.tmp / "pend.yaml"
        pend.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0002", approved_on=None, approval_ref="pending"),
                        encoding="utf-8")
        r = self.run_checks("pending", pend, ok_nc, repo_grype_ignore(self.tmp))
        self.assertEqual(r.returncode, 1)
        self.assertIn("CVE-2000-0002: approval_ref is pending", r.stderr)
        p_nc = self.tmp / "pnc.txt"
        p_nc.write_text(nc_line(on="-", ref="pending"), encoding="utf-8")
        r = self.run_checks("pending", ign, p_nc, repo_grype_ignore(self.tmp))
        self.assertEqual(r.returncode, 1)
        self.assertIn("yuzu-server-chisel: approval_ref is pending", r.stderr)
        # An expired entry is not pending, but it is not in force either: a
        # release would fail on what it accepted (G8P4-release-deploy-1).
        old = self.tmp / "old.yaml"
        old.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0003", approved_on=None, approval_ref="pending",
                                                     expired_at=days(-1)), encoding="utf-8")
        r = self.run_checks("pending", old, ok_nc, repo_grype_ignore(self.tmp))
        self.assertEqual(r.returncode, 1)
        self.assertIn("CVE-2000-0003: expired on", r.stderr)
        self.assertNotIn("approval_ref is pending", r.stderr)
        # Expiring today or tomorrow can lapse mid-release: refused too.
        for n in (0, 1):
            soon = self.tmp / f"soon{n}.yaml"
            soon.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0004", expired_at=days(n)), encoding="utf-8")
            r = self.run_checks("pending", soon, ok_nc, repo_grype_ignore(self.tmp))
            self.assertEqual(r.returncode, 1, n)
            self.assertIn("CVE-2000-0004: expires on", r.stderr)
        later = self.tmp / "later.yaml"
        later.write_text("vulnerabilities:\n" + entry(id="CVE-2000-0005", expired_at=days(2)), encoding="utf-8")
        r = self.run_checks("pending", later, ok_nc, repo_grype_ignore(self.tmp))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning:", r.stdout)
        # The same for a not-covered listing: expired, expiring, and a warning.
        for exp, rc, text in ((days(-1), 1, "yuzu-server-chisel: expired on"),
                              (days(1), 1, "yuzu-server-chisel: expires on"),
                              (days(10), 0, "warning:")):
            with self.subTest(listing_expires=exp):
                r = self.run_checks("pending", ign, self.nc(nc_line(exp=exp)), repo_grype_ignore(self.tmp))
                self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
                self.assertIn(text, r.stdout + r.stderr)
        bad = self.tmp / "bad.yaml"
        bad.write_text("vulnerabilities:\n" + entry(paths=['"**"']), encoding="utf-8")
        self.assertEqual(self.run_checks("pending", bad, ok_nc, repo_grype_ignore(self.tmp)).returncode, 1)
        bad_nc = self.tmp / "bnc.txt"
        bad_nc.write_text("junk\n", encoding="utf-8")
        self.assertEqual(self.run_checks("pending", ign, bad_nc, repo_grype_ignore(self.tmp)).returncode, 1)

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


    # ── grype (WP15): the acceptance file, the DB listing and status, the report ──
    def gentry(self, **over):
        f = {"id": "CVE-2001-0001", "package_name": "erlang", "package_version": "28.5.0.2",
             "package_type": "binary", "statement": "not reachable", "expired_at": days(30),
             "approved_by": "some-login", "approved_on": days(-1), "approval_ref": '"#1234"'}
        f.update(over)
        out = [f"  - id: {f['id']}"]
        for k, v in f.items():
            if k != "id" and v is not None:
                out.append(f"    {k}: {v}")
        return "\n".join(out) + "\n"

    def gfile(self, *entries, name="g.yaml"):
        p = self.tmp / name
        p.write_text("vulnerabilities:\n" + "".join(entries), encoding="utf-8")
        return p

    def test_repository_grype_ignore_file_is_valid(self):
        r = self.run_checks("grype-ignore-file", GRYPE_IGNORE, "--require-approved")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_grype_ignore_file_emits_only_the_entries_in_force_as_ignore_rules(self):
        src = self.gfile(self.gentry(), self.gentry(id="CVE-2001-0002", approved_on=None, approval_ref="pending"),
                         self.gentry(id="CVE-2001-0003", expired_at=days(-1)),
                         self.gentry(id="CVE-2001-0004", package_type=None))
        out = self.tmp / "grype.yaml"
        r = self.run_checks("grype-ignore-file", src, "--emit", out, "--require-approved")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("in_force=2", r.stdout)
        self.assertIn("pending_not_honoured=1", r.stdout)
        text = out.read_text(encoding="utf-8")
        self.assertEqual(text.splitlines()[1:], [
            "ignore:",
            '  - vulnerability: "CVE-2001-0001"', "    package:", '      name: "erlang"',
            '      version: "28.5.0.2"', '      type: "binary"',
            '  - vulnerability: "CVE-2001-0004"', "    package:", '      name: "erlang"',
            '      version: "28.5.0.2"'])
        # Nothing but the rules: no statement, approval or any key grype could read as config.
        for word in ("statement", "approved", "expired", "exclude", "only-fixed"):
            self.assertNotIn(word, text)
        empty = self.gfile(name="empty.yaml")
        r = self.run_checks("grype-ignore-file", empty, "--emit", out)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(out.read_text(encoding="utf-8").splitlines()[1:], ["ignore: []"])

    def test_grype_entries_need_a_package_name_and_version_without_globs(self):
        bad = {
            "no name": {"package_name": None},
            "no version": {"package_version": None},
            "glob name": {"package_name": "erl*"},
            "regex plus (grype reads names as regex)": {"package_name": '"libstdc++"'},
            "regex bracket": {"package_name": '"erl[a]ng"'},
            "regex alternation": {"package_name": '"erlang|zzz"'},
            "regex anchors": {"package_name": '"^erlang$"'},
            "glob version": {"package_version": "28.*"},
            "bracket version": {"package_version": '"28.5.[0-9]"'},
            "space name": {"package_name": '"erl ang"'},
            "upper type": {"package_type": "Binary"},
            "no statement": {"statement": None},
            "no expiry": {"expired_at": None},
            "expiry too far": {"expired_at": days(93)},
            "no approver": {"approved_by": None},
            "bad ref": {"approval_ref": '"PR 12"'},
            "pending with a date": {"approval_ref": "pending"},
            "bad id": {"id": "cve-1"},
        }
        for label, over in bad.items():
            with self.subTest(label):
                r = self.run_checks("grype-ignore-file", self.gfile(self.gentry(**over)))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_grype_file_refuses_trivy_keys_and_unknown_keys(self):
        for line in ('    paths:\n      - "usr/bin/x"\n', '    purls:\n      - "pkg:apk/alpine/x@1"\n',
                     "    exclude: yes\n", "    package:\n"):
            with self.subTest(line=line.strip()):
                r = self.run_checks("grype-ignore-file", self.gfile(self.gentry() + line))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        p = self.tmp / "top.yaml"
        p.write_text("ignore:\n  - vulnerability: CVE-2001-0001\n", encoding="utf-8")
        self.assertEqual(self.run_checks("grype-ignore-file", p).returncode, 1)

    def test_grype_duplicate_entry_is_refused(self):
        r = self.run_checks("grype-ignore-file", self.gfile(self.gentry(), self.gentry()))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("duplicate entry", r.stderr)

    def test_trivy_file_still_refuses_grype_keys(self):
        p = self.tmp / "t.yaml"
        p.write_text("vulnerabilities:\n" + entry() + "    package_name: x\n", encoding="utf-8")
        self.assertEqual(self.run_checks("ignore-file", p).returncode, 1)

    def test_pending_needs_the_grype_file_and_checks_it(self):
        ign = self.tmp / "ign.yaml"
        ign.write_text("vulnerabilities:\n" + entry(), encoding="utf-8")
        ok_nc = self.nc(nc_line())
        self.assertEqual(self.run_checks("pending", ign, ok_nc).returncode, 2, "the grype file is required")
        r = self.run_checks("pending", ign, ok_nc, self.gfile(self.gentry()))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.run_checks("pending", ign, ok_nc,
                            self.gfile(self.gentry(approved_on=None, approval_ref="pending"), name="p.yaml"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("CVE-2001-0001: approval_ref is pending", r.stderr)
        r = self.run_checks("pending", ign, ok_nc, self.gfile(self.gentry(expired_at=days(1)), name="s.yaml"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("CVE-2001-0001: expires on", r.stderr)
        r = self.run_checks("pending", ign, ok_nc, self.gfile(self.gentry(package_version=None), name="b.yaml"))
        self.assertEqual(r.returncode, 1)

    def listing(self, raw=None, **over):
        built = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        d = {"status": "active", "schemaVersion": "v6.1.10", "built": built, "path": GRYPE_DB_ARCHIVE,
             "checksum": "sha256:" + "a" * 64}
        d.update(over)
        p = self.tmp / "latest.json"
        p.write_text(raw if raw is not None else json.dumps(d), encoding="utf-8")
        return p, built

    def test_grype_db_listing(self):
        p, built = self.listing()
        r = self.run_checks("grype-db-listing", p)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"path={GRYPE_DB_ARCHIVE}", r.stdout)
        self.assertIn(f"built={built}", r.stdout)
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=73)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        bad = {"stale": {"built": old}, "future": {"built": "2999-01-01T00:00:00Z"}, "no time": {"built": "x"},
               "deprecated": {"status": "deprecated"}, "v5": {"schemaVersion": "v5.0.0"},
               "slash": {"path": "a/" + GRYPE_DB_ARCHIVE}, "dotdot": {"path": "../" + GRYPE_DB_ARCHIVE},
               "url": {"path": "https://x/" + GRYPE_DB_ARCHIVE}, "md5": {"checksum": "md5:" + "a" * 32},
               "short": {"checksum": "sha256:abc"}}
        for label, over in bad.items():
            with self.subTest(label):
                p, _ = self.listing(**over)
                self.assertEqual(self.run_checks("grype-db-listing", p).returncode, 1)
        for raw in ("{", "[]", "null"):
            with self.subTest(raw=raw):
                p, _ = self.listing(raw=raw)
                self.assertEqual(self.run_checks("grype-db-listing", p).returncode, 1)
        self.assertEqual(self.run_checks("grype-db-listing", self.tmp / "absent.json").returncode, 1)

    def test_grype_db_status(self):
        built = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

        def status(**over):
            d = {"schemaVersion": "v6.1.10", "built": built, "valid": True, "path": "/x/6/vulnerability.db"}
            d.update(over)
            p = self.tmp / "status.json"
            p.write_text(json.dumps(d), encoding="utf-8")
            return self.run_checks("grype-db-status", p, "--built", built, "--schema", "v6.1.10")

        self.assertEqual(status().returncode, 0)
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=80)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        for label, over in {"invalid": {"valid": False}, "valid string": {"valid": "true"},
                            "other build": {"built": old}, "other schema": {"schemaVersion": "v6.1.9"}}.items():
            with self.subTest(label):
                self.assertEqual(status(**over).returncode, 1)
        p = self.tmp / "status.json"
        p.write_text(json.dumps({"schemaVersion": "v6.1.10", "built": old, "valid": True}), encoding="utf-8")
        r = self.run_checks("grype-db-status", p, "--built", old, "--schema", "v6.1.10")
        self.assertEqual(r.returncode, 1, "a stale DB is refused even when it is the listed one")
        self.assertEqual(self.run_checks("grype-db-status", p, "--built", old).returncode, 2)

    def test_grype_report(self):
        def report(d):
            p = self.tmp / "g.json"
            p.write_text(d if isinstance(d, str) else json.dumps(d), encoding="utf-8")
            return self.run_checks("grype-report", p)

        crit = {"vulnerability": {"severity": "Critical", "fix": {"state": "fixed"}}}
        unfixed = {"vulnerability": {"severity": "Critical", "fix": {"state": "not-fixed"}}}
        good = {"descriptor": {"name": "grype", "version": "0.121.3"}, "matches": [crit, unfixed],
                "ignoredMatches": [crit], "distro": {"name": "alpine", "version": "3.23.8"},
                "source": {"target": {"imageID": "sha256:" + "9" * 64}}}
        r = report(good)
        self.assertEqual(r.returncode, 0, r.stderr)
        for line in ("distro_family=alpine", "distro_version=3.23.8", "matches=2", "ignored=1",
                     "fixable_critical=1", "fixable_critical_accepted=1", "image_id=sha256:" + "9" * 64,
                     "grype_version=0.121.3"):
            self.assertIn(line, r.stdout.splitlines())
        # The record scan applies acceptances: a fixable CRITICAL that is only in
        # ignoredMatches is accepted, never counted as not accepted (C-1).
        r = report(dict(good, matches=[unfixed], ignoredMatches=[crit, crit]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("fixable_critical=0", r.stdout.splitlines())
        self.assertIn("fixable_critical_accepted=2", r.stdout.splitlines())
        for label, d in {"trivy report": {"SchemaVersion": 2, "ArtifactName": "x", "Results": []},
                         "no matches": {"descriptor": {"name": "grype"}},
                         "matches not a list": dict(good, matches={}),
                         "bad match": dict(good, matches=["x"]), "array": [], "not json": "{"}.items():
            with self.subTest(label):
                self.assertEqual(report(d).returncode, 1)


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


@unittest.skipUnless(have_bash(), "uses the gate's checker the same way the gate does")
class ProviderWaiverChecks(unittest.TestCase):
    """The `provider_waivers:` section of .grypeignore.yaml, through the one
    parser, and grype-db-providers --waivers, called directly."""

    setUp = Checks.setUp
    run_checks = Checks.run_checks
    gentry = Checks.gentry
    nc = Checks.nc

    def wfile(self, *waivers, entries="", name="w.yaml", raw=None):
        p = self.tmp / name
        p.write_text(raw if raw is not None else
                     "vulnerabilities:\n" + entries + "provider_waivers:\n" + "".join(waivers), encoding="utf-8")
        return p

    def providers(self, **captured):
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = []
        for name in ("nvd", "alpine", "debian", "ubuntu"):
            v = captured.get(name, 2)
            if v is None:
                continue
            rows.append({"name": name, "dateCaptured": v if isinstance(v, str) else
                         (now - datetime.timedelta(hours=v)).strftime("%Y-%m-%dT%H:%M:%SZ")})
        p = self.tmp / f"providers-{len(list(self.tmp.glob('providers-*')))}.json"
        p.write_text(json.dumps(rows), encoding="utf-8")
        return p

    def emitted(self, *waivers, require_approved=False):
        out = self.tmp / "waivers.json"
        args = ["grype-ignore-file", self.wfile(*waivers), "--emit", self.tmp / "g.yaml", "--emit-waivers", out]
        r = self.run_checks(*args, *(["--require-approved"] if require_approved else []))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return out, r

    def test_well_formed_waivers_are_accepted_beside_entries_in_either_order(self):
        # Each case writes its own file inside its subtest (one shared name in
        # an eagerly built tuple would test only the last file written).
        cases = {
            "after": lambda: self.wfile(waiver(), waiver(provider="debian"), waiver(provider="alpine"),
                                        entries=self.gentry(), name="after.yaml"),
            "before": lambda: self.wfile(raw="provider_waivers:\n" + waiver() + "vulnerabilities:\n"
                                         + self.gentry(), name="before.yaml"),
            "empty": lambda: self.wfile(name="empty.yaml"),
        }
        for label, make in cases.items():
            with self.subTest(label):
                p = make()
                r = self.run_checks("grype-ignore-file", p, "--require-approved")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                want = {"after": 3, "before": 1, "empty": 0}[label]
                self.assertIn(f"waivers_in_force={want}", r.stdout)
                self.assertIn("in_force=" + ("0" if label == "empty" else "1"), r.stdout)

    def test_the_expiry_bounds_are_inclusive_at_14_days_and_today(self):
        # The exact boundaries: 14 days out and expiring today are in force;
        # 15 days out and yesterday refuse the file. (A run straddling UTC
        # midnight between building a case and checking it shifts every date
        # by a day; the window is milliseconds.)
        for label, exp, rc, why in (("14 days out", days(14), 0, None), ("expires today", days(0), 0, None),
                                    ("15 days out", days(15), 1, "the maximum for a provider waiver is 14"),
                                    ("expired yesterday", days(-1), 1, "expired on")):
            with self.subTest(label):
                p = self.wfile(waiver(expired_at=exp), name=label.replace(" ", "-") + ".yaml")
                r = self.run_checks("grype-ignore-file", p, "--require-approved")
                self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
                if why:
                    self.assertIn(why, r.stderr)
                else:
                    self.assertIn("waivers_in_force=1", r.stdout)

    def test_a_bad_waiver_refuses_the_whole_file(self):
        # Each case is one field changed from a valid waiver, and must be
        # refused for THAT reason.
        bad = {
            "expired": (waiver(expired_at=days(-2)), "expired on"),
            "16 days out": (waiver(expired_at=days(16)), "the maximum for a provider waiver is 14"),
            "unknown provider": (waiver(provider="rhel"), "provider must be one of"),
            "provider spelled in capitals": (waiver(provider="NVD"), "provider must be one of"),
            "the github provider": (waiver(provider="github"), "provider must be one of"),
            "duplicate provider": (waiver() + waiver(expired_at=days(3)), "duplicate provider waiver"),
            "no statement": (waiver(statement=None), "no `statement`"),
            "no expiry": (waiver(expired_at=None), "expired_at must be a YYYY-MM-DD date"),
            "quoted expiry": (waiver(expired_at=f'"{days(3)}"'), "is an unquoted YYYY-MM-DD date"),
            "not a date": (waiver(expired_at="soon"), "expired_at must be a YYYY-MM-DD date"),
            "no approver": (waiver(approved_by=None), "approved_by must be"),
            "approver not a login": (waiver(approved_by="-x"), "approved_by must be"),
            "bad approval ref": (waiver(approval_ref='"PR 12"'), "must be `#N`"),
            "no approval ref": (waiver(approval_ref=None), "no approval_ref"),
            "pending with a date": (waiver(approval_ref="pending"), "approved_on is set but approval_ref is pending"),
            "approved in the future": (waiver(approved_on=days(2)), "is in the future"),
            "an entry key": (waiver() + "    package_name: erlang\n", "key `package_name` is not allowed"),
            "an unknown key": (waiver() + "    hours: 200\n", "key `hours` is not allowed"),
            "a comment after a value": (waiver(provider="nvd # stalled"), "a comment after a value"),
            "flow style": (None, "allowed at the top level"),
        }
        for label, (body, why) in bad.items():
            with self.subTest(label):
                name = re.sub(r"[^a-z0-9]+", "-", label) + ".yaml"
                p = (self.wfile(raw="vulnerabilities:\nprovider_waivers: []\n", name=name) if body is None
                     else self.wfile(body, name=name))
                r = self.run_checks("grype-ignore-file", p)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, r.stderr)
        # Shape: a waiver section twice, an entry under the wrong section, and
        # the section in Trivy's file are refused by the same parser.
        for label, raw, sub, why in (
                ("twice", "vulnerabilities:\nprovider_waivers:\n" + waiver() + "provider_waivers:\n"
                 + waiver(provider="debian"), "grype-ignore-file", "second `provider_waivers:` key"),
                ("waiver under vulnerabilities", "vulnerabilities:\n" + waiver(), "grype-ignore-file",
                 "every `vulnerabilities` entry starts with `- id:`"),
                ("entry under provider_waivers", "vulnerabilities:\nprovider_waivers:\n" + self.gentry(),
                 "grype-ignore-file", "every `provider_waivers` entry starts with `- provider:`"),
                ("no vulnerabilities key", "provider_waivers:\n" + waiver(), "grype-ignore-file",
                 "no `vulnerabilities:` key"),
                ("in .trivyignore.yaml", "vulnerabilities:\n" + entry() + "provider_waivers:\n" + waiver(),
                 "ignore-file", "only `vulnerabilities:` allowed at the top level")):
            with self.subTest(label):
                r = self.run_checks(sub, self.wfile(raw=raw, name=re.sub(r"[^a-z]+", "-", label) + ".yaml"))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, r.stderr)

    def test_the_emitted_waivers_are_those_in_force_without_free_text(self):
        out, r = self.emitted(waiver(), waiver(provider="debian", approved_on=None, approval_ref="pending"),
                              require_approved=True)
        self.assertIn("waivers_in_force=1", r.stdout)
        self.assertIn("NOT IN FORCE", r.stdout)
        rows = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual([w["provider"] for w in rows], ["nvd"])
        self.assertEqual(set(rows[0]), {"provider", "expired_at", "approved_by", "approval_ref", "approved_on",
                                        "where"})
        self.assertNotIn("outage", out.read_text(encoding="utf-8"))
        out, r = self.emitted(waiver(), waiver(provider="debian", approved_on=None, approval_ref="pending"))
        self.assertIn("waivers_in_force=2", r.stdout)
        # The generated grype config never carries a waiver.
        self.assertEqual((self.tmp / "g.yaml").read_text(encoding="utf-8").splitlines()[1:], ["ignore: []"])

    def test_providers_admit_only_a_waived_provider_that_is_only_stale(self):
        out, _ = self.emitted(waiver())
        r = self.run_checks("grype-db-providers", self.providers(nvd=100), "--waivers", out, "nvd")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"(?m)^waiver: provider nvd captured \S+, 100 hours old \(over the 72-hour "
                                   r"limit\), admitted by the provider waiver at w\.yaml:3: expires ")
        for label, prov, args, why in (
                ("no waivers file", self.providers(nvd=100), [], "only a reviewed provider waiver for nvd"),
                ("missing provider", self.providers(nvd=None), ["--waivers", out], "is not in the DB"),
                ("unreadable capture", self.providers(nvd="yesterday"), ["--waivers", out], "RFC 3339"),
                ("future capture", self.providers(nvd="2999-01-01T00:00:00Z"), ["--waivers", out], "future"),
                ("another provider stale", self.providers(debian=100), ["--waivers", out], "provider debian"),
                ("unreadable waivers", self.providers(nvd=100), ["--waivers", self.tmp / "absent.json"],
                 "missing or unreadable")):
            with self.subTest(label):
                req = ["debian"] if label == "another provider stale" else ["nvd"]
                r = self.run_checks("grype-db-providers", prov, *args, *req)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, r.stderr)
                self.assertNotIn("waiver:", r.stdout)
        # A malformed providers listing fails even with a waiver in force.
        for raw in ("{", "{}", "[1]", "null"):
            with self.subTest(providers=raw):
                bad = self.tmp / "bad-providers.json"
                bad.write_text(raw, encoding="utf-8")
                r = self.run_checks("grype-db-providers", bad, "--waivers", out, "nvd")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("missing or unreadable", r.stderr)
        # A current provider with a waiver in force is reported plainly.
        r = self.run_checks("grype-db-providers", self.providers(), "--waivers", out, "nvd")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("waiver:", r.stdout)

    def test_a_waivers_file_is_read_strictly_and_a_lapsed_row_admits_nothing(self):
        good = {"provider": "nvd", "expired_at": days(3), "approved_by": "x", "approval_ref": "#1",
                "approved_on": days(-1), "where": "w.yaml:3"}
        for label, rows, rc in (
                ("lapsed since it was written", [dict(good, expired_at=days(-1))], 1),
                ("not a waivable provider", [dict(good, provider="rhel")], 1),
                ("duplicate", [good, good], 1),
                ("a field missing", [{k: v for k, v in good.items() if k != "approved_by"}], 1),
                ("not a list", {"nvd": good}, 1),
                ("well formed", [good], 0)):
            with self.subTest(label):
                w = self.tmp / "rows.json"
                w.write_text(json.dumps(rows), encoding="utf-8")
                r = self.run_checks("grype-db-providers", self.providers(nvd=100), "--waivers", w, "nvd")
                self.assertEqual(r.returncode, rc, r.stdout + r.stderr)

    def test_the_pre_tag_check_reads_the_waivers(self):
        ign = self.tmp / "ign.yaml"
        ign.write_text("vulnerabilities:\n" + entry(), encoding="utf-8")
        nc = self.nc(nc_line())
        r = self.run_checks("pending", ign, nc, self.wfile(waiver()))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("provider waiver nvd: in force until", r.stdout)
        self.assertEqual(r.stdout.count("in force until"), 1, r.stdout)
        for label, w, why in (("pending", waiver(approved_on=None, approval_ref="pending"), "approval_ref is pending"),
                              ("expires tomorrow", waiver(expired_at=days(1)), "within 2 days"),
                              ("expired", waiver(expired_at=days(-1)), "expired on")):
            with self.subTest(label):
                r = self.run_checks("pending", ign, nc, self.wfile(w, name=label.replace(" ", "-") + ".yaml"))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, r.stderr)


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
        lines = ["image: yuzu-agent-bundle-chisel (sha256:1)", f"run attempt: {attempt}", f"gate: {result}",
                 "scanned at: 2026-11-18T00:00:00Z"]
        # Both scanners' reports, as image-vuln-gate.sh writes them.
        for scanner in ("trivy", "grype"):
            (d / f"{scanner}-{stem}.json").write_text('{"SchemaVersion": 2}\n')
            (d / f"{scanner}-{stem}.txt").write_text("table\n")
            (d / f"{scanner}-{stem}.gate.txt").write_text("\n".join(lines) + "\n")
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
    FILES = ([f"{sc}-yuzu-agent-bundle-chisel.attempt-2." + s for sc in ("trivy", "grype")
              for s in ("gate.txt", "json", "txt")]
             + ["publish-yuzu-agent-bundle-chisel.attempt-2.txt"])

    def complete_first_run(self):
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.log.unlink()
        return r

    def test_an_attempt_missing_a_scanners_gate_report_attaches_nothing(self):
        # Both scanners write a .gate.txt on every exit; an attempt without one
        # of them is not the gate's output, so nothing is attached (WP15).
        for scanner in ("trivy", "grype"):
            with self.subTest(missing=scanner):
                f = self.work / "bundle-gate" / f"{scanner}-yuzu-agent-bundle-chisel.attempt-2.gate.txt"
                f.unlink()
                r = self.run_attach()
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn(f"no {scanner}-yuzu-agent-bundle-chisel.attempt-2.gate.txt", r.stdout + r.stderr)
                self.assertEqual(self.uploads(), [])
                self.write_report()

    def test_an_unjournaled_attempt_without_grypes_verdict_is_attached_as_it_is(self):
        # A gate killed before grype's verdict leaves Trivy's files only; that
        # attempt opened no journal and must not block every later attach.
        d = self.work / "bundle-gate"
        stem = "yuzu-agent-bundle-chisel.attempt-1"
        for suf, body in (("json", '{"SchemaVersion": 2}\n'), ("txt", "table\n"),
                          ("gate.txt", "image: x\nrun attempt: 1\ngate: FAIL: cancelled (SIGTERM)\n")):
            (d / f"trivy-{stem}.{suf}").write_text(body)
        r = self.run_attach()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"trivy-{stem}.gate.txt", self.assets())

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
