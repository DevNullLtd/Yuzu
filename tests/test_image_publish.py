#!/usr/bin/env python3
"""The publish journal contract (WP15/S9): the release tag moves last, and the
journal (scripts/ci/image-publish.sh) is write-ahead.

A table of rows: gate outcome x stop point x publish shape (buildx push by
digest, the agent bundle's `docker push` of a candidate tag). Each row runs a
publish job of .github/workflows/release.yml from its gate step on: the steps
in the WORKFLOW'S order, every `run:` block that touches the registry or the
journal executed as written (bash, `${{ }}` filled from a context), the `uses:`
steps that touch the registry simulated, against stub `docker` and `cosign`
that hold a fake registry in a JSON file. A stop point is a failure or a
cancel (SIGINT, then SIGTERM, to the step's process group) at a given moment.
Then, on the journal as UPLOADED (the evidence a consumer reads):

  I0  this attempt pushed anything            => the label is push-started or later
  I1  a release tag names this attempt's digest => the label is tagging or tagged
  I2  the label is tagged => every tag in it names its digest, which has the
      scanned layers and a signature
  I3  the journal is a legal prefix (or absent)
  I4  the digest is signed or attested => the label is verified or later
  and a complete row ends `tagged`.

Cross-attempt rows run 2-3 attempts of the bundle job on one registry, then
the attach job's `Sign and attach` block as written (stub gh), interrupted at
each attempt's attach and clean at the end: every attempt's files end up on the
release, and `image-publish.sh published` agrees with the registry.

Mutants, on scratch copies of release.yml and the scripts: adjacent swaps of
the publish steps, named reorders, a dropped intent line, `tagged` recorded
early. Each must be killed by some row.

The future-findings rule this enforces (docs/ci-architecture.md "The publish
journal"): a defect is a reachable row where the journal's terminal label
claims less than the registry holds, or where attach or the release check
accepts an illegal sequence.

Needs bash and PyYAML; skips on Windows.
"""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
SCRIPTS = ["image-publish.sh", "image-identity.sh"]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_image_vuln_gate as tivg  # noqa: E402  (GH stub, attach block)

OWNER_REPO = "ghcr.io/o"
SCANNED = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
OTHER = ["sha256:" + "1" * 64, "sha256:" + "3" * 64]
IMAGE_ID = "sha256:" + "9" * 64
LABELS = ["none", "push-started", "verified", "signed-attested", "tagging", "tagged"]

DOCKER_STUB = textwrap.dedent(
    """\
    import json, os, sys, time
    a = sys.argv[1:]
    st_path = os.environ["STUB_REG"]
    def load():
        return json.load(open(st_path))
    def save(st):
        json.dump(st, open(st_path, "w"))
    with open(os.environ["STUB_REG"] + ".log", "a") as f:
        f.write(json.dumps(a) + "\\n")
    fault = os.environ.get("STUB_FAULT", "")
    def hang():
        open(os.environ["STUB_HANG_MARK"], "w").write(str(os.getpid()))
        time.sleep(20)
        sys.exit(1)
    def count(kind):
        p = st_path + "." + kind + "." + os.environ["GITHUB_RUN_ATTEMPT"]
        n = int(open(p).read()) + 1 if os.path.exists(p) else 1
        open(p, "w").write(str(n))
        return n
    def resolve(st, ref):
        if "@" in ref:
            d = ref.split("@", 1)[1]
            return d if d in st["manifests"] else None
        return st["tags"].get(ref)
    def opt(n):
        return a[a.index(n) + 1]
    if a[:2] == ["image", "inspect"]:
        print(os.environ["STUB_IMAGE_ID"]); sys.exit(0)
    if a[:2] == ["image", "rm"] or a[0] == "tag":
        sys.exit(0)
    if a[0] == "push":
        cand = a[1]
        if fault == "push-hang-before":
            hang()
        st = load()
        d = os.environ["STUB_PUSH_DIGEST"]
        st["manifests"][d] = {"layers": json.loads(os.environ["STUB_PUSH_LAYERS"]),
                              "attempt": os.environ["GITHUB_RUN_ATTEMPT"]}
        st["tags"][cand] = d
        save(st)
        if fault == "push-hang-after":
            hang()
        print("digest: " + d); sys.exit(0)
    if a[:3] == ["buildx", "imagetools", "inspect"]:
        ref, fmt = a[3], opt("--format")
        if fmt == "{{json .Image}}":
            if fault == "verify-hang":
                hang()
            st = load()
            d = resolve(st, ref)
            if d is None:
                sys.exit(1)
            print(json.dumps({"rootfs": {"type": "layers", "diff_ids": st["manifests"][d]["layers"]}}))
            sys.exit(0)
        if fmt == "{{.Manifest.Digest}}":
            tag = ref.rsplit("/", 1)[1].partition(":")[2] if "@" not in ref else ""
            if fault == "resolve-hang" and tag and not tag.startswith("candidate-"):
                hang()
            st = load()
            d = resolve(st, ref)
            if d is None:
                sys.exit(1)
            print(d); sys.exit(0)
        sys.exit(2)
    if a[:3] == ["buildx", "imagetools", "create"]:
        assert "--prefer-index=false" in a, a
        tag, src = opt("-t"), a[-1]
        n = count("create")
        if fault == "create-hang-before:%d" % n:
            hang()
        st = load()
        d = resolve(st, src)
        if d is None:
            sys.exit(1)
        st["tags"][tag] = d
        save(st)
        if fault == "create-hang-after:%d" % n:
            hang()
        sys.exit(0)
    sys.exit(2)
    """
)

COSIGN_STUB = textwrap.dedent(
    """\
    import hashlib, json, os, sys
    a = sys.argv[1:]
    def opt(n):
        return a[a.index(n) + 1]
    if a[0] in ("sign", "verify"):
        st_path = os.environ["STUB_REG"]
        st = json.load(open(st_path))
        ref = a[-1]
        d = ref.split("@", 1)[1] if "@" in ref else st["tags"].get(ref)
        if a[0] == "sign":
            if os.environ.get("STUB_FAULT") == "sign-fail" or d not in st["manifests"]:
                sys.exit(1)
            st["signed"].append(d)
            json.dump(st, open(st_path, "w"))
            sys.exit(0)
        sys.exit(0 if d in st["signed"] else 1)
    valued = {"--bundle", "--certificate-identity", "--certificate-oidc-issuer"}
    pos = [x for i, x in enumerate(a[1:], 1) if not x.startswith("--") and a[i - 1] not in valued]
    sha = hashlib.sha256(open(pos[0], "rb").read()).hexdigest()
    if a[0] == "sign-blob":
        json.dump({"sha256": sha}, open(opt("--bundle"), "w")); sys.exit(0)
    if a[0] == "verify-blob":
        try:
            b = json.load(open(opt("--bundle")))
        except Exception:
            sys.exit(1)
        sys.exit(0 if b.get("sha256") == sha else 1)
    sys.exit(2)
    """
)


def digest_of(*parts):
    return "sha256:" + hashlib.sha256("/".join(map(str, parts)).encode()).hexdigest()


# ── The workflow, as data ────────────────────────────────────────────────────
def load_steps(text, job):
    """The job's steps from its gate step (id: gate) on, as dicts."""
    steps = yaml.safe_load(text)["jobs"][job]["steps"]
    i = next(i for i, s in enumerate(steps) if s.get("id") == "gate")
    return steps[i:]


def step_key(st):
    """A short role for a step, for mutants and the no-op decision."""
    run = st.get("run") or ""
    uses = st.get("uses") or ""
    for sub in ("open", "push-started", "verified", "signed-attested", "tag", "state"):
        if re.search(rf"image-publish\.sh {sub} ", run):
            return "push" if "docker push" in run else sub
    if "check-release-tag-sha.sh" in run:
        return "recheck"
    if "cosign sign --yes" in run:
        return "sign"
    if "build-push-action" in uses and "push=true" not in str((st.get("with") or {}).get("outputs", "")):
        return "build"   # a build that pushes nothing (the healthcheck/scan build)
    for k, v in (("build-push-action", "push"), ("sbom-action", "sbom"), ("attest-build-provenance", "attest"),
                 ("cosign-installer", "cosign-install"), ("upload-artifact", "upload")):
        if k in uses:
            if v == "upload":
                return "upload-gate" if "image-vuln-gate" in str((st.get("with") or {}).get("name", "")) else "upload"
            return v
    if st.get("id") == "gate":
        return "gate"
    return "other"


EXPR = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def fill(value, ctx):
    def sub(m):
        k = m.group(1)
        if k not in ctx:
            # As on GitHub, an output a step has not (yet) set is empty; any
            # other unknown expression is a harness gap, not a silent ''.
            if re.fullmatch(r"steps\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+", k):
                return ""
            raise KeyError(f"no context for ${{{{ {k} }}}}")
        return str(ctx[k])
    return EXPR.sub(sub, str(value))


KINDS = {
    "buildx": dict(job="docker-publish", name="yuzu-server", repo=f"{OWNER_REPO}/yuzu-server",
                   tags=[f"{OWNER_REPO}/yuzu-server:1.2.3", f"{OWNER_REPO}/yuzu-server:1.2",
                         f"{OWNER_REPO}/yuzu-server:latest"]),
    "bundle": dict(job="docker-publish-agent-bundle", name="yuzu-agent-bundle-chisel",
                   repo=f"{OWNER_REPO}/yuzu-agent-bundle-chisel",
                   tags=[f"{OWNER_REPO}/yuzu-agent-bundle-chisel:1.2.3"]),
}

GATES = {
    "pass": ("gate: pass", "success"),
    "fail": ("gate: FAIL: fixable CRITICAL", "failure"),
    "SIGINT": ("gate: FAIL: cancelled (SIGINT) before this image was judged", "cancelled"),
    "SIGTERM": ("gate: FAIL: cancelled (SIGTERM) before this image was judged", "cancelled"),
    "budget": ("gate: FAIL: gate stopped before this image was judged: the gate ran out of its 1500s budget",
               "failure"),
}

# stop point -> (where, how). where: a step role (cancel before it runs), or a
# stub fault for the step that hits it.
STOPS = {
    "complete": (None, None),
    "pre-push": ("before", "push"),
    "mid-push": ("fault", "push-hang-after"),
    "verify fail": ("layers", "other"),
    "verify cancel": ("fault", "verify-hang"),
    "attest fail": ("fail", "attest"),
    "sign fail": ("fault", "sign-fail"),
    "pre-tag": ("before", "tag"),
    "mid-tag applied": ("fault", "create-hang-after:1"),
    "mid-tag not applied": ("fault", "create-hang-before:1"),
    "post-tag before tagged": ("fault", "resolve-hang"),
}


class Rig:
    """One fake registry, one release; runs publish-job attempts on them."""

    def __init__(self, tmp, release_text=None, scripts=None):
        self.tmp = Path(tmp)
        self.root = self.tmp / "root"
        (self.root / "scripts" / "ci").mkdir(parents=True)
        for s in SCRIPTS:
            src = (scripts or {}).get(s)
            dst = self.root / "scripts" / "ci" / s
            dst.write_text(src if src is not None else (ROOT / "scripts" / "ci" / s).read_text(encoding="utf-8"))
            dst.chmod(0o755)
        (self.root / "scripts" / "ci" / "check-release-tag-sha.sh").write_text("exit 0\n")
        self.release_text = release_text if release_text is not None else RELEASE.read_text(encoding="utf-8")
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for name, body in (("docker", DOCKER_STUB), ("cosign", COSIGN_STUB), ("gh", tivg.GH_STUB)):
            p = self.bin / name
            p.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
            p.chmod(0o755)
        self.reg = self.tmp / "registry.json"
        self.reg.write_text(json.dumps({"manifests": {}, "tags": {}, "signed": [], "attested": []}))
        self.artifacts = {}   # attempt -> {file name: bytes}, as uploaded

    def registry(self):
        return json.loads(self.reg.read_text())

    def env(self, attempt, extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "STUB_", "RUNNER_"))}
        env.update(PATH=f"{self.bin}{os.pathsep}{env.get('PATH', '')}", STUB_REG=str(self.reg),
                   GITHUB_RUN_ID="77", GITHUB_RUN_ATTEMPT=str(attempt), GITHUB_SERVER_URL="https://github.com",
                   GITHUB_WORKFLOW_REF="o/r/.github/workflows/release.yml@refs/tags/v1.2.3",
                   GITHUB_REF_NAME="v1.2.3", STUB_IMAGE_ID=IMAGE_ID)
        env.update(extra or {})
        return env

    def run_job(self, kind, attempt, gate="pass", stop="complete"):
        """Runs one attempt of the publish job. Returns the step outcomes."""
        k = KINDS[kind]
        rt = self.tmp / f"rt-{kind}-{attempt}"
        rt.mkdir()
        rep = rt / "image-vuln-gate"
        where, how = STOPS[stop]
        ctx = {"matrix.image": "server", "steps.owner.outputs.value": "o",
               "steps.built.outputs.id": IMAGE_ID, "steps.built.outputs.layers": ",".join(SCANNED),
               "steps.meta.outputs.tags": "\n".join(k["tags"]), "steps.meta.outputs.labels": "",
               "steps.ref.outputs.image": k["repo"], "steps.ref.outputs.version": "1.2.3",
               "github.run_id": "77", "github.run_attempt": str(attempt), "github.sha": "abc",
               "runner.temp": str(rt), "runner.tool_cache": str(rt), "env.YUZU_BUILD_JOBS": "2",
               "matrix.dockerfile": "x"}
        push_digest = digest_of(kind, attempt)
        layers = OTHER if (where, how) == ("layers", "other") else SCANNED
        stub = {"STUB_FAULT": how if where == "fault" else "", "STUB_PUSH_DIGEST": push_digest,
                "STUB_PUSH_LAYERS": json.dumps(layers), "RUNNER_TEMP": str(rt),
                "STUB_HANG_MARK": str(rt / "hang")}
        status, outcomes = "success", []
        for st in load_steps(self.release_text, k["job"]):
            role = step_key(st)
            cond = str(st.get("if", ""))
            if status != "success" and "always()" not in cond:
                outcomes.append((role, "skipped"))
                continue
            hit = role in ("push-started", "push") if how == "push" else role == how
            if where == "before" and hit and status == "success":
                status = "cancelled"
                outcomes.append((role, "cancelled-before"))
                continue
            out = self.run_step(st, role, ctx, rep, attempt, gate, stub, where, how, push_digest, layers)
            outcomes.append((role, out))
            if out in ("failure", "cancelled") and status == "success" and not st.get("continue-on-error"):
                status = out
        return outcomes

    def run_step(self, st, role, ctx, rep, attempt, gate, stub, where, how, push_digest, layers):
        name = None
        for kname, k in KINDS.items():
            if k["repo"] == ctx["steps.ref.outputs.image"]:
                name = k["name"]
        if role == "gate":
            shutil.rmtree(rep, ignore_errors=True)
            rep.mkdir(parents=True)
            line, outcome = GATES[gate]
            stem = f"trivy-{name}.attempt-{attempt}"
            if outcome == "success":
                (rep / f"{stem}.json").write_text('{"SchemaVersion": 2}\n')
                (rep / f"{stem}.txt").write_text("Report Summary\n")
            (rep / f"{stem}.gate.txt").write_text(f"image: {name}\nrun attempt: {attempt}\n{line}\n")
            return outcome
        uses = st.get("uses") or ""
        if uses:
            if role == "push":   # build-push-action, push by digest
                w = st.get("with") or {}
                out = fill(w.get("outputs", ""), ctx)
                assert "push-by-digest=true" in out and "push=true" in out, out
                assert "tags" not in w, "the push carries no release tag"
                reg = self.registry()
                reg["manifests"][push_digest] = {"layers": layers, "attempt": str(attempt)}
                self.reg.write_text(json.dumps(reg))
                ctx["steps.build.outputs.digest"] = push_digest
                return "cancelled" if (where, how) == ("fault", "push-hang-after") else "success"
            if role == "attest":
                if (where, how) == ("fail", "attest"):
                    return "failure"
                d = fill((st.get("with") or {})["subject-digest"], ctx)
                reg = self.registry()
                reg["attested"].append(d)
                self.reg.write_text(json.dumps(reg))
                return "success"
            if role == "upload-gate":
                if rep.is_dir():
                    self.artifacts[attempt] = {p.name: p.read_bytes() for p in rep.iterdir()}
                return "success"
            return "success"   # sbom, cosign-install, other uploads, checkout
        run = st.get("run") or ""
        if role in ("other", "recheck"):
            return "success"
        env = self.env(attempt, stub)
        for key, val in (st.get("env") or {}).items():
            env[key] = fill(val, ctx)
        gh_out = rep.parent / f"out-{len(os.listdir(rep.parent))}"
        env["GITHUB_OUTPUT"] = str(gh_out)
        env["GITHUB_STEP_SUMMARY"] = str(rep.parent / "summary.md")
        script = rep.parent / "step.sh"
        script.write_text(run)
        mark = Path(stub["STUB_HANG_MARK"])
        mark.unlink(missing_ok=True)
        p = subprocess.Popen(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)], cwd=self.root,
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)
        cancelled = False
        deadline = time.monotonic() + 30
        while p.poll() is None and time.monotonic() < deadline:
            if mark.exists():
                # The runner's cancel: SIGINT, then SIGTERM.
                os.killpg(p.pid, signal.SIGINT)
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGTERM)
                cancelled = True
                break
            time.sleep(0.01)
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        self.last_output = p.stdout.read()
        p.stdout.close()
        if gh_out.exists():
            for line in gh_out.read_text().splitlines():
                key, _, val = line.partition("=")
                ctx[f"steps.{st.get('id')}.outputs.{key}"] = val
        if cancelled:
            return "cancelled"
        return "success" if p.returncode == 0 else "failure"

    # ── Reading the evidence ──
    def journal(self, kind, attempt):
        files = self.artifacts.get(attempt, {})
        return files.get(f"publish-{KINDS[kind]['name']}.attempt-{attempt}.txt")

    def state(self, kind, attempt):
        """(exit status, {state, digest, tags, ...}) of the uploaded journal."""
        d = self.tmp / f"read-{kind}-{attempt}"
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir()
        for n, data in self.artifacts.get(attempt, {}).items():
            (d / n).write_bytes(data)
        r = subprocess.run(["bash", str(ROOT / "scripts" / "ci" / "image-publish.sh"), "state", str(d),
                            KINDS[kind]["name"], str(attempt)], capture_output=True, text=True)
        info = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
        return r.returncode, info

    def published(self, kind):
        d = self.tmp / f"merged-{kind}"
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir()
        for files in self.artifacts.values():
            for n, data in files.items():
                (d / n).write_bytes(data)
        r = subprocess.run(["bash", str(ROOT / "scripts" / "ci" / "image-publish.sh"), "published", str(d),
                            KINDS[kind]["name"]], capture_output=True, text=True)
        info = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
        return r.returncode, info


def violations(rig, kind, attempt, gate, stop):
    """Every invariant the row breaks, as text."""
    out = []
    k = KINDS[kind]
    reg = rig.registry()
    mine = digest_of(kind, attempt)
    rc, info = rig.state(kind, attempt)
    if attempt not in rig.artifacts:
        out.append("the gate reports were not uploaded")
    if rc != 0:
        out.append("I3: the uploaded journal is not a legal prefix")
        return out
    label = info.get("state", "absent")
    rank = LABELS.index(label) if label in LABELS else -1
    pushed = mine in reg["manifests"]
    if pushed and rank < LABELS.index("push-started"):
        out.append(f"I0: attempt {attempt} pushed {mine} but the journal says {label}")
    tagged_here = [t for t in k["tags"] if reg["tags"].get(t) == mine]
    if tagged_here and label not in ("tagging", "tagged"):
        out.append(f"I1: {tagged_here} name this attempt's digest but the journal says {label}")
    if (mine in reg["signed"] or mine in reg["attested"]) and rank < LABELS.index("verified"):
        out.append(f"I4: {mine} is signed or attested but the journal says {label}")
    if label == "tagged":
        d = info["digest"]
        for t in info["tags"].split(","):
            if reg["tags"].get(t) != d:
                out.append(f"I2: {t} names {reg['tags'].get(t)}, not the journal's {d}")
        if reg["manifests"].get(d, {}).get("layers") != SCANNED:
            out.append(f"I2: {d} does not have the scanned layers")
        if d not in reg["signed"]:
            out.append(f"I2: {d} is not signed")
    if gate != "pass" and (label != "absent" or pushed):
        out.append(f"the gate did not pass, but the journal says {label} (pushed: {pushed})")
    if gate == "pass" and stop == "complete" and label != "tagged":
        out.append(f"a complete run ended at {label}, not tagged")
    return out


ROWS = [(g, s) for g in GATES for s in (STOPS if g == "pass" else ["complete"])]


def first_killing_row(kind, release_text=None, scripts=None, rows=None):
    """The first row whose invariants fail, or None (the mutant survived)."""
    for gate, stop in rows or ROWS:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_publish_mut_") as t:
            rig = Rig(t, release_text, scripts)
            rig.run_job(kind, 1, gate, stop)
            v = violations(rig, kind, 1, gate, stop)
            if v:
                return (gate, stop, v)
    return None


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class PublishTable(unittest.TestCase):
    def test_every_row_keeps_the_invariants(self):
        for kind in KINDS:
            for gate, stop in ROWS:
                with self.subTest(kind=kind, gate=gate, stop=stop), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_publish_") as t:
                    rig = Rig(t)
                    outcomes = rig.run_job(kind, 1, gate, stop)
                    self.assertEqual(violations(rig, kind, 1, gate, stop), [], outcomes)

    def test_the_stop_points_reach_the_state_they_name(self):
        # The table is only as good as its stop points: each must stop where it
        # says, so a row cannot pass by stopping somewhere harmless.
        want = {"pre-push": "none", "mid-push": "push-started", "verify fail": "push-started",
                "verify cancel": "push-started", "attest fail": "verified", "sign fail": "verified",
                "pre-tag": "signed-attested", "mid-tag applied": "tagging", "mid-tag not applied": "tagging",
                "post-tag before tagged": "tagging", "complete": "tagged"}
        for kind in KINDS:
            for stop, label in want.items():
                with self.subTest(kind=kind, stop=stop), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_publish_") as t:
                    rig = Rig(t)
                    rig.run_job(kind, 1, "pass", stop)
                    rc, info = rig.state(kind, 1)
                    self.assertEqual((rc, info.get("state")), (0, label))
                    reg = rig.registry()
                    mine = digest_of(kind, 1)
                    applied = [t_ for t_ in KINDS[kind]["tags"] if reg["tags"].get(t_) == mine]
                    if stop == "mid-tag applied":
                        self.assertTrue(applied, "the first tag should have moved")
                    if stop == "mid-tag not applied":
                        self.assertEqual(applied, [])
                    if stop == "post-tag before tagged":
                        self.assertEqual(applied, KINDS[kind]["tags"])
                    if stop in ("mid-push", "verify fail", "verify cancel"):
                        self.assertIn(mine, reg["manifests"])
        for gate in ("fail", "SIGINT", "SIGTERM", "budget"):
            with self.subTest(gate=gate), tempfile.TemporaryDirectory(prefix="yuzu_test_publish_") as t:
                rig = Rig(t)
                rig.run_job("bundle", 1, gate)
                self.assertEqual(rig.state("bundle", 1)[1].get("state"), "absent")
                self.assertIn(1, rig.artifacts, "a refusal's report is uploaded too")


def attach_env(rig, interrupt=""):
    return rig.env(0, {"GH_REPO": "o/r", "GH_TOKEN": "x", "SIGN_REPOSITORY": "o/r", "SIGN_REF": "refs/tags/v1.2.3",
                       "PUBLISH": str(rig.root / "scripts" / "ci" / "image-publish.sh"),
                       "RUNNER_TEMP": str(rig.tmp / "attach-rt"), "STUB_GH_STATE": str(rig.tmp / "gh.json"),
                       "STUB_GH_LOG": str(rig.tmp / "gh.log"), "STUB_GH_INTERRUPT": interrupt})


def run_attach(rig, interrupt=""):
    """The attach job as in a fresh runner: download every attempt so far
    (pattern + merge-multiple), then `Sign and attach` as written."""
    work = rig.tmp / f"attach-{time.monotonic_ns()}"
    (work / "bundle-gate").mkdir(parents=True)
    (rig.tmp / "attach-rt").mkdir(exist_ok=True)
    for files in rig.artifacts.values():
        for n, data in files.items():
            (work / "bundle-gate" / n).write_bytes(data)
    script = rig.tmp / "attach.sh"
    script.write_text(tivg.attach_block())
    return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)], cwd=work,
                          env=attach_env(rig, interrupt), capture_output=True, text=True, timeout=60)


# (gate, stop) per attempt; expected `published` exit status and attempt.
CROSS = {
    "refused, then published": ([("fail", "complete"), ("pass", "complete")], 0, "2"),
    "published, then a re-run fails verify": ([("pass", "complete"), ("pass", "verify fail")], 0, "1"),
    "published, then a re-run is cancelled mid-tag": ([("pass", "complete"), ("pass", "mid-tag applied")], 3, "1"),
    "a mid-tag stop is healed by a third attempt": (
        [("pass", "complete"), ("pass", "mid-tag applied"), ("pass", "complete")], 0, "3"),
    "a stop before tagged, a cancel, then published": (
        [("pass", "mid-tag not applied"), ("SIGTERM", "complete"), ("pass", "complete")], 0, "3"),
    "published, a budget stop, then stopped after the tags moved": (
        [("pass", "complete"), ("budget", "complete"), ("pass", "post-tag before tagged")], 3, "1"),
    "nothing published": ([("pass", "sign fail"), ("SIGINT", "complete")], 0, "none"),
}


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class CrossAttempt(unittest.TestCase):
    def test_every_attempt_reaches_the_release_and_the_published_one_is_the_registrys(self):
        for label, (attempts, want_rc, want_pub) in CROSS.items():
            for interrupt_at in range(1, len(attempts) + 1):
                with self.subTest(case=label, attach_interrupted_at=interrupt_at), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_publish_x_") as t:
                    rig = Rig(t)
                    (rig.tmp / "gh.json").write_text(json.dumps(
                        {"tag": "v1.2.3", "release_id": 42, "next_id": 100, "assets": []}))
                    for n, (gate, stop) in enumerate(attempts, 1):
                        rig.run_job("bundle", n, gate, stop)
                        self.assertEqual(violations(rig, "bundle", n, gate, stop), [])
                        if n == interrupt_at:
                            # This attempt's attach dies part-way through its upload.
                            first = sorted(rig.artifacts[n])[0]
                            r = run_attach(rig, interrupt=first)
                            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                        else:
                            run_attach(rig)
                    r = run_attach(rig)   # the final, clean attach
                    self.assertEqual(r.returncode, 1 if want_rc == 3 else 0, r.stdout + r.stderr)
                    on_release = {a["name"]: bytes.fromhex(a["data"])
                                  for a in json.loads((rig.tmp / "gh.json").read_text())["assets"]
                                  if a["state"] == "uploaded"}
                    for n, files in rig.artifacts.items():
                        for f, data in files.items():
                            self.assertEqual(on_release.get(f), data, f"attempt {n}: {f}")
                        sums = f"yuzu-agent-bundle-chisel-image-vuln-gate.attempt-{n}.SHA256SUMS"
                        self.assertIn(sums, on_release)
                        self.assertIn(sums + ".sigstore", on_release)
                    rc, info = rig.published("bundle")
                    self.assertEqual(rc, want_rc, info)
                    if rc == 0:
                        self.assertEqual(info.get("published"), want_pub)
                    if rc == 0 and want_pub != "none":
                        # The published attempt is what the registry's tag names.
                        reg = rig.registry()
                        self.assertEqual(reg["tags"][KINDS["bundle"]["tags"][0]], digest_of("bundle", int(want_pub)))

    def test_buildx_attempts_resolve_like_the_registry(self):
        for label, (attempts, want_rc, want_pub) in CROSS.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="yuzu_test_publish_x_") as t:
                rig = Rig(t)
                for n, (gate, stop) in enumerate(attempts, 1):
                    rig.run_job("buildx", n, gate, stop)
                rc, info = rig.published("buildx")
                self.assertEqual(rc, want_rc, info)
                if rc == 0 and want_pub != "none":
                    reg = rig.registry()
                    for tag in KINDS["buildx"]["tags"]:
                        self.assertEqual(reg["tags"][tag], digest_of("buildx", int(want_pub)), tag)


# ── Mutants ──────────────────────────────────────────────────────────────────
def swap_steps(text, job, a, b):
    """release.yml text with job's steps of roles a and b (first of each)
    swapped, every other byte unchanged."""
    lines = text.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln == f"  {job}:")
    end = next(i for i in range(start + 1, len(lines)) if re.match(r"^  [A-Za-z0-9_-]+:$", lines[i]))
    steps_at = [i for i in range(start, end) if lines[i].startswith("      - ")]
    blocks = []
    for j, s in enumerate(steps_at):
        e = steps_at[j + 1] if j + 1 < len(steps_at) else end
        # Leading comment lines belong to the next step.
        while e > s and (lines[e - 1].strip() == "" or lines[e - 1].lstrip().startswith("#")):
            e -= 1
        blocks.append((s, e))
    roles = []
    for s, e in blocks:
        st = yaml.safe_load("\n".join(ln[6:] for ln in lines[s:e]))[0]
        roles.append(step_key(st))
    g = roles.index("gate")   # the publish steps are after the gate
    ia, ib = roles.index(a, g), roles.index(b, g)
    (sa, ea), (sb, eb) = sorted([blocks[ia], blocks[ib]])
    first, second = lines[sa:ea], lines[sb:eb]
    mid = lines[ea:sb]
    return "\n".join(lines[:sa] + second + mid + first + lines[eb:])


PUBLISH_ROLES = {
    "buildx": ["open", "push-started", "push", "verified", "sbom", "attest", "cosign-install", "sign",
               "signed-attested", "upload", "recheck", "tag", "upload-gate"],
    "bundle": ["open", "push", "verified", "sbom", "upload", "attest", "sign", "signed-attested", "recheck", "tag",
               "upload-gate"],
}
# Adjacent swaps that change nothing the journal or the registry can see: the
# SBOM (it reads the registry, by digest) against verify, the by-digest
# SBOM/attest/sign steps among themselves, the SBOM artifact upload against its
# neighbours, and the #5282 git-tag re-check against its neighbours (its place
# before the tag move is pinned by tests/shell/test_release_guard.sh).
NEUTRAL = {frozenset(p) for p in (("verified", "sbom"), ("sbom", "attest"), ("attest", "cosign-install"),
                                  ("cosign-install", "sign"), ("attest", "sign"), ("sbom", "upload"),
                                  ("upload", "attest"), ("upload", "recheck"), ("signed-attested", "upload"),
                                  ("signed-attested", "recheck"), ("recheck", "tag"))}


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class Mutants(unittest.TestCase):
    """Each mutant runs on scratch copies; each must be killed by some row."""

    def test_the_roles_are_the_workflows(self):
        text = RELEASE.read_text(encoding="utf-8")
        for kind, roles in PUBLISH_ROLES.items():
            got = [step_key(s) for s in load_steps(text, KINDS[kind]["job"])]
            got = [r for r in got if r in roles]
            with self.subTest(kind=kind):
                dedup = [r for i, r in enumerate(got) if r not in got[:i]]
                self.assertEqual(dedup, roles)

    def test_adjacent_step_swaps_are_killed(self):
        text = RELEASE.read_text(encoding="utf-8")
        for kind, roles in PUBLISH_ROLES.items():
            for a, b in zip(roles, roles[1:]):
                if frozenset((a, b)) in NEUTRAL:
                    continue
                with self.subTest(kind=kind, swap=(a, b)):
                    mutant = swap_steps(text, KINDS[kind]["job"], a, b)
                    self.assertNotEqual(mutant, text)
                    self.assertIsNotNone(first_killing_row(kind, release_text=mutant),
                                         f"swapping {a} and {b} in {KINDS[kind]['job']} survived")

    def test_named_reorders_are_killed(self):
        text = RELEASE.read_text(encoding="utf-8")
        for kind, a, b in (("buildx", "push-started", "push"),      # push before its intent
                           ("buildx", "tag", "sign"),               # tags before the signature
                           ("bundle", "tag", "sign"),
                           ("buildx", "upload-gate", "tag"),        # evidence uploaded before the tags move
                           ("bundle", "upload-gate", "tag"),
                           ("buildx", "verified", "sign"),          # signed before verified
                           ("bundle", "verified", "sign")):
            with self.subTest(kind=kind, swap=(a, b)):
                mutant = swap_steps(text, KINDS[kind]["job"], a, b)
                self.assertIsNotNone(first_killing_row(kind, release_text=mutant), f"{kind}: {a}<->{b} survived")
        # The bundle's intent line moved after its push, inside one step.
        old = 'scripts/ci/image-publish.sh push-started "$RUNNER_TEMP/image-vuln-gate" "$NAME" "$GITHUB_RUN_ATTEMPT" "$candidate"'
        self.assertEqual(text.count(old), 1)
        moved = text.replace(old + "\n", "").replace('          docker push "$candidate"\n',
                                                     '          docker push "$candidate"\n          ' + old + "\n")
        self.assertNotEqual(moved, text)
        self.assertIsNotNone(first_killing_row("bundle", release_text=moved), "intent after the bundle push survived")

    def test_script_mutants_are_killed(self):
        src = (ROOT / "scripts" / "ci" / "image-publish.sh").read_text(encoding="utf-8")
        intent = '        append "$DIR" "$NAME" "$N" "push-started $cand"\n'
        tagging = '        append "$DIR" "$NAME" "$N" "tagging $list $J_DIGEST"\n'
        tagged = '        append "$DIR" "$NAME" "$N" "tagged $list $J_DIGEST"\n'
        for line in (intent, tagging, tagged):
            self.assertEqual(src.count(line), 1, line)
        mutants = {
            "intent line dropped": src.replace(intent, ""),
            "tagging line dropped": src.replace(tagging, ""),
            "tagged recorded before the tags move": src.replace(tagged, "").replace(tagging, tagging + tagged),
            "tagging recorded after the tags move": src.replace(tagging, "").replace(tagged, tagging + tagged),
        }
        for label, mutant in mutants.items():
            for kind in KINDS:
                with self.subTest(mutant=label, kind=kind):
                    self.assertNotEqual(mutant, src)
                    self.assertIsNotNone(first_killing_row(kind, scripts={"image-publish.sh": mutant}),
                                         f"{label} survived")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
