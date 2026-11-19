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
cancel at a given moment, delivered as the Actions runner delivers it: SIGINT
to the step's PID only (never its process group), SIGTERM after a grace, then
SIGKILL of the PID (actions/runner src/Runner.Sdk/ProcessInvoker.cs
CancelAndKillProcessTree/SendSignal: kill(pid, sig)). A process the step left
behind keeps running, as on a runner, until the job ends (the runner's orphan
cleanup, JobExtension FinalizeJob), which the rig models by waiting for the
step's leftovers after the last step.
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

The two in-place edits of the local image SBOM pair (`artifact-sbom.py
augment`, then `mark-image`) touch neither the registry nor the journal, so no
row can see them: SbomEditOrder pins them structurally after `signed-attested`
and before the SBOM upload and the tag move, and refuses each reorder mutant.

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
        # A stalled call. It fails on its own after 20 s, or as soon as the
        # step that ran it is gone (it was orphaned: it moves nothing later).
        open(os.environ["STUB_HANG_MARK"], "w").write(str(os.getpid()))
        ppid = os.getppid()
        for _ in range(200):
            if os.getppid() != ppid:
                sys.exit(1)
            time.sleep(0.1)
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
        if fault == "create-late:%d" % n:
            # A slow registry call that COMPLETES: if nothing stops it, it moves
            # the tag ~8 s later, orphaned or not.
            open(os.environ["STUB_HANG_MARK"], "w").write(str(os.getpid()))
            time.sleep(8)
        st = load()
        d = resolve(st, src)
        if d is None:
            sys.exit(1)
        st["tags"][tag] = d
        if fault == "tag-raced:%d" % n:
            # Another writer moves the tag right after this one did.
            st["tags"][tag] = "sha256:" + "e" * 64
        save(st)
        if fault == "create-hang-after:%d" % n:
            hang()
        sys.exit(0)
    sys.exit(2)
    """
)

# `tail`, for the stall row: image-publish.sh reads a journal's last byte with
# `tail -c 1 FILE` while loading it. When the journal is the one `tag` is about
# to extend (its last line `signed-attested`), this stalls 3 s first (a loaded
# runner, slow storage): long enough to outlast the rig's SIGINT grace.
TAIL_STUB = textwrap.dedent(
    """\
    import os, sys, time
    a = sys.argv[1:]
    f = a[-1] if a else ""
    lines = open(f).read().splitlines() if os.path.basename(f).startswith("publish-") and os.path.isfile(f) else []
    if os.environ.get("STUB_FAULT") == "stall-before-tagging" and lines and \
            lines[-1].startswith("publish: signed-attested "):
        open(os.environ["STUB_HANG_MARK"], "w").write(str(os.getpid()))
        time.sleep(3)
    os.execv(os.environ["STUB_REAL_TAIL"], ["tail"] + a)
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


# A step `if:` as the rig evaluates it: always(), step outcomes, && and ||.
def condition_holds(cond, status, outcomes_by_id):
    cond = cond.strip()
    if cond.startswith("${{") and cond.endswith("}}"):
        cond = cond[3:-2].strip()
    if not cond:
        return status == "success"
    if not re.search(r"\balways\(\)|\bfailure\(\)|\bcancelled\(\)", cond) and status != "success":
        return False
    expr = re.sub(r"steps\.([A-Za-z0-9_-]+)\.outcome",
                  lambda m: repr(outcomes_by_id.get(m.group(1), "skipped")), cond)
    expr = (expr.replace("&&", " and ").replace("||", " or ").replace("always()", "True")
            .replace("failure()", repr(status == "failure")).replace("cancelled()", repr(status == "cancelled")))
    assert re.fullmatch(r"[\sA-Za-z0-9_'()=!.-]*", expr), expr
    return bool(eval(expr, {"__builtins__": {}}, {}))   # noqa: S307 (rig-built text only)


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
            return sub
    if re.search(r"^\s*docker push ", run, re.M):
        return "push"   # the agent bundle's push of its candidate tag
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
    # The two in-place edits of the local image SBOM pair (scripts/ci/
    # artifact-sbom.py): neither touches the registry or the journal, so the
    # rig runs them as no-ops; their place is pinned by SbomEditOrder below.
    m = re.search(r"artifact-sbom\.py (augment|mark-image) ", run)
    if m:
        return m.group(1)
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
    # G8P6-chaos-injector-1: the cancel lands while `tag` is still loading the
    # journal, before it appends `tagging`, and that load stalls past the
    # runner's SIGINT grace. Unless the script is the step's process (`exec`)
    # and stops at the next boundary, it outlives the step and moves the tags
    # after the upload has captured `signed-attested`.
    "cancel mid-tag before tagging": ("fault", "stall-before-tagging"),
    # A tag move in flight when the cancel lands, that would complete ~8 s
    # later if nothing stopped it (G8P6-chaos-injector-2 across runs).
    "mid-tag late create": ("fault", "create-late:1"),
    # Another writer moves the first tag right after `tag` did: the post-move
    # resolve must see it and leave the journal at `tagging`.
    "tag raced": ("fault", "tag-raced:1"),
    # The evidence upload fails once; the retry step uploads it.
    "upload fails once": ("upload", "fail-once"),
}


SIGINT_GRACE = 1.5    # the runner waits 7.5 s after SIGINT
SIGTERM_GRACE = 2.5   # and 2.5 s after SIGTERM, then SIGKILLs the PID


class Rig:
    """One fake registry, one release; runs publish-job attempts on them."""

    def __init__(self, tmp, release_text=None, scripts=None, registry=None, salt=None, run_id="77"):
        self.salt = salt
        self.run_id = run_id
        self.pending = []      # process groups of steps that ran, drained at the job's end
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
        self.real_tail = shutil.which("tail")
        for name, body in (("docker", DOCKER_STUB), ("cosign", COSIGN_STUB), ("gh", tivg.GH_STUB),
                           ("tail", TAIL_STUB)):
            p = self.bin / name
            p.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
            p.chmod(0o755)
        if registry is not None:
            self.reg = Path(registry)   # another run on the same registry
        else:
            self.reg = self.tmp / "registry.json"
            self.reg.write_text(json.dumps({"manifests": {}, "tags": {}, "signed": [], "attested": []}))
        self.artifacts = {}   # attempt -> {file name: bytes}, as uploaded

    def registry(self):
        return json.loads(self.reg.read_text())

    def digest(self, kind, attempt):
        """The digest this rig's run pushes for one attempt."""
        return digest_of(kind, attempt) if self.salt is None else digest_of(kind, attempt, self.salt)

    def drain(self, cap=20):
        """The job's end: wait for what the steps left behind, then kill it
        (the runner's orphan cleanup runs after the last step)."""
        deadline = time.monotonic() + cap
        for pgid in self.pending:
            while time.monotonic() < deadline:
                try:
                    os.killpg(pgid, 0)
                except (ProcessLookupError, PermissionError):
                    break
                time.sleep(0.05)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        self.pending = []

    def env(self, attempt, extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "STUB_", "RUNNER_"))}
        env.update(PATH=f"{self.bin}{os.pathsep}{env.get('PATH', '')}", STUB_REG=str(self.reg),
                   GITHUB_RUN_ID=self.run_id, GITHUB_RUN_ATTEMPT=str(attempt), GITHUB_SERVER_URL="https://github.com",
                   GITHUB_WORKFLOW_REF="o/r/.github/workflows/release.yml@refs/tags/v1.2.3",
                   GITHUB_REF_NAME="v1.2.3", STUB_IMAGE_ID=IMAGE_ID, STUB_REAL_TAIL=self.real_tail)
        env.update(extra or {})
        return env

    def run_job(self, kind, attempt, gate="pass", stop="complete", drain=True):
        """Runs one attempt of the publish job. Returns the step outcomes.
        drain=False leaves whatever the steps left running (another run may
        start meanwhile); call drain() later."""
        k = KINDS[kind]
        rt = self.tmp / f"rt-{kind}-{attempt}"
        rt.mkdir()
        rep = rt / "image-vuln-gate"
        where, how = STOPS[stop]
        ctx = {"matrix.image": "server", "steps.owner.outputs.value": "o",
               "steps.built.outputs.id": IMAGE_ID, "steps.built.outputs.layers": ",".join(SCANNED),
               "steps.meta.outputs.tags": "\n".join(k["tags"]), "steps.meta.outputs.labels": "",
               "steps.ref.outputs.image": k["repo"], "steps.ref.outputs.version": "1.2.3",
               "github.run_id": self.run_id, "github.run_attempt": str(attempt), "github.sha": "abc",
               "runner.temp": str(rt), "runner.tool_cache": str(rt), "env.YUZU_BUILD_JOBS": "2",
               "matrix.dockerfile": "x"}
        push_digest = self.digest(kind, attempt)
        layers = OTHER if (where, how) == ("layers", "other") else SCANNED
        stub = {"STUB_FAULT": how if where == "fault" else "", "STUB_PUSH_DIGEST": push_digest,
                "STUB_PUSH_LAYERS": json.dumps(layers), "RUNNER_TEMP": str(rt),
                "STUB_HANG_MARK": str(rt / "hang")}
        status, outcomes, by_id = "success", [], {}
        self.upload_failures = 1 if (where, how) == ("upload", "fail-once") else 0
        for st in load_steps(self.release_text, k["job"]):
            role = step_key(st)
            cond = str(st.get("if", ""))
            if not condition_holds(cond, status, by_id):
                outcomes.append((role, "skipped"))
                if st.get("id"):
                    by_id[st["id"]] = "skipped"
                continue
            hit = role in ("push-started", "push") if how == "push" else role == how
            if where == "before" and hit and status == "success":
                status = "cancelled"
                outcomes.append((role, "cancelled-before"))
                continue
            out = self.run_step(st, role, ctx, rep, attempt, gate, stub, where, how, push_digest, layers)
            outcomes.append((role, out))
            if st.get("id"):
                by_id[st["id"]] = out
            if out in ("failure", "cancelled") and status == "success" and not st.get("continue-on-error"):
                status = out
        if drain:
            self.drain()
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
                if self.upload_failures:
                    self.upload_failures -= 1
                    return "failure"   # nothing reached the artifact service
                if attempt in self.artifacts:
                    return "failure"   # an artifact name is never overwritten
                if rep.is_dir():
                    self.artifacts[attempt] = {p.name: p.read_bytes() for p in rep.iterdir()}
                return "success"
            return "success"   # sbom, cosign-install, other uploads, checkout
        run = st.get("run") or ""
        if role in ("other", "recheck", "augment", "mark-image"):
            return "success"
        env = self.env(attempt, stub)
        for key, val in (st.get("env") or {}).items():
            env[key] = fill(val, ctx)
        n_step = len(os.listdir(rep.parent))
        gh_out = rep.parent / f"out-{n_step}"
        env["GITHUB_OUTPUT"] = str(gh_out)
        env["GITHUB_STEP_SUMMARY"] = str(rep.parent / "summary.md")
        script = rep.parent / f"step-{n_step}.sh"
        script.write_text(run)
        log = rep.parent / f"log-{n_step}.txt"
        mark = Path(stub["STUB_HANG_MARK"])
        mark.unlink(missing_ok=True)
        # Output to a file, not a pipe: a process the step leaves behind must
        # not hold the rig up (the runner gives up on the pipe after 5 s).
        with open(log, "wb") as logf:
            p = subprocess.Popen(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)], cwd=self.root,
                                 env=env, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        self.pending.append(p.pid)   # its own process group, for the job-end cleanup
        cancelled = False
        deadline = time.monotonic() + 30
        while p.poll() is None and time.monotonic() < deadline:
            if mark.exists():
                # The runner's cancel, to the step's PID ONLY: SIGINT, SIGTERM
                # after a grace, then SIGKILL (scaled down from 7.5 s and 2.5 s).
                os.kill(p.pid, signal.SIGINT)
                try:
                    p.wait(timeout=SIGINT_GRACE)
                except subprocess.TimeoutExpired:
                    os.kill(p.pid, signal.SIGTERM)
                    try:
                        p.wait(timeout=SIGTERM_GRACE)
                    except subprocess.TimeoutExpired:
                        os.kill(p.pid, signal.SIGKILL)
                cancelled = True
                break
            time.sleep(0.01)
        if p.poll() is None:
            os.kill(p.pid, signal.SIGKILL)
        p.wait()
        self.last_output = log.read_text(errors="replace")
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
    mine = rig.digest(kind, attempt)
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
                "post-tag before tagged": "tagging", "complete": "tagged",
                "cancel mid-tag before tagging": "signed-attested", "mid-tag late create": "tagging",
                "tag raced": "tagging", "upload fails once": "tagged"}
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
                    if stop in ("mid-tag not applied", "cancel mid-tag before tagging", "mid-tag late create"):
                        # Nothing moved, and nothing moves later: the script
                        # stopped its own registry call on the cancel.
                        self.assertEqual(applied, [])
                    if stop == "post-tag before tagged":
                        self.assertEqual(applied, KINDS[kind]["tags"])
                    if stop in ("mid-push", "verify fail", "verify cancel"):
                        self.assertIn(mine, reg["manifests"])
                    if stop in ("cancel mid-tag before tagging", "mid-tag late create"):
                        log = "".join(p.read_text(errors="replace")
                                      for p in rig.tmp.glob(f"rt-{kind}-1/log-*.txt"))
                        self.assertRegex(log, r"stopped by SIG(INT|TERM); nothing further is recorded")
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


def cross_run_violations(release_text=None, scripts=None):
    """G8P6-chaos-injector-2: run A of the same tag is cancelled mid-tag (a
    tag move in flight that would complete later), and run B publishes on the
    same registry before A's job has ended. Nothing of A's may move a tag
    after B's `tagged`: every violation of either run's invariants, as text."""
    with tempfile.TemporaryDirectory(prefix="yuzu_test_publish_xr_") as ta, \
            tempfile.TemporaryDirectory(prefix="yuzu_test_publish_xr_") as tb:
        a = Rig(ta, release_text, scripts)
        b = Rig(tb, release_text, scripts, registry=a.reg, salt="run-78", run_id="78")
        a.run_job("buildx", 1, "pass", "mid-tag late create", drain=False)
        b.run_job("buildx", 1, "pass", "complete")
        a.drain()
        return ([f"run A: {v}" for v in violations(a, "buildx", 1, "pass", "mid-tag late create")]
                + [f"run B: {v}" for v in violations(b, "buildx", 1, "pass", "complete")])


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class CrossRun(unittest.TestCase):
    def test_a_cancelled_runs_tag_move_cannot_land_after_a_later_run(self):
        self.assertEqual(cross_run_violations(), [])


# ── Mutants ──────────────────────────────────────────────────────────────────
def _job_blocks(text, job):
    """(lines, blocks, roles) of one job in release.yml text: each step's line
    span (its leading comments belong to no block) and its step_key role."""
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
    return lines, blocks, roles


def swap_steps(text, job, a, b):
    """release.yml text with job's steps of roles a and b (first of each)
    swapped, every other byte unchanged."""
    lines, blocks, roles = _job_blocks(text, job)
    g = roles.index("gate")   # the publish steps are after the gate
    ia, ib = roles.index(a, g), roles.index(b, g)
    (sa, ea), (sb, eb) = sorted([blocks[ia], blocks[ib]])
    first, second = lines[sa:ea], lines[sb:eb]
    mid = lines[ea:sb]
    return "\n".join(lines[:sa] + second + mid + first + lines[eb:])


PUBLISH_ROLES = {
    "buildx": ["open", "push-started", "push", "verified", "sbom", "attest", "cosign-install", "sign",
               "signed-attested", "upload", "recheck", "tag", "upload-gate"],
    "bundle": ["open", "push-started", "push", "verified", "sbom", "upload", "attest", "sign", "signed-attested",
               "recheck", "tag", "upload-gate"],
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
                           ("bundle", "push-started", "push"),
                           ("buildx", "tag", "sign"),               # tags before the signature
                           ("bundle", "tag", "sign"),
                           ("buildx", "upload-gate", "tag"),        # evidence uploaded before the tags move
                           ("bundle", "upload-gate", "tag"),
                           ("buildx", "verified", "sign"),          # signed before verified
                           ("bundle", "verified", "sign")):
            with self.subTest(kind=kind, swap=(a, b)):
                mutant = swap_steps(text, KINDS[kind]["job"], a, b)
                self.assertIsNotNone(first_killing_row(kind, release_text=mutant), f"{kind}: {a}<->{b} survived")
        # The bundle's intent and push folded back into one step, the intent
        # after the push.
        old = ('          exec scripts/ci/image-publish.sh push-started "$RUNNER_TEMP/image-vuln-gate" "$NAME" '
               '"$GITHUB_RUN_ATTEMPT" "$candidate"\n')
        self.assertEqual(text.count(old), 1)
        moved = text.replace(old, '          docker push "$candidate"\n' + old.replace("exec ", ""))
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

    def test_cancellation_mutants_are_killed(self):
        # G8P6-chaos-injector-1/-2: the script must be the step's process
        # (exec), act on SIGINT/SIGTERM (trap), and run its registry calls so
        # the trap can stop them (background + wait); and after a signal it
        # appends nothing.
        src = (ROOT / "scripts" / "ci" / "image-publish.sh").read_text(encoding="utf-8")
        text = RELEASE.read_text(encoding="utf-8")
        traps = "        trap 'on_signal INT' INT\n        trap 'on_signal TERM' TERM\n"
        background = ('    if [ "$out" = - ]; then "$@" & else "$@" >"$out" & fi\n    CHILD=$!\n'
                      '    wait "$CHILD" || rc=$?\n')
        foreground = '    if [ "$out" = - ]; then "$@" || rc=$?; else "$@" >"$out" || rc=$?; fi\n'
        append_check = "    stop_if_signalled\n    printf 'publish: %s\\n'"
        for needle in (traps, background, append_check):
            self.assertEqual(src.count(needle), 1, needle)
        self.assertEqual(text.count("exec scripts/ci/image-publish.sh tag "), 4)
        mutants = {
            "the script ignores the signal": (None, {"image-publish.sh": src.replace(traps, "")}),
            "registry calls in the foreground": (None, {"image-publish.sh": src.replace(background, foreground)}),
            "the tag step without exec": (text.replace("exec scripts/ci/image-publish.sh tag ",
                                                       "scripts/ci/image-publish.sh tag "), None),
        }
        for label, (rt, sc) in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(cross_run_violations(rt, sc), [], f"{label} survived")
        with self.subTest(mutant="appends after the signal"), \
                tempfile.TemporaryDirectory(prefix="yuzu_test_publish_mut_") as t:
            rig = Rig(t, scripts={"image-publish.sh": src.replace(append_check, "    printf 'publish: %s\\n'")})
            rig.run_job("buildx", 1, "pass", "cancel mid-tag before tagging")
            self.assertNotEqual(rig.state("buildx", 1)[1].get("state"), "signed-attested", "survived")

    def test_journal_check_mutants_are_killed(self):
        # G8P6-quality-engineer-2: the reader's signed-attested and tagged
        # checks, and `tag`'s post-move resolve check.
        src = (ROOT / "scripts" / "ci" / "image-publish.sh").read_text(encoding="utf-8")
        e1 = ('                [ "$rest" = "$J_REPO@$J_DIGEST" ] \\\n'
              '                    || { J_WHY="signed-attested \'$rest\' is not the verified $J_REPO@$J_DIGEST"; return 1; } ;;\n')
        e2 = ('                [ "$rest" = "$J_TAGS $J_DIGEST" ] \\\n'
              '                    || { J_WHY="tagged \'$rest\' is not the tagging line\'s \'$J_TAGS $J_DIGEST\'"; return 1; } ;;\n')
        j = ('            [ "$RESOLVED" = "$J_DIGEST" ] || { err "$t names $RESOLVED, not $J_DIGEST; '
             'the journal stays at tagging"; exit 1; }\n')
        for needle in (e1, e2, j):
            self.assertEqual(src.count(needle), 1, needle)
        for label, mutant in (("signed-attested digest unchecked", src.replace(e1, "                ;;\n")),
                              ("tagged line unchecked", src.replace(e2, "                ;;\n"))):
            with self.subTest(mutant=label), tempfile.TemporaryDirectory(prefix="yuzu_test_publish_mut_") as t:
                p = Path(t) / "image-publish.sh"
                p.write_text(mutant)
                self.assertNotEqual(illegal_journals_accepted(p), [], f"{label} survived")
        with self.subTest(mutant="post-move resolve unchecked"):
            self.assertIsNotNone(first_killing_row("buildx", scripts={"image-publish.sh": src.replace(j, "")},
                                                   rows=[("pass", "tag raced")]))


# Journals that break only the one-digest / same-tags rule at a late line.
REPO = f"{OWNER_REPO}/yuzu-server"
D1, D2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64
GOOD = [f"publish: none", f"publish: push-started {REPO}", f"publish: verified {REPO}@{D1}",
        f"publish: signed-attested {REPO}@{D1}", f"publish: tagging {REPO}:1.2.3,{REPO}:latest {D1}",
        f"publish: tagged {REPO}:1.2.3,{REPO}:latest {D1}"]
ILLEGAL_LATE = {
    "signed-attested names another digest": GOOD[:3] + [f"publish: signed-attested {REPO}@{D2}"],
    "signed-attested names another repository": GOOD[:3] + [f"publish: signed-attested {OWNER_REPO}/x@{D1}"],
    "tagged names another digest": GOOD[:5] + [f"publish: tagged {REPO}:1.2.3,{REPO}:latest {D2}"],
    "tagged names other tags": GOOD[:5] + [f"publish: tagged {REPO}:1.2.3 {D1}"],
}


# ── The image SBOM edits: after signed-attested, before the upload and tags ──
# `augment` (yuzu-server's vendored components) and `mark-image` (the
# incomplete marker) rewrite the local image SBOM pair in place. They describe
# the digest `signed-attested` recorded, so they run after it; the upload
# sends what they wrote, and the tags move last, so both run before those.
# augment runs first: mark-image then marks the augmented pair. The journal
# rig above cannot see either step (neither touches the registry or the
# journal), so the order is pinned here, structurally, and each mutant below
# must be refused.
# No resume skips the syft scan: the journal is per attempt (`open` refuses an
# existing one) and gates no step, and a re-run runs the whole job again, so
# the SBOM steps rewrite the pair before augment reads it, or fail the job
# first. A pair that already lists any part of the vendored set (a stale file
# on a reused workspace) is refused by augment itself, not completed
# (tests/test_artifact_sbom.py: the second augment run and the partly
# augmented pair).
SBOM_EDIT_ORDER = {
    "docker-publish": ["signed-attested", "augment", "mark-image", "upload", "recheck", "tag"],
    "docker-publish-chisel": ["signed-attested", "augment", "mark-image", "upload", "recheck", "tag"],
    # No yuzu-server in the postgres image: no augment step.
    "docker-publish-postgres": ["signed-attested", "mark-image", "upload", "recheck", "tag"],
}


def sbom_edit_order_errors(text, job):
    """Why job's publish steps break SBOM_EDIT_ORDER (empty: they keep it)."""
    want = SBOM_EDIT_ORDER[job]
    _lines, _blocks, roles = _job_blocks(text, job)
    roles = roles[roles.index("gate"):]
    errs = [f"{job}: {r} appears {roles.count(r)} times, not once" for r in want if roles.count(r) != 1]
    if "augment" not in want and "augment" in roles:
        errs.append(f"{job}: runs augment, which this image does not take")
    if errs:
        return errs
    at = {r: roles.index(r) for r in want}
    return [f"{job}: {a} is not before {b}" for a, b in zip(want, want[1:]) if at[a] >= at[b]]


def move_step(text, job, role, anchor, after):
    """release.yml text with job's `role` step moved to just before (or after)
    its `anchor` step; every other byte unchanged."""
    lines, blocks, roles = _job_blocks(text, job)
    g = roles.index("gate")
    s, e = blocks[roles.index(role, g)]
    moved = lines[s:e]
    rest = lines[:s] + lines[e:]
    a_s, a_e = blocks[roles.index(anchor, g)]
    shift = (e - s) if a_s > s else 0
    at = (a_e if after else a_s) - shift
    return "\n".join(rest[:at] + moved + rest[at:])


class SbomEditOrder(unittest.TestCase):

    def test_the_workflow_keeps_the_order(self):
        text = RELEASE.read_text(encoding="utf-8")
        for job in SBOM_EDIT_ORDER:
            with self.subTest(job=job):
                self.assertEqual(sbom_edit_order_errors(text, job), [])

    def test_reorders_are_refused(self):
        text = RELEASE.read_text(encoding="utf-8")
        mutants = []
        for job in ("docker-publish", "docker-publish-chisel"):
            mutants += [
                (job, "augment before signed-attested", move_step(text, job, "augment", "signed-attested", False)),
                (job, "augment after the SBOM upload", move_step(text, job, "augment", "upload", True)),
                (job, "augment after the tag move", move_step(text, job, "augment", "tag", True)),
                (job, "mark-image before augment", swap_steps(text, job, "augment", "mark-image")),
            ]
        for job in SBOM_EDIT_ORDER:
            mutants += [
                (job, "mark-image before signed-attested",
                 move_step(text, job, "mark-image", "signed-attested", False)),
                (job, "mark-image after the SBOM upload", move_step(text, job, "mark-image", "upload", True)),
                (job, "mark-image after the tag move", move_step(text, job, "mark-image", "tag", True)),
            ]
        for job, label, mutant in mutants:
            with self.subTest(job=job, mutant=label):
                self.assertNotEqual(mutant, text)
                yaml.safe_load(mutant)   # still a workflow
                self.assertTrue(sbom_edit_order_errors(mutant, job), f"{job}: {label} survived")

    def test_a_dropped_or_added_augment_is_refused(self):
        text = RELEASE.read_text(encoding="utf-8")
        for job in ("docker-publish", "docker-publish-chisel"):
            lines, blocks, roles = _job_blocks(text, job)
            s, e = blocks[roles.index("augment", roles.index("gate"))]
            with self.subTest(job=job, mutant="dropped"):
                self.assertTrue(sbom_edit_order_errors("\n".join(lines[:s] + lines[e:]), job))
            with self.subTest(job=job, mutant="twice"):
                self.assertTrue(sbom_edit_order_errors("\n".join(lines[:e] + lines[s:e] + lines[e:]), job))
        # An augment step copied into the postgres job.
        lines, blocks, roles = _job_blocks(text, "docker-publish")
        s, e = blocks[roles.index("augment", roles.index("gate"))]
        step = lines[s:e]
        plines, pblocks, proles = _job_blocks(text, "docker-publish-postgres")
        ps, _pe = pblocks[proles.index("mark-image", proles.index("gate"))]
        self.assertTrue(sbom_edit_order_errors("\n".join(plines[:ps] + step + plines[ps:]),
                                               "docker-publish-postgres"))


def illegal_journals_accepted(script):
    """The ILLEGAL_LATE journals `state` accepts (it must refuse them all)."""
    accepted = []
    for label, lines in ILLEGAL_LATE.items():
        with tempfile.TemporaryDirectory(prefix="yuzu_test_publish_j_") as t:
            (Path(t) / "publish-yuzu-server.attempt-1.txt").write_text("".join(ln + "\n" for ln in lines))
            r = subprocess.run(["bash", str(script), "state", t, "yuzu-server", "1"], capture_output=True, text=True)
            if r.returncode == 0:
                accepted.append(label)
    return accepted


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class JournalReader(unittest.TestCase):
    def test_a_late_line_that_changes_the_digest_or_tags_is_refused(self):
        self.assertEqual(illegal_journals_accepted(ROOT / "scripts" / "ci" / "image-publish.sh"), [])
        with tempfile.TemporaryDirectory(prefix="yuzu_test_publish_j_") as t:
            (Path(t) / "publish-yuzu-server.attempt-1.txt").write_text("".join(ln + "\n" for ln in GOOD))
            r = subprocess.run(["bash", str(ROOT / "scripts" / "ci" / "image-publish.sh"), "state", t,
                                "yuzu-server", "1"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("state=tagged", r.stdout)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
