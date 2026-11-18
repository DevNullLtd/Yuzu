#!/usr/bin/env python3
"""scripts/ci/image-candidate-delete.sh: a leftover candidate digest is deleted
from GHCR only when no release tag names it, decided from the registry at
delete time (WP15/S9, G8P6-release-deploy-1).

A publish journal cannot decide it: one ending `tagging` may have moved a
release tag to its digest, and a `tagged` attempt whose gate artifact upload
failed has no journal at all. Deleting a GHCR version deletes every tag that
names it, so the script lists every tag (the packages API), resolves each one
that is not a `candidate-*` tag in the registry, and refuses any digest one of
them names, directly or as an index child.

Run against a stub `gh` (the packages API, `run list`, DELETE) and a stub
`docker` (`buildx imagetools inspect`) over one JSON state, with the real `jq`
applying the script's own `--jq` filters. Mutants on scratch copies must be
killed. Needs bash and jq; skips on Windows.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "image-candidate-delete.sh"


def dg(c):
    return "sha256:" + c * 64


D_REL, D_PREV, D_CAND, D_UNTAG, D_TAGGING, D_KID, D_IDX = (dg(c) for c in "abcdef0")

GH_STUB = textwrap.dedent(
    """\
    import json, os, subprocess, sys
    a = sys.argv[1:]
    p = os.environ["STUB_STATE"]
    st = json.load(open(p))
    with open(p + ".log", "a") as f:
        f.write(json.dumps(a) + "\\n")
    def opt(n):
        return a[a.index(n) + 1]
    if a[:2] == ["run", "list"]:
        if st.get("runs_fail"):
            sys.exit(1)
        runs = [{"status": s} for s in st.get("runs", [])]
        sys.stdout.write(subprocess.run(["jq", "-r", opt("--jq")], input=json.dumps(runs), text=True,
                                        capture_output=True, check=True).stdout)
        sys.exit(0)
    if a[0] == "api" and "-X" in a and opt("-X") == "DELETE":
        vid = int(a[-1].rsplit("/", 1)[1])
        st["versions"] = [v for v in st["versions"] if v["id"] != vid]
        st["deleted"].append(vid)
        json.dump(st, open(p, "w"))
        sys.exit(0)
    if a[0] == "api" and "/versions" in [x for x in a if x.startswith("/orgs/")][0]:
        st["lists"] = st.get("lists", 0) + 1
        mv = st.get("move_on_list")
        if mv and st["lists"] == mv["at"]:
            # A release moves a tag between the check and the re-check.
            for v in st["versions"]:
                v["tags"] = [t for t in v["tags"] if t != mv["tag"]]
                if v["name"] == mv["to"]:
                    v["tags"].append(mv["tag"])
            st["registry"][mv["tag"]] = mv["to"]
        json.dump(st, open(p, "w"))
        body = [{"id": v["id"], "name": v["name"],
                 "metadata": {"package_type": "container", "container": {"tags": v["tags"]}}}
                for v in st["versions"]]
        sys.stdout.write(subprocess.run(["jq", "-r", opt("--jq")], input=json.dumps(body), text=True,
                                        capture_output=True, check=True).stdout)
        sys.exit(0)
    sys.exit(2)
    """
)

DOCKER_STUB = textwrap.dedent(
    """\
    import json, os, sys
    a = sys.argv[1:]
    st = json.load(open(os.environ["STUB_STATE"]))
    if a[:3] != ["buildx", "imagetools", "inspect"]:
        sys.exit(2)
    ref = a[3]
    tag = ref.rsplit(":", 1)[1]
    live = {v["name"] for v in st["versions"]}
    d = st["registry"].get(tag)
    if d is None or d not in live or tag in st.get("unresolvable", []):
        sys.exit(1)
    if "--raw" in a:
        print(json.dumps(st.get("raw", {}).get(d, {"schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json"})))
    else:
        print(d)
    """
)


def base_state():
    versions = [
        {"id": 11, "name": D_REL, "tags": ["1.2.3", "1.2", "latest"]},
        {"id": 12, "name": D_PREV, "tags": ["1.2.2"]},
        {"id": 13, "name": D_CAND, "tags": ["candidate-77-1"]},
        {"id": 14, "name": D_UNTAG, "tags": []},
        {"id": 15, "name": D_TAGGING, "tags": ["candidate-77-2"]},
        {"id": 16, "name": D_KID, "tags": []},
        {"id": 17, "name": D_IDX, "tags": ["edge"]},
        {"id": 18, "name": dg("9"), "tags": [f"sha256-{'a' * 64}.sig"]},
    ]
    registry = {t: v["name"] for v in versions for t in v["tags"]}
    raw = {D_IDX: {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                   "manifests": [{"digest": D_KID, "mediaType": "application/vnd.oci.image.manifest.v1+json"}]}}
    return {"versions": versions, "registry": registry, "raw": raw, "deleted": [], "runs": ["completed"]}


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None or shutil.which("jq") is None,
                 "needs a POSIX bash and jq")
class CandidateDelete(unittest.TestCase):
    def run_script(self, args, state=None, script=None):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_candel_") as t:
            t = Path(t)
            (t / "bin").mkdir()
            for name, body in (("gh", GH_STUB), ("docker", DOCKER_STUB)):
                p = t / "bin" / name
                p.write_text(f"#!{sys.executable}\n" + body)
                p.chmod(0o755)
            sp = t / "state.json"
            sp.write_text(json.dumps(state or base_state()))
            sc = t / "script.sh"
            sc.write_text(script if script is not None else SCRIPT.read_text(encoding="utf-8"))
            env = {k: v for k, v in os.environ.items() if not k.startswith("STUB_")}
            env.update(PATH=f"{t / 'bin'}{os.pathsep}{env.get('PATH', '')}", STUB_STATE=str(sp))
            r = subprocess.run(["bash", str(sc), *args], env=env, capture_output=True, text=True, timeout=60)
            return r, json.loads(sp.read_text())

    def test_the_default_only_checks(self):
        r, st = self.run_script(["devnullltd", "yuzu-server", D_UNTAG, D_CAND])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nothing deleted", r.stdout)
        self.assertEqual(st["deleted"], [])

    def test_untagged_and_candidate_only_digests_are_deleted(self):
        r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", D_UNTAG, D_CAND])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(st["deleted"]), [13, 14])
        for tag in ("1.2.3", "1.2", "latest", "1.2.2", "edge"):
            self.assertIn(st["registry"][tag], {v["name"] for v in st["versions"]}, tag)

    def test_a_digest_a_release_tag_names_is_refused(self):
        # CH-1: a `tagging` attempt's digest that :1.2.3 now names (the
        # journal does not matter; the registry does), alongside its
        # candidate tag. Nothing is deleted, not even the deletable digest.
        st0 = base_state()
        st0["registry"]["1.2.3"] = D_TAGGING
        for v in st0["versions"]:
            v["tags"] = [t for t in v["tags"] if t != "1.2.3"] + (["1.2.3"] if v["name"] == D_TAGGING else [])
        for target in (D_TAGGING, D_REL, D_PREV, D_IDX):
            with self.subTest(target=target):
                r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", D_UNTAG, target], state=st0)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("named by a release tag", r.stderr)
                self.assertEqual(st["deleted"], [])

    def test_a_child_of_an_index_a_tag_names_is_refused(self):
        r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", D_KID])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(st["deleted"], [])

    def test_a_signature_referrer_tag_is_protected_too(self):
        r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", dg("9")])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(st["deleted"], [])

    def test_fails_closed(self):
        cases = {
            "api and registry disagree": lambda s: s["registry"].__setitem__("1.2.2", D_UNTAG),
            "a tag does not resolve": lambda s: s.__setitem__("unresolvable", ["1.2"]),
            "a release run is in progress": lambda s: s.__setitem__("runs", ["completed", "in_progress"]),
            "a release run is queued": lambda s: s.__setitem__("runs", ["queued"]),
            "the run list fails": lambda s: s.__setitem__("runs_fail", True),
            "the API lists nothing": lambda s: s.__setitem__("versions", []),
            "a duplicate version": lambda s: s["versions"].append({"id": 19, "name": D_UNTAG, "tags": []}),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                st0 = base_state()
                mutate(st0)
                r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", D_UNTAG], state=st0)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(st["deleted"], [])

    def test_unknown_or_malformed_digests(self):
        r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", dg("8")])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(st["deleted"], [])
        for bad in (["devnullltd", "yuzu-server", "sha256:abc"], ["DevNullLtd", "yuzu-server", D_UNTAG],
                    ["devnullltd", "yuzu-server"], ["devnullltd", "yuzu-server", ""]):
            with self.subTest(args=bad):
                r, st = self.run_script(["--delete", *bad])
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertEqual(st["deleted"], [])

    def test_a_tag_moved_after_the_check_is_seen_before_the_delete(self):
        st0 = base_state()
        st0["move_on_list"] = {"at": 2, "tag": "1.2.3", "to": D_UNTAG}
        r, st = self.run_script(["--delete", "devnullltd", "yuzu-server", D_UNTAG], state=st0)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("re-check", r.stderr)
        self.assertEqual(st["deleted"], [])

    def test_mutants_are_killed(self):
        src = SCRIPT.read_text(encoding="utf-8")
        needles = {
            "the release-tag check dropped": ('        if grep -qxF "$d" "$WORK/protected"; then',
                                              '        if false; then'),
            "index children not protected": ('        [ -z "$kids" ] || printf \'%s\\n\' "$kids" >>"$WORK/protected"\n', ""),
            "the API view trusted over the registry": ('        if [ "$got" != "$want" ]; then', "        if false; then"),
            "no re-check before each delete": ('    check "$d" >/dev/null || ', "    true || "),
            "deletes by default": ("DELETE=0\n", "DELETE=1\n"),
            "no in-progress run check": ('    [ "$n" = 0 ] || {', '    true || {'),
        }
        for label, (old, new) in needles.items():
            with self.subTest(mutant=label):
                self.assertEqual(src.count(old), 1, old)
                mutant = src.replace(old, new)
                killed = []
                for test in ("test_the_default_only_checks", "test_a_digest_a_release_tag_names_is_refused",
                             "test_a_child_of_an_index_a_tag_names_is_refused", "test_fails_closed",
                             "test_a_tag_moved_after_the_check_is_seen_before_the_delete"):
                    case = CandidateDelete(test)
                    orig = case.run_script
                    case.run_script = lambda args, state=None, script=None, orig=orig: orig(args, state, mutant)
                    res = unittest.TestResult()
                    case.run(res)
                    if res.failures or res.errors:
                        killed.append(test)
                self.assertTrue(killed, f"{label} survived")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
