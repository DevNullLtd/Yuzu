#!/usr/bin/env python3
"""Tests for scripts/ci/check-gateway-base-index.py and the Dockerfile.gateway contract it reads (#6711).

Hermetic: fixture indexes, no registry, no Docker. The networked run lives in
.github/workflows/docker-healthcheck-invariants.yml.

The arch guard in the deps stage is EXECUTED here (its real RUN text, continuations
joined, under `sh`), the way test_gateway_abi_guard.py runs the abi-guard: a test that
only matched the guard's text stayed green when `exit 1` became `exit 0` or when
`ARG TARGETARCH` was deleted.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "check-gateway-base-index.py"
DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile.gateway"

spec = importlib.util.spec_from_file_location("check_gateway_base_index", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

HAVE_SH = os.name != "nt" and shutil.which("sh") is not None


def entry(arch, base=None, os_="linux", variant=None):
    e = {"platform": {"os": os_, "architecture": arch}}
    if variant:
        e["platform"]["variant"] = variant
    if base is not None:
        e["annotations"] = {mod.BASE_NAME_KEY: base}
    return e


MIXED = {  # the shape #6711 was filed against
    "manifests": [
        entry("amd64", "alpine:3.23"),
        entry("unknown", None, os_="unknown"),  # attestation manifest
        entry("arm64", "alpine:3.24"),
        entry("s390x", "alpine:3.24"),
    ]
}
AGREE = {"manifests": [entry("amd64", "alpine:3.23"), entry("arm64", "alpine:3.23")]}


class CheckTests(unittest.TestCase):
    def test_unsupported_divergent_platform_is_a_note_not_a_failure(self):
        failures, notes = mod.check(MIXED, ["linux/amd64"], "3.23")
        self.assertEqual(failures, [])
        self.assertTrue(any("linux/arm64" in n and "3.24" in n for n in notes))

    def test_supported_divergent_platform_fails(self):
        failures, _ = mod.check(MIXED, ["linux/amd64", "linux/arm64"], "3.23")
        self.assertEqual(len(failures), 1)
        self.assertIn("linux/arm64", failures[0])

    def test_all_supported_agree_passes(self):
        self.assertEqual(mod.check(AGREE, ["linux/amd64", "linux/arm64"], "3.23")[0], [])

    def test_runtime_tag_differs_fails(self):
        failures, _ = mod.check(AGREE, ["linux/amd64"], "3.24")
        self.assertEqual(len(failures), 1)

    def test_missing_annotation_fails_closed(self):
        idx = {"manifests": [entry("amd64", None)]}
        self.assertEqual(len(mod.check(idx, ["linux/amd64"], "3.23")[0]), 1)

    def test_unreadable_annotation_fails_closed(self):
        for bad in ("scratch", "debian:12", "alpine:edge", "alpine:3"):
            with self.subTest(base=bad):
                idx = {"manifests": [entry("amd64", bad)]}
                self.assertEqual(len(mod.check(idx, ["linux/amd64"], "3.23")[0]), 1)

    def test_patch_level_annotation_is_reduced_to_the_release(self):
        idx = {"manifests": [entry("amd64", "alpine:3.23.6")]}
        self.assertEqual(mod.check(idx, ["linux/amd64"], "3.23")[0], [])

    def test_supported_platform_absent_from_index_fails(self):
        self.assertEqual(len(mod.check(AGREE, ["linux/riscv64"], "3.23")[0]), 1)

    def test_empty_supported_list_fails(self):
        self.assertEqual(len(mod.check(AGREE, [], "3.23")[0]), 1)

    def test_attestation_manifest_does_not_count_as_a_platform(self):
        idx = {"manifests": [entry("amd64", "alpine:3.23"), entry("unknown", "alpine:3.99", os_="unknown")]}
        failures, notes = mod.check(idx, ["linux/amd64"], "3.23")
        self.assertEqual((failures, notes), ([], []))

    def test_every_entry_for_a_supported_platform_is_checked(self):
        idx = {"manifests": [entry("amd64", "alpine:3.23"), entry("amd64", "alpine:3.24", variant="v2")]}
        failures, _ = mod.check(idx, ["linux/amd64"], "3.23")
        self.assertEqual(len(failures), 1)
        self.assertIn("3.24", failures[0])

    def test_single_manifest_digest_is_an_input_defect_not_a_missing_platform(self):
        single = {"schemaVersion": 2, "config": {}, "layers": []}
        with self.assertRaisesRegex(mod.InputDefect, "image index"):
            mod.check(single, ["linux/amd64"], "3.23")

    def test_mis_shaped_entries_are_input_defects_not_tracebacks(self):
        bad = (
            {"manifests": None},
            {"manifests": ["x"]},
            {"manifests": [{"platform": None}]},
            {"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "annotations": []}]},
            [],
        )
        for idx in bad:
            with self.subTest(idx=idx), self.assertRaises(mod.InputDefect):
                mod.check(idx, ["linux/amd64"], "3.23")


class MainTests(unittest.TestCase):
    """main() exit codes through the hermetic --index-file path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_gwindex_")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def run_main(self, dockerfile_text, index):
        df = self.dir / "Dockerfile"
        df.write_text(dockerfile_text, encoding="utf-8")
        argv = ["--dockerfile", str(df)]
        if index is not None:
            idx = self.dir / "index.json"
            idx.write_text(index if isinstance(index, str) else json.dumps(index), encoding="utf-8")
            argv += ["--index-file", str(idx)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(argv)
        return rc, out.getvalue(), err.getvalue()

    GOOD = (
        "# yuzu:gateway-platforms linux/amd64\n"
        "FROM erlang:28-alpine@sha256:" + "a" * 64 + " AS deps\n"
        "FROM alpine:3.23@sha256:" + "b" * 64 + "\n"
    )

    def test_consistent_is_0(self):
        rc, out, _ = self.run_main(self.GOOD, MIXED)
        self.assertEqual(rc, 0)
        self.assertIn("supported=linux/amd64", out)

    def test_mismatch_is_1(self):
        rc, _, err = self.run_main(self.GOOD.replace("linux/amd64", "linux/amd64 linux/arm64"), MIXED)
        self.assertEqual(rc, 1)
        self.assertIn("linux/arm64", err)

    def test_input_defects_are_3_not_1(self):
        cases = {
            "no marker": self.GOOD.replace("# yuzu:gateway-platforms linux/amd64\n", ""),
            "two runtimes": self.GOOD + "FROM alpine:3.23\n",
            "no builder": self.GOOD.replace(" AS deps", " AS other"),
        }
        for name, text in cases.items():
            with self.subTest(name), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.run_main(text, MIXED)[0], 3)

    def test_non_index_and_bad_json_are_3(self):
        self.assertEqual(self.run_main(self.GOOD, {"layers": []})[0], 3)
        self.assertEqual(self.run_main(self.GOOD, "{not json")[0], 3)

    def test_builder_stage_name_is_case_insensitive(self):
        rc, _, _ = self.run_main(self.GOOD.replace(" AS deps", " as deps"), MIXED)
        self.assertEqual(rc, 0)

    def test_missing_index_file_is_3(self):
        df = self.dir / "Dockerfile"
        df.write_text(self.GOOD, encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            rc = mod.main(["--dockerfile", str(df), "--index-file", str(self.dir / "absent.json")])
        self.assertEqual(rc, 3)


class FetchTests(unittest.TestCase):
    """fetch_index with the network replaced: digest verification and retry policy."""

    def setUp(self):
        self._get = mod._get
        self._sleep = mod.time.sleep
        mod.time.sleep = lambda s: None
        self.addCleanup(lambda: (setattr(mod, "_get", self._get), setattr(mod.time, "sleep", self._sleep)))

    def test_body_not_matching_the_pinned_digest_is_a_registry_error(self):
        body = json.dumps(AGREE).encode()
        mod._get = lambda url, headers, attempts=4: b'{"token": "t"}' if "auth.docker.io" in url else body
        with self.assertRaisesRegex(mod.RegistryError, "not the pinned"):
            mod.fetch_index("erlang", "sha256:" + "0" * 64)

    def test_body_matching_the_pinned_digest_is_returned(self):
        body = json.dumps(AGREE).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        mod._get = lambda url, headers, attempts=4: b'{"token": "t"}' if "auth.docker.io" in url else body
        self.assertEqual(mod.fetch_index("erlang", digest), AGREE)

    def test_retries_then_gives_up_on_server_errors(self):
        calls = []
        orig = mod.urllib.request.urlopen

        def boom(req, timeout=0):
            calls.append(1)
            raise mod.urllib.error.HTTPError(req.full_url, 503, "unavailable", {}, None)

        mod.urllib.request.urlopen = boom
        self.addCleanup(lambda: setattr(mod.urllib.request, "urlopen", orig))
        with self.assertRaises(mod.RegistryError):
            mod._get("https://example.invalid/x", {})
        self.assertEqual(len(calls), len(mod.RETRY_DELAYS) + 1)

    def test_does_not_retry_a_client_error(self):
        calls = []
        orig = mod.urllib.request.urlopen

        def nf(req, timeout=0):
            calls.append(1)
            raise mod.urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)

        mod.urllib.request.urlopen = nf
        self.addCleanup(lambda: setattr(mod.urllib.request, "urlopen", orig))
        with self.assertRaises(mod.RegistryError):
            mod._get("https://example.invalid/x", {})
        self.assertEqual(len(calls), 1)


class DockerfileContractTests(unittest.TestCase):
    """The real Dockerfile must stay parseable by the lint, and its arch guard must REFUSE."""

    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text(encoding="utf-8")

    def guard_body(self):
        """The guard RUN's shell text, continuations joined (as Docker does)."""
        m = re.search(r'^RUN (case "\$\{TARGETARCH:-amd64\}" in .*?exit 1;; esac)$',
                      self.text, re.M | re.S)
        self.assertIsNotNone(m, "the deps stage's TARGETARCH guard is missing or reshaped")
        return re.sub(r"\\\n", " ", m.group(1))

    def run_guard(self, **env):
        return subprocess.run(["sh", "-c", self.guard_body()], env={"PATH": os.environ["PATH"], **env},
                              capture_output=True, text=True)

    def test_lint_can_parse_the_real_dockerfile(self):
        supported, builder, runtime = mod.parse_dockerfile(self.text)
        self.assertTrue(supported)
        self.assertEqual(builder["repo"], "erlang")
        self.assertRegex(runtime, r"^[0-9]+\.[0-9]+$")

    @unittest.skipUnless(HAVE_SH, "needs a POSIX sh")
    def test_guard_admits_exactly_the_marker_platforms_and_refuses_the_rest(self):
        supported, _, _ = mod.parse_dockerfile(self.text)
        for plat in supported:
            with self.subTest(admit=plat):
                self.assertEqual(self.run_guard(TARGETARCH=plat.split("/", 1)[1]).returncode, 0)
        for arch in ("arm64", "s390x", "ppc64le", "386", "arm"):
            if f"linux/{arch}" in supported:
                continue
            with self.subTest(refuse=arch):
                r = self.run_guard(TARGETARCH=arch)
                self.assertEqual(r.returncode, 1)
                self.assertIn("FATAL", r.stdout + r.stderr)
                self.assertIn("6711", r.stdout + r.stderr)

    @unittest.skipUnless(HAVE_SH, "needs a POSIX sh")
    def test_guard_treats_an_unset_targetarch_as_amd64_by_design(self):
        # A builder that does not set TARGETARCH cannot be told apart from amd64 here; the abi-guard is
        # the backstop for that case (stated in the Dockerfile header). Pinned so a change is deliberate.
        self.assertEqual(self.run_guard().returncode, 0)
        self.assertEqual(self.run_guard(TARGETARCH="").returncode, 0)

    def test_arg_targetarch_is_declared_in_the_deps_stage_before_the_guard(self):
        deps = self.text.split(" AS deps", 1)[1].split("FROM deps AS builder", 1)[0]
        self.assertRegex(deps, r"(?m)^ARG TARGETARCH$")
        self.assertLess(deps.index("ARG TARGETARCH"), deps.index('RUN case "${TARGETARCH:-amd64}"'),
                        "without ARG in the stage the variable is always empty and the guard never refuses")

    def test_arch_guard_is_the_first_run_of_the_deps_stage(self):
        stage = self.text.split(" AS deps", 1)[1].split("FROM deps AS builder", 1)[0]
        runs = [ln for ln in stage.splitlines() if ln.startswith("RUN ")]
        self.assertTrue(runs[0].startswith('RUN case "${TARGETARCH:-amd64}"'), runs[0])


if __name__ == "__main__":
    unittest.main(verbosity=1)
