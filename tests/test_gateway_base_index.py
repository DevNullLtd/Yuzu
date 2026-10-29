#!/usr/bin/env python3
"""Tests for scripts/ci/check-gateway-base-index.py and the Dockerfile.gateway contract it reads (#6711).

Hermetic: fixture indexes, no registry, no Docker. The networked run lives in
.github/workflows/docker-healthcheck-invariants.yml.
"""

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "check-gateway-base-index.py"
DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile.gateway"

spec = importlib.util.spec_from_file_location("check_gateway_base_index", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def entry(arch, base=None, os_="linux"):
    e = {"platform": {"os": os_, "architecture": arch}}
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


class DockerfileContractTests(unittest.TestCase):
    """The real Dockerfile must stay parseable by the lint and carry the early arch refusal."""

    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text()

    def test_lint_can_parse_the_real_dockerfile(self):
        supported, builder, runtime = mod.parse_dockerfile(self.text)
        self.assertTrue(supported)
        self.assertEqual(builder["repo"], "erlang")
        self.assertRegex(runtime, r"^[0-9]+\.[0-9]+$")

    def test_arch_guard_allows_exactly_the_marker_platforms(self):
        supported, _, _ = mod.parse_dockerfile(self.text)
        m = re.search(r'RUN case "\$\{TARGETARCH:-amd64\}" in ([a-z0-9|]+\)) ;; \*\)', self.text)
        self.assertIsNotNone(m, "the deps stage's TARGETARCH guard is missing or reshaped")
        allowed = {f"linux/{a}" for a in m.group(1).rstrip(")").split("|")}
        self.assertEqual(allowed, set(supported))

    def test_arch_guard_precedes_any_other_run_in_the_deps_stage(self):
        stage = self.text.split("AS deps", 1)[1].split("FROM deps AS builder", 1)[0]
        runs = [ln for ln in stage.splitlines() if ln.startswith("RUN ")]
        self.assertTrue(runs[0].startswith('RUN case "${TARGETARCH:-amd64}"'), runs[0])


if __name__ == "__main__":
    unittest.main(verbosity=1)
