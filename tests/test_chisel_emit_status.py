#!/usr/bin/env python3
"""deploy/docker/chisel-emit-status.py and its four call sites.

The script turns a chisel manifest into dpkg status.d records so Trivy and
grype can see the OS packages of a FROM-scratch image. Two kinds of test:

  - behaviour, on synthetic manifests: the stanza text, the Source lookup, and
    every refusal (a slice with no package, an archive record at another
    version, a status.d set that differs from the manifest);
  - wiring, lexical: each chiselled Dockerfile cuts base-files_chisel, copies the
    script, and runs it on the SAME slice list it cut, and the agent-bundle
    helper stages the script into its small build context. A Dockerfile that
    stopped calling the script would still build, and ship an image the
    scanners read as having no packages.

The real build (chisel cut, apt-cache, both scanners over the final image) is
not run here; it was run by hand and is recorded in the PR.
"""
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "deploy/docker/chisel-emit-status.py")

spec = importlib.util.spec_from_file_location("chisel_emit_status", SCRIPT)
ces = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ces)

MANIFEST = "\n".join([
    '{"jsonwall":"1.0","schema":"1.0","count":9}',
    '{"kind":"package","name":"busybox-static","version":"1:1.37.0-7ubuntu1","sha256":"aa","arch":"amd64"}',
    '{"kind":"package","name":"libssl3t64","version":"3.5.1-1ubuntu3","sha256":"bb","arch":"amd64"}',
    '{"kind":"path","path":"/etc/passwd"}',
])

SHOW = """Package: libssl3t64
Source: openssl-old
Version: 3.5.1-1ubuntu2
Architecture: amd64

Package: libssl3t64
Source: openssl
Version: 3.5.1-1ubuntu3
Architecture: amd64
Description: Secure Sockets Layer toolkit
 Source: not a field, a continuation line
"""


class Behaviour(unittest.TestCase):
    def test_manifest_keeps_only_packages(self):
        self.assertEqual(ces.parse_manifest(MANIFEST), {
            "busybox-static": ("1:1.37.0-7ubuntu1", "amd64"),
            "libssl3t64": ("3.5.1-1ubuntu3", "amd64")})

    def test_duplicate_package_is_refused(self):
        row = '{"kind":"package","name":"a","version":"1","arch":"amd64"}'
        with self.assertRaises(ValueError):
            ces.parse_manifest(row + "\n" + row)

    def test_source_is_taken_from_the_matching_version_only(self):
        self.assertEqual(ces.source_from_show(SHOW, "libssl3t64", "3.5.1-1ubuntu3"), "openssl")

    def test_continuation_line_is_not_a_field(self):
        text = "Package: p\nVersion: 1\n Source: not-this\n"
        self.assertEqual(ces.source_from_show(text, "p", "1"), "")

    def test_no_record_at_that_version_is_refused(self):
        with self.assertRaises(ValueError):
            ces.source_from_show(SHOW, "libssl3t64", "9.9")
        with self.assertRaises(ValueError):
            ces.source_from_show("", "libssl3t64", "3.5.1-1ubuntu3")

    def test_source_with_a_version_suffix_passes_through_verbatim(self):
        text = "Package: p\nSource: glibc (2.41-6ubuntu1)\nVersion: 2.41-6ubuntu1.1\n"
        self.assertEqual(ces.source_from_show(text, "p", "2.41-6ubuntu1.1"), "glibc (2.41-6ubuntu1)")

    def test_a_malformed_source_is_refused(self):
        for bad in ("a\nPackage: x", "../x", "a b c"):
            with self.subTest(source=bad):
                text = "Package: p\nSource: " + bad.split("\n")[0] + "\nVersion: 1\n"
                with self.assertRaises(ValueError):
                    ces.source_from_show(text, "p", "1")

    def test_malformed_manifest_rows_are_refused(self):
        def row(**kw):
            d = {"kind": "package", "name": "a", "version": "1", "arch": "amd64"}
            d.update(kw)
            return json.dumps(d)
        for bad in (row(name="../x"), row(name="a/b"), row(name="A"), row(version="1\nSource: x"),
                    row(version=""), row(arch="amd 64"), row(name=5),
                    '{"kind":"package","name":"a","version":"1"}'):
            with self.subTest(row=bad):
                with self.assertRaises(ValueError):
                    ces.parse_manifest(bad)
        self.assertEqual(ces.parse_manifest(row(name="libstdc++6", version="1:1.37.0-7ubuntu1~1", arch="all")),
                         {"libstdc++6": ("1:1.37.0-7ubuntu1~1", "all")})

    def test_stanza_text(self):
        self.assertEqual(
            ces.stanza("busybox-static", "1:1.37.0-7ubuntu1", "amd64", "busybox"),
            "Package: busybox-static\nStatus: install ok installed\n"
            "Architecture: amd64\nVersion: 1:1.37.0-7ubuntu1\nSource: busybox\n")
        self.assertNotIn("Source", ces.stanza("p", "1", "amd64", ""))

    def test_slice_packages(self):
        self.assertEqual(ces.slice_packages("libc6_libs  libstdc++6_libs\n base-files_base"),
                         {"libc6", "libstdc++6", "base-files"})
        with self.assertRaises(ValueError):
            ces.slice_packages("nounderscore")

    def test_check_sets(self):
        m = {"a": ("1", "amd64"), "b": ("1", "amd64")}
        self.assertEqual(ces.check_sets(m, {"a"}, ["a", "b"]), [])
        self.assertEqual(len(ces.check_sets(m, {"a", "c"}, ["a", "b"])), 1)
        self.assertEqual(len(ces.check_sets(m, {"a"}, ["a"])), 1)
        self.assertEqual(len(ces.check_sets(m, {"a"}, ["a", "b", "z"])), 1)


class Main(unittest.TestCase):
    def run_main(self, manifest, slices, source=lambda n, v: "src-" + n):
        saved = ces.read_manifest, ces.archive_source
        ces.read_manifest = lambda root: manifest
        ces.archive_source = source
        try:
            with tempfile.TemporaryDirectory() as root:
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    rc = ces.main(["--root", root, "--slices", slices])
                d = os.path.join(root, "var/lib/dpkg/status.d")
                files = sorted(os.listdir(d)) if os.path.isdir(d) else []
                text = {}
                for f in files:
                    with open(os.path.join(d, f)) as fh:
                        text[f] = fh.read()
                return rc, files, text, err.getvalue()
        finally:
            ces.read_manifest, ces.archive_source = saved

    def test_writes_one_record_per_manifest_package_including_dependencies(self):
        m = {"libpq5": ("18.1", "amd64"), "libldap2": ("2.6", "amd64")}  # libldap2 is not a slice
        rc, files, text, _ = self.run_main(m, "libpq5_libs")
        self.assertEqual((rc, files), (0, ["libldap2", "libpq5"]))
        self.assertIn("Source: src-libldap2", text["libldap2"])

    def test_a_slice_whose_package_is_not_in_the_manifest_fails(self):
        rc, _, _, err = self.run_main({"a": ("1", "amd64")}, "a_libs b_libs")
        self.assertEqual(rc, 1)
        self.assertIn("b is not in the chisel manifest", err)

    def test_an_archive_miss_fails(self):
        def miss(n, v):
            raise ValueError("no archive record for %s=%s" % (n, v))
        rc, _, _, err = self.run_main({"a": ("1", "amd64")}, "a_libs", miss)
        self.assertEqual(rc, 1)
        self.assertIn("no archive record", err)

    def test_a_missing_manifest_fails(self):
        with tempfile.TemporaryDirectory() as root:
            err = io.StringIO()
            with redirect_stderr(err):
                rc = ces.main(["--root", root, "--slices", "a_libs"])
        self.assertEqual(rc, 1)
        self.assertIn("base-files_chisel", err.getvalue())


class Subprocesses(unittest.TestCase):
    """read_manifest and archive_source against a real zstd file and a fake apt-cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_chisel_")
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "root")
        os.makedirs(os.path.join(self.root, "var/lib/chisel"))
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.bin)
        self.saved_path = os.environ["PATH"]
        self.addCleanup(lambda: os.environ.__setitem__("PATH", self.saved_path))

    def fake_apt_cache(self, body, rc=0):
        p = os.path.join(self.bin, "apt-cache")
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\ncat <<'EOF'\n%sEOF\nexit %d\n" % (body, rc))
        os.chmod(p, 0o755)
        os.environ["PATH"] = self.bin + os.pathsep + self.saved_path

    def write_manifest(self, raw):
        import shutil
        import subprocess
        if shutil.which("zstd") is None:
            self.skipTest("zstd is not installed")
        path = os.path.join(self.root, "var/lib/chisel/manifest.wall")
        subprocess.run(["zstd", "-q", "-o", path], input=raw, check=True)

    def test_read_manifest_decodes_a_real_zstd_file(self):
        self.write_manifest(MANIFEST.encode())
        self.assertEqual(ces.read_manifest(self.root)["libssl3t64"], ("3.5.1-1ubuntu3", "amd64"))

    def test_a_truncated_zstd_file_fails_the_run(self):
        self.write_manifest(MANIFEST.encode())
        path = os.path.join(self.root, "var/lib/chisel/manifest.wall")
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(data[:len(data) // 2])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(ces.main(["--root", self.root, "--slices", "libssl3t64_libs"]), 1)

    def test_archive_source_reads_the_matching_record(self):
        self.fake_apt_cache(SHOW)
        self.assertEqual(ces.archive_source("libssl3t64", "3.5.1-1ubuntu3"), "openssl")

    def test_apt_cache_failure_with_no_output_is_an_archive_miss(self):
        self.fake_apt_cache("", rc=100)
        with self.assertRaises(ValueError):
            ces.archive_source("libssl3t64", "3.5.1-1ubuntu3")

    def test_the_whole_run_over_real_wrappers(self):
        self.write_manifest(MANIFEST.encode())
        self.fake_apt_cache(SHOW + "\nPackage: busybox-static\nSource: busybox\nVersion: 1:1.37.0-7ubuntu1\n")
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ces.main(["--root", self.root, "--slices", "libssl3t64_libs busybox-static_bins"])
        self.assertEqual(rc, 0)
        with open(os.path.join(self.root, "var/lib/dpkg/status.d/busybox-static")) as fh:
            self.assertIn("Source: busybox\n", fh.read())


class Wiring(unittest.TestCase):
    DOCKERFILES = ["server", "agent", "gateway", "agent-bundle"]

    def text(self, rel):
        with open(os.path.join(ROOT, rel)) as fh:
            return fh.read()

    def test_each_dockerfile_cuts_the_manifest_and_runs_the_script_on_its_slices(self):
        for n in self.DOCKERFILES:
            with self.subTest(dockerfile=n):
                s = self.text("deploy/docker/Dockerfile.%s.chisel" % n)
                cut = re.search(r'SLICES="([^"]*)"', s)
                self.assertIsNotNone(cut)
                self.assertIn("base-files_chisel", cut.group(1).split())
                self.assertIn('chisel cut --release "${CHISEL_RELEASE}" --root /rootfs ${SLICES}', s)
                call = 'python3 /usr/local/bin/chisel-emit-status.py --root /rootfs --slices "${SLICES}"'
                self.assertIn(call, s)
                # the call comes after the cut, in the same RUN (SLICES is a shell variable)
                self.assertLess(s.index("chisel cut --release"), s.index(call))
                start = s.rindex("RUN set -eux; mkdir -p /rootfs;", 0, s.index(call))
                end = s.index("\n\n", s.index(call))
                run = "\n".join(l for l in s[start:end].split("\n") if not l.lstrip().startswith("#"))
                self.assertIn("SLICES=", run)
                self.assertIn(call, run)  # not commented out
                # cut, index refresh and emit are ONE conditional list inside the retry loop, so a
                # transient failure of any of them retries the lot, and nothing after it is `|| true`
                chain = re.search(r"if (chisel cut[^;]*?)\s*&&\s*apt-get update -qq\s*&&\s*(python3 [^;]*?); then ok=1",
                                  re.sub(r"\\\n\s*", " ", run))
                self.assertIsNotNone(chain, "cut && apt-get update && emit must be one if-condition")
                self.assertNotIn("||", run)
                self.assertRegex(run, r'\[ "\$ok" = 1 \]')
                self.assertLess(run.index("[ \"$ok\" = 1 ]"), run.index("rm -rf /var/lib/apt/lists"))
                self.assertRegex(s, r"ca-certificates python3 zstd")
                self.assertRegex(s, r"COPY \S*chisel-emit-status\.py /usr/local/bin/chisel-emit-status\.py")

    def test_the_bundle_helper_stages_the_script_into_its_build_context(self):
        s = self.text("scripts/build-agent-bundle.sh")
        self.assertIn('cp deploy/docker/chisel-emit-status.py "$STAGING/chisel-emit-status.py"', s)
        self.assertIn("COPY chisel-emit-status.py ", self.text("deploy/docker/Dockerfile.agent-bundle.chisel"))


if __name__ == "__main__":
    unittest.main()
