#!/usr/bin/env python3
"""Regression net for scripts/ci/artifact-sbom.py (supply-chain item S8).

The release SBOMs used to be a syft scan of the whole checkout: 40,853
components on v0.15.0, almost all the vcpkg ports catalogue, and none of the
C++ libraries the static binaries link. The script now describes one artifact
at a time. These tests pin what that means:

  - the vcpkg closure is the agent's (vcpkg.json core dependencies) or the
    server's (plus the `server` feature), never the test-only ports, the
    `vcpkg-*` helpers or a host-triplet build tool, and a port the manifest
    needs but the tree lacks fails instead of being dropped;
  - a generated SBOM pair names the artifact, records its SHA-256, carries the
    ports with an upstream purl (and a CPE where NVD has one), and a Hex
    package gets a pkg:hex purl;
  - an artifact holding a Yuzu binary with no vcpkg tree given fails, as does
    a tarball member that escapes the extraction directory;
  - `check` refuses an SBOM over the entry bound, one listing a path under
    vcpkg/, tests/ or _build_*, and one whose SHA-256 or name does not match
    its artifact, and skips the image SBOMs.

syft is replaced by a small stub that reports the Erlang applications it finds,
so the test needs no network and no syft. Stdlib only; skips on Windows (the
stub is a #! script).
"""

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "artifact-sbom.py"
TRIPLET = "x64-linux-static"

STUB_SYFT = textwrap.dedent('''\
    #!PYTHON
    """Stand-in for `syft scan dir:X --source-name N --source-version V -o fmt=path ...`."""
    import json, os, sys
    args = sys.argv[1:]
    root = args[args.index("scan") + 1][len("dir:"):]
    name = args[args.index("--source-name") + 1]
    version = args[args.index("--source-version") + 1]
    outs = dict(a.split("=", 1) for a in (args[i + 1] for i, x in enumerate(args) if x == "-o"))
    comps, pkgs, rels = [], [], []
    extra = os.environ.get("STUB_SYFT_EXTRA_PATH")
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            rel = "/" + os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")
            if f.endswith(".app") and "/ebin/" in rel:
                app, vsn = rel.split("/")[-3].rsplit("-", 1)
                comps.append({"bom-ref": app, "type": "library", "name": app, "version": vsn,
                              "purl": f"pkg:otp/{app}@{vsn}",
                              "properties": [{"name": "syft:location:0:path", "value": rel}]})
                pkgs.append({"name": app, "SPDXID": f"SPDXRef-Package-{app}", "versionInfo": vsn,
                             "downloadLocation": "NOASSERTION", "sourceInfo": f"from file: {rel}",
                             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                               "referenceType": "purl",
                                               "referenceLocator": f"pkg:otp/{app}@{vsn}"}]})
    if extra:
        comps.append({"bom-ref": "x", "type": "library", "name": "x", "version": "1",
                      "properties": [{"name": "syft:location:0:path", "value": extra}]})
    root_id = "SPDXRef-DocumentRoot-Directory-" + name
    for p in pkgs:
        rels.append({"spdxElementId": root_id, "relationshipType": "CONTAINS", "relatedSpdxElement": p["SPDXID"]})
    rels.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id})
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"component": {"bom-ref": "root", "type": "file", "name": name, "version": version}},
           "components": comps}
    spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
            "packages": [{"name": name, "SPDXID": root_id, "versionInfo": version,
                          "downloadLocation": "NOASSERTION"}] + pkgs,
            "files": [], "relationships": rels}
    json.dump(cdx, open(outs["cyclonedx-json"], "w"))
    json.dump(spdx, open(outs["spdx-json"], "w"))
''').replace("PYTHON", sys.executable)

MANIFEST = {
    "name": "yuzu",
    "dependencies": [{"name": "grpc", "features": ["codegen"]}, "openssl", "zlib"],
    "default-features": ["server", "tests"],
    "features": {
        "server": {"dependencies": [{"name": "libpq", "default-features": False}]},
        "tests": {"dependencies": [{"name": "catch2", "platform": "x64 | arm64"}]},
    },
}

# vcpkg's status file for a static release triplet whose host triplet differs:
# host tools are recorded as name:x64-linux. A helper port with no suffix (as
# on Windows/macOS, where host and target triplet are the same) is still a
# build helper. One purged entry must be ignored.
STATUS = textwrap.dedent(f"""\
    Package: vcpkg-cmake
    Version: 2025-08-07
    Architecture: x64-linux
    Status: install ok installed

    Package: abseil
    Version: 20260107.1
    Port-Version: 3
    Depends: vcpkg-cmake:x64-linux
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: protobuf
    Version: 6.33.4
    Port-Version: 2
    Depends: abseil, vcpkg-cmake:x64-linux, protoc-tool:x64-linux
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: vcpkg-cmake-get-vars
    Version: 2025-05-29
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: openssl
    Version: 3.6.5
    Port-Version: 2
    Depends: vcpkg-cmake:x64-linux, vcpkg-cmake-get-vars
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: zlib
    Version: 1.3.2
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: grpc
    Version: 1.81.1
    Depends: abseil, openssl, zlib, vcpkg-cmake:x64-linux
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: grpc
    Feature: codegen
    Depends: protobuf
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: libpq
    Version: 18.4
    Port-Version: 1
    Depends: vcpkg-tool-meson:x64-linux
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: libpq
    Feature: openssl
    Depends: openssl
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: catch2
    Version: 3.16.0
    Architecture: {TRIPLET}
    Status: install ok installed

    Package: oldport
    Version: 1.0
    Architecture: {TRIPLET}
    Status: purge ok not-installed
""")

UPSTREAM = {
    "abseil": ("Apache-2.0", "git+https://github.com/abseil/abseil-cpp@20260107.1"),
    "protobuf": ("BSD-3-Clause", "git+https://github.com/protocolbuffers/protobuf@v33.4"),
    "openssl": ("Apache-2.0", "git+https://github.com/openssl/openssl@openssl-3.6.5"),
    "zlib": ("Zlib", "git+https://github.com/madler/zlib@v1.3.2"),
    "grpc": ("Apache-2.0", "git+https://github.com/grpc/grpc@v1.81.1"),
    "libpq": ("PostgreSQL", "https://ftp.postgresql.org/pub/source/v18.4/postgresql-18.4.tar.bz2"),
    "catch2": ("BSL-1.0", "git+https://github.com/catchorg/Catch2@v3.16.0"),
}

AGENT_PORTS = ["abseil", "grpc", "openssl", "protobuf", "zlib"]
SERVER_PORTS = sorted(AGENT_PORTS + ["libpq"])


def make_vcpkg_tree(root: Path, drop_spdx: str = "") -> Path:
    inst = root / "vcpkg_installed"
    (inst / "vcpkg").mkdir(parents=True)
    (inst / "vcpkg" / "status").write_text(STATUS)
    for port, (lic, loc) in UPSTREAM.items():
        if port == drop_spdx:
            continue
        share = inst / TRIPLET / "share" / port
        share.mkdir(parents=True)
        spdx = {"packages": [
            {"SPDXID": "SPDXRef-port", "name": port, "licenseConcluded": lic,
             "homepage": f"https://example.invalid/{port}",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:vcpkg/{port}@x"}]},
            {"SPDXID": "SPDXRef-resource-0", "name": f"{port}-src", "downloadLocation": loc},
        ]}
        (share / "vcpkg.spdx.json").write_text(json.dumps(spdx))
    (root / "vcpkg.json").write_text(json.dumps(MANIFEST))
    return inst


def make_tar(path: Path, files: dict) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


@unittest.skipIf(os.name == "nt", "the syft stub is a #! script")
class ArtifactSbom(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_sbom_"))
        self.syft = self.tmp / "syft"
        self.syft.write_text(STUB_SYFT)
        self.syft.chmod(self.syft.stat().st_mode | stat.S_IXUSR)
        self.out = self.tmp / "out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *args, env=None):
        e = dict(os.environ, **(env or {}))
        return subprocess.run([sys.executable, "-I", str(SCRIPT)] + [str(a) for a in args],
                              capture_output=True, text=True, env=e)

    def generate(self, artifact: Path, vcpkg=True, extra=(), env=None):
        args = ["generate", "--syft", self.syft, "--artifact", artifact, "--version", "1.2.3",
                "--out-dir", self.out]
        if vcpkg:
            args += ["--vcpkg-installed", self.tmp / "vcpkg_installed", "--triplet", TRIPLET,
                     "--manifest", self.tmp / "vcpkg.json"]
        return self.run_script(*args, *extra, env=env)

    def vcpkg_names(self, cdx):
        return sorted(c["name"] for c in cdx["components"]
                      if any(p["name"] == "yuzu:vcpkg:port" for p in c.get("properties", [])))

    # ── generate ──
    def test_agent_archive(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-agent-macos-arm64.tar.gz",
                       {"yuzu-agent-1.2.3/bin/yuzu-agent": b"\x7fELF", "yuzu-agent-1.2.3/bin/README": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx = json.loads((self.out / "yuzu-agent-macos-arm64.cdx.json").read_text())
        spdx = json.loads((self.out / "yuzu-agent-macos-arm64.spdx.json").read_text())
        sha = hashlib.sha256(art.read_bytes()).hexdigest()
        root = cdx["metadata"]["component"]
        self.assertEqual((root["name"], root["version"]), (art.name, "1.2.3"))
        self.assertEqual(root["hashes"], [{"alg": "SHA-256", "content": sha}])
        # Agent closure only: no server port, no test port, no helper or host tool.
        self.assertEqual(self.vcpkg_names(cdx), AGENT_PORTS)
        by = {c["name"]: c for c in cdx["components"]}
        self.assertEqual(by["openssl"]["version"], "3.6.5")
        self.assertEqual(by["openssl"]["purl"], "pkg:github/openssl/openssl@openssl-3.6.5")
        self.assertEqual(by["openssl"]["cpe"], "cpe:2.3:a:openssl:openssl:3.6.5:*:*:*:*:*:*:*")
        self.assertEqual(by["openssl"]["licenses"], [{"expression": "Apache-2.0"}])
        # SPDX: same ports, contained by the described root, which carries the hash.
        names = sorted(p["name"] for p in spdx["packages"] if p["SPDXID"].startswith("SPDXRef-Package-vcpkg-"))
        self.assertEqual(names, AGENT_PORTS)
        root_pkg = next(p for p in spdx["packages"] if p["SPDXID"].startswith("SPDXRef-DocumentRoot"))
        self.assertEqual(root_pkg["checksums"], [{"algorithm": "SHA256", "checksumValue": sha}])
        contained = {r["relatedSpdxElement"] for r in spdx["relationships"]
                     if r["spdxElementId"] == root_pkg["SPDXID"] and r["relationshipType"] == "CONTAINS"}
        self.assertTrue({f"SPDXRef-Package-vcpkg-{n}" for n in AGENT_PORTS} <= contained)

    def test_server_package_adds_server_feature(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz",
                       {"y/bin/yuzu-server": b"x", "y/bin/libyuzu_agent_core.so": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx = json.loads((self.out / "yuzu-linux-x64.cdx.json").read_text())
        self.assertEqual(self.vcpkg_names(cdx), SERVER_PORTS)
        libpq = next(c for c in cdx["components"] if c["name"] == "libpq")
        self.assertTrue(libpq["purl"].startswith("pkg:generic/libpq@18.4?download_url="), libpq["purl"])

    def test_hex_purl_for_gateway(self):
        lock = self.tmp / "rebar.lock"
        lock.write_text('{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.19.0">>},0}]}.\n')
        art = make_tar(self.tmp / "yuzu-gateway-linux-x64.tar.gz",
                       {"g/lib/cowboy-2.19.0/ebin/cowboy.app": b"x", "g/lib/kernel-10.6/ebin/kernel.app": b"x"})
        r = self.generate(art, vcpkg=False, extra=("--rebar-lock", lock))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx = json.loads((self.out / "yuzu-gateway-linux-x64.cdx.json").read_text())
        purls = {c["name"]: c["purl"] for c in cdx["components"]}
        self.assertEqual(purls, {"cowboy": "pkg:hex/cowboy@2.19.0", "kernel": "pkg:otp/kernel@10.6"})
        spdx = json.loads((self.out / "yuzu-gateway-linux-x64.spdx.json").read_text())
        refs = {r["referenceLocator"] for p in spdx["packages"] for r in p.get("externalRefs", [])}
        self.assertIn("pkg:hex/cowboy@2.19.0", refs)

    def test_yuzu_binary_without_vcpkg_tree_fails(self):
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art, vcpkg=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ships a Yuzu C++ binary", r.stderr)

    def test_vcpkg_tree_without_yuzu_binary_fails(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/README": b"x"})
        r = self.generate(art)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no Yuzu C++ binary found", r.stderr)

    def test_missing_port_spdx_fails(self):
        make_vcpkg_tree(self.tmp, drop_spdx="zlib")
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cannot describe vcpkg port zlib", r.stderr)

    def test_manifest_port_not_installed_fails(self):
        make_vcpkg_tree(self.tmp)
        m = dict(MANIFEST, dependencies=MANIFEST["dependencies"] + ["sqlite3"])
        (self.tmp / "vcpkg.json").write_text(json.dumps(m))
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sqlite3 is not installed", r.stderr)

    def test_escaping_tar_member_fails(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"../escape": b"x", "y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.tmp / "escape").exists())

    def test_installer_contents_from_archive(self):
        make_vcpkg_tree(self.tmp)
        zip_path = self.tmp / "yuzu-agent-windows-x64.zip"
        import zipfile
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("a/bin/yuzu-agent.exe", b"MZ")
        exe = self.tmp / "YuzuAgentSetup-1.2.3.exe"
        exe.write_bytes(b"MZ installer")
        r = self.generate(exe, extra=("--contents-from", zip_path))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx = json.loads((self.out / "YuzuAgentSetup-1.2.3.cdx.json").read_text())
        self.assertEqual(cdx["metadata"]["component"]["name"], exe.name)
        self.assertEqual(cdx["metadata"]["component"]["hashes"][0]["content"],
                         hashlib.sha256(exe.read_bytes()).hexdigest())
        self.assertEqual(self.vcpkg_names(cdx), AGENT_PORTS)
        # ...and without --contents-from an installer is refused, not guessed.
        r = self.generate(exe)
        self.assertNotEqual(r.returncode, 0)

    def test_generate_refuses_a_forbidden_path(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art, env={"STUB_SYFT_EXTRA_PATH": "/vcpkg/ports/openssl/vcpkg.json"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("under vcpkg/", r.stderr)

    # ── check ──
    def _good_pair(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stderr)
        for f in self.out.iterdir():
            shutil.copy(f, self.tmp / f.name)
        return art

    def test_check_dir_passes_and_skips_images(self):
        self._good_pair()
        # An image SBOM legitimately lists /usr/share/.../tests paths and many packages.
        (self.tmp / "yuzu-server-image.cdx.json").write_text(json.dumps(
            {"bomFormat": "CycloneDX", "components": [{"type": "file", "name": "/usr/lib/x/tests/y"}] * 1000}))
        r = self.run_script("check", "--artifacts-dir", self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 file(s), OK", r.stdout)

    def test_check_refuses_changed_artifact(self):
        art = self._good_pair()
        art.write_bytes(art.read_bytes() + b"tampered")
        r = self.run_script("check", "--artifacts-dir", self.tmp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHA-256 of yuzu-linux-x64.tar.gz differs", r.stderr)

    def test_check_refuses_misnamed_sbom(self):
        self._good_pair()
        (self.tmp / "yuzu-linux-x64.cdx.json").rename(self.tmp / "yuzu-agent-linux-x64.cdx.json")
        r = self.run_script("check", "--artifacts-dir", self.tmp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must be named yuzu-linux-x64.cdx.json", r.stderr)

    def test_check_refuses_workspace_scan(self):
        # The shape of the v0.15.0 SBOM: thousands of port manifests from the
        # vcpkg clone, test tooling and gateway test build trees.
        comps = [{"type": "library", "name": f"p{i}", "properties": [
            {"name": "syft:location:0:path", "value": f"/vcpkg/ports/p{i}/vcpkg.json"}]} for i in range(500)]
        comps += [{"type": "library", "name": "puppeteer", "properties": [
            {"name": "syft:location:0:path", "value": "/tests/puppeteer/package.json"}]},
            {"type": "file", "name": "/gateway/_build_eunit/lib/meck/ebin/meck.app"}]
        f = self.tmp / "yuzu-linux-x64.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": comps}))
        r = self.run_script("check", f)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("more than the bound", r.stderr)
        self.assertIn("under vcpkg/", r.stderr)
        # The path rule alone, under the bound.
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": comps[-2:]}))
        r = self.run_script("check", f)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("2 path(s)", r.stderr)
        self.assertNotIn("more than the bound", r.stderr)

    def test_check_refuses_empty(self):
        f = self.tmp / "yuzu-linux-x64.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
        r = self.run_script("check", f)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no components", r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
