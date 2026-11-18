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
    ports with an upstream purl (and a CPE where NVD has one), a Hex package
    gets a pkg:hex purl from rebar.lock (by its Hex name, which can differ from
    the application's), and a port with no licence is named in a warning;
  - every artifact kind is unpacked and described: archives, a .deb, an .rpm,
    the macOS .pkg in the layout v0.15.0 shipped (its binaries staged as
    `.yuzu-agent.incoming` and `.libyuzu_agent_core.incoming.dylib`), and the
    Windows installer, whose SBOM lists only the archive files its .iss
    installs; rc-named packages pass `check` under their own names;
  - an SBOM for a file holding yuzu-server, and an installer's SBOM, say they
    are incomplete (CycloneDX composition, SPDX CONTAINS NOASSERTION);
  - unsafe input is refused: a tar or zip member that escapes the extraction
    directory (with and without tarfile's data filter, including a link
    chain), a binary with no vcpkg tree, a stalled command (timeout), and an
    unexpected error is one `::error::` line, not a traceback;
  - `check` refuses an SBOM over the entry bound, one listing a path under
    vcpkg/, vcpkg_installed/, build-*/, _build*/, site/, tests/, .git/ or
    .github/ wherever syft records a path (CycloneDX file names, location
    properties and evidence; SPDX file names and package sourceInfo), one
    with no components and no record of unpacked files, and one whose SHA-256
    or name does not match its artifact, and skips the image SBOMs.

syft (and pkgutil, rpm2cpio for those formats) is replaced by a small stub, so
the test needs no network and no syft. Stdlib only. The `generate` tests skip
on Windows (the stubs are #! scripts); the unit and `check` tests run there.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "artifact-sbom.py"
TRIPLET = "x64-linux-static"
POSIX_STUBS = os.name != "nt"
# Where an absolute tar member would land if extraction let it escape; salted,
# because the CI runners share one OS identity and /tmp across jobs.
ABS_ESCAPE = Path(tempfile.gettempdir()) / f"yuzu_test_abs_escape_{os.getpid()}_{secrets.token_hex(8)}"


def load_script():
    spec = importlib.util.spec_from_file_location("artifact_sbom", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


STUB_SYFT = textwrap.dedent('''\
    #!PYTHON
    """Stand-in for `syft scan dir:X --source-name N --source-version V -o fmt=path ...`.
    Reports the Erlang applications it finds (as syft does), and with
    STUB_SYFT_FILES=1 every file as an SPDX file entry (syft's shape: no
    leading slash)."""
    import json, os, sys
    args = sys.argv[1:]
    root = args[args.index("scan") + 1][len("dir:"):]
    name = args[args.index("--source-name") + 1]
    version = args[args.index("--source-version") + 1]
    outs = dict(a.split("=", 1) for a in (args[i + 1] for i, x in enumerate(args) if x == "-o"))
    comps, pkgs, rels, files = [], [], [], []
    extra = os.environ.get("STUB_SYFT_EXTRA_PATH")
    for dirpath, _dirs, fs in os.walk(root):
        for f in fs:
            rel = "/" + os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")
            if os.environ.get("STUB_SYFT_FILES"):
                files.append({"fileName": rel[1:], "SPDXID": "SPDXRef-File-" + str(len(files))})
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
            "files": files, "relationships": rels}
    json.dump(cdx, open(outs["cyclonedx-json"], "w"))
    json.dump(spdx, open(outs["spdx-json"], "w"))
''').replace("PYTHON", sys.executable)

# `pkgutil --expand-full <pkg> <dest>`: the fixture .pkg is a tar.gz of what
# pkgutil writes, so the stub only unpacks it into the (new) dest directory.
STUB_PKGUTIL = textwrap.dedent('''\
    #!PYTHON
    import os, sys, tarfile
    assert sys.argv[1] == "--expand-full", sys.argv
    src, dest = sys.argv[2], sys.argv[3]
    os.mkdir(dest)  # pkgutil refuses an existing directory
    with tarfile.open(src, "r:gz") as tf:
        tf.extractall(dest)
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

# The payload of the real YuzuAgent-0.15.0-macos-arm64.pkg (read with a xar
# and cpio reader on 2026-11-18; the 71 plugins cut to two), as
# `pkgutil --expand-full` lays it out: the product archive's Distribution,
# then the component package with its Bom, PackageInfo, expanded Payload and
# Scripts. build-pkg.sh stages the loose binaries under hidden `.incoming`
# names that postinstall renames into place.
PKG_EXPANDED = {
    "Distribution": b"<installer-gui-script/>",
    "yuzu-agent-component.pkg/Bom": b"BOMStore",
    "yuzu-agent-component.pkg/PackageInfo": b"<pkg-info/>",
    "yuzu-agent-component.pkg/Payload/usr/local/bin/.yuzu-agent.incoming": b"\xcf\xfa\xed\xfe",
    "yuzu-agent-component.pkg/Payload/usr/local/bin/.libyuzu_agent_core.incoming.dylib": b"\xcf\xfa\xed\xfe",
    "yuzu-agent-component.pkg/Payload/usr/local/lib/yuzu/.package-mode.incoming": b"loose\n",
    "yuzu-agent-component.pkg/Payload/usr/local/lib/yuzu/uninstall.sh": b"#!/bin/bash\n",
    "yuzu-agent-component.pkg/Payload/usr/local/lib/yuzu/.package-files.sha256.incoming": b"",
    "yuzu-agent-component.pkg/Payload/usr/local/lib/yuzu/.package-files.incoming": b"# package-version 0.15.0\n",
    "yuzu-agent-component.pkg/Payload/usr/local/lib/yuzu/.plugins.incoming/status.dylib": b"\xcf\xfa\xed\xfe",
    "yuzu-agent-component.pkg/Payload/usr/local/lib/yuzu/.plugins.incoming/echo.dylib": b"\xcf\xfa\xed\xfe",
    "yuzu-agent-component.pkg/Payload/Library/LaunchDaemons/.com.yuzu.agent.incoming.plist": b"<plist/>",
    "yuzu-agent-component.pkg/Scripts/preinstall": b"#!/bin/bash\n",
    "yuzu-agent-component.pkg/Scripts/postinstall": b"#!/bin/bash\n",
    "yuzu-agent-component.pkg/Scripts/merge-launchd-plist.js": b"",
    "yuzu-agent-component.pkg/Scripts/package-info": b"mode=loose\nunsigned_plugins=1\n",
    "yuzu-agent-component.pkg/Scripts/package-files.list": b"",
}

# The shape of deploy/packaging/windows/yuzu-agent.iss's [Files] section, with
# one plugin (`omitted`) left out, as origin/dev's script leaves out six.
ISS = textwrap.dedent(r'''
    #ifndef BuildDir
      #define BuildDir "..\..\..\build-windows"
    #endif
    [Setup]
    AppName=Yuzu Agent
    [Files]
    ; --- Core agent ---
    Source: "{#BuildDir}\agents\core\yuzu-agent.exe"; DestDir: "{app}\bin"; Components: core; Flags: ignoreversion
    Source: "{#BuildDir}\agents\core\*.dll"; DestDir: "{app}\bin"; Components: core; Flags: ignoreversion
    Source: "{#BuildDir}\agents\plugins\status\status.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
    Source: "{#BuildDir}\agents\plugins\echo\echo.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
    [Dirs]
    Name: "{app}\logs"
''')

WIN_ZIP = {
    "yuzu-agent-1.2.3-windows-x64/bin/yuzu-agent.exe": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/bin/yuzu_agent_core.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/bin/libcrypto-3-x64.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/plugins/status.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/plugins/echo.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/plugins/omitted.dll": b"MZ",
}


def make_vcpkg_tree(root: Path, drop_spdx: str = "", no_licence: str = "") -> Path:
    inst = root / "vcpkg_installed"
    (inst / "vcpkg").mkdir(parents=True)
    (inst / "vcpkg" / "status").write_text(STATUS)
    for port, (lic, loc) in UPSTREAM.items():
        if port == drop_spdx:
            continue
        share = inst / TRIPLET / "share" / port
        share.mkdir(parents=True)
        port_pkg = {"SPDXID": "SPDXRef-port", "name": port, "licenseConcluded": lic,
                    "homepage": f"https://example.invalid/{port}",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:vcpkg/{port}@x"}]}
        if port == no_licence:
            port_pkg["licenseConcluded"] = "NOASSERTION"
        spdx = {"packages": [port_pkg,
                             {"SPDXID": "SPDXRef-resource-0", "name": f"{port}-src", "downloadLocation": loc}]}
        (share / "vcpkg.spdx.json").write_text(json.dumps(spdx))
    (root / "vcpkg.json").write_text(json.dumps(MANIFEST))
    return inst


def make_tar(path: Path, files: dict, links: dict = None) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, target in (links or {}).items():  # links first: a chain must exist before its use
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def make_zip(path: Path, files: dict) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


def write_exe(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def run_script(*args, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([sys.executable, "-I", str(SCRIPT)] + [str(a) for a in args],
                          capture_output=True, text=True, env=e)


# ── Units: no subprocess stubs, so these run on Windows too ──────────────────

class Units(unittest.TestCase):
    def setUp(self):
        self.mod = load_script()
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_sbom_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pkg_staged_names_are_read_as_installed(self):
        m = self.mod
        self.assertEqual(m.installed_name(".yuzu-agent.incoming"), "yuzu-agent")
        self.assertEqual(m.installed_name(".libyuzu_agent_core.incoming.dylib"), "libyuzu_agent_core.dylib")
        # Only a hidden name with an `.incoming` infix or suffix is a staged one.
        for same in ("yuzu-agent", "libyuzu_agent_core.dylib", "yuzu-agent.incoming", ".hidden",
                     ".a.incoming.x.y", ".yuzu-agent.incomingx"):
            self.assertEqual(m.installed_name(same), same)
        root = self.tmp / "pkg"
        for rel, data in PKG_EXPANDED.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(data)
        self.assertEqual(m.yuzu_binaries(root), (True, False))
        # Either staged binary alone is enough, and neither is mistaken for the server.
        (root / "yuzu-agent-component.pkg/Payload/usr/local/bin/.yuzu-agent.incoming").unlink()
        self.assertEqual(m.yuzu_binaries(root), (True, False))

    def test_iss_files_section(self):
        iss = self.tmp / "agent.iss"
        iss.write_text(ISS)
        entries = self.mod.iss_file_entries(iss)
        self.assertEqual(entries, [("bin", "yuzu-agent.exe"), ("bin", "*.dll"),
                                   ("plugins", "status.dll"), ("plugins", "echo.dll")])

    def test_iss_refuses_what_it_cannot_map(self):
        cases = {
            "preprocessor": '[Files]\n#ifdef X\nSource: "a.dll"; DestDir: "{app}\\bin"\n#endif\n',
            "outside app": '[Files]\nSource: "a.dll"; DestDir: "{sys}"\n',
            "recursive": '[Files]\nSource: "x\\*"; DestDir: "{app}\\bin"; Flags: recursesubdirs\n',
            "destname": '[Files]\nSource: "a.dll"; DestDir: "{app}\\bin"; DestName: "b.dll"\n',
            "empty": '[Setup]\nAppName=x\n',
        }
        for what, text in cases.items():
            with self.subTest(what=what):
                iss = self.tmp / "x.iss"
                iss.write_text(text)
                with self.assertRaises(self.mod.SbomError):
                    self.mod.iss_file_entries(iss)

    def test_installer_keeps_only_what_the_iss_installs(self):
        iss = self.tmp / "agent.iss"
        iss.write_text(ISS)
        contents = self.tmp / "contents"
        for rel, data in WIN_ZIP.items():
            (contents / rel).parent.mkdir(parents=True, exist_ok=True)
            (contents / rel).write_bytes(data)
        kept, dropped, unmatched = self.mod.keep_installed(contents, self.mod.iss_file_entries(iss))
        self.assertEqual(dropped, ["plugins/omitted.dll"])
        self.assertEqual(kept, ["bin/libcrypto-3-x64.dll", "bin/yuzu-agent.exe", "bin/yuzu_agent_core.dll",
                                "plugins/echo.dll", "plugins/status.dll"])
        self.assertEqual(unmatched, [])
        self.assertFalse((contents / "yuzu-agent-1.2.3-windows-x64/plugins/omitted.dll").exists())
        # An entry with nothing behind it in the archive is reported, not hidden.
        (contents / "yuzu-agent-1.2.3-windows-x64/plugins/echo.dll").unlink()
        _k, _d, unmatched = self.mod.keep_installed(contents, self.mod.iss_file_entries(iss))
        self.assertEqual(unmatched, ["{app}\\plugins\\echo.dll"])

    def test_forbidden_segments(self):
        bad = ["/vcpkg/ports/zlib/vcpkg.json", "vcpkg_installed/x64-linux/lib/libz.a",
               "/build-windows/agents/core/yuzu-agent.exe", "build-linux/x", "/gateway/_build/default/lib/x.app",
               "/gateway/_build_eunit/lib/meck/ebin/meck.app", "/site/assets/x.js", "/tests/puppeteer/package.json",
               "/.git/config", "/.github/workflows/ci.yml", "C:\\w\\build-windows\\x.dll"]
        good = ["/yuzu-0.15.0-linux-x64/bin/yuzu-server", "usr/lib/.build-id/ab/cdef", "/usr/share/doc/x/test/y",
                "/yuzu-gateway-0.15.0-linux-x64/lib/kernel-10.6/ebin/kernel.app", "/opt/yuzu/plugins/build.so",
                "/x/vcpkg-cmake/y", "/x/sites/y", "/x/build/y"]
        for p in bad:
            self.assertIsNotNone(self.mod.FORBIDDEN_SEGMENTS.search(p), p)
        for p in good:
            self.assertIsNone(self.mod.FORBIDDEN_SEGMENTS.search(p), p)

    def _extract(self, art: Path, data_filter: bool):
        dest = self.tmp / ("d" + str(len(list(self.tmp.iterdir()))))
        dest.mkdir()
        with mock.patch.object(self.mod, "HAS_DATA_FILTER", data_filter and hasattr(tarfile, "data_filter")):
            self.mod.extract(art, dest)
        return dest

    def test_tar_extraction_refuses_escapes_with_and_without_the_data_filter(self):
        cases = {
            "dotdot": ({"../escape": b"x"}, {}),
            "absolute": ({str(ABS_ESCAPE): b"x"}, {}),
            "link out": ({}, {"y/out": "../../.."}),
            "absolute link": ({}, {"y/out": "/etc"}),
            # Each link is inside on its own; together `a/b` resolves to ../.
            "link chain": ({"a/b/c": b"x"}, {"a": ".", "a/b": ".."}),
        }
        for data_filter in (True, False):
            for what, (files, links) in cases.items():
                if what == "absolute" and os.name == "nt":
                    continue  # a POSIX absolute member name; Windows has its own rules for one
                with self.subTest(what=what, data_filter=data_filter):
                    art = make_tar(self.tmp / f"t-{data_filter}.tar.gz", files, links)
                    if what == "absolute" and data_filter:
                        # The data filter strips the leading "/" and extracts
                        # inside; the fallback refuses. Either way nothing escapes.
                        self._extract(art, data_filter)
                    else:
                        with self.assertRaises(self.mod.SbomError):
                            self._extract(art, data_filter)
                    self.assertFalse((self.tmp / "escape").exists())
                    self.assertFalse(ABS_ESCAPE.exists())
                    self.assertFalse((self.tmp / "c").exists())

    def test_tar_fallback_extracts_a_clean_tree(self):
        art = make_tar(self.tmp / "ok.tar.gz", {"y/bin/yuzu-agent": b"x", "y/lib/libz.so.1.3": b"z"},
                       {"y/lib/libz.so.1": "libz.so.1.3"})
        dest = self._extract(art, False)
        self.assertEqual((dest / "y/bin/yuzu-agent").read_bytes(), b"x")
        link = dest / "y/lib/libz.so.1"
        # Where a symlink cannot be made (Windows without the privilege),
        # tarfile writes a copy of the target instead.
        self.assertTrue(link.is_symlink() or link.read_bytes() == b"z")

    def test_zip_member_escaping_is_refused(self):
        for member in ("../escape", "/abs/escape", "y/../../escape"):
            with self.subTest(member=member):
                art = make_zip(self.tmp / "z.zip", {"y/bin/yuzu-agent.exe": b"MZ", member: b"x"})
                with self.assertRaises(self.mod.SbomError) as cm:
                    self._extract(art, True)
                self.assertIn("escapes the extraction directory", str(cm.exception))

    def test_hex_lock_maps_app_to_its_hex_package(self):
        lock = self.tmp / "rebar.lock"
        lock.write_text('{"1.2.0",\n[{<<"chatterbox">>,{pkg,<<"ts_chatterbox">>,<<"0.15.1">>},0},\n'
                        ' {<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.19.0">>},0}]}.\n')
        hexmap = self.mod.hex_packages(lock)
        self.assertEqual(hexmap, {("chatterbox", "0.15.1"): "ts_chatterbox", ("cowboy", "2.19.0"): "cowboy"})
        self.assertEqual(self.mod._hex_purl("pkg:otp/chatterbox@0.15.1", hexmap), "pkg:hex/ts_chatterbox@0.15.1")
        self.assertIsNone(self.mod._hex_purl("pkg:otp/cowboy@2.18.0", hexmap))  # not the locked version
        self.assertIsNone(self.mod._hex_purl("pkg:otp/kernel@10.6", hexmap))


# ── check: no stubs, so these run on Windows too ─────────────────────────────

class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_sbom_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

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
        r = run_script("check", f)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("more than the bound", r.stderr)
        self.assertIn("under vcpkg/", r.stderr)
        # The path rule alone, under the bound.
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": comps[-2:]}))
        r = run_script("check", f)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("2 path(s)", r.stderr)
        self.assertNotIn("more than the bound", r.stderr)

    def test_check_finds_a_path_wherever_syft_records_one(self):
        # One offending path at a time, in each place real syft 1.57.2 output
        # records a path, for each forbidden segment, so dropping any place or
        # any segment from the rule fails here.
        def cdx(place, path):
            c = {"type": "library", "name": "x", "version": "1"}
            if place == "file":
                c = {"type": "file", "name": path}
            elif place == "property":
                c["properties"] = [{"name": "syft:package:foundBy", "value": "x"},
                                   {"name": "syft:location:0:path", "value": path}]
            elif place == "evidence":
                c["evidence"] = {"occurrences": [{"location": path}]}
            ok = {"type": "library", "name": "ok", "version": "1"}
            return {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [ok, c]}

        def spdx(place, path):
            root = {"name": "a", "SPDXID": "SPDXRef-DocumentRoot-Directory-a", "downloadLocation": "NOASSERTION"}
            pkg = {"name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
                   "sourceInfo": "acquired package info from installed node module manifest file: /ok"}
            files = [{"fileName": "ok/bin/x", "SPDXID": "SPDXRef-File-0"}]
            if place == "fileName":
                files.append({"fileName": path, "SPDXID": "SPDXRef-File-1"})
            else:
                pkg["sourceInfo"] = f"acquired package info from ErLang application resource file: {path}"
            return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [root, pkg],
                    "files": files, "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                                                        "relationshipType": "DESCRIBES",
                                                        "relatedSpdxElement": root["SPDXID"]}]}

        segments = ["vcpkg/ports/zlib/vcpkg.json", "vcpkg_installed/x64-linux/share/zlib/copyright",
                    "build-windows/agents/core/yuzu-agent.exe", "gateway/_build/prod/lib/x/ebin/x.app",
                    "gateway/_build_eunit/lib/meck/ebin/meck.app", "site/assets/js/x.js",
                    "tests/puppeteer/package.json", ".git/config", ".github/workflows/ci.yml"]
        for seg in segments:
            for fmt, places, make in (("cdx", ("file", "property", "evidence"), cdx),
                                      ("spdx", ("fileName", "sourceInfo"), spdx)):
                for place in places:
                    for lead in ("/", ""):
                        with self.subTest(seg=seg, place=place, lead=lead):
                            f = self.tmp / f"yuzu-linux-x64.{fmt}.json"
                            f.write_text(json.dumps(make(place, lead + seg)))
                            r = run_script("check", f)
                            self.assertNotEqual(r.returncode, 0, r.stdout)
                            self.assertIn("1 path(s) under", r.stderr)

    def test_check_refuses_empty(self):
        f = self.tmp / "yuzu-linux-x64.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
        r = run_script("check", f)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no components at all", r.stderr)

    def test_check_accepts_no_components_when_files_were_unpacked(self):
        # A plugins-only package: syft recognises nothing in it, which is not
        # a scan of nothing when the SBOM records the files it held.
        f = self.tmp / "yuzu-plugins_1.2.3_amd64.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [], "metadata": {
            "properties": [{"name": "yuzu:sbom:unpacked-files", "value": "29"}]}}))
        r = run_script("check", f)
        self.assertEqual(r.returncode, 0, r.stderr)
        g = self.tmp / "yuzu-plugins_1.2.3_amd64.spdx.json"
        root = {"name": "a", "SPDXID": "SPDXRef-R", "comment": "artifact: a; unpacked-files: 29"}
        g.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [root], "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-R"}]}))
        r = run_script("check", g)
        self.assertEqual(r.returncode, 0, r.stderr)
        root["comment"] = "artifact: a; unpacked-files: 0"
        g.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [root], "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-R"}]}))
        r = run_script("check", g)
        self.assertNotEqual(r.returncode, 0)


# ── generate: syft, pkgutil and rpm2cpio stubbed; POSIX only ─────────────────

@unittest.skipUnless(POSIX_STUBS, "the syft, pkgutil and rpm2cpio stubs are #! scripts")
class ArtifactSbom(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_sbom_"))
        self.syft = write_exe(self.tmp / "syft", STUB_SYFT)
        self.out = self.tmp / "out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def generate(self, artifact: Path, vcpkg=True, extra=(), env=None):
        args = ["generate", "--syft", self.syft, "--artifact", artifact, "--version", "1.2.3",
                "--out-dir", self.out]
        if vcpkg:
            args += ["--vcpkg-installed", self.tmp / "vcpkg_installed", "--triplet", TRIPLET,
                     "--manifest", self.tmp / "vcpkg.json"]
        return run_script(*args, *extra, env=env)

    def vcpkg_names(self, cdx):
        return sorted(c["name"] for c in cdx["components"]
                      if any(p["name"] == "yuzu:vcpkg:port" for p in c.get("properties", [])))

    def load(self, stem):
        return (json.loads((self.out / f"{stem}.cdx.json").read_text()),
                json.loads((self.out / f"{stem}.spdx.json").read_text()))

    def check_dir(self, artifact: Path):
        for f in self.out.iterdir():
            shutil.copy(f, artifact.parent / f.name)
        return run_script("check", "--artifacts-dir", artifact.parent)

    def props(self, cdx):
        return {p["name"]: p["value"] for p in cdx["metadata"].get("properties", [])}

    # ── generate ──
    def test_agent_archive(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-agent-macos-arm64.tar.gz",
                       {"yuzu-agent-1.2.3/bin/yuzu-agent": b"\x7fELF", "yuzu-agent-1.2.3/bin/README": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, spdx = self.load("yuzu-agent-macos-arm64")
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
        # The agent archive holds nothing known to be unlisted: no incompleteness mark.
        self.assertNotIn("compositions", cdx)
        self.assertNotIn("NOASSERTION", contained)
        self.assertEqual(self.props(cdx)["yuzu:sbom:unpacked-files"], "2")

    def test_server_package_adds_server_feature_and_is_marked_incomplete(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz",
                       {"y/bin/yuzu-server": b"x", "y/bin/libyuzu_agent_core.so": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, spdx = self.load("yuzu-linux-x64")
        self.assertEqual(self.vcpkg_names(cdx), SERVER_PORTS)
        libpq = next(c for c in cdx["components"] if c["name"] == "libpq")
        self.assertTrue(libpq["purl"].startswith("pkg:generic/libpq@18.4?download_url="), libpq["purl"])
        # yuzu-server compiles in vendored code no SBOM lists yet: say so in the data.
        root_ref = cdx["metadata"]["component"]["bom-ref"]
        self.assertEqual(cdx["compositions"], [{"aggregate": "incomplete", "assemblies": [root_ref]}])
        self.assertIn("qrcodegen", self.props(cdx)["yuzu:sbom:incomplete"])
        root_pkg = next(p for p in spdx["packages"] if p["SPDXID"].startswith("SPDXRef-DocumentRoot"))
        self.assertIn({"spdxElementId": root_pkg["SPDXID"], "relationshipType": "CONTAINS",
                       "relatedSpdxElement": "NOASSERTION"}, spdx["relationships"])
        self.assertIn("incomplete: yuzu-server compiles in vendored C++", root_pkg["comment"])

    def test_port_without_licence_is_warned_and_noted(self):
        make_vcpkg_tree(self.tmp, no_licence="zlib")
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("::warning::yuzu-linux-x64.tar.gz: 1 vcpkg port(s) have no licence", r.stderr)
        self.assertIn("(NOASSERTION): zlib", r.stderr)
        cdx, spdx = self.load("yuzu-linux-x64")
        self.assertEqual(self.props(cdx)["yuzu:sbom:licence-noassertion"], "zlib")
        zlib = next(c for c in cdx["components"] if c["name"] == "zlib")
        self.assertNotIn("licenses", zlib)
        pkg = next(p for p in spdx["packages"] if p["name"] == "zlib")
        self.assertEqual(pkg["licenseDeclared"], "NOASSERTION")

    def test_hex_purl_for_gateway(self):
        lock = self.tmp / "rebar.lock"
        lock.write_text('{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.19.0">>},0},\n'
                        ' {<<"chatterbox">>,{pkg,<<"ts_chatterbox">>,<<"0.15.1">>},0},\n'
                        ' {<<"ranch">>,{pkg,<<"ranch">>,<<"2.3.0">>},1}]}.\n')
        art = make_tar(self.tmp / "yuzu-gateway-linux-x64.tar.gz",
                       {"g/lib/cowboy-2.19.0/ebin/cowboy.app": b"x", "g/lib/kernel-10.6/ebin/kernel.app": b"x",
                        "g/lib/chatterbox-0.15.1/ebin/chatterbox.app": b"x",
                        "g/lib/ranch-2.2.0/ebin/ranch.app": b"x"})
        r = self.generate(art, vcpkg=False, extra=("--rebar-lock", lock))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, spdx = self.load("yuzu-gateway-linux-x64")
        purls = {c["name"]: c["purl"] for c in cdx["components"]}
        # The Hex package name, not the application's; an OTP app or a version
        # the lock does not name keeps pkg:otp.
        self.assertEqual(purls, {"cowboy": "pkg:hex/cowboy@2.19.0", "kernel": "pkg:otp/kernel@10.6",
                                 "chatterbox": "pkg:hex/ts_chatterbox@0.15.1", "ranch": "pkg:otp/ranch@2.2.0"})
        chatterbox = next(c for c in cdx["components"] if c["name"] == "chatterbox")
        self.assertIn({"name": "yuzu:otp:purl", "value": "pkg:otp/chatterbox@0.15.1"}, chatterbox["properties"])
        kernel = next(c for c in cdx["components"] if c["name"] == "kernel")
        self.assertNotIn("yuzu:otp:purl", [p["name"] for p in kernel["properties"]])
        refs = {p["name"]: [r["referenceLocator"] for r in p.get("externalRefs", [])] for p in spdx["packages"]}
        self.assertEqual(refs["chatterbox"], ["pkg:hex/ts_chatterbox@0.15.1"])
        self.assertEqual(refs["cowboy"], ["pkg:hex/cowboy@2.19.0"])
        self.assertEqual(refs["kernel"], ["pkg:otp/kernel@10.6"])

    def test_macos_pkg_in_the_shipped_layout(self):
        # v0.15.0's .pkg stages yuzu-agent and its core dylib under hidden
        # `.incoming` names; describing it must find the agent and add its
        # ports (it failed with "no Yuzu C++ binary found" before).
        make_vcpkg_tree(self.tmp)
        stubs = self.tmp / "bin"
        stubs.mkdir()
        write_exe(stubs / "pkgutil", STUB_PKGUTIL)
        pkg = make_tar(self.tmp / "YuzuAgent-1.2.3_rc1-macos-arm64.pkg", PKG_EXPANDED)
        env = {"PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}"}
        r = self.generate(pkg, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, _spdx = self.load("YuzuAgent-1.2.3_rc1-macos-arm64")
        self.assertEqual(self.vcpkg_names(cdx), AGENT_PORTS)
        self.assertEqual(cdx["metadata"]["component"]["name"], pkg.name)
        r = self.check_dir(pkg)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_deb_rc_named(self):
        if not shutil.which("dpkg-deb"):
            self.skipTest("dpkg-deb not installed")
        make_vcpkg_tree(self.tmp)
        stage = self.tmp / "stage"
        (stage / "DEBIAN").mkdir(parents=True)
        (stage / "DEBIAN" / "control").write_text(
            "Package: yuzu-agent\nVersion: 1.2.3~rc1\nArchitecture: amd64\nMaintainer: t <t@example.invalid>\n"
            "Description: t\n")
        (stage / "usr" / "bin").mkdir(parents=True)
        (stage / "usr" / "bin" / "yuzu-agent").write_bytes(b"\x7fELF")
        rel = self.tmp / "rel"
        rel.mkdir()
        deb = rel / "yuzu-agent_1.2.3-rc1_amd64.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(deb)],
                       check=True, capture_output=True)
        r = self.generate(deb)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, _ = self.load("yuzu-agent_1.2.3-rc1_amd64")
        self.assertEqual(self.vcpkg_names(cdx), AGENT_PORTS)
        r = self.check_dir(deb)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 file(s), OK", r.stdout)

    def test_rpm_rc_named(self):
        if not shutil.which("cpio"):
            self.skipTest("cpio not installed")
        make_vcpkg_tree(self.tmp)
        stubs = self.tmp / "bin"
        stubs.mkdir()
        # The .rpm fixture is the cpio payload rpm2cpio would print, so the
        # stub prints the file; the real cpio unpacks it.
        write_exe(stubs / "rpm2cpio", '#!/bin/sh\nexec cat "$1"\n')
        stage = self.tmp / "stage"
        (stage / "usr" / "bin").mkdir(parents=True)
        (stage / "usr" / "bin" / "yuzu-server").write_bytes(b"\x7fELF")
        rel = self.tmp / "rel"
        rel.mkdir()
        rpm = rel / "yuzu-server-1.2.3-0.1.rc1.x86_64.rpm"
        with open(rpm, "wb") as f:
            subprocess.run(["cpio", "-o", "-H", "newc", "--quiet"], input=b"./usr/bin/yuzu-server\n",
                           cwd=stage, stdout=f, check=True)
        env = {"PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}"}
        r = self.generate(rpm, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, _ = self.load("yuzu-server-1.2.3-0.1.rc1.x86_64")
        self.assertEqual(self.vcpkg_names(cdx), SERVER_PORTS)
        r = self.check_dir(rpm)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_plugins_only_package_passes(self):
        art = make_tar(self.tmp / "yuzu-plugins-linux-x64.tar.gz",
                       {"p/plugins/status.so": b"\x7fELF", "p/plugins/echo.so": b"\x7fELF"})
        r = self.generate(art, vcpkg=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 entries", r.stdout)

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

    def test_installer_lists_only_what_its_script_installs(self):
        make_vcpkg_tree(self.tmp)
        rel = self.tmp / "rel"
        rel.mkdir()
        zip_path = make_zip(rel / "yuzu-agent-windows-x64.zip", WIN_ZIP)
        iss = self.tmp / "yuzu-agent.iss"
        iss.write_text(ISS)
        exe = rel / "YuzuAgentSetup-1.2.3_rc1.exe"
        exe.write_bytes(b"MZ installer")
        r = self.generate(exe, extra=("--contents-from", zip_path, "--iss", iss), env={"STUB_SYFT_FILES": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("plugins/omitted.dll", r.stderr)  # the warning names what is left out
        cdx, spdx = self.load("YuzuAgentSetup-1.2.3_rc1")
        self.assertEqual(cdx["metadata"]["component"]["name"], exe.name)
        self.assertEqual(cdx["metadata"]["component"]["hashes"][0]["content"],
                         hashlib.sha256(exe.read_bytes()).hexdigest())
        self.assertEqual(self.vcpkg_names(cdx), AGENT_PORTS)
        listed = {f["fileName"].split("/", 1)[1] for f in spdx["files"]}
        self.assertEqual(listed, {"bin/yuzu-agent.exe", "bin/yuzu_agent_core.dll", "bin/libcrypto-3-x64.dll",
                                  "plugins/status.dll", "plugins/echo.dll"})
        props = self.props(cdx)
        self.assertIn("the 5 file(s) of yuzu-agent-windows-x64.zip", props["yuzu:sbom:contents"])
        self.assertIn("yuzu-agent.iss installs", props["yuzu:sbom:contents"])
        self.assertIn("left out: plugins/omitted.dll", props["yuzu:sbom:contents"])
        self.assertEqual(cdx["compositions"][0]["aggregate"], "incomplete")
        self.assertIn("InnoSetup runtime", props["yuzu:sbom:incomplete"])
        r = self.check_dir(exe)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # ...and without --contents-from or --iss an installer is refused, not guessed.
        self.assertNotEqual(self.generate(exe).returncode, 0)
        r = self.generate(exe, extra=("--contents-from", zip_path))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--contents-from and --iss go together", r.stderr)

    def test_generate_refuses_a_forbidden_path(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art, env={"STUB_SYFT_EXTRA_PATH": "/vcpkg/ports/openssl/vcpkg.json"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("under vcpkg/", r.stderr)

    # ── failure handling ──
    def test_stalled_command_times_out(self):
        mod = load_script()
        sleeper = write_exe(self.tmp / "slow-syft", f"#!{sys.executable}\nimport time; time.sleep(30)\n")
        a = types.SimpleNamespace(syft=str(sleeper), version="1")
        with mock.patch.object(mod, "SYFT_TIMEOUT", 1), self.assertRaises(mod.SbomError) as cm:
            mod._syft(a, self.tmp, self.tmp / "x.tar.gz", self.tmp / "a", self.tmp / "b")
        self.assertIn("did not finish within 1 s", str(cm.exception))
        with mock.patch.object(mod, "UNPACK_TIMEOUT", 1), self.assertRaises(mod.SbomError) as cm:
            mod._run([str(sleeper)])
        self.assertIn("did not finish within 1 s", str(cm.exception))

    def test_unexpected_error_is_one_error_line(self):
        make_vcpkg_tree(self.tmp)
        (self.tmp / "vcpkg.json").write_text("{not json")
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)
        self.assertRegex(r.stderr.strip(), r"^::error::yuzu-linux-x64\.tar\.gz: unexpected JSONDecodeError: ")

    def test_temp_cleanup_failure_does_not_fail_the_run(self):
        # On Windows an AV or indexer handle on an unpacked DLL makes removing
        # the temporary tree raise after the SBOMs are made. Simulate that.
        mod = load_script()
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})

        def locked(path, ignore_errors=False, *a, **kw):
            if not ignore_errors:
                raise PermissionError(13, "The process cannot access the file", str(path))

        argv = ["generate", "--syft", str(self.syft), "--artifact", str(art), "--version", "1.2.3",
                "--out-dir", str(self.out), "--vcpkg-installed", str(self.tmp / "vcpkg_installed"),
                "--triplet", TRIPLET, "--manifest", str(self.tmp / "vcpkg.json")]
        err = io.StringIO()
        # RUNNER_TEMP inside this test's own directory, so the tree the fake
        # lock leaves behind is removed by tearDown and never touches another job's.
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.tmp)}), \
                mock.patch.object(shutil, "rmtree", locked), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = mod.main(argv)
        self.assertEqual(rc, 0, err.getvalue())
        self.assertTrue((self.out / "yuzu-linux-x64.cdx.json").is_file())
        self.assertIn("could not remove the temporary directory", err.getvalue())
        self.assertEqual(len(list(self.tmp.glob("yuzu_sbom_*"))), 1)

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
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 file(s), OK", r.stdout)

    def test_check_refuses_changed_artifact(self):
        art = self._good_pair()
        art.write_bytes(art.read_bytes() + b"tampered")
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHA-256 of yuzu-linux-x64.tar.gz differs", r.stderr)

    def test_check_refuses_misnamed_sbom(self):
        self._good_pair()
        (self.tmp / "yuzu-linux-x64.cdx.json").rename(self.tmp / "yuzu-agent-linux-x64.cdx.json")
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must be named yuzu-linux-x64.cdx.json", r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
