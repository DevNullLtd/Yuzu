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
    Windows installer, whose SBOM lists the files the Inno Setup compiler's
    own manifest (OutputManifestFile) lists, each read from the build
    directory with the SHA-256 the compiler recorded; rc-named packages pass
    `check` under their own names;
  - an SBOM for a file holding yuzu-server, an installer's SBOM and a
    gateway SBOM (the Erlang emulator, beam.smp, vendors code) say they are
    incomplete (CycloneDX composition, SPDX CONTAINS NOASSERTION) and why, by
    tokens from a closed set that release-verification.md documents exactly;
  - `mark-image` marks an image SBOM pair whose image holds a Yuzu C++ binary
    or the Erlang emulator, idempotently, refuses a mismatched or partly
    marked pair, and the release check refuses an image pair left unmarked,
    partly marked, marked for nothing, or named as a release image without
    that image's title label;
  - the installer manifest contract (artifact-sbom.py): a manifest built in
    ISCC's format (issrc is-6_7_3) from the real yuzu-agent.iss's [Files]
    layout is read, and its files copied at their build-relative paths; its
    paths map onto the build directory as defined (Windows paths, normalised,
    compared case-insensitively); and every refusal is pinned: the encoding
    (no UTF-8 byte order mark, not UTF-8), line ends, the header, zero rows,
    a column count, the Index sequence, the hash form, a path outside the
    build directory (`..`, another drive, UNC, a symlink or junction), a
    missing file, a one-byte change; yuzu-agent.iss sets OutputManifestFile
    and release.yml hands the SBOM step the manifest of the same ISCC run,
    with the build directory that run was given; the .pkg's staged names are
    the ones deploy/packaging/macos/build-pkg.sh stages;
  - every `yuzu:sbom:` note the docs name is written under the same key in
    both formats (a CycloneDX property; a line of the SPDX root's comment),
    and the docs' own extraction commands, run with jq, read every reason
    token from a generated CycloneDX and SPDX file alike;
  - unsafe input is refused: a tar or zip member that escapes the extraction
    directory (with and without tarfile's data filter, including a link
    chain), a device or FIFO member, a binary with no vcpkg tree, a stalled
    command (syft, and rpm2cpio | cpio: timeout), a failing syft, an
    rpm2cpio that fails after writing part of the payload, a cpio that
    fails, a note written twice, and an unexpected error is one `::error::`
    line, not a traceback;
  - every SBOM pair `generate` writes here validates against the vendored
    CycloneDX 1.7 and SPDX 2.3 schemas when jsonschema is importable, and
    YUZU_REQUIRE_JSONSCHEMA=1 makes its absence a failure;
  - `check` refuses an SBOM over the entry bound (400 passes, 401 fails), one listing a path under
    vcpkg/, vcpkg_installed/, build-*/, _build/, _build_*/, site/, tests/, .git/ or
    .github/ wherever syft records a path (CycloneDX file names, location
    properties and evidence; SPDX file names and package sourceInfo), one
    with no components and no record of unpacked files, and one whose SHA-256
    or name does not match its artifact, and skips the image SBOMs.

syft (and pkgutil, rpm2cpio for those formats) is replaced by a small stub, so
the test needs no network and no syft. Stdlib only, plus jsonschema for the
schema validation when it is importable. The `generate` tests skip
on Windows (the stubs are #! scripts); the unit and `check` tests run there.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
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


# Schema validation of every SBOM `generate` writes in these tests: CycloneDX
# 1.7 (tests/fixtures/cyclonedx, the schemas test_cbom_schema.py uses) and SPDX
# 2.3 (tests/fixtures/spdx). It runs whenever jsonschema (>= 4.18, with
# `referencing`) is importable; YUZU_REQUIRE_JSONSCHEMA=1 makes its absence a
# failure (docs-lint's `CBOM schema` job sets it). syft is stubbed here, so this
# checks this script's merge into a syft-shaped document, not real syft output;
# format keywords (date-time, iri-reference) are not checked.
REQUIRE_JSONSCHEMA = os.environ.get("YUZU_REQUIRE_JSONSCHEMA") == "1"
CDX_SCHEMA_DIR = ROOT / "tests" / "fixtures" / "cyclonedx"
SPDX_SCHEMA = ROOT / "tests" / "fixtures" / "spdx" / "spdx-schema-2.3.json"
_VALIDATORS: list = []


def sbom_validators():
    """(cyclonedx, spdx) Draft-7 validators, or None when jsonschema is not
    importable and YUZU_REQUIRE_JSONSCHEMA is not 1 (then: AssertionError)."""
    if not _VALIDATORS:
        try:
            import jsonschema
            from referencing import Registry, Resource
            from referencing.jsonschema import DRAFT7
        except ImportError as exc:
            if REQUIRE_JSONSCHEMA:
                raise AssertionError(f"YUZU_REQUIRE_JSONSCHEMA=1 but jsonschema/referencing is not importable "
                                     f"({exc}): the generated SBOMs cannot be schema-validated") from exc
            _VALIDATORS.append(None)
        else:
            registry = Registry()
            for name in ("bom-1.7.schema.json", "cryptography-defs.schema.json", "jsf-0.82.schema.json",
                         "spdx.schema.json"):
                res = Resource.from_contents(json.loads((CDX_SCHEMA_DIR / name).read_text(encoding="utf-8")),
                                             default_specification=DRAFT7)
                registry = registry.with_resource(f"http://cyclonedx.org/schema/{name}", res).with_resource(name, res)
            cdx = registry.contents("bom-1.7.schema.json")
            spdx = json.loads(SPDX_SCHEMA.read_text(encoding="utf-8"))
            _VALIDATORS.append((jsonschema.Draft7Validator(cdx, registry=registry),
                                jsonschema.Draft7Validator(spdx)))
    return _VALIDATORS[0]


def schema_errors(doc: dict) -> list:
    """Schema errors of a CycloneDX or SPDX document ([] when valid); None
    when validation is unavailable (see sbom_validators)."""
    validators = sbom_validators()
    if validators is None:
        return None
    v = validators[0] if doc.get("bomFormat") == "CycloneDX" else validators[1]
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}"
            for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))]


STUB_SYFT = textwrap.dedent('''\
    #!PYTHON
    """Stand-in for `syft scan dir:X --source-name N --source-version V -o fmt=path ...`.
    Reports the Erlang applications it finds (as syft does), and with
    STUB_SYFT_FILES=1 every file as an SPDX file entry (syft's shape: no
    leading slash, SHA-1 and SHA-256 checksums). Writes the document-level
    fields syft 1.57.2 writes, so the output is valid CycloneDX 1.7 and SPDX 2.3
    before artifact-sbom.py merges into it."""
    import hashlib, json, os, sys, uuid
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
                data = open(os.path.join(dirpath, f), "rb").read()
                files.append({"fileName": rel[1:], "SPDXID": "SPDXRef-File-" + str(len(files)),
                              "checksums": [{"algorithm": "SHA1", "checksumValue": hashlib.sha1(data).hexdigest()},
                                            {"algorithm": "SHA256",
                                             "checksumValue": hashlib.sha256(data).hexdigest()}]})
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
    cdx = {"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX",
           "specVersion": "1.7", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": "2026-11-18T00:00:00Z",
                        "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft",
                                                  "version": "1.57.2"}]},
                        "component": {"bom-ref": "root", "type": "file", "name": name, "version": version}},
           "components": comps}
    spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
            "documentNamespace": f"https://anchore.com/syft/dir/{name}-{uuid.uuid4()}",
            "creationInfo": {"licenseListVersion": "3.29", "creators": ["Organization: Anchore, Inc",
                                                                         "Tool: syft-1.57.2"],
                             "created": "2026-11-18T00:00:00Z"},
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

# ── The Windows installer's manifest (ISCC's OutputManifestFile) ─────────────
#
# The installer SBOM is made from the file list the Inno Setup compiler writes
# beside the installer, in the format of issrc is-6_7_3
# (Compiler.SetupCompiler.pas, CreateManifestFile; Shared.FileClass.pas,
# TTextFileWriter): UTF-8 with a byte order mark, CR LF after every line, one
# tab-separated row per packed file, the SHA-256 in lowercase hex. The fixture
# below is built in that format from the real yuzu-agent.iss's [Files] layout
# and the real hashes of fixture files. The release itself never reads the
# script; only these fixtures do.

# The build directory as the release's ISCC run is given it (/DBuildDir): a
# runner workspace path, on a drive the test machine does not have.
ISCC_BUILD_DIR = r"D:\a\Yuzu\Yuzu\build-windows"
INNO_HEADER = ("Index\tSourceFilename\tTimeStamp\tVersion\tSHA256Sum\tOriginalSize\tFirstSlice\tLastSlice\t"
               "StartOffset\tChunkSuboffset\tChunkCompressedSize\tEncrypted\tISSigKeyID")
# What the script's `{#BuildDir}\agents\core\*.dll` finds in a release build:
# the agent core and the vcpkg runtime DLLs scripts/deploy_build_dlls.py copies
# there. ISCC sorts a wildcard's matches by name.
CORE_DLLS = ("libcrypto-3-x64.dll", "libssl-3-x64.dll", "yuzu_agent_core.dll", "zlib1.dll")


def iss_sources() -> list:
    """The `{#BuildDir}`-relative Source of each [Files] line of the real
    yuzu-agent.iss that takes a file from the build directory, in order. A
    fixture input only: the release never parses the script, and a line of
    another shape is skipped here rather than failing the test."""
    text = (ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss").read_text(encoding="utf-8-sig")
    sources = re.findall(r'^Source: "\{#BuildDir\}\\([^"]+)";', text, re.M)
    assert len(sources) > 40, "yuzu-agent.iss no longer installs the plugins from {#BuildDir}"
    return sources


def make_inno_build(build: Path) -> list:
    """Fill `build` with the files the real yuzu-agent.iss packs from the build
    directory, and return [(build-relative Windows path, bytes)] in the order
    ISCC lists them: one row per source path (ISCC merges an entry naming a
    path already listed)."""
    rows, seen = [], set()
    for src in iss_sources():
        folder, name = src.rsplit("\\", 1)
        for n in (CORE_DLLS if name == "*.dll" else (name,)):
            rel = f"{folder}\\{n}"
            if rel.lower() in seen:
                continue
            seen.add(rel.lower())
            data = f"MZ\x90\x00 {rel}".encode()
            path = build.joinpath(*rel.split("\\"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            rows.append((rel, data))
    return rows


def inno_manifest_lines(rows, build_dir: str = ISCC_BUILD_DIR) -> list:
    """The lines (without CR LF) of the manifest ISCC writes for `rows`."""
    lines, offset = [INNO_HEADER], 0
    for i, (rel, data) in enumerate(rows):
        version = "0.15.0.0" if rel.startswith("agents\\core\\yuzu") else ""
        lines.append("\t".join((str(i), f"{build_dir}\\{rel}", f"2026-11-18 10:{i // 60:02d}:{i % 60:02d}.000",
                                version, hashlib.sha256(data).hexdigest(), str(len(data)), "1", "1", "0",
                                str(offset), "1048576", "no", "")))
        offset += len(data)
    return lines


def inno_manifest_bytes(lines) -> bytes:
    """`lines` as TTextFileWriter writes them: a UTF-8 byte order mark, then
    each line UTF-8 encoded and ended by CR LF."""
    return b"\xef\xbb\xbf" + "".join(ln + "\r\n" for ln in lines).encode("utf-8")


WIN_ZIP = {
    "yuzu-agent-1.2.3-windows-x64/bin/yuzu-agent.exe": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/bin/yuzu_agent_core.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/bin/libcrypto-3-x64.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/plugins/status.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/plugins/echo.dll": b"MZ",
    "yuzu-agent-1.2.3-windows-x64/plugins/omitted.dll": b"MZ",
}


def make_image_pair(title: str, files: list, version: str = "1.2.3", owned: tuple = ()) -> tuple:
    """A syft 1.57.2 image scan pair, in the shape of the release's real ones
    (v0.14.x chisel and server images): a `container` CycloneDX root with the
    OCI title label as a metadata property; an SPDX root with purpose CONTAINER
    and every file in `files`; CycloneDX lists a file only when a package owns
    it (`owned`, as syft's erlang classifier owns beam.smp), so an unpackaged
    yuzu-server appears in SPDX only."""
    name = f"ghcr.io/example/{title}"
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.7",
           "metadata": {"component": {"bom-ref": "daa5fd985d9b5998", "type": "container", "name": name,
                                      "version": version},
                        "properties": [{"name": "syft:image:labels:org.opencontainers.image.title",
                                        "value": title}]},
           "components": [{"bom-ref": "os", "type": "operating-system", "name": "ubuntu", "version": "26.04"}] +
                         [{"bom-ref": f"f{i}", "type": "file", "name": "/" + f} for i, f in enumerate(owned)]}
    root_id = "SPDXRef-DocumentRoot-Image-" + name.replace("/", "-")
    spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
            "packages": [{"name": name, "SPDXID": root_id, "versionInfo": version, "downloadLocation": "NOASSERTION",
                          "copyrightText": "NOASSERTION", "primaryPackagePurpose": "CONTAINER"}],
            "files": [{"fileName": f, "SPDXID": f"SPDXRef-File-{i}"} for i, f in enumerate(files)],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": root_id,
                               "relationshipType": "DESCRIBES"}]}
    return cdx, spdx


def force_mark(cdx: dict, spdx: dict, tokens: str, parts=("composition", "property", "relationship", "comment")):
    """Write (some parts of) an incomplete marker onto an image pair by hand,
    whatever the image holds: what mark-image would refuse to produce."""
    croot, sroot = cdx["metadata"]["component"], spdx["packages"][0]
    if "composition" in parts:
        cdx.setdefault("compositions", []).append({"aggregate": "incomplete", "assemblies": [croot["bom-ref"]]})
    if "property" in parts:
        cdx["metadata"]["properties"].append({"name": "yuzu:sbom:incomplete-reasons", "value": tokens})
    if "relationship" in parts:
        spdx["relationships"].append({"spdxElementId": sroot["SPDXID"], "relationshipType": "CONTAINS",
                                      "relatedSpdxElement": "NOASSERTION"})
    if "comment" in parts:
        sroot["comment"] = f"yuzu:sbom:incomplete-reasons: {tokens}"
    return cdx, spdx


SERVER_IMAGE_FILES = ["usr/bin/busybox", "usr/lib/x86_64-linux-gnu/libc.so.6", "usr/local/bin/yuzu-server"]
AGENT_IMAGE_FILES = ["usr/bin/busybox", "usr/local/bin/yuzu-agent", "usr/local/lib/libyuzu_agent_core.so",
                     "usr/lib/yuzu/plugins/status/status.so"]
GATEWAY_IMAGE_FILES = ["opt/yuzu_gw/erts-16.4.0.7/bin/beam.smp", "opt/yuzu_gw/erts-16.4.0.7/bin/erlexec",
                       "usr/bin/busybox"]
# syft 1.57.2 on ghcr.io/devnullltd/yuzu-postgres:0.14.1 (2026-11-18): vector.so
# is a file with no package (pgvector is built from source).
POSTGRES_IMAGE_FILES = ["usr/lib/postgresql/18/bin/postgres", "usr/lib/postgresql/18/lib/vector.so"]


def make_vcpkg_tree(root: Path, drop_spdx: str = "", no_licence: str = "", copyright_port: str = "") -> Path:
    inst = root / "vcpkg_installed"
    (inst / "vcpkg").mkdir(parents=True)
    (inst / "vcpkg" / "status").write_text(STATUS)
    for port, (lic, loc) in UPSTREAM.items():
        if port == drop_spdx:
            continue
        share = inst / TRIPLET / "share" / port
        share.mkdir(parents=True)
        # vcpkg writes copyrightText NOASSERTION on every port today.
        port_pkg = {"SPDXID": "SPDXRef-port", "name": port, "licenseConcluded": lic,
                    "homepage": f"https://example.invalid/{port}", "copyrightText": "NOASSERTION",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:vcpkg/{port}@x"}]}
        if port == copyright_port:
            port_pkg["copyrightText"] = f"Copyright (c) The {port} authors"
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

    # ── the installer manifest contract (ISCC's OutputManifestFile) ──
    def _inno(self, edit=None, mutate=None):
        """(manifest, build dir, rows): the realistic fixture. `edit(lines)`
        returns the manifest's lines, or its bytes, from ISCC's; `mutate(build)`
        changes the build directory after it is filled."""
        build = self.tmp / "build-windows"
        rows = make_inno_build(build)
        if mutate:
            mutate(build)
        out = inno_manifest_lines(rows)
        if edit:
            out = edit(out)
        manifest = self.tmp / "YuzuAgentSetup.manifest.txt"
        manifest.write_bytes(out if isinstance(out, bytes) else inno_manifest_bytes(out))
        return manifest, build, rows

    def _contents(self, manifest, build, inno_build_dir=ISCC_BUILD_DIR):
        dest = self.tmp / f"contents{len(list(self.tmp.glob('contents*')))}"
        dest.mkdir()
        return dest, self.mod.installer_contents(manifest, build, inno_build_dir, dest)

    def test_installer_manifest_in_the_iscc_format_is_read(self):
        manifest, build, rows = self._inno()
        # The script's header constant is the one issrc is-6_7_3 writes.
        self.assertEqual(self.mod.INNO_MANIFEST_HEADER, INNO_HEADER)
        self.assertTrue(manifest.read_bytes().startswith(b"\xef\xbb\xbfIndex\tSourceFilename\t"))
        dest, listed = self._contents(manifest, build)
        want = [rel.replace("\\", "/") for rel, _ in rows]
        self.assertEqual(listed, want)
        self.assertEqual(listed[:2], ["agents/core/yuzu-agent.exe", "agents/core/libcrypto-3-x64.dll"])
        self.assertIn("agents/core/yuzu_agent_core.dll", listed)
        self.assertGreater(sum(1 for p in listed if p.startswith("agents/plugins/")), 40)
        # Each file is copied, byte for byte, to its build-relative path, and
        # nothing else is.
        copied = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
        self.assertEqual(copied, sorted(want))
        for rel, data in rows:
            self.assertEqual(dest.joinpath(*rel.split("\\")).read_bytes(), data)

    def test_installer_manifest_paths_are_mapped_as_defined(self):
        m = self.mod
        b = ISCC_BUILD_DIR
        # Read as Windows paths: normalised (a `..` that stays inside is
        # resolved), drive and names compared case-insensitively, `/` as `\`.
        for source, parts in ((b + r"\agents\core\a.dll", ["agents", "core", "a.dll"]),
                              (b.lower() + r"\agents\a.dll", ["agents", "a.dll"]),
                              (b.replace("D:", "d:") + r"\a.dll", ["a.dll"]),
                              (b + r"\agents\..\agents\.\a.dll", ["agents", "a.dll"]),
                              (b + "/agents/a.dll", ["agents", "a.dll"]),
                              (b + r"\\agents\a.dll", ["agents", "a.dll"])):
            with self.subTest(source=source):
                self.assertEqual(m.inno_build_parts(source, b, "m"), parts)
        self.assertEqual(m.inno_build_parts(r"C:\b\x.dll", "C:\\b\\", "m"), ["x.dll"])
        # One path listed twice, in another case, with one hash, is one file
        # (ISCC merges such entries itself unless told not to).
        def dup(lines):
            row = lines[1].split("\t")
            return lines + ["\t".join([str(len(lines) - 1), row[1].upper()] + row[2:])]
        manifest, build, rows = self._inno(edit=dup)
        _dest, listed = self._contents(manifest, build)
        self.assertEqual(listed, [rel.replace("\\", "/") for rel, _ in rows])

    def test_installer_manifest_refusals(self):
        # Every refusal of the contract, each loud and naming the problem.
        # A manifest shape the contract refuses is an expected refusal, not a
        # finding (docs/ci-architecture.md, "The installer manifest contract").
        b = ISCC_BUILD_DIR
        outside = self.tmp / "outside"
        outside.mkdir()

        def row(n, col, value):
            def edit(lines):
                cols = lines[n].split("\t")
                cols[col] = value(cols[col]) if callable(value) else value
                return lines[:n] + ["\t".join(cols)] + lines[n + 1:]
            return edit

        def flip_byte(build):
            p = build / "agents" / "plugins" / "status" / "status.dll"
            data = bytearray(p.read_bytes())
            data[-1] ^= 0x01
            p.write_bytes(bytes(data))

        def link_out(build):
            p = build / "agents" / "plugins" / "status" / "status.dll"
            (outside / "status.dll").write_bytes(p.read_bytes())  # same bytes: only the link is wrong
            p.unlink()
            os.symlink(outside / "status.dll", p)

        def link_dir_out(build):
            d = build / "agents" / "plugins" / "echo"
            shutil.copytree(d, outside / "echo")
            shutil.rmtree(d)
            os.symlink(outside / "echo", d, target_is_directory=True)

        def to_dir(build):
            p = build / "agents" / "plugins" / "status" / "status.dll"
            p.unlink()
            p.mkdir()

        enc = lambda lines: inno_manifest_bytes(lines)  # noqa: E731
        cases = [
            # encoding and line ends
            ("no byte order mark", lambda ls: enc(ls)[3:], None, "does not start with one"),
            ("UTF-16", lambda ls: "".join(x + "\r\n" for x in ls).encode("utf-16"), None,
             "does not start with one"),
            ("not UTF-8 after the mark", lambda ls: enc(ls).replace(b"agents", b"ag\xe9nts", 1), None,
             "is not UTF-8"),
            ("LF line ends", lambda ls: b"\xef\xbb\xbf" + "".join(x + "\n" for x in ls).encode(), None,
             "does not end in CR LF"),
            ("one bare LF", lambda ls: enc(ls).replace(b"\r\n", b"\n", 2).replace(b"\n", b"\r\n", 1), None,
             "a CR or LF that is not part of a CR LF"),
            ("a bare CR", lambda ls: enc(ls).replace(b"\r\n", b"\r", 1), None,
             "a CR or LF that is not part of a CR LF"),
            ("no final CR LF", lambda ls: enc(ls)[:-2], None, "does not end in CR LF"),
            # header and shape
            ("header column renamed", lambda ls: [ls[0].replace("SHA256Sum", "SHA1Sum")] + ls[1:], None,
             "the header is not the one"),
            ("header column added", lambda ls: [ls[0] + "\tExtra"] + ls[1:], None, "the header is not the one"),
            ("header column dropped", lambda ls: [ls[0].rsplit("\t", 1)[0]] + ls[1:], None,
             "the header is not the one"),
            ("header in another case", lambda ls: [ls[0].lower()] + ls[1:], None, "the header is not the one"),
            ("zero rows", lambda ls: ls[:1], None, "no file rows"),
            ("an empty file after the mark", lambda ls: b"\xef\xbb\xbf", None, "does not end in CR LF"),
            ("extra column", lambda ls: ls[:3] + [ls[3] + "\tx"] + ls[4:], None, "14 tab-separated columns"),
            ("missing column", lambda ls: ls[:3] + [ls[3].rsplit("\t", 1)[0]] + ls[4:], None,
             "12 tab-separated columns"),
            ("a blank line at the end", lambda ls: ls + [""], None, "1 tab-separated columns"),
            ("Index out of sequence", lambda ls: [ls[0], ls[2], ls[1]] + ls[3:], None, "Index '1', not 0"),
            ("upper-case SHA-256", row(1, 4, str.upper), None, "64 lowercase hex digits"),
            ("short SHA-256", row(1, 4, lambda h: h[:-1]), None, "64 lowercase hex digits"),
            ("long SHA-256", row(1, 4, lambda h: h + "0"), None, "64 lowercase hex digits"),
            # paths
            ("`..` out of the build directory", row(1, 1, b + r"\..\outside\x.dll"), None,
             "not strictly inside the build directory"),
            ("`..` out at the end", row(1, 1, b + r"\agents\..\..\build-windowsx\a.dll"), None,
             "not strictly inside the build directory"),
            ("another drive", row(1, 1, lambda p: "E" + p[1:]), None, "not strictly inside the build directory"),
            ("a sibling with the build directory's name as a prefix", row(1, 1, lambda p: p.replace(
                "build-windows", "build-windows2", 1)), None, "not strictly inside the build directory"),
            ("the build directory itself", row(1, 1, b), None, "not strictly inside the build directory"),
            ("a UNC path", row(1, 1, lambda p: "\\\\runner\\share" + p[2:]), None,
             "not a drive-absolute Windows path"),
            ("a device path", row(1, 1, lambda p: "\\\\?\\" + p), None, "not a drive-absolute Windows path"),
            ("a relative path", row(1, 1, lambda p: p[len(b) + 1:]), None, "not a drive-absolute Windows path"),
            ("a drive-relative path", row(1, 1, lambda p: "D:" + p[len(b) + 1:]), None,
             "not a drive-absolute Windows path"),
            ("an NTFS stream", row(1, 1, lambda p: p + ":evil"), None, "holds a character Windows does not allow"),
            ("a trailing dot", row(1, 1, lambda p: p + "."), None, "ends in a dot or space"),
            ("a trailing space", row(1, 1, lambda p: p + " "), None, "ends in a dot or space"),
            ("one path, two hashes", lambda ls: ls + ["\t".join([str(len(ls) - 1), ls[1].split("\t")[1]] +
                                                               ls[2].split("\t")[2:])], None,
             "listed again with another SHA-256"),
            # the build directory
            ("a missing file", None, lambda d: (d / "agents" / "plugins" / "status" / "status.dll").unlink(),
             "is missing from the build directory"),
            ("a directory, not a file", None, to_dir, "is not a regular file"),
            ("a one-byte change", None, flip_byte, "not the file the installer holds"),
        ]
        if hasattr(os, "symlink") and self._can_symlink():
            cases += [("a symlink out of the build directory", None, link_out, "outside the build directory"),
                      ("a symlinked directory out of it", None, link_dir_out, "outside the build directory")]
        for what, edit, mutate, msg in cases:
            with self.subTest(what=what):
                shutil.rmtree(self.tmp / "build-windows", ignore_errors=True)
                for p in self.tmp.glob("contents*"):
                    shutil.rmtree(p)
                for p in outside.iterdir():
                    shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                manifest, build, _rows = self._inno(edit=edit, mutate=mutate)
                with self.assertRaises(self.mod.SbomError) as cm:
                    self._contents(manifest, build)
                self.assertIn(msg, str(cm.exception))
                self.assertTrue(str(cm.exception).startswith(("YuzuAgentSetup.manifest.txt", "--")),
                                str(cm.exception))
        # The build directory ISCC was given must itself be drive-absolute.
        shutil.rmtree(self.tmp / "build-windows")
        manifest, build, _rows = self._inno()
        for bad in ("build-windows", r"\a\build-windows", "D:build-windows"):
            with self.subTest(inno_build_dir=bad):
                with self.assertRaises(self.mod.SbomError) as cm:
                    self._contents(manifest, build, inno_build_dir=bad)
                self.assertIn("--inno-build-dir", str(cm.exception))

    def _can_symlink(self) -> bool:
        try:
            os.symlink(self.tmp, self.tmp / "probe-link", target_is_directory=True)
        except (OSError, NotImplementedError):
            return False
        (self.tmp / "probe-link").unlink()
        return True

    def test_release_feeds_the_installer_sbom_its_own_iscc_manifest(self):
        # yuzu-agent.iss asks ISCC for the manifest; release.yml's ISCC step
        # removes any old one first, checks this run wrote one, and copies it
        # beside the installer; the SBOM step passes that copy, with the same
        # build directory ISCC was given, and nothing reads the .iss itself.
        iss = (ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss").read_text(encoding="utf-8-sig")
        setup = iss.split("\n[Setup]\n", 1)[1].split("\n[", 1)[0].splitlines()
        self.assertIn("OutputManifestFile=YuzuAgentSetup.manifest.txt", setup)
        self.assertIn("OutputDir=output", setup)
        self.assertEqual(sum(1 for ln in iss.splitlines() if ln.startswith("OutputManifestFile=")), 1)
        wf = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        # Step names repeat across jobs (each build job has its own
        # "Generate per-artifact SBOMs"), so steps are a list, not a map.
        steps = [(s.split("\n", 1)[0].strip(), s) for s in wf.split("\n      - name: ")[1:]]
        iscc = [s for n, s in steps if n == "Build Windows installers (InnoSetup)"]
        gen = [s for _n, s in steps if "artifact-sbom.py generate --artifact $exe.Name" in s]
        self.assertEqual((len(iscc), len(gen)), (1, 1))
        iscc, gen = iscc[0], gen[0]
        out = r'"deploy\packaging\windows\output\YuzuAgentSetup.manifest.txt"'
        self.assertIn(f"$manifest = {out}", iscc)
        order = [iscc.index(x) for x in ('Remove-Item -Force -ErrorAction SilentlyContinue $manifest, '
                                         '"YuzuAgentSetup-${version}.manifest.txt"', "& $iscc",
                                         "if (-not (Test-Path $manifest))",
                                         'Copy-Item $manifest "YuzuAgentSetup-${version}.manifest.txt"')]
        self.assertEqual(order, sorted(order))
        self.assertIn('Copy-Item $agentInstaller "YuzuAgentSetup-${version}.exe"', iscc)
        build_dir = re.search(r'"/DBuildDir=([^"]+)"', iscc).group(1)
        self.assertIn('--inno-manifest "$($exe.BaseName).manifest.txt" --build-dir build-windows', gen)
        self.assertEqual(re.search(r'--inno-build-dir "([^"]+)"', gen).group(1), build_dir)
        self.assertTrue(build_dir.endswith("\\build-windows"))
        # Only the ISCC step writes the installer manifest; nothing passes the
        # retired arguments.
        writers = [n for n, s in steps if re.search(r"(Copy-Item|Move-Item|Set-Content|Out-File)[^\n]*"
                                                            r"manifest\.txt", s)]
        self.assertEqual(writers, ["Build Windows installers (InnoSetup)"])
        self.assertNotIn("--contents-from", wf)
        self.assertNotIn("--iss", wf)

    def test_pkg_staged_names_are_the_ones_build_pkg_stages(self):
        # The .pkg's payload names come from deploy/packaging/macos/build-pkg.sh,
        # not from pkgutil (which keeps payload names as they are), so the
        # fixture is checked against the script: each loose binary it stages
        # maps back to its installed name, counts as the agent, and is in the
        # fixture at the same payload path.
        script = (ROOT / "deploy" / "packaging" / "macos" / "build-pkg.sh").read_text(encoding="utf-8")
        staged = re.findall(r'record_loose_binary "\$\{STAGING\}/([^"]+)" (\S+)', script)
        self.assertEqual(len(staged), 2, staged)
        for rel, installed in staged:
            with self.subTest(rel=rel):
                base = rel.rsplit("/", 1)[-1]
                self.assertEqual(self.mod.installed_name(base), installed)
                self.assertTrue(installed in self.mod.AGENT_NAMES or installed.startswith(self.mod.AGENT_PREFIXES))
                self.assertIn(f"yuzu-agent-component.pkg/Payload/{rel}", PKG_EXPANDED)
        # Detection reads basenames only, so the directory layout pkgutil
        # writes cannot hide the agent.
        root = self.tmp / "anywhere"
        (root / "a" / "b").mkdir(parents=True)
        (root / "a" / "b" / staged[0][0].rsplit("/", 1)[-1]).write_bytes(b"x")
        self.assertEqual(self.mod.yuzu_binaries(root), (True, False))

    def test_reason_vocabulary_is_closed_and_documented(self):
        m = self.mod
        self.assertEqual(m.incomplete_notes([]), {})
        notes = m.incomplete_notes([("installer-runtime", ""), ("erts-static", "g/erts-16.4/bin/beam.smp")])
        self.assertEqual(notes["incomplete-reasons"], "installer-runtime, erts-static")
        self.assertIn(": g/erts-16.4/bin/beam.smp", notes["incomplete"])
        with self.assertRaises(m.SbomError):
            m.incomplete_notes([("something-new", "")])
        for token, prose in m.INCOMPLETE_REASONS.items():
            self.assertRegex(token, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
            self.assertNotIn(";", prose)  # the SPDX root comment separates notes with "; "
        doc = (ROOT / "docs" / "user-manual" / "release-verification.md").read_text(encoding="utf-8")
        section = doc.split("\n### Why an SBOM says it is incomplete\n", 1)[1].split("\n#", 1)[0]
        documented = re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M)
        self.assertEqual(sorted(documented), sorted(m.INCOMPLETE_REASONS))

    def test_tar_device_or_fifo_member_is_refused(self):
        for kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE):
            for data_filter in (True, False):
                with self.subTest(kind=kind, data_filter=data_filter):
                    art = self.tmp / "dev.tar.gz"
                    with tarfile.open(art, "w:gz") as tf:
                        tf.addfile(tarfile.TarInfo("y/bin/yuzu-agent"), io.BytesIO(b""))
                        info = tarfile.TarInfo("y/pipe")
                        info.type = kind
                        tf.addfile(info)
                    with self.assertRaises(self.mod.SbomError):
                        dest = self._extract(art, data_filter)
                    self.assertEqual(list(self.tmp.glob("d*/y/pipe")), [])

    def test_mark_image(self):
        m = self.mod
        cases = {
            "yuzu-server": (SERVER_IMAGE_FILES, (), ["server-vendored", "image-static-cpp"]),
            "yuzu-server-chisel": (SERVER_IMAGE_FILES, (), ["server-vendored", "image-static-cpp"]),
            "yuzu-agent-chisel": (AGENT_IMAGE_FILES, (), ["image-static-cpp"]),
            "yuzu-gateway": (GATEWAY_IMAGE_FILES, (GATEWAY_IMAGE_FILES[0],), ["erts-static"]),
            "yuzu-postgres": (POSTGRES_IMAGE_FILES, (), ["pgvector-source"]),
            # Not one of the release's labelled images, holding nothing known: untouched.
            "yuzu-agent-bundle": (["opt/yuzu-agents/yuzu-agent_1.2.3_amd64.deb"], (), []),
        }
        for title, (files, owned, want) in cases.items():
            with self.subTest(title=title):
                cdx, spdx = make_image_pair(title, files, owned=owned)
                tokens, changed = m.mark_image(cdx, spdx)
                self.assertEqual((tokens, changed), (want, bool(want)))
                root = cdx["metadata"]["component"]
                sroot = spdx["packages"][0]
                if want:
                    self.assertEqual(cdx["compositions"], [{"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}])
                    props = {p["name"]: p["value"] for p in cdx["metadata"]["properties"]}
                    self.assertEqual(props["yuzu:sbom:incomplete-reasons"], ", ".join(want))
                    self.assertIn({"spdxElementId": sroot["SPDXID"], "relationshipType": "CONTAINS",
                                   "relatedSpdxElement": "NOASSERTION"}, spdx["relationships"])
                    self.assertIn(f"yuzu:sbom:incomplete-reasons: {', '.join(want)}", sroot["comment"].split("\n"))
                    self.assertEqual(m.spdx_note(sroot["comment"], "incomplete-reasons"), ", ".join(want))
                    self.assertEqual(m.image_marker(cdx, spdx), (want, want))
                else:
                    self.assertNotIn("compositions", cdx)
                    self.assertNotIn("comment", sroot)
                # Idempotent: a second run changes nothing.
                before = json.dumps([cdx, spdx])
                self.assertEqual(m.mark_image(cdx, spdx), (want, False))
                self.assertEqual(json.dumps([cdx, spdx]), before)

    def test_mark_image_refuses(self):
        m = self.mod
        cdx, spdx = make_image_pair("yuzu-server", SERVER_IMAGE_FILES)
        _, other = make_image_pair("yuzu-server", SERVER_IMAGE_FILES, version="9.9.9")
        _, gateway = make_image_pair("yuzu-gateway", GATEWAY_IMAGE_FILES)
        unlabelled_server = make_image_pair("yuzu-server", ["usr/bin/busybox"])
        unlabelled_gateway = make_image_pair("yuzu-gateway-chisel", ["usr/bin/busybox"])
        unlabelled_postgres = make_image_pair("yuzu-postgres", ["usr/lib/postgresql/18/bin/postgres"])
        half = make_image_pair("yuzu-server", SERVER_IMAGE_FILES)
        m.mark_image(*half)
        cases = {
            "different versions": (cdx, other),
            "different images": (make_image_pair("yuzu-gateway", GATEWAY_IMAGE_FILES)[0], spdx),
            "server title, no yuzu-server": unlabelled_server,
            "gateway title, no beam.smp": unlabelled_gateway,
            "postgres title, no vector.so": unlabelled_postgres,
            "only the CycloneDX marked": (half[0], make_image_pair("yuzu-server", SERVER_IMAGE_FILES)[1]),
            "only the SPDX marked": (make_image_pair("yuzu-server", SERVER_IMAGE_FILES)[0], half[1]),
            "an artifact SBOM": ({"bomFormat": "CycloneDX", "metadata": {"component": {"type": "application"}}},
                                 spdx),
        }
        for what, (c, s) in cases.items():
            with self.subTest(what=what):
                with self.assertRaises(m.SbomError):
                    m.mark_image(c, s)
        # Partly marked (one part of the marker missing from one document):
        # never "already marked", never completed in place.
        full = ("composition", "property", "relationship", "comment")
        for missing in full:
            with self.subTest(missing=missing):
                c, s = force_mark(*make_image_pair("yuzu-server", SERVER_IMAGE_FILES),
                                  "server-vendored, image-static-cpp", tuple(x for x in full if x != missing))
                self.assertIn(m.PARTIAL, m.image_marker(c, s))
                with self.assertRaises(m.SbomError) as cm:
                    m.mark_image(c, s)
                self.assertIn("only in part", str(cm.exception))
        # Part of a marker on a pair that needs none: refused, not left as it is.
        for part in full:
            with self.subTest(nothing_to_mark=part):
                c, s = force_mark(*make_image_pair("yuzu-other", ["usr/bin/busybox"]), "server-vendored", (part,))
                with self.assertRaises(m.SbomError) as cm:
                    m.mark_image(c, s)
                self.assertIn("only in part", str(cm.exception))
        # Marked for other reasons: refused, not re-marked.
        c, s = make_image_pair("yuzu-agent", AGENT_IMAGE_FILES)
        m.mark_image(c, s)
        s["files"].append({"fileName": "usr/local/bin/yuzu-server", "SPDXID": "SPDXRef-File-x"})
        with self.assertRaises(m.SbomError):
            m.mark_image(c, s)

    def test_mark_image_keeps_the_scans_own_spdx_comment(self):
        # syft may write a comment on the image root; the marker's note lines
        # are added after it, never written over it (p4-qe-2, w3).
        m = self.mod
        cdx, spdx = make_image_pair("yuzu-server", SERVER_IMAGE_FILES)
        spdx["packages"][0]["comment"] = "scanned by syft"
        m.mark_image(cdx, spdx)
        lines = spdx["packages"][0]["comment"].split("\n")
        self.assertEqual(lines[0], "scanned by syft")
        self.assertIn("yuzu:sbom:incomplete-reasons: server-vendored, image-static-cpp", lines[1:])
        self.assertEqual(m.image_marker(cdx, spdx), (["server-vendored", "image-static-cpp"],) * 2)

    def test_a_note_written_twice_is_refused(self):
        # The script writes each note once; a second copy is ambiguous (the
        # documented recipe prints both), so every reader refuses it rather
        # than pick one (p4-qe-2, r3).
        m = self.mod
        with self.assertRaises(m.SbomError):
            m.spdx_note("yuzu:sbom:incomplete-reasons: a\nyuzu:sbom:incomplete-reasons: b", "incomplete-reasons")
        with self.assertRaises(m.SbomError):
            m.cdx_note({"properties": [{"name": "yuzu:sbom:unpacked-files", "value": "1"},
                                       {"name": "yuzu:sbom:unpacked-files", "value": "2"}]}, "unpacked-files")
        self.assertEqual(m.cdx_note({"properties": [{"name": "yuzu:sbom:unpacked-files", "value": "2"}]},
                                    "unpacked-files"), "2")
        self.assertIsNone(m.cdx_note({}, "unpacked-files"))
        # Through the release gate and mark-image: a duplicated reason line
        # or property fails, whichever copy would have matched.
        for dup in ("cdx", "spdx"):
            with self.subTest(dup=dup):
                cdx, spdx = make_image_pair("yuzu-server", SERVER_IMAGE_FILES)
                m.mark_image(cdx, spdx)
                if dup == "cdx":
                    cdx["metadata"]["properties"].append({"name": "yuzu:sbom:incomplete-reasons",
                                                          "value": "server-vendored, image-static-cpp"})
                else:
                    spdx["packages"][0]["comment"] += "\nyuzu:sbom:incomplete-reasons: server-vendored, image-static-cpp"
                with self.assertRaises(m.SbomError) as cm:
                    m.image_marker(cdx, spdx)
                self.assertIn("appears 2 times", str(cm.exception))
                adir = self.tmp / f"dup-{dup}"
                adir.mkdir()
                (adir / "yuzu-server-image.cdx.json").write_text(json.dumps(cdx))
                (adir / "yuzu-server-image.spdx.json").write_text(json.dumps(spdx))
                errs = m.image_pair_errors(adir)
                self.assertEqual(len(errs), 1, errs)
                self.assertIn("appears 2 times", errs[0])
        doc = {"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "x"}],
               "metadata": {"component": {"name": "a.tar.gz"},
                            "properties": [{"name": "yuzu:sbom:unpacked-files", "value": "1"}] * 2}}
        path = self.tmp / "a.cdx.json"
        path.write_text(json.dumps(doc))
        self.assertEqual(m.check_file(path, None, 400),
                         ["a.cdx.json: note yuzu:sbom:unpacked-files appears 2 times in the CycloneDX metadata "
                          "properties"])

    def test_schema_validation_is_not_vacuous(self):
        # The validators the generate tests use are the vendored CycloneDX 1.7
        # and SPDX 2.3 schemas, and they reject what those schemas forbid.
        if schema_errors({"bomFormat": "CycloneDX"}) is None:
            self.skipTest("jsonschema is not importable (YUZU_REQUIRE_JSONSCHEMA=1 makes this a failure)")
        cdx_v, spdx_v = sbom_validators()
        self.assertEqual(cdx_v.schema["$id"], "http://cyclonedx.org/schema/bom-1.7.schema.json")
        self.assertEqual(spdx_v.schema["title"], "SPDX 2.3")
        good_cdx = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
                    "metadata": {"component": {"bom-ref": "a", "type": "application", "name": "a.tar.gz"}},
                    "compositions": [{"aggregate": "incomplete", "assemblies": ["a"]}]}
        good_spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "a",
                     "creationInfo": {"created": "2026-11-18T00:00:00Z", "creators": ["Tool: x"]},
                     "packages": [{"SPDXID": "SPDXRef-a", "name": "a", "downloadLocation": "NOASSERTION"}]}
        self.assertEqual(schema_errors(good_cdx), [])
        self.assertEqual(schema_errors(good_spdx), [])
        bad = {
            "cdx: unknown aggregate": dict(good_cdx, compositions=[{"aggregate": "mostly"}]),
            "cdx: component without a name": dict(good_cdx, components=[{"type": "library"}]),
            "spdx: no creationInfo": {k: v for k, v in good_spdx.items() if k != "creationInfo"},
            "spdx: file without checksums": dict(good_spdx, files=[{"SPDXID": "SPDXRef-f", "fileName": "f"}]),
            "spdx: unknown relationship": dict(good_spdx, relationships=[
                {"spdxElementId": "SPDXRef-a", "relationshipType": "HOLDS", "relatedSpdxElement": "NOASSERTION"}]),
        }
        for what, doc in bad.items():
            with self.subTest(what=what):
                self.assertTrue(schema_errors(doc))

    def test_spdx_notes_are_one_line_each(self):
        m = self.mod
        comment = m.spdx_notes_comment({"artifact": "a.tar.gz", "contents": "x; y: z", "incomplete-reasons": "a, b"})
        self.assertEqual(comment.split("\n"), ["yuzu:sbom:artifact: a.tar.gz", "yuzu:sbom:contents: x; y: z",
                                               "yuzu:sbom:incomplete-reasons: a, b"])
        self.assertEqual(m.spdx_note(comment, "contents"), "x; y: z")
        self.assertEqual(m.spdx_note(comment, "incomplete-reasons"), "a, b")
        self.assertIsNone(m.spdx_note(comment, "incomplete"))
        self.assertIsNone(m.spdx_note("contents: x", "contents"))  # only the prefixed key
        # A line break in a value would end its line early and could forge a note.
        for brk in ("\n", "\r", "\x0b", "\x0c", "\x85", "\u2028"):
            with self.subTest(brk=brk), self.assertRaises(m.SbomError):
                m.spdx_notes_comment({"contents": f"a.dll{brk}yuzu:sbom:incomplete-reasons: x"})

    def test_erts_emulator_is_found_by_its_exact_name(self):
        root = self.tmp / "g"
        for rel in ("erts-16.4/bin/xbeam.smp", "erts-16.4/bin/beam.smp.bak", "lib/beam.smp/x.app"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(b"x")
        self.assertEqual(self.mod.erts_emulators(root), [])
        (root / "erts-16.4/bin/beam.smp").write_bytes(b"x")
        self.assertEqual(self.mod.erts_emulators(root), ["erts-16.4/bin/beam.smp"])
        # The image rule reads the same exact basename.
        with self.assertRaises(self.mod.SbomError):
            self.mod.mark_image(*make_image_pair("yuzu-gateway", ["opt/yuzu_gw/erts-16.4/bin/xbeam.smp"]))

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

    def test_check_entry_bound_boundary(self):
        # The default bound, at its edge, in both formats: 400 entries pass and
        # 401 fail. The real v0.15.0 Windows archive, the largest asset,
        # measured 212.
        self.assertEqual(load_script().MAX_COMPONENTS, 400)
        for n, ok in ((212, True), (400, True), (401, False)):
            with self.subTest(n=n, fmt="cdx"):
                f = self.tmp / "yuzu-linux-x64.cdx.json"
                f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
                    {"type": "library", "name": f"p{i}", "version": "1"} for i in range(n)]}))
                r = run_script("check", f)
                self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)
                self.assertEqual("more than the bound of 400" in r.stderr, not ok)
            with self.subTest(n=n, fmt="spdx"):
                # SPDX counts packages and files, the described root excluded.
                g = self.tmp / "yuzu-linux-x64.spdx.json"
                root = {"name": "a", "SPDXID": "SPDXRef-R"}
                pkgs = [{"name": f"p{i}", "SPDXID": f"SPDXRef-P{i}"} for i in range(n // 2)]
                files = [{"fileName": f"y/f{i}", "SPDXID": f"SPDXRef-F{i}"} for i in range(n - n // 2)]
                g.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [root] + pkgs, "files": files,
                                         "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                                                            "relationshipType": "DESCRIBES",
                                                            "relatedSpdxElement": "SPDXRef-R"}]}))
                r = run_script("check", g)
                self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)

    def test_mark_image_command(self):
        cdx, spdx = make_image_pair("yuzu-server-chisel", SERVER_IMAGE_FILES)
        c = self.tmp / "yuzu-server-chisel-image.cdx.json"
        s = self.tmp / "yuzu-server-chisel-image.spdx.json"
        c.write_text(json.dumps(cdx))
        s.write_text(json.dumps(spdx))
        r = run_script("mark-image", "--cdx", c, "--spdx", s)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("marked incomplete (server-vendored, image-static-cpp)", r.stdout)
        once = (c.read_bytes(), s.read_bytes())
        r = run_script("mark-image", "--cdx", c, "--spdx", s)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already marked", r.stdout)
        self.assertEqual((c.read_bytes(), s.read_bytes()), once)
        # A mismatched pair fails closed and leaves both files as they were.
        _, other = make_image_pair("yuzu-server-chisel", SERVER_IMAGE_FILES, version="9.9.9")
        s2 = self.tmp / "x-image.spdx.json"
        s2.write_text(json.dumps(other))
        c2 = self.tmp / "x-image.cdx.json"
        c2.write_text(json.dumps(make_image_pair("yuzu-server-chisel", SERVER_IMAGE_FILES)[0]))
        before = (c2.read_bytes(), s2.read_bytes())
        r = run_script("mark-image", "--cdx", c2, "--spdx", s2)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("describe different images", r.stderr)
        self.assertEqual((c2.read_bytes(), s2.read_bytes()), before)
        r = run_script("mark-image", "--cdx", c, "--spdx", s2)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("are not one image's pair", r.stderr)
        r = run_script("mark-image", "--cdx", self.tmp / "yuzu-linux-x64.cdx.json", "--spdx", s)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(list(self.tmp.glob("*.mark.tmp")), [])

    def test_check_dir_gates_image_markers(self):
        # Every image pair in the release directory must carry the marker
        # mark-image would add: a dropped mark-image step fails the release.
        pairs = {"yuzu-server-image": make_image_pair("yuzu-server", SERVER_IMAGE_FILES),
                 "yuzu-gateway-chisel-image": make_image_pair("yuzu-gateway-chisel", GATEWAY_IMAGE_FILES,
                                                              owned=(GATEWAY_IMAGE_FILES[0],)),
                 "yuzu-postgres-image": make_image_pair("yuzu-postgres", POSTGRES_IMAGE_FILES),
                 "yuzu-other-image": make_image_pair("yuzu-other", ["usr/bin/busybox"])}

        def write(mark):
            for stem, (cdx, spdx) in pairs.items():
                cdx, spdx = json.loads(json.dumps(cdx)), json.loads(json.dumps(spdx))
                if mark:
                    load_script().mark_image(cdx, spdx)
                (self.tmp / f"{stem}.cdx.json").write_text(json.dumps(cdx))
                (self.tmp / f"{stem}.spdx.json").write_text(json.dumps(spdx))

        # One artifact and its SBOM, so the run reaches the image gate.
        art = self.tmp / "yuzu-plugins-linux-x64.tar.gz"
        art.write_bytes(b"plugins")
        (self.tmp / "yuzu-plugins-linux-x64.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "components": [], "metadata": {
                "component": {"name": art.name, "hashes": [{"alg": "SHA-256",
                                                            "content": hashlib.sha256(b"plugins").hexdigest()}]},
                "properties": [{"name": "yuzu:sbom:unpacked-files", "value": "2"}]}}))
        write(mark=True)
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("4 image SBOM pair(s), OK", r.stdout)
        write(mark=False)
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("yuzu-server-image: the image holds what its SBOM cannot list "
                      "(server-vendored, image-static-cpp)", r.stderr)
        self.assertIn("yuzu-gateway-chisel-image: the image holds what its SBOM cannot list (erts-static)", r.stderr)
        self.assertIn("yuzu-postgres-image: the image holds what its SBOM cannot list (pgvector-source)", r.stderr)
        self.assertNotIn("yuzu-other-image:", r.stderr)
        (self.tmp / "yuzu-other-image.spdx.json").unlink()
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertIn("yuzu-other-image: only cdx.json", r.stderr)

    def test_check_dir_refuses_a_wrong_image_marker(self):
        # Each case alone in an otherwise passing release directory.
        art = self.tmp / "yuzu-plugins-linux-x64.tar.gz"
        art.write_bytes(b"plugins")
        (self.tmp / "yuzu-plugins-linux-x64.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "components": [], "metadata": {
                "component": {"name": art.name, "hashes": [{"alg": "SHA-256",
                                                            "content": hashlib.sha256(b"plugins").hexdigest()}]},
                "properties": [{"name": "yuzu:sbom:unpacked-files", "value": "2"}]}}))
        tokens = "server-vendored, image-static-cpp"
        no_label = make_image_pair("yuzu-server-chisel", ["usr/bin/busybox"])
        del no_label[0]["metadata"]["properties"]
        agent_as_gateway = make_image_pair("yuzu-agent", AGENT_IMAGE_FILES)
        load_script().mark_image(*agent_as_gateway)
        cases = {
            # Marked for something the image is not seen to hold.
            "yuzu-other": (force_mark(*make_image_pair("yuzu-other", ["usr/bin/busybox"]), "server-vendored"),
                           "marked incomplete (server-vendored / server-vendored) for nothing the image is seen"),
            # Part of a marker on an image that needs none (p4-qe-2, p5): still
            # "marked for nothing", never read as unmarked.
            **{f"yuzu-other-{part}": (force_mark(*make_image_pair(f"yuzu-other-{part}", ["usr/bin/busybox"]),
                                                 "server-vendored", (part,)),
                                      "for nothing the image is seen to hold")
               for part in ("composition", "property", "relationship", "comment")},
            # Every part but one: the reason tokens without the composition.
            "yuzu-server": (force_mark(*make_image_pair("yuzu-server", SERVER_IMAGE_FILES), tokens,
                                       ("property", "relationship", "comment")), "is marked only in part"),
            # The SPDX relationship without its comment line.
            "yuzu-server-chisel": (force_mark(*make_image_pair("yuzu-server-chisel", SERVER_IMAGE_FILES), tokens,
                                              ("composition", "property", "relationship")), "/ only in part"),
            # Named as a release image, with no title label: the marker it
            # needs is keyed on the label, so it cannot pass unmarked.
            "yuzu-agent-chisel": (no_label, "carries no title label"),
            # Named as one release image, labelled as another.
            "yuzu-gateway": (agent_as_gateway, "its title label is 'yuzu-agent'"),
        }
        for title, ((cdx, spdx), msg) in cases.items():
            with self.subTest(title=title):
                for old in self.tmp.glob("*-image.*.json"):
                    old.unlink()
                (self.tmp / f"{title}-image.cdx.json").write_text(json.dumps(cdx))
                (self.tmp / f"{title}-image.spdx.json").write_text(json.dumps(spdx))
                r = run_script("check", "--artifacts-dir", self.tmp)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn(f"{title}-image: ", r.stderr)
                self.assertIn(msg, r.stderr)
        # The same pairs, marked properly, pass.
        for old in self.tmp.glob("*-image.*.json"):
            old.unlink()
        cdx, spdx = make_image_pair("yuzu-server", SERVER_IMAGE_FILES)
        load_script().mark_image(cdx, spdx)
        (self.tmp / "yuzu-server-image.cdx.json").write_text(json.dumps(cdx))
        (self.tmp / "yuzu-server-image.spdx.json").write_text(json.dumps(spdx))
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_release_marks_every_yuzu_image_sbom(self):
        # release.yml runs mark-image on the image SBOM pair of each job that
        # publishes a release image (the release check above is the backstop;
        # this fails in PR CI instead).
        wf = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for stem in ("yuzu-${{ matrix.image }}-image", "yuzu-postgres-image", "yuzu-${{ matrix.image }}-chisel-image"):
            with self.subTest(stem=stem):
                self.assertIn(f"SBOM: {stem}\n        run: python3 scripts/ci/artifact-sbom.py mark-image "
                              f'--cdx "$SBOM.cdx.json" --spdx "$SBOM.spdx.json"', wf)

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
        root = {"name": "a", "SPDXID": "SPDXRef-R", "comment": "yuzu:sbom:artifact: a\nyuzu:sbom:unpacked-files: 29"}
        g.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [root], "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-R"}]}))
        r = run_script("check", g)
        self.assertEqual(r.returncode, 0, r.stderr)
        root["comment"] = "yuzu:sbom:artifact: a\nyuzu:sbom:unpacked-files: 0"
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
        r = run_script(*args, *extra, env=env)
        if r.returncode == 0:
            # Every SBOM pair generate writes is valid CycloneDX 1.7 and SPDX 2.3.
            stem = load_script().artifact_stem(Path(artifact).name)
            for fmt in ("cdx.json", "spdx.json"):
                doc = json.loads((self.out / f"{stem}.{fmt}").read_text(encoding="utf-8"))
                errs = schema_errors(doc)
                self.assertFalse(errs, f"{stem}.{fmt} fails its schema: {errs[:5] if errs else errs}")
        return r

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
        self.assertNotIn("yuzu:sbom:incomplete-reasons", self.props(cdx))
        # vcpkg records no copyright text: NOASSERTION, never a made-up one.
        self.assertNotIn("copyright", by["openssl"])
        ssl = next(p for p in spdx["packages"] if p["name"] == "openssl")
        self.assertEqual(ssl["copyrightText"], "NOASSERTION")

    def test_copyright_text_is_carried_from_vcpkg(self):
        make_vcpkg_tree(self.tmp, copyright_port="zlib")
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        r = self.generate(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, spdx = self.load("yuzu-linux-x64")
        self.assertEqual(next(c for c in cdx["components"] if c["name"] == "zlib")["copyright"],
                         "Copyright (c) The zlib authors")
        self.assertEqual(next(p for p in spdx["packages"] if p["name"] == "zlib")["copyrightText"],
                         "Copyright (c) The zlib authors")

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
        self.assertIn("\nyuzu:sbom:incomplete: yuzu-server compiles in vendored C++", root_pkg["comment"])
        self.assertEqual(self.props(cdx)["yuzu:sbom:incomplete-reasons"], "server-vendored")
        self.assertIn("yuzu:sbom:incomplete-reasons: server-vendored", root_pkg["comment"].split("\n"))

    def test_gateway_is_marked_incomplete_for_the_erlang_runtime(self):
        # The gateway bundles ERTS; its emulator beam.smp links in code it
        # vendors (PCRE2, asmjit, zstd, Ryu, OpenSSL's MD5) that syft, listing
        # one `erlang` component, does not list. Checked on the v0.15.0
        # gateway tarball's erts-16.4.0.7/bin/beam.smp on 2026-11-18.
        art = make_tar(self.tmp / "yuzu-gateway-linux-x64.tar.gz",
                       {"g/erts-16.4.0.7/bin/beam.smp": b"\x7fELF", "g/erts-16.4.0.7/bin/erlexec": b"\x7fELF",
                        "g/lib/kernel-10.6/ebin/kernel.app": b"x"})
        r = self.generate(art, vcpkg=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, spdx = self.load("yuzu-gateway-linux-x64")
        root_ref = cdx["metadata"]["component"]["bom-ref"]
        self.assertEqual(cdx["compositions"], [{"aggregate": "incomplete", "assemblies": [root_ref]}])
        props = self.props(cdx)
        self.assertEqual(props["yuzu:sbom:incomplete-reasons"], "erts-static")
        for vendored in ("PCRE2", "asmjit", "zstd", "Ryu"):
            self.assertIn(vendored, props["yuzu:sbom:incomplete"])
        self.assertIn("g/erts-16.4.0.7/bin/beam.smp", props["yuzu:sbom:incomplete"])
        root_pkg = next(p for p in spdx["packages"] if p["SPDXID"].startswith("SPDXRef-DocumentRoot"))
        self.assertIn({"spdxElementId": root_pkg["SPDXID"], "relationshipType": "CONTAINS",
                       "relatedSpdxElement": "NOASSERTION"}, spdx["relationships"])
        self.assertIn("yuzu:sbom:incomplete-reasons: erts-static", root_pkg["comment"].split("\n"))
        r = self.check_dir(art)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

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

    def test_rpm2cpio_failure_fails_the_run(self):
        # A truncated .rpm: rpm2cpio writes part of the payload, which cpio
        # unpacks and exits 0 on, then rpm2cpio exits non-zero. Its exit code
        # is the only signal, so it must fail the run rather than describe a
        # partial tree as the package.
        if not shutil.which("cpio"):
            self.skipTest("cpio not installed")
        make_vcpkg_tree(self.tmp)
        stubs = self.tmp / "bin"
        stubs.mkdir()
        write_exe(stubs / "rpm2cpio", '#!/bin/sh\ncat "$1"\necho "rpm2cpio: payload truncated" >&2\nexit 1\n')
        stage = self.tmp / "stage"
        (stage / "usr" / "bin").mkdir(parents=True)
        (stage / "usr" / "bin" / "yuzu-server").write_bytes(b"\x7fELF")
        rel = self.tmp / "rel"
        rel.mkdir()
        rpm = rel / "yuzu-server-1.2.3-1.x86_64.rpm"
        with open(rpm, "wb") as f:
            subprocess.run(["cpio", "-o", "-H", "newc", "--quiet"], input=b"./usr/bin/yuzu-server\n",
                           cwd=stage, stdout=f, check=True)
        r = self.generate(rpm, env={"PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("::error::yuzu-server-1.2.3-1.x86_64.rpm: rpm2cpio|cpio failed (rpm2cpio exited 1, cpio exited 0): "
                      "rpm2cpio: payload truncated", r.stderr)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_cpio_failure_fails_the_run(self):
        # The other side of the pipe (p4-qe-1): rpm2cpio succeeds, cpio exits
        # non-zero (a corrupt payload, a full disk). Its exit code alone must
        # fail the run.
        make_vcpkg_tree(self.tmp)
        stubs = self.tmp / "bin"
        stubs.mkdir()
        write_exe(stubs / "rpm2cpio", '#!/bin/sh\nexec cat "$1"\n')
        write_exe(stubs / "cpio", '#!/bin/sh\ncat >/dev/null\necho "cpio: premature end of archive" >&2\nexit 2\n')
        rel = self.tmp / "rel"
        rel.mkdir()
        rpm = rel / "yuzu-server-1.2.3-1.x86_64.rpm"
        rpm.write_bytes(b"not a cpio archive")
        r = self.generate(rpm, env={"PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("::error::yuzu-server-1.2.3-1.x86_64.rpm: rpm2cpio|cpio failed (rpm2cpio exited 0, cpio exited 2): "
                      "cpio: premature end of archive", r.stderr)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_every_documented_note_reads_the_same_from_both_formats(self):
        # The docs tell a script to read the `yuzu:sbom:` notes, and give a
        # command for each format. Generate SBOMs carrying every reason token
        # (a server archive, a gateway archive, the installer, and the four
        # kinds of marked image), then read
        # each documented note from both formats: the CycloneDX property and
        # the SPDX comment line must agree, the marker must agree with the
        # note, and the docs' own commands, run as written, must find it.
        mod = load_script()
        docs = "".join((ROOT / "docs" / "user-manual" / n).read_text(encoding="utf-8")
                       for n in ("release-verification.md", "upgrading.md"))
        documented = set(re.findall(r"yuzu:sbom:[a-z][a-z-]*[a-z]", docs))
        self.assertTrue({"yuzu:sbom:incomplete-reasons", "yuzu:sbom:incomplete", "yuzu:sbom:contents",
                         "yuzu:sbom:licence-noassertion"} <= documented, documented)
        make_vcpkg_tree(self.tmp, no_licence="zlib")
        rel = self.tmp / "rel"
        rel.mkdir()
        server = make_tar(rel / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-server": b"x", "y/bin/yuzu-agent": b"x"})
        gateway = make_tar(rel / "yuzu-gateway-linux-x64.tar.gz",
                           {"g/erts-16.4/bin/beam.smp": b"x", "g/lib/kernel-10.6/ebin/kernel.app": b"x"})
        zip_path = make_zip(rel / "yuzu-agent-windows-x64.zip", WIN_ZIP)
        build = self.tmp / "build-windows"
        manifest = self.tmp / "YuzuAgentSetup-1.2.3.manifest.txt"
        manifest.write_bytes(inno_manifest_bytes(inno_manifest_lines(make_inno_build(build))))
        exe = rel / "YuzuAgentSetup-1.2.3.exe"
        exe.write_bytes(b"MZ installer")
        for art, vcpkg, extra in ((server, True, ()), (gateway, False, ()), (zip_path, True, ()),
                                  (exe, True, ("--inno-manifest", manifest, "--build-dir", build, "--inno-build-dir", ISCC_BUILD_DIR))):
            r = self.generate(art, vcpkg=vcpkg, extra=extra)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for title, files, owned in (("yuzu-server", SERVER_IMAGE_FILES, ()),
                                    ("yuzu-agent-chisel", AGENT_IMAGE_FILES, ()),
                                    ("yuzu-gateway-chisel", GATEWAY_IMAGE_FILES, (GATEWAY_IMAGE_FILES[0],)),
                                    ("yuzu-postgres", POSTGRES_IMAGE_FILES, ())):
            cdx, spdx = make_image_pair(title, files, owned=owned)
            mod.mark_image(cdx, spdx)
            (self.out / f"{title}-image.cdx.json").write_text(json.dumps(cdx))
            (self.out / f"{title}-image.spdx.json").write_text(json.dumps(spdx))
        stems = sorted({p.name[: -len(".cdx.json")] for p in self.out.glob("*.cdx.json")})
        self.assertEqual(len(stems), 8, stems)
        notes, tokens, emitted = {}, set(), set()
        for stem in stems:
            with self.subTest(stem=stem):
                cdx, spdx = self.load(stem)
                cprops = {p["name"]: p["value"] for p in cdx["metadata"].get("properties", [])
                          if p["name"].startswith("yuzu:sbom:")}
                sroot = mod._spdx_root(spdx)
                slines = dict(line.split(": ", 1) for line in (sroot.get("comment") or "").split("\n")
                              if line.startswith("yuzu:sbom:"))
                self.assertEqual(slines, cprops)
                marked_c = any(c.get("aggregate") == "incomplete" for c in cdx.get("compositions", []))
                marked_s = {"spdxElementId": sroot["SPDXID"], "relationshipType": "CONTAINS",
                            "relatedSpdxElement": "NOASSERTION"} in spdx["relationships"]
                has_reasons = "yuzu:sbom:incomplete-reasons" in cprops
                self.assertEqual((marked_c, marked_s), (has_reasons, has_reasons))
                tokens |= set(mod._reason_tokens(cprops.get("yuzu:sbom:incomplete-reasons")))
                emitted |= set(cprops)
                notes[stem] = cprops
        self.assertEqual(tokens, set(mod.INCOMPLETE_REASONS))
        # The docs name no note the release does not write.
        self.assertEqual(documented - emitted, set())
        # The docs' recipe, as written, with only KEY and the file names
        # changed: the CycloneDX command, then the SPDX one.
        doc = (ROOT / "docs" / "user-manual" / "release-verification.md").read_text(encoding="utf-8")
        block = next(b for b in re.findall(r"```bash\n(.*?)```", doc, re.S)
                     if b.startswith("KEY=yuzu:sbom:incomplete-reasons\n") and 'sed -n "s/^$KEY: //p"' in b)
        self.assertIn("yuzu-gateway-linux-x64.cdx.json", block)
        self.assertIn("yuzu-gateway-linux-x64.spdx.json", block)
        if not (shutil.which("jq") and shutil.which("bash") and shutil.which("sed")):
            self.skipTest("jq, bash or sed not installed: the docs' extraction commands were not run")
        for stem in stems:
            for key in sorted(documented | {"yuzu:sbom:incomplete-reasons"}):
                with self.subTest(stem=stem, key=key):
                    script = block.replace("KEY=yuzu:sbom:incomplete-reasons", f"KEY={key}", 1)
                    script = script.replace("yuzu-gateway-linux-x64", stem)
                    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], cwd=self.out,
                                       capture_output=True, text=True)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    value = notes[stem].get(key)
                    self.assertEqual(r.stdout, "" if value is None else f"{value}\n{value}\n")

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

    def test_installer_lists_what_its_compiler_manifest_lists(self):
        make_vcpkg_tree(self.tmp)
        rel = self.tmp / "rel"
        rel.mkdir()
        build = self.tmp / "build-windows"
        rows = make_inno_build(build)
        # A file in the build directory the manifest does not list is not
        # described: the installer does not hold it.
        (build / "agents" / "plugins" / "omitted").mkdir(parents=True)
        (build / "agents" / "plugins" / "omitted" / "omitted.dll").write_bytes(b"MZ omitted")
        manifest = self.tmp / "YuzuAgentSetup-1.2.3_rc1.manifest.txt"
        manifest.write_bytes(inno_manifest_bytes(inno_manifest_lines(rows)))
        exe = rel / "YuzuAgentSetup-1.2.3_rc1.exe"
        exe.write_bytes(b"MZ installer")
        inno = ("--inno-manifest", manifest, "--build-dir", build, "--inno-build-dir", ISCC_BUILD_DIR)
        r = self.generate(exe, extra=inno, env={"STUB_SYFT_FILES": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cdx, spdx = self.load("YuzuAgentSetup-1.2.3_rc1")
        self.assertEqual(cdx["metadata"]["component"]["name"], exe.name)
        self.assertEqual(cdx["metadata"]["component"]["hashes"][0]["content"],
                         hashlib.sha256(exe.read_bytes()).hexdigest())
        self.assertEqual(self.vcpkg_names(cdx), AGENT_PORTS)
        # The files syft was shown are the manifest's, at their build-relative
        # paths, with the bytes the manifest's hashes name.
        files = {f["fileName"]: next(c["checksumValue"] for c in f["checksums"] if c["algorithm"] == "SHA256")
                 for f in spdx["files"]}
        self.assertEqual(files, {r.replace("\\", "/"): hashlib.sha256(d).hexdigest() for r, d in rows})
        props = self.props(cdx)
        self.assertEqual(props["yuzu:sbom:unpacked-files"], str(len(rows)))
        self.assertIn(f"the {len(rows)} file(s) the Inno Setup compiler's manifest ({manifest.name}, "
                      f"OutputManifestFile) lists", props["yuzu:sbom:contents"])
        self.assertIn("at its path below the build directory, not the path it is installed to",
                      props["yuzu:sbom:contents"])
        self.assertEqual(cdx["compositions"][0]["aggregate"], "incomplete")
        self.assertEqual(props["yuzu:sbom:incomplete-reasons"], "installer-runtime")
        self.assertIn("licence text, icon, compiled [Code] script", props["yuzu:sbom:incomplete"])
        r = self.check_dir(exe)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # A refusal of the contract fails the run, naming the problem.
        (build / "agents" / "plugins" / "echo" / "echo.dll").write_bytes(b"MZ changed")
        r = self.generate(exe, extra=inno)
        self.assertEqual(r.returncode, 1)
        self.assertRegex(r.stderr, r"^::error::YuzuAgentSetup-1\.2\.3_rc1\.manifest\.txt:\d+: agents/plugins/echo/"
                                   r"echo\.dll in the build directory has SHA-256 [0-9a-f]{64}, not the [0-9a-f]{64} "
                                   r"ISCC recorded")
        # ...and an installer is never described without its manifest, nor a
        # manifest used for anything but an installer.
        r = self.generate(exe)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pass --inno-manifest, --build-dir and --inno-build-dir", r.stderr)
        for drop in (0, 2, 4):
            with self.subTest(without=inno[drop]):
                r = self.generate(exe, extra=inno[:drop] + inno[drop + 2:])
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("--inno-manifest, --build-dir and --inno-build-dir go together", r.stderr)
        zip_path = make_zip(rel / "yuzu-agent-windows-x64.zip", WIN_ZIP)
        r = self.generate(zip_path, extra=inno)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--inno-manifest describes an InnoSetup installer", r.stderr)

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

    def test_rpm_unpack_timeout(self):
        # rpm2cpio | cpio stalling (a hung pipe) is cut off, both processes
        # ended, and reported, not waited on until the job's limit.
        mod = load_script()
        stubs = self.tmp / "bin"
        stubs.mkdir()
        write_exe(stubs / "rpm2cpio", f"#!{sys.executable}\nimport time; time.sleep(30)\n")
        write_exe(stubs / "cpio", f"#!{sys.executable}\nimport sys; sys.stdin.read()\n")
        rpm = self.tmp / "yuzu-agent-1.2.3-1.x86_64.rpm"
        rpm.write_bytes(b"x")
        dest = self.tmp / "dest"
        dest.mkdir()
        with mock.patch.dict(os.environ, {"PATH": str(stubs)}), mock.patch.object(mod, "UNPACK_TIMEOUT", 1), \
                self.assertRaises(mod.SbomError) as cm:
            mod.extract(rpm, dest)
        self.assertIn("rpm2cpio | cpio did not finish within 1 s", str(cm.exception))

    def test_syft_failure_fails_the_run(self):
        make_vcpkg_tree(self.tmp)
        art = make_tar(self.tmp / "yuzu-linux-x64.tar.gz", {"y/bin/yuzu-agent": b"x"})
        self.syft = write_exe(self.tmp / "syft-fails", f"#!{sys.executable}\nimport sys\n"
                                                        f"sys.stderr.write('cataloger exploded\\n'); sys.exit(3)\n")
        r = self.generate(art)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("::error::syft exited 3: cataloger exploded", r.stderr)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

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
        # An image SBOM legitimately lists /usr/share/.../tests paths and many
        # packages: it is not held to the artifact rules, only to the marker.
        cdx, spdx = make_image_pair("yuzu-server", SERVER_IMAGE_FILES)
        cdx["components"] += [{"type": "file", "name": "/usr/lib/x/tests/y"}] * 1000
        load_script().mark_image(cdx, spdx)
        (self.tmp / "yuzu-server-image.cdx.json").write_text(json.dumps(cdx))
        (self.tmp / "yuzu-server-image.spdx.json").write_text(json.dumps(spdx))
        r = run_script("check", "--artifacts-dir", self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 file(s), OK", r.stdout)
        self.assertIn("1 image SBOM pair(s), OK", r.stdout)

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
