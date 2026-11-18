#!/usr/bin/env python3
"""Per-artifact SBOMs for the release assets (supply-chain item S8).

The release used to run syft over the whole checkout (`path: .`), which listed
the vcpkg ports catalogue, docs and test tooling (about 40,000 components) and
none of the C++ libraries the binaries actually link: they are static, so syft
sees nothing in them. This script makes one SBOM per shipped file instead.

`generate` describes ONE artifact (an archive, .deb, .rpm, .pkg or installer):

  1. Unpack the artifact into a fresh temporary directory and run syft over
     that directory only, so the SBOM lists what is inside the file. A macOS
     .pkg is expanded with pkgutil; its payload stages the binaries under
     hidden `.incoming` names (deploy/packaging/macos/build-pkg.sh), which are
     read as the names they are installed under. An InnoSetup installer is
     not unpacked here: its contents are the files the compiler's own
     manifest (--inno-manifest, the installer script's OutputManifestFile)
     lists, each taken from --build-dir and checked against the SHA-256 the
     compiler recorded, at their paths below the build directory (not the
     paths they are installed to): see THE INSTALLER MANIFEST CONTRACT.
  2. If the unpacked tree holds a Yuzu C++ binary, add the vcpkg ports it is
     built from, read from the INSTALLED vcpkg tree for the release triplet
     (`vcpkg_installed/vcpkg/status` + `<triplet>/share/<port>/vcpkg.spdx.json`):
     the dependency closure of vcpkg.json's core dependencies (agent) plus its
     `server` feature (server), with the real version, licence and a
     `pkg:github` (or `pkg:generic`) purl of the upstream source. The
     `vcpkg-*` helper ports are left out, and so is a dependency recorded for
     another triplet (a host build tool when the host triplet differs from the
     release triplet, as on Linux; on Windows and macOS the two are the same,
     so only the `vcpkg-*` filter applies). The closure follows every
     INSTALLED feature of a reached port, so it can over-list a port a feature
     pulled in that the binary does not end up linking; it never under-lists a
     vcpkg port. A port whose vcpkg SPDX file gives no licence is listed with
     none (NOASSERTION in SPDX) and named in a warning.
  3. If the unpacked tree holds yuzu-server, add the third-party components
     compiled into it that no package manager knows about: the web assets it
     serves (htmx, ECharts, three.js, Cytoscape.js, IBM Plex) and the vendored
     C++ QR-code library, from VENDORED_MANIFEST. The manifest is first checked
     against the source tree (`check-vendored` below); a mismatch fails the run
     rather than describe bytes the binary does not hold.
  4. With --rebar-lock, an Erlang application that is a Hex package in the lock
     gets a `pkg:hex` purl (syft reports every OTP application as `pkg:otp`).
  5. Stamp the artifact's file name, version and SHA-256 on the SBOM root, write
     `<stem>.cdx.json` and `<stem>.spdx.json`, and run the `check` below on both.

Not every component is listed. An installer's own runtime (InnoSetup's setup
loader and uninstaller) and the code the bundled Erlang runtime's emulator
(beam.smp) vendors and links statically (PCRE2, asmjit, zstd, Ryu, an MD5 taken
from OpenSSL; syft lists the runtime as one `erlang` component) are not. An
SBOM whose file holds any of them carries a
CycloneDX composition with `aggregate: incomplete` on the root (SPDX 2.3 has no
such field: the root gets a `CONTAINS NOASSERTION` relationship, SPDX's way of
saying no assertion is made that the listed elements are all it contains), and
says why: `yuzu:sbom:incomplete-reasons` holds tokens from the closed set
INCOMPLETE_REASONS and `yuzu:sbom:incomplete` the prose. Every note has ONE
key, `yuzu:sbom:<name>`, in both formats: a CycloneDX metadata property of that
name, and in SPDX a line `yuzu:sbom:<name>: <value>` of the described package's
comment (one note per line; see NOTE_PREFIX). Libraries a binary loads from the
operating system at run time are not in the file, so they are not a reason.

`mark-image` adds the same marker to a syft scan of a published container
image, given as its CycloneDX and SPDX pair and rewritten in place, when syft
lists a statically linked Yuzu C++ binary (whose vcpkg libraries an image scan
cannot see), the Erlang emulator or the source-built pgvector in it. It refuses
a pair that does not describe one image, an image labelled as the release's
server, agent, gateway or postgres image in which syft lists no such file, and
a pair already marked differently; a pair already marked the same way is left
as it is.

`augment` adds the VENDORED_MANIFEST components (after the same check against
the source tree) to a syft scan of a published container image, given as its
CycloneDX and SPDX pair and rewritten in place, with a `yuzu:sbom:vendored`
note in both formats. It acts only when syft lists a yuzu-server binary in the
image (as an SPDX file: syft 1.57 lists it nowhere in CycloneDX), and leaves
any other image's pair untouched without reading the manifest. It refuses a
pair that does not describe one image, an image labelled as the release's
server image in which syft lists no yuzu-server, and a pair already carrying
any part of what it adds. syft's entries are kept: components, packages and
relationships are appended to, and the SPDX root's comment gains the note line
after any comment syft wrote; nothing else of syft's changes. It adds no
incompleteness marker; `mark-image` decides that, and the components it adds
are not a reason for one.

The vendored entries carry fixed identifiers a consumer may rely on, in every
SBOM that lists them (artifact and image): CycloneDX components whose
`bom-ref` starts `vendored-` (a bundled component nested in its parent), SPDX
packages whose SPDXID starts `SPDXRef-Package-vendored-`, the
`yuzu:vendored:*` properties on each CycloneDX component, and the
`yuzu:sbom:vendored` note on the root (NOTE_PREFIX). docs/ci-architecture.md
("Release artifact gate") names the same set.

`check-vendored` compares VENDORED_MANIFEST with the source tree: every file
under its tracked roots is listed with its SHA-256 and size, first-party by
name (a first_party_patterns entry: its directory exactly, its glob on the
file name only, so nothing in a subdirectory is first-party), or an
attribution file a component names as its `notice`; every listed file exists
with that hash. A NOTICE whose bytes are not valid UTF-8 fails; its SPDX
licence line must be its components', and every SHA-256 it records must be one
of the files of a component naming it. Valid UTF-8 is not proof of a UTF-8
text: a BOM-less UTF-16 NOTICE can decode as valid UTF-8, and then its SPDX and
SHA-256 lines are simply not found, which the check treats like a NOTICE that
records none. A symbolic link anywhere under a tracked root (or on the
path of a listed file or NOTICE) and a directory the walk cannot read fail it,
as does an unlisted, changed or missing file, so a vendor refresh cannot skip
the manifest.

`check` is the release gate: an artifact SBOM fails when it has more than
MAX_COMPONENTS entries, has none and does not record that its file was
unpacked and held files, lists a path with one of the FORBIDDEN_SEGMENTS (a
checkout, vcpkg or build tree, the docs site or a test tree, the paths a scan of
the wrong directory lists; a path elsewhere is not detected), or (with
--artifacts-dir) names an artifact that is absent or whose SHA-256 differs.
Image SBOMs (`*-image.*`) are not artifact SBOMs and are not checked against
those rules; with --artifacts-dir, each image pair must carry the marker
`mark-image` would add, and list yuzu-server's vendored components in both
formats exactly when syft lists yuzu-server in the image (so a dropped
`mark-image` or `augment` step fails the release).

Stdlib only (Python 3.9+); needs syft for `generate`, plus
dpkg-deb (.deb), rpm2cpio and cpio (.rpm) or pkgutil (.pkg) for those formats.
Every external command runs with a timeout. Pinned by
tests/test_artifact_sbom.py and tests/test_vendored_components.py.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

# File types this script describes, longest suffix first.
ARTIFACT_SUFFIXES = (".tar.gz", ".zip", ".deb", ".rpm", ".pkg", ".exe")

# Upper bound on entries (CycloneDX components; SPDX packages + files) in ONE
# artifact SBOM. Measured locally on 2026-11-17 with syft 1.57.2: 16 to 22
# CycloneDX components and 22 to 58 SPDX entries per artifact (Linux archive and
# .debs from a partial local build, gateway tarball and .deb from a fresh prod
# release). syft records each Windows PE binary it sees twice in CycloneDX (an
# application and a file component) and once in SPDX: the real v0.15.0 Windows
# archive (server and agent, 95 .exe/.dll files) measured 212 entries in each
# format on 2026-11-18, and its installer's SBOM 190. That archive is the
# largest; each plugin added on Windows adds about two. An artifact holding
# yuzu-server also gets the VENDORED_MANIFEST components (10 entries in each
# format): the Linux archive measured 32 and 63 on 2026-11-18. The v0.15.0 workspace
# scans this replaces had 40,853 (Linux) and 43,407 (Windows). 400 leaves
# about twice the largest artifact and still fails any return to a checkout
# scan by two orders of magnitude. Raise it deliberately, with a measurement,
# never to silence a failing scan.
MAX_COMPONENTS = 400

# A path with one of these segments in an artifact SBOM means the checkout, the
# vcpkg clone or its installed tree (vcpkg_installed/), a Meson build tree
# (build-linux/, build-windows/, ...), a rebar3 build tree (_build/,
# _build_eunit/, ...), the docs site or a test tree was scanned, not the
# artifact. Only these are detected: a scan of some other wrong directory is
# caught, if at all, by the entry bound. None of the 1,998 paths in v0.15.0's
# archives, .debs and .pkg payload has such a segment (checked 2026-11-18; the
# .rpms and the installer were not listed). The messages and the docs name the
# same set as FORBIDDEN_LABEL.
FORBIDDEN_SEGMENTS = re.compile(
    r"(?:^|[/\\])(?:vcpkg|vcpkg_installed|site|tests|_build|_build_[^/\\]*|build-[^/\\]+|\.git|\.github)"
    r"(?:[/\\]|$)")
FORBIDDEN_LABEL = "vcpkg/, vcpkg_installed/, build-*/, _build/, _build_*/, site/, tests/, .git/ or .github/"

# Basenames that identify the Yuzu C++ binaries in an unpacked artifact, by the
# name each is installed under (see installed_name()).
SERVER_NAMES = {"yuzu-server", "yuzu-server.exe"}
AGENT_NAMES = {"yuzu-agent", "yuzu-agent.exe", "yuzu_agent_core.dll"}
AGENT_PREFIXES = ("libyuzu_agent_core.so", "libyuzu_agent_core.dylib")

# The macOS .pkg payload stages each loose binary under a hidden name that
# postinstall renames into place (deploy/packaging/macos/build-pkg.sh):
# usr/local/bin/.yuzu-agent.incoming and .libyuzu_agent_core.incoming.dylib.
STAGED_NAME = re.compile(r"^\.(?P<base>[^/\\]+?)\.incoming(?P<ext>\.[A-Za-z0-9]+)?$")

# Seconds an unpacking command (dpkg-deb, rpm2cpio | cpio, pkgutil) or syft may
# run. A stalled one (a FIFO in a payload, a hung mount) would otherwise hold a
# self-hosted runner until the job's own limit. Measured runs take seconds.
UNPACK_TIMEOUT = 600
SYFT_TIMEOUT = 900

# NVD vendor:product for the vcpkg ports that have one, so a CPE-matching
# scanner (grype, trivy, Dependency-Track) sees the C++ libraries: they carry no
# package metadata of their own. Every pair was confirmed to exist in the grype
# vulnerability database on 2026-11-17. A port not listed gets no CPE (no NVD
# product was found for re2, jsoncpp, nlohmann-json, cli11, libuuid, trantor or
# utf8-range under the names tried); add a pair when a new port has one.
NVD_CPE = {
    "abseil": "abseil:common_libraries", "brotli": "google:brotli", "c-ares": "c-ares:c-ares",
    "cpp-httplib": "yhirose:cpp-httplib", "drogon": "drogon:drogon", "fmt": "fmt:fmt",
    "grpc": "grpc:grpc", "libpq": "postgresql:postgresql", "libxml2": "xmlsoft:libxml2",
    "openssl": "openssl:openssl", "protobuf": "google:protobuf", "spdlog": "gabime:spdlog",
    "sqlite3": "sqlite:sqlite", "xmlsec": "xmlsec_project:xmlsec", "zlib": "zlib:zlib",
}

# The third-party components compiled into yuzu-server that no package manager
# describes (paths are relative to the repository root).
REPO_ROOT = Path(__file__).resolve().parents[2]
VENDORED_MANIFEST = "server/core/vendored-components.json"
VENDORED_TYPES = {"library": "library", "font": "file"}  # manifest type -> CycloneDX type
# A SHA-256 recorded in an attribution file (a NOTICE): any case, as bytes.
NOTICE_SHA256 = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
SPDX_LINE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")

GITHUB_GIT = re.compile(r"^git\+https://github\.com/([^/]+)/([^/@]+?)(?:\.git)?@(.+)$")
HEX_LOCK = re.compile(r'\{<<"([A-Za-z0-9_]+)">>,\s*\{pkg,\s*<<"([A-Za-z0-9_]+)">>,\s*<<"([^"]+)">>')


class SbomError(Exception):
    pass


# The key of every note this script writes on an SBOM root, in both formats:
# CycloneDX `metadata.properties[].name` is `yuzu:sbom:<name>`, and the SPDX
# described package's `comment` holds one line `yuzu:sbom:<name>: <value>` per
# note, so a script reads the same key from either format (in SPDX: the line
# starting with `<key>: `). docs/user-manual/release-verification.md gives the
# extraction recipe for each format and tests/test_artifact_sbom.py runs it.
NOTE_PREFIX = "yuzu:sbom:"


def spdx_notes_comment(notes: dict) -> str:
    """The SPDX root comment for `notes`: one `yuzu:sbom:<name>: <value>` line
    each. A value holding a line break would end its line early and could
    start a line that reads as another note, so it is refused."""
    for k, v in notes.items():
        if re.search(r"[\r\n\x0b\x0c\x1c-\x1e\x85\u2028\u2029]", f"{k}{v}"):
            raise SbomError(f"note {k!r}: a value with a line break cannot be one line of the SPDX root comment")
    return "\n".join(f"{NOTE_PREFIX}{k}: {v}" for k, v in notes.items())


def spdx_note(comment, name: str):
    """The value of note `name` in an SPDX root comment, or None. A note this
    script writes once is ambiguous when it appears twice (the documented jq
    recipe prints both lines), so a duplicate is refused, not resolved."""
    found = re.findall(rf"^{re.escape(NOTE_PREFIX + name)}: (.*)$", comment or "", re.M)
    if len(found) > 1:
        raise SbomError(f"note {NOTE_PREFIX}{name} appears {len(found)} times in the SPDX root comment")
    return found[0] if found else None


def cdx_note(meta, name: str):
    """The value of note `name` among CycloneDX metadata properties, or None;
    a duplicate is refused, as in spdx_note()."""
    found = [p.get("value") for p in (meta or {}).get("properties") or [] if p.get("name") == NOTE_PREFIX + name]
    if len(found) > 1:
        raise SbomError(f"note {NOTE_PREFIX}{name} appears {len(found)} times in the CycloneDX metadata properties")
    return found[0] if found else None


# ── Artifacts ────────────────────────────────────────────────────────────────

def artifact_stem(name: str) -> str:
    for suffix in ARTIFACT_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    raise SbomError(f"{name}: not a release artifact type ({', '.join(ARTIFACT_SUFFIXES)})")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _inside(root: Path, target: Path) -> bool:
    root = root.resolve()
    try:
        target.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def _extract_tar(path: Path, dest: Path) -> None:
    try:
        _extract_tar_checked(path, dest)
    except tarfile.TarError as e:  # includes the "data" filter's refusals
        raise SbomError(f"{path.name}: {e}") from e


# Python 3.12+ (and 3.8.17+/3.9.17+/3.10.12+/3.11.4+) has tarfile's "data"
# extraction filter. An older python3 (Apple's /usr/bin/python3 is 3.9.6) does
# not and takes the fallback below; the v0.15.0 macOS release job ran Homebrew's
# python3 3.14, so the fallback is not known to run in a release today. A
# module flag so the tests can force it.
HAS_DATA_FILTER = hasattr(tarfile, "data_filter")


def _extract_tar_checked(path: Path, dest: Path) -> None:
    with tarfile.open(path, "r:gz") as tf:
        if HAS_DATA_FILTER:
            tf.extractall(dest, filter="data")
            return
        # No extraction filters: refuse, rather than extract, a member that is
        # absolute, escapes `dest`, is a device or FIFO, is a link whose target
        # is absolute or escapes, or lies under a link member. The last rule
        # closes link chains (`a -> .` then `a/b -> ..`): each link is checked
        # lexically before anything is written, so a member must never be
        # reached through another member that is a link.
        links: set[str] = set()
        for m in tf.getmembers():
            name = os.path.normpath(m.name)
            target = dest / name
            if os.path.isabs(m.name) or Path(name).parts[:1] == ("..",) or not _inside(dest, target):
                raise SbomError(f"{path.name}: member {m.name!r} escapes the extraction directory")
            if m.isdev() or m.isfifo():
                raise SbomError(f"{path.name}: member {m.name!r} is a device or FIFO")
            parts = Path(name).parts
            if any(str(Path(*parts[:i])) in links for i in range(1, len(parts))):
                raise SbomError(f"{path.name}: member {m.name!r} lies under a link member")
            if m.issym() or m.islnk():
                link = (target.parent / m.linkname) if m.issym() else (dest / m.linkname)
                if os.path.isabs(m.linkname) or not _inside(dest, link):
                    raise SbomError(f"{path.name}: link {m.name!r} points outside the extraction directory")
                links.add(str(Path(name)))
        # Rely on the checks above alone, as an old Python does (an explicit
        # "fully_trusted" where filters exist: Python 3.14 would otherwise
        # apply "data" here and hide a gap in them from the tests).
        tf.extractall(dest, **({"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}))


def _timeout_error(cmd, seconds) -> SbomError:
    return SbomError(f"{Path(cmd[0]).name} did not finish within {seconds} s (stalled? see UNPACK_TIMEOUT/SYFT_TIMEOUT)")


def _run(cmd, **kw) -> None:
    exe = shutil.which(cmd[0])
    if not exe:
        raise SbomError(f"{cmd[0]} not found on PATH (needed to unpack the artifact)")
    try:
        r = subprocess.run([exe] + list(cmd[1:]), capture_output=True, text=True,
                           timeout=UNPACK_TIMEOUT, **kw)
    except subprocess.TimeoutExpired as e:
        raise _timeout_error(cmd, UNPACK_TIMEOUT) from e
    if r.returncode != 0:
        raise SbomError(f"{' '.join(cmd)} exited {r.returncode}: {r.stderr.strip()[:500]}")


def extract(path: Path, dest: Path) -> None:
    """Unpack `path` into the empty directory `dest`."""
    name = path.name
    if name.endswith(".tar.gz"):
        _extract_tar(path, dest)
    elif name.endswith(".zip"):
        if not zipfile.is_zipfile(path):
            raise SbomError(f"{name}: not a zip archive")
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if os.path.isabs(n) or not _inside(dest, dest / n):
                    raise SbomError(f"{name}: member {n!r} escapes the extraction directory")
            zf.extractall(dest)
    elif name.endswith(".deb"):
        _run(["dpkg-deb", "-x", str(path), str(dest)])
    elif name.endswith(".rpm"):
        rpm2cpio, cpio = shutil.which("rpm2cpio"), shutil.which("cpio")
        if not rpm2cpio or not cpio:
            raise SbomError("rpm2cpio and cpio are needed to unpack an .rpm")
        # rpm2cpio's stderr goes to a file, not a pipe nobody reads while it runs.
        with tempfile.TemporaryFile() as err1:
            p1 = subprocess.Popen([rpm2cpio, str(path)], stdout=subprocess.PIPE, stderr=err1)
            try:
                p2 = subprocess.run([cpio, "-idm", "--quiet", "--no-absolute-filenames"],
                                    stdin=p1.stdout, cwd=dest, capture_output=True, timeout=UNPACK_TIMEOUT)
                p1.stdout.close()
                rc1 = p1.wait(timeout=UNPACK_TIMEOUT)
            except subprocess.TimeoutExpired as e:
                p1.kill()
                p1.wait()
                p1.stdout.close()
                raise _timeout_error(["rpm2cpio | cpio"], UNPACK_TIMEOUT) from e
            # Either side failing is a refusal: a truncated .rpm can make
            # rpm2cpio fail while cpio exits 0 over the part it was given.
            if rc1 != 0 or p2.returncode != 0:
                err1.seek(0)
                why = " ".join(t for t in (err1.read(500).decode(errors="replace").strip(),
                                           p2.stderr.decode(errors="replace").strip()[:500]) if t)
                raise SbomError(f"{name}: rpm2cpio|cpio failed (rpm2cpio exited {rc1}, cpio exited "
                                f"{p2.returncode}){': ' + why if why else ''}")
    elif name.endswith(".pkg"):
        # pkgutil wants a directory that does not exist yet.
        _run(["pkgutil", "--expand-full", str(path), str(dest / "pkg")])
    else:
        raise SbomError(f"{name}: cannot unpack this type here; an installer's SBOM is made from the compiler's "
                        f"manifest: pass --inno-manifest, --build-dir and --inno-build-dir")


def installed_name(f: str) -> str:
    """The name a file in an unpacked artifact is installed under: the .pkg's
    staged `.yuzu-agent.incoming` is `yuzu-agent`, and
    `.libyuzu_agent_core.incoming.dylib` is `libyuzu_agent_core.dylib`. Any
    other name is returned unchanged."""
    m = STAGED_NAME.match(f)
    return m.group("base") + (m.group("ext") or "") if m else f


def yuzu_binaries(root: Path) -> tuple[bool, bool]:
    """(has_agent, has_server) for an unpacked tree."""
    agent = server = False
    for _dirpath, _dirs, files in os.walk(root):
        for f in map(installed_name, files):
            if f in SERVER_NAMES:
                server = True
            if f in AGENT_NAMES or f.startswith(AGENT_PREFIXES):
                agent = True
    return agent, server


# The Erlang runtime's emulator, as relx bundles it (erts-<vsn>/bin/beam.smp).
ERTS_EMULATOR = "beam.smp"


def erts_emulators(root: Path) -> list[str]:
    """Paths (relative, /-separated) of the Erlang emulators in an unpacked tree."""
    return sorted(Path(d, f).relative_to(root).as_posix()
                  for d, _dirs, files in os.walk(root) for f in files if f == ERTS_EMULATOR)


def count_files(root: Path) -> int:
    return sum(len(files) for _d, _s, files in os.walk(root))


# ── InnoSetup installer contents: the compiler's own file list ───────────────
#
# THE INSTALLER MANIFEST CONTRACT. An InnoSetup installer is not unpacked here.
# deploy/packaging/windows/yuzu-agent.iss sets `OutputManifestFile`, so the
# compiler (ISCC) writes, beside the installer, the list of files it packed,
# and the installer SBOM is made from that list: each file is taken from the
# build directory, its SHA-256 checked against the one ISCC recorded, and the
# verified bytes copied into a scratch tree at their build-relative paths,
# which syft and the vcpkg closure then read. The installer script itself is
# never parsed. The format below was read from Inno Setup's source, tag
# is-6_7_3 (the version v0.15.0 was built with; the release does not pin it):
#
#  - Projects/Src/Compiler.SetupCompiler.pas, CreateManifestFile (7942-8005):
#    a TTextFileWriter, one WriteLine for the header and one per file location
#    entry, columns joined by a tab; the header is INNO_MANIFEST_HEADER; the
#    SourceFilename column is the compile-time source path as ISCC built it
#    (the [Files] Source with {#BuildDir} expanded, concatenated with the
#    found name, not normalised: 5186, 5789, 5804-5812); SHA256Sum is
#    SHA256DigestToString of the digest CompressFile took over the file's own
#    bytes before any compression transform (Compiler.CompressionHandler.pas
#    243-260). ISCC merges two [Files] entries naming the same source path,
#    compared case-insensitively, into one location (5193), and writes the
#    manifest only after a successful compile, having deleted any old one
#    first (8745-8746, 8905-8907).
#  - Components/SHA256.pas, SHA256DigestToString (71-): 64 lowercase hex digits.
#  - Projects/Src/Shared.FileClass.pas, TTextFileWriter (508-573): Write
#    encodes with Utf8Encode, a new file starts with the UTF-8 byte order mark
#    (UTF8WithoutBOM is never set for the manifest), and WriteLine appends
#    CR LF, so every line, the last included, ends in CR LF.
#
# Refused, each with an error naming the manifest and the problem: no UTF-8
# byte order mark, bytes that are not UTF-8, a line not ended by CR LF or a
# bare CR or LF, a header other than INNO_MANIFEST_HEADER exactly, no rows, a
# row whose column count is not the header's, an Index out of sequence, a
# SHA256Sum that is not 64 lowercase hex digits, a SourceFilename that is not a
# drive-absolute Windows path strictly inside the build directory as ISCC was
# given it (--inno-build-dir) after normalisation (`..` out of it, another
# drive, a UNC or device path, the directory itself), a name Windows reads
# differently (a reserved character, a trailing dot or space), one path listed
# twice with two hashes, a file absent from --build-dir or not a regular file,
# a file that resolves outside --build-dir (a symlink or junction), and a
# SHA-256 that differs. A defect is an accepted row whose listed file differs
# from the packed bytes; a manifest shape this refuses is an expected refusal.
INNO_MANIFEST_HEADER = "\t".join((
    "Index", "SourceFilename", "TimeStamp", "Version", "SHA256Sum", "OriginalSize", "FirstSlice", "LastSlice",
    "StartOffset", "ChunkSuboffset", "ChunkCompressedSize", "Encrypted", "ISSigKeyID"))
INNO_MANIFEST_COLUMNS = INNO_MANIFEST_HEADER.count("\t") + 1
UTF8_BOM = b"\xef\xbb\xbf"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
# A path component Windows would not open as written: a reserved character
# (an NTFS stream colon among them) or a control character, or a trailing dot
# or space, which Windows strips.
WIN_BAD_COMPONENT = re.compile(r'[<>:"|?*\x00-\x1f]|[. ]$')


def read_inno_manifest(path: Path) -> list[tuple[str, str]]:
    """[(SourceFilename, SHA256Sum)] for each row of an ISCC
    OutputManifestFile, read under THE INSTALLER MANIFEST CONTRACT above (the
    encoding, line ends, header, column count, Index sequence and hash form;
    the paths are checked by inno_build_parts())."""
    name = path.name
    data = path.read_bytes()
    if not data.startswith(UTF8_BOM):
        raise SbomError(f"{name}: not the encoding ISCC writes a manifest in: UTF-8 with a byte order mark "
                        f"(TTextFileWriter), and this file does not start with one")
    try:
        text = data[len(UTF8_BOM):].decode("utf-8")
    except UnicodeDecodeError as e:
        raise SbomError(f"{name}: not the encoding ISCC writes a manifest in: it starts with a UTF-8 byte order "
                        f"mark but is not UTF-8 ({e})") from e
    if not text.endswith("\r\n"):
        raise SbomError(f"{name}: the last line does not end in CR LF, as every line ISCC writes does "
                        f"(a truncated or rewritten manifest?)")
    lines = text[:-2].split("\r\n")
    for lineno, line in enumerate(lines, 1):
        if "\r" in line or "\n" in line:
            raise SbomError(f"{name}:{lineno}: a CR or LF that is not part of a CR LF: ISCC ends every line in "
                            f"CR LF (a rewritten manifest?)")
    if lines[0] != INNO_MANIFEST_HEADER:
        raise SbomError(f"{name}:1: the header is not the one Inno Setup 6.7.3 writes "
                        f"({INNO_MANIFEST_HEADER!r}) but {lines[0]!r}: another compiler version changed the "
                        f"format; update the contract in scripts/ci/artifact-sbom.py and its test fixture "
                        f"deliberately, after reading the new format in that version's source")
    rows = lines[1:]
    if not rows:
        raise SbomError(f"{name}: a header and no file rows: ISCC lists every file it packs, and an installer "
                        f"packs at least yuzu-agent.exe")
    out = []
    for i, line in enumerate(rows):
        where = f"{name}:{i + 2}"
        cols = line.split("\t")
        if len(cols) != INNO_MANIFEST_COLUMNS:
            raise SbomError(f"{where}: {len(cols)} tab-separated columns, not the header's {INNO_MANIFEST_COLUMNS}")
        if cols[0] != str(i):
            raise SbomError(f"{where}: Index {cols[0]!r}, not {i}: the rows must be ISCC's file locations in order")
        if not SHA256_HEX.fullmatch(cols[4]):
            raise SbomError(f"{where}: SHA256Sum {cols[4]!r} is not 64 lowercase hex digits, the form ISCC "
                            f"writes (SHA256DigestToString)")
        out.append((cols[1], cols[4]))
    return out


def _win_parts(p: str):
    """(drive, [components]) of a drive-absolute Windows path after
    ntpath.normpath, or None for any other form (relative, drive-relative,
    UNC, device or `\\\\?\\` paths)."""
    drive, rest = ntpath.splitdrive(p)
    if not (len(drive) == 2 and drive[1] == ":" and drive[0].isascii() and drive[0].isalpha()
            and rest[:1] in ("\\", "/")):
        return None
    drive, rest = ntpath.splitdrive(ntpath.normpath(p))
    return drive.upper(), [c for c in rest.split("\\") if c]


def inno_build_parts(source: str, inno_build_dir: str, where: str) -> list[str]:
    """The components of manifest path `source` below `inno_build_dir` (the
    build directory as ISCC was given it, /DBuildDir), both read as Windows
    paths: drive-absolute, normalised by ntpath.normpath (so `..` is resolved
    lexically), drive and components compared case-insensitively, as Windows
    compares them. Refuses a path that is not strictly inside, and a component
    Windows would read differently."""
    build = _win_parts(inno_build_dir)
    if build is None:
        raise SbomError(f"--inno-build-dir {inno_build_dir!r} is not a drive-absolute Windows path (X:\\...)")
    src = _win_parts(source)
    if src is None:
        raise SbomError(f"{where}: SourceFilename {source!r} is not a drive-absolute Windows path, so it is not "
                        f"inside the build directory {inno_build_dir!r}")
    (bdrive, bparts), (sdrive, sparts) = build, src
    n = len(bparts)
    if (sdrive != bdrive or len(sparts) <= n
            or [c.casefold() for c in sparts[:n]] != [c.casefold() for c in bparts]):
        raise SbomError(f"{where}: SourceFilename {source!r} is not strictly inside the build directory "
                        f"{inno_build_dir!r} (after normalisation it is {sdrive}\\{chr(92).join(sparts)})")
    rel = sparts[n:]
    bad = next((c for c in rel if WIN_BAD_COMPONENT.search(c)), None)
    if bad is not None:
        raise SbomError(f"{where}: SourceFilename {source!r}: component {bad!r} holds a character Windows does "
                        f"not allow in a name or ends in a dot or space, which Windows strips")
    return rel


def _copy_hashed(src: Path, dest: Path) -> str:
    """Copy `src` to the new file `dest`, returning the SHA-256 of the bytes
    copied, so the hash checked is the hash of what syft reads."""
    h = hashlib.sha256()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as f, open(dest, "xb") as o:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            o.write(chunk)
    return h.hexdigest()


def installer_contents(manifest: Path, build_dir: Path, inno_build_dir: str, dest: Path) -> list[str]:
    """Copy into `dest` every file the ISCC manifest lists, at its path below
    the build directory, after checking it under THE INSTALLER MANIFEST
    CONTRACT. Returns the build-relative paths, /-separated, in manifest
    order, each once."""
    rows = read_inno_manifest(manifest)
    if not build_dir.is_dir():
        raise SbomError(f"--build-dir {build_dir}: no such directory")
    root = build_dir.resolve(strict=True)
    seen: dict = {}
    out = []
    for i, (source, sha) in enumerate(rows):
        where = f"{manifest.name}:{i + 2}"
        rel = inno_build_parts(source, inno_build_dir, where)
        key = tuple(c.casefold() for c in rel)
        if key in seen:
            # ISCC merges these itself unless DontMergeDuplicateFiles is set.
            if seen[key] != sha:
                raise SbomError(f"{where}: {source!r} is listed again with another SHA-256 ({seen[key]} and {sha})")
            continue
        seen[key] = sha
        shown = "/".join(rel)
        local = build_dir.joinpath(*rel)
        try:
            real = local.resolve(strict=True)
        except OSError:
            raise SbomError(f"{where}: {source!r} is missing from the build directory {build_dir} "
                            f"(looked for {local})") from None
        if real == root or not real.is_relative_to(root):
            raise SbomError(f"{where}: {source!r} resolves to {real}, outside the build directory {root} "
                            f"(a symlink or junction)")
        if not real.is_file():
            raise SbomError(f"{where}: {source!r} is not a regular file in the build directory ({real})")
        try:
            got = _copy_hashed(real, dest.joinpath(*rel))
        except FileExistsError:
            raise SbomError(f"{where}: {source!r} maps onto a path already copied ({shown})") from None
        if got != sha:
            raise SbomError(f"{where}: {shown} in the build directory has SHA-256 {got}, not the {sha} ISCC "
                            f"recorded when it packed the installer: not the file the installer holds")
        out.append(shown)
    return out


# ── vcpkg ────────────────────────────────────────────────────────────────────

def parse_status(path: Path) -> list[dict]:
    """vcpkg's `status` file: Debian-control-style paragraphs."""
    paras, cur, key = [], {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            if cur:
                paras.append(cur)
            cur, key = {}, None
        elif line[0] in " \t" and key:
            cur[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            cur[key] = val.strip()
    if cur:
        paras.append(cur)
    return paras


def installed_ports(paras: list[dict], triplet: str) -> dict:
    """{port: {"version", "port_version", "depends": [raw...], "features": [...]}}
    for every port INSTALLED for `triplet` (core paragraph plus its features)."""
    ports: dict = {}
    for p in paras:
        if p.get("Architecture") != triplet or not p.get("Status", "").endswith(" installed"):
            continue
        if not p.get("Status", "").startswith("install "):
            continue
        name = p.get("Package")
        if not name:
            continue
        e = ports.setdefault(name, {"version": None, "port_version": "0", "depends": [], "features": []})
        deps = [d.strip() for d in p.get("Depends", "").split(",") if d.strip()]
        e["depends"] += deps
        if "Feature" in p:
            e["features"].append(p["Feature"])
        else:
            e["version"] = p.get("Version")
            e["port_version"] = p.get("Port-Version", "0")
    for name, e in ports.items():
        if not e["version"]:
            raise SbomError(f"vcpkg status: {name}:{triplet} has feature paragraphs but no core paragraph")
    return ports


def _dep_name(raw: str, triplet: str):
    """'abseil' -> 'abseil'; 'vcpkg-cmake:x64-linux' (a host tool when the target
    triplet differs) -> None; 'curl[ssl]' -> 'curl'."""
    name, _, trip = raw.partition(":")
    name = name.split("[", 1)[0].strip()
    if trip and trip.strip() != triplet:
        return None
    return name


def _manifest_roots(manifest: dict, server: bool) -> list[dict]:
    def norm(d):
        return {"name": d} if isinstance(d, str) else d
    roots = [norm(d) for d in manifest.get("dependencies", [])]
    if server:
        feat = manifest.get("features", {}).get("server")
        if feat is None:
            raise SbomError("vcpkg.json has no `server` feature, but the artifact ships yuzu-server")
        roots += [norm(d) for d in feat.get("dependencies", [])]
    return roots


def vcpkg_closure(ports: dict, manifest: dict, triplet: str, agent: bool, server: bool) -> list[str]:
    seen: set[str] = set()
    queue: list[str] = []
    for d in _manifest_roots(manifest, server):
        name = d["name"]
        if name not in ports:
            if "platform" in d:
                continue  # filtered out for this triplet
            raise SbomError(f"vcpkg.json dependency {name} is not installed for {triplet}: wrong tree or triplet?")
        queue.append(name)
    while queue:
        name = queue.pop()
        if name in seen or name.startswith("vcpkg-"):
            continue
        seen.add(name)
        for raw in ports[name]["depends"]:
            dep = _dep_name(raw, triplet)
            if dep is None or dep.startswith("vcpkg-"):
                continue
            if dep not in ports:
                raise SbomError(f"vcpkg status: {name} depends on {dep}, which is not installed for {triplet}")
            queue.append(dep)
    return sorted(seen)


def _upstream(spdx: dict, port: str):
    """(download_location, vcs_url_or_None, purl) for the port's upstream source."""
    resources = [p for p in spdx.get("packages", []) if p.get("SPDXID", "").startswith("SPDXRef-resource")]
    for r in resources:
        loc = r.get("downloadLocation", "")
        m = GITHUB_GIT.match(loc)
        if m:
            owner, repo, ref = m.groups()
            return loc, f"https://github.com/{owner}/{repo}", f"pkg:github/{owner.lower()}/{repo.lower()}@{quote(ref, safe='')}"
    for r in resources:
        loc = r.get("downloadLocation", "")
        if loc.startswith(("https://", "http://")) and not r.get("name", "").endswith(".patch"):
            return loc, None, None
    return None, None, None


def vcpkg_components(installed: Path, triplet: str, names: list[str], ports: dict) -> list[dict]:
    out = []
    for port in names:
        spdx_path = installed / triplet / "share" / port / "vcpkg.spdx.json"
        if not spdx_path.is_file():
            raise SbomError(f"{spdx_path} missing: cannot describe vcpkg port {port}")
        spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
        port_pkg = next((p for p in spdx.get("packages", []) if p.get("SPDXID") == "SPDXRef-port"), {})
        version = ports[port]["version"]
        download, vcs, purl = _upstream(spdx, port)
        if purl is None:
            purl = f"pkg:generic/{quote(port, safe='')}@{quote(version, safe='')}"
            if download:
                purl += f"?download_url={quote(download, safe='')}"
        vcpkg_purl = next((r.get("referenceLocator") for r in port_pkg.get("externalRefs", []) or []
                           if r.get("referenceType") == "purl"), None)
        lic = port_pkg.get("licenseConcluded") or "NOASSERTION"
        if lic in ("NOASSERTION", "NONE"):
            lic = port_pkg.get("licenseDeclared") or "NOASSERTION"
        # vcpkg's own SPDX file records no copyright text today (NOASSERTION
        # on every port checked, 2026-11-18); one that does is carried over.
        copyright_text = port_pkg.get("copyrightText")
        if copyright_text in (None, "", "NOASSERTION", "NONE"):
            copyright_text = None
        cpe = None
        if port in NVD_CPE:
            cpe_version = re.sub(r"([^A-Za-z0-9._-])", r"\\\1", version)  # CPE 2.3 quoting
            cpe = f"cpe:2.3:a:{NVD_CPE[port]}:{cpe_version}:*:*:*:*:*:*:*"
        out.append({
            "port": port, "version": version, "port_version": ports[port]["port_version"], "cpe": cpe,
            "license": None if lic in ("NOASSERTION", "NONE") else lic, "copyright": copyright_text,
            "homepage": port_pkg.get("homepage"), "download": download, "vcs": vcs,
            "purl": purl, "vcpkg_purl": vcpkg_purl, "triplet": triplet,
        })
    return out


# ── Erlang (Hex) ─────────────────────────────────────────────────────────────

def hex_packages(lock: Path) -> dict:
    """{(app, version): hex_package} from a rebar.lock."""
    return {(app, ver): pkg for app, pkg, ver in HEX_LOCK.findall(lock.read_text(encoding="utf-8"))}


def _hex_purl(purl: str, hexmap: dict):
    m = re.match(r"^pkg:otp/([^@/?#]+)@([^?#]+)$", purl or "")
    if m and (m.group(1), m.group(2)) in hexmap:
        return f"pkg:hex/{hexmap[(m.group(1), m.group(2))]}@{m.group(2)}"
    return None


# ── Vendored components (compiled into yuzu-server) ─────────────────────────

def _cpp_raw_string(data: bytes, symbol: str, where: str) -> bytes:
    """The body of the one raw string literal `symbol = R"D(...)D"` in a C++ file."""
    pat = re.compile(rb"\b" + re.escape(symbol.encode()) + rb'\s*=\s*R"([^()\\\s"]{0,16})\((.*?)\)\1"', re.S)
    found = pat.findall(data)
    if len(found) != 1:
        raise SbomError(f"{where}: expected one raw string literal assigned to {symbol}, found {len(found)}")
    return found[0][1]


def vendored_bytes(root: Path, entry: dict) -> bytes:
    """The bytes yuzu-server embeds for one manifest file entry: the file itself,
    or the concatenated raw string literals it names (htmx is hand-split into
    literals in a .cpp rather than kept as a file)."""
    data = (root / entry["path"]).read_bytes()
    syms = entry.get("cpp_raw_strings")
    if syms:
        return b"".join(_cpp_raw_string(data, sym, entry["path"]) for sym in syms)
    return data


def _manifest_shape(m: dict) -> list[str]:
    errs = []
    comps = m.get("components")
    if not isinstance(comps, list) or not comps:
        return ["no components"]
    ids = [c.get("id") for c in comps]
    for dup in sorted({i for i in ids if ids.count(i) > 1}, key=str):
        errs.append(f"component id {dup!r} is listed twice")
    with_files = {c.get("id") for c in comps if c.get("files")}
    for c in comps:
        cid = c.get("id") or "?"
        for key in ("id", "name", "title", "license", "upstream", "version_source"):
            if not isinstance(c.get(key), str) or not c[key].strip():
                errs.append(f"{cid}: `{key}` is missing or empty")
        if c.get("type") not in VENDORED_TYPES:
            errs.append(f"{cid}: `type` must be one of {sorted(VENDORED_TYPES)}")
        if not str(c.get("upstream", "")).startswith("https://"):
            errs.append(f"{cid}: `upstream` must be an https URL")
        purl = c.get("purl")
        if purl is not None and not str(purl).startswith("pkg:"):
            errs.append(f"{cid}: `purl` must be a package URL or null")
        status = c.get("version_status")
        if status == "resolved":
            if not isinstance(c.get("version"), str) or not c["version"].strip():
                errs.append(f"{cid}: resolved but `version` is empty")
            if purl and "@" not in purl:
                errs.append(f"{cid}: resolved, so its purl must carry the version")
        elif status == "unresolved":
            if c.get("version") is not None:
                errs.append(f"{cid}: unresolved, so `version` must be null (do not guess)")
            if purl and "@" in purl:
                errs.append(f"{cid}: unresolved, so its purl must carry no version")
            if not isinstance(c.get("version_candidates"), list):
                errs.append(f"{cid}: unresolved needs a `version_candidates` list (may be empty)")
        else:
            errs.append(f"{cid}: `version_status` must be resolved or unresolved")
        if "part_of" in c:
            if c.get("files"):
                errs.append(f"{cid}: a component inside another (`part_of`) lists no files of its own")
            if c["part_of"] not in with_files:
                errs.append(f"{cid}: `part_of` names {c['part_of']!r}, which is not a component with files")
        elif not c.get("files"):
            errs.append(f"{cid}: lists no files (or set `part_of` to the component it is bundled in)")
    return errs


def _bad_relpath(rel: str) -> bool:
    """A manifest path that is not relative to the repository root."""
    return not rel or rel.startswith("/") or ".." in Path(rel).parts


def _linked_part(root: Path, rel: str):
    """The first part of `rel` (itself or a directory above it, below `root`)
    that is a symbolic link, or None. A link would let the manifest's check
    read bytes from outside the checkout, or skip a directory os.walk does not
    descend into. It assumes the checkout is not modified while the check
    runs: the read after this check follows links, so a link swapped in
    between would be read through (its bytes are still hashed against the
    manifest)."""
    parts = Path(rel).parts
    for i in range(1, len(parts) + 1):
        sub = "/".join(parts[:i])
        if os.path.islink(root / sub):
            return sub
    return None


def _link_problem(rel: str) -> str:
    return (f"{rel} is a symbolic link; a vendored file, a NOTICE and everything under a tracked root must be a "
            f"regular file or directory in the checkout")


def _first_party(rel: str, patterns) -> bool:
    """`rel` matches a first_party_patterns entry: the pattern's directory
    exactly (no glob there), and its file-name glob on the file name alone, so
    a `*` never crosses a `/` (static/yuzu-x/lodash.js is not `yuzu-*.js`)."""
    rdir, _, rbase = rel.rpartition("/")
    for p in patterns:
        pdir, _, pbase = str(p).rpartition("/")
        if rdir == pdir and fnmatch.fnmatchcase(rbase, pbase):
            return True
    return False


def _notice_text(data: bytes):
    """A NOTICE's text: strict UTF-8 (a leading byte-order mark is allowed), or
    None when the bytes are not valid UTF-8, which the caller fails. That
    catches a NOTICE re-encoded with a byte-order mark (UTF-16 with a BOM is
    not valid UTF-8), not every other encoding: a BOM-less UTF-16 file of
    ASCII text decodes as valid UTF-8 (with NULs), and then its SHA-256 and
    SPDX lines are simply not found, which the checks below treat like a
    NOTICE that records none."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def vendored_problems(manifest_path: Path, root: Path) -> list[str]:
    """Every way VENDORED_MANIFEST and the source tree under `root` disagree."""
    try:
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"{manifest_path}: {e}"]
    errs = [f"{manifest_path.name}: {e}" for e in _manifest_shape(m)]
    if errs:
        return errs
    tracked = [r.strip("/") for r in m.get("tracked_roots", [])]
    first_party = m.get("first_party_patterns", [])
    attribution = m.get("attribution_patterns", [])
    if not tracked:
        return [f"{manifest_path.name}: no `tracked_roots`"]

    def under_tracked(rel: str) -> bool:
        return any(rel.startswith(t + "/") for t in tracked)

    listed: set[str] = set()
    comp_hashes: dict = {}   # component id -> SHA-256 of each of its files
    notices: dict = {}       # NOTICE path -> the components naming it
    seen: set = set()
    for c in m["components"]:
        hashes = comp_hashes.setdefault(c["id"], set())
        for f in c.get("files", []):
            rel = str(f.get("path", ""))
            syms = tuple(f.get("cpp_raw_strings") or ())
            where = f"{c['id']}: {rel}{'#' + '+'.join(syms) if syms else ''}"
            if _bad_relpath(rel):
                errs.append(f"{where}: path must be relative to the repository root")
                continue
            if (rel, syms) in seen:
                errs.append(f"{where}: listed twice")
            seen.add((rel, syms))
            if not syms:
                if not under_tracked(rel):
                    errs.append(f"{where}: a vendored file must lie under {', '.join(tracked)} "
                                f"(or name the `cpp_raw_strings` it is embedded as)")
                if _first_party(rel, first_party):
                    errs.append(f"{where}: matches a first-party pattern but is listed as third-party")
                listed.add(rel)
            link = _linked_part(root, rel)
            if link:
                errs.append(_link_problem(link))
                continue
            if not (root / rel).is_file():
                errs.append(f"{where}: no such file")
                continue
            try:
                data = vendored_bytes(root, f)
            except (OSError, SbomError) as e:
                errs.append(f"{where}: {e}" if isinstance(e, OSError) else str(e))
                continue
            sha = hashlib.sha256(data).hexdigest()
            if sha != str(f.get("sha256", "")).lower() or len(data) != f.get("bytes"):
                errs.append(f"{where}: is {len(data)} bytes, SHA-256 {sha}; the manifest records "
                            f"{f.get('bytes')} bytes, {f.get('sha256')}. A vendored file changed: update its "
                            f"entry (version, version_source, sha256, bytes) together with the file")
            hashes.add(sha)
        for n in c.get("notice", []) or []:
            n = str(n)
            if _bad_relpath(n):
                errs.append(f"{c['id']}: notice {n}: path must be relative to the repository root")
                continue
            notices.setdefault(n, []).append(c)

    # Each NOTICE once, against the components that name it: its SPDX licence
    # must be each one's, and every SHA-256 it records must be one of THEIR
    # files' (a NOTICE carrying another component's hash vouches for nothing).
    for n, owners in sorted(notices.items()):
        ids = ", ".join(c["id"] for c in owners)
        link = _linked_part(root, n)
        if link:
            errs.append(_link_problem(link))
            continue
        if not (root / n).is_file():
            errs.extend(f"{c['id']}: notice {n} does not exist" for c in owners)
            continue
        try:
            text = _notice_text((root / n).read_bytes())
        except OSError as e:
            errs.append(f"{n}: cannot be read ({e.strerror or e})")
            continue
        if text is None:
            errs.append(f"{n} is not UTF-8 (the NOTICE of {ids}): its SHA-256 and SPDX lines cannot be checked")
            continue
        for c in owners:
            for lic in SPDX_LINE.findall(text):
                if lic != c["license"]:
                    errs.append(f"{c['id']}: {n} says SPDX-License-Identifier: {lic}, the manifest {c['license']}")
        own = set().union(*(comp_hashes.get(c["id"], set()) for c in owners))
        for h in NOTICE_SHA256.findall(text.encode("utf-8")):
            if h.decode().lower() not in own:
                errs.append(f"{n} records SHA-256 {h.decode()}, which is no file of a component naming it ({ids}): "
                            f"a stale NOTICE, or a file missing from {manifest_path.name}")

    for t in tracked:
        link = _linked_part(root, t)
        if link:
            errs.append(_link_problem(link))
            continue
        base = root / t
        if not base.is_dir():
            errs.append(f"tracked root {t} does not exist")
            continue

        def unreadable(e: OSError) -> None:
            where = Path(e.filename).relative_to(root).as_posix() if e.filename else t
            errs.append(f"{where}: cannot be read ({e.strerror or e}), so the files under it cannot be checked "
                        f"against {manifest_path.name}")

        for dirpath, dirs, files in os.walk(base, onerror=unreadable):
            # os.walk lists a link to a directory in `dirs` without descending
            # into it, and a link to a file (or a dangling one) in `files`.
            for name in [d for d in dirs if os.path.islink(os.path.join(dirpath, d))]:
                errs.append(_link_problem((Path(dirpath) / name).relative_to(root).as_posix()))
                dirs.remove(name)
            dirs.sort()
            for name in sorted(files):
                rel = (Path(dirpath) / name).relative_to(root).as_posix()
                if os.path.islink(root / rel):
                    errs.append(_link_problem(rel))
                    continue
                if rel in listed or _first_party(rel, first_party):
                    continue
                if any(fnmatch.fnmatchcase(name, p) for p in attribution):
                    if rel in notices:
                        continue  # checked above, against the components naming it
                    errs.append(f"{rel}: an attribution file no component in {manifest_path.name} names as its "
                                f"`notice`: name it on the component(s) it attributes")
                    continue
                errs.append(f"{rel}: not in {manifest_path.name}. A third-party file needs an entry with its "
                            f"version, licence and SHA-256; a first-party one a name matching "
                            f"first_party_patterns")
    return errs


def vendored_components(manifest_path: Path, root: Path) -> list[dict]:
    """The manifest's components, after checking it against the source tree."""
    errs = vendored_problems(manifest_path, root)
    if errs:
        shown = "; ".join(errs[:5]) + (f"; and {len(errs) - 5} more" if len(errs) > 5 else "")
        raise SbomError(f"{manifest_path} does not match the source tree under {root}: {shown}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))["components"]


def _file_note(f: dict) -> str:
    syms = f.get("cpp_raw_strings")
    where = f["path"] + (f" ({'+'.join(syms)})" if syms else "")
    return f"{where} sha256:{f['sha256']} bytes:{f['bytes']}"


def _vendored_cdx(c: dict, children: list[dict]) -> dict:
    out = {"bom-ref": f"vendored-{c['id']}", "type": VENDORED_TYPES[c["type"]], "name": c["name"]}
    if c.get("group"):
        out["group"] = c["group"]
    if c.get("version"):
        out["version"] = c["version"]
    out["description"] = c["title"]
    if c.get("purl"):
        out["purl"] = c["purl"]
    out["licenses"] = [{"license": {"id": c["license"]}}]
    files = c.get("files", [])
    if len(files) == 1:
        out["hashes"] = [{"alg": "SHA-256", "content": files[0]["sha256"]}]
    refs = [{"type": "vcs" if c["upstream"].startswith("https://github.com/") else "website", "url": c["upstream"]}]
    if c.get("download"):
        refs.append({"type": "distribution", "url": c["download"]})
    out["externalReferences"] = refs
    props = [("yuzu:vendored:version-source", c["version_source"])]
    if c["version_status"] == "unresolved":
        props.append(("yuzu:vendored:version", "unresolved; candidates: " + (", ".join(c["version_candidates"]) or "none")))
    props += [("yuzu:vendored:file", _file_note(f)) for f in files]
    props.append(("yuzu:vendored:manifest", VENDORED_MANIFEST))
    out["properties"] = [{"name": k, "value": v} for k, v in props]
    if children:
        out["components"] = [_vendored_cdx(ch, []) for ch in children]
    return out


def _vendored_spdx(c: dict, parent: dict | None) -> dict:
    files = c.get("files", [])
    if parent is None:
        where = "vendored in the Yuzu source tree (" + ", ".join(dict.fromkeys(f["path"] for f in files)) + ")"
    else:
        where = f"bundled inside {parent['name']} {parent.get('version') or ''}".rstrip()
    pkg = {"name": f"{c['group']}/{c['name']}" if c.get("group") else c["name"],
           "SPDXID": _vendored_spdx_id(c), "supplier": "NOASSERTION",
           "downloadLocation": c.get("download") or "NOASSERTION", "filesAnalyzed": False,
           "homepage": c["upstream"], "summary": c["title"],
           "sourceInfo": f"{where}, compiled into yuzu-server",
           "licenseConcluded": c["license"], "licenseDeclared": c["license"], "copyrightText": "NOASSERTION",
           "comment": " ".join([c["version_source"]] + [f"File: {_file_note(f)}." for f in files])}
    if c.get("version"):
        pkg["versionInfo"] = c["version"]
    if len(files) == 1:
        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": files[0]["sha256"]}]
    if c.get("purl"):
        pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                "referenceLocator": c["purl"]}]
    return pkg


def _vendored_spdx_id(c: dict) -> str:
    return "SPDXRef-Package-vendored-" + re.sub(r"[^A-Za-z0-9.-]", "-", c["id"])


# ── Merging ──────────────────────────────────────────────────────────────────

def _cdx_mark_incomplete(doc: dict, root: dict) -> None:
    doc["compositions"] = (doc.get("compositions") or []) + [
        {"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}]


def _spdx_mark_incomplete(doc: dict, root: dict) -> None:
    # SPDX 2.3 has no completeness field; NOASSERTION as the related element
    # says no assertion is made that the listed ones are all the root holds.
    doc.setdefault("relationships", []).append(
        {"spdxElementId": root["SPDXID"], "relationshipType": "CONTAINS", "relatedSpdxElement": "NOASSERTION"})


def merge_cdx(doc: dict, artifact: str, version: str, sha: str, notes: dict,
              vcomps: list[dict], hexmap: dict, wcomps: list[dict] = (),
              incomplete: bool = False) -> dict:
    meta = doc.setdefault("metadata", {})
    root = meta.setdefault("component", {})
    root.update({"type": "application", "name": artifact, "version": version,
                 "hashes": [{"alg": "SHA-256", "content": sha}]})
    root.setdefault("bom-ref", "artifact")
    meta["properties"] = meta.get("properties", []) + [
        {"name": NOTE_PREFIX + k, "value": v} for k, v in notes.items()]
    if incomplete:
        # The artifact holds components this SBOM does not list (notes say
        # which kind): machine-readable, not only prose.
        _cdx_mark_incomplete(doc, root)
    comps = doc.setdefault("components", [])
    for c in comps:
        new = _hex_purl(c.get("purl"), hexmap)
        if new:
            c.setdefault("properties", []).append({"name": "yuzu:otp:purl", "value": c["purl"]})
            c["purl"] = new
    for v in vcomps:
        c = {"bom-ref": f"vcpkg-{v['port']}", "type": "library", "name": v["port"],
             "version": v["version"], "purl": v["purl"]}
        if v["cpe"]:
            c["cpe"] = v["cpe"]
        if v["license"]:
            c["licenses"] = [{"expression": v["license"]}]
        if v["copyright"]:
            c["copyright"] = v["copyright"]
        refs = []
        if v["vcs"]:
            refs.append({"type": "vcs", "url": v["vcs"]})
        elif v["download"]:
            refs.append({"type": "distribution", "url": v["download"]})
        if v["homepage"]:
            refs.append({"type": "website", "url": v["homepage"]})
        if refs:
            c["externalReferences"] = refs
        props = [("yuzu:vcpkg:port", v["port"]), ("yuzu:vcpkg:port-version", v["port_version"]),
                 ("yuzu:vcpkg:triplet", v["triplet"])]
        if v["vcpkg_purl"]:
            props.append(("yuzu:vcpkg:purl", v["vcpkg_purl"]))
        c["properties"] = [{"name": k, "value": val} for k, val in props]
        comps.append(c)
    add_vendored_cdx(doc, wcomps)
    return doc


def add_vendored_cdx(doc: dict, wcomps: list[dict]) -> None:
    """Append the vendored components (a bundled one nested in its parent)."""
    comps = doc.setdefault("components", [])
    for w in wcomps:
        if "part_of" not in w:
            comps.append(_vendored_cdx(w, [ch for ch in wcomps if ch.get("part_of") == w["id"]]))


def _spdx_root(doc: dict) -> dict:
    ids = [r["relatedSpdxElement"] for r in doc.get("relationships", [])
           if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES"]
    ids += doc.get("documentDescribes", []) or []
    roots = [p for p in doc.get("packages", []) if p.get("SPDXID") in ids]
    if len(roots) != 1:
        raise SbomError(f"SPDX document must describe exactly one package, found {len(roots)}")
    return roots[0]


def merge_spdx(doc: dict, artifact: str, version: str, sha: str, notes: dict,
               vcomps: list[dict], hexmap: dict, wcomps: list[dict] = (),
               incomplete: bool = False) -> dict:
    root = _spdx_root(doc)
    root.update({"name": artifact, "versionInfo": version,
                 "checksums": [{"algorithm": "SHA256", "checksumValue": sha}],
                 "comment": spdx_notes_comment(notes)})
    if incomplete:
        _spdx_mark_incomplete(doc, root)
    for p in doc.get("packages", []):
        for ref in p.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                new = _hex_purl(ref.get("referenceLocator"), hexmap)
                if new:
                    ref["referenceLocator"] = new
    rels = doc.setdefault("relationships", [])
    for v in vcomps:
        sid = "SPDXRef-Package-vcpkg-" + re.sub(r"[^A-Za-z0-9.-]", "-", v["port"])
        pkg = {"name": v["port"], "SPDXID": sid, "versionInfo": v["version"],
               "supplier": "NOASSERTION",
               "downloadLocation": v["download"] or "NOASSERTION",
               "filesAnalyzed": False,
               "sourceInfo": f"vcpkg port {v['port']} {v['version']}#{v['port_version']} installed for "
                             f"triplet {v['triplet']}, built into the binaries this artifact ships",
               "licenseConcluded": "NOASSERTION",
               "licenseDeclared": v["license"] or "NOASSERTION",
               "copyrightText": v["copyright"] or "NOASSERTION",
               "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                 "referenceLocator": v["purl"]}]}
        if v["cpe"]:
            pkg["externalRefs"].insert(0, {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                                           "referenceLocator": v["cpe"]})
        if v["homepage"]:
            pkg["homepage"] = v["homepage"]
        doc.setdefault("packages", []).append(pkg)
        rels.append({"spdxElementId": root["SPDXID"], "relationshipType": "CONTAINS", "relatedSpdxElement": sid})
    add_vendored_spdx(doc, root["SPDXID"], wcomps)
    return doc


def add_vendored_spdx(doc: dict, root_id: str, wcomps: list[dict]) -> None:
    """Append one package per vendored component: `root_id` CONTAINS each
    top-level one, and a bundled one is CONTAINED by its parent."""
    rels = doc.setdefault("relationships", [])
    by_id = {w["id"]: w for w in wcomps}
    for w in wcomps:
        parent = by_id.get(w.get("part_of"))
        doc.setdefault("packages", []).append(_vendored_spdx(w, parent))
        rels.append({"spdxElementId": _vendored_spdx_id(parent) if parent else root_id,
                     "relationshipType": "CONTAINS", "relatedSpdxElement": _vendored_spdx_id(w)})


# ── Check ────────────────────────────────────────────────────────────────────

def _cdx_components(comps):
    for c in comps or []:
        yield c
        yield from _cdx_components(c.get("components"))


def _unpacked_files(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def inspect(doc: dict):
    """(format, entry_count, paths, described_name, described_sha256,
    unpacked_files): the last is the number of files `generate` recorded it
    unpacked from the artifact (0 when the SBOM records none)."""
    if doc.get("bomFormat") == "CycloneDX":
        comps = list(_cdx_components(doc.get("components")))
        paths = []
        for c in comps:
            if c.get("type") == "file":
                paths.append(c.get("name", ""))
            for p in c.get("properties", []) or []:
                if re.fullmatch(r"syft:location:\d+:path", p.get("name", "")):
                    paths.append(p.get("value", ""))
            for occ in (c.get("evidence") or {}).get("occurrences", []) or []:
                paths.append(occ.get("location", ""))
        meta = doc.get("metadata") or {}
        root = meta.get("component") or {}
        sha = next((h.get("content") for h in root.get("hashes", []) or [] if h.get("alg") == "SHA-256"), None)
        unpacked = _unpacked_files(cdx_note(meta, "unpacked-files"))
        return "cdx", len(comps), paths, root.get("name"), sha, unpacked
    if "spdxVersion" in doc:
        root = _spdx_root(doc)
        pkgs = [p for p in doc.get("packages", []) if p is not root]
        files = doc.get("files", []) or []
        # sourceInfo is prose ("acquired package info from ... file: /path",
        # or a comma-separated path list): each word holding a path separator
        # is checked as a path (the vcpkg ports' own sourceInfo has none).
        paths = [f.get("fileName", "") for f in files] + [
            w for p in pkgs for w in re.split(r"[\s,]+", p.get("sourceInfo") or "") if "/" in w or "\\" in w]
        sha = next((c.get("checksumValue") for c in root.get("checksums", []) or []
                    if c.get("algorithm") == "SHA256"), None)
        unpacked = spdx_note(root.get("comment"), "unpacked-files")
        return "spdx", len(pkgs) + len(files), paths, root.get("name"), sha, _unpacked_files(unpacked)
    raise SbomError("neither a CycloneDX nor an SPDX JSON document")


def check_file(path: Path, artifacts_dir: Path | None, max_components: int) -> list[str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        fmt, count, paths, name, sha, unpacked = inspect(doc)
    except (OSError, ValueError, SbomError) as e:
        return [f"{path.name}: {e}"]
    errs = []
    if count > max_components:
        errs.append(f"{path.name}: {count} entries, more than the bound of {max_components} "
                    f"(a checkout or build-tree scan, not an artifact scan?)")
    if count < 1 and unpacked < 1:
        # A file whose contents no scanner recognises (a plugins-only package)
        # legitimately has no components; an SBOM that records no unpacked
        # files as well is a scan of nothing.
        errs.append(f"{path.name}: no components at all, and no record that its file was unpacked and held files")
    bad = sorted({p for p in paths if FORBIDDEN_SEGMENTS.search(p)})
    if bad:
        errs.append(f"{path.name}: {len(bad)} path(s) under {FORBIDDEN_LABEL} e.g. {bad[:3]}")
    if artifacts_dir is not None:
        if not name or not sha:
            errs.append(f"{path.name}: the SBOM root carries no artifact name and SHA-256")
        else:
            target = artifacts_dir / name
            if "/" in name or "\\" in name or not target.is_file():
                errs.append(f"{path.name}: describes {name}, which is not in {artifacts_dir}")
            elif sha256_of(target) != sha.lower():
                errs.append(f"{path.name}: SHA-256 of {name} differs from the one the SBOM records")
            else:
                try:
                    expect = artifact_stem(name) + "." + ("cdx.json" if fmt == "cdx" else "spdx.json")
                except SbomError as e:
                    errs.append(f"{path.name}: {e}")
                else:
                    if path.name != expect:
                        errs.append(f"{path.name}: describes {name}, so it must be named {expect}")
    return errs


def is_image_sbom(name: str) -> bool:
    return name.endswith(("-image.cdx.json", "-image.spdx.json"))


# ── Image SBOMs ──────────────────────────────────────────────────────────────

# The OCI title label the release workflow sets on every image it publishes, as
# syft records it on a CycloneDX image SBOM.
IMAGE_TITLE_PROPERTY = "syft:image:labels:org.opencontainers.image.title"
# Titles of the release's Yuzu images (docker-publish: yuzu-<image>;
# docker-publish-chisel: yuzu-<image>-chisel). Such an image must show syft
# listing what its title promises, or the marker would silently not be added.
YUZU_IMAGE_TITLE = re.compile(r"^yuzu-(server|agent|gateway|postgres)(?:-chisel)?$")


def _image_roots(cdx: dict, spdx: dict) -> tuple[dict, dict]:
    """The described image in each document, after checking that both are a
    syft scan of ONE container image (not an artifact SBOM, not a mixed pair)."""
    if cdx.get("bomFormat") != "CycloneDX":
        raise SbomError("--cdx is not a CycloneDX JSON document")
    if "spdxVersion" not in spdx:
        raise SbomError("--spdx is not an SPDX JSON document")
    croot = (cdx.get("metadata") or {}).get("component") or {}
    sroot = _spdx_root(spdx)
    if croot.get("type") != "container" or sroot.get("primaryPackagePurpose") != "CONTAINER":
        raise SbomError("not an image SBOM: the described root is not a container image")
    if (croot.get("name"), croot.get("version")) != (sroot.get("name"), sroot.get("versionInfo")):
        raise SbomError(f"the two SBOMs describe different images: {croot.get('name')}@{croot.get('version')} "
                        f"(CycloneDX), {sroot.get('name')}@{sroot.get('versionInfo')} (SPDX)")
    return croot, sroot


def image_title(cdx: dict) -> str:
    """The OCI title label syft recorded on a CycloneDX image SBOM ("" if none)."""
    meta = cdx.get("metadata") or {}
    return next((p.get("value", "") for p in ((meta.get("component") or {}).get("properties") or []) +
                 (meta.get("properties") or []) if p.get("name") == IMAGE_TITLE_PROPERTY), "")


def _image_paths(cdx: dict, spdx: dict) -> list[str]:
    """The file paths syft lists in an image (absolute, /-separated). syft 1.57
    records an unpackaged binary as an SPDX file only, not as a CycloneDX
    component, so both documents are read."""
    listed = [c.get("name", "") for c in _cdx_components(cdx.get("components")) if c.get("type") == "file"]
    listed += [f.get("fileName", "") for f in spdx.get("files", []) or []]
    return sorted({"/" + p.replace("\\", "/").lstrip("/") for p in listed if p})


def _image_base(p: str) -> str:
    return installed_name(p.rsplit("/", 1)[-1])


def image_server_paths(cdx: dict, spdx: dict) -> list[str]:
    """The yuzu-server binaries syft lists in an image."""
    return [p for p in _image_paths(cdx, spdx) if _image_base(p) in SERVER_NAMES]


def image_incomplete_reasons(cdx: dict, spdx: dict) -> list[tuple[str, str]]:
    """[(token, detail)] for what an image holds that its syft scan cannot list:
    Yuzu C++ binaries (their static vcpkg libraries), the Erlang emulator
    (what it vendors) and the source-built pgvector. What is compiled into
    yuzu-server from VENDORED_MANIFEST is not a reason: `augment` lists it."""
    croot, _sroot = _image_roots(cdx, spdx)
    paths = _image_paths(cdx, spdx)
    base = _image_base
    server = [p for p in paths if base(p) in SERVER_NAMES]
    cpp = [p for p in paths if base(p) in SERVER_NAMES or base(p) in AGENT_NAMES or base(p).startswith(AGENT_PREFIXES)]
    erts = [p for p in paths if base(p) == ERTS_EMULATOR]
    pgvector = [p for p in paths if base(p) == "vector.so" and "/postgresql/" in p]
    title = image_title(cdx)
    m = YUZU_IMAGE_TITLE.match(title)
    if m:
        want = {"server": ("yuzu-server", server), "agent": ("yuzu-agent", cpp),
                "gateway": ("the Erlang emulator (beam.smp)", erts),
                "postgres": ("pgvector (vector.so)", pgvector)}[m.group(1)]
        if not want[1]:
            raise SbomError(f"image {croot.get('name')} is labelled {title}, but syft lists no {want[0]} in it: "
                            f"refusing to leave its SBOM unmarked (did syft stop listing unpackaged files?)")
    reasons: list[tuple[str, str]] = []
    if cpp:
        reasons.append(("image-static-cpp", ", ".join(cpp)))
    if erts:
        reasons.append(("erts-static", ", ".join(erts)))
    if pgvector:
        reasons.append(("pgvector-source", ", ".join(pgvector)))
    return reasons


def _reason_tokens(value) -> list[str]:
    return [t.strip() for t in (value or "").split(",") if t.strip()]


# image_marker()'s state for a document that carries only some parts of the
# marker (the composition or relationship without the reason tokens, or the
# tokens without it): never a complete marker, so mark_image and the release
# check both refuse it rather than treat it as marked.
PARTIAL = "partial"


def image_marker(cdx: dict, spdx: dict):
    """(cdx_state, spdx_state). Each is the list of incomplete-reason tokens
    when the document carries the whole marker (CycloneDX: the incomplete
    composition on the root AND a non-empty `yuzu:sbom:incomplete-reasons`
    property; SPDX: the root's `CONTAINS NOASSERTION` AND a non-empty
    `yuzu:sbom:incomplete-reasons` comment line), None when it carries no part
    of it, and PARTIAL otherwise."""
    croot, sroot = _image_roots(cdx, spdx)
    cmarked = any(c.get("aggregate") == "incomplete" and croot.get("bom-ref") in (c.get("assemblies") or [])
                  for c in cdx.get("compositions") or [])
    ctok = cdx_note(cdx.get("metadata"), "incomplete-reasons")
    smarked = any(r.get("spdxElementId") == sroot.get("SPDXID") and r.get("relationshipType") == "CONTAINS"
                  and r.get("relatedSpdxElement") == "NOASSERTION" for r in spdx.get("relationships") or [])
    stok = spdx_note(sroot.get("comment"), "incomplete-reasons")

    def state(marked, tokens):
        if not marked and tokens is None:
            return None
        return _reason_tokens(tokens) if marked and _reason_tokens(tokens) else PARTIAL
    return state(cmarked, ctok), state(smarked, stok)


def _marker_label(state) -> str:
    if state is None:
        return "unmarked"
    if state == PARTIAL:
        return "only in part (its composition or relationship, or its reason tokens, missing)"
    return ", ".join(state)


def mark_image(cdx: dict, spdx: dict) -> tuple[list[str], bool]:
    """Mark an image SBOM pair incomplete, in place, for what
    image_incomplete_reasons() finds. Returns (tokens, changed). Idempotent: a
    pair whose two documents each carry the whole marker with exactly those
    tokens is left as it is. Any other existing marker or part of one, on
    either document, is refused."""
    reasons = image_incomplete_reasons(cdx, spdx)
    notes = incomplete_notes(reasons)
    want = _reason_tokens(notes.get("incomplete-reasons"))
    have = image_marker(cdx, spdx)
    if have == (None, None):
        if not want:
            return [], False
    elif have == (want, want) and want:
        return want, False
    else:
        raise SbomError(f"the pair is already marked: {_marker_label(have[0])} (CycloneDX) / "
                        f"{_marker_label(have[1])} (SPDX), not {', '.join(want) or 'unmarked'}: "
                        f"mark a fresh syft scan")
    croot, sroot = _image_roots(cdx, spdx)
    croot.setdefault("bom-ref", "image")
    _cdx_mark_incomplete(cdx, croot)
    meta = cdx.setdefault("metadata", {})
    meta["properties"] = (meta.get("properties") or []) + [
        {"name": NOTE_PREFIX + k, "value": v} for k, v in notes.items()]
    _spdx_mark_incomplete(spdx, sroot)
    sroot["comment"] = "\n".join([c for c in [sroot.get("comment")] if c] + [spdx_notes_comment(notes)])
    return want, True


def image_vendored_state(cdx: dict, spdx: dict) -> tuple:
    """(cdx_state, spdx_state) of yuzu-server's vendored components on an image
    pair. Each is True when the document carries both the `yuzu:sbom:vendored`
    note and the vendored entries `augment` adds, None when it carries neither,
    and PARTIAL otherwise."""
    _croot, sroot = _image_roots(cdx, spdx)
    cnote = cdx_note(cdx.get("metadata"), "vendored")
    ccomps = any(str(c.get("bom-ref", "")).startswith("vendored-") for c in _cdx_components(cdx.get("components")))
    snote = spdx_note(sroot.get("comment"), "vendored")
    spkgs = any(str(p.get("SPDXID", "")).startswith("SPDXRef-Package-vendored-") for p in spdx.get("packages") or [])

    def state(note, entries):
        if note is None and not entries:
            return None
        return True if note is not None and entries else PARTIAL
    return state(cnote, ccomps), state(snote, spkgs)


def augment_image(cdx: dict, spdx: dict, load_vendored) -> list[str]:
    """Add yuzu-server's vendored components to an image SBOM pair in place when
    syft lists a yuzu-server binary in the image; return those paths (empty:
    the pair is untouched). syft's own entries are kept as they are:
    components, packages and relationships are only appended to, and the
    `yuzu:sbom:vendored` note is added (a CycloneDX metadata property, a line
    of the SPDX root's comment after any comment syft wrote). `load_vendored`
    returns the manifest's components after checking it against the source
    tree, and is called only for an image holding yuzu-server. Refuses a pair
    that is not one image's, an image labelled as the release's server image
    in which syft lists no yuzu-server, and a pair already carrying any part
    of what this adds (with or without yuzu-server in the image, as the
    release check does)."""
    croot, sroot = _image_roots(cdx, spdx)
    found = image_server_paths(cdx, spdx)
    vendored = image_vendored_state(cdx, spdx)
    title = image_title(cdx)
    m = YUZU_IMAGE_TITLE.match(title)
    if not found:
        if m and m.group(1) == "server":
            raise SbomError(f"image {croot.get('name')} is labelled {title}, but syft lists no yuzu-server binary "
                            f"in it: refusing to publish its SBOM without the components compiled into yuzu-server "
                            f"(did syft stop listing unpackaged files?)")
        if vendored != (None, None):
            raise SbomError(f"the pair lists yuzu-server's vendored components ({_vendored_label(vendored[0])} / "
                            f"{_vendored_label(vendored[1])}), but syft lists no yuzu-server in the image")
        return []
    if vendored != (None, None):
        raise SbomError("the pair already lists yuzu-server's vendored components (or part of them): augment a "
                        "fresh syft scan")
    wcomps = load_vendored()
    notes = {"vendored": (f"{len(wcomps)} third-party components compiled into yuzu-server ({', '.join(found)}; "
                          f"web assets and the QR-code library), from {VENDORED_MANIFEST}: an image scan cannot "
                          f"see them in the binary")}
    comment = spdx_notes_comment(notes)
    add_vendored_cdx(cdx, wcomps)
    meta = cdx.setdefault("metadata", {})
    meta["properties"] = (meta.get("properties") or []) + [
        {"name": NOTE_PREFIX + k, "value": v} for k, v in notes.items()]
    add_vendored_spdx(spdx, sroot["SPDXID"], wcomps)
    sroot["comment"] = "\n".join([c for c in [sroot.get("comment")] if c] + [comment])
    return found


def image_pair_errors(adir: Path) -> list[str]:
    """The release gate for image SBOMs in `adir`: each `<stem>-image.cdx.json`
    has its SPDX partner, a pair named as one of the release's images
    (`<title>-image`, YUZU_IMAGE_TITLE) carries that image's title label, the
    pair carries exactly the marker mark-image adds, and it lists yuzu-server's
    vendored components (in both formats) exactly when syft lists yuzu-server
    in the image."""
    stems: dict = {}
    for p in sorted(adir.iterdir()):
        if is_image_sbom(p.name):
            stem, _, fmt = p.name.rpartition("-image.")
            stems.setdefault(stem, {})[fmt] = p
    errs = []
    for stem, pair in sorted(stems.items()):
        if set(pair) != {"cdx.json", "spdx.json"}:
            errs.append(f"{stem}-image: only {', '.join(sorted(pair))}; an image SBOM is a CycloneDX and SPDX pair")
            continue
        try:
            cdx, spdx = (json.loads(pair[f].read_text(encoding="utf-8")) for f in ("cdx.json", "spdx.json"))
            want = _reason_tokens(incomplete_notes(image_incomplete_reasons(cdx, spdx)).get("incomplete-reasons"))
            have = image_marker(cdx, spdx)
            server = image_server_paths(cdx, spdx)
            vendored = image_vendored_state(cdx, spdx)
        except (OSError, ValueError, SbomError) as e:
            errs.append(f"{stem}-image: {e}")
            continue
        # The marker a release image needs is keyed on its title label: a pair
        # named as a release image whose label is missing or another image's
        # would otherwise be held to nothing.
        title = image_title(cdx)
        if YUZU_IMAGE_TITLE.match(stem) and title != stem:
            label = f"its title label is {title!r}" if title else "it carries no title label"
            errs.append(f"{stem}-image: named as the release's {stem} image, but {label}, so the marker "
                        f"it needs cannot be decided")
            continue
        if want and have != (want, want):
            marked = ("carries no marker" if have == (None, None) else
                      f"is marked {_marker_label(have[0])} / {_marker_label(have[1])}")
            errs.append(f"{stem}-image: the image holds what its SBOM cannot list ({', '.join(want)}), but the pair "
                        f"{marked}: run `artifact-sbom.py mark-image` on a fresh scan")
        elif not want and have != (None, None):
            errs.append(f"{stem}-image: marked incomplete ({_marker_label(have[0])} / {_marker_label(have[1])}) "
                        f"for nothing the image is seen to hold")
        if server and vendored != (True, True):
            errs.append(f"{stem}-image: the image holds yuzu-server ({', '.join(server)}), but the pair does not list "
                        f"the components compiled into it ({_vendored_label(vendored[0])} (CycloneDX) / "
                        f"{_vendored_label(vendored[1])} (SPDX)): run `artifact-sbom.py augment` on a fresh scan")
        elif not server and vendored != (None, None):
            errs.append(f"{stem}-image: lists yuzu-server's vendored components ({_vendored_label(vendored[0])} / "
                        f"{_vendored_label(vendored[1])}), but syft lists no yuzu-server in the image")
    return errs


def _vendored_label(state) -> str:
    if state is None:
        return "not listed"
    if state == PARTIAL:
        return "only in part (the yuzu:sbom:vendored note or the vendored entries missing)"
    return "listed"


# ── Commands ─────────────────────────────────────────────────────────────────

# What yuzu-server compiles in from VENDORED_MANIFEST is not an incompleteness
# reason: `generate` lists it on every file holding yuzu-server and `augment`
# on every image holding it, and a manifest that does not match the source
# tree fails either.
INSTALLER_UNLISTED = ("the installer's own InnoSetup runtime (setup loader and uninstaller) and what it embeds "
                      "besides the files its manifest lists (licence text, icon, compiled [Code] script) are not "
                      "listed")

# Why an SBOM says it is incomplete: a CLOSED set. An SBOM carrying the marker
# names its reasons by these tokens, comma-separated, in
# `yuzu:sbom:incomplete-reasons` (CycloneDX metadata property; SPDX: that key's
# line of the root's comment, NOTE_PREFIX), and the prose (each entry below, with any detail after a colon) in
# `yuzu:sbom:incomplete`, joined by " | ". A consumer may rely on the tokens;
# the prose may change. docs/user-manual/release-verification.md documents the
# same set and tests/test_artifact_sbom.py fails if the two differ. A new
# reason is a new token here and a new row there; never reuse one for another
# meaning. Retired, never to be reused: `server-vendored` (yuzu-server's
# vendored code, which `generate` and `augment` now list; it was never in a
# release).
INCOMPLETE_REASONS = {
    "installer-runtime": INSTALLER_UNLISTED,
    "erts-static": ("the bundled Erlang runtime is listed as one component (erlang), but its emulator beam.smp "
                    "links in code it vendors (PCRE2, asmjit, zstd, Ryu, an MD5 taken from OpenSSL) that this "
                    "SBOM does not list"),
    "image-static-cpp": ("the image holds Yuzu C++ binaries whose vcpkg libraries are linked statically, which an "
                         "image scan cannot see: the SBOM of the matching package or archive lists them"),
    "pgvector-source": ("the image's pgvector extension is built from source (deploy/docker/Dockerfile.postgres) "
                        "and has no package record, so the image scan does not list it"),
}


def incomplete_notes(reasons: list[tuple[str, str]]) -> dict:
    """{"incomplete": prose, "incomplete-reasons": tokens} for [(token, detail)];
    {} for none. A token outside INCOMPLETE_REASONS is a bug, not a new reason."""
    tokens: list[str] = []
    prose: list[str] = []
    for token, detail in reasons:
        if token not in INCOMPLETE_REASONS:
            raise SbomError(f"internal: {token!r} is not an incomplete reason (INCOMPLETE_REASONS)")
        if token not in tokens:
            tokens.append(token)
        prose.append(INCOMPLETE_REASONS[token] + (f": {detail}" if detail else ""))
    if not tokens:
        return {}
    return {"incomplete": " | ".join(prose), "incomplete-reasons": ", ".join(tokens)}


def _syft(a, contents: Path, artifact: Path, syft_cdx: Path, syft_spdx: Path) -> None:
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
    try:
        r = subprocess.run([a.syft, "scan", f"dir:{contents}", "--source-name", artifact.name,
                            "--source-version", a.version, "-q",
                            "-o", f"cyclonedx-json={syft_cdx}", "-o", f"spdx-json={syft_spdx}"],
                           capture_output=True, text=True, env=env, timeout=SYFT_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise _timeout_error([a.syft], SYFT_TIMEOUT) from e
    if r.returncode != 0:
        raise SbomError(f"syft exited {r.returncode}: {r.stderr.strip()[:1000]}")


def _describe(a, artifact: Path, tmp: Path):
    """Unpack, scan and merge; returns (cdx, spdx, vcomps, wcomps)."""
    contents = tmp / "contents"
    contents.mkdir()
    incomplete: list[tuple[str, str]] = []
    if a.inno_manifest is None:
        extract(artifact, contents)
        notes = {"artifact": artifact.name, "contents": f"unpacked from {artifact.name}"}
    else:
        manifest = Path(a.inno_manifest)
        listed = installer_contents(manifest, Path(a.build_dir), a.inno_build_dir, contents)
        notes = {"artifact": artifact.name,
                 "contents": (f"{artifact.name} is not unpacked here; its contents are the {len(listed)} file(s) "
                              f"the Inno Setup compiler's manifest ({manifest.name}, OutputManifestFile) lists for "
                              f"it, each read from the build directory and matching the SHA-256 the compiler "
                              f"recorded, listed at its path below the build directory, not the path it is "
                              f"installed to")}
        incomplete.append(("installer-runtime", ""))
    files = count_files(contents)
    if files < 1:
        raise SbomError(f"{artifact.name}: unpacked to no files")
    notes["unpacked-files"] = str(files)
    agent, server = yuzu_binaries(contents)
    vcomps: list[dict] = []
    if agent or server:
        if not a.vcpkg_installed:
            raise SbomError(f"{artifact.name} ships a Yuzu C++ binary: pass --vcpkg-installed, --triplet and --manifest")
        installed = Path(a.vcpkg_installed)
        ports = installed_ports(parse_status(installed / "vcpkg" / "status"), a.triplet)
        manifest = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
        names = vcpkg_closure(ports, manifest, a.triplet, agent, server)
        vcomps = vcpkg_components(installed, a.triplet, names, ports)
        notes["vcpkg"] = (f"{len(vcomps)} ports from the installed {a.triplet} tree for the "
                          f"{'+'.join(x for x, y in (('agent', agent), ('server', server)) if y)} build")
        noassert = sorted(v["port"] for v in vcomps if not v["license"])
        if noassert:
            notes["licence-noassertion"] = ", ".join(noassert)
            print(f"::warning::{artifact.name}: {len(noassert)} vcpkg port(s) have no licence in their vcpkg "
                  f"SPDX file and are listed without one (NOASSERTION): {', '.join(noassert)}", file=sys.stderr)
    elif a.vcpkg_installed:
        raise SbomError(f"{artifact.name}: --vcpkg-installed given but no Yuzu C++ binary found in it")
    wcomps: list[dict] = []
    if server:
        wcomps = vendored_components(*_vendored_paths(a))
        notes["vendored"] = (f"{len(wcomps)} third-party components compiled into yuzu-server "
                             f"(web assets and the QR-code library), from {VENDORED_MANIFEST}")
    erts = erts_emulators(contents)
    if erts:
        incomplete.append(("erts-static", ", ".join(erts)))
    notes.update(incomplete_notes(incomplete))
    hexmap = hex_packages(Path(a.rebar_lock)) if a.rebar_lock else {}
    syft_cdx, syft_spdx = tmp / "syft.cdx.json", tmp / "syft.spdx.json"
    _syft(a, contents, artifact, syft_cdx, syft_spdx)
    sha = sha256_of(artifact)
    cdx = merge_cdx(json.loads(syft_cdx.read_text(encoding="utf-8")), artifact.name, a.version,
                    sha, notes, vcomps, hexmap, wcomps, incomplete=bool(incomplete))
    spdx = merge_spdx(json.loads(syft_spdx.read_text(encoding="utf-8")), artifact.name, a.version,
                      sha, notes, vcomps, hexmap, wcomps, incomplete=bool(incomplete))
    return cdx, spdx, vcomps, wcomps


def cmd_generate(a) -> int:
    artifact = Path(a.artifact)
    if not artifact.is_file():
        raise SbomError(f"{artifact}: no such artifact")
    stem = artifact_stem(artifact.name)
    out_dir = Path(a.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # mkdtemp + a cleanup that cannot fail the run: on Windows an indexer or
    # Defender handle on an unpacked DLL makes removal raise PermissionError
    # after the SBOMs are already made (and TemporaryDirectory's
    # ignore_cleanup_errors needs Python 3.10, and this script supports 3.9).
    tmp = Path(tempfile.mkdtemp(prefix="yuzu_sbom_", dir=os.environ.get("RUNNER_TEMP") or None))
    try:
        cdx, spdx, vcomps, wcomps = _describe(a, artifact, tmp)
        outs = []
        for fmt, doc in (("cdx.json", cdx), ("spdx.json", spdx)):
            p = out_dir / f"{stem}.{fmt}"
            # newline="\n": the same bytes on every OS (no CRLF on Windows).
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(doc, indent=2) + "\n")
            outs.append(p)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if tmp.exists():
            print(f"::warning::could not remove the temporary directory {tmp}", file=sys.stderr)
    errs = [e for p in outs for e in check_file(p, artifact.parent, MAX_COMPONENTS)]
    for p in outs:
        count = inspect(json.loads(p.read_text(encoding="utf-8")))[1]
        print(f"{p.name}: {count} entries ({len(vcomps)} vcpkg ports, {len(wcomps)} vendored components)")
    for e in errs:
        print(f"::error::{e}", file=sys.stderr)
    return 1 if errs else 0


def _vendored_paths(a) -> tuple[Path, Path]:
    root = Path(a.source_root) if a.source_root else REPO_ROOT
    manifest = Path(a.vendored_components) if a.vendored_components else root / VENDORED_MANIFEST
    return manifest, root


def cmd_check_vendored(a) -> int:
    manifest, root = _vendored_paths(a)
    errs = vendored_problems(manifest, root)
    for e in errs:
        print(f"::error::{e}", file=sys.stderr)
    print(f"vendored components: {manifest} against {root}: {'FAILED' if errs else 'OK'}")
    return 1 if errs else 0


def cmd_check(a) -> int:
    adir = Path(a.artifacts_dir) if a.artifacts_dir else None
    files = [Path(f) for f in a.sboms]
    if not files:
        if adir is None:
            raise SbomError("give SBOM files, or --artifacts-dir to check every artifact SBOM in it")
        files = sorted(p for p in adir.iterdir()
                       if p.name.endswith((".cdx.json", ".spdx.json")) and not is_image_sbom(p.name))
        if not files:
            raise SbomError(f"no artifact SBOMs in {adir}")
    errs = [e for f in files for e in check_file(f, adir, a.max_components)]
    images = ""
    if adir is not None and not a.sboms:
        image_errs = image_pair_errors(adir)
        errs += image_errs
        n = len({p.name.rpartition("-image.")[0] for p in adir.iterdir() if is_image_sbom(p.name)})
        images = f"; {n} image SBOM pair(s), {'FAILED' if image_errs else 'OK'}"
    for e in errs:
        print(f"::error::{e}", file=sys.stderr)
    print(f"artifact SBOM check: {len(files)} file(s), {'FAILED' if errs else 'OK'} "
          f"(bound {a.max_components} entries; no path under {FORBIDDEN_LABEL}){images}")
    return 1 if errs else 0


def _read_image_pair(a) -> tuple[list[Path], dict, dict]:
    """The --cdx/--spdx pair of one image's SBOM, by name and content."""
    paths = [Path(a.cdx), Path(a.spdx)]
    for p, suffix in zip(paths, ("-image.cdx.json", "-image.spdx.json")):
        if not p.name.endswith(suffix):
            raise SbomError(f"{p.name}: an image SBOM is named *{suffix} (the release's artifact SBOM check "
                            f"treats only those as image SBOMs)")
    if paths[0].name[: -len("-image.cdx.json")] != paths[1].name[: -len("-image.spdx.json")]:
        raise SbomError(f"{paths[0].name} and {paths[1].name} are not one image's pair")
    try:
        cdx, spdx = (json.loads(p.read_text(encoding="utf-8")) for p in paths)
    except (OSError, ValueError) as e:
        raise SbomError(str(e)) from e
    return paths, cdx, spdx


def _write_image_pair(paths: list[Path], cdx: dict, spdx: dict, tag: str) -> None:
    """Rewrite an image pair in place. Both files are written out in full
    before either is replaced, so a failed write leaves the pair as it was and
    no temporary file behind. The two replacements are two renames, not one:
    if the second fails after the first succeeded, the CycloneDX half is the
    new one and the SPDX half the old one. That torn pair fails the job (the
    error propagates) and, if it were uploaded anyway, the release check
    (image_pair_errors), which refuses a pair whose halves disagree on the
    marker or on the vendored components."""
    tmps = [p.with_name(f"{p.name}.{tag}.tmp") for p in paths]
    try:
        for t, doc in zip(tmps, (cdx, spdx)):
            with open(t, "w", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(doc, indent=2) + "\n")
        for t, p in zip(tmps, paths):
            os.replace(t, p)
    finally:
        for t in tmps:
            if t.exists():
                t.unlink()


def cmd_mark_image(a) -> int:
    paths, cdx, spdx = _read_image_pair(a)
    tokens, changed = mark_image(cdx, spdx)
    label = f"{paths[0].name}, {paths[1].name}"
    if not changed:
        print(f"{label}: {'already marked incomplete (' + ', '.join(tokens) + ')' if tokens else 'nothing the scan cannot list; left unchanged'}")
        return 0
    _write_image_pair(paths, cdx, spdx, "mark")
    print(f"{label}: marked incomplete ({', '.join(tokens)})")
    return 0


def cmd_augment(a) -> int:
    paths, cdx, spdx = _read_image_pair(a)
    found = augment_image(cdx, spdx, lambda: vendored_components(*_vendored_paths(a)))
    label = f"{paths[0].name}, {paths[1].name}"
    if not found:
        print(f"{label}: no yuzu-server in the image; left unchanged")
        return 0
    _write_image_pair(paths, cdx, spdx, "augment")
    n = sum(1 for p in spdx["packages"] if p.get("SPDXID", "").startswith("SPDXRef-Package-vendored-"))
    print(f"{label}: added {n} vendored components (yuzu-server at {', '.join(found)})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="CycloneDX + SPDX SBOM for one artifact")
    g.add_argument("--artifact", required=True)
    g.add_argument("--version", required=True)
    g.add_argument("--syft", required=True)
    g.add_argument("--out-dir", required=True)
    g.add_argument("--inno-manifest", help="for an InnoSetup installer: the manifest the same ISCC run wrote "
                                           "(OutputManifestFile); its files are described (needs --build-dir and "
                                           "--inno-build-dir)")
    g.add_argument("--build-dir", help="the build directory the installer's files are read from")
    g.add_argument("--inno-build-dir", help="that build directory as ISCC was given it (/DBuildDir), a "
                                            "drive-absolute Windows path: the prefix of the manifest's paths")
    g.add_argument("--vcpkg-installed", help="the vcpkg_installed directory (holds vcpkg/status)")
    g.add_argument("--triplet")
    g.add_argument("--manifest", help="vcpkg.json")
    g.add_argument("--rebar-lock", help="gateway rebar.lock, to give Hex packages a pkg:hex purl")
    v = sub.add_parser("check-vendored", help="the vendored-components manifest against the source tree")
    au = sub.add_parser("augment", help="add yuzu-server's vendored components to a syft image SBOM pair, in place")
    au.add_argument("--cdx", required=True, help="the image's CycloneDX SBOM (*-image.cdx.json)")
    au.add_argument("--spdx", required=True, help="the same image's SPDX SBOM (*-image.spdx.json)")
    for p in (g, v, au):
        p.add_argument("--source-root", help="repository root holding the vendored files (default: this checkout)")
        p.add_argument("--vendored-components", help=f"the manifest (default: <source root>/{VENDORED_MANIFEST})")
    c = sub.add_parser("check", help="the release gate over artifact SBOMs")
    c.add_argument("--artifacts-dir")
    c.add_argument("--max-components", type=int, default=MAX_COMPONENTS)
    c.add_argument("sboms", nargs="*")
    mi = sub.add_parser("mark-image", help="mark a syft image SBOM pair incomplete where the image holds what the "
                                           "scan cannot list, in place")
    mi.add_argument("--cdx", required=True, help="the image's CycloneDX SBOM (*-image.cdx.json)")
    mi.add_argument("--spdx", required=True, help="the same image's SPDX SBOM (*-image.spdx.json)")
    a = ap.parse_args(argv)
    label = {"generate": lambda: Path(a.artifact).name, "mark-image": lambda: Path(a.cdx).name,
             "augment": lambda: Path(a.cdx).name,
             "check-vendored": lambda: "vendored components check"}.get(
        a.cmd, lambda: "artifact SBOM check")()
    try:
        if a.cmd == "generate":
            if a.vcpkg_installed and not (a.triplet and a.manifest):
                raise SbomError("--vcpkg-installed needs --triplet and --manifest")
            inno = (a.inno_manifest, a.build_dir, a.inno_build_dir)
            if any(inno) and not all(inno):
                raise SbomError("--inno-manifest, --build-dir and --inno-build-dir go together: an installer's "
                                "SBOM is made from the compiler's manifest, read against the build directory")
            if a.inno_manifest and not Path(a.artifact).name.endswith(".exe"):
                raise SbomError(f"{Path(a.artifact).name}: --inno-manifest describes an InnoSetup installer (.exe)")
            return cmd_generate(a)
        if a.cmd == "mark-image":
            return cmd_mark_image(a)
        if a.cmd == "check-vendored":
            return cmd_check_vendored(a)
        if a.cmd == "augment":
            return cmd_augment(a)
        return cmd_check(a)
    except SbomError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - one annotated line, not a traceback
        print(f"::error::{label}: unexpected {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
