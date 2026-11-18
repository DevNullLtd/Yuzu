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
     not unpacked here: its contents are the files of the archive named by
     --contents-from that the installer script named by --iss installs (its
     [Files] `Source:` lines, resolved against the archive's layout); a file
     the installer does not install is dropped, and the SBOM root says so.
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
  3. With --rebar-lock, an Erlang application that is a Hex package in the lock
     gets a `pkg:hex` purl (syft reports every OTP application as `pkg:otp`).
  4. Stamp the artifact's file name, version and SHA-256 on the SBOM root, write
     `<stem>.cdx.json` and `<stem>.spdx.json`, and run the `check` below on both.

Not every component is listed. Code vendored into the source tree (for
yuzu-server, server/core/vendor: qrcodegen and the embedded web assets), an
installer's own runtime (InnoSetup's setup loader and uninstaller), and the code
the bundled Erlang runtime's emulator (beam.smp) vendors and links statically
(PCRE2, asmjit, zstd, Ryu, an MD5 taken from OpenSSL; syft lists the runtime as
one `erlang` component) are not. An SBOM whose file holds any of them carries a
CycloneDX composition with `aggregate: incomplete` on the root (SPDX 2.3 has no
such field: the root gets a `CONTAINS NOASSERTION` relationship, SPDX's way of
saying no assertion is made that the listed elements are all it contains), and
says why: `yuzu:sbom:incomplete-reasons` holds tokens from the closed set
INCOMPLETE_REASONS and `yuzu:sbom:incomplete` the prose (CycloneDX metadata
properties; SPDX: the root's comment). Libraries a binary loads from the
operating system at run time are not in the file, so they are not a reason.

`mark-image` adds the same marker to a syft scan of a published container
image, given as its CycloneDX and SPDX pair and rewritten in place, when syft
lists a statically linked Yuzu C++ binary (whose vcpkg libraries an image scan
cannot see), the Erlang emulator or the source-built pgvector in it. It refuses
a pair that does not describe one image, an image labelled as the release's
server, agent, gateway or postgres image in which syft lists no such file, and
a pair already marked differently; a pair already marked the same way is left
as it is.

`check` is the release gate: an artifact SBOM fails when it has more than
MAX_COMPONENTS entries, has none and does not record that its file was
unpacked and held files, lists a path with one of the FORBIDDEN_SEGMENTS (a
checkout, vcpkg or build tree, the docs site or a test tree, the paths a scan of
the wrong directory lists; a path elsewhere is not detected), or (with
--artifacts-dir) names an artifact that is absent or whose SHA-256 differs.
Image SBOMs (`*-image.*`) are not artifact SBOMs and are not checked against
those rules; with --artifacts-dir, each image pair must carry the marker
`mark-image` would add (so a dropped `mark-image` step fails the release).

Stdlib only (Python 3.9+); needs syft for `generate`, plus
dpkg-deb (.deb), rpm2cpio and cpio (.rpm) or pkgutil (.pkg) for those formats.
Every external command runs with a timeout. Pinned by
tests/test_artifact_sbom.py.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
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
# largest; each plugin added on Windows adds about two. The v0.15.0 workspace
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

GITHUB_GIT = re.compile(r"^git\+https://github\.com/([^/]+)/([^/@]+?)(?:\.git)?@(.+)$")
HEX_LOCK = re.compile(r'\{<<"([A-Za-z0-9_]+)">>,\s*\{pkg,\s*<<"([A-Za-z0-9_]+)">>,\s*<<"([^"]+)">>')


class SbomError(Exception):
    pass


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
        p1 = subprocess.Popen([rpm2cpio, str(path)], stdout=subprocess.PIPE)
        try:
            p2 = subprocess.run([cpio, "-idm", "--quiet", "--no-absolute-filenames"],
                                stdin=p1.stdout, cwd=dest, capture_output=True, timeout=UNPACK_TIMEOUT)
            p1.stdout.close()
            rc1 = p1.wait(timeout=UNPACK_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            p1.kill()
            p1.wait()
            raise _timeout_error(["rpm2cpio | cpio"], UNPACK_TIMEOUT) from e
        if rc1 != 0 or p2.returncode != 0:
            raise SbomError(f"{name}: rpm2cpio|cpio failed: {p2.stderr.decode(errors='replace')[:500]}")
    elif name.endswith(".pkg"):
        # pkgutil wants a directory that does not exist yet.
        _run(["pkgutil", "--expand-full", str(path), str(dest / "pkg")])
    else:
        raise SbomError(f"{name}: cannot unpack this type here; pass --contents-from <archive with the same files>")


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


# ── InnoSetup installer contents ─────────────────────────────────────────────

ISS_ENTRY = re.compile(r'\s*([A-Za-z]+)\s*:\s*("(?:[^"]|"")*"|[^;]*)\s*(?:;|$)')

# An ISPP (Inno Setup preprocessor) directive: `#` then a name. A Pascal
# character constant in [Code] (`#13#10`, `#$0D`) is `#` then a digit or `$`.
ISPP_DIRECTIVE = re.compile(r"^#\s*[A-Za-z_]")
# The only directives allowed, and only before the first section: a default for
# a name the command line can override, as yuzu-agent.iss's header has:
#   #ifndef BuildDir / #define BuildDir "..\..\..\build-windows" / #endif
# Anything else (#include, #if, #pragma, a #define with an expression, any
# directive inside a section) could add or change [Files] lines this parser
# would then not see, so it is refused rather than evaluated.
ISPP_HEADER_LINE = re.compile(r'^#\s*(?:ifndef\s+[A-Za-z_]\w*|define\s+[A-Za-z_]\w*\s+"[^"{}]*"|endif)\s*$')
# A Source basename this maps the same way Windows' FindFirstFile (which Inno
# Setup uses) does: a literal name, or one `*` directly before a literal
# extension (`*.dll`). `?` and `*.*` (which on Windows also matches a name with
# no dot) are refused. Residual: FindFirstFile also matches a file's 8.3 short
# name, so on a volume that keeps them `*.dll` would match `x.dllx` too.
ISS_SOURCE_NAME = re.compile(r"^(?:[^*?]+|[^*?]*\*\.[^*?.]+)$")

# Bytes Python's cp1252 leaves undefined; Windows' code page 1252 maps each to
# the C1 control of the same value.
_CP1252_UNDEFINED = re.compile("[\udc80-\udcff]")


def read_iss(iss: Path) -> str:
    """The script's text as the Inno Setup compiler reads it: UTF-8 when the
    file starts with a UTF-8 byte order mark, otherwise the system's ANSI code
    page (1252 on the release's Windows runner). A BOM-less script with a byte
    such as a cp1252 copyright sign (0xA9) is therefore read, not refused."""
    data = iss.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data[3:].decode("utf-8")
        except UnicodeDecodeError as e:
            raise SbomError(f"{iss.name}: starts with a UTF-8 byte order mark but is not UTF-8 ({e})") from e
    text = data.decode("cp1252", errors="surrogateescape")
    return _CP1252_UNDEFINED.sub(lambda m: chr(ord(m.group()) - 0xDC00), text)


def iss_file_entries(iss: Path) -> list[tuple[str, str]]:
    """[(dest_dir_below_app, source_basename_glob)] for each `Source:` line of
    the [Files] section of an InnoSetup script, e.g.
      Source: "{#BuildDir}\\agents\\plugins\\x\\x.dll"; DestDir: "{app}\\plugins"
    -> ("plugins", "x.dll"). Fails on anything this cannot map onto the
    archive layout without guessing: a preprocessor directive other than the
    header defaults (ISPP_HEADER_LINE), an ISPP expansion in a Source name or a
    DestDir, a DestDir outside {app}, a recursive or DestName entry, a Source
    name with a wildcard other than `*.<ext>`."""
    entries, section = [], None
    for lineno, raw in enumerate(read_iss(iss).splitlines(), 1):
        line = raw.strip()
        where = f"{iss.name}:{lineno}"
        if ISPP_DIRECTIVE.match(line):
            if section is not None or not ISPP_HEADER_LINE.match(line):
                raise SbomError(f"{where}: preprocessor directive {line!r}: this script evaluates no ISPP, "
                                f"and only a #ifndef/#define \"literal\"/#endif default before the first "
                                f"section cannot change the [Files] lines")
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "files" or not line or line.startswith(";"):
            continue
        fields = {}
        pos = 0
        while pos < len(line):
            m = ISS_ENTRY.match(line, pos)
            if not m or m.end() == pos:
                raise SbomError(f"{where}: cannot parse [Files] line {line!r}")
            val = m.group(2).strip()
            if val.startswith('"') and val.endswith('"') and len(val) >= 2:
                val = val[1:-1].replace('""', '"')
            fields[m.group(1).lower()] = val
            pos = m.end()
        if "source" not in fields:
            raise SbomError(f"{where}: [Files] line without Source: {line!r}")
        flags = fields.get("flags", "").lower().split()
        if "recursesubdirs" in flags or "destname" in fields:
            raise SbomError(f"{where}: recursesubdirs/DestName entries are not mapped onto the archive")
        dest = fields.get("destdir", "").replace("/", "\\")
        if dest.lower() != "{app}" and not dest.lower().startswith("{app}\\"):
            raise SbomError(f"{where}: DestDir {dest!r} is not under {{app}}")
        name = fields["source"].replace("/", "\\").rsplit("\\", 1)[-1]
        if "{#" in dest or "{#" in name:
            raise SbomError(f"{where}: an ISPP expansion in the Source name or DestDir is not evaluated here")
        if not ISS_SOURCE_NAME.match(name):
            raise SbomError(f"{where}: Source name {name!r}: only a literal name or `*.<ext>` is mapped "
                            f"onto the archive the way Inno Setup resolves it")
        sub = "/".join(p for p in dest[len("{app}"):].split("\\") if p)
        entries.append((sub, name))
    if not entries:
        raise SbomError(f"{iss.name}: no Source: lines in a [Files] section")
    return entries


def keep_installed(contents: Path, entries: list[tuple[str, str]]):
    """Delete from the unpacked archive every file the installer does not
    install. The archive holds one top-level directory standing for {app}
    (yuzu-agent-<version>-windows-x64/), so {app}\\plugins is <top>/plugins.
    Returns (kept, dropped, unmatched_entries) as sorted relative paths."""
    tops = [p for p in contents.iterdir()]
    if len(tops) != 1 or not tops[0].is_dir():
        raise SbomError("--contents-from archive must hold exactly one top-level directory (the install root)")
    top = tops[0]
    kept, dropped, used = [], [], set()
    for dirpath, _dirs, files in os.walk(top):
        rel_dir = Path(dirpath).relative_to(top).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        for f in files:
            hit = [i for i, (sub, pat) in enumerate(entries)
                   if sub.lower() == rel_dir.lower() and fnmatch.fnmatch(f.lower(), pat.lower())]
            rel = f"{rel_dir}/{f}" if rel_dir else f
            if hit:
                kept.append(rel)
                used.update(hit)
            else:
                dropped.append(rel)
                os.remove(os.path.join(dirpath, f))
    unmatched = [app_path(sub, pat) for i, (sub, pat) in enumerate(entries) if i not in used]
    return sorted(kept), sorted(dropped), unmatched


def app_path(sub: str, pat: str) -> str:
    """An iss_file_entries() entry as the script names it: ("plugins", "x.dll")
    -> {app}\\plugins\\x.dll."""
    return "\\".join(["{app}"] + [p for p in sub.split("/") if p] + [pat])


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
              vcomps: list[dict], hexmap: dict, incomplete: bool = False) -> dict:
    meta = doc.setdefault("metadata", {})
    root = meta.setdefault("component", {})
    root.update({"type": "application", "name": artifact, "version": version,
                 "hashes": [{"alg": "SHA-256", "content": sha}]})
    root.setdefault("bom-ref", "artifact")
    meta["properties"] = meta.get("properties", []) + [
        {"name": f"yuzu:sbom:{k}", "value": v} for k, v in notes.items()]
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
    return doc


def _spdx_root(doc: dict) -> dict:
    ids = [r["relatedSpdxElement"] for r in doc.get("relationships", [])
           if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES"]
    ids += doc.get("documentDescribes", []) or []
    roots = [p for p in doc.get("packages", []) if p.get("SPDXID") in ids]
    if len(roots) != 1:
        raise SbomError(f"SPDX document must describe exactly one package, found {len(roots)}")
    return roots[0]


def merge_spdx(doc: dict, artifact: str, version: str, sha: str, notes: dict,
               vcomps: list[dict], hexmap: dict, incomplete: bool = False) -> dict:
    root = _spdx_root(doc)
    root.update({"name": artifact, "versionInfo": version,
                 "checksums": [{"algorithm": "SHA256", "checksumValue": sha}],
                 "comment": "; ".join(f"{k}: {v}" for k, v in notes.items())})
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
    return doc


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
        unpacked = next((_unpacked_files(p.get("value")) for p in meta.get("properties", []) or []
                         if p.get("name") == "yuzu:sbom:unpacked-files"), 0)
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
        m = re.search(r"(?:^|; )unpacked-files: (\d+)(?:;|$)", root.get("comment") or "")
        return "spdx", len(pkgs) + len(files), paths, root.get("name"), sha, _unpacked_files(m and m.group(1))
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


def image_incomplete_reasons(cdx: dict, spdx: dict) -> list[tuple[str, str]]:
    """[(token, detail)] for what an image holds that its syft scan cannot list:
    Yuzu C++ binaries (their static vcpkg libraries), the Erlang emulator
    (what it vendors) and the source-built pgvector. syft 1.57 records an unpackaged binary as an SPDX file
    only, not as a CycloneDX component, so both documents are read."""
    croot, _sroot = _image_roots(cdx, spdx)
    listed = [c.get("name", "") for c in _cdx_components(cdx.get("components")) if c.get("type") == "file"]
    listed += [f.get("fileName", "") for f in spdx.get("files", []) or []]
    paths = sorted({"/" + p.replace("\\", "/").lstrip("/") for p in listed if p})

    def base(p):
        return installed_name(p.rsplit("/", 1)[-1])
    server = [p for p in paths if base(p) in SERVER_NAMES]
    cpp = [p for p in paths if base(p) in SERVER_NAMES or base(p) in AGENT_NAMES or base(p).startswith(AGENT_PREFIXES)]
    erts = [p for p in paths if base(p) == ERTS_EMULATOR]
    pgvector = [p for p in paths if base(p) == "vector.so" and "/postgresql/" in p]
    title = next((p.get("value", "") for p in (croot.get("properties") or []) +
                  ((cdx.get("metadata") or {}).get("properties") or []) if p.get("name") == IMAGE_TITLE_PROPERTY), "")
    m = YUZU_IMAGE_TITLE.match(title)
    if m:
        want = {"server": ("yuzu-server", server), "agent": ("yuzu-agent", cpp),
                "gateway": ("the Erlang emulator (beam.smp)", erts),
                "postgres": ("pgvector (vector.so)", pgvector)}[m.group(1)]
        if not want[1]:
            raise SbomError(f"image {croot.get('name')} is labelled {title}, but syft lists no {want[0]} in it: "
                            f"refusing to leave its SBOM unmarked (did syft stop listing unpackaged files?)")
    reasons: list[tuple[str, str]] = []
    if server:
        reasons.append(("server-vendored", ""))
    if cpp:
        reasons.append(("image-static-cpp", ", ".join(cpp)))
    if erts:
        reasons.append(("erts-static", ", ".join(erts)))
    if pgvector:
        reasons.append(("pgvector-source", ", ".join(pgvector)))
    return reasons


def _reason_tokens(value) -> list[str]:
    return [t.strip() for t in (value or "").split(",") if t.strip()]


def image_marker(cdx: dict, spdx: dict):
    """(cdx_tokens, spdx_tokens): the incomplete-reason tokens each document
    carries, or None where it carries no incompleteness marker at all."""
    croot, sroot = _image_roots(cdx, spdx)
    cmarked = any(c.get("aggregate") == "incomplete" and croot.get("bom-ref") in (c.get("assemblies") or [])
                  for c in cdx.get("compositions") or [])
    ctok = next((p.get("value") for p in (cdx.get("metadata") or {}).get("properties") or []
                 if p.get("name") == "yuzu:sbom:incomplete-reasons"), None)
    smarked = any(r.get("spdxElementId") == sroot.get("SPDXID") and r.get("relationshipType") == "CONTAINS"
                  and r.get("relatedSpdxElement") == "NOASSERTION" for r in spdx.get("relationships") or [])
    m = re.search(r"(?:^|; )incomplete-reasons: ([^;]*)(?:;|$)", sroot.get("comment") or "")
    return (_reason_tokens(ctok) if cmarked or ctok is not None else None,
            _reason_tokens(m and m.group(1)) if smarked or m else None)


def mark_image(cdx: dict, spdx: dict) -> tuple[list[str], bool]:
    """Mark an image SBOM pair incomplete, in place, for what
    image_incomplete_reasons() finds. Returns (tokens, changed). Idempotent: a
    pair already carrying exactly those tokens (marker included) is left as it
    is. Any other existing marker, on either document, is refused."""
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
        raise SbomError(f"the pair is already marked {have[0]} (CycloneDX) / {have[1]} (SPDX), not {want}: "
                        f"mark a fresh syft scan")
    croot, sroot = _image_roots(cdx, spdx)
    croot.setdefault("bom-ref", "image")
    _cdx_mark_incomplete(cdx, croot)
    meta = cdx.setdefault("metadata", {})
    meta["properties"] = (meta.get("properties") or []) + [
        {"name": f"yuzu:sbom:{k}", "value": v} for k, v in notes.items()]
    _spdx_mark_incomplete(spdx, sroot)
    sroot["comment"] = "; ".join([c for c in [sroot.get("comment")] if c] + [f"{k}: {v}" for k, v in notes.items()])
    return want, True


def image_pair_errors(adir: Path) -> list[str]:
    """The release gate for image SBOMs in `adir`: each `<stem>-image.cdx.json`
    has its SPDX partner, and the pair carries the marker mark-image adds."""
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
        except (OSError, ValueError, SbomError) as e:
            errs.append(f"{stem}-image: {e}")
            continue
        if want and have != (want, want):
            marked = "carries no marker" if have == (None, None) else f"is marked {have[0]} / {have[1]}"
            errs.append(f"{stem}-image: the image holds what its SBOM cannot list ({', '.join(want)}), but the pair "
                        f"{marked}: run `artifact-sbom.py mark-image` on a fresh scan")
        elif not want and have != (None, None):
            errs.append(f"{stem}-image: marked incomplete ({have[0]} / {have[1]}) for nothing the image is seen to hold")
    return errs


# ── Commands ─────────────────────────────────────────────────────────────────

# What a file holding yuzu-server carries that no SBOM lists yet.
SERVER_UNLISTED = ("yuzu-server compiles in vendored C++ (server/core/vendor: qrcodegen) and embeds web "
                   "assets (htmx, ECharts, three.js, Cytoscape, IBM Plex fonts) that this SBOM does not list")
INSTALLER_UNLISTED = "the installer's own InnoSetup runtime (setup loader and uninstaller) is not listed"

# Why an SBOM says it is incomplete: a CLOSED set. An SBOM carrying the marker
# names its reasons by these tokens, comma-separated, in
# `yuzu:sbom:incomplete-reasons` (CycloneDX metadata property; SPDX: the root's
# comment), and the prose (each entry below, with any detail after a colon) in
# `yuzu:sbom:incomplete`, joined by " | ". A consumer may rely on the tokens;
# the prose may change. docs/user-manual/release-verification.md documents the
# same set and tests/test_artifact_sbom.py fails if the two differ. A new
# reason is a new token here and a new row there; never reuse one for another
# meaning.
INCOMPLETE_REASONS = {
    "server-vendored": SERVER_UNLISTED,
    "installer-runtime": INSTALLER_UNLISTED,
    "installer-wildcard": ("the installer's script installs a wildcard Source (a `*.dll` from the build directory), "
                           "listed here as the archive's matching files, so a file the build directory held "
                           "beyond the archive's would not be listed"),
    "installer-file-missing": ("the installer's script installs a file the archive this SBOM is made from does "
                               "not hold, so it is not listed"),
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
    """Unpack, scan and merge; returns (cdx, spdx, vcomps)."""
    contents = tmp / "contents"
    contents.mkdir()
    source = Path(a.contents_from) if a.contents_from else artifact
    extract(source, contents)
    incomplete: list[tuple[str, str]] = []
    if a.contents_from is None:
        notes = {"artifact": artifact.name, "contents": f"unpacked from {source.name}"}
    else:
        iss = Path(a.iss)
        entries = iss_file_entries(iss)
        kept, dropped, unmatched = keep_installed(contents, entries)
        contents_note = (f"{artifact.name} is not unpacked here; its contents are the {len(kept)} file(s) of "
                         f"{source.name}, built from the same output, that {iss.name} installs (its [Files] "
                         f"Source: lines, resolved against the archive's layout)")
        if dropped:
            shown = ", ".join(dropped[:20]) + (f" and {len(dropped) - 20} more" if len(dropped) > 20 else "")
            contents_note += f"; {len(dropped)} file(s) of the archive the installer does not install are left out: {shown}"
            print(f"::warning::{artifact.name}: {len(dropped)} file(s) of {source.name} are not installed by "
                  f"{iss.name} and are left out of its SBOM: {shown}", file=sys.stderr)
        notes = {"artifact": artifact.name, "contents": contents_note}
        incomplete.append(("installer-runtime", ""))
        wild = [app_path(sub, pat) for sub, pat in entries if "*" in pat]
        if wild:
            incomplete.append(("installer-wildcard", ", ".join(wild)))
        if unmatched:
            incomplete.append(("installer-file-missing", f"{iss.name} installs {', '.join(unmatched)}, "
                                                         f"which {source.name} does not hold"))
            print(f"::warning::{artifact.name}: {iss.name} installs {', '.join(unmatched)}, which {source.name} "
                  f"does not hold; not listed", file=sys.stderr)
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
    if server:
        incomplete.insert(0, ("server-vendored", ""))
    erts = erts_emulators(contents)
    if erts:
        incomplete.append(("erts-static", ", ".join(erts)))
    notes.update(incomplete_notes(incomplete))
    hexmap = hex_packages(Path(a.rebar_lock)) if a.rebar_lock else {}
    syft_cdx, syft_spdx = tmp / "syft.cdx.json", tmp / "syft.spdx.json"
    _syft(a, contents, artifact, syft_cdx, syft_spdx)
    sha = sha256_of(artifact)
    cdx = merge_cdx(json.loads(syft_cdx.read_text(encoding="utf-8")), artifact.name, a.version,
                    sha, notes, vcomps, hexmap, incomplete=bool(incomplete))
    spdx = merge_spdx(json.loads(syft_spdx.read_text(encoding="utf-8")), artifact.name, a.version,
                      sha, notes, vcomps, hexmap, incomplete=bool(incomplete))
    return cdx, spdx, vcomps


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
        cdx, spdx, vcomps = _describe(a, artifact, tmp)
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
        print(f"{p.name}: {count} entries ({len(vcomps)} vcpkg ports)")
    for e in errs:
        print(f"::error::{e}", file=sys.stderr)
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


def cmd_mark_image(a) -> int:
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
    tokens, changed = mark_image(cdx, spdx)
    label = f"{paths[0].name}, {paths[1].name}"
    if not changed:
        print(f"{label}: {'already marked incomplete (' + ', '.join(tokens) + ')' if tokens else 'nothing the scan cannot list; left unchanged'}")
        return 0
    # Both files are written out before either is replaced, so a failed write
    # leaves the syft pair as it was rather than one file marked.
    tmps = [p.with_name(p.name + ".mark.tmp") for p in paths]
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
    print(f"{label}: marked incomplete ({', '.join(tokens)})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="CycloneDX + SPDX SBOM for one artifact")
    g.add_argument("--artifact", required=True)
    g.add_argument("--version", required=True)
    g.add_argument("--syft", required=True)
    g.add_argument("--out-dir", required=True)
    g.add_argument("--contents-from", help="an archive built from the same output, for an installer that cannot be "
                                           "unpacked here (needs --iss)")
    g.add_argument("--iss", help="the InnoSetup script that built the installer: only the archive files its "
                                 "[Files] section installs are described")
    g.add_argument("--vcpkg-installed", help="the vcpkg_installed directory (holds vcpkg/status)")
    g.add_argument("--triplet")
    g.add_argument("--manifest", help="vcpkg.json")
    g.add_argument("--rebar-lock", help="gateway rebar.lock, to give Hex packages a pkg:hex purl")
    c = sub.add_parser("check", help="the release gate over artifact SBOMs")
    c.add_argument("--artifacts-dir")
    c.add_argument("--max-components", type=int, default=MAX_COMPONENTS)
    c.add_argument("sboms", nargs="*")
    mi = sub.add_parser("mark-image", help="mark a syft image SBOM pair incomplete where the image holds what the "
                                           "scan cannot list, in place")
    mi.add_argument("--cdx", required=True, help="the image's CycloneDX SBOM (*-image.cdx.json)")
    mi.add_argument("--spdx", required=True, help="the same image's SPDX SBOM (*-image.spdx.json)")
    a = ap.parse_args(argv)
    label = {"generate": lambda: Path(a.artifact).name, "mark-image": lambda: Path(a.cdx).name}.get(
        a.cmd, lambda: "artifact SBOM check")()
    try:
        if a.cmd == "generate":
            if a.vcpkg_installed and not (a.triplet and a.manifest):
                raise SbomError("--vcpkg-installed needs --triplet and --manifest")
            if bool(a.contents_from) != bool(a.iss):
                raise SbomError("--contents-from and --iss go together: the installer's SBOM lists only "
                                "the archive files its script installs")
            return cmd_generate(a)
        if a.cmd == "mark-image":
            return cmd_mark_image(a)
        return cmd_check(a)
    except SbomError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - one annotated line, not a traceback
        print(f"::error::{label}: unexpected {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
