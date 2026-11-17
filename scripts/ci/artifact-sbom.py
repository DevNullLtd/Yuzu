#!/usr/bin/env python3
"""Per-artifact SBOMs for the release assets (supply-chain item S8).

The release used to run syft over the whole checkout (`path: .`), which listed
the vcpkg ports catalogue, docs and test tooling (about 40,000 components) and
none of the C++ libraries the binaries actually link: they are static, so syft
sees nothing in them. This script makes one SBOM per shipped file instead.

`generate` describes ONE artifact (an archive, .deb, .rpm, .pkg or installer):

  1. Unpack the artifact into a fresh temporary directory (or, for an installer
     this script cannot unpack, the archive named by --contents-from) and run
     syft over that directory only, so the SBOM lists what is inside the file.
  2. If the unpacked tree holds a Yuzu C++ binary, add the vcpkg ports it is
     built from, read from the INSTALLED vcpkg tree for the release triplet
     (`vcpkg_installed/vcpkg/status` + `<triplet>/share/<port>/vcpkg.spdx.json`):
     the dependency closure of vcpkg.json's core dependencies (agent) plus its
     `server` feature (server), with the real version, licence and a
     `pkg:github` (or `pkg:generic`) purl of the upstream source. Host-only build
     tools and the `vcpkg-*` helper ports are left out. The closure follows every
     INSTALLED feature of a reached port, so it can over-list a port a feature
     pulled in that the binary does not end up linking; it never under-lists.
  3. With --rebar-lock, an Erlang application that is a Hex package in the lock
     gets a `pkg:hex` purl (syft reports every OTP application as `pkg:otp`).
  4. Stamp the artifact's file name, version and SHA-256 on the SBOM root, write
     `<stem>.cdx.json` and `<stem>.spdx.json`, and run the `check` below on both.

`check` is the release gate: an artifact SBOM fails when it has more than
MAX_COMPONENTS entries or fewer than one, lists a path under one of the
FORBIDDEN_SEGMENTS (a sign the checkout or a test tree was scanned), or (with
--artifacts-dir) names an artifact that is absent or whose SHA-256 differs.
Image SBOMs (`*-image.*`) are not artifact SBOMs and are not checked.

Stdlib only; needs syft for `generate`, plus dpkg-deb (.deb), rpm2cpio and cpio
(.rpm) or pkgutil (.pkg) for those formats. Pinned by tests/test_artifact_sbom.py.
"""

from __future__ import annotations

import argparse
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
# release). SPDX also lists each binary syft records as a file, so a full build
# adds one entry per plugin: about 100 for the Windows agent archive (74
# plugins, the agent, its core DLL, about 10 vcpkg DLLs, 16 ports; estimated,
# not measured). The v0.15.0 workspace scans this replaces had 40,853 (Linux)
# and 43,407 (Windows). 400 leaves about four times the largest artifact and
# still fails any return to a checkout scan by two orders of magnitude. Raise
# it deliberately, with a measurement, never to silence a failing scan.
MAX_COMPONENTS = 400

# A path with one of these segments in an artifact SBOM means the checkout, the
# vcpkg clone, the docs site or a test build tree was scanned, not the artifact.
FORBIDDEN_SEGMENTS = re.compile(
    r"(?:^|[/\\])(?:vcpkg|site|tests|_build_[^/\\]*|\.git|\.github)(?:[/\\]|$)")

# Basenames that identify the Yuzu C++ binaries in an unpacked artifact.
SERVER_NAMES = {"yuzu-server", "yuzu-server.exe"}
AGENT_NAMES = {"yuzu-agent", "yuzu-agent.exe", "yuzu_agent_core.dll"}
AGENT_PREFIXES = ("libyuzu_agent_core.so", "libyuzu_agent_core.dylib")

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


def _extract_tar_checked(path: Path, dest: Path) -> None:
    with tarfile.open(path, "r:gz") as tf:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")
            return
        # Older Python without extraction filters: refuse anything the "data"
        # filter would refuse rather than extract it.
        for m in tf.getmembers():
            target = dest / m.name
            if os.path.isabs(m.name) or not _inside(dest, target):
                raise SbomError(f"{path.name}: member {m.name!r} escapes the extraction directory")
            if m.isdev():
                raise SbomError(f"{path.name}: member {m.name!r} is a device")
            if m.issym() or m.islnk():
                link = (target.parent / m.linkname) if m.issym() else (dest / m.linkname)
                if os.path.isabs(m.linkname) or not _inside(dest, link):
                    raise SbomError(f"{path.name}: link {m.name!r} points outside the extraction directory")
        tf.extractall(dest)


def _run(cmd, **kw) -> None:
    exe = shutil.which(cmd[0])
    if not exe:
        raise SbomError(f"{cmd[0]} not found on PATH (needed to unpack the artifact)")
    r = subprocess.run([exe] + list(cmd[1:]), capture_output=True, text=True, **kw)
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
        p2 = subprocess.run([cpio, "-idm", "--quiet", "--no-absolute-filenames"],
                            stdin=p1.stdout, cwd=dest, capture_output=True)
        p1.stdout.close()
        if p1.wait() != 0 or p2.returncode != 0:
            raise SbomError(f"{name}: rpm2cpio|cpio failed: {p2.stderr.decode(errors='replace')[:500]}")
    elif name.endswith(".pkg"):
        # pkgutil wants a directory that does not exist yet.
        _run(["pkgutil", "--expand-full", str(path), str(dest / "pkg")])
    else:
        raise SbomError(f"{name}: cannot unpack this type here; pass --contents-from <archive with the same files>")


def yuzu_binaries(root: Path) -> tuple[bool, bool]:
    """(has_agent, has_server) for an unpacked tree."""
    agent = server = False
    for _dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f in SERVER_NAMES:
                server = True
            if f in AGENT_NAMES or f.startswith(AGENT_PREFIXES):
                agent = True
    return agent, server


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
        cpe = None
        if port in NVD_CPE:
            cpe_version = re.sub(r"([^A-Za-z0-9._-])", r"\\\1", version)  # CPE 2.3 quoting
            cpe = f"cpe:2.3:a:{NVD_CPE[port]}:{cpe_version}:*:*:*:*:*:*:*"
        out.append({
            "port": port, "version": version, "port_version": ports[port]["port_version"], "cpe": cpe,
            "license": None if lic in ("NOASSERTION", "NONE") else lic,
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

def merge_cdx(doc: dict, artifact: str, version: str, sha: str, notes: dict,
              vcomps: list[dict], hexmap: dict) -> dict:
    meta = doc.setdefault("metadata", {})
    root = meta.setdefault("component", {})
    root.update({"type": "application", "name": artifact, "version": version,
                 "hashes": [{"alg": "SHA-256", "content": sha}]})
    meta["properties"] = meta.get("properties", []) + [
        {"name": f"yuzu:sbom:{k}", "value": v} for k, v in notes.items()]
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
               vcomps: list[dict], hexmap: dict) -> dict:
    root = _spdx_root(doc)
    root.update({"name": artifact, "versionInfo": version,
                 "checksums": [{"algorithm": "SHA256", "checksumValue": sha}],
                 "comment": "; ".join(f"{k}: {v}" for k, v in notes.items())})
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
               "copyrightText": "NOASSERTION",
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


def inspect(doc: dict):
    """(format, entry_count, paths, described_name, described_sha256)."""
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
        root = (doc.get("metadata") or {}).get("component") or {}
        sha = next((h.get("content") for h in root.get("hashes", []) or [] if h.get("alg") == "SHA-256"), None)
        return "cdx", len(comps), paths, root.get("name"), sha
    if "spdxVersion" in doc:
        root = _spdx_root(doc)
        pkgs = [p for p in doc.get("packages", []) if p is not root]
        files = doc.get("files", []) or []
        paths = [f.get("fileName", "") for f in files] + [p.get("sourceInfo", "") for p in pkgs]
        sha = next((c.get("checksumValue") for c in root.get("checksums", []) or []
                    if c.get("algorithm") == "SHA256"), None)
        return "spdx", len(pkgs) + len(files), paths, root.get("name"), sha
    raise SbomError("neither a CycloneDX nor an SPDX JSON document")


def check_file(path: Path, artifacts_dir: Path | None, max_components: int) -> list[str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        fmt, count, paths, name, sha = inspect(doc)
    except (OSError, ValueError, SbomError) as e:
        return [f"{path.name}: {e}"]
    errs = []
    if count > max_components:
        errs.append(f"{path.name}: {count} entries, more than the bound of {max_components} "
                    f"(a checkout or build-tree scan, not an artifact scan?)")
    if count < 1:
        errs.append(f"{path.name}: no components at all")
    bad = sorted({p for p in paths if FORBIDDEN_SEGMENTS.search(p)})
    if bad:
        errs.append(f"{path.name}: {len(bad)} path(s) under vcpkg/, site/, tests/, _build_*, .git or .github, "
                    f"e.g. {bad[:3]}")
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


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_generate(a) -> int:
    artifact = Path(a.artifact)
    if not artifact.is_file():
        raise SbomError(f"{artifact}: no such artifact")
    stem = artifact_stem(artifact.name)
    out_dir = Path(a.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_parent = os.environ.get("RUNNER_TEMP") or None
    with tempfile.TemporaryDirectory(prefix="yuzu_sbom_", dir=tmp_parent) as tmp:
        tmp = Path(tmp)
        contents = tmp / "contents"
        contents.mkdir()
        source = Path(a.contents_from) if a.contents_from else artifact
        extract(source, contents)
        notes = {"artifact": artifact.name,
                 "contents": f"unpacked from {source.name}" if a.contents_from is None else
                             f"{artifact.name} is not unpacked here; contents taken from {source.name}, "
                             f"which carries the same build output"}
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
        elif a.vcpkg_installed:
            raise SbomError(f"{artifact.name}: --vcpkg-installed given but no Yuzu C++ binary found in it")
        hexmap = hex_packages(Path(a.rebar_lock)) if a.rebar_lock else {}
        syft_cdx, syft_spdx = tmp / "syft.cdx.json", tmp / "syft.spdx.json"
        env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
        r = subprocess.run([a.syft, "scan", f"dir:{contents}", "--source-name", artifact.name,
                            "--source-version", a.version, "-q",
                            "-o", f"cyclonedx-json={syft_cdx}", "-o", f"spdx-json={syft_spdx}"],
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise SbomError(f"syft exited {r.returncode}: {r.stderr.strip()[:1000]}")
        sha = sha256_of(artifact)
        cdx = merge_cdx(json.loads(syft_cdx.read_text(encoding="utf-8")), artifact.name, a.version,
                        sha, notes, vcomps, hexmap)
        spdx = merge_spdx(json.loads(syft_spdx.read_text(encoding="utf-8")), artifact.name, a.version,
                          sha, notes, vcomps, hexmap)
    outs = []
    for fmt, doc in (("cdx.json", cdx), ("spdx.json", spdx)):
        p = out_dir / f"{stem}.{fmt}"
        p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        outs.append(p)
    errs = [e for p in outs for e in check_file(p, artifact.parent, MAX_COMPONENTS)]
    for p in outs:
        _fmt, count, _paths, _n, _s = inspect(json.loads(p.read_text(encoding="utf-8")))
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
    for e in errs:
        print(f"::error::{e}", file=sys.stderr)
    print(f"artifact SBOM check: {len(files)} file(s), {'FAILED' if errs else 'OK'} "
          f"(bound {a.max_components} entries; no vcpkg/, site/, tests/, _build_* paths)")
    return 1 if errs else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="CycloneDX + SPDX SBOM for one artifact")
    g.add_argument("--artifact", required=True)
    g.add_argument("--version", required=True)
    g.add_argument("--syft", required=True)
    g.add_argument("--out-dir", required=True)
    g.add_argument("--contents-from", help="an archive with the same contents, for an installer that cannot be unpacked here")
    g.add_argument("--vcpkg-installed", help="the vcpkg_installed directory (holds vcpkg/status)")
    g.add_argument("--triplet")
    g.add_argument("--manifest", help="vcpkg.json")
    g.add_argument("--rebar-lock", help="gateway rebar.lock, to give Hex packages a pkg:hex purl")
    c = sub.add_parser("check", help="the release gate over artifact SBOMs")
    c.add_argument("--artifacts-dir")
    c.add_argument("--max-components", type=int, default=MAX_COMPONENTS)
    c.add_argument("sboms", nargs="*")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "generate":
            if a.vcpkg_installed and not (a.triplet and a.manifest):
                raise SbomError("--vcpkg-installed needs --triplet and --manifest")
            return cmd_generate(a)
        return cmd_check(a)
    except SbomError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
