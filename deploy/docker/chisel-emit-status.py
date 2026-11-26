#!/usr/bin/env python3
"""chisel-emit-status.py - give a chiselled rootfs a dpkg package record.

WHY: a chiselled image is assembled FROM scratch and ships no dpkg database, so
Trivy and grype see no OS packages and cannot match Ubuntu advisories against
the slices it carries (docs/ci-architecture.md "Chiselled demo images + agent bundle"). `chisel cut`
does record what it installed, in /var/lib/chisel/manifest.wall (cut it with
the `base-files_chisel` slice), but no scanner reads that file. Both scanners do
read /var/lib/dpkg/status.d/<package>, the layout Google's distroless images use,
so this script converts the manifest into one stanza per package there.

WHAT IT WRITES: for every package in the manifest, `Package`, `Status`,
`Architecture`, `Version` and, where the archive record has one, `Source`. The
`Source` line matters: Ubuntu advisories are keyed on the SOURCE package name
(`busybox-static` is built from `busybox`).

WHAT IT REFUSES (exit 1, so the image build fails instead of shipping a record a
scanner would read as "no vulnerabilities"):
  - a slice named on --slices whose package is not in the manifest;
  - a package for which the archive has no record at that exact version;
  - a status.d directory whose package set differs from the manifest's.

Runs inside the throwaway `chisel` build stage only, which has apt metadata and
zstd. Nothing here executes in the final image.
"""
import argparse
import json
import os
import re
import subprocess
import sys

# Debian policy shapes. A value outside them never reaches a file name or a
# stanza line: the name is a path component and the version, architecture and
# source are written into a line-oriented record.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
VERSION_RE = re.compile(r"^[A-Za-z0-9.+~:-]+$")
ARCH_RE = re.compile(r"^[a-z0-9-]+$")
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+( \([A-Za-z0-9.+~:-]+\))?$")


def parse_manifest(text):
    """Return {name: (version, arch)} from the text of a decompressed jsonwall."""
    pkgs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if row.get("kind") != "package":
            continue
        try:
            name, version, arch = row["name"], row["version"], row["arch"]
        except KeyError as e:
            raise ValueError("a manifest package row has no %s field" % e)
        if not (isinstance(name, str) and NAME_RE.match(name)
                and isinstance(version, str) and VERSION_RE.match(version)
                and isinstance(arch, str) and ARCH_RE.match(arch)):
            raise ValueError("manifest package row has a malformed name, version or arch: %r"
                             % (row,))
        if name in pkgs:
            raise ValueError("package %r appears twice in the manifest" % name)
        pkgs[name] = (version, arch)
    return pkgs


def slice_packages(slices):
    """Package names named by a space-separated list of <package>_<slice>."""
    names = set()
    for s in slices.split():
        if "_" not in s:
            raise ValueError("not a slice name: %r" % s)
        names.add(s.rsplit("_", 1)[0])
    return names


def source_from_show(text, name, version):
    """The `Source:` value from `apt-cache show name=version` ('' if it has none).

    Raises if the output holds no record for that exact package and version.
    """
    for record in text.split("\n\n"):
        fields = {}
        for line in record.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            fields.setdefault(k, v.strip())
        if fields.get("Package") == name and fields.get("Version") == version:
            source = fields.get("Source", "")
            if source and not SOURCE_RE.match(source):
                raise ValueError("archive record for %s=%s has a malformed Source: %r"
                                 % (name, version, source))
            return source
    raise ValueError("no archive record for %s=%s" % (name, version))


def stanza(name, version, arch, source):
    lines = ["Package: " + name, "Status: install ok installed",
             "Architecture: " + arch, "Version: " + version]
    if source:
        lines.append("Source: " + source)
    return "\n".join(lines) + "\n"


def check_sets(manifest, required, written):
    """Problems (list of strings) between slices asked for, manifest and output."""
    problems = []
    for n in sorted(required - set(manifest)):
        problems.append("slice package %s is not in the chisel manifest" % n)
    if set(written) != set(manifest):
        for n in sorted(set(manifest) - set(written)):
            problems.append("%s is in the manifest but has no status.d record" % n)
        for n in sorted(set(written) - set(manifest)):
            problems.append("%s has a status.d record but is not in the manifest" % n)
    return problems


def read_manifest(root):
    path = os.path.join(root, "var/lib/chisel/manifest.wall")
    if not os.path.isfile(path):
        raise ValueError("%s is missing; cut the base-files_chisel slice" % path)
    out = subprocess.run(["zstd", "-dc", path], check=True, capture_output=True, text=True)
    return parse_manifest(out.stdout)


def archive_source(name, version):
    out = subprocess.run(["apt-cache", "show", "%s=%s" % (name, version)],
                         capture_output=True, text=True)
    return source_from_show(out.stdout, name, version)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", required=True, help="the chiselled rootfs")
    ap.add_argument("--slices", required=True, help="the slice list given to chisel cut")
    args = ap.parse_args(argv)
    try:
        manifest = read_manifest(args.root)
        required = slice_packages(args.slices)
        outdir = os.path.join(args.root, "var/lib/dpkg/status.d")
        os.makedirs(outdir, exist_ok=True)
        for name, (version, arch) in sorted(manifest.items()):
            text = stanza(name, version, arch, archive_source(name, version))
            with open(os.path.join(outdir, name), "w") as fh:
                fh.write(text)
        problems = check_sets(manifest, required, os.listdir(outdir))
    except (ValueError, subprocess.CalledProcessError, OSError) as e:
        print("chisel-emit-status: " + str(e), file=sys.stderr)
        return 1
    if problems:
        for p in problems:
            print("chisel-emit-status: " + p, file=sys.stderr)
        return 1
    print("chisel-emit-status: %d packages recorded under %s" % (len(manifest), outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
