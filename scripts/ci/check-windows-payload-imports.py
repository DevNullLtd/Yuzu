#!/usr/bin/env python3
r"""Check that the Windows agent payloads carry every DLL their binaries import.

Run by release.yml's build-windows job, after "Package archive" and before the
installer is compiled, against both payloads the release ships:

  --zip yuzu-agent-windows-x64.zip
      the release archive itself: one top-level directory holding bin\ and
      plugins\.
  --iss deploy\packaging\windows\yuzu-agent.iss --build-dir build-windows
      the installer payload, i.e. the files the .iss [Files] section packs,
      expanded against the build directory exactly as ISCC will expand them
      ({#BuildDir} substituted, wildcards globbed, non-recursive).

For every .exe and .dll in a payload's bin\ and plugins\, the PE import table
and delay-load import table are read (stdlib only, no Windows API), and every
imported DLL must be one of:

  - present in that payload's bin\ (the agent loads plugins with
    LoadLibraryW(full path), so a plugin's dependencies resolve from the
    directory of yuzu-agent.exe, never from plugins\);
  - an API set (api-ms-win-*, ext-ms-win-*), which Windows resolves itself;
  - an operating-system DLL: one found in a --system-dir (the release passes
    %SystemRoot%\System32), EXCEPT a Microsoft Visual C++ redistributable DLL
    (vcruntime140*, msvcp140*, concrt140, vccorlib140, vcomp140, ...). Those are
    in System32 on the build machine only because the runner has the VC++
    runtime installed; a customer machine need not, so they must be shipped.
    This exception is the whole point of the check: without it the v0.15.0
    payloads, which shipped no C++ runtime, would have passed.

A debug C++ runtime import (vcruntime140d, msvcp140d, ucrtbased, ...) fails
outright: it is not redistributable. A binary that cannot be parsed, or whose
import table is empty, fails (every real Windows binary imports at least
kernel32.dll), as does a payload with no yuzu-agent.exe or no plugin, so the
check cannot pass by reading nothing.

Residual (stated, not hidden): a non-Microsoft DLL that some other software
installed into the runner's System32 would be taken for an OS DLL. The release
runner is provisioned (deploy/windows/README.md) and every vcpkg DLL ships in
bin\ regardless, so the exposure is a DLL that is neither.

Exit 0 when every import resolves, 1 when any does not (each missing import is
listed with the binaries that need it) or a payload cannot be read, 2 on a
usage error: bad arguments, or a --zip, --iss or --system-dir path that does
not exist (a message, no traceback).
"""

import argparse
import glob
import os
import re
import struct
import sys
import zipfile
import zlib

# PE import names are case-insensitive (the v0.15.0 binaries import
# VCRUNTIME140.dll), so every pattern here is too; tests/test_windows_payload_imports.py
# holds a table of names and the class each must get.
API_SET_RE = re.compile(r"^(api|ext)-ms-win-[a-z0-9.-]+\.dll$", re.I)
# Visual C++ redistributable DLLs (VS 2015-2022 share the 14x ABI). Never an
# OS DLL, whatever the build machine's System32 holds.
REDIST_RE = re.compile(
    r"^(vcruntime140(_\d+|_threads)?|msvcp140(_\d+|_atomic_wait|_codecvt_ids)?|concrt140|vccorlib140|"
    r"vcomp140|vcamp140|mfc140[a-z]*|mfcm140[a-z]*)\.dll$", re.I)
# Debug runtimes: never redistributable, never acceptable in a release. The
# debug names put the "d" after the version for most DLLs (msvcp140_1d.dll,
# vcruntime140_threadsd.dll) but before the suffix for two
# (msvcp140d_atomic_wait.dll, msvcp140d_codecvt_ids.dll); both forms count.
DEBUG_CRT_RE = re.compile(
    r"^(vcruntime140(_\d+|_threads)?d|msvcp140(_\d+|_atomic_wait|_codecvt_ids)?d|"
    r"msvcp140d_(atomic_wait|codecvt_ids)|concrt140d|vccorlib140d|"
    r"vcomp140d|ucrtbased|mfc140[a-z]*d|mfcm140[a-z]*d)\.dll$", re.I)
PE_SUFFIXES = (".exe", ".dll")
MAX_DESCRIPTORS = 4096


class PEError(Exception):
    pass


def classify(dll: str) -> str:
    """The class of an imported DLL name: 'debug' (a debug C++ runtime, always
    a failure), 'apiset' (resolved by Windows), 'redist' (the Visual C++
    runtime, which must be shipped) or 'other' (shipped in bin\\ or an OS DLL).
    Debug is tested first: ucrtbased.dll and the like are never 'other'."""
    if DEBUG_CRT_RE.match(dll):
        return "debug"
    if API_SET_RE.match(dll):
        return "apiset"
    if REDIST_RE.match(dll):
        return "redist"
    return "other"


def pe_imports(data: bytes) -> list:
    """Names of the DLLs a PE image imports (normal and delay-load), in order."""
    def u16(off):
        if off + 2 > len(data):
            raise PEError("truncated")
        return struct.unpack_from("<H", data, off)[0]

    def u32(off):
        if off + 4 > len(data):
            raise PEError("truncated")
        return struct.unpack_from("<I", data, off)[0]

    def u64(off):
        if off + 8 > len(data):
            raise PEError("truncated")
        return struct.unpack_from("<Q", data, off)[0]

    if data[:2] != b"MZ":
        raise PEError("no MZ header")
    pe = u32(0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise PEError("no PE signature")
    nsect = u16(pe + 6)
    opt_size = u16(pe + 20)
    opt = pe + 24
    magic = u16(opt)
    if magic == 0x20B:
        image_base, ndirs, dirs = u64(opt + 24), u32(opt + 108), opt + 112
    elif magic == 0x10B:
        image_base, ndirs, dirs = u32(opt + 28), u32(opt + 92), opt + 96
    else:
        raise PEError(f"unknown optional-header magic {magic:#x}")
    sections = []
    for i in range(nsect):
        s = opt + opt_size + 40 * i
        vsize, va, rawsize, rawptr = u32(s + 8), u32(s + 12), u32(s + 16), u32(s + 20)
        sections.append((va, max(vsize, rawsize), rawptr, rawsize))

    def rva_to_off(rva):
        for va, span, rawptr, rawsize in sections:
            if va <= rva < va + span:
                delta = rva - va
                if delta >= rawsize:
                    raise PEError(f"rva {rva:#x} is in a section's uninitialised tail")
                return rawptr + delta
        raise PEError(f"rva {rva:#x} is in no section")

    def cstr(rva):
        off = rva_to_off(rva)
        end = data.find(b"\0", off, off + 512)
        if end < 0:
            raise PEError(f"unterminated name at rva {rva:#x}")
        try:
            name = data[off:end].decode("ascii")
        except UnicodeDecodeError:
            raise PEError(f"non-ASCII DLL name at rva {rva:#x}") from None
        if not name.strip():
            raise PEError(f"empty DLL name at rva {rva:#x}")
        return name

    def directory(index):
        if index >= ndirs:
            return 0, 0
        return u32(dirs + 8 * index), u32(dirs + 8 * index + 4)

    names = []
    rva, size = directory(1)  # IMAGE_DIRECTORY_ENTRY_IMPORT
    if rva:
        off = rva_to_off(rva)
        for i in range(MAX_DESCRIPTORS):
            d = off + 20 * i
            if data[d:d + 20] == b"\0" * 20:
                break
            name_rva = u32(d + 12)
            if name_rva == 0:
                break
            names.append(cstr(name_rva))
        else:
            raise PEError("import table not terminated")
    rva, size = directory(13)  # IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    if rva:
        off = rva_to_off(rva)
        for i in range(MAX_DESCRIPTORS):
            d = off + 32 * i
            attrs, name = u32(d), u32(d + 4)
            if name == 0:
                break
            if not attrs & 1:  # pre-VC7 descriptors hold VAs, not RVAs
                name -= image_base
            names.append(cstr(name))
        else:
            raise PEError("delay-import table not terminated")
    return names


# ── payloads ────────────────────────────────────────────────────────────────

class Payload:
    """bin\\ and plugins\\ of one shipped payload: name (lower) -> bytes loader."""

    def __init__(self, label):
        self.label = label
        self.files = {"bin": {}, "plugins": {}}
        self.problems = []

    def add(self, where, name, loader):
        key = name.lower()
        if key in self.files[where]:
            self.problems.append(f"{self.label}: {where}\\{name} is supplied twice")
        self.files[where][key] = (name, loader)


def load_zip(path) -> Payload:
    p = Payload(f"zip {os.path.basename(path)}")
    with zipfile.ZipFile(path) as z:
        members = [i for i in z.infolist() if not i.is_dir()]
        tops = {i.filename.replace("\\", "/").split("/", 1)[0] for i in members}
        if len(tops) != 1:
            p.problems.append(f"{p.label}: expected one top-level directory, found {sorted(tops)}")
            return p
        for info in members:
            parts = info.filename.replace("\\", "/").split("/")
            if len(parts) == 3 and parts[1] in ("bin", "plugins") and parts[2].lower().endswith(PE_SUFFIXES):
                data = z.read(info)
                p.add(parts[1], parts[2], lambda data=data: data)
    return p


ISS_PARAM_RE = re.compile(r'\s*([A-Za-z]+):\s*("([^"]*)"|[^;]*)\s*(?:;|$)')
DEST_MAP = {"{app}\\bin": "bin", "{app}\\plugins": "plugins"}
KNOWN_PARAMS = {"Source", "DestDir", "Components", "Flags"}
KNOWN_FLAGS = {"ignoreversion"}


def iss_files_section(text):
    m = re.search(r"^\[Files\]\s*$(.*?)(?=^\[[A-Za-z]+\]\s*$|\Z)", text, re.S | re.M)
    return m.group(1) if m else None


def load_iss(iss_path, build_dir) -> Payload:
    p = Payload(f"installer payload ({os.path.basename(iss_path)})")
    with open(iss_path, encoding="utf-8-sig") as f:
        text = f.read()
    files = iss_files_section(text)
    if files is None:
        p.problems.append(f"{p.label}: no [Files] section")
        return p
    for line in files.splitlines():
        if not line.strip() or line.lstrip().startswith(";"):
            continue
        params = {}
        pos = 0
        while pos < len(line):
            m = ISS_PARAM_RE.match(line, pos)
            if not m or m.end() == pos:
                break
            params[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(2).strip()
            pos = m.end()
        if "Source" not in params:
            p.problems.append(f"{p.label}: cannot parse [Files] line: {line.strip()}")
            continue
        src, dest = params["Source"], params.get("DestDir", "")
        where = DEST_MAP.get(dest)
        is_pe = src.lower().endswith(PE_SUFFIXES) or src.lower().endswith("*")
        if where is None:
            if is_pe:
                p.problems.append(f"{p.label}: {src} goes to {dest!r}; only {{app}}\\bin and {{app}}\\plugins are checked")
            continue
        unknown = set(params) - KNOWN_PARAMS
        flags = set(params.get("Flags", "").split())
        if unknown or flags - KNOWN_FLAGS:
            p.problems.append(f"{p.label}: unsupported parameter or flag on {src} "
                              f"({sorted(unknown | (flags - KNOWN_FLAGS))}); extend this check before using it")
            continue
        if where == "bin" and params.get("Components", "").strip() != "core":
            p.problems.append(f"{p.label}: {src} is installed to bin\\ under component "
                              f"{params.get('Components')!r}, not core, so a custom install can drop it")
        if "{#" in src.replace("{#BuildDir}", ""):
            p.problems.append(f"{p.label}: {src} uses an ISPP define other than BuildDir")
            continue
        pattern = src.replace("{#BuildDir}", build_dir).replace("\\", os.sep)
        matches = sorted(m for m in glob.glob(pattern) if os.path.isfile(m))
        if not matches:
            p.problems.append(f"{p.label}: {src} matches no file under {build_dir} (ISCC would fail too)")
            continue
        for m in matches:
            name = os.path.basename(m)
            if not name.lower().endswith(PE_SUFFIXES):
                continue

            def loader(m=m):
                with open(m, "rb") as fh:
                    return fh.read()
            p.add(where, name, loader)
    return p


def system_dll_names(dirs) -> set:
    names = set()
    for d in dirs:
        names |= {n.lower() for n in os.listdir(d)}
    return names


def check(payload: Payload, system_names: set) -> list:
    problems = list(payload.problems)
    bin_names = set(payload.files["bin"])
    if "yuzu-agent.exe" not in bin_names:
        problems.append(f"{payload.label}: bin\\yuzu-agent.exe is missing")
    if not payload.files["plugins"]:
        problems.append(f"{payload.label}: plugins\\ holds no plugin DLL")
    missing = {}
    for where in ("bin", "plugins"):
        for key, (name, loader) in sorted(payload.files[where].items()):
            try:
                imports = pe_imports(loader())
            except PEError as e:
                problems.append(f"{payload.label}: {where}\\{name}: not a readable PE image ({e})")
                continue
            if not imports:
                problems.append(f"{payload.label}: {where}\\{name}: no imports read (every Windows binary imports kernel32.dll)")
            for dll in imports:
                low = dll.lower()
                kind = classify(low)
                if kind == "debug":
                    problems.append(f"{payload.label}: {where}\\{name} imports the debug C++ runtime {dll}, "
                                    "which is not redistributable")
                    continue
                if low in bin_names or kind == "apiset":
                    continue
                if kind != "redist" and low in system_names:
                    continue
                missing.setdefault(low, []).append(f"{where}\\{name}")
    for dll, users in sorted(missing.items()):
        kind = "Visual C++ runtime DLL" if REDIST_RE.match(dll) else "DLL"
        shown = ", ".join(users[:6]) + (f" and {len(users) - 6} more" if len(users) > 6 else "")
        problems.append(f"{payload.label}: {kind} {dll} is imported but not in bin\\ (needed by {shown})")
    return problems


def summary(payload: Payload) -> str:
    redist = sorted(n for n in payload.files["bin"] if REDIST_RE.match(n))
    return (f"{payload.label}: {len(payload.files['bin'])} binaries in bin\\, "
            f"{len(payload.files['plugins'])} in plugins\\; C++ runtime in bin\\: {', '.join(redist) or 'none'}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--zip", help="the release archive (yuzu-agent-windows-x64.zip)")
    ap.add_argument("--iss", help="the installer script (yuzu-agent.iss)")
    ap.add_argument("--build-dir", help="the Meson build directory the .iss packs from ({#BuildDir})")
    ap.add_argument("--system-dir", action="append", default=[],
                    help="a directory of OS DLLs (repeatable); the release passes %%SystemRoot%%\\System32")
    args = ap.parse_args(argv)
    if not args.zip and not args.iss:
        ap.error("give --zip, --iss, or both")
    if bool(args.iss) != bool(args.build_dir):
        ap.error("--iss and --build-dir go together")
    if not args.system_dir:
        ap.error("give at least one --system-dir")
    # A path that does not exist is a usage error (exit 2, no traceback), not
    # a finding about the payload.
    usage = [f"--system-dir {d} is not a directory" for d in args.system_dir if not os.path.isdir(d)]
    if args.zip and not os.path.isfile(args.zip):
        usage.append(f"--zip {args.zip} is not a file")
    if args.iss and not os.path.isfile(args.iss):
        usage.append(f"--iss {args.iss} is not a file")
    if usage:
        for msg in usage:
            print(f"check-windows-payload-imports: {msg}", file=sys.stderr)
        return 2
    system_names = system_dll_names(args.system_dir)
    if not system_names:
        print("check-windows-payload-imports: the --system-dir set is empty", file=sys.stderr)
        return 2

    payloads = []
    if args.zip:
        try:
            payloads.append(load_zip(args.zip))
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, OSError) as e:
            # A damaged archive or member (bad central directory, a corrupt
            # deflate stream, a CRC mismatch, a truncated member, a compression
            # method zipfile cannot read) is a finding, not a crash.
            print(f"::error::zip {os.path.basename(args.zip)}: not a readable zip archive "
                  f"({type(e).__name__}: {e})")
            print("check-windows-payload-imports: FAILED: a payload could not be read")
            return 1
    if args.iss:
        payloads.append(load_iss(args.iss, args.build_dir))
    failed = False
    for p in payloads:
        problems = check(p, system_names)
        print(summary(p))
        for msg in problems:
            print(f"::error::{msg}")
        failed = failed or bool(problems)
    if failed:
        print("check-windows-payload-imports: FAILED: a shipped binary imports a DLL the payload does not carry")
        return 1
    print("check-windows-payload-imports: every import of every shipped binary resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
