#!/usr/bin/env python3
"""WP13 lexical pin: the Echo `$Module` drain keys its signing cache on the REAL file-version stamp.

SigningCache itself is unit-tested with hand-built stamps on every OS, but nothing builds on
Windows here, so a refactor of ModuleEtwCollector::drain() could pass a default-constructed or
mtime-only stamp (restoring the last-write-time bypass) and stay green. This gate pins, inside
echo_module_etw.cpp:

  1. the drain reads the stamp from the OPEN image handle: `read_image_version_stamp(img.get())`;
  2. that read happens BEFORE the verify, i.e. before `sign_cache_.get(`;
  3. the cache is consulted with that very variable: `sign_cache_.get(full, <stamp var>,`;
  4. the stamp is not default-built or hand-filled around the read (`FileVersionStamp{`,
     `.usn =`, `.available = true`) anywhere in the drain region.

Lexical only (comments stripped, whitespace collapsed): it cannot see control-flow changes
that keep the tokens. The self-test applies in-memory mutations and requires problems() to be
non-empty on each; a mutation whose pattern no longer matches fails loudly (stale pattern).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_module_etw.cpp"
HINT = " (if the $Module drain was legitimately restructured, update tests/test_echo_module_signing_wiring_lexical.py)"


def normalise(src):
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    t = normalise(src)
    out = []
    m_stamp = re.search(
        r"(?:const )?FileVersionStamp (\w+) ?= ?read_image_version_stamp\( ?\w+\.get\(\) ?\);", t)
    if not m_stamp:
        return ["drain no longer reads `FileVersionStamp x = read_image_version_stamp(<image>.get())`" + HINT]
    var = m_stamp.group(1)
    m_get = re.search(r"sign_cache_\.get\( ?full, ?(\w+) ?,", t)
    if not m_get:
        out.append("drain no longer calls sign_cache_.get(full, <stamp>, ...)" + HINT)
    else:
        if m_get.group(1) != var:
            out.append(f"sign_cache_.get is passed `{m_get.group(1)}`, not the stamp `{var}` read from the image")
        if m_get.start() < m_stamp.start():
            out.append("sign_cache_.get runs BEFORE the stamp is read from the open image")
    drain = t[t.find("ModuleEtwCollector::drain"):] if "ModuleEtwCollector::drain" in t else t
    for bad in (r"FileVersionStamp ?\{", r"\.usn ?=", r"\.available ?= ?true", r"\.mtime ?="):
        if re.search(bad, drain):
            out.append(f"drain region builds or edits a stamp by hand ({bad}); only read_image_version_stamp may")
    return out


def selftest(src):
    muts = [
        ("stamp read deleted",
         lambda s: re.sub(r"const FileVersionStamp stamp = read_image_version_stamp\(img\.get\(\)\);", "", s, count=1)),
        ("default stamp passed",
         lambda s: s.replace("sign_cache_.get(full, stamp,", "sign_cache_.get(full, FileVersionStamp{},", 1)),
        ("other variable passed",
         lambda s: s.replace("sign_cache_.get(full, stamp,", "sign_cache_.get(full, other_stamp,", 1)),
        ("stamp read after the cache call",
         lambda s: s.replace("const FileVersionStamp stamp = read_image_version_stamp(img.get());", "", 1)
                    .replace("e.signed_state = v.state;",
                             "e.signed_state = v.state; const FileVersionStamp stamp = read_image_version_stamp(img.get());", 1)),
        ("usn forced",
         lambda s: s.replace("sign_cache_.get(full, stamp,", "x.usn = 1; sign_cache_.get(full, stamp,", 1)),
    ]
    errs = []
    for name, fn in muts:
        m = fn(src)
        if m == src:
            errs.append(f"selftest '{name}': pattern no longer matches echo_module_etw.cpp (stale)")
        elif not problems(m):
            errs.append(f"selftest '{name}': mutation was NOT detected")
    return errs


def main():
    src = SRC.read_text(encoding="utf-8")
    errs = problems(src) + selftest(src)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
