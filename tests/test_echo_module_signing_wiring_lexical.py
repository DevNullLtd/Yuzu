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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_module_etw.cpp"
HINT = " (if the $Module drain was legitimately restructured, update tests/test_echo_module_signing_wiring_lexical.py)"


def normalise(src):
    """Comments (line and block), `#if 0` blocks and string-literal contents are removed."""
    return lexh.code_only(src)


def _match_brace(t, open_idx):
    d = 0
    for k in range(open_idx, len(t)):
        if t[k] == "{":
            d += 1
        elif t[k] == "}":
            d -= 1
            if d == 0:
                return k
    return -1


def drain_body(t):
    """The body of the ModuleEtwCollector::drain() definition that uses sign_cache_ (the Windows
    one; the other definition is a one-line ring drain). Returns (body, error)."""
    bodies = []
    for m in re.finditer(r"std::vector<ModuleEvent> ModuleEtwCollector::drain\(\) \{", t):
        e = _match_brace(t, m.end() - 1)
        if e > 0:
            bodies.append(t[m.end():e])
    users = [b for b in bodies if "sign_cache_" in b]
    if len(users) != 1:
        return None, f"expected exactly one ModuleEtwCollector::drain() body using sign_cache_, found {len(users)}"
    return users[0], None


def problems(src):
    t = normalise(src)
    body, err = drain_body(t)
    if err:
        return [err + HINT]
    out = []
    # 1. the image handle comes from open_local_image_no_reparse (never a weaker opener)
    m_h = re.search(r"(?:const )?ImageHandle (\w+) ?= ?[^;]*?open_local_image_no_reparse\( ?\w+ ?\)[^;]*;", body)
    if not m_h:
        return ["drain no longer opens the image with `ImageHandle h = ... open_local_image_no_reparse(...)`" + HINT]
    h = m_h.group(1)
    # 2. the stamp is read from THAT handle, inside drain()
    m_stamp = re.search(
        r"const FileVersionStamp (\w+) ?= ?read_image_version_stamp\( ?(\w+)\.get\(\) ?\);", body)
    if not m_stamp:
        return ["drain() no longer reads `FileVersionStamp x = read_image_version_stamp(<image>.get())`" + HINT]
    var = m_stamp.group(1)
    if m_stamp.group(2) != h:
        out.append(f"the stamp is read from `{m_stamp.group(2)}`, not the handle `{h}` opened by open_local_image_no_reparse")
    if m_stamp.start() < m_h.start():
        out.append("the stamp is read BEFORE the image handle is opened")
    # a const stamp that is never reassigned (`stamp = weak_stamp(full);` after the read)
    if len(re.findall(r"(?<![\w.])" + re.escape(var) + r" ?=(?!=)", body)) != 1:
        out.append(f"the stamp `{var}` must be assigned exactly once (const, from read_image_version_stamp)")
    # 3. the cache is consulted with that stamp, after it is read, inside drain()
    m_get = re.search(r"sign_cache_\.get\( ?full, ?(\w+) ?,", body)
    if not m_get:
        out.append("drain() no longer calls sign_cache_.get(full, <stamp>, ...)" + HINT)
    else:
        if m_get.group(1) != var:
            out.append(f"sign_cache_.get is passed `{m_get.group(1)}`, not the stamp `{var}` read from the image")
        if m_get.start() < m_stamp.start():
            out.append("sign_cache_.get runs BEFORE the stamp is read from the open image")
    # 4. a default-built / hand-filled stamp anywhere in drain(): `FileVersionStamp{}`,
    # `FileVersionStamp x{}`, `FileVersionStamp x;`, `FileVersionStamp x = {}`, `.usn =` ...
    for bad in (r"FileVersionStamp ?\{", r"FileVersionStamp \w+ ?\{", r"FileVersionStamp \w+ ?;",
                r"FileVersionStamp \w+ ?= ?\{", r"\.usn ?=", r"\.available ?= ?true", r"\.mtime ?="):
        if re.search(bad, body):
            out.append(f"drain() builds or edits a stamp by hand ({bad}); only read_image_version_stamp may")
    # 5. nothing outside drain() may be the one that satisfies the pin: the stamp read must not
    # appear only elsewhere (covered by 2: it must be inside the body).
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
        ("stamp hidden in a block comment",
         lambda s: s.replace("const FileVersionStamp stamp = read_image_version_stamp(img.get());",
                             "/* const FileVersionStamp stamp = read_image_version_stamp(img.get()); */"
                             " const FileVersionStamp stamp{};", 1)),
        ("stamp read moved into a string literal",
         lambda s: s.replace("const FileVersionStamp stamp = read_image_version_stamp(img.get());",
                             'const char* x = "const FileVersionStamp stamp = read_image_version_stamp(img.get());";'
                             " const FileVersionStamp stamp{};", 1)),
        ("stamp read under #if 0",
         lambda s: s.replace("const FileVersionStamp stamp = read_image_version_stamp(img.get());",
                             "\n#if 0\nconst FileVersionStamp stamp = read_image_version_stamp(img.get());\n#endif\n"
                             "const FileVersionStamp stamp{};\n", 1)),
        ("default-built stamp beside the read",
         lambda s: s.replace("sign_cache_.get(full, stamp,", "FileVersionStamp other{}; sign_cache_.get(full, stamp,", 1)),
        ("stamp read moved to a helper outside drain(), weaker stamp in drain()",
         lambda s: s.replace("const FileVersionStamp stamp = read_image_version_stamp(img.get());",
                             "const FileVersionStamp stamp = weak_stamp(img.get());", 1)
                    + "\nstatic FileVersionStamp helper_elsewhere(void* x) { const FileVersionStamp stamp = "
                      "read_image_version_stamp(img.get()); return stamp; }\n"
                      "ModuleEvent ModuleEtwCollector::other() { const FileVersionStamp stamp = "
                      "read_image_version_stamp(img.get()); sign_cache_.get(full, stamp, v); }\n"),
        ("stamp read from a different handle",
         lambda s: s.replace("read_image_version_stamp(img.get())", "read_image_version_stamp(other.get())", 1)),
        ("handle not from open_local_image_no_reparse",
         lambda s: s.replace("open_local_image_no_reparse(full) : ImageHandle{}", "open_weaker_image(full) : ImageHandle{}", 1)),
        ("stamp reassigned after the read",
         lambda s: s.replace("sign_cache_.get(full, stamp,", "stamp = weak_stamp(full); sign_cache_.get(full, stamp,", 1)),
        ("stamp made non-const",
         lambda s: s.replace("const FileVersionStamp stamp = read_image_version_stamp(img.get());", "FileVersionStamp stamp = read_image_version_stamp(img.get());", 1)),
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
