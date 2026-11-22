#!/usr/bin/env python3
"""Tripwire: the file_search plugin's sources spell no call that reads a matched file's bytes, writes,
syncs or creates a file; and the one-approval cover of a multi-slice read keeps its single production
caller.

PART 1, the plugin sources. "A matched file is opened and never read, and a search never writes a file"
is the plugin's first catastrophic clause (the plugin does write its output rows, through
`write_output(`, which is not a file write). A unit test sees the pure request value (`fiemap_request()`),
not the statement that copies it into the ioctl, and an open flag set is checked for set bits only
(`O_RDONLY` is 0, so a bit test cannot see a write flag added beside it). Pinned lexically over
`agents/plugins/file_search/src/**` and `agents/shared/file_search_*` (comments stripped), as EXACT
spellings, never a `write*` or `read_file*` prefix, so the plugin's own `write_output(` and
`read_file_extents(` do not count:

  - forbidden: `FIEMAP_FLAG_SYNC` (it writes dirty pages back); the open flags `O_RDWR`, `O_WRONLY`,
    `O_CREAT`, `O_TRUNC`, `O_APPEND`; the calls `write`, `pwrite`, `pwrite64`, `writev`, `pwritev`,
    `creat`; `fsync`, `fdatasync`, `syncfs`, `msync`, `sync`; `pread*` and `mmap*`; `fopen`, `fread`,
    `fgets` and `[io]?fstream`; `readv`, `recv`, `recvfrom`, `recvmsg`; and the shared bounded readers
    of posix_secure_read.hpp (`read_open_fd`, `read_file`, `read_file_at`, `read_file_no_follow`,
    `read_file_no_follow_at`);
  - exactly one `read(` call, the `::read(` of the mount table reader in file_search_posix.cpp;
  - the extents request is built as `m->fm_flags = want.flags;` and that is the ONLY assignment to
    `fm_flags` in scope (the value is the pure builder's, which is flags 0).

PART 2, the cover. `ApprovalManager::covers_continuation` lets one spent ticket cover every later slice of
a read. Its one production caller is the MCP `execute_instruction` arm, and the flag it sets
(`approval_covers_continuation`) is read in two places in the same file. Pinned lexically over
`server/core/src` and `server/core/include` (comments stripped): `covers_continuation(` occurs once each in
approval_manager.hpp (the declaration), approval_manager.cpp (the definition) and mcp_server.cpp (the call);
the bare name occurs 1, 2 (the definition, and a log line that names it) and 1 times in those three files, so
a member pointer or a macro naming it is counted too; the name appears in no other file;
`approval_covers_continuation` is named only in mcp_server.cpp, declared `false` once and assigned `true`
once. A second caller is a security decision: see the #1398 row of .claude/routed-concerns-access-control.md.

GREP LIMIT: lexical. The match open is `PosixFs::match_facts` in component_fs_posix.cpp, which opens the
leaf through `shared::open_file_no_follow_at` (`kFileFlags` in posix_secure_read.hpp); that file also holds
the scan leg's `PosixFs::open_file` and `pread_range`, so it is outside the scope above, and the facts
tests of that file and `tests/unit/test_posix_secure_read.cpp` (the open flags are read-only, checked with
`O_ACCMODE`) cover it. The gate cannot see a call built at run time, a function pointer to `read`, a
syscall reached by number (the plugin's own `syscall(SYS_ioprio_set)` is one), an aliased store to
`fm_flags` (a pointer to the field, then a store through it) or a byte-wise overwrite of the extent request
(`memset`, `std::fill`, a struct assignment): the request buffer is value-initialised in
file_search_extents_linux.cpp, written by the one counted statement, and the builder's value is pinned by
the unit test of `fiemap_request()`. `--selftest` appends each forbidden spelling, deletes each required
statement and adds a second `::read(`, a second `fm_flags` write, a second `covers_continuation(` call, a
member pointer to it and a second `= true` in memory, and requires the gate to name each.

Usage: python3 -I tests/test_file_search_source_tripwire.py [--selftest]
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
PLUGIN_SRC = os.path.join("agents", "plugins", "file_search", "src")
SHARED = os.path.join("agents", "shared")
SERVER_SRC = os.path.join("server", "core", "src")
SERVER_INCLUDE = os.path.join("server", "core", "include")
EXTENTS_LINUX = os.path.join(PLUGIN_SRC, "file_search_extents_linux.cpp")
POSIX_CPP = os.path.join(PLUGIN_SRC, "file_search_posix.cpp")
APPROVAL_HPP = os.path.join(SERVER_SRC, "approval_manager.hpp")
APPROVAL_CPP = os.path.join(SERVER_SRC, "approval_manager.cpp")
MCP_CPP = os.path.join(SERVER_SRC, "mcp_server.cpp")
SRC_HINT = (" (this gate pins that the file_search plugin spells no call that reads a matched file's bytes, "
            "writes, syncs or creates a file, the forbidden spellings listed in its docstring; if a rule was "
            "legitimately changed, a content or hash read is a NEW action with its own catalogue row: update "
            "agents/plugins/file_search/README.md and the routed-concerns file_search row first, then "
            "tests/test_file_search_source_tripwire.py)")
COVER_HINT = (" (this gate pins the one production caller of ApprovalManager::covers_continuation, the MCP "
              "execute_instruction arm; a second caller is a security decision recorded in the #1398 row of "
              ".claude/routed-concerns-access-control.md (Dispatch-caller approval provenance): update that "
              "row and docs/security-reviews/1398-dispatch-approval-gate-design.md first, then "
              "tests/test_file_search_source_tripwire.py)")

# The comment-free, whitespace-collapsed text the sibling gates already use: one scanner, so a comment
# that mentions a token can neither satisfy nor break a check here either.
_spec = importlib.util.spec_from_file_location(
    "forensics_tier_wiring_lexical", os.path.join(HERE, "test_forensics_tier_wiring_lexical.py"))
_sib = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _sib
_spec.loader.exec_module(_sib)
canonical = _sib.canonical

_SRC_EXTS = (".cpp", ".hpp", ".h", ".cc", ".c", ".mm", ".inl")
_ID = r"(?<![A-Za-z0-9_])"

# ---- part 1 ----

# (id, pattern over canonical(), why). A pattern here may not occur in any file in scope.
SRC_FORBIDDEN: list[tuple[str, str, str]] = [
    ("fiemap-sync", _ID + r"FIEMAP_FLAG_SYNC\b",
     "the sync flag writes dirty pages back: a search must never cause a write"),
    ("open-write-flag", _ID + r"(?:O_RDWR|O_WRONLY|O_CREAT|O_TRUNC|O_APPEND)\b",
     "a file or directory is opened read-only, never for writing, creating, truncating or appending"),
    ("write-call", _ID + r"(?:write|pwrite|pwrite64|writev|pwritev|creat)\(",
     "a search writes no file or descriptor (its rows go out through write_output(), which does not count)"),
    ("sync-call", _ID + r"(?:fsync|fdatasync|syncfs|msync|sync)\(",
     "a search never forces data to disk"),
    ("positional-read", _ID + r"pread\w*",
     "a matched file is opened and never read"),
    ("mapped-read", _ID + r"mmap\w*",
     "a matched file is opened and never mapped"),
    ("stream-read", _ID + r"(?:fopen|fread|fgets)\(|" + _ID + r"[io]?fstream\b",
     "a matched file is opened and never read through stdio or a stream"),
    ("vector-read", _ID + r"(?:readv|recv|recvfrom|recvmsg)\(",
     "a matched file is opened and never read"),
    ("bounded-reader", _ID + r"(?:read_open_fd|read_file|read_file_at|read_file_no_follow|read_file_no_follow_at)\b",
     "the shared bounded readers read a file's bytes: a matched file is opened and never read"),
]
READ_CALL = re.compile(_ID + r"read\(")
FM_FLAGS_WRITE = re.compile(_ID + r"fm_flags(?:<<|>>|[|&^+\-])?=(?!=)")

# (id, file, a C++ snippet, why). The snippet is canonicalised like the text it is looked for in.
SRC_REQUIRED: list[tuple[str, str, str, str]] = [
    ("fiemap-flags", EXTENTS_LINUX, "m->fm_flags = want.flags;",
     "the FIEMAP request carries the flags of the pure request builder (flags 0, no sync)"),
]


def _scope_files(root: str) -> list[str]:
    out: list[str] = []
    for dirpath, _dirs, files in sorted(os.walk(os.path.join(root, PLUGIN_SRC))):
        for name in sorted(files):
            if name.endswith(_SRC_EXTS):
                out.append(os.path.relpath(os.path.join(dirpath, name), root))
    shared = os.path.join(root, SHARED)
    for name in sorted(os.listdir(shared)):
        if name.startswith("file_search_") and name.endswith(_SRC_EXTS):
            out.append(os.path.join(SHARED, name))
    return out


def load_sources(root: str = REPO_ROOT) -> dict[str, str]:
    """{path relative to the repo: canonical text} for every file in the plugin-source scope."""
    out: dict[str, str] = {}
    for rel in _scope_files(root):
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            out[rel] = canonical(fh.read())
    return out


def source_problems(texts: dict[str, str]) -> list[tuple[str, str]]:
    """Every violated part-1 rule as (id, message); empty when the gate holds."""
    found: list[tuple[str, str]] = []
    for rid, pattern, why in SRC_FORBIDDEN:
        for path, text in sorted(texts.items()):
            if re.search(pattern, text):
                found.append((rid, f"{path} spells a forbidden form: {why}{SRC_HINT}"))
    sites = [(path, text[max(0, m.start() - 2):m.start()])
             for path, text in sorted(texts.items()) for m in READ_CALL.finditer(text)]
    if sites != [(POSIX_CPP, "::")]:
        found.append(("read-call", f"expected exactly one read( call, the `::read(` of the mount table "
                      f"reader in {POSIX_CPP}; found {sites or 'none'}: a matched file is opened and "
                      f"never read{SRC_HINT}"))
    writes = [(path, len(FM_FLAGS_WRITE.findall(text)))
              for path, text in sorted(texts.items()) if FM_FLAGS_WRITE.search(text)]
    if writes != [(EXTENTS_LINUX, 1)]:
        found.append(("fm-flags-write", f"expected exactly one assignment to fm_flags, in {EXTENTS_LINUX}; "
                      f"found {writes or 'none'}: the extent request carries no flags{SRC_HINT}"))
    for rid, path, snippet, why in SRC_REQUIRED:
        text = texts.get(path)
        if text is None:
            found.append((rid, f"{path} is missing: {why}{SRC_HINT}"))
        elif canonical(snippet).strip() not in text:
            found.append((rid, f"{path} no longer holds `{snippet}`: {why}{SRC_HINT}"))
    return found


# ---- part 2 ----

CALL = re.compile(_ID + r"covers_continuation\(")
NAME = re.compile(_ID + r"covers_continuation\b")
FLAG = re.compile(_ID + r"approval_covers_continuation\b")
FLAG_ASSIGN = re.compile(_ID + r"approval_covers_continuation=(?!=)(\w+)")
CALL_SITES = {APPROVAL_HPP: 1, APPROVAL_CPP: 1, MCP_CPP: 1}
# The bare name, string literals included (canonical() strips comments only): the cpp also names it in a log line.
NAME_SITES = {APPROVAL_HPP: 1, APPROVAL_CPP: 2, MCP_CPP: 1}


def load_server(root: str = REPO_ROOT) -> dict[str, str]:
    """{path relative to the repo: canonical text} for every server source (src and include) that mentions either name."""
    out: dict[str, str] = {}
    for tree in (SERVER_SRC, SERVER_INCLUDE):
        for dirpath, _dirs, files in os.walk(os.path.join(root, tree)):
            for name in files:
                if not name.endswith(_SRC_EXTS):
                    continue
                full = os.path.join(dirpath, name)
                with open(full, encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
                if "covers_continuation" in raw:
                    out[os.path.relpath(full, root)] = canonical(raw)
    return out


def cover_problems(texts: dict[str, str]) -> list[tuple[str, str]]:
    """Every violated part-2 rule as (id, message); empty when the gate holds."""
    found: list[tuple[str, str]] = []
    for path, text in sorted(texts.items()):
        if path not in CALL_SITES and NAME.search(text):
            found.append(("cover-caller-outside", f"{path} names covers_continuation; only "
                          f"approval_manager.hpp, approval_manager.cpp and mcp_server.cpp may{COVER_HINT}"))
        if path != MCP_CPP and FLAG.search(text):
            found.append(("cover-flag-outside", f"{path} names approval_covers_continuation; only "
                          f"mcp_server.cpp may{COVER_HINT}"))
    for path, want in CALL_SITES.items():
        text = texts.get(path)
        have = 0 if text is None else len(CALL.findall(text))
        if have != want:
            found.append(("cover-call-count", f"{path} holds {have} covers_continuation( occurrence(s); "
                          f"it must hold exactly {want} (the declaration, the definition, the one MCP "
                          f"call){COVER_HINT}"))
    for path, want in NAME_SITES.items():
        text = texts.get(path)
        have = 0 if text is None else len(NAME.findall(text))
        if have != want:
            found.append(("cover-name-count", f"{path} names covers_continuation {have} time(s); it must name "
                          f"it exactly {want} (a member pointer or a macro naming it is a second "
                          f"caller){COVER_HINT}"))
    assigned = FLAG_ASSIGN.findall(texts.get(MCP_CPP, ""))
    if assigned != ["false", "true"]:
        found.append(("cover-flag-assign", f"{MCP_CPP} must declare approval_covers_continuation = false "
                      f"once and assign it true once; its assignments read {assigned or 'none'}{COVER_HINT}"))
    return found


def problems(src: dict[str, str], srv: dict[str, str]) -> list[tuple[str, str]]:
    return source_problems(src) + cover_problems(srv)


def selftest() -> int:
    """Mutate the real sources in memory (nothing on disk is touched) and require each mutation named."""
    failures: list[str] = []

    def expect(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)
            print(f"FAIL: {what}", file=sys.stderr)

    src, srv = load_sources(), load_server()
    base = problems(src, srv)
    expect(base == [], "the real tree must pass the gate: " + "; ".join(m for _, m in base))
    expect(len(SRC_FORBIDDEN) >= 9 and len(SRC_REQUIRED) >= 1, "the rule lists must not shrink silently")

    def src_ids(extra_path: str, spelling: str, replace: dict[str, str] | None = None) -> set[str]:
        texts = dict(src, **(replace or {}))
        texts[extra_path] = texts.get(extra_path, "") + canonical(spelling)
        return {rid for rid, _ in source_problems(texts)}

    driver = os.path.join(PLUGIN_SRC, "file_search_driver.hpp")
    shared = os.path.join(SHARED, "file_search_governor.hpp")
    expect(driver in src and shared in src, "scope: the driver and the shared governor header must be scanned")
    with tempfile.TemporaryDirectory() as tmp:  # the scan walks subdirectories and reads every source extension
        for rel in (os.path.join(PLUGIN_SRC, "sub", "deep.mm"), os.path.join(PLUGIN_SRC, "x.inl"),
                    os.path.join(SHARED, "file_search_y.c"), os.path.join(SHARED, "other.hpp")):
            os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
            open(os.path.join(tmp, rel), "w").close()
        scanned = set(_scope_files(tmp))
        expect(scanned == {os.path.join(PLUGIN_SRC, "sub", "deep.mm"), os.path.join(PLUGIN_SRC, "x.inl"),
                           os.path.join(SHARED, "file_search_y.c")},
               f"scope: a subdirectory, .mm, .inl and .c source must be scanned, others not; scanned {sorted(scanned)}")
    for rid, spelling in (("fiemap-sync", "auto f = FIEMAP_FLAG_SYNC;"),
                          ("open-write-flag", "int a = O_RDWR;"),
                          ("open-write-flag", "int a = O_WRONLY | O_CLOEXEC;"),
                          ("open-write-flag", "int a = O_RDONLY | O_CREAT;"),
                          ("open-write-flag", "int a = O_RDONLY | O_TRUNC;"),
                          ("open-write-flag", "int a = O_RDONLY | O_APPEND;"),
                          ("write-call", "auto n = write(fd, b, 4);"),
                          ("write-call", "auto n = ::pwrite(fd, b, 4, 0);"),
                          ("write-call", "auto n = pwrite64(fd, b, 4, 0);"),
                          ("write-call", "auto n = writev(fd, v, 2);"),
                          ("write-call", "auto n = pwritev(fd, v, 2, 0);"),
                          ("write-call", "int f = creat(p, 0600);"),
                          ("write-call", "out.write(b, 4);"),
                          ("sync-call", "fsync(fd);"),
                          ("sync-call", "::fdatasync(fd);"),
                          ("sync-call", "syncfs(fd);"),
                          ("sync-call", "msync(p, 4, 0);"),
                          ("sync-call", "sync();"),
                          ("stream-read", "FILE* f = fopen(p, \"r\");"),
                          ("stream-read", "auto n = fread(b, 1, 4, f);"),
                          ("stream-read", "char* l = fgets(b, 4, f);"),
                          ("stream-read", "std::ifstream in(p);"),
                          ("stream-read", "std::ofstream out(p);"),
                          ("stream-read", "std::fstream io(p);"),
                          ("vector-read", "auto n = readv(fd, v, 2);"),
                          ("vector-read", "auto n = recv(fd, b, 4, 0);"),
                          ("vector-read", "auto n = recvfrom(fd, b, 4, 0, 0, 0);"),
                          ("vector-read", "auto n = recvmsg(fd, &m, 0);"),
                          ("bounded-reader", "auto r = sh::read_open_fd(fd, 4);"),
                          ("bounded-reader", "auto r = sh::read_file(p, 4);"),
                          ("bounded-reader", "auto r = sh::read_file_at(d, n, 4);"),
                          ("bounded-reader", "auto r = sh::read_file_no_follow(p, 4);"),
                          ("bounded-reader", "auto r = sh::read_file_no_follow_at(d, n, 4);"),
                          ("positional-read", "auto n = pread(fd, b, 4, 0);"),
                          ("positional-read", "auto n = pread64(fd, b, 4, 0);"),
                          ("mapped-read", "void* p = mmap(0, 4, 1, 1, fd, 0);"),
                          ("read-call", "auto n = ::read(fd, b, 4);"),
                          ("read-call", "auto n = read(fd, b, 4);"),
                          ("read-call", "in.read(b, 4);"),
                          ("fm-flags-write", "m->fm_flags = 1;"),
                          ("fm-flags-write", "m->fm_flags |= 1;"),
                          ("fm-flags-write", "const Fiemap f{.fm_flags = 1};")):
        for where in (driver, shared):  # a plugin source and a shared search header: both in scope
            expect(rid in src_ids(where, spelling), f"{rid}: `{spelling}` appended to {where} was NOT detected")
        expect(rid not in {r for r, _ in source_problems(dict(src, **{driver: src[driver] + canonical("// " + spelling)}))},
               f"{rid}: a comment spelling `{spelling}` must not count")

    # The one allowed read( call: moving it, or adding one beside it, is named.
    posix_text = src.get(POSIX_CPP, "")
    expect("::read(" in posix_text, "read-call: the real mount table reader no longer holds `::read(` (stale gate)")
    expect("read-call" in {r for r, _ in source_problems(dict(src, **{POSIX_CPP: posix_text.replace("::read(", "::recv(", 1)}))},
           "read-call: removing the mount table reader's read call was NOT detected")
    expect("read-call" in {r for r, _ in source_problems(dict(src, **{POSIX_CPP: posix_text + canonical("auto n = ::read(fd, b, 4);")}))},
           "read-call: a second ::read( in the same file was NOT detected")

    # Names that merely contain `read(` are not calls.
    benign = canonical("std::thread t; t = std::thread(f); read_mounts(x); auto r = pthread_create(&t, 0, f, 0); "
                       "x.fm_flags == 3; if (y.fm_flags != 3 || y.fm_flags <= 3) {} spread(1); lpread = 2;")
    expect("read-call" not in src_ids(driver, "", {driver: src[driver] + benign}) and
           "fm-flags-write" not in src_ids(driver, "", {driver: src[driver] + benign}),
           "read-call: `thread(`, `read_mounts(` and a comparison of fm_flags must not count")
    expect("positional-read" not in src_ids(driver, "", {driver: src[driver] + canonical("spread(1); lpread = 2;")}),
           "positional-read: an identifier that merely contains `pread` must not count")
    # The plugin's own names that begin with a pinned one are not the pinned call: exact spellings only.
    own = canonical("write_output(a); write_row = 1; read_file_extents(p); sync_state(1); recv_buf = 2; "
                    "fwrite_x(1); ifstream_like = 3; O_CREATED = 1; async(f); prewrite(1);")
    own_ids = {r for r, _ in source_problems(dict(src, **{driver: src[driver] + own}))}
    expect(own_ids == set(), f"scope: write_output(, read_file_extents( and the like must not count: {sorted(own_ids)}")

    # The required statement: deleted, or only mentioned in a comment, is named.
    for rid, path, snippet, _why in SRC_REQUIRED:
        text = src.get(path, "")
        needle = canonical(snippet).strip()
        if needle not in text:
            expect(False, f"{rid}: the statement no longer matches the real source (stale snippet)")
            continue
        ids = {r for r, _ in source_problems(dict(src, **{path: text.replace(needle, "", 1)}))}
        expect(rid in ids, f"{rid}: deleting its statement was NOT detected")
        expect("fm-flags-write" in ids, "fm-flags-write: deleting the only fm_flags write was NOT detected")
        ids = {r for r, _ in source_problems(dict(src, **{path: canonical("// " + snippet + "\n")}))}
        expect(rid in ids, f"{rid}: a comment mentioning its statement satisfied it")

    # A file out of scope is not scanned: the match open and pread_range live in component_fs_posix.cpp.
    expect(os.path.join("agents", "plugins", "component_inventory", "src", "component_fs_posix.cpp") not in src,
           "scope: component_fs_posix.cpp must stay outside the lexical scope (it holds pread_range)")

    # Part 2.
    def srv_ids(texts: dict[str, str]) -> set[str]:
        return {rid for rid, _ in cover_problems(texts)}

    other = os.path.join(SERVER_SRC, "agent_registry.cpp")
    mcp = srv.get(MCP_CPP, "")
    expect(CALL.search(mcp) is not None and FLAG.search(mcp) is not None,
           "cover: mcp_server.cpp no longer holds the call and the flag (stale gate)")
    expect("cover-caller-outside" in srv_ids(dict(srv, **{other: canonical("auto c = mgr.covers_continuation(id, p);")})),
           "cover-caller-outside: a second caller in another file was NOT detected")
    expect("cover-caller-outside" in srv_ids(dict(srv, **{other: canonical("auto f = &ApprovalManager::covers_continuation;")})),
           "cover-caller-outside: a pointer to the function in another file was NOT detected")
    expect("cover-caller-outside" not in srv_ids(dict(srv, **{other: canonical("// mgr.covers_continuation(id, p)")})),
           "cover-caller-outside: a comment mention must not count")
    expect("cover-call-count" in srv_ids(dict(srv, **{MCP_CPP: mcp + canonical("auto c = approval_manager->covers_continuation(id, p);")})),
           "cover-call-count: a second call in mcp_server.cpp was NOT detected")
    for what, spelling in (("a member pointer", "auto f = &ApprovalManager::covers_continuation;"),
                           ("a macro", "#define COVER covers_continuation")):
        for path in (MCP_CPP, APPROVAL_HPP, APPROVAL_CPP):
            expect("cover-name-count" in srv_ids(dict(srv, **{path: srv.get(path, "") + canonical(spelling)})),
                   f"cover-name-count: {what} naming covers_continuation in {path} was NOT detected")
    expect(srv_ids(dict(srv, **{MCP_CPP: mcp + canonical("auto f = &ApprovalManager::covers_continuation;")})) == {"cover-name-count"},
           "cover-name-count: a member pointer must be named by the name-count rule alone (the call count cannot see it)")
    expect("cover-call-count" in srv_ids(dict(srv, **{MCP_CPP: CALL.sub("covers_continuation_x(", mcp, count=1)})),
           "cover-call-count: deleting the one MCP call was NOT detected")
    for path in (APPROVAL_HPP, APPROVAL_CPP):
        text = srv.get(path, "")
        expect(CALL.search(text) is not None, f"cover-call-count: {path} no longer holds its occurrence (stale gate)")
        expect("cover-call-count" in srv_ids(dict(srv, **{path: text + canonical("bool covers_continuation(int);")})),
               f"cover-call-count: a second occurrence in {path} was NOT detected")
    expect("cover-flag-outside" in srv_ids(dict(srv, **{other: canonical("bool approval_covers_continuation = true;")})),
           "cover-flag-outside: the flag named in another file was NOT detected")
    expect("cover-flag-assign" in srv_ids(dict(srv, **{MCP_CPP: mcp + canonical("approval_covers_continuation = true;")})),
           "cover-flag-assign: a second `= true` was NOT detected")
    expect("cover-flag-assign" in srv_ids(dict(srv, **{MCP_CPP: mcp + canonical("approval_covers_continuation = cover.value();")})),
           "cover-flag-assign: an assignment from an expression was NOT detected")
    expect("cover-flag-assign" in srv_ids(dict(srv, **{MCP_CPP: mcp.replace("approval_covers_continuation=true", "approval_covers_continuation=false", 1)})),
           "cover-flag-assign: removing the one `= true` was NOT detected")
    expect("cover-flag-assign" not in srv_ids(dict(srv, **{MCP_CPP: mcp + canonical("if (approval_covers_continuation == true) {}")})),
           "cover-flag-assign: a comparison must not count as an assignment")
    expect("#1398" in COVER_HINT and "routed-concerns-access-control.md" in COVER_HINT,
           "the cover hint must point at the #1398 routed row")

    print(f"selftest: {len(failures)} failure(s)")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    found = problems(load_sources(), load_server())
    for rid, msg in found:
        print(f"FAIL [{rid}]: {msg}", file=sys.stderr)
    if found:
        return 1
    print("test_file_search_source_tripwire: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
