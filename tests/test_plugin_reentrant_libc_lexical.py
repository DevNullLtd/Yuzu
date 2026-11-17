#!/usr/bin/env python3
"""Source-text gate: the tags, users and filesystem agent plugins must not call the NON-reentrant
passwd/group lookups.

getpwuid/getpwnam/getgrnam/getgrgid return a pointer into one libc static buffer. The agent runs
plugin commands concurrently on a thread pool, so a second thread's lookup rewrites (or frees) the
buffer the first is still reading (WP12 F40/F63). The reentrant `_r` forms into a caller-owned
buffer are the only forms allowed here.

BEST-EFFORT TRIPWIRE, not proof: comments and string literals are stripped and the remaining text
is scanned for a bare call (C++ raw string literals and digit separators are handled); it cannot
see a call spelled through a macro, a function pointer or a wrapper, and it does not cover other plugins (extend DIRS when one is fixed). It is the ONLY
regression check for these call sites in a plain build: the concurrency tests exercise the code
but detect the race only under ThreadSanitizer (the nightly TSan job on main).

Usage: python3 tests/test_plugin_reentrant_libc_lexical.py [repo_root]
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 and Path(sys.argv[1]).is_dir() else Path(__file__).resolve().parent.parent
DIRS = ["agents/plugins/tags/src", "agents/plugins/users/src", "agents/plugins/filesystem/src"]
FORBIDDEN = ("getpwuid", "getpwnam", "getgrnam", "getgrgid", "getpwent", "getgrent")
CALL = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(FORBIDDEN) + r")\s*\(")


def strip_comments_and_strings(src: str) -> str:
    """Remove // and /* */ comments and "..." / '...' literals (keeping line breaks)."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, j))
            i = j
        elif c == "R" and src[i + 1:i + 2] == '"' and not (out and (out[-1].isalnum() or out[-1] == "_")):
            # raw string literal R"delim( ... )delim"
            m = re.match(r'R"([^()\\ \t\n]{0,16})\(', src[i:])
            if not m:
                out.append(c)
                i += 1
                continue
            end = src.find(")" + m.group(1) + '"', i + m.end())
            end = n if end < 0 else end + len(m.group(1)) + 2
            out.append('""' + "\n" * src.count("\n", i, end))
            i = end
        elif c == "'" and out and out[-1].isalnum() and src[i + 1:i + 2].isalnum():
            out.append(c)  # digit separator (1'000), not a char literal
            i += 1
        elif c in "\"'":
            q = c
            i += 1
            while i < n and src[i] != q:
                i += 2 if src[i] == "\\" else 1
            i += 1
            out.append(q + q)
        else:
            out.append(c)
            i += 1
    return "".join(out)


def problems(text: str):
    """(line, name) for every bare non-reentrant call in `text`."""
    stripped = strip_comments_and_strings(text)
    return [(stripped.count("\n", 0, m.start()) + 1, m.group(1)) for m in CALL.finditer(stripped)]


class ReentrantLibc(unittest.TestCase):
    def test_no_non_reentrant_lookups(self):
        bad = []
        files = 0
        for d in DIRS:
            for f in sorted((ROOT / d).glob("*.[ch]pp")):
                files += 1
                for line, name in problems(f.read_text(encoding="utf-8", errors="replace")):
                    bad.append(f"{f.relative_to(ROOT)}:{line}: non-reentrant {name}() "
                               f"(use {name}_r into a caller-owned buffer)")
        self.assertGreaterEqual(files, len(DIRS), "scanned too few files: DIRS is stale")
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def test_selftest(self):
        self.assertEqual(problems("x = getpwuid(0);"), [(1, "getpwuid")])
        self.assertEqual(problems("getgrnam (n);\ngetgrgid(1);"), [(1, "getgrnam"), (2, "getgrgid")])
        self.assertEqual(problems("getpwuid_r(0, &p, b, n, &r); getgrnam_r(a,b,c,d,e);"), [])
        self.assertEqual(problems('// getpwuid(0)\n/* getgrnam(x) */ s = "getpwnam(x)";'), [])
        self.assertEqual(problems("my_getpwuid(0); xgetpwnam(1);"), [])
        self.assertEqual(problems("getpwent(); getgrent();"), [(1, "getpwent"), (1, "getgrent")])
        # raw string: contents are not code, but code after it is
        self.assertEqual(problems('s = R"x(getpwuid(0) " )x"; getgrnam(a);'), [(1, "getgrnam")])
        # digit separator must not open a char literal that swallows a real call
        self.assertEqual(problems("n = 1'000; getpwuid(0);"), [(1, "getpwuid")])


if __name__ == "__main__":
    sys.argv = sys.argv[:1]
    unittest.main()
