#!/usr/bin/env python3
"""#1611 tripwire: no first-party call to libpq's conn-less escape APIs.

tests/unit/test_runner_main.cpp compiles a TSan suppression for libpq's
static_std_strings / static_client_encoding globals (written on every
connection's ParameterStatus in fe-exec.c's pqSaveParameterStatus). That
suppression is honest ONLY while nothing in this tree reads those globals, and
libpq's only readers are the conn-less PQescapeString / PQescapeBytea. A new
caller would turn a benign write-write race into a real, now-silenced
read-write race, so this test fails on the first such reference — not just a
call with an immediately-following '(', but any bare identifier reference
(covers function pointers / aliasing too). A `//`-comment line (e.g. this
file's own docstring-adjacent prose in tests/unit/test_runner_main.cpp,
which quotes libpq's comment naming both functions to explain the
suppression) is skipped everywhere, uniformly — not via a per-file
exclusion list, so a REAL call later added to that same file still trips
this the moment it isn't itself inside a `//` comment. The Conn-suffixed
variants (PQescapeStringConn, PQescapeByteaConn, PQescapeLiteral,
PQescapeIdentifier) take a PGconn and are NOT matched. Wired into
tests/meson.build (suite 'docs') and docs-lint.yml (merge ref).
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROOTS = ["server", "common", "agents", "sdk", "gateway", "tests", "tools"]
EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".mm", ".m", ".ipp")
PATTERN = re.compile(r"\bPQescapeString\b|\bPQescapeBytea\b")
SELF = Path(__file__).resolve()


def _selfcheck() -> None:
    # Explicit raises, not `assert`: python3 -O strips asserts.
    must_match = [
        "x = PQescapeString(to, from, n);",
        "PQescapeBytea (b, n, &m)",
        "auto fp = &PQescapeString;",  # bare identifier, no paren adjacent
        "/* PQescapeString */ foo();",  # block comment, NOT skipped (only // lines are)
    ]
    must_not = [
        "PQescapeStringConn(conn, to, from, n, &e)",
        "PQescapeByteaConn(conn, b, n, &m)",
        "PQescapeLiteral(conn, s, n)",
        "PQescapeIdentifier(conn, s, n)",
    ]
    for s in must_match:
        if not PATTERN.search(s):
            raise SystemExit(f"selfcheck: pattern failed to match {s!r}")
    for s in must_not:
        if PATTERN.search(s):
            raise SystemExit(f"selfcheck: pattern wrongly matched {s!r}")
    # Comment-line skip: only a line whose STRIPPED form starts with `//` is
    # exempt — this is what replaces the old per-file EXCLUDE_PATHS list.
    comment_lines_skipped = [
        "// PQescapeString and PQescapeBytea can behave somewhat sanely",
        "  // calls PQescapeBytea internally, see the header comment",
    ]
    code_lines_not_skipped = [
        "auto fp = &PQescapeString;  // trailing comment doesn't exempt code",
    ]
    for s in comment_lines_skipped:
        if not s.lstrip().startswith("//"):
            raise SystemExit(f"selfcheck: fixture {s!r} isn't actually a // line")
    for s in code_lines_not_skipped:
        if s.lstrip().startswith("//"):
            raise SystemExit(f"selfcheck: fixture {s!r} unexpectedly a // line")


def main() -> int:
    _selfcheck()
    out = subprocess.run(
        ["git", "ls-files", "--", *ROOTS],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    hits = []
    for rel in out.splitlines():
        if not rel.endswith(EXTS):
            continue
        p = REPO_ROOT / rel
        if p == SELF or not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            if PATTERN.search(line):
                hits.append(f"{rel}:{n}: {line.strip()}")
    if hits:
        print(
            "FAIL: conn-less PQescapeString/PQescapeBytea reference(s) found. They\n"
            "read libpq's static_std_strings/static_client_encoding, which\n"
            "tests/unit/test_runner_main.cpp suppresses under TSan (#1611).\n"
            "Use PQescapeStringConn/PQescapeByteaConn or pg::exec_params instead:"
        )
        print("\n".join(hits))
        return 1
    print("OK: no conn-less PQescapeString/PQescapeBytea references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
