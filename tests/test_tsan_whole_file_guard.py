#!/usr/bin/env python3
"""Source-text gate: a unit-test file that says it is "Whole file compiled out under TSan" must
actually be compiled out whole.

Those files wrap their test content in `#ifndef YUZU_TSAN_BUILD ... #endif` because loopback httplib
hits #2504 under ThreadSanitizer. When a later change appends a TEST_CASE after the closing `#endif`,
the file still builds and passes everywhere except a TSan leg, where the guarded fixture no longer
exists and `yuzu_server_tests` does not compile (#6419). No PR-time job builds with TSan, so nothing
would catch it until the nightly. This gate reads the file as text and fails when anything but
whitespace and comments follows the guard's matching `#endif`.

BEST-EFFORT TRIPWIRE, not proof: it is a text scan, not a compile, and it understands only the one
guard spelling `#ifndef YUZU_TSAN_BUILD`. A file that is only partly guarded on purpose must not carry
the "Whole file compiled out under TSan" marker.
"""

import re
import sys
from pathlib import Path

MARKER = "Whole file compiled out under TSan"
GUARD = re.compile(r"^\s*#\s*ifndef\s+YUZU_TSAN_BUILD\b")
OPEN = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
CLOSE = re.compile(r"^\s*#\s*endif\b")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check_text(text: str) -> list[str]:
    """Return the problems in one file's text (empty list = fine)."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if GUARD.match(ln)), None)
    if start is None:
        return ["carries the marker but has no top-level `#ifndef YUZU_TSAN_BUILD` guard"]
    depth = 0
    end = None
    for i in range(start, len(lines)):
        if OPEN.match(lines[i]):
            depth += 1
        elif CLOSE.match(lines[i]):
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return ["the `#ifndef YUZU_TSAN_BUILD` guard has no matching `#endif`"]
    tail = strip_comments("\n".join(lines[end + 1 :])).strip()
    if tail:
        first = tail.splitlines()[0].strip()
        return [
            f"code follows the guard's closing `#endif` (line {end + 1}) and would be compiled "
            f"under TSan, where the guarded fixtures do not exist: {first[:80]!r}"
        ]
    return []


def selftest() -> None:
    ok = "#ifndef YUZU_TSAN_BUILD\n#if X\nint a;\n#endif\nTEST_CASE(1);\n#endif // YUZU_TSAN_BUILD\n"
    assert check_text(ok) == [], check_text(ok)
    assert check_text(ok + "// trailing comment\n/* block */\n") == []
    bad = "#ifndef YUZU_TSAN_BUILD\nstruct P{};\n#endif\nTEST_CASE(2){ P p; }\n"
    assert len(check_text(bad)) == 1, check_text(bad)
    assert check_text("int main(){}\n"), "a marker file with no guard must fail"
    assert check_text("#ifndef YUZU_TSAN_BUILD\nint a;\n"), "an unclosed guard must fail"
    # An inner #if ... #endif must not be mistaken for the guard's own close.
    inner = "#ifndef YUZU_TSAN_BUILD\n#ifdef _WIN32\n#endif\nTEST_CASE(3);\n#endif\n"
    assert check_text(inner) == []


def main(argv: list[str]) -> int:
    selftest()
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent
    files = sorted((root / "unit").rglob("*.cpp")) if (root / "unit").is_dir() else []
    checked = 0
    failed = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if MARKER not in text:
            continue
        checked += 1
        for problem in check_text(text):
            failed += 1
            print(f"FAIL {path.relative_to(root.parent)}: {problem}")
    if checked == 0:
        print("FAIL no file carries the marker - the gate is checking nothing")
        return 1
    print(f"checked {checked} TSan whole-file-guard file(s), {failed} problem(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
