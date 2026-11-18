#!/usr/bin/env python3
"""WP13c/C-2 lexical tripwire: the vuln_scan plugin must never execute Homebrew's brew.

The macOS agent runs as root and a Homebrew prefix is owned by the installing (non-root) user,
so running `brew` executes a user-controlled script as root (same defect as WP13/F19 in
installed_apps). The macOS enumeration is `#elif defined(__APPLE__)`, so a behavioural test cannot
run on Linux; pin the source text instead (best-effort lexical backstop, not a proof).

Method: a small C++ tokenizer strips comments WITHOUT being fooled by `//` or `/*` inside string
literals (`"https://x"; run("brew list")`), decodes simple escapes, and joins adjacent string
literals (`"br" "ew"`) before the search. Every C/C++/Objective-C++ source under
agents/plugins/vuln_scan/src/ is scanned recursively. Not caught (disclosed): a name built at run
time, or split across preprocessor macros. Self-test: test_vuln_scan_no_brew_lexical_selftest.py.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents/plugins/vuln_scan/src"
SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".mm"}

# `brew` as a whole word (also matches /bin/brew and /opt/homebrew/bin/brew; does NOT match the
# status token `homebrew_not_scanned` or prose "Homebrew") or a Homebrew prefix path.
BREW = re.compile(r"\bbrew\b|/(?:opt|usr/local)/homebrew", re.I)

_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}


def _decode_escape(src: str, i: int):
    """src[i] is the char after a backslash. Returns (decoded, next_index)."""
    c = src[i]
    if c == "x":
        m = re.match(r"[0-9a-fA-F]+", src[i + 1:])
        if m:
            return chr(int(m.group(0)[-2:], 16) & 0xFF), i + 1 + len(m.group(0))
    if c in "01234567":
        m = re.match(r"[0-7]{1,3}", src[i:])
        return chr(int(m.group(0), 8) & 0xFF), i + len(m.group(0))
    return _SIMPLE_ESC.get(c, c), i + 1


def lex(src: str) -> str:
    """Return the code with comments removed and adjacent string literals joined.

    String contents are kept (a brew call lives in a string); each joined literal run is emitted as
    one `"..."` token.
    """
    out: list[str] = []
    last_idx = -1
    last_is_str = False  # only whitespace/comments since the previous string literal
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j  # newline itself handled as whitespace
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c.isspace():
            out.append(c)
            i += 1
            continue
        # raw string literal R"delim( ... )delim"
        m = re.compile(r'R"([^()\\\s]{0,16})\(').match(src, i)
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_") or src[i - 1] in "uUL8"):
            end = src.find(")" + m.group(1) + '"', m.end())
            body = src[m.end():] if end < 0 else src[m.end():end]
            i = n if end < 0 else end + len(m.group(1)) + 2
            content = body
        elif c == '"':
            buf = []
            i += 1
            while i < n and src[i] != '"' and src[i] != "\n":
                if src[i] == "\\" and i + 1 < n:
                    d, i = _decode_escape(src, i + 1)
                    buf.append(d)
                else:
                    buf.append(src[i])
                    i += 1
            i += 1  # closing quote
            content = "".join(buf)
        elif c == "'" and not (i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")):
            # character literal (a digit separator 1'000 is excluded by the check above)
            i += 1
            while i < n and src[i] != "'" and src[i] != "\n":
                i += 2 if src[i] == "\\" else 1
            i += 1
            out.append("' '")
            last_is_str = False
            continue
        else:
            out.append(c)
            last_is_str = False
            i += 1
            continue
        if last_is_str:
            out[last_idx] = out[last_idx][:-1] + content + '"'  # join with the previous literal
        else:
            out.append('"' + content + '"')
            last_idx = len(out) - 1
        last_is_str = True
    return "".join(out)


def scan_source(text: str) -> list[str]:
    return sorted({m.group(0) for m in BREW.finditer(lex(text))})


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUFFIXES)


def scan_tree(root: pathlib.Path) -> list[str]:
    errs = []
    files = source_files(root)
    if not files:
        errs.append(f"no vuln_scan sources found under {root}")
    for f in files:
        hits = scan_source(f.read_text(errors="replace"))
        if hits:
            errs.append(f"{f.relative_to(root)}: executes or names brew {hits} "
                        "(root agent must not run a user-owned script)")
    return errs


def main() -> int:
    errs = scan_tree(PLUGIN)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
