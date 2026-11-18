#!/usr/bin/env python3
"""WP13c/C-2 lexical tripwire: the vuln_scan plugin must never execute Homebrew's brew.

The macOS agent runs as root and a Homebrew prefix is owned by the installing (non-root) user,
so running `brew` executes a user-controlled script as root (same defect as WP13/F19 in
installed_apps). The macOS enumeration is `#elif defined(__APPLE__)`, so a behavioural test cannot
run on Linux; pin the source text instead (best-effort lexical backstop, not a proof).

Method: backslash-newline splices are removed first; a small C++ tokenizer strips comments WITHOUT
being fooled by `//` or `/*` inside string literals (`"https://x"; run("brew list")`), treats the
L/u8/u/U prefixes as part of a literal, decodes simple, \\x, octal, \\u and \\U escapes, and joins
adjacent string literals (`"br" "ew"`, `"br" L"ew"`) before the search. The search also runs over a
view with shell-quoting characters removed (`b''rew`). Every C/C++/Objective-C++ source under
agents/plugins/vuln_scan/src/ is scanned recursively.

Three structural pins (the "commands are absolute / coverage is wired" claims have no off-Mac
behavioural test, so they are pinned lexically):
  (a) no string literal in the plugin sources starts with a bare macOS tool name (spctl, fdesetup,
      csrutil, socketfilterfw, systemsetup, system_profiler, defaults);
  (b) every kMacos*Cmd constant defined in macos_software.hpp is USED in another source file;
  (c) in vuln_scan_plugin.cpp each of the five action branches calls declare_coverage exactly once
      (five calls in all), scan/cve_scan call emit_coverage_row, summary calls
      emit_coverage_summary_row, and inventory calls neither row emitter (its rows feed NVD
      matching).

Not caught (disclosed): a name built at run time, split across preprocessor macros, or reached by
indirection. Self-test: test_vuln_scan_no_brew_lexical_selftest.py.
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
    if c in "uU":
        n = 4 if c == "u" else 8
        m = re.match(r"[0-9a-fA-F]{%d}" % n, src[i + 1:])
        if m:
            try:
                return chr(int(m.group(0), 16)), i + 1 + n
            except (ValueError, OverflowError):
                return "\ufffd", i + 1 + n
    if c == "x":
        m = re.match(r"[0-9a-fA-F]+", src[i + 1:])
        if m:
            return chr(int(m.group(0)[-2:], 16) & 0xFF), i + 1 + len(m.group(0))
    if c in "01234567":
        m = re.match(r"[0-7]{1,3}", src[i:])
        return chr(int(m.group(0), 8) & 0xFF), i + len(m.group(0))
    return _SIMPLE_ESC.get(c, c), i + 1


_LIT_START = re.compile(r'(?:u8|u|U|L)?(R)?"')
_RAW_OPEN = re.compile(r'([^()\\\s]{0,16})\(')
_IDENT = re.compile(r"[A-Za-z0-9_]")


def _splice(src: str) -> str:
    """Translation phase 2: remove backslash-newline (also CRLF) before anything is lexed."""
    return re.sub(r"\\\r?\n", "", src)


def lex_all(src: str):
    """Return (code, literals): the code with comments removed and adjacent string literals
    joined (each joined run emitted as one `"..."` token), and the list of joined literal values.

    String contents are kept in the code (a brew call lives in a string).
    """
    src = _splice(src)
    out: list[str] = []
    lits: list[str] = []
    last_is_str = False  # only whitespace/comments since the previous string literal
    last_idx = -1
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
        m = _LIT_START.match(src, i) if (i == 0 or not _IDENT.match(src[i - 1])) else None
        if m:
            i = m.end()
            if m.group(1):  # raw string: R"delim( ... )delim"
                ro = _RAW_OPEN.match(src, i)
                if ro:
                    end = src.find(")" + ro.group(1) + '"', ro.end())
                    content = src[ro.end():] if end < 0 else src[ro.end():end]
                    i = n if end < 0 else end + len(ro.group(1)) + 2
                else:
                    content = ""
            else:
                buf = []
                while i < n and src[i] != '"' and src[i] != "\n":
                    if src[i] == "\\" and i + 1 < n:
                        d, i = _decode_escape(src, i + 1)
                        buf.append(d)
                    else:
                        buf.append(src[i])
                        i += 1
                i += 1  # closing quote
                content = "".join(buf)
            if last_is_str:
                out[last_idx] = out[last_idx][:-1] + content + '"'
                lits[-1] += content
            else:
                out.append('"' + content + '"')
                lits.append(content)
                last_idx = len(out) - 1
            last_is_str = True
            continue
        if c == "'" and not (i > 0 and _IDENT.match(src[i - 1])):
            # character literal (a digit separator 1'000 is excluded by the check above)
            i += 1
            while i < n and src[i] != "'" and src[i] != "\n":
                i += 2 if src[i] == "\\" else 1
            i += 1
            out.append("' '")
            last_is_str = False
            continue
        out.append(c)
        last_is_str = False
        i += 1
    return "".join(out), lits


def lex(src: str) -> str:
    return lex_all(src)[0]


def scan_source(text: str) -> list[str]:
    code = lex(text)
    # second view: shell quoting removed, so b''rew / b""rew / b\rew read as brew
    dequoted = re.sub(r"""['"\\]""", "", code)
    return sorted({m.group(0) for v in (code, dequoted) for m in BREW.finditer(v)})


BARE_TOOL = re.compile(r"\s*(?:spctl|fdesetup|csrutil|socketfilterfw|systemsetup|system_profiler|defaults)\b")
ACTIONS = ("scan", "cve_scan", "config_scan", "inventory", "summary")


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUFFIXES)


def action_blocks(code: str) -> dict:
    """Map each `if (action == "x")` branch of execute() to its text (to the next branch)."""
    marks = [(m.start(), m.group(1)) for m in re.finditer(r'if\s*\(\s*action\s*==\s*"(\w+)"\s*\)', code)]
    end_all = code.find('unknown action')
    blocks = {}
    for k, (pos, name) in enumerate(marks):
        stop = marks[k + 1][0] if k + 1 < len(marks) else (end_all if end_all > pos else len(code))
        blocks[name] = code[pos:stop]
    return blocks


def pin_errors(root: pathlib.Path) -> list[str]:
    errs = []
    files = source_files(root)
    lexed = {f.relative_to(root).as_posix(): lex_all(f.read_text(errors="replace")) for f in files}
    # (a) no bare macOS tool literal
    for name, (_code, lits) in lexed.items():
        for lit in lits:
            if BARE_TOOL.match(lit):
                errs.append(f"{name}: string literal starts with a bare tool name {lit[:40]!r} "
                            "(macOS commands must be absolute paths, defined in macos_software.hpp)")
    # (b) every kMacos*Cmd constant is used outside macos_software.hpp
    hdr = lexed.get("macos_software.hpp")
    if hdr is None:
        errs.append("macos_software.hpp is missing")
    else:
        consts = sorted(set(re.findall(r"\b(kMacos\w*Cmd)\b", hdr[0])))
        if not consts:
            errs.append("macos_software.hpp defines no kMacos*Cmd constants")
        others = "\n".join(c for n, (c, _l) in lexed.items() if n != "macos_software.hpp")
        for c in consts:
            if not re.search(r"\b%s\b" % c, others):
                errs.append(f"{c} is defined in macos_software.hpp but used by no other source")
    # (c) coverage wiring in vuln_scan_plugin.cpp
    plug = lexed.get("vuln_scan_plugin.cpp")
    if plug is None:
        errs.append("vuln_scan_plugin.cpp is missing")
    else:
        blocks = action_blocks(plug[0])
        for a in ACTIONS:
            b = blocks.get(a)
            if b is None:
                errs.append(f"vuln_scan_plugin.cpp: no `action == \"{a}\"` branch found")
                continue
            if len(re.findall(r"\bdeclare_coverage\s*\(\s*ctx\b", b)) != 1:
                errs.append(f"{a}: must call declare_coverage(ctx, ...) exactly once")
            row = len(re.findall(r"\bemit_coverage_row\s*\(", b))
            srow = len(re.findall(r"\bemit_coverage_summary_row\s*\(", b))
            want_row, want_srow = (1, 0) if a in ("scan", "cve_scan") else (0, 1) if a == "summary" else (0, 0)
            if (row, srow) != (want_row, want_srow):
                errs.append(f"{a}: coverage row emitters are ({row}, {srow}), expected ({want_row}, {want_srow})"
                            + (" (inventory rows feed NVD matching; no in-band rows)" if a == "inventory" else ""))
        if len(re.findall(r"\bdeclare_coverage\s*\(\s*ctx\b", plug[0])) != len(ACTIONS):
            errs.append(f"declare_coverage(ctx, ...) must appear exactly {len(ACTIONS)} times in vuln_scan_plugin.cpp")
    return errs


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
    if files:
        errs.extend(pin_errors(root))
    return errs


def main() -> int:
    errs = scan_tree(PLUGIN)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
