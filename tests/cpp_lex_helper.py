"""Shared C++ source tokenizer for the WP13 lexical gates (helper, not a test).

Adapted from the WP13c vuln_scan gate's lexer: strips comments WITHOUT being fooled by `//` or
`/*` inside string literals, decodes simple escapes and joins adjacent string literals, so a
token hidden in a comment or a string cannot satisfy a pin and a token split across adjacent
literals is still seen. `code_only()` additionally replaces every string literal's CONTENT with
an empty literal (so a call named inside a string cannot satisfy a pin) and removes `#if 0`
blocks. Tests insert this directory on sys.path explicitly (they run under `python3 -I`).
"""
import re

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


def drop_if0(src: str) -> str:
    """Remove `#if 0 ... #endif` (nesting-aware; an `#else` branch is kept)."""
    out, depth, skipping = [], 0, False
    skip_depth = 0
    for line in src.splitlines(keepends=True):
        s = line.strip()
        if re.match(r"#\s*if(def|ndef)?\b", s):
            depth += 1
            if not skipping and re.match(r"#\s*if\s+0\b", s):
                skipping, skip_depth = True, depth
                continue
        elif re.match(r"#\s*else\b", s) and skipping and depth == skip_depth:
            skipping = False
            continue
        elif re.match(r"#\s*endif\b", s):
            if skipping and depth == skip_depth:
                skipping = False
                depth -= 1
                continue
            depth -= 1
        if not skipping:
            out.append(line)
    return "".join(out)


def code_only(src: str) -> str:
    """Comments, `#if 0` blocks and string-literal contents removed; whitespace collapsed."""
    t = lex(drop_if0(src))
    t = re.sub(r'"[^"\n]*"', '""', t)
    return re.sub(r"\s+", " ", t)
