"""Shared C++ source tokenizer for the WP13 lexical gates (helper, not a test).

Adapted from the WP13c vuln_scan gate's lexer: strips comments WITHOUT being fooled by `//` or
`/*` inside string literals, decodes simple escapes and joins adjacent string literals, so a
token hidden in a comment or a string cannot satisfy a pin and a token split across adjacent
literals is still seen. `code_only()` additionally replaces every string literal's CONTENT with
an empty literal (so a call named inside a string cannot satisfy a pin) and removes `#if 0`
blocks. Tests insert this directory on sys.path explicitly (they run under `python3 -I`).
"""
import functools
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


def lex(src: str, keep_strings: bool = True) -> str:
    """Return the code with comments removed and adjacent string literals joined.

    With keep_strings (default) string contents are kept (a brew call lives in a string); each
    joined literal run is emitted as one `"..."` token. With keep_strings=False every joined run is
    emitted as `""` directly (no later regex over the output, so a literal that contains an
    escaped or raw-string quote cannot confuse the blanking).
    """
    out: list[str] = []
    last_idx = -1
    last_is_str = False  # only whitespace/comments since the previous string literal
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            # a backslash-newline continues a // comment onto the next line
            while j > 0 and (src[j - 1] == "\\" or src[j - 2:j] == "\\\r") and src.find("\n", j + 1) >= 0:
                j = src.find("\n", j + 1)
            i = n if j < 0 else j  # newline itself handled as whitespace
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            end = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, end))  # keep line numbers aligned
            i = end
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
                    buf.append("\\n" if d == "\n" else d)  # keep the source line count
                else:
                    buf.append(src[i])
                    i += 1
            i += 1  # closing quote
            content = "".join(buf)
        elif c == "'" and (not (i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_"))
                           or re.search(r"(?<![A-Za-z0-9_])(?:u8|u|U|L)$", src[max(0, i - 3):i])):
            # character literal, plain or prefixed (u8'x', u'x', U'x', L'x'); a digit separator
            # (1'000, 0x1'F) has an alphanumeric char before it and no such prefix
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
        raw_newlines = content.count("\n")
        if not keep_strings:
            content = ""
        if last_is_str:
            out[last_idx] = out[last_idx][:-1] + content + '"'  # join with the previous literal
        else:
            out.append('"' + content + '"')
            last_idx = len(out) - 1
        if not keep_strings and raw_newlines:
            out.append("\n" * raw_newlines)  # a multi-line raw string keeps its line count
        last_is_str = True
    return "".join(out)


_ZLIT = r"(?:0[xX]0+|0[0-7]*)[uUlL]*"
_OLIT = r"(?:0[xX]0*1|1)[uUlL]*"
_ZERO_C = re.compile(rf"(?:\(\s*)*(?:{_ZLIT}|false|FALSE|!\s*(?:{_OLIT}|true|TRUE))(?:\s*\))*")
_ONE_C = re.compile(rf"(?:\(\s*)*(?:{_OLIT}|true|TRUE|!\s*(?:{_ZLIT}|false|FALSE))(?:\s*\))*")


def _cond(d: str):
    """('if'|'elif', condition text) for a directive line, else None."""
    m = re.match(r"#\s*(if|elif)\b\s*(.*)$", d)
    return (m.group(1), m.group(2).strip()) if m else None


def _lines(text: str) -> list[str]:
    """Split on '\\n' only (str.splitlines also splits on \\r, \\v, \\f and Unicode separators)."""
    return re.findall(r"[^\n]*\n|[^\n]+", text)


def dead_lines(masked: str) -> set[int]:
    """Indices of lines inside a dead preprocessor branch, from COMMENT- AND STRING-FREE text
    (lex(..., keep_strings=False)). A condition that is a literal zero (`0`, `(0)`, `00`, `0L`,
    `0x0`, `false`, `!1`, `!true`) is dead; one that is a literal one (`1`, `true`, `!0`, `0x1`)
    kills every LATER `#elif`/`#else` branch; any other condition (an identifier, an expression)
    is unknown and treated as live, so a pin under it still counts. `#elif 0` chains are tracked
    branch by branch. Directive lines inside a dead branch are dead. `#ifdef`/`#ifndef` are
    unknown (a non-goal)."""
    dead: set[int] = set()
    stack: list[dict] = []
    for idx, line in enumerate(_lines(masked)):
        d = line.strip()
        top_skip = stack[-1]["skip"] if stack else False
        if re.match(r"#\s*if(?:def|ndef)?\b", d):
            e = {"skip": top_skip, "parent": top_skip, "all_zero": False, "one": False}
            c = _cond(d)
            if top_skip:
                dead.add(idx)
            elif c and _ZERO_C.fullmatch(c[1]):
                e["skip"], e["all_zero"] = True, True
                dead.add(idx)
            elif c and _ONE_C.fullmatch(c[1]):
                e["one"] = True
            stack.append(e)
            continue
        if re.match(r"#\s*(?:else|elif)\b", d) and stack:
            e = stack[-1]
            c = _cond(d)  # None for #else
            if e["parent"] or e["one"]:
                e["skip"] = True  # inside a dead region, or a known-true branch was already taken
            elif c is None:  # #else after only-unknown or all-zero branches: live
                e["skip"], e["all_zero"] = False, False
            elif _ZERO_C.fullmatch(c[1]):
                e["skip"] = e["all_zero"]  # still dead after all-zero; live (unknown) otherwise
            elif _ONE_C.fullmatch(c[1]):
                e["skip"], e["one"], e["all_zero"] = False, True, False
            else:
                e["skip"], e["all_zero"] = False, False
            if e["skip"]:
                dead.add(idx)
            continue
        if re.match(r"#\s*endif\b", d) and stack:
            if stack[-1]["skip"]:
                dead.add(idx)
            stack.pop()
            continue
        if top_skip:
            dead.add(idx)
    return dead


def _filter(src: str, keep_strings: bool) -> str:
    dead = dead_lines(lex(src, keep_strings=False))
    lines = _lines(lex(src, keep_strings=keep_strings))
    # Both lexes keep every source line (block comments and raw strings emit their newlines), so
    # indices align; a disagreement is a tokenizer bug and fails loudly.
    if len(lines) != len(_lines(lex(src, keep_strings=False))):
        raise AssertionError("cpp_lex_helper: keep/blank lexes disagree on the line count")
    return "".join(l for k, l in enumerate(lines) if k not in dead)


@functools.lru_cache(maxsize=256)
def live_text(src: str) -> str:
    """Comments (line, block, backslash-continued) and dead preprocessor branches removed,
    string contents KEPT. Dead-branch detection runs on comment- and string-free text, so a
    `#if 0` inside a comment or string cannot start one."""
    return _filter(src, True)


@functools.lru_cache(maxsize=256)
def code_only(src: str) -> str:
    """As live_text but string-literal contents blanked to `""`; whitespace collapsed."""
    return re.sub(r"\s+", " ", _filter(src, False))


# Non-goals (a regex-free tokenizer cannot evaluate them): `#ifdef NEVER` / `#ifndef ALWAYS`
# style conditions, `#if` expressions other than a literal zero/one (`0 && X`, `defined(X)`),
# macro-built tokens, trigraphs / digraphs, and backslash-newline SPLICES inside a token or
# between the two characters of a comment opener (comments are recognised before splicing). A pin that matters must not rely on these being excluded.


def _selftest() -> list[str]:
    """Direct self-test of the tokenizer shapes the gates depend on; returns failure messages."""
    cases = [
        
        ("line comment", 'a(); // b();\n', "b()", False),
        ("backslash-continued line comment", 'a(); // x \\\n b();\nc();', "b()", False),
        ("CRLF backslash-continued comment", 'a(); // x \\\r\n b();\r\nc();', "b()", False),
        ("block comment", 'a(); /* b(); */ c();', "b()", False),
        ("string contents blanked", 'a("b();"); c();', "b()", False),
        ("string with escaped quote", 'a("x\\"y"); keep();', "keep()", True),
        ("string with escaped quote hides call", 'a("x\\" b(); "); keep();', "b()", False),
        ("raw string with quote", 'a(R"(x"y)"); keep();', "keep()", True),
        ("raw string hides call", 'a(R"(x" b(); ")"); keep();', "b()", False),
        ("char literal quote", "a('\"'); b(); keep();", "keep()", True),
        ("char literal quote hides nothing", "a('\"'); b(); keep();", "b()", True),
        ("L'\"' char literal", "a(L'\"'); b(); keep();", "keep()", True),
        ("u8'\"' char literal", "a(u8'\"'); b(); keep();", "keep()", True),
        ("u'\"' / U'\"' char literals", "a(u'\"', U'\"'); b(); keep();", "keep()", True),
        ("digit separator", "int x = 1'000'000; b(); keep();", "keep()", True),
        ("hex digit separator", "int x = 0xFF'FF; b(); keep();", "keep()", True),
        ("adjacent literals joined (kept)", 'a("b" "c");', None, None),
        ("#if 0", "#if 0\nb();\n#endif\nkeep();", "b()", False),
        ("#if (0)", "#if (0)\nb();\n#endif\nkeep();", "b()", False),
        ("#if false", "#if false\nb();\n#endif\nkeep();", "b()", False),
        ("#if 00", "#if 00\nb();\n#endif\nkeep();", "b()", False),
        ("#if 0L", "#if 0L\nb();\n#endif\nkeep();", "b()", False),
        ("#if !1", "#if !1\nb();\n#endif\nkeep();", "b()", False),
        ("#if 0 else branch kept", "#if 0\nb();\n#else\nkeep();\n#endif", "keep()", True),
        ("#if 0 nested", "#if 0\n#if X\nb();\n#endif\nb();\n#endif\nkeep();", "b()", False),
        ("#if 1 kept", "#if 1\nkeep();\n#endif", "keep()", True),
        ("#if 0 #elif 0 both dead", "#if 0\nb();\n#elif 0\nb();\n#endif\nkeep();", "b()", False),
        ("#if 0 #elif 0 #else live", "#if 0\nb();\n#elif 0\nb();\n#else\nkeep();\n#endif", "keep()", True),
        ("#if 0 #elif 0 #else drops dead", "#if 0\nb();\n#elif 0\nb();\n#else\nkeep();\n#endif", "b()", False),
        ("#if 0 #elif X live", "#if 0\nb();\n#elif X\nkeep();\n#endif", "keep()", True),
        ("#if 0 #elif X drops the dead branch", "#if 0\nb();\n#elif X\nkeep();\n#endif", "b()", False),
        ("#if 0 #elif 1 live", "#if 0\nb();\n#elif 1\nkeep();\n#else\nb2();\n#endif", "keep()", True),
        ("#if 0 #elif 1 kills the else", "#if 0\nb();\n#elif 1\nkeep();\n#else\nb2();\n#endif", "b2()", False),
        ("#if 1 #elif 0 dead", "#if 1\nkeep();\n#elif X\nb();\n#endif", "b()", False),
        ("#if 0x0", "#if 0x0\nb();\n#endif\nkeep();", "b()", False),
        ("#if 0x00UL", "#if 0x00UL\nb();\n#endif\nkeep();", "b()", False),
        ("#if 0x1 is live", "#if 0x1\nkeep();\n#else\nb();\n#endif", "b()", False),
        ("#if ((0))", "#if ((0))\nb();\n#endif\nkeep();", "b()", False),
        ("#if X stays live", "#if X\nkeep();\n#endif", "keep()", True),
        ("nested #if 0 / #elif 0 inside live", "#if X\n#if 0\nb();\n#elif 0\nb();\n#endif\nkeep();\n#endif", "b()", False),
        ("#if 1 #else dropped", "#if 1\nkeep();\n#else\nb();\n#endif", "b()", False),
        ("#if 1 #else keeps the live branch", "#if 1\nkeep();\n#else\nb();\n#endif", "keep()", True),
        ("#if 0 inside a block comment is not a directive", "/*\n#if 0\n*/\nkeep();\nb();", "b()", True),
        ("#if 0 inside a string is not a directive", 'a("\\n#if 0\\n");\nb();\nkeep();', "b()", True),
        ("CRLF #if 0", "#if 0\r\nb();\r\n#endif\r\nkeep();\r\n", "b()", False),
        ("CRLF #if 0 keeps after", "#if 0\r\nb();\r\n#endif\r\nkeep();\r\n", "keep()", True),
        ("multi-line raw string keeps line alignment", 'a(R"(\nx\n)");\n#if 0\nb();\n#endif\nkeep();', "b()", False),
    ]
    errs = []
    for name, src, token, want in cases:
        if token is None:
            if lex(src).replace(' ', '') != 'a("bc");':
                errs.append(f"{name}: adjacent literals not joined: {lex(src)!r}")
            continue
        got = token in code_only(src)
        if got != want:
            errs.append(f"{name}: expected {token!r} present={want}, got {got} ({code_only(src)!r})")
    # live_text (strings kept) must agree with code_only on dead branches, even when a string
    # holds an escaped newline or a raw string spans lines.
    for name, src, token, want in [
        ("live_text: escaped newline in a string", 'a("x\\ny");\n#if 0\nb();\n#endif\nkeep();', "b()", False),
        ("live_text: raw string spans lines", 'a(R"(x\ny)");\n#if 0\nb();\n#endif\nkeep();', "b()", False),
        ("live_text: strings kept", 'a("keepme");', "keepme", True),
    ]:
        try:
            got = token in live_text(src)
        except AssertionError as exc:  # noqa: BLE001
            errs.append(f"{name}: {exc}")
            continue
        if got != want:
            errs.append(f"{name}: expected {token!r} present={want}, got {got}")
    return errs


if __name__ == "__main__":
    import sys
    _errs = _selftest()
    for _e in _errs:
        print("FAIL:", _e)
    sys.exit(1 if _errs else 0)
