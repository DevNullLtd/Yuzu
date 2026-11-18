#!/usr/bin/env python3
"""Lexical gate for the Echo test-writing standard (docs/testing/echo-test-standard.md).

Scans tests/unit/**/test_echo*.cpp for four patterns the standard forbids, comments and
string/char literals stripped first:

  [sleep]      any sleep_for / sleep_until: wait on a future, latch or callback instead.
  [async]      any std::async: a bounded return goes through yuzu::test::must_return_within.
  [wait]       a wait_for / wait_until with no ScopeExit or Joiner earlier in the same top-level
               definition: a failed assertion would unwind past the thread it waits on.
  [size-check] a CHECK on X.size() / X.empty() followed within 10 lines by X[ / X.front() /
               X.back(): a failed CHECK carries on into an out-of-range read. Use REQUIRE.
               (.at() throws, a clean failure, so it is not flagged.)

A finding is waived only by `// echo-test-ok: <reason>` in a real `//` line comment on the same
line, or on the comment-only line directly above. The same text inside a string literal or a block
comment waives nothing. There is no baseline file: the tree is clean, or the finding is marked.

The gate is lexical: a guard token that is present but does not protect the wait passes, and a
size CHECK more than 10 lines before its index, or through an alias, is missed.
"""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
UNIT = ROOT / "tests" / "unit"

HINT = ("\nSee docs/testing/echo-test-standard.md. Fix the finding, or waive it with a real `//` "
        "comment on the same line or the comment line directly above: "
        "`// echo-test-ok: <reason>` (a non-empty reason; a string literal or /* */ comment waives "
        "nothing).")

# Comments and literals are found in ONE pass, so a quote inside a comment, or a comment marker
# inside a literal, cannot hide code or pass a comment off as a marker.
LEX = re.compile(r'//[^\n]*|/\*.*?\*/|R"([^\s()\\]{0,16})\(.*?\)\1"|"(?:\\.|[^"\\\n])*"'
                 r"|'(?:\\.|[^'\\\n])'", re.S)
SLEEP = re.compile(r"\bsleep_(?:for|until)\s*\(")
ASYNC = re.compile(r"\bstd::async\s*\(")
WAIT = re.compile(r"\bwait_(?:for|until)\s*\(")
GUARD = re.compile(r"\b(?:ScopeExit|Joiner)\b")
SIZE_CHECK = re.compile(r"\bCHECK(?:_FALSE)?\s*\(\s*!?\s*([A-Za-z_][\w:]*(?:(?:\.|->)\w+)*)"
                        r"\s*(?:\.|->)\s*(?:size|empty)\s*\(\s*\)")
MARKER = re.compile(r"echo-test-ok:\s*\S")
SIZE_WINDOW = 10


def lex(src):
    """Return (code, comments): `code` is src with comments and literals blanked (newlines and
    columns kept); `comments` maps a 1-based line to the text of its `//` line comment."""
    comments = {}

    def blank(m):
        tok = m.group(0)
        if tok.startswith("//"):
            comments[src.count("\n", 0, m.start()) + 1] = tok[2:]
        return re.sub(r"[^\n]", " ", tok)

    return LEX.sub(blank, src), comments


def waived(code_lines, comments, line):
    """True if a real // comment on `line`, or on the comment-only line above it, carries a marker."""
    if MARKER.search(comments.get(line, "")):
        return True
    above = line - 1
    return above >= 1 and not code_lines[above - 1].strip() and bool(MARKER.search(comments.get(above, "")))


def problems(name, src):
    """Findings for one file's text, as `name:line: [flag] message`."""
    code, comments = lex(src)
    lines = code.split("\n")
    starts = [0]
    for ln in lines[:-1]:
        starts.append(starts[-1] + len(ln) + 1)

    def lineno(pos):
        return code.count("\n", 0, pos) + 1

    def def_start(line):
        """Offset of the nearest line at or above `line` starting at column 0 with an identifier char."""
        for i in range(line - 1, -1, -1):
            if lines[i][:1].isalnum() or lines[i][:1] == "_":
                return starts[i]
        return 0

    out = []

    def add(line, flag, msg):
        if not waived(lines, comments, line):
            out.append(f"{name}:{line}: [{flag}] {msg}")

    for m in SLEEP.finditer(code):
        add(lineno(m.start()), "sleep",
            "sleep_for/sleep_until: wait on a future, latch or callback, never on the clock")
    for m in ASYNC.finditer(code):
        add(lineno(m.start()), "async",
            "std::async: a call whose return is under test uses yuzu::test::must_return_within")
    for m in WAIT.finditer(code):
        line = lineno(m.start())
        if not GUARD.search(code, def_start(line), m.start()):
            add(line, "wait",
                "wait_for/wait_until with no ScopeExit or Joiner earlier in this definition: a failed "
                "assertion would unwind past the thread it waits on")
    for m in SIZE_CHECK.finditer(code):
        line = lineno(m.start())
        x = r"(?:\.|->)".join(re.escape(t) for t in re.split(r"\.|->", m.group(1)))
        window = "\n".join(lines[line:line + SIZE_WINDOW])
        index = re.search(rf"\b{x}\s*(?:\[|(?:\.|->)\s*(?:front|back)\s*\()", window)
        if not index:
            continue
        # a REQUIRE on the same size before the index makes the index safe
        guard = re.search(rf"\bREQUIRE(?:_FALSE)?\s*\(\s*!?\s*{x}\s*(?:\.|->)\s*(?:size|empty)\s*\(", window)
        if guard and guard.start() < index.start():
            continue
        add(line, "size-check",
            f"CHECK on {m.group(1)}.size()/empty() then an index: use REQUIRE so a failure stops here")
    return out


def echo_files():
    return sorted(UNIT.rglob("test_echo*.cpp"))


def tree_problems():
    out = []
    for f in echo_files():
        out += problems(f.relative_to(ROOT).as_posix(), f.read_text(encoding="utf-8"))
    return out


def mutate(src, old, new, count=1):
    assert old in src, f"stale mutation pattern: {old!r}"
    return src.replace(old, new, count)


def real(rel):
    return (UNIT / rel).read_text(encoding="utf-8")


OPEN_RETRY_MARKER = "// echo-test-ok: every caller's OpenRetryLoop destructor stops and joins the worker on unwind"
TIMELINE_MARKER = "// echo-test-ok: the loop below bounds i by labels.size()"
TIMELINE_LINE = "CHECK(labels.size() == r.ticks); " + TIMELINE_MARKER


class EchoTestStandardLexical(unittest.TestCase):
    def flags(self, name, src):
        return problems(name, src)

    def assertFlagged(self, name, src, flag):
        found = self.flags(name, src)
        self.assertTrue(any(f"[{flag}]" in f for f in found), f"expected [{flag}], got {found}")

    def test_tree_is_clean(self):
        self.assertTrue(echo_files(), "no tests/unit/**/test_echo*.cpp found")
        self.assertEqual(tree_problems(), [], HINT)

    def test_real_file_mutations_are_caught(self):
        nstat = real("test_echo_netqual_nstat.cpp")
        store = real("test_echo_store.cpp")
        agg = real("test_echo_aggregator.cpp")
        fold = real("test_echo_fold.cpp")
        retry = real("test_echo_open_retry.cpp")
        render = real("server/test_echo_timeline_render.cpp")
        cases = {
            "nstat: REQUIRE back to CHECK": ("test_echo_netqual_nstat.cpp", mutate(
                nstat, "REQUIRE(kept.size() == 8)", "CHECK(kept.size() == 8)"), "size-check"),
            "store: REQUIRE back to CHECK": ("test_echo_store.cpp", mutate(
                store, "REQUIRE(remaining->rows.size() == 5)", "CHECK(remaining->rows.size() == 5)"),
                "size-check"),
            "aggregator: Joiner renamed, the cv wait has no guard": ("test_echo_aggregator.cpp", mutate(
                agg, "Joiner", "Joinr", count=-1), "wait"),
            "fold: the GC case loses its ScopeExit": ("test_echo_fold.cpp", mutate(
                fold, "const yuzu::test::ScopeExit release_and_join{", "const yuzu::test::ScopeOut release_and_join{"),
                "wait"),
            "a sleep_for is inserted": ("test_echo_fold.cpp", mutate(
                fold, "TEST_CASE(\"fold_rows waits while a GC pass holds op_mu_\", \"[echo][fold][gc][concurrency]\") {\n",
                "TEST_CASE(\"fold_rows waits while a GC pass holds op_mu_\", \"[echo][fold][gc][concurrency]\") {\n"
                "    std::this_thread::sleep_for(std::chrono::milliseconds(5));\n"), "sleep"),
            "a sleep_until is inserted": ("test_echo_fold.cpp", mutate(
                fold, "TEST_CASE(\"fold_rows waits while a GC pass holds op_mu_\", \"[echo][fold][gc][concurrency]\") {\n",
                "TEST_CASE(\"fold_rows waits while a GC pass holds op_mu_\", \"[echo][fold][gc][concurrency]\") {\n"
                "    std::this_thread::sleep_until(std::chrono::steady_clock::now());\n"), "sleep"),
            "a std::async is inserted": ("test_echo_open_retry.cpp", mutate(
                retry, "bool signalled(std::future<void>& f) {\n",
                "bool signalled(std::future<void>& f) {\n    auto x = std::async(std::launch::async, [] {});\n"),
                "async"),
            "the open_retry marker's reason is emptied": ("test_echo_open_retry.cpp", mutate(
                retry, OPEN_RETRY_MARKER, "// echo-test-ok:"), "wait"),
            "the open_retry marker moves two lines above": ("test_echo_open_retry.cpp", mutate(
                retry, OPEN_RETRY_MARKER + "\n", OPEN_RETRY_MARKER + "\n    // unrelated\n"), "wait"),
            "the open_retry marker becomes a block comment": ("test_echo_open_retry.cpp", mutate(
                retry, OPEN_RETRY_MARKER, "/* echo-test-ok: x */"), "wait"),
            "the timeline_render marker is removed": ("server/test_echo_timeline_render.cpp", mutate(
                render, TIMELINE_LINE, "CHECK(labels.size() == r.ticks);"), "size-check"),
            "the timeline_render marker moves into a string literal": ("server/test_echo_timeline_render.cpp",
                mutate(render, TIMELINE_LINE,
                       'CHECK(labels.size() == r.ticks); const char* k = "// echo-test-ok: x";'), "size-check"),
        }
        for label, (name, src, flag) in cases.items():
            with self.subTest(mutation=label):
                self.assertFlagged(name, src, flag)

    def test_negative_controls_stay_clean(self):
        clean = {
            "sleep and async only in a // comment": "void f() {\n    // std::this_thread::sleep_for(1ms); std::async(x);\n}\n",
            "sleep and async only in a block comment": "void f() {\n    /* sleep_until(t); std::async(x); */\n}\n",
            "sleep and async only in a string literal": 'void f() {\n    log("sleep_for( std::async( ");\n}\n',
            "wait_for_event( and wait_for_peer_fin( calls": "void f() {\n    wait_for_event(a);\n    wait_for_peer_fin(b);\n}\n",
            "a size CHECK followed by .at()": "void f() {\n    CHECK(v.size() == 2);\n    CHECK(v.at(1) == 3);\n}\n",
            "a size CHECK then a REQUIRE on the same size before the index":
                "void f() {\n    CHECK(v.size() == 2);\n    REQUIRE(v.size() == 2);\n    CHECK(v[1] == 3);\n}\n",
            "a wait with a ScopeExit earlier in the definition":
                "TEST_CASE(\"x\") {\n    const ScopeExit g{[&] {}};\n    REQUIRE(fut.wait_for(1s) == ready);\n}\n",
            "a size CHECK on a different container": "void f() {\n    CHECK(a.size() == 2);\n    CHECK(b[1] == 3);\n}\n",
        }
        for label, src in clean.items():
            with self.subTest(control=label):
                self.assertEqual(problems("test_echo_x.cpp", src), [])

    def test_wait_guard_is_per_definition(self):
        src = ("TEST_CASE(\"a\") {\n    const ScopeExit g{[&] {}};\n}\n"
               "TEST_CASE(\"b\") {\n    REQUIRE(fut.wait_for(1s) == ready);\n}\n")
        self.assertFlagged("test_echo_x.cpp", src, "wait")

    def test_marker_waives_on_the_same_line_and_the_line_above(self):
        body = "REQUIRE(fut.wait_for(1s) == ready);"
        reason = "// echo-test-ok: the owner joins on unwind"
        same = f"void f() {{\n    {body} {reason}\n}}\n"
        above = f"void f() {{\n    {reason}\n    {body}\n}}\n"
        bare = f"void f() {{\n    {body}\n}}\n"
        self.assertFlagged("test_echo_x.cpp", bare, "wait")
        self.assertEqual(problems("test_echo_x.cpp", same), [])
        self.assertEqual(problems("test_echo_x.cpp", above), [])
        # a marker above a CODE line (not a comment-only line) does not carry down
        code_above = f"void f() {{\n    int x = 0; {reason}\n    {body}\n}}\n"
        self.assertFlagged("test_echo_x.cpp", code_above, "wait")


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
