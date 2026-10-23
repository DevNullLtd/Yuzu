#!/usr/bin/env python3
"""2a-1b static lexical gate over server/core/src/server.cpp: the typed-source purge thread must
start inside run()'s OWN body, after the `if (startup_failed_)` recheck that follows
start_web_server() -- not in the ServerImpl constructor and not inside start_web_server().

Why: a constructor that starts a std::thread and then throws destroys a joinable thread during
unwind (std::terminate), and start_web_server() still has fail-closed exits (SCIM boot failure,
HTTPS cipher-pin failure, MFA step-up classification abort) that run AFTER its body and rely on
the recheck in run(). Invariants:

  1. `typed_purge_thread_ = std::thread` appears exactly once.
  2. It is inside the brace-matched body of `void run() override`.
  3. It is textually after the `if (startup_failed_)` recheck that follows the
     `start_web_server();` call in that body.
  4. stop() joins it (`typed_purge_thread_.join()`), and it is not a std::jthread.

`//` comments are stripped and whitespace collapsed before matching; braces are matched on the
normalised text (string/char literals are blanked first so a brace in a literal cannot skew
the count). Lexical only: it cannot see a relocation that keeps the tokens in run() but
changes control flow (review-enforced). The self-tests MOVE (never copy) the single start
site into the constructor, start_web_server() and before the recheck, and assert the exact
message each time.

Usage: python3 tests/test_typed_purge_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
START = "typed_purge_thread_ = std::thread"

MSG_COUNT = "expected exactly one `typed_purge_thread_ = std::thread` start site, found {n}"
MSG_NOT_IN_RUN = "typed_purge_thread_ is started outside run()'s own body (constructor, start_web_server() or elsewhere)"
MSG_BEFORE_RECHECK = ("typed_purge_thread_ is started before run()'s startup_failed_ recheck that follows "
                      "start_web_server()")
MSG_NO_JOIN = "stop() no longer joins typed_purge_thread_"
MSG_JTHREAD = "typed_purge_thread_ must not be a std::jthread (stop_requested_ is declared after it)"


def normalise(src):
    src = re.sub(r"//.*", "", src)
    src = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', src)
    src = re.sub(r"'(?:\\.|[^'\\\n])'", "''", src)
    return re.sub(r"[ \t\n\r\f\v]+", " ", src)


def body_span(t, head):
    """(start, end) of the brace-matched body whose opening `{` ends `head`; None if absent."""
    i = t.find(head)
    if i < 0:
        return None
    j = t.index("{", i)
    depth = 0
    for k in range(j, len(t)):
        if t[k] == "{":
            depth += 1
        elif t[k] == "}":
            depth -= 1
            if depth == 0:
                return (j, k)
    return None


def problems(src):
    t = normalise(src)
    out = []
    starts = [m.start() for m in re.finditer(re.escape(START), t)]
    if len(starts) != 1:
        return [MSG_COUNT.format(n=len(starts))]
    pos = starts[0]
    run = body_span(t, "void run() override {")
    if run is None:
        return ["`void run() override {` not found (stale pattern)"]
    if not (run[0] < pos < run[1]):
        out.append(MSG_NOT_IN_RUN)
    else:
        web = t.find("start_web_server();", run[0])
        recheck = t.find("if (startup_failed_)", web) if web >= 0 else -1
        if web < 0 or recheck < 0 or recheck > run[1]:
            return out + ["run() no longer has start_web_server(); followed by an "
                          "`if (startup_failed_)` recheck (stale pattern)"]
        if pos < recheck:
            out.append(MSG_BEFORE_RECHECK)
    if "typed_purge_thread_.join()" not in t:
        out.append(MSG_NO_JOIN)
    if re.search(r"std::jthread typed_purge_thread_", t):
        out.append(MSG_JTHREAD)
    return out


class TypedPurgeWiring(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_clean(self):
        self.assertEqual(problems(self.src), [])

    def test_moved_into_constructor(self):
        # move the start into the ctor body: just after its opening brace
        m2 = self.src
        i = m2.index(START)
        j = m2.index("});", i) + 3
        stmt = m2[i:j]
        rest = m2[:i] + m2[j:]
        ctor = rest.index("explicit ServerImpl(Config cfg, auth::AuthManager& auth_mgr)")
        brace = rest.index("{", rest.index(")", ctor))
        m2 = rest[:brace + 1] + "\n" + stmt + "\n" + rest[brace + 1:]
        self.assertEqual(problems(m2), [MSG_NOT_IN_RUN])

    def test_moved_into_start_web_server(self):
        m = self.src
        i = m.index(START)
        j = m.index("});", i) + 3
        stmt = m[i:j]
        rest = m[:i] + m[j:]
        head = rest.index("void start_web_server() {")
        brace = rest.index("{", head)
        m = rest[:brace + 1] + "\n" + stmt + "\n" + rest[brace + 1:]
        self.assertEqual(problems(m), [MSG_NOT_IN_RUN])

    def test_moved_before_recheck(self):
        m = self.src
        i = m.index(START)
        j = m.index("});", i) + 3
        stmt = m[i:j]
        rest = m[:i] + m[j:]
        web = rest.index("start_web_server();", rest.index("void run() override {"))
        end = web + len("start_web_server();")
        m = rest[:end] + "\n" + stmt + "\n" + rest[end:]
        self.assertEqual(problems(m), [MSG_BEFORE_RECHECK])

    def test_missing_join(self):
        m = self.src.replace("typed_purge_thread_.join()", "typed_purge_thread_.detach()")
        self.assertEqual(problems(m), [MSG_NO_JOIN])

    def test_jthread(self):
        m = self.src.replace("std::thread typed_purge_thread_;", "std::jthread typed_purge_thread_;")
        self.assertEqual(problems(m), [MSG_JTHREAD])

    def test_copied_not_moved_is_caught(self):
        m = self.src.replace(START, START + "{}; " + START, 1)
        self.assertEqual(problems(m), [MSG_COUNT.format(n=2)])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
