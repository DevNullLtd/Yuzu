#!/usr/bin/env python3
"""2a-1b static lexical gate: the typed-source purge thread must be started in run(), never in
the ServerImpl constructor.

A constructor that starts a std::thread and then throws (≈16 throwing store make_unique calls
follow the old start site) destroys a joinable thread during unwind -> std::terminate instead of
the clean startup failure exit (server.cpp's WS-3 elector note says the same). Invariants:

  1. `typed_purge_thread_ = std::thread` appears exactly once, and AFTER `void run() override {`
     (the constructor and ~ServerImpl precede run() in the file).
  2. It appears after the `start_web_server();` call inside run() (past the post-start
     startup_failed_ recheck).
  3. stop() joins it (`typed_purge_thread_.join()`).
  4. It is not a std::jthread.

`//` comments are stripped and whitespace collapsed before matching. Lexical only: it cannot
see a relocation that keeps the tokens in run() but changes control flow (review-enforced).
The self-test mutates the source in memory and requires problems() to be non-empty.

Usage: python3 tests/test_typed_purge_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
START = "typed_purge_thread_ = std::thread"


def normalise(src):
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    t = normalise(src)
    out = []
    starts = [m.start() for m in re.finditer(re.escape(START), t)]
    if len(starts) != 1:
        out.append(f"expected exactly one `{START}` site, found {len(starts)}")
        return out
    run = t.find("void run() override {")
    if run < 0:
        out.append("`void run() override {` not found (stale pattern)")
        return out
    if starts[0] < run:
        out.append("typed_purge_thread_ is started before run() (constructor/destructor region): "
                   "a later constructor throw would std::terminate on the joinable thread")
    web = t.find("start_web_server();", run)
    if web < 0 or starts[0] < web:
        out.append("typed_purge_thread_ must start after start_web_server() in run(), past the "
                   "startup_failed_ recheck")
    if "typed_purge_thread_.join()" not in t:
        out.append("stop() no longer joins typed_purge_thread_")
    if re.search(r"std::jthread typed_purge_thread_", t):
        out.append("typed_purge_thread_ must not be a std::jthread (stop_requested_ is declared after it)")
    return out


class TypedPurgeWiring(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_clean(self):
        self.assertEqual(problems(self.src), [])

    def test_selftest_ctor_start_is_caught(self):
        m = self.src.index("typed_purge_thread_ = std::thread")
        # Move the start token into the constructor region (before run()).
        mutated = self.src.replace(START, "typed_purge_thread_ = std::thread{}; // moved", 1)
        ctor = self.src.index("explicit ServerImpl(")
        mutated = mutated[:ctor] + "typed_purge_thread_ = std::thread([]{});\n" + mutated[ctor:]
        self.assertTrue(problems(mutated), "constructor-start mutation not detected")

    def test_selftest_missing_join_is_caught(self):
        mutated = self.src.replace("typed_purge_thread_.join()", "typed_purge_thread_.detach()")
        self.assertTrue(problems(mutated))

    def test_selftest_jthread_is_caught(self):
        mutated = self.src.replace("std::thread typed_purge_thread_;", "std::jthread typed_purge_thread_;")
        self.assertTrue(problems(mutated))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
