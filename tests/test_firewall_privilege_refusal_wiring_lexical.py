#!/usr/bin/env python3
"""Static lexical gate over the packaged-Linux privilege refusal in the firewall plugin.

The packaged Linux agent (User=yuzu-agent, NoNewPrivileges=true, no sudoers grant) cannot elevate,
so every mutating containment action must refuse cleanly (`privilege_unavailable`) BEFORE any
record is written or tool is called, rather than write an `applying` record and fail every tool
call after it. The decision is a pure function (fq::linux_privilege_refusal, unit-tested in
test_firewall_quarantine_parsers.cpp); only the two OS reads and the call sites live in
firewall_plugin.cpp, and `privilege_refusal()` is `#if defined(__linux__)`, so no macOS or Windows
build or test can observe a dropped or reordered call. This gate pins what they cannot:

  1. In each of do_quarantine, do_release, do_quarantine_allow and do_repair, a
     `if (const auto why = privilege_refusal()) return emit_refusal(` statement exists and
     appears BEFORE `Containment containment(` (the Containment constructor reads the leg and the
     record; a refusal evaluated after it has already touched the host or the store).
  2. `privilege_refusal()`'s Linux branch calls `fq::linux_privilege_refusal(` with
     `::geteuid() == 0` and a `PR_GET_NO_NEW_PRIVS` prctl read (a predicate replaced by a constant
     would refuse nothing, or everything), and in that ORDER: the call shape is also pinned as one
     anchored pattern, because the two arguments are both ints-or-bools and a swap compiles and
     keeps every token present while inverting the refusal.

The live half (a real NoNewPrivileges unit refusing for real) is exercised on the Linux lane at
gate 4, not here.

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a check.
Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations (each of the four calls deleted, one
moved after the Containment constructor, the predicate replaced by std::nullopt, the two arguments
swapped, the root test replaced by a bare constant) and requires
problems() to be non-empty on each; a mutation whose pattern no longer matches fails loudly
(stale pattern) rather than passing vacuously.

Usage: python3 tests/test_firewall_privilege_refusal_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_CPP = ROOT / "agents" / "plugins" / "firewall" / "src" / "firewall_plugin.cpp"
TAG = "test_firewall_privilege_refusal_wiring_lexical"
HINT = (
    " (this gate pins the packaged-Linux privilege refusal call sites in the firewall plugin; if"
    " firewall_plugin.cpp was legitimately restructured, update"
    " tests/test_firewall_privilege_refusal_wiring_lexical.py)"
)

# The four mutating handlers; do_quarantine_status is read-only and never refused.
HANDLERS = ("do_quarantine", "do_release", "do_quarantine_allow", "do_repair")

# `\w+` so a renamed local does not break the gate; the call and the returned refusal are the invariant.
REFUSAL = r"if \( ?const auto \w+ = privilege_refusal\(\) ?\) return emit_refusal\("

# The full call shape on normalised text: root test first, then the NoNewPrivileges read.
CALL_SHAPE = r"fq::linux_privilege_refusal\( ?::geteuid\( ?\) == 0, ?::prctl\( ?PR_GET_NO_NEW_PRIVS"


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(plugin_src):
    """One message per violated invariant, in invariant order; [] when clean."""
    out = []
    cpp = normalise(plugin_src)

    for fn in HANDLERS:
        body = re.search(r"\bint " + fn + r"\(.*?(?= int do_\w+\(|$)", cpp)
        if not body:
            out.append(f"firewall_plugin.cpp no longer defines int {fn}(")
            continue
        text = body.group(0)
        refusal = re.search(REFUSAL, text)
        containment = text.find("Containment containment(")
        if not refusal:
            out.append(f"{fn} no longer returns emit_refusal( when privilege_refusal() answers "
                       "(the packaged Linux unit would write a record and fail every tool call after it)")
        elif containment < 0 or refusal.start() > containment:
            out.append(f"{fn} no longer evaluates privilege_refusal() before `Containment containment(` "
                       "(the refusal would run after the leg and the record were already touched)")

    fn_body = re.search(r"std::optional<std::string_view> privilege_refusal\(\) \{.*?(?=template <class Body> int gated\()",
                        cpp)
    if not fn_body:
        out.append("firewall_plugin.cpp no longer defines privilege_refusal() ahead of gated()")
    else:
        linux = re.search(r"#if defined\( ?__linux__ ?\)(.*?)#else", fn_body.group(0))
        branch = linux.group(1) if linux else ""
        if not re.search(r"fq::linux_privilege_refusal\(", branch):
            out.append("privilege_refusal() Linux branch no longer calls fq::linux_privilege_refusal( "
                       "(the decision would not be the unit-tested one)")
        if not re.search(r"::geteuid\( ?\) == 0", branch):
            out.append("privilege_refusal() Linux branch no longer passes `::geteuid() == 0` "
                       "(root would be refused, or a non-root caller not)")
        if not re.search(r"PR_GET_NO_NEW_PRIVS", branch):
            out.append("privilege_refusal() Linux branch no longer reads PR_GET_NO_NEW_PRIVS "
                       "(NoNewPrivileges would not be detected)")
        if not re.search(CALL_SHAPE, branch):
            out.append("privilege_refusal() Linux branch no longer calls "
                       "fq::linux_privilege_refusal(::geteuid() == 0, ::prctl(PR_GET_NO_NEW_PRIVS, ...) "
                       "in that argument order (swapped or constant arguments would invert or void the refusal)")
    return out


def _in_handler(fn, pat, repl):
    """Mutator: apply pat->repl once, to the first match at or after `int <fn>(` in the raw source."""
    def mutate(raw):
        start = re.search(r"\bint " + fn + r"\(", raw)
        if not start:
            return raw, 0
        head, tail = raw[:start.start()], raw[start.start():]
        tail, n = re.subn(pat, repl, tail, count=1)
        return head + tail, n
    return mutate


_CALL = r"if \(const auto why = privilege_refusal\(\)\)\s*return emit_refusal\([^;]*;"
_CTOR = r"Containment containment\([^;]*;"

# Each row removes one invariant: (mutator, expected substring of a problem message).
MUTATIONS = []
for _fn in HANDLERS:
    MUTATIONS.append((_in_handler(_fn, _CALL, ""), f"{_fn} no longer returns emit_refusal("))
MUTATIONS.append((_in_handler("do_release", "(" + _CALL + r")(\s*" + _CTOR + ")", r"\2\n    \1"),
                  "do_release no longer evaluates privilege_refusal() before"))
MUTATIONS.append((_in_handler("do_quarantine", "(" + _CALL + r")(\s*" + _CTOR + ")", r"\2\n    \1"),
                  "do_quarantine no longer evaluates privilege_refusal() before"))
MUTATIONS.append((_in_handler("do_quarantine_allow", "(" + _CALL + r")(\s*" + _CTOR + ")", r"\2\n    \1"),
                  "do_quarantine_allow no longer evaluates privilege_refusal() before"))
MUTATIONS.append((_in_handler("do_repair", "(" + _CALL + r")(\s*" + _CTOR + ")", r"\2\n    \1"),
                  "do_repair no longer evaluates privilege_refusal() before"))
MUTATIONS.append((lambda raw: re.subn(r"return fq::linux_privilege_refusal\([^;]*;", "return std::nullopt;", raw,
                                      count=1),
                  "no longer calls fq::linux_privilege_refusal("))
MUTATIONS.append((lambda raw: re.subn(r"::geteuid\(\) == 0,", "true,", raw, count=1),
                  "no longer passes `::geteuid() == 0`"))
# The two arguments swapped: every token is still present, so only the anchored shape sees it.
MUTATIONS.append((lambda raw: re.subn(
                      r"fq::linux_privilege_refusal\(::geteuid\(\) == 0,(\s*)(::prctl\(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0\))\)",
                      r"fq::linux_privilege_refusal(\2,\1::geteuid() == 0)", raw, count=1),
                  "in that argument order"))
# The root test replaced by a bare constant (the shape, not just the token, must hold).
MUTATIONS.append((lambda raw: re.subn(r"::geteuid\(\) == 0,", "0,", raw, count=1),
                  "in that argument order"))
MUTATIONS.append((lambda raw: re.subn(r"::prctl\(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0\)", "0", raw, count=1),
                  "no longer reads PR_GET_NO_NEW_PRIVS"))


class FirewallPrivilegeRefusalWiringLexical(unittest.TestCase):
    def setUp(self):
        self.cpp = PLUGIN_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.cpp)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.cpp)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
