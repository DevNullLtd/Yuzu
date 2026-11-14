#!/usr/bin/env python3
"""Static lexical gate over the Windows release's default-action guard in the firewall plugin.

A Windows release WIDENS first and removes its own allowance rules last. Step 3 puts each
profile's default action back; if one will not go back (or its captured image cannot be read) the
profile still BLOCKS, and the allowance rules are the only thing keeping the control channel and
DNS open. WinLeg::remove() therefore returns `release_incomplete` as soon as
`tally.policy_restore_failed > 0`, BEFORE step 4 deletes the rules, leaving the record `releasing`
for the next release or start to retry. The decision (fq::win_release_decision) is pure and
unit-tested, but the early return is a statement inside the `_WIN32` COM leg, so no macOS or Linux
build or test can observe it deleted, weakened or moved below the removal loop: the whole suite
stayed green with it reverted. This gate pins what they cannot, inside WinLeg::remove():

  1. A `if (tally.policy_restore_failed > 0) return release_incomplete(` statement exists.
  2. It appears BEFORE the first `remove_rules_by_name(` call (the rule deletion) and before the
     step-4 `for (int pass` loop that drives it. `collect_our_rule_names(` is deliberately NOT
     the anchor: its first call is step 1's `ours_at_start`, which step 3's fallback decision
     needs and which therefore legitimately precedes the guard.

  3. The unreadable-image branch (`PriorImageStep::unreadable_image`) increments
     `tally.policy_restore_failed` before any default setter can run, so a present-but-unparsable
     captured image refuses instead of falling back to the OS default.
  4. Inside `restore_default`, the delete_local branch calls `put_Default*Action` BEFORE
     `RegDeleteKeyValueW(`, and returns false when the put fails.

The live half (a failing default-action restore mid-release on a real Windows host: the rules
survive and the record stays `releasing`) is exercised at gate 4 on Windows, not here.

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a check.
Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations (the return deleted, the guard moved
after the removal loop, the comparison replaced by `== 0`, the returned value replaced by the
success result) and requires problems() to be non-empty on each; a mutation whose pattern no
longer matches fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 tests/test_firewall_release_guard_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_CPP = ROOT / "agents" / "plugins" / "firewall" / "src" / "firewall_plugin.cpp"
TAG = "test_firewall_release_guard_wiring_lexical"
HINT = (
    " (this gate pins the default-action restore guard in WinLeg::remove(); if firewall_plugin.cpp"
    " was legitimately restructured, update tests/test_firewall_release_guard_wiring_lexical.py)"
)

# The guard statement on normalised text.
GUARD = r"if \( ?tally\.policy_restore_failed > 0 ?\) return release_incomplete\("
# The rule deletion and the step-4 loop that drives it.
REMOVAL = r"remove_rules_by_name\("
PASS_LOOP = r"for \( ?int \w+ = 0; ?\w+ < \d+; ?\+\+\w+ ?\)"


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def _restore_default_body(cpp):
    m = re.search(r"static bool restore_default\(.*?\) \{(.*?)struct PolicyDword", cpp)
    return m.group(1) if m else None


def problems(plugin_src):
    """One message per violated invariant, in invariant order; [] when clean."""
    out = []
    cpp = normalise(plugin_src)

    leg = re.search(r"class WinLeg final : public fq::Leg \{", cpp)
    body = None
    if leg:
        body = re.search(
            r"fq::StepResult remove\( ?fq::OsPayload& os, fq::Deadline& dl ?\) override \{(.*?)fq::LegStatus read_status\(",
            cpp[leg.end():])
    if not body:
        out.append("firewall_plugin.cpp no longer defines WinLeg::remove( ahead of read_status(")
        return out
    text = body.group(1)

    guard = re.search(GUARD, text)
    removal = re.search(REMOVAL, text)
    loop = re.search(PASS_LOOP, text)
    if not removal or not loop:
        out.append("WinLeg::remove() no longer has the step-4 `for (int pass ...)` loop calling "
                   "remove_rules_by_name( (the anchor this gate orders the guard against is gone)")
    if not guard:
        out.append("WinLeg::remove() no longer returns release_incomplete( when "
                   "tally.policy_restore_failed > 0 (a default action that will not restore would "
                   "leave the host blocking with no allowance once step 4 deleted them)")
    elif removal and loop and (guard.start() > removal.start() or guard.start() > loop.start()):
        out.append("WinLeg::remove() no longer returns release_incomplete( for a failed "
                   "default-action restore BEFORE the step-4 rule removal (the allowances would be "
                   "deleted while a profile still blocks)")

    unreadable = re.search(
        r"fq::PriorImageStep::unreadable_image\) \{ ?\+\+tally\.policy_restore_failed;", text)
    if not unreadable:
        out.append("WinLeg::remove() no longer counts a present-but-unreadable prior-policy image "
                   "(PriorImageStep::unreadable_image) as tally.policy_restore_failed (the release "
                   "would fall back to the OS default over a captured hardened policy)")

    rd = _restore_default_body(cpp)
    if rd is None:
        out.append("firewall_plugin.cpp no longer defines restore_default( ahead of the policy-store reader")
    else:
        put = re.search(r"put_Default(?:Inbound|Outbound)Action\(", rd)
        delete = re.search(r"RegDeleteKeyValueW\(", rd)
        if not put or not delete or put.start() > delete.start():
            out.append("restore_default() no longer puts the OS default through put_Default*Action( "
                       "BEFORE RegDeleteKeyValueW( (the running firewall service would keep the "
                       "quarantine block after the local value is deleted)")
        if not re.search(r"!= S_OK\) return false;\s*const LONG rc = RegDeleteKeyValueW\(", rd):
            out.append("restore_default() no longer returns false when the put_Default*Action( before "
                       "RegDeleteKeyValueW( fails (a failed put would count as restored)")
    return out


_GUARD_RAW = r"if \(tally\.policy_restore_failed > 0\)\s*return release_incomplete\([^;]*;"


def _delete_guard(raw):
    return re.subn(_GUARD_RAW, "", raw, count=1)


def _move_guard_after_removal(raw):
    m = re.search(_GUARD_RAW, raw)
    if not m:
        return raw, 0
    stmt = m.group(0)
    without = raw[:m.start()] + raw[m.end():]
    # Re-insert it just ahead of step 5, i.e. after the step-4 loop has deleted the rules.
    out, n = re.subn(r"(\n[ \t]*// 5\. Keys go only after a clean release)",
                     lambda mm: "\n        " + stmt + mm.group(1), without, count=1)
    return out, n


# Each row removes one invariant: (mutator, expected substring of a problem message).
MUTATIONS = [
    (_delete_guard, "no longer returns release_incomplete( when"),
    (_move_guard_after_removal, "BEFORE the step-4 rule removal"),
    (lambda raw: re.subn(r"policy_restore_failed > 0\)(\s*)return release_incomplete\(",
                         r"policy_restore_failed == 0)\1return release_incomplete(", raw, count=1),
     "no longer returns release_incomplete( when"),
    (lambda raw: re.subn(r"(if \(tally\.policy_restore_failed > 0\)\s*)return release_incomplete\([^;]*;",
                         r"\1return result;", raw, count=1),
     "no longer returns release_incomplete( when"),
]


def _swap_put_and_delete(raw):
    m = re.search(
        r"(            const NET_FW_ACTION os_default = .*?\n)(            if \(\(inbound \? policy\.put_DefaultInboundAction.*?return false;\n)"
        r"(            const LONG rc = RegDeleteKeyValueW\([^\n]*\n)", raw, re.S)
    if not m:
        return raw, 0
    return raw[:m.start()] + m.group(1) + m.group(3) + m.group(2) + raw[m.end():], 1


MUTATIONS += [
    (_swap_put_and_delete, "BEFORE RegDeleteKeyValueW("),
    (lambda raw: re.subn(r"\n            if \(\(inbound \? policy\.put_DefaultInboundAction.*?return false;\n",
                         "\n", raw, count=1, flags=re.S),
     "BEFORE RegDeleteKeyValueW("),
    (lambda raw: re.subn(r"(!= S_OK\)\s*)return false;(\s*const LONG rc = RegDeleteKeyValueW)", r"\1return true;\2", raw, count=1),
     "no longer returns false when the put_Default"),
    (lambda raw: re.subn(r"(PriorImageStep::unreadable_image\) \{(?:\s*//[^\n]*)*\s*)\+\+tally\.policy_restore_failed;", r"\1", raw, count=1),
     "unreadable_image"),
]


class FirewallReleaseGuardWiringLexical(unittest.TestCase):
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
