#!/usr/bin/env python3
"""Static lexical gate over the Windows callers of the checked HKEY_USERS listing.

`yuzu::win::enumerate_hku_subkeys_checked()` answers a failed or unstable listing with an `error`
and no names (agents/shared/win_profiles.hpp; the decision is unit-tested in
test_value_enumeration.cpp). Refusing on that error is each caller's job, and the callers are
Windows-only shells the unit suites cannot run, so the refusal is pinned here on source text. The
Echo start-up sweep is pinned by test_echo_mapdrive_pin_lexical.py. For each caller file below:

  1. The number of `enumerate_hku_subkeys_checked()` calls is the expected one, so a NEW call must
     be listed here (a new file that calls it is found by a scan of agents/).
  2. After each call, `hku.error.empty()` appears before the first `hku.names`: the names are never
     read before the listing is known to be complete.
  3. The failure token `hku_list_incomplete` appears after each call, before the next call.
  4. Polarity: a refusal-first caller (`!hku.error.empty()`) reports the token before it reads
     the names; a success-first caller (`hku.error.empty()`) reads the names before the token,
     which then belongs to its else arm. A flipped condition breaks one of the two orders.
  5. Terminal outcome: a refusal-first caller in RETURNS leaves the function (`return`) between
     the check and the first read of the names.

Robustness: `//` and `/* */` comments are blanked (string and character literals are kept) and
whitespace is collapsed, so a commented-out check cannot satisfy a pin. Lexical only: it cannot
see a relocation that keeps the tokens but changes control flow (review-enforced). The self-test
applies in-memory mutations and requires problems() to be non-empty on each; a mutation whose
pattern no longer matches the source fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 tests/test_hku_listing_pin_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CALL = "enumerate_hku_subkeys_checked()"
TOKEN = "hku_list_incomplete"
CHECK = "hku.error.empty()"
EXPECTED = {  # file -> number of calls
    "agents/plugins/registry/src/registry_win.cpp": 2,
    "agents/plugins/installed_apps/src/installed_apps_plugin.cpp": 1,
    "agents/plugins/license_scan/src/licensing_win.cpp": 1,
    "agents/plugins/autoruns/src/autoruns_win.cpp": 1,
    "agents/plugins/privacy_permissions/src/privacy_permissions_win.cpp": 1,
    "agents/plugins/echo/src/echo_mapdrive_collector.cpp": 1,
}
RETURNS = {  # callers whose refusal arm ends the function before the names are read
    "agents/plugins/registry/src/registry_win.cpp",
    "agents/plugins/installed_apps/src/installed_apps_plugin.cpp",
    "agents/plugins/license_scan/src/licensing_win.cpp",
    "agents/plugins/echo/src/echo_mapdrive_collector.cpp",
}
ELSEWHERE = {  # the definition, and the sweep (test_echo_mapdrive_pin_lexical.py)
    "agents/shared/win_profiles.hpp",
    "agents/plugins/echo/src/echo_registry_source.cpp",
}
HINT = (" (this gate pins the HKEY_USERS listing callers; if a caller was legitimately"
        " restructured, update tests/test_hku_listing_pin_lexical.py)")

_BLANK = re.compile(r'"(?:\\.|[^"\\])*"|' + r"'(?:\\.|[^'\\])'" + r"|//[^\n]*|/\*.*?\*/", re.S)


def normalise(src):
    """Blank // and /* */ comments (literals kept), then collapse whitespace."""
    kept = _BLANK.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", src)
    return re.sub(r"\s+", " ", kept)


def problems(rel, src):
    t = normalise(src)
    starts = [m.start() for m in re.finditer(re.escape(CALL), t)]
    out = []
    if len(starts) != EXPECTED[rel]:
        out.append(f"{rel}: expected {EXPECTED[rel]} {CALL} call(s), found {len(starts)}")
    for i, s in enumerate(starts, 1):
        window = t[s + len(CALL):(starts[i] if i < len(starts) else len(t))]
        err, names = window.find(CHECK), window.find("hku.names")
        if err < 0 or 0 <= names < err:
            out.append(f"{rel}: call {i} must test {CHECK} before it reads hku.names")
        if TOKEN not in window:
            out.append(f"{rel}: call {i} must report {TOKEN} on a failed listing")
            continue
        tok = window.find(TOKEN)
        if err < 0 or names < 0:
            continue
        negated = err > 0 and window[err - 1] == "!"
        if negated and tok > names:
            out.append(f"{rel}: call {i} must report {TOKEN} before it reads hku.names")
        if not negated and tok < names:
            out.append(f"{rel}: call {i} tests {CHECK} first, so it must read hku.names before"
                       f" the {TOKEN} arm")
        if negated and rel in RETURNS and "return" not in window[err:names]:
            out.append(f"{rel}: call {i} must return before it reads hku.names on a failed listing")
    return out


def unlisted_callers():
    found = []
    for p in (ROOT / "agents").rglob("*"):
        rel = p.relative_to(ROOT).as_posix()
        if p.suffix in (".cpp", ".hpp", ".h") and rel not in EXPECTED and rel not in ELSEWHERE:
            if CALL in normalise(p.read_text(encoding="utf-8", errors="replace")):
                found.append(rel)
    return found


def mutate(src, old, new, which="all"):
    """Replace the first, last or every `old`; a pattern that no longer matches fails loudly."""
    assert old in src, f"stale mutation pattern: {old!r}"
    if which == "all":
        return src.replace(old, new)
    i = src.index(old) if which == "first" else src.rindex(old)
    return src[:i] + new + src[i + len(old):]


class HkuListingPin(unittest.TestCase):
    def test_sources_are_pinned(self):
        for rel in EXPECTED:
            with self.subTest(file=rel):
                self.assertEqual(problems(rel, (ROOT / rel).read_text(encoding="utf-8")), [], HINT)

    def test_every_caller_is_listed(self):
        self.assertEqual(unlisted_callers(), [], "a file calls " + CALL + " and is not pinned" + HINT)

    def test_mutations_are_caught(self):
        for rel, calls in EXPECTED.items():
            src = (ROOT / rel).read_text(encoding="utf-8")
            cases = {
                "check removed": mutate(src, CHECK, "true"),
                "token dropped": mutate(src, TOKEN, "hku_list_ok"),
                "extra call": src + f"\nvoid extra() {{ (void)yuzu::win::{CALL}; }}\n",
                "names read before the check": mutate(src, CALL + ";", CALL + "; (void)hku.names;",
                                                      "first"),
            }
            neg = "!" + CHECK
            cases["polarity flipped"] = (mutate(src, neg, CHECK) if neg in src
                                         else mutate(src, CHECK, neg))
            if rel in RETURNS:
                i = src.index(CALL)
                cases["refusal does not return"] = (src[:i]
                                                    + mutate(src[i:], "return", "(void)0", "first"))
            if calls > 1:  # one call alone loses its check (or its token)
                cases["first call's check removed"] = mutate(src, CHECK, "true", "first")
                cases["last call's check removed"] = mutate(src, CHECK, "true", "last")
                cases["last call's token dropped"] = mutate(src, TOKEN, "hku_list_ok", "last")
            for name, mutated in cases.items():
                with self.subTest(file=rel, mutation=name):
                    self.assertNotEqual(problems(rel, mutated), [], f"mutation not caught: {name}")


if __name__ == "__main__":
    unittest.main()
