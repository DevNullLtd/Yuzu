#!/usr/bin/env python3
"""#7520 / #7519 wiring pins for the DEX Apps page (lexical, no build required).

Two properties the C++ unit tests cannot see, because each is a property of which source line
hands what to whom, not of behaviour:

  1. THE PAGE HAS ITS API. server.cpp must call `dex_routes_->set_dex_api(<x>)` with the very
     object `make_local_dex_api` returned. Without that call the Apps tab answers its not_wired
     panel on a healthy server, and every route-level test still passes because each builds its
     own DexRoutes and wires its own double.
  2. THE API HAS ITS OBSERVER SOURCE. The `make_local_dex_api` call in that block must pass an
     observer provider that reads `health_store_.dex_observer_for`. Without it the live observer
     split never appears (`observer_state` stays null) and every unit test still passes, since
     they inject their own provider. The destruction order that makes the provider safe
     (health_store_ declared before every DexApi holder) is pinned by
     test_guardian_backend_wiring_lexical.py.

`//` and block comments are stripped before matching, so prose cannot satisfy a check. The
self-test applies in-memory mutations and requires problems() to report each one.

WHAT THIS DOES NOT PROVE (a lexical gate is not a C++ lexer): that the lambda returns what the
accessor returns, or that the call sits on the path the server takes at boot; only that the two
lines exist and name each other.

Usage: python3 tests/test_dex_apps_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_guardian_backend_wiring_lexical import call_args, strip_comments  # noqa: E402

SERVER = HERE.parent / "server" / "core" / "src" / "server.cpp"


def problems(server_text: str) -> list:
    code = strip_comments(server_text)
    found = []
    makes = list(re.finditer(r"(\w+)\s*=\s*make_local_dex_api\s*\(", code))
    if len(makes) != 1:
        return [f"server.cpp: expected exactly one `<x> = make_local_dex_api(` assignment, found {len(makes)}"]
    var = makes[0].group(1)
    args = next(call_args(code[makes[0].start():], "make_local_dex_api("), "")
    if "health_store_.dex_observer_for" not in args:
        found.append("server.cpp: the make_local_dex_api call does not pass an observer provider that "
                     "reads health_store_.dex_observer_for (the Apps page would never show the live split)")
    sets = [a.strip() for a in call_args(code, "dex_routes_->set_dex_api(")]
    if not sets:
        found.append("server.cpp: no call to dex_routes_->set_dex_api( (the Apps tab would answer not_wired)")
    elif any(a != var for a in sets):
        found.append(f"server.cpp: dex_routes_->set_dex_api( is not handed `{var}`, the object "
                     "make_local_dex_api returned")
    return found


class DexAppsWiring(unittest.TestCase):
    def test_tree_is_clean(self):
        self.assertEqual(problems(SERVER.read_text(encoding="utf-8")), [])

    def test_selftest_mutations_are_reported(self):
        base = SERVER.read_text(encoding="utf-8")

        def mutated(old, new):
            self.assertEqual(base.count(old), 1, f"mutation anchor missing or ambiguous: {old!r}")
            return base.replace(old, new, 1)

        cases = {
            "set_dex_api call removed": mutated("dex_routes_->set_dex_api(dex_api);", ""),
            "set_dex_api handed another object": mutated("dex_routes_->set_dex_api(dex_api);",
                                                         "dex_routes_->set_dex_api(nullptr);"),
            "observer provider removed": mutated("health_store_.dex_observer_for(",
                                                 "health_store_.something_else("),
        }
        for label, text in cases.items():
            self.assertTrue(problems(text), f"mutation not reported: {label}")
        # A mention in a comment must not satisfy a pin.
        commented = mutated("dex_routes_->set_dex_api(dex_api);", "// dex_routes_->set_dex_api(dex_api);")
        self.assertTrue(problems(commented), "a commented-out call satisfied the pin")


if __name__ == "__main__":
    unittest.main()
