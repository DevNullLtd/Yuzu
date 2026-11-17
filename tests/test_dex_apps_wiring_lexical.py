#!/usr/bin/env python3
"""#7520 / #7519 wiring pins for the DEX Apps page (lexical, no build required).

Three properties the C++ unit tests cannot see, because each is a property of which source line
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
  3. THE STATEMENT-TIMEOUT SERIES EXISTS AT ZERO. The Apps read counts
     `yuzu_server_guardian_read_degrade_total{reason="statement_timeout",source="guardian_state"}`;
     server.cpp must create that series at boot, or the first timeout appears as a series that
     did not exist a scrape ago and `rate()` cannot see it. The store tests count through their own
     registry, so only this pin sees the boot-time seed go missing.
  4. THE FLEET USAGE ROUTE HAS ITS READ. The `make_local_dex_api` call must be handed the usage
     wiring (`dex_usage`), and that wiring's `read` must capture `dex_app_usage_owner_`. Without
     it GET /api/v1/dex/apps/usage answers a not_wired refusal on a healthy server while every
     route test still passes, since each builds its own wiring. Its four degrade reasons must be
     pre-seeded at zero on source `dex_usage`, for the same reason as property 3.

`//` and block comments are stripped before matching, so prose cannot satisfy a check. The
self-test applies in-memory mutations and requires problems() to report each one.

WHAT THIS DOES NOT PROVE (a lexical gate is not a C++ lexer): that the lambda returns what the
accessor returns, or that a call sits on the path the server takes at boot; only that the lines
exist and name each other.

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
    if not any('"yuzu_server_guardian_read_degrade_total"' in a and '"statement_timeout"' in a
               and '"guardian_state"' in a for a in call_args(code, "metrics_.counter(")):
        found.append("server.cpp: no metrics_.counter( pre-seed of yuzu_server_guardian_read_degrade_total "
                     "with reason statement_timeout and source guardian_state (the first Apps statement "
                     "timeout would be invisible to rate())")
    if not re.search(r"std::move\(\s*dex_usage\s*\)\s*$", args.strip()):
        found.append("server.cpp: the make_local_dex_api call is not handed the usage wiring "
                     "(`std::move(dex_usage)` as its last argument): GET /api/v1/dex/apps/usage would "
                     "answer not_wired")
    if not re.search(r"\bdex_usage\.read\s*=\s*\[[^\]]*\bdex_app_usage_owner_\b", code):
        found.append("server.cpp: dex_usage.read does not capture dex_app_usage_owner_ (the usage "
                     "route would read from nothing)")
    seed = next((m for m in re.finditer(r"for\s*\(\s*const\s+auto\s+reason\s*:\s*\{([^}]*)\}\s*\)\s*"
                                        r"metrics_\.counter\(([^;]*)\);", code)
                 if '"dex_usage"' in m.group(2)), None)
    reasons = set(re.findall(r'"([a-z_]+)"', seed.group(1))) if seed else set()
    if (not seed or '"yuzu_server_guardian_read_degrade_total"' not in seed.group(2)
            or '"dex_usage"' not in seed.group(2)
            or reasons != {"pool_acquire_timeout", "query_error", "statement_timeout",
                           "concurrency_budget"}):
        found.append("server.cpp: the four dex_usage degrade reasons (pool_acquire_timeout, query_error, "
                     "statement_timeout, concurrency_budget) are not pre-seeded on "
                     "yuzu_server_guardian_read_degrade_total with source dex_usage")
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
            "statement_timeout pre-seed removed": mutated(
                '{{"reason", "statement_timeout"}, {"source", "guardian_state"}}',
                '{{"reason", "statement_timeout"}, {"source", "guardian_census_device"}}'),
            "usage wiring not handed to the factory": mutated("                std::move(dex_usage));",
                                                              "                {});"),
            "usage read no longer captures the owner": mutated(
                "dex_usage.read = [owner = dex_app_usage_owner_.get()]",
                "dex_usage.read = [owner = static_cast<DexAppUsageOwner*>(nullptr)]"),
            "a dex_usage degrade reason not pre-seeded": mutated(
                '"statement_timeout",\n                                  "concurrency_budget"})',
                '"statement_timeout"})'),
            "dex_usage pre-seed on the wrong source": mutated(
                '{{"reason", reason}, {"source", "dex_usage"}}', '{{"reason", reason}, {"source", "guardian_state"}}'),
        }
        for label, text in cases.items():
            self.assertTrue(problems(text), f"mutation not reported: {label}")
        # A mention in a comment must not satisfy a pin.
        commented = mutated("dex_routes_->set_dex_api(dex_api);", "// dex_routes_->set_dex_api(dex_api);")
        self.assertTrue(problems(commented), "a commented-out call satisfied the pin")


if __name__ == "__main__":
    unittest.main()
