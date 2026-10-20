#!/usr/bin/env python3
"""#5047 static lexical gate over server/core/src/server.cpp's two TierPolicyFn wiring sites, plus
(clause 4, #6065 PR-Q) the one-definition-two-uses wiring of the dispatch authorizer closure.

AuthRoutes::gateless_tier_policy_fn() (auth_routes.hpp) is the SOLE production factory for a
gate-less-route TierPolicyFn -- both server.cpp sites' own comments say so explicitly: "never
re-inline this as a local lambda; a second copy is exactly how the original clause-5 violation
this belt exists to prevent could recur unreviewed at a 9th call site."

The unit test in test_auth_routes.cpp ("gateless_tier_policy_fn -- the REAL production
TierPolicyFn...") drives the factory directly and proves its OUTPUT is correct, but it cannot
observe whether server.cpp actually calls the factory -- a reverted call site (back to a
hand-rolled lambda naming .permission, reopening the clause-5 gap) or a new undocumented third
call site would pass every existing test. This gate closes that:

  1. `result_set::Deps`'s designated-init field (the dashboard-fragment wiring,
     /fragments/result-sets/*) reads `.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),`
     -- exactly once, as an ACTIVE line (anchored start-of-line, not merely a substring -- a
     commented-out copy of this exact text does not count; #5047 governance re-review finding,
     independently converged by two reviewers).
  2. `rest_api_v1_->register_routes(...)`'s positional tier-policy argument (the REST
     /api/v1/result-sets JSON wiring) is `auth_routes_->gateless_tier_policy_fn(),` -- exactly
     once, same anchored-active-line requirement. It is no longer the FINAL argument: #6065 PR-Q
     appends `authorize_dispatch` after it, so the line ends in a comma, not `);`. The only other
     active line of this shape is clause 1's, which carries the `.tier_policy_fn = ` prefix and
     so cannot satisfy this anchored pattern.
  3. The literal substring `auth_routes_->gateless_tier_policy_fn()` appears in server.cpp
     EXACTLY TWICE, total -- DELIBERATELY a broad, unanchored substring count (not just the sum
     of clauses 1+2): it exists to catch a brand-new third call site written in some OTHER shape
     neither clause 1 nor 2 would recognise. The trade-off: an unrelated comment that happens to
     quote the literal string would also trip this clause -- a false RED, never a false GREEN.

  4. (#6065 PR-Q) The dispatch-chokepoint pre-check closure is defined ONCE in server.cpp
     (`const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch =`) and used EXACTLY twice,
     both as ACTIVE lines: as REST's trailing `register_routes` argument (`authorize_dispatch);`)
     and in `set_authorize_dispatch_fn(authorize_dispatch)`. The REST parameter is defaulted so
     that unrelated callers still compile, which means dropping the trailing argument compiles
     cleanly and every POST and DELETE /api/v1/quarantine then answers 500 -- and no unit test, whose rig
     wires its own closure, can see it. A second definition (a route-local copy) is the drift the
     closure exists to prevent. Same anchored-active-line requirement as clauses 1 and 2.

Static/text-only, no build required -- a lexical gate, not a semantic one: it cannot see a
relocation that keeps the same tokens but changes the surrounding control flow, nor a `#if 0` /
`/* */` block that comments out an entire real site while preserving its exact leading
whitespace and text -- both stay review-enforced concerns clauses 1/2's anchoring cannot reach.

Known limitation (NICE, not fixed): clause 3 only catches a new call that reuses the
gateless_tier_policy_fn() literal. A wholly new gate-less route wired with its OWN fresh inline
lambda -- one that never references gateless_tier_policy_fn() at all -- is invisible to this
gate; that class of regression stays a plain-review concern.

Lines are counted per line: split on "\\n", one count per line, never str.count. The file
is read with universal newlines, so a CRLF checkout is matched the same as LF (all sources are
LF today). A missing source now raises in setUp instead of a `::error::` line.

Usage: python3 tests/test_tier_policy_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
TAG = "test_tier_policy_wiring_lexical"
CALL = "auth_routes_->gateless_tier_policy_fn()"
DESIGNATED = r"[ \t\r\f\v]*\.tier_policy_fn = auth_routes_->gateless_tier_policy_fn\(\),"
POSITIONAL = r"[ \t\r\f\v]*auth_routes_->gateless_tier_policy_fn\(\),"
CLOSURE_DEF = r"[ \t\r\f\v]*const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch =.*"
CLOSURE_REST = r"[ \t\r\f\v]*authorize_dispatch\);"
CLOSURE_MCP = r"[ \t\r\f\v]*mcp_server_->set_authorize_dispatch_fn\(authorize_dispatch\);"


def problems(src):
    """One message per violated clause, in clause order (1, 2, 3); [] when clean."""
    lines = src.split("\n")
    total = sum(1 for ln in lines if CALL in ln)
    designated = sum(1 for ln in lines if re.fullmatch(DESIGNATED, ln))
    positional = sum(1 for ln in lines if re.fullmatch(POSITIONAL, ln))
    closure_def = sum(1 for ln in lines if re.fullmatch(CLOSURE_DEF, ln))
    closure_rest = sum(1 for ln in lines if re.fullmatch(CLOSURE_REST, ln))
    closure_mcp = sum(1 for ln in lines if re.fullmatch(CLOSURE_MCP, ln))
    out = []
    if designated != 1:
        out.append("expected exactly 1 designated-init site ('.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),' "
                   f"-- the dashboard-fragment result_set::Deps wiring), found {designated}. A reversion to a "
                   "hand-rolled lambda here reopens the #5047 clause-5 gap on /fragments/result-sets/*.")
    if positional != 1:
        out.append("expected exactly 1 positional-arg site ('auth_routes_->gateless_tier_policy_fn(),' -- the REST "
                   f"rest_api_v1_->register_routes(...) wiring), found {positional}. A reversion to a hand-rolled "
                   "lambda here reopens the #5047 clause-5 gap on /api/v1/result-sets.")
    if total != 2:
        out.append("expected the literal 'auth_routes_->gateless_tier_policy_fn()' to appear EXACTLY TWICE in "
                   f"server.cpp (the two known call sites), found {total}. A count above 2 means an undocumented "
                   "new call site was added outside this gate's knowledge -- extend this script in the same change, "
                   "per gateless_tier_policy_fn()'s own doc comment (auth_routes.hpp: 'both server.cpp wiring "
                   "sites call this SAME function').")
    if (closure_def, closure_rest, closure_mcp) != (1, 1, 1):
        out.append("expected the dispatch authorizer closure to be defined exactly once "
                   "('const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch =') and used exactly once as "
                   "REST's trailing register_routes argument ('authorize_dispatch);') and once as "
                   "'mcp_server_->set_authorize_dispatch_fn(authorize_dispatch);'; found "
                   f"definition={closure_def}, rest-arg={closure_rest}, mcp-wiring={closure_mcp}. A dropped "
                   "REST argument compiles (the parameter is defaulted) and makes POST and DELETE /api/v1/quarantine "
                   "answer 500; a second definition is a route-local copy that can drift from MCP's.")
    return out


DESIGNATED_LINE = "                            .tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),\n"
POSITIONAL_LINE = "            auth_routes_->gateless_tier_policy_fn(),\n"
CLOSURE_REST_LINE = "            authorize_dispatch);\n"
CLOSURE_MCP_LINE = "            mcp_server_->set_authorize_dispatch_fn(authorize_dispatch);\n"
LAMBDA = "[](const auto&) { return TierPolicy{}; }"


class TierPolicyWiringLexical(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.src)
        for m in p:
            print(f"\n::error::{TAG}: {m}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        src = self.src
        for a in (DESIGNATED_LINE, POSITIONAL_LINE, CLOSURE_REST_LINE, CLOSURE_MCP_LINE):
            n = src.count(a)
            self.assertEqual(n, 1, f"mutation anchor must match exactly once, found {n}; update the constant: {a!r}")
        # (name, mutated source, the clause fragments that must appear; len(p) pins that no other clause fires)
        cases = [
            ("T1 designated reverted to a lambda",
             src.replace(DESIGNATED_LINE, DESIGNATED_LINE.replace(CALL, LAMBDA), 1),
             ["designated-init", "EXACTLY TWICE"]),
            ("T2 designated line commented out (anchoring proof: clause 1 only)",
             src.replace(DESIGNATED_LINE, "// " + DESIGNATED_LINE, 1),
             ["designated-init"]),
            ("T3 positional reverted to a lambda",
             src.replace(POSITIONAL_LINE, POSITIONAL_LINE.replace(CALL, LAMBDA), 1),
             ["positional-arg", "EXACTLY TWICE"]),
            ("T4 third call appended (clause 3 only)",
             src + "    auth_routes_->gateless_tier_policy_fn();\n",
             ["EXACTLY TWICE"]),
            ("T5 REST trailing authorize_dispatch argument dropped (compiles: the param is defaulted)",
             src.replace(CLOSURE_REST_LINE, "            );\n", 1),
             ["authorizer closure"]),
            ("T6 MCP wiring dropped",
             src.replace(CLOSURE_MCP_LINE, "", 1),
             ["authorizer closure"]),
            ("T7 a route-local second definition appended",
             src + "    const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch = {};\n",
             ["authorizer closure"]),
        ]
        for name, mutated, present in cases:
            with self.subTest(mutation=name):
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                joined = "\n".join(p)
                for frag in present:
                    self.assertIn(frag, joined)
                self.assertEqual(len(p), len(present))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
