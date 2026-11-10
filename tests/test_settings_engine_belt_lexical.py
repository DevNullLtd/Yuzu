#!/usr/bin/env python3
"""Static lexical gate over server/core/src/settings_routes.cpp: the engine-session belt (#6744).

The unit tests prove the belt refuses an engine session, but they need Postgres, and a rebase that
silently drops a call site (the handlers are edited by neighbouring work) or re-inlines a second
copy is invisible without it. This gate pins the source shape:

  1. `Session::is_engine()` is called exactly ONCE in the file: inside
     `SettingsRoutes::refuse_engine_session`. A second call is a forked copy of the belt.
  2. Each of the three fragments below calls `refuse_engine_session(` with its audit verb, ACTS on
     its result (`if (refuse_engine_session(...)) return;`), and in this order: permission gate,
     then `auth_fn_`, then the belt, then the render/`set_content`.
       /fragments/settings/engine-principals       verb engine_principal.list
       /fragments/settings/access-reviews          verb access_review.list
       /fragments/settings/access-reviews/campaign verb access_review.get
  3. The literal `engine_session_denied` appears only in the helper.
  4. The two access-reviews fragments call `no_store_private(res)` AFTER the belt and before the
     render (#6940): a cached copy of the grant evidence is the leak, and a call before the belt
     would stamp the headers on a refusal that already sets its own `no-store`.
  5. `valid_campaign_id(` is called ONCE in the file (the campaign renderer's single validator,
     #7315): a second call is a duplicate validator, for example from a stale port of an older
     change.

Source-text only, no build. Carries its own mutation self-test.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS_CPP = ROOT / "server" / "core" / "src" / "settings_routes.cpp"
TAG = "test_settings_engine_belt_lexical"
HINT = (" (this gate pins the engine-session belt of the Settings fragments, #6744; if"
        " settings_routes.cpp was legitimately restructured, update"
        " tests/test_settings_engine_belt_lexical.py)")

# (route literal, permission-gate token, verb)
FRAGMENTS = [
    ("/fragments/settings/engine-principals", "read_perm(", "engine_principal.list"),
    ("/fragments/settings/access-reviews", "perm_fn_(", "access_review.list"),
    ("/fragments/settings/access-reviews/campaign", "perm_fn_(", "access_review.get"),
]
HELPER_DEF = "bool SettingsRoutes::refuse_engine_session("
# The belt must be the condition of an `if` whose body is `return;`: a dropped `return;` or a
# `false && refuse_engine_session(...)` leaves the call present but its verdict ignored.
ACTED_ON = re.compile(r"if\s*\(\s*refuse_engine_session\([^()]*\)\s*\)\s*return\s*;")
ROUTE_START = re.compile(r"\bsink\.(?:Get|Post|Put|Delete|Patch)\(")


def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def helper_span(t):
    at = t.find(HELPER_DEF)
    if at < 0:
        return None
    brace = t.index("{", t.index(")", at))
    depth = 0
    for i in range(brace, len(t)):
        depth += (t[i] == "{") - (t[i] == "}")
        if depth == 0:
            return at, i + 1
    return None


def handler_text(t, route):
    m = re.search(r'sink\.Get\(\s*"' + re.escape(route) + r'"\s*,', t)
    if not m:
        return None
    nxt = ROUTE_START.search(t, m.end())
    return t[m.start(): nxt.start() if nxt else len(t)]


def problems(raw):
    t = strip_comments(raw)
    out = []
    span = helper_span(t)
    if span is None:
        return ["refuse_engine_session is no longer defined in settings_routes.cpp"]
    inside = t[span[0]:span[1]]
    outside = t[:span[0]] + t[span[1]:]
    if len(re.findall(r"\bis_engine\(\)", inside)) != 1:
        out.append("the helper must call Session::is_engine() exactly once")
    if re.search(r"\bis_engine\(\)", outside):
        out.append("is_engine() is called outside refuse_engine_session: a forked copy of the belt")
    if "engine_session_denied" in outside:
        out.append("engine_session_denied appears outside refuse_engine_session: a forked copy")
    if t.count("valid_campaign_id(") > 1:
        out.append("valid_campaign_id( is called more than once: the campaign renderer has one "
                   "validator call (#7315)")
    for route, perm, verb in FRAGMENTS:
        h = handler_text(t, route)
        if h is None:
            out.append(f"{route}: handler not found")
            continue
        i_perm = h.find(perm)
        i_auth = h.find("auth_fn_(")
        i_belt = h.find("refuse_engine_session(")
        i_render = min([i for i in (h.find("render_"), h.find("set_content(")) if i >= 0],
                       default=-1)
        if min(i_perm, i_auth, i_belt) < 0:
            out.append(f"{route}: needs {perm}, auth_fn_( and refuse_engine_session( in its handler")
            continue
        if not (i_perm < i_auth < i_belt):
            out.append(f"{route}: order must be permission gate, auth_fn_, refuse_engine_session")
        if i_render >= 0 and not i_belt < i_render:
            out.append(f"{route}: refuse_engine_session must run before any render/set_content")
        if route != "/fragments/settings/engine-principals":
            i_nostore = h.find("no_store_private(res)")
            if i_nostore < 0:
                out.append(f"{route}: needs no_store_private(res) after the belt (#6940)")
            elif not i_belt < i_nostore:
                out.append(f"{route}: no_store_private(res) must come after the belt (#6940)")
            elif i_render >= 0 and not i_nostore < i_render:
                out.append(f"{route}: no_store_private(res) must come before the render (#6940)")
        if not ACTED_ON.search(h):
            out.append(f"{route}: the belt's result must be acted on: "
                       "if (refuse_engine_session(...)) return;")
        if f'"{verb}"' not in h[i_belt:i_belt + 400]:
            out.append(f"{route}: the belt must be called with the verb {verb}")
    return out


# (pattern, replacement, expected substring of problems()[0]); each applied once to the real source.
MUTATIONS = [
    # drop the belt from the main access-reviews fragment
    (r'if \(refuse_engine_session\(req, res, \*session, "access_review\.list",\s*"AccessReview"\)\)\s*return;',
     "", "access-reviews: needs"),
    # drop it from the campaign fragment
    (r'if \(refuse_engine_session\(req, res, \*session, "access_review\.get",\s*"AccessReview"\)\)\s*return;',
     "", "campaign: needs"),
    # wrong verb on the engine-principals fragment
    (r'"engine_principal\.list",\s*"EnginePrincipal", "", /\*also_mcp_tier=\*/true',
     '"engine_principal.lisp", "EnginePrincipal", "", /*also_mcp_tier=*/true',
     "the belt must be called with the verb engine_principal.list"),
    # the verdict ignored: the `return;` dropped
    (r'(if \(refuse_engine_session\(req, res, \*session, "access_review\.list",\s*"AccessReview"\)\))\s*return;',
     r"\1 {}", "the belt's result must be acted on"),
    # the verdict short-circuited away
    (r'if \(refuse_engine_session\(req, res, \*session, "access_review\.get",',
     'if (false && refuse_engine_session(req, res, *session, "access_review.get",',
     "the belt's result must be acted on"),
    # the verdict discarded with a void cast
    (r'if \(refuse_engine_session\(req, res, \*session, "access_review\.get",\s*"AccessReview"\)\)\s*return;',
     '(void)refuse_engine_session(req, res, *session, "access_review.get", "AccessReview");',
     "the belt's result must be acted on"),
    # the session check removed from the main fragment (the belt would run without a session)
    (r'auto session = auth_fn_\(req, res\);\s*if \(!session\)\s*return;\s*// #6744: as every /api/v1/access-reviews twin',
     '// #6744: as every /api/v1/access-reviews twin',
     "needs"),
    # #6940: the campaign fragment's no_store_private dropped
    (r'(access_review\.get",\s*"AccessReview"\)\)\s*return;\s*)no_store_private\(res\);[^\n]*\n',
     r'\1', "campaign: needs no_store_private(res)"),
    # #6940: no_store_private moved ahead of the belt on the main fragment
    (r'(auto session = auth_fn_\(req, res\);\s*if \(!session\)\s*return;\s*)(// #6744: as every /api/v1/access-reviews twin)',
     r'\1no_store_private(res);\n                 \2', "no_store_private(res) must come after the belt"),
    # #7315: a second validator call (a stale port of an older change)
    (r'if \(!valid_campaign_id\(campaign_id\)\) \{',
     'if (!valid_campaign_id(campaign_id) || !valid_campaign_id(campaign_id)) {',
     "valid_campaign_id( is called more than once"),
    # a second inline copy of the belt
    (r"(bool SettingsRoutes::refuse_cross_site\()",
     "static bool inline_copy(const auth::Session& s) { return s.is_engine(); }\n\\1",
     "is_engine() is called outside"),
]


class SettingsEngineBelt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = SETTINGS_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = re.subn(pat, repl, self.raw, count=1)
                self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"{expected!r} not in {p}")


if __name__ == "__main__":
    unittest.main()
