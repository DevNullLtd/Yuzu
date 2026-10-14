#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's Access reviews registration block.

The route tests stub every dependency, so a permissive gate or a swapped data source in
server.cpp would leave them all green. This gate pins the production wiring of
access_reviews::register_access_reviews_routes( ... ):

  1. `.perm_fn`/`.audit_fn` are the server's; `.probe_perm_fn` runs the loud `perm_fn` on a
     scratch Response (never a constant, never a gate that writes the real response).
  2. The campaign reads fail closed on a missing or closed store.
  3. `.grants_fn` reads the grant TABLE through build_access_review (not a roster walk, so orphan
     grants are kept) and stamps access_review_rbac_enforcement.

Same method as test_access_audit_wiring_lexical.py (comments stripped, whitespace collapsed,
in-memory mutations prove each pattern is live). Lexical only.

Usage: python3 tests/test_access_reviews_wiring_lexical.py
"""
import re
import sys
import unittest

from test_access_audit_wiring_lexical import SERVER_CPP, block

TAG = "test_access_reviews_wiring_lexical"
HINT = (" (this gate pins the Access reviews production wiring; if server.cpp was legitimately"
        " restructured, update tests/test_access_reviews_wiring_lexical.py)")


def problems(src):
    b = block(src, "access_reviews::register_access_reviews_routes(")
    if b is None:
        return ["server.cpp no longer calls access_reviews::register_access_reviews_routes( (or its parens are unbalanced)"]
    out = []
    if ".perm_fn = perm_fn," not in b:
        out.append("reviews .perm_fn is no longer the server's loud perm_fn")
    if ".audit_fn = audit_fn," not in b:
        out.append("reviews .audit_fn is no longer the server's audit_fn")
    pf = re.search(r"\.probe_perm_fn = (.*?), \.audit_fn", b)
    if not pf or "httplib::Response scratch; return perm_fn(req, scratch, type, op);" not in pf.group(1):
        out.append("reviews .probe_perm_fn is no longer the loud perm_fn on a scratch Response")
    for name, call in ((".list_campaigns_fn", "access_review_store_->list_campaigns()"),
                       (".get_campaign_fn", "access_review_store_->get_campaign(id)")):
        m = re.search(re.escape(name) + r" = (.*?)(?=, \.(?:get_campaign_fn|grants_fn)|$)", b)
        body = m.group(1) if m else ""
        if not m:
            out.append(f"reviews {name} is no longer bound")
        else:
            if not re.search(r"if \(!access_review_store_ \|\| !access_review_store_->is_open\(\)\) return std::unexpected\(", body):
                out.append(f"reviews {name} no longer fails closed for a missing or closed store")
            if call not in body:
                out.append(f"reviews {name} no longer reads {call}")
    g = re.search(r"\.grants_fn = (.*)$", b)
    gbody = g.group(1) if g else ""
    if not g:
        out.append("reviews .grants_fn is no longer bound")
    else:
        if "build_access_review(" not in gbody:
            out.append("reviews .grants_fn no longer reads build_access_review")
        if "access_review_rbac_enforcement(rbac_store_.get())" not in gbody:
            out.append("reviews .grants_fn no longer stamps access_review_rbac_enforcement")
        if "if (!rows) return std::unexpected(rows.error());" not in gbody:
            out.append("reviews .grants_fn no longer maps a read failure to std::unexpected")
    if re.search(r"\.probe_perm_fn = \[[^\]]*\]\([^)]*\) -> bool \{ return (true|false)", b):
        out.append("reviews .probe_perm_fn returns a constant")
    return out


# (pattern, replacement, expected substring of a problem)
MUTATIONS = [
    (r"httplib::Response scratch;\s*return perm_fn\(req, scratch, type, op\);", "return true;",
     "probe_perm_fn"),
    (r"if \(!access_review_store_ \|\| !access_review_store_->is_open\(\)\)\s*return std::unexpected\(std::string\(\"access review store not open\"\)\);\s*return access_review_store_->list_campaigns\(\);",
     "return access_review_store_->list_campaigns();", "list_campaigns_fn"),
    (r"build_access_review\(auth_mgr_", "build_roster(auth_mgr_", "build_access_review"),
    (r"access_reviews::register_access_reviews_routes\(", "access_reviews::register_access_reviews_route(",
     "register_access_reviews_routes"),
]


class ReviewsWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = SERVER_CPP.read_text(encoding="utf-8")

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
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
