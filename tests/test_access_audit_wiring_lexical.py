#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's Audit and reviews registration blocks.

The route tests stub every dependency, so a permissive gate or a swapped data source in
server.cpp would leave them all green. This gate pins the production wiring of
access_audit::register_access_audit_routes( ... ):

  1. `.perm_fn` is the server's loud `perm_fn`, `.quiet_perm_fn` its `draw_perm_fn` probe (never a lambda returning a constant) and
     `.audit_fn` is the server's `audit_fn`.
  2. `.query_fn` returns std::nullopt for a missing or closed audit store and otherwise returns
     `audit_store_->query(q, pool_size)`; it never returns a literal empty vector.
  3. `.retention_days_fn` reads cfg_.audit_retention_days.

`//` comments are stripped and whitespace collapsed before matching. Lexical only: it cannot see
a relocation that keeps the tokens (review-enforced). The self-test applies in-memory mutations
and fails loudly if a pattern goes stale.

Usage: python3 tests/test_access_audit_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
TAG = "test_access_audit_wiring_lexical"
HINT = (" (this gate pins the Audit and reviews production wiring; if server.cpp was legitimately"
        " restructured, update tests/test_access_audit_wiring_lexical.py)")


def normalise(src):
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def block(src, opener):
    """The balanced-paren text of the `opener(` call, or None."""
    t = normalise(src)
    at = t.find(opener)
    if at < 0:
        return None
    start = t.index("(", at)
    depth = 0
    for i in range(start, len(t)):
        depth += (t[i] == "(") - (t[i] == ")")
        if depth == 0:
            return t[start:i + 1]
    return None


def audit_problems(src):
    b = block(src, "access_audit::register_access_audit_routes(")
    if b is None:
        return ["server.cpp no longer calls access_audit::register_access_audit_routes( (or its parens are unbalanced)"]
    out = []
    if ".perm_fn = perm_fn," not in b:
        out.append("audit .perm_fn is no longer the server's loud perm_fn")
    if ".quiet_perm_fn = draw_perm_fn," not in b:
        out.append("audit .quiet_perm_fn is no longer the server's quiet probe (draw_perm_fn)")
    if ".audit_fn = audit_fn," not in b:
        out.append("audit .audit_fn is no longer the server's audit_fn")
    qf = re.search(r"\.query_fn = (.*?), \.retention_days_fn", b)
    body = qf.group(1) if qf else ""
    if not qf:
        out.append("audit .query_fn is no longer bound")
    else:
        if not re.search(r"if \(!audit_store_ \|\| !audit_store_->is_open\(\)\) return std::nullopt;", body):
            out.append("audit .query_fn no longer returns nullopt for a missing or closed store")
        if "return audit_store_->query(q, pool_size);" not in body:
            out.append("audit .query_fn no longer reads audit_store_->query(q, pool_size)")
        if re.search(r"std::vector<AuditEvent>\{\}", body.replace("std::optional<std::vector<AuditEvent>>", "")):
            out.append("audit .query_fn returns a literal empty vector")
    if ".retention_days_fn = [this]() { return cfg_.audit_retention_days; }," not in b:
        out.append("audit .retention_days_fn no longer reads cfg_.audit_retention_days")
    if re.search(r"\.perm_fn = \[[^\]]*\]\([^)]*\) \{ return (true|false)", b):
        out.append("audit .perm_fn returns a constant")
    return out


def problems(src):
    return audit_problems(src)


# (pattern, replacement, expected substring of the first problem)
MUTATIONS = [
    (r"(register_access_audit_routes\(\s*inline_sink,\s*yuzu::server::access_audit::Deps\{\s*\.auth_fn = auth_fn,\s*)\.perm_fn = perm_fn,",
     r"\1.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) { return true; },",
     "perm_fn"),
    (r"\.quiet_perm_fn = draw_perm_fn,",
     r".quiet_perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) { return true; },",
     "quiet_perm_fn"),
    (r"if \(!audit_store_ \|\| !audit_store_->is_open\(\)\)\n\s*return std::nullopt;\n(\s*return audit_store_->query\(q, pool_size\);)",
     r"\1", "nullopt"),
    (r"return audit_store_->query\(q, pool_size\);", "return std::vector<AuditEvent>{};", "query"),
    (r"return cfg_\.audit_retention_days;", "return 365;", "retention_days_fn"),
    (r"access_audit::register_access_audit_routes\(", "access_audit::register_access_audit_route(",
     "register_access_audit_routes"),
]


class AuditWiring(unittest.TestCase):
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
