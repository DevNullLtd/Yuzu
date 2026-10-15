#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's access::register_access_routes(...) block.

The Access route tests stub every dependency, so a permissive admin gate or a swapped account
source in server.cpp would leave them all green. This gate pins the production wiring:

  1. `.admin_fn` calls `auth_routes_->probe_admin(req, res)` (the admin decision, denial row
     withheld for cookie sessions only) and never returns a constant.
  2. `.list_users_fn` guards a null `auth_db_` with `std::unexpected` and reads
     `auth_db_->list_users()`; it maps a failure to `std::unexpected`.
  3. The block never reads the in-memory fallback (`AuthManager`, `auth_mgr_`,
     `auth_manager_`) and never returns a literal empty vector as success.

`//` comments are stripped and whitespace collapsed before matching. Lexical only: it cannot see
a relocation that keeps the tokens (review-enforced). The self-test applies in-memory mutations
and fails loudly if a pattern goes stale.

Usage: python3 tests/test_access_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
TAG = "test_access_wiring_lexical"
HINT = (" (this gate pins the Access Users production wiring; if server.cpp was legitimately"
        " restructured, update tests/test_access_wiring_lexical.py)")


def normalise(src):
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def block(src):
    """The balanced-paren text of the register_access_routes( call, or None."""
    t = normalise(src)
    at = t.find("access::register_access_routes(")
    if at < 0:
        return None
    start = t.index("(", at)
    depth = 0
    for i in range(start, len(t)):
        depth += (t[i] == "(") - (t[i] == ")")
        if depth == 0:
            return t[start:i + 1]
    return None


def problems(src):
    b = block(src)
    if b is None:
        return ["server.cpp no longer calls access::register_access_routes( (or its parens are unbalanced)"]
    out = []
    admin = re.search(r"\.admin_fn = \[this\]\(const httplib::Request& req, httplib::Response& res\) \{(.*?)\},"
                      r" \.perm_fn", b)
    if not admin or "return auth_routes_->probe_admin(req, res);" not in admin.group(1):
        out.append("access .admin_fn no longer returns auth_routes_->probe_admin(req, res)")
    elif re.search(r"return (true|false)", admin.group(1)):
        out.append("access .admin_fn returns a constant")
    lu = b.find(".list_users_fn")
    body = b[lu:] if lu >= 0 else ""
    if lu < 0:
        out.append("access .list_users_fn is no longer bound")
    else:
        if not re.search(r"if \(!auth_db_\) return std::unexpected\(", body):
            out.append("access .list_users_fn no longer fails closed when auth_db_ is null")
        if "auth_db_->list_users()" not in body:
            out.append("access .list_users_fn no longer reads AuthDB::list_users()")
        if not re.search(r"if \(!r\) return std::unexpected\(", body):
            out.append("access .list_users_fn no longer maps an AuthDB failure to std::unexpected")
    if re.search(r"AuthManager|auth_mgr_|auth_manager_", b):
        out.append("access block reads the in-memory AuthManager fallback")
    if re.search(r"return (std::vector<auth::UserEntry>\{\}|\{\});", b):
        out.append("access block returns a literal empty list as success")
    return out


# (pattern, replacement, expected substring of the first problem)
MUTATIONS = [
    (r"return auth_routes_->probe_admin\(req, res\);\n(\s*\},\n\s*\.perm_fn)", r"return true;\n\1",
     "admin_fn"),
    (r"auth_db_->list_users\(\)", "auth_mgr_->list_users()", "list_users_fn"),
    (r"if \(!auth_db_\)\n\s*return std::unexpected\(std::string\(\"auth store not configured\"\)\);",
     "", "fails closed"),
    (r"if \(!r\)\n\s*return std::unexpected\(\"AuthDB::list_users failed",
     "if (!r)\n                        return std::vector<auth::UserEntry>{}; //(\"AuthDB::list_users failed",
     "AuthDB failure"),
    (r"yuzu::server::access::register_access_routes\(", "yuzu::server::access::register_access_route(",
     "register_access_routes"),
]


class AccessWiring(unittest.TestCase):
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
