#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's production wiring of the Access Users
page (access::register_access_routes), the Settings enrolment fragments and the Groups page.

The route tests stub every dependency, so a permissive admin gate, a swapped account source or a
route family that is never installed would leave them all green. This gate pins the production
wiring.

Access Users (register_access_routes block):

  1. `.admin_fn` calls `auth_routes_->probe_admin(req, res)` (the admin decision, denial row
     withheld for cookie sessions only) and never returns a constant.
  2. `.list_users_fn` guards a null `auth_db_` with `std::unexpected` and reads
     `auth_db_->list_users()`; it maps a failure to `std::unexpected`.
  3. The block never reads the in-memory fallback (`AuthManager`, `auth_mgr_`,
     `auth_manager_`) and never returns a literal empty vector as success.

Settings enrolment fragments (settings_routes_ wiring):

  4. `set_read_admin_fn` binds `auth_routes_->probe_admin(req, res)`: the three auto-loading GET
     fragments (tokens, pending, auto-approve) use the quiet probe so a non-administrator's page
     view writes no auth.admin_required row per panel (the Users page fix, ef7adec0c).
  5. `settings_routes_->register_routes(...)` still binds the LOUD `require_admin` as `admin_fn`
     and never `probe_admin`: every mutating route keeps its denial row.

Groups page (register_groups_routes block):

  6. `groups::register_groups_routes(inline_sink, Deps{.auth_fn = auth_fn})` is called: nothing
     else installs GET /groups or /static/yuzu-groups.js, and test_groups_page.cpp drives the
     registrar directly, so a deleted call would leave every unit test green.

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


def block(src, opener="access::register_access_routes("):
    """The balanced-paren text of the `opener` call, or None."""
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


def settings_problems(src):
    out = []
    rd = block(src, "settings_routes_->set_read_admin_fn(")
    if rd is None:
        out.append("server.cpp no longer calls settings_routes_->set_read_admin_fn( "
                   "(the enrolment GET fragments lose their quiet probe)")
    elif "return auth_routes_->probe_admin(req, res);" not in rd:
        out.append("settings read_admin_fn no longer returns auth_routes_->probe_admin(req, res)")
    elif re.search(r"return (true|false)|require_admin", rd):
        out.append("settings read_admin_fn returns a constant or the loud gate")
    reg = block(src, "settings_routes_->register_routes(")
    if reg is None:
        out.append("server.cpp no longer calls settings_routes_->register_routes(")
    else:
        if "return require_admin(req, res);" not in reg:
            out.append("settings register_routes no longer binds the loud require_admin as admin_fn "
                       "(mutating routes lose their denial row)")
        if "probe_admin" in reg:
            out.append("settings register_routes binds probe_admin: mutating routes must stay loud")
    return out


def groups_problems(src):
    g = block(src, "groups::register_groups_routes(")
    if g is None:
        return ["server.cpp no longer calls groups::register_groups_routes( "
                "(GET /groups and /static/yuzu-groups.js are not installed)"]
    out = []
    if not re.match(r"\( ?inline_sink, ", g):
        out.append("groups register_groups_routes( is no longer installed on inline_sink "
                   "(the shared route seam)")
    if "Deps{ .auth_fn = auth_fn" not in g and "Deps{.auth_fn = auth_fn" not in g:
        out.append("groups register_groups_routes( no longer binds Deps{.auth_fn = auth_fn}")
    return out


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
    return out + settings_problems(src) + groups_problems(src)


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
    # Settings enrolment fragments: the quiet probe is bound ...
    (r"(set_read_admin_fn\(\s*\[this\]\(const httplib::Request& req, httplib::Response& res\) \{\s*)"
     r"return auth_routes_->probe_admin\(req, res\);", r"\1return true;", "read_admin_fn"),
    (r"settings_routes_->set_read_admin_fn\(", "settings_routes_->set_read_admin_fn_gone(",
     "set_read_admin_fn"),
    # ... and the mutating routes keep the loud gate.
    (r"(\[this\]\(const httplib::Request& req, httplib::Response& res\) \{\s*)"
     r"return require_admin\(req, res\);(\s*\},\s*\[this\]\(const httplib::Request& req, "
     r"httplib::Response& res,\s*const std::string& securable_type)",
     r"\1return auth_routes_->probe_admin(req, res);\2", "loud require_admin"),
    # Groups page: the call that installs /groups and its script.
    (r"yuzu::server::groups::register_groups_routes\(", "yuzu::server::groups::register_groups_route(",
     "register_groups_routes"),
    (r"(groups::Deps\{\s*)\.auth_fn = auth_fn,", r"\1", "auth_fn"),
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
