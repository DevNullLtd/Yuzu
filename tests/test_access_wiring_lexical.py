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

  8. `.rbac_admin_hint_fn` passes the SESSION, `auth_db_.get()`, `rbac_store_.get()` and
     `RbacAdminSurface::kRest` to `rbac_admin_hint`, in that order (#6034). The rig re-binds its
     own copy of the lambda, so no unit test executes the production one: a `nullptr` store, a
     discarded session or `kMcp` there leaves every other test green while the hint folds to
     kUnconfirmed (or skips the MCP-tier structural deny) fleet-wide.

Settings enrolment fragments (settings_routes_ wiring):

  4. `set_read_admin_fn` binds `auth_routes_->probe_admin(req, res)`: the three auto-loading GET
     fragments (tokens, pending, auto-approve) use the quiet probe so a non-administrator's page
     view writes no auth.admin_required row per panel (the Users page fix, ef7adec0c).
  5. `settings_routes_->register_routes(...)` still binds the LOUD `require_admin` as `admin_fn`
     and never `probe_admin`: every mutating route keeps its denial row.
  7. `set_read_perm_fn` binds `auth_routes_->probe_permission(req, res, type, op)`: the
     auto-loading Engine Principals fragment gates on EnginePrincipal:Read with the same
     permission test as its REST twin (#5882), through the quiet probe. Never the loud
     `require_permission`, never a constant.

Groups page (register_groups_routes block):

  6. `groups::register_groups_routes(inline_sink, Deps{.auth_fn = auth_fn})` is called: nothing
     else installs GET /groups or /static/yuzu-groups.js, and test_groups_page.cpp drives the
     registrar directly, so a deleted call would leave every unit test green.

Engine Principals panel difference list (#5882; a doc-and-comment pin, not server.cpp wiring):

  9. docs/user-manual/upgrading.md "Where the panel and the route differ" is the ONE canonical list.
     It must be numbered 1..N without a gap, and the same count (as a word: SEVEN, seven) must be
     stated by the handler comment in settings_routes.cpp, the comment in settings_routes.hpp and
     the header of test_settings_engine_panel_authz.cpp; the handler comment must also number its
     own items 1..N. The count is stated as a word in those three places, and one item is cited by
     number (`(difference 7)` in settings_routes.cpp); no manual page cites the count or a number.
     A list that gains or loses an item without those following is a silent drift (G8-32). Not
     gated: the count also appears in docs/test-coverage.md and the handler comment's "pins 1 to 3,
     6 and 7" claim, which this test does not read.

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
SETTINGS_CPP = ROOT / "server" / "core" / "src" / "settings_routes.cpp"
SETTINGS_HPP = ROOT / "server" / "core" / "src" / "settings_routes.hpp"
UPGRADING_MD = ROOT / "docs" / "user-manual" / "upgrading.md"
PANEL_TEST = ROOT / "tests" / "unit" / "server" / "test_settings_engine_panel_authz.cpp"
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


HINT_LAMBDA = (r"\.rbac_admin_hint_fn = \[this\]\(const auth::Session& s\) \{ "
               r"return yuzu::server::rbac_admin_hint\( s, auth_db_\.get\(\), rbac_store_\.get\(\), "
               r"yuzu::server::RbacAdminSurface::kRest\); \}")


def hint_problems(b):
    if ".rbac_admin_hint_fn" not in b:
        return ["access block no longer binds .rbac_admin_hint_fn (the controls lose their server-side hint)"]
    if not re.search(HINT_LAMBDA, b):
        return ["access .rbac_admin_hint_fn no longer calls yuzu::server::rbac_admin_hint( s, "
                "auth_db_.get(), rbac_store_.get(), yuzu::server::RbacAdminSurface::kRest)"]
    return []


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
    rp = block(src, "settings_routes_->set_read_perm_fn(")
    if rp is None:
        out.append("server.cpp no longer calls settings_routes_->set_read_perm_fn( "
                   "(the Engine Principals fragment falls back to the loud perm_fn_)")
    elif "return auth_routes_->probe_permission(req, res, type, op);" not in rp:
        out.append("settings read_perm_fn no longer returns "
                   "auth_routes_->probe_permission(req, res, type, op)")
    elif re.search(r"return (true|false)|require_permission|require_admin", rp):
        out.append("settings read_perm_fn returns a constant or a loud gate")
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
    out += hint_problems(b)
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
    # The Access hint lambda passes the session, both stores and kRest, in order (#6034).
    (r"(rbac_admin_hint\(\s*s, auth_db_\.get\(\), )rbac_store_\.get\(\)", r"\1nullptr", "rbac_admin_hint"),
    (r"(rbac_admin_hint\(\s*)s(, auth_db_\.get\(\), rbac_store_\.get\(\))",
     r"\1auth::Session{}\2", "rbac_admin_hint"),
    (r"(rbac_admin_hint\(\s*s, )auth_db_\.get\(\)", r"\1nullptr", "rbac_admin_hint"),
    (r"RbacAdminSurface::kRest\);\n(\s*\},\n\s*\}\);)", r"RbacAdminSurface::kMcp);\n\1", "rbac_admin_hint"),
    # A comment carrying the pinned tokens does not satisfy the pin.
    (r"(rbac_admin_hint\(\s*s, auth_db_\.get\(\), )rbac_store_\.get\(\),",
     r"\1nullptr, // rbac_store_.get(),", "rbac_admin_hint"),
    (r"\.rbac_admin_hint_fn = ", ".rbac_admin_hint_gone = ", "rbac_admin_hint_fn"),
    # Settings enrolment fragments: the quiet probe is bound ...
    (r"(set_read_admin_fn\(\s*\[this\]\(const httplib::Request& req, httplib::Response& res\) \{\s*)"
     r"return auth_routes_->probe_admin\(req, res\);", r"\1return true;", "read_admin_fn"),
    (r"settings_routes_->set_read_admin_fn\(", "settings_routes_->set_read_admin_fn_gone(",
     "set_read_admin_fn"),
    # The Engine Principals fragment's quiet permission probe is bound ...
    (r"(set_read_perm_fn\(\s*\[this\]\(const httplib::Request& req, httplib::Response& res, "
     r"const std::string& type,\s*const std::string& op\) \{\s*)"
     r"return auth_routes_->probe_permission\(req, res, type, op\);", r"\1return true;",
     "read_perm_fn"),
    (r"(set_read_perm_fn\(\s*\[this\]\(const httplib::Request& req, httplib::Response& res, "
     r"const std::string& type,\s*const std::string& op\) \{\s*)"
     r"return auth_routes_->probe_permission\(req, res, type, op\);",
     r"\1return auth_routes_->require_permission(req, res, type, op);", "read_perm_fn"),
    (r"settings_routes_->set_read_perm_fn\(", "settings_routes_->set_read_perm_fn_gone(",
     "set_read_perm_fn"),
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


# ── The Engine Principals panel's difference list (item 9) ────────────────────────────────────
NUMBER_WORDS = {w: n for n, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve".split())}
LIST_ANCHOR = "**Where the panel and the route differ, deliberately.**"


def canonical_numbers(md):
    """The item numbers of the canonical list, in order, or None when the anchor is missing.
    The list is the run of top-level `N. ` lines between the anchor and the next bold paragraph;
    indented sub-bullets and continuation lines are not items."""
    lines = md.splitlines()
    at = next((i for i, l in enumerate(lines) if l.startswith(LIST_ANCHOR)), None)
    if at is None:
        return None
    out = []
    for l in lines[at + 1:]:
        if l.startswith("**"):
            break
        m = re.match(r"(\d+)\. ", l)
        if m:
            out.append(int(m.group(1)))
    return out


def count_word(text, pattern):
    """The count a comment states, from the first match of `pattern` (group 1 is a number word),
    or None when it is absent or not a number word."""
    m = re.search(pattern, text)
    return NUMBER_WORDS.get(m.group(1).lower()) if m else None


def handler_comment_numbers(cpp):
    """The `//  N.` item numbers of the settings handler's difference comment, in order."""
    start = cpp.find("There are ")
    end = cpp.find('sink.Get("/fragments/settings/engine-principals"', start)
    if start < 0 or end < 0:
        return None
    return [int(m.group(1)) for m in re.finditer(r"^\s*//\s{1,3}(\d+)\. ", cpp[start:end], re.M)]


def difference_list_problems(md, cpp, hpp, test_src):
    nums = canonical_numbers(md)
    if nums is None:
        return ["upgrading.md no longer has the 'Where the panel and the route differ, deliberately.' list"]
    n = len(nums)
    out = []
    if n == 0 or nums != list(range(1, n + 1)):
        out.append(f"upgrading.md's difference list is not numbered 1..N without a gap (found {nums})")
    for name, text, pattern in (
        ("settings_routes.cpp handler comment", cpp, r"There are ([A-Za-z]+), listed once"),
        ("settings_routes.hpp comment", hpp, r"its ([A-Za-z]+) differences"),
        ("test_settings_engine_panel_authz.cpp header", test_src, r"They are ([A-Za-z]+), numbered 1 to"),
    ):
        stated = count_word(text, pattern)
        if stated is None:
            out.append(f"{name} no longer states the difference count as a number word")
        elif stated != n:
            out.append(f"{name} says {stated} differences but upgrading.md lists {n}")
    hn = handler_comment_numbers(cpp)
    if hn is None or hn != list(range(1, n + 1)):
        out.append(f"settings_routes.cpp handler comment does not number its items 1..{n} (found {hn})")
    return out


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


class DifferenceListCount(unittest.TestCase):
    """Item 9: the canonical list's count and numbering match every place that states them."""

    @classmethod
    def setUpClass(cls):
        cls.md = UPGRADING_MD.read_text(encoding="utf-8")
        cls.cpp = SETTINGS_CPP.read_text(encoding="utf-8")
        cls.hpp = SETTINGS_HPP.read_text(encoding="utf-8")
        cls.test_src = PANEL_TEST.read_text(encoding="utf-8")

    def test_counts_agree(self):
        p = difference_list_problems(self.md, self.cpp, self.hpp, self.test_src)
        for m in p:
            print(f"\n::error::{TAG}: {m} (update the list in docs/user-manual/upgrading.md and the"
                  " count in the three places that state it)", file=sys.stderr)
        self.assertEqual(p, [])
        # Not vacuous: the list has items and the real sources state a count.
        self.assertGreaterEqual(len(canonical_numbers(self.md)), 1)

    def test_mutations_are_caught(self):
        # upgrading.md is newest-first: an unrelated entry above the canonical list may carry its
        # own numbered list, so mutate only the slice that starts at the list's anchor.
        def in_list(md, mutate):
            at = md.index(LIST_ANCHOR)
            return md[:at] + mutate(md[at:])

        def drop_item_7(md):
            return in_list(md, lambda t: re.sub(r"^7\. .*\n", "", t, count=1, flags=re.M))

        def add_item_8(md):
            return in_list(md, lambda t: re.sub(r"(^7\. .*\n)", r"\g<1>" + "8. A new difference.\n",
                                                t, count=1, flags=re.M))

        def gap(md):
            return in_list(md, lambda t: re.sub(r"^5\. ", "6. ", t, count=1, flags=re.M))

        def lose_item_3(cpp):
            at = cpp.index("There are ")  # the item numbers are matched only after this marker
            head, tail = cpp[:at], cpp[at:]
            return head + re.sub(r"^\s*//\s{1,3}3\. ", "    //     x ", tail, count=1, flags=re.M)

        cases = [
            ("drop item 7 of the canonical list", (drop_item_7(self.md), self.cpp, self.hpp, self.test_src),
             "says 7 differences but upgrading.md lists 6"),
            ("add an item 8 to the canonical list", (add_item_8(self.md), self.cpp, self.hpp, self.test_src),
             "says 7 differences but upgrading.md lists 8"),
            ("renumber so the list has a gap", (gap(self.md), self.cpp, self.hpp, self.test_src),
             "not numbered 1..N"),
            ("handler comment says SIX", (self.md, self.cpp.replace("There are SEVEN,", "There are SIX,", 1),
                                          self.hpp, self.test_src), "handler comment says 6"),
            ("hpp comment says six", (self.md, self.cpp, self.hpp.replace("its seven differences", "its six differences", 1),
                                      self.test_src), "settings_routes.hpp comment says 6"),
            ("test header says EIGHT", (self.md, self.cpp, self.hpp,
                                        self.test_src.replace("They are SEVEN,", "They are EIGHT,", 1)),
             "header says 8"),
            ("handler comment loses item 3", (self.md, lose_item_3(self.cpp), self.hpp, self.test_src),
             "does not number its items"),
            ("anchor renamed", (self.md.replace("Where the panel and the route differ, deliberately.", "Differences.", 1),
                                self.cpp, self.hpp, self.test_src), "no longer has"),
        ]
        for name, args, expected in cases:
            with self.subTest(mutation=name):
                p = difference_list_problems(*args)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"{expected!r} not in {p}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
