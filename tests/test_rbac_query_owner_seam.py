#!/usr/bin/env python3
"""ADR-0012 s3 tripwire for the RBAC cross-schema query owner (PR #4985).

ADR-0012 s3: per-store classes stay single-schema owners; cross-schema work is written by a
dedicated query owner that takes one lease. The last-Administrator guard needs grants
(`rbac_store`) and account state (`auth`) in one transaction, so its SQL lives ONLY in
`RbacAdminAuthorityOwner` (server/core/src/rbac_admin_authority_owner.cpp). This test fails
if either half of that seam regresses:

  1. `server/core/src/rbac_store.cpp` contains an `auth.`-schema reference inside a string
     literal (SQL). Comments are ignored, so prose that names `auth.users` is fine.
  2. Symmetrically, an `auth_db*` file (server/core/src/auth_db.cpp, auth_db_sql_helpers.hpp,
     the public server/core/include/yuzu/server/auth_db.hpp) contains an `rbac_store.`-schema
     reference inside a string literal. `AuthDB` and the statements it shares with the owner
     (`auth_sql::`, #4966) are own-schema `auth.*` SQL only; the cross-schema half lives in the
     owner.
  3. `kAuthenticatableAdminGrantsFrom`, the one SQL fragment that defines "an authenticatable
     Administrator grant", is not defined exactly once under server/core/src, in the owner's
     translation unit. A second copy is the drift the fragment exists to remove.
  4. The active-local-admin predicate (`role = 'admin' AND is_active`, the column floor's
     population, #4966) is not exactly ONE string literal under server/, in
     `auth_db_sql_helpers.hpp` (`kActiveLocalAdminPredicate`). The count helper, the owner's
     survivor list and the owner's per-target membership read all embed it by name; a second
     literal is a drift the floor cannot tolerate. Also counted: the reversed order
     (`is_active AND role = 'admin'`), an aliased copy (`u.role = 'admin' AND u.is_active`),
     `is_active IS TRUE`, `role IN ('admin')`, `role NOT IN ('user')`, `role <> 'user'` / `role != 'user'`, a
     parenthesised operand, `lower(role) = 'admin'`, `role = ANY(...admin...)`, `role ILIKE 'admin'`, a cast
     (`role::text = 'admin'`, `'admin'::text`), the swapped comparison (`'admin' = role`), the active
     operand spelled `is_active = 't'` / `'true'` and the negated active operand (`NOT is_active =
     FALSE`, `NOT (is_active = FALSE)`, `NOT is_active IS FALSE`, `NOT (is_active <> TRUE)`), in
     either order. SQL comments (`/* */`, `-- ...`) inside a literal are stripped (replaced by a
     space) BEFORE matching, in both directions: a comment cannot split a predicate apart, and a
     predicate inside a comment does not count.
     UNDETECTED (known gaps): a copy that splits the predicate across statements or SQL fragments;
     `role LIKE`/`~`/`SIMILAR TO` patterns; `role = (SELECT ...)`; `NOT (role = 'user')`;
     `coalesce(...)` or `CASE` wrappers around either operand; `role NOT IN ('user', ...)` lists of
     two or more values; `role::text IN (...)` lists of two or more admin-class values.
  5. An unguarded fixture primitive is called from production code. `AuthDB::remove_user` and
     `AuthDB::update_role` write the soft delete / role column WITHOUT the last-Administrator
     guard (they exist for fixtures; production goes through `AuthManager::remove_user_checked` /
     `update_role_checked`). No file under server/core/src or server/core/include other than
     `auth_db.cpp` may call either through a receiver whose identifier CONTAINS `db`
     (`db`, `auth_db_`, `auth_db_ptr()`, `get_db()`, `mydb`, ...) or a parenthesised dereference
     `(*expr)`. This scans for those receiver SPELLINGS. UNDETECTED (known gaps): a call through an
     alias that does not contain `db` (a reference named `store`, a lambda capture, a function
     pointer), `std::invoke`/`std::bind`/`std::mem_fn` or a pointer-to-member call, a call through
     a macro, and a call from a file outside server/core/src and server/core/include.
  6. A statement that decreases the guarded populations is written outside the shared helpers:
     an `UPDATE [ONLY] [auth.]users [[AS] alias] SET ...` whose SET list (any column position,
     including a tuple assignment `SET (role, x) = ...`, and a quoted column `SET "role"` /
     `"is_active"`, bare or alias-qualified) assigns `role` or assigns `is_active` anything other
     than the literal TRUE followed by a comma or the end of the SET list (`SET is_active = TRUE AND
     $1` can be false, so it counts), an `INSERT INTO [auth.]users ... ON CONFLICT ... DO UPDATE
     SET ...` whose SET list does the same, a `MERGE INTO [auth.]users`, a `TRUNCATE [auth.]users`
     and any `DELETE FROM [ONLY] [auth.]users` may appear only in `auth_db_sql_helpers.hpp` (the
     soft delete and the role write the owner and `AuthDB` share). The table name is recognised
     bare, schema-qualified and with quoted identifiers (`"auth"."users"`). SQL comments inside a
     literal are stripped before matching (`UPDATE auth.users /* c */ SET role = $1` is found).
     `SET is_active = TRUE`
     (reactivation) is deliberately not in scope: it can only GROW the population. UNDETECTED
     (known gaps): SQL assembled from fragments at runtime, a stored procedure or trigger, a
     `COPY`, an `INSERT ... SELECT` into users, `ALTER TABLE ... RENAME`, an UPDATE through a view
     or an inheritance child, a table name built from a `{}` format argument, and a role
     assignment spelled so that `role` is not directly followed by `=` or by a tuple closing `)`.

It scans string literals only (a small tokenizer skips `//` and `/* */` comments), so a doc
comment cannot trip it. Wired into tests/meson.build (suite 'docs') and docs-lint.yml.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STORE = "server/core/src/rbac_store.cpp"
OWNER = "server/core/src/rbac_admin_authority_owner.cpp"
FRAGMENT = "kAuthenticatableAdminGrantsFrom"
FOREIGN = re.compile(r"\bauth\.[A-Za-z_]+", re.IGNORECASE)
DEFINITION = re.compile(
    r"\b(?:constexpr|const)\b[^;=]*\b" + FRAGMENT + r"\s*=|#\s*define\s+" + FRAGMENT + r"\b"
)
# A character literal, so a C++14 digit separator (5'000) is not mistaken for one: an unmatched
# apostrophe is skipped alone. Scanning to the next apostrophe instead inverts string/code phase
# for the rest of the file and can hide an `auth.` literal.
CHAR_LIT = re.compile(
    r"'(?:\\(?:x[0-9A-Fa-f]+|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|.)|[^\\'\n])'"
)
STORE_PREFIX = "server/core/src/rbac_store"
FOREIGN_RBAC = re.compile(r"\brbac_store\.[A-Za-z_]+", re.IGNORECASE)
AUTH_PREFIXES = ("server/core/src/auth_db", "server/core/include/yuzu/server/auth_db")
# Every spelling of "an active local admin" the column floor's population can be written as: the
# canonical order, the reversed order, an aliased column (`u.role`, `u.is_active`), a redundant
# `is_active = TRUE`, a one-element `role IN ('admin')`, the negated `role <> 'user'`, optional
# parentheses around either operand (which is also how `lower(role) = 'admin'` is matched: the
# unanchored `(role)` after `lower`) and `role = ANY(...)`. ONE combined regex with
# alternation, so a spelling that two alternatives could both match is counted once.
_COL = r"(?:\w+\.)?"
_ADMIN = r"'admin'(?:\s*::\s*\w+)?"
_USER = r"'user'(?:\s*::\s*\w+)?"
_ROLE_REF = _COL + r"role(?:\s*::\s*\w+)?"
_ROLE_FWD = (
    r"\(?\s*" + _ROLE_REF + r"\s*\)?\s*"
    r"(?:(?:=|ILIKE)\s*" + _ADMIN + r"|(?:<>|!=)\s*" + _USER + r"|IN\s*\(\s*" + _ADMIN + r"\s*\)"
    r"|NOT\s+IN\s*\(\s*" + _USER + r"\s*\)"
    r"|=\s*ANY\s*\([^)]*admin[^)]*\))"
    r"\s*\)?"
)
_ROLE_REV = r"\(?\s*" + _ADMIN + r"\s*=\s*" + _ROLE_REF + r"\s*\)?"
_ROLE = "(?:" + _ROLE_FWD + "|" + _ROLE_REV + ")"
# The "is active" operand: `is_active`, `is_active = TRUE|1|'t'|'true'`, `is_active IS TRUE`,
# `is_active IS NOT FALSE`, and the negated spellings `NOT is_active = FALSE`, `NOT (is_active =
# FALSE)`, `NOT is_active IS FALSE`, `NOT is_active <> TRUE`, optionally parenthesised.
_ACTIVE_POS = (
    _COL + r"is_active\b(?:\s*=\s*(?:TRUE|1|'t'|'true')|\s+IS\s+TRUE\b|\s+IS\s+NOT\s+FALSE\b)?"
)
_ACTIVE_NEG = (
    r"NOT\s*\(?\s*" + _COL + r"is_active\s*(?:=\s*(?:FALSE|0|'f'|'false')|IS\s+FALSE\b"
    r"|(?:<>|!=)\s*(?:TRUE|1)\b|IS\s+NOT\s+TRUE\b)\s*\)?"
)
_ACTIVE = r"\(?\s*(?:" + _ACTIVE_NEG + "|" + _ACTIVE_POS + r")\s*\)?"
ADMIN_PREDICATES = (
    re.compile(
        "(?:" + _ROLE + r"\s+AND\s+" + _ACTIVE + "|" + _ACTIVE + r"\s+AND\s+" + _ROLE +
        r"|" + _ROLE_REF + r"\s+IN\s*\(\s*" + _ADMIN + r"\s*\))",
        re.IGNORECASE,
    ),
)
ADMIN_PREDICATE_FILE = "server/core/src/auth_db_sql_helpers.hpp"


_SQL_COMMENTS = re.compile(r"/\*.*?\*/|--[^\n]*", re.DOTALL)


def strip_sql_comments(lit: str) -> str:
    """A SQL comment (`/* ... */` or `-- ...` to end of line) replaced by one space, so it cannot
    split a statement's tokens apart (`UPDATE auth.users /* c */ SET role = $1`)."""
    return _SQL_COMMENTS.sub(" ", lit)


def admin_predicate_count(lit: str) -> int:
    lit = strip_sql_comments(lit)
    return sum(len(p.findall(lit)) for p in ADMIN_PREDICATES)


# Rule 5: a production call of an unguarded fixture primitive. The receiver is any identifier
# containing `db` (optionally called, `get_db()`), or a parenthesised dereference `(*expr)`.
UNGUARDED_CALL = re.compile(
    r"(?:\b\w*db\w*(?:\s*\(\s*\))?|\(\s*\*(?:[^()]|\([^()]*\))*\))\s*(?:->|\.)\s*"
    r"(?:remove_user|update_role)\s*\(",
    re.IGNORECASE,
)
UNGUARDED_CALL_ALLOWED = ("server/core/src/auth_db.cpp",)
UNGUARDED_CALL_ROOTS = ("server/core/src/", "server/core/include/")
# Rule 6: a statement that can SHRINK the guarded populations. The users table is recognised bare,
# schema-qualified, with an optional ONLY and with quoted identifiers (`"auth"."users"`).
_USERS_TABLE = r'(?:ONLY\s+)?(?:"?auth"?\s*\.\s*)?"?users"?(?!\w)'
# An UPDATE of it (with an optional alias) whose SET list assigns `role`, or `is_active` anything
# other than a literal TRUE, in ANY column position (or as a tuple); the same SET list after an
# INSERT ... ON CONFLICT ... DO UPDATE; a MERGE INTO it; a TRUNCATE of it; any DELETE FROM it.
_UPDATE_USERS = re.compile(
    r"UPDATE\s+" + _USERS_TABLE + r"(?:\s+(?:AS\s+)?(?!SET\b)\w+)?\s+SET\s+(?P<set>[^;]*)",
    re.IGNORECASE,
)
_UPSERT_USERS = re.compile(
    r"INSERT\s+INTO\s+" + _USERS_TABLE + r"[^;]*?\bON\s+CONFLICT\b[^;]*?\bDO\s+UPDATE\s+SET\s+"
    r"(?P<set>[^;]*)",
    re.IGNORECASE,
)
_SET_LIST_END = re.compile(r"\b(?:WHERE|FROM|RETURNING)\b", re.IGNORECASE)
# A column name may be quoted (`"role"`) and qualified by a (possibly quoted) alias (`u.role`,
# `"u"."role"`). The lookbehind keeps `last_role` and `x.last_role` from matching. `is_active` is
# shrinking unless it is assigned the literal TRUE followed by a delimiter (a comma, or the end of
# the SET list): `is_active = TRUE AND $1` can be false, so it is shrinking.
_QUAL = r'(?:"?\w+"?\s*\.\s*)?'
_COLQ = _QUAL + r'"?'
_SHRINKING_ASSIGN = re.compile(
    r'(?<![\w"])' + _COLQ + r'(?:role"?\s*=(?!=)|is_active"?\s*=(?!\s*TRUE\s*(?:,|$))(?!=))'
    r'|\(\s*(?:[\w."]+\s*,\s*)*' + _COLQ + r'(?:role|is_active)"?\b[^)]*\)\s*=(?!=)',
    re.IGNORECASE,
)
_DELETE_USERS = re.compile(r"DELETE\s+FROM\s+" + _USERS_TABLE, re.IGNORECASE)
_MERGE_USERS = re.compile(r"MERGE\s+INTO\s+" + _USERS_TABLE, re.IGNORECASE)
_TRUNCATE_USERS = re.compile(r"TRUNCATE\s+(?:TABLE\s+)?" + _USERS_TABLE, re.IGNORECASE)


def population_write_count(lit: str) -> int:
    lit = lit.replace('\\"', '"')  # a C++ literal's escaped quote is the SQL's quote
    lit = strip_sql_comments(lit)
    n = len(_DELETE_USERS.findall(lit)) + len(_MERGE_USERS.findall(lit))
    n += len(_TRUNCATE_USERS.findall(lit))
    for pattern in (_UPDATE_USERS, _UPSERT_USERS):
        for m in pattern.finditer(lit):
            set_list = _SET_LIST_END.split(m.group("set"), maxsplit=1)[0]
            if _SHRINKING_ASSIGN.search(set_list):
                n += 1
    return n


POPULATION_WRITE_FILE = "server/core/src/auth_db_sql_helpers.hpp"


def tokenize(src: str):
    """Yield ("code" | "string", text) chunks; comments are dropped, char literals kept as code."""
    i, n = 0, len(src)
    code_start = 0
    out = []

    def flush(end):
        if end > code_start:
            out.append(("code", src[code_start:end]))

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            flush(i)
            j = src.find("\n", i)
            i = n if j == -1 else j
            code_start = i
        elif c == "/" and nxt == "*":
            flush(i)
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
            code_start = i
        elif c == "R" and nxt == '"':
            k = src.find("(", i + 2)
            delim = src[i + 2:k]
            end = src.find(")" + delim + '"', k + 1)
            if k == -1 or end == -1:
                i += 1
                continue
            flush(i)
            out.append(("string", src[k + 1:end]))
            i = end + len(delim) + 2
            code_start = i
        elif c == '"':
            flush(i)
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(("string", src[i + 1:j]))
            i = j + 1
            code_start = i
        elif c == "'":
            m = CHAR_LIT.match(src, i)
            i = m.end() if m else i + 1
        else:
            i += 1
    flush(n)
    return out


def literals(src: str):
    """String literals, with adjacent literals (separated only by whitespace) concatenated."""
    out, prev_string = [], False
    for kind, t in tokenize(src):
        if kind == "string":
            if prev_string and out:
                out[-1] += t
            else:
                out.append(t)
            prev_string = True
        elif t.strip():
            prev_string = False
    return out


def foreign_match(lit: str, pattern=FOREIGN):
    """First `pattern` schema reference in a literal, also seen through escaped quotes/whitespace."""
    m = pattern.search(lit)
    if m:
        return m.group(0)
    tidy = re.sub(r"\s*\.\s*", ".", re.sub(r'[\\"]', "", lit))
    m = pattern.search(tidy)
    return m.group(0) if m else None


def code(src: str) -> str:
    return "".join(t for kind, t in tokenize(src) if kind == "code")


def _selfcheck() -> None:
    # Explicit raises, not `assert`: python3 -O strips asserts.
    sample = (
        '// auth.users in a line comment\n'
        '/* auth.users in a block comment */\n'
        'const char* a = "SELECT 1 FROM auth.users";\n'
        'const char* b = R"sql(SELECT * FROM auth.users u)sql";\n'
        'const char* c = "https://example.test/x"; // auth.users trailing\n'
        'int rbac = 1; // rbac_store.principal_roles is fine\n'
    )
    lits = literals(sample)
    hits = [s for s in lits if FOREIGN.search(s)]
    if len(hits) != 2:
        raise SystemExit(f"selfcheck: expected 2 auth. literals, got {hits!r}")
    if any("comment" in s for s in lits):
        raise SystemExit("selfcheck: a comment leaked into the literal set")
    if FOREIGN.search(code(sample)):
        raise SystemExit("selfcheck: auth. leaked into the code (non-literal) stream")
    # Each construct below must NOT stop the scan from finding the `auth.` literal after it.
    # These fail if the char-literal branch, string-escape handling or raw-string handling
    # is removed or reverts to scanning to the next apostrophe.
    must_still_find = {
        "digit separator": "constexpr int a = 5'000;\nconst char* s = \"SELECT 1 FROM auth.users\";\n",
        "digit separators": "constexpr long a = 1'000'000;\nconst char* s = \"FROM auth.users\";\n",
        "quote char literal": "char q = '\"';\nconst char* s = \"FROM auth.users\";\n",
        "escaped quote char literal": "char q = '\\\"';\nconst char* s = \"FROM auth.users\";\n",
        "escaped quote in string": 'const char* a = "x\\" y";\nconst char* s = "FROM auth.users";\n',
        "raw string with a quote and //": 'const char* a = R"sql(a " b // c)sql"; const char* s = "FROM auth.users";\n',
        "adjacent literals": 'const char* s = "FROM au" "th.users";\n',
        "escaped-quote schema": 'const char* s = "FROM \\"auth\\".users";\n',
    }
    for name, text in must_still_find.items():
        if not any(foreign_match(l) for l in literals(text)):
            raise SystemExit(f"selfcheck: the scan lost an auth. literal after: {name}")
    for text in ('const char* a = "docs are fine";\n// "auth.users" in a comment\n',):
        if any(foreign_match(l) for l in literals(text)):
            raise SystemExit("selfcheck: a comment or clean literal was reported")
    # The symmetric (rbac_store.) pattern: found in a literal, ignored in a comment, and seen
    # through the same escaping/adjacent-literal tricks as the auth. scan.
    rbac_sample = (
        '// rbac_store.principal_roles in a comment\n'
        'const char* a = "SELECT 1 FROM rbac_store.principal_roles";\n'
        'const char* b = "FROM rbac" "_store.roles";\n'
        'const char* c = "FROM \\"rbac_store\\".roles";\n'
        'const char* d = "plain auth.users text";\n'
    )
    rbac_hits = [l for l in literals(rbac_sample) if foreign_match(l, FOREIGN_RBAC)]
    if len(rbac_hits) != 3:
        raise SystemExit(f"selfcheck: expected 3 rbac_store. literals, got {rbac_hits!r}")
    if foreign_match('docs only, no schema', FOREIGN_RBAC):
        raise SystemExit("selfcheck: a clean literal was reported by the rbac_store. scan")
    pred = 'const char* p = "x WHERE role = \'admin\' AND is_active";\n// role = \'admin\' AND is_active\n'
    if sum(admin_predicate_count(l) for l in literals(pred)) != 1:
        raise SystemExit("selfcheck: the admin-predicate scan must count literals only")
    # Each alternative spelling of the predicate is counted (rule 4 hardening, #4966) ...
    for name, text in {
        "reversed order": "x WHERE is_active AND role = 'admin'",
        "reversed order with = TRUE": "x WHERE is_active = TRUE AND role = 'admin'",
        "aliased canonical order": "x WHERE u.role = 'admin' AND u.is_active",
        "aliased reversed order": "x WHERE u.is_active AND u.role = 'admin'",
        "one-element IN": "x WHERE role IN ('admin')",
        "aliased one-element IN": "x WHERE u.role IN ( 'admin' )",
        "negated role": "x WHERE role <> 'user' AND is_active",
        "negated role (!=) reversed": "x WHERE is_active AND role != 'user'",
        "parenthesised operands": "x WHERE (role = 'admin') AND (is_active)",
        "lower(role)": "x WHERE lower(role) = 'admin' AND is_active",
        "ANY array": "x WHERE role = ANY(ARRAY['admin']) AND is_active",
        "ANY text array": "x WHERE is_active AND role = ANY('{admin}')",
        "aliased negated": "x WHERE u.role <> 'user' AND u.is_active",
        "is_active IS TRUE": "x WHERE role = 'admin' AND is_active IS TRUE",
        "is_active IS TRUE reversed": "x WHERE is_active IS TRUE AND role = 'admin'",
        "text cast on the literal": "x WHERE role = 'admin'::text AND is_active",
        "text cast on the column": "x WHERE role::text = 'admin' AND is_active",
        "swapped comparison": "x WHERE 'admin' = role AND is_active",
        "swapped comparison, cast": "x WHERE 'admin'::text = u.role AND u.is_active",
        "ILIKE": "x WHERE role ILIKE 'admin' AND is_active",
        "IN with a cast": "x WHERE role::text IN ('admin')",
        "NOT is_active = FALSE": "x WHERE role = 'admin' AND NOT is_active = FALSE",
        "NOT (is_active = FALSE)": "x WHERE role = 'admin' AND NOT (is_active = FALSE)",
        "NOT is_active = FALSE, reversed": "x WHERE NOT is_active = FALSE AND role = 'admin'",
        "NOT is_active IS FALSE": "x WHERE role = 'admin' AND NOT is_active IS FALSE",
        "NOT is_active <> TRUE": "x WHERE role = 'admin' AND NOT (is_active <> TRUE)",
        "role NOT IN ('user')": "x WHERE role NOT IN ('user') AND is_active",
        "aliased role NOT IN, reversed": "x WHERE u.is_active AND u.role NOT IN ('user')",
        "is_active = 't', forward": "x WHERE role = 'admin' AND is_active = 't'",
        "is_active = 't', reversed": "x WHERE is_active = 't' AND role = 'admin'",
        "is_active = 'true'": "x WHERE is_active = 'true' AND role = 'admin'",
        "block comment inside": "x WHERE role /* c */ = 'admin' AND is_active",
        "line comment inside": "x WHERE role = 'admin' -- c\n AND is_active",
        "comment between the operands": "x WHERE role = 'admin' /* AND */ AND is_active",
    }.items():
        if admin_predicate_count(text) != 1:
            raise SystemExit(f"selfcheck: the admin-predicate scan missed: {name}")
    # ... and an unrelated literal is not.
    for text in ("x WHERE role = 'user' AND is_active", "x WHERE role = $1 AND is_active",
                 "x WHERE is_active AND role = $1", "role IN ('admin', 'user')",
                 "x WHERE role <> 'admin' AND is_active", "x WHERE role <> 'user'",
                 "x WHERE /* role = 'admin' AND is_active */ id = 1",
                 "x WHERE id = 1 -- role = 'admin' AND is_active\n",
                 "x WHERE role NOT IN ('admin') AND is_active",
                 "x WHERE role = 'admin' AND NOT is_active"):
        if admin_predicate_count(text) != 0:
            raise SystemExit(f"selfcheck: the admin-predicate scan over-matched: {text!r}")
    # Rule 5: the unguarded-primitive call scan finds every receiver spelling it names (any
    # identifier containing `db`, optionally called; a parenthesised dereference) and ignores the
    # guarded API, comments and receivers that do not contain `db`.
    for text in ("db->remove_user(u);", "auth_db_->update_role(u, r);", "auth_db.remove_user(u);",
                 "auth_db_ptr()->update_role(u, r);", "x = db ->  remove_user (u);",
                 "mydb->remove_user(u);", "get_db()->update_role(u, r);",
                 "AuthDB_ref.remove_user(u);", "(*db).remove_user(u);",
                 "(*mgr->auth_db_ptr()).update_role(u, r);", "(* ptr ).remove_user(u);",
                 "this->db_handle_.update_role(u, r);", "auth_mgr_->auth_db_ptr()->remove_user(u);"):
        if not UNGUARDED_CALL.search(code(text + "\n")):
            raise SystemExit(f"selfcheck: the unguarded-call scan missed: {text!r}")
    for text in ("auth_mgr_->remove_user_checked(u);", "auth_mgr.update_role_checked(u, r);",
                 "auth_mgr_->remove_user(u);", "// db->remove_user(u);", "store->remove_user(u);",
                 "db->remove_user_checked(u);", "db->user_exists(u);"):
        if UNGUARDED_CALL.search(code(text + "\n")):
            raise SystemExit(f"selfcheck: the unguarded-call scan over-matched: {text!r}")
    # Rule 6: every shrinking write shape is found in a literal; a growing write, an unrelated
    # column and a comment are not.
    shrinking = {
        "is_active = FALSE": "UPDATE auth.users SET is_active = FALSE WHERE x",
        "role =": "UPDATE auth.users SET role = $1",
        "multi-column, role second": "UPDATE auth.users SET last_login_at = now(), role = $2 WHERE x",
        "multi-column, is_active last": "UPDATE auth.users SET a = 1, is_active = FALSE",
        "alias with AS": "UPDATE auth.users AS u SET is_active = FALSE WHERE u.username = $1",
        "alias without AS": "UPDATE auth.users u SET u.role = 'user'",
        "unqualified users": "UPDATE users SET role = 'user'",
        "bound is_active": "UPDATE auth.users SET is_active = $2 WHERE username = $1",
        "is_active = 0": "UPDATE auth.users SET is_active = 0",
        "DELETE": "DELETE FROM auth.users WHERE username = $1",
        "unqualified DELETE": "delete from users",
        "UPDATE ONLY": "UPDATE ONLY auth.users SET role = $1",
        "quoted identifiers": 'UPDATE "auth"."users" SET role = $1',
        "escaped-quote identifiers in a literal": 'UPDATE \\"auth\\".\\"users\\" SET is_active = FALSE',
        "DELETE FROM ONLY": "DELETE FROM ONLY auth.users WHERE username = $1",
        "quoted DELETE": 'DELETE FROM "auth"."users"',
        "upsert assigning role": "INSERT INTO auth.users (username, role) VALUES ($1, $2) "
                                 "ON CONFLICT (username) DO UPDATE SET role = excluded.role",
        "upsert deactivating": "INSERT INTO auth.users(username) VALUES ($1) "
                               "ON CONFLICT (username) DO UPDATE SET is_active = FALSE",
        "upsert, role second": "INSERT INTO auth.users(username) VALUES ($1) ON CONFLICT (username) "
                               "DO UPDATE SET display_name = excluded.display_name, role = $2 "
                               "RETURNING id",
        "MERGE": "MERGE INTO auth.users u USING t ON u.username = t.username WHEN MATCHED THEN "
                 "UPDATE SET role = t.role",
        "TRUNCATE": "TRUNCATE auth.users",
        "TRUNCATE TABLE": "TRUNCATE TABLE ONLY auth.users CASCADE",
        "is_active = 'f'": "UPDATE auth.users SET is_active = 'f' WHERE x",
        "is_active = CASE": "UPDATE auth.users SET is_active = CASE WHEN x THEN TRUE ELSE FALSE END",
        "is_active = NOT is_active": "UPDATE auth.users SET is_active = NOT is_active",
        "is_active = coalesce": "UPDATE auth.users SET is_active = coalesce($1, FALSE)",
        "tuple assignment": "UPDATE auth.users SET (role, updated_at) = ($1, now()) WHERE x",
        "tuple assignment, role second": "UPDATE auth.users SET (updated_at, role) = (now(), $1)",
        "block comment between the table and SET": "UPDATE auth.users /* c */ SET role = $1",
        "block comment without spaces": "UPDATE auth.users/**/SET role = $1",
        "line comment between the table and SET": "UPDATE auth.users -- c\n SET role = $1",
        "comment before the assignment": "UPDATE auth.users SET /* c */ is_active = FALSE",
        "comment between UPDATE and the table": "UPDATE /* c */ auth.users SET role = $1",
        "is_active = TRUE AND $1": "UPDATE auth.users SET is_active = TRUE AND $1 WHERE x",
        "is_active = TRUE AND, no WHERE": "UPDATE auth.users SET is_active = TRUE AND $1",
        "is_active = TRUE AND $1, then another column": "UPDATE auth.users SET is_active = TRUE AND $1, a = 2",
        "quoted role": 'UPDATE auth.users SET "role" = $1',
        "quoted is_active": 'UPDATE auth.users SET "is_active" = FALSE',
        "quoted alias and column": 'UPDATE auth.users u SET "u"."role" = $1',
        "quoted column, multi-column": 'UPDATE auth.users SET a = 1, "role" = $1',
        "quoted tuple": 'UPDATE auth.users SET ("role", updated_at) = ($1, now())',
        "quoted tuple, is_active second": 'UPDATE auth.users SET (updated_at, "is_active") = (now(), $1)',
    }
    for name, text in shrinking.items():
        if population_write_count(text) != 1:
            raise SystemExit(f"selfcheck: the population-write scan missed: {name}")
    if sum(population_write_count(l) for l in literals(
            'a = "UPDATE auth.users SET is_active = " "FALSE WHERE x"; b = "UPDATE auth.users SET role = $1";\n')) != 2:
        raise SystemExit("selfcheck: the population-write scan must see adjacent literals")
    for text in ('a = "UPDATE auth.users SET is_active = TRUE WHERE x";\n',
                 'a = "UPDATE auth.users SET last_login_at = now()";\n',
                 'a = "UPDATE auth.users SET last_role = $1 WHERE x";\n',
                 'a = "UPDATE auth.users SET a = 1 WHERE role = \'admin\'";\n',
                 'a = "UPDATE auth.users SET is_active = TRUE WHERE is_active = FALSE";\n',
                 'a = "UPDATE auth.user_prefs SET role = $1";\n',
                 'a = "UPDATE auth.users SET is_active = TRUE, last_login_at = now()";\n',
                 'a = "INSERT INTO auth.users(username) VALUES ($1) ON CONFLICT (username) DO '
                 'UPDATE SET display_name = excluded.display_name, last_seen_at = now() '
                 'RETURNING id";\n',
                 'a = "INSERT INTO auth.users(username, role) VALUES ($1, $2) ON CONFLICT '
                 '(username) DO NOTHING RETURNING id";\n',
                 'a = "INSERT INTO auth.users(username) VALUES ($1) ON CONFLICT (username) DO '
                 'UPDATE SET last_seen_at = now() WHERE auth.users.role = \'admin\'";\n',
                 'a = "TRUNCATE auth.user_prefs";\n',
                 'a = "UPDATE auth.users SET /* role = $1 */ last_login_at = now()";\n',
                 'a = "UPDATE auth.users SET last_login_at = now() -- role = $1\\n";\n',
                 'a = "UPDATE auth.users SET is_active = TRUE /* c */ WHERE x";\n',
                 'a = "UPDATE auth.users SET is_active = TRUE, last_login_at = now()";\n',
                 'a = "UPDATE auth.users SET \\"last_role\\" = $1";\n',
                 'a = "UPDATE auth.users SET role_note = $1";\n',
                 'a = "SELECT username FROM auth.users WHERE role = \'admin\'";\n',
                 '// "UPDATE auth.users SET role = $1"\n'):
        if any(population_write_count(l) for l in literals(text)):
            raise SystemExit(f"selfcheck: the population-write scan over-matched: {text!r}")
    for text in ("#define " + FRAGMENT + " \"FROM x\"\n",
                 "static const char* " + FRAGMENT + " = \"FROM x\";\n"):
        if not DEFINITION.search(code(text)):
            raise SystemExit("selfcheck: an alternative definition form was not counted")
    d = 'constexpr std::string_view ' + FRAGMENT + ' =\n    "FROM x";\n'
    if len(DEFINITION.findall(code(d))) != 1:
        raise SystemExit("selfcheck: definition pattern failed to match a definition")
    use = "auto s = std::string(" + FRAGMENT + ");\n"
    if DEFINITION.search(code(use)):
        raise SystemExit("selfcheck: definition pattern wrongly matched a use")
    if DEFINITION.search(code("// constexpr " + FRAGMENT + " = 1;\n")):
        raise SystemExit("selfcheck: definition pattern wrongly matched a comment")


def main() -> int:
    _selfcheck()
    failures = []

    files = subprocess.run(
        ["git", "ls-files", "--", "server/core/src"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    store_files = [f for f in files if f.startswith(STORE_PREFIX) and f.endswith((".cpp", ".hpp"))]
    if STORE not in store_files:
        failures.append(f"{STORE} is not tracked; the seam scan has nothing to check")
    for rel in store_files:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lit in literals(text):
            hit = foreign_match(lit)
            if hit:
                failures.append(
                    f"{rel}: string literal references the auth schema ({hit!r}); "
                    f"cross-schema SQL belongs in {OWNER} (ADR-0012 s3)"
                )
    # Rule 2: the mirror of rule 1. Also scans the public header, which lives outside src/.
    auth_files = [
        f for f in subprocess.run(
            ["git", "ls-files", "--", "server/core/src", "server/core/include"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        if f.startswith(AUTH_PREFIXES) and f.endswith((".cpp", ".hpp"))
    ]
    if "server/core/src/auth_db.cpp" not in auth_files:
        failures.append("server/core/src/auth_db.cpp is not tracked; the seam scan has nothing to check")
    for rel in auth_files:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lit in literals(text):
            hit = foreign_match(lit, FOREIGN_RBAC)
            if hit:
                failures.append(
                    f"{rel}: string literal references the rbac_store schema ({hit!r}); "
                    f"cross-schema SQL belongs in {OWNER} (ADR-0012 s3)"
                )
    # Rule 4: ONE active-local-admin predicate literal under server/.
    pred_sites = []
    unguarded_calls = []
    population_writes = []
    for rel in subprocess.run(
        ["git", "ls-files", "--", "server"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines():
        if not rel.endswith((".cpp", ".hpp", ".h", ".cc")):
            continue
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lit in literals(text):
            pred_sites.extend([rel] * admin_predicate_count(lit))
        if rel.startswith(UNGUARDED_CALL_ROOTS) and rel not in UNGUARDED_CALL_ALLOWED:
            for _ in UNGUARDED_CALL.findall(code(text)):
                unguarded_calls.append(rel)
        for lit in literals(text):
            population_writes.extend([rel] * population_write_count(lit))
    if pred_sites != [ADMIN_PREDICATE_FILE]:
        failures.append(
            "the active-local-admin predicate (role = 'admin' AND is_active) must be exactly one "
            f"string literal under server/, in {ADMIN_PREDICATE_FILE} (kActiveLocalAdminPredicate); "
            f"found {pred_sites!r}"
        )
    if unguarded_calls:
        failures.append(
            "AuthDB::remove_user / update_role are UNGUARDED fixture primitives; production must "
            "use AuthManager::remove_user_checked / update_role_checked (#4966). Called (through a "
            "receiver containing `db`, or a `(*...)` dereference) from: "
            f"{sorted(set(unguarded_calls))!r}"
        )
    if population_writes != [POPULATION_WRITE_FILE] * len(population_writes) or not population_writes:
        failures.append(
            "a users-table UPDATE that assigns role / sets is_active to FALSE, 0 or a bound parameter, "
            "and any DELETE FROM users, may appear only in "
            f"{POPULATION_WRITE_FILE} (the soft delete and role write the owner and AuthDB share); "
            f"found {sorted(set(population_writes))!r} ({len(population_writes)} site(s))"
        )
    defs = []
    for rel in files:
        if not rel.endswith((".cpp", ".hpp", ".h", ".cc")):
            continue
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for _ in DEFINITION.findall(code(text)):
            defs.append(rel)
    if defs != [OWNER]:
        failures.append(
            f"{FRAGMENT} must be defined exactly once, in {OWNER}; found {defs!r}"
        )

    if failures:
        print("FAIL: the RBAC cross-schema query-owner seam regressed (ADR-0012 s3):")
        print("\n".join("  " + f for f in failures))
        return 1
    print(f"OK: no auth. SQL in {len(store_files)} rbac_store* file(s); no rbac_store. SQL in "
          f"{len(auth_files)} auth_db* file(s); {FRAGMENT} defined once, in {OWNER}; "
          f"active-admin predicate defined once, in {ADMIN_PREDICATE_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
