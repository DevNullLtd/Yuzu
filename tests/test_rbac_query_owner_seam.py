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
     (`is_active AND role = 'admin'`), an aliased copy (`u.role = 'admin' AND u.is_active`) and
     `role IN ('admin')`. A copy that splits the predicate across statements is NOT seen by this
     textual scan.
  5. An unguarded fixture primitive is called from production code. `AuthDB::remove_user` and
     `AuthDB::update_role` write the soft delete / role column WITHOUT the last-Administrator
     guard (they exist for fixtures; production goes through `AuthManager::remove_user_checked` /
     `update_role_checked`). No file under server/core/src other than `auth_db.cpp` may call
     either through a `db` / `auth_db` / `auth_db_` / `auth_db_ptr()` receiver.
  6. A statement that decreases the guarded populations is written outside the shared helpers:
     `UPDATE auth.users SET is_active = FALSE` and `UPDATE auth.users SET role = ...` may appear
     only in `auth_db_sql_helpers.hpp` (the soft delete and the role write the owner and `AuthDB`
     share). `SET is_active = TRUE` (reactivation) is deliberately not in scope: it can only
     GROW the population.

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
# `is_active = TRUE`, and a one-element `role IN ('admin')`.
_COL = r"(?:\w+\.)?"
ADMIN_PREDICATES = (
    re.compile(_COL + r"role\s*=\s*'admin'\s+AND\s+" + _COL + r"is_active\b", re.IGNORECASE),
    re.compile(_COL + r"is_active\b(?:\s*=\s*(?:TRUE|1))?\s+AND\s+" + _COL + r"role\s*=\s*'admin'",
               re.IGNORECASE),
    re.compile(_COL + r"role\s+IN\s*\(\s*'admin'\s*\)", re.IGNORECASE),
)
ADMIN_PREDICATE_FILE = "server/core/src/auth_db_sql_helpers.hpp"


def admin_predicate_count(lit: str) -> int:
    return sum(len(p.findall(lit)) for p in ADMIN_PREDICATES)


# Rule 5: a production call of an unguarded fixture primitive.
UNGUARDED_CALL = re.compile(
    r"\b(?:auth_db_?|auth_db_ptr\s*\(\s*\)|db)\s*(?:->|\.)\s*(?:remove_user|update_role)\s*\("
)
UNGUARDED_CALL_ALLOWED = ("server/core/src/auth_db.cpp",)
# Rule 6: a statement that can SHRINK the guarded populations.
POPULATION_WRITE = re.compile(
    r"UPDATE\s+auth\.users\s+SET\s+(?:is_active\s*=\s*(?:FALSE|0)\b|role\s*=)", re.IGNORECASE
)
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
    }.items():
        if admin_predicate_count(text) != 1:
            raise SystemExit(f"selfcheck: the admin-predicate scan missed: {name}")
    # ... and an unrelated literal is not.
    for text in ("x WHERE role = 'user' AND is_active", "x WHERE role = $1 AND is_active",
                 "x WHERE is_active AND role = $1", "role IN ('admin', 'user')"):
        if admin_predicate_count(text) != 0:
            raise SystemExit(f"selfcheck: the admin-predicate scan over-matched: {text!r}")
    # Rule 5: the unguarded-primitive call scan finds the receivers it names and ignores the
    # guarded API, comments and fixtures spelled through AuthManager.
    for text in ("db->remove_user(u);", "auth_db_->update_role(u, r);", "auth_db.remove_user(u);",
                 "auth_db_ptr()->update_role(u, r);", "x = db ->  remove_user (u);"):
        if not UNGUARDED_CALL.search(code(text + "\n")):
            raise SystemExit(f"selfcheck: the unguarded-call scan missed: {text!r}")
    for text in ("auth_mgr_->remove_user_checked(u);", "auth_mgr.update_role_checked(u, r);",
                 "auth_mgr_->remove_user(u);", "// db->remove_user(u);", "mydb->remove_user(u);"):
        if UNGUARDED_CALL.search(code(text + "\n")):
            raise SystemExit(f"selfcheck: the unguarded-call scan over-matched: {text!r}")
    # Rule 6: a shrinking write is found in a literal, a growing one and a comment are not.
    if sum(len(POPULATION_WRITE.findall(l)) for l in literals(
            'a = "UPDATE auth.users SET is_active = FALSE WHERE x"; b = "UPDATE auth.users SET role = $1";\n')) != 2:
        raise SystemExit("selfcheck: the population-write scan missed a shrinking write")
    for text in ('a = "UPDATE auth.users SET is_active = TRUE WHERE x";\n',
                 'a = "UPDATE auth.users SET last_login_at = now()";\n',
                 '// "UPDATE auth.users SET role = $1"\n'):
        if any(POPULATION_WRITE.search(l) for l in literals(text)):
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
        if rel.startswith("server/core/src/") and rel not in UNGUARDED_CALL_ALLOWED:
            for _ in UNGUARDED_CALL.findall(code(text)):
                unguarded_calls.append(rel)
        for lit in literals(text):
            for _ in POPULATION_WRITE.findall(lit):
                population_writes.append(rel)
    if pred_sites != [ADMIN_PREDICATE_FILE]:
        failures.append(
            "the active-local-admin predicate (role = 'admin' AND is_active) must be exactly one "
            f"string literal under server/, in {ADMIN_PREDICATE_FILE} (kActiveLocalAdminPredicate); "
            f"found {pred_sites!r}"
        )
    if unguarded_calls:
        failures.append(
            "AuthDB::remove_user / update_role are UNGUARDED fixture primitives; production must "
            "use AuthManager::remove_user_checked / update_role_checked (#4966). Called from: "
            f"{sorted(set(unguarded_calls))!r}"
        )
    if population_writes != [POPULATION_WRITE_FILE] * len(population_writes) or not population_writes:
        failures.append(
            "`UPDATE auth.users SET is_active = FALSE` / `SET role =` may appear only in "
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
