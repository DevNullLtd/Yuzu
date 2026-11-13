#!/usr/bin/env python3
"""Lexical tripwire for the durable-session account gate wiring (#7223).

The behavioural tests (tests/unit/server/test_session_account_active.cpp and the deactivation
cases in test_rbac_account_lifecycle_guard.cpp) drive the real code, so they catch a broken
guarantee. This gate pins the SHAPE of the six places the guarantee hangs on, so a refactor that
moves one of them fails here with a pointer to the rule. It is a BEST-EFFORT tripwire over
comment-stripped text, not a proof.

  (i)   exactly one SQL string literal under server/ writes `is_active = FALSE` (the soft delete in
        auth_db_sql_helpers.hpp). A second writer would deactivate an account without the owner's
        generation bump. A comment that names the text does not count (comments are dropped).
  (ii)  `RbacAdminAuthorityOwner::deactivate_account` calls `session_sql::bump_generation_in_txn`
        under `SessionGenerationMode::kBumpSessionGeneration`, AFTER the soft delete.
  (iii) auth.cpp mentions `SessionGenerationMode::kNoSessionStore` once, and only inside the exact
        shape `session_store_ ? SessionGenerationMode::kBumpSessionGeneration :
        SessionGenerationMode::kNoSessionStore`: the mode follows whether a SessionStore is
        wired, and a bare no-store literal at a production call site would silently skip the bump.
        The ternary is the one allowed shape; it needs no helper.
  (iv)  every session built from a store row passes ONE gate: in `validate_session_durable` each
        `session_from_row(` is followed by `from_store = true;`, and the single
        `if (from_store && !session_account_admits(key, *session_copy)) return std::nullopt;`
        comes after the last of them, after the idle re-read's expiry test, and before the cache
        insert. The account read (`auth_db_->user_exists(`) lives only in
        `session_account_admits`, which counts a degrade, closes on `auth_source` (three
        comparisons) and erases the cached entry on every refusal (`if (!admit)`).
  (v)   the validate tail's cache insert is the only `sessions_[key] = *session_copy` and is
        guarded by `session_cache_epoch_ == cache_epoch`.
  (vi)  the cache epoch is incremented in the same block as the single `sessions_.clear()`.

Comments and string-literal contents are excluded from every scan except (i), which reads
literals on purpose. Wired into tests/meson.build (suite 'docs') and docs-lint.yml.
"""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AUTH = "server/core/src/auth.cpp"
OWNER = "server/core/src/rbac_admin_authority_owner.cpp"
SOFT_DELETE_FILE = "server/core/src/auth_db_sql_helpers.hpp"

_spec = importlib.util.spec_from_file_location(
    "owner_seam_lexer", Path(__file__).resolve().parent / "test_rbac_query_owner_seam.py"
)
_lexer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lexer)  # defines functions only; its main() is guarded


def squash(text: str) -> str:
    """Comment-free code with literals removed and whitespace collapsed."""
    return re.sub(r"\s+", " ", _lexer.code(text)).strip()


def function_body(src: str, signature: str):
    """The balanced `{...}` body following the first occurrence of `signature`, or None."""
    i = src.find(signature)
    if i == -1:
        return None
    j = src.find("{", i)
    if j == -1:
        return None
    depth = 0
    for k in range(j, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[j:k + 1]
    return None


SOFT_FALSE = re.compile(r"\bis_active\s*=\s*FALSE\b", re.IGNORECASE)
TERNARY = ("session_store_ ? SessionGenerationMode::kBumpSessionGeneration : "
           "SessionGenerationMode::kNoSessionStore")


def check_soft_delete_literals(files):
    """(i): `files` maps path -> text. Returns failure strings."""
    hits = []
    for rel, text in files.items():
        for lit in _lexer.literals(text):
            if SOFT_FALSE.search(_lexer.strip_sql_comments(lit)):
                hits.append(rel)
    if len(hits) != 1 or hits[0] != SOFT_DELETE_FILE:
        return [f"(i) expected exactly one SQL literal setting is_active = FALSE, in "
                f"{SOFT_DELETE_FILE}; found in: {hits or 'none'}"]
    return []


def check_owner(owner_src: str):
    """(ii)."""
    body = function_body(squash(owner_src), "RbacAdminAuthorityOwner::deactivate_account(")
    if body is None:
        return ["(ii) RbacAdminAuthorityOwner::deactivate_account not found"]
    bump = re.search(r"session_mode == SessionGenerationMode::kBumpSessionGeneration && "
                     r"!session_sql::bump_generation_in_txn\(c\)", body)
    soft = body.find("soft_delete_user_in_txn(")
    if body.count("session_sql::bump_generation_in_txn(") != 1 or not bump:
        return ["(ii) deactivate_account must call session_sql::bump_generation_in_txn exactly "
                "once, under SessionGenerationMode::kBumpSessionGeneration"]
    if soft == -1 or bump.start() < soft:
        return ["(ii) the session generation bump must come after the soft delete"]
    return []


def check_auth(auth_src: str):
    """(iii)-(vi)."""
    fails = []
    flat = squash(auth_src)
    # (iii)
    if flat.count("kNoSessionStore") != 1 or TERNARY not in flat:
        fails.append("(iii) auth.cpp must name kNoSessionStore only in the exact ternary: "
                     f"`{TERNARY}`")
    body = function_body(flat, "AuthManager::validate_session_durable(")
    if body is None:
        return fails + ["(iv) validate_session_durable not found"]
    # (iv)
    gates = [m.start() for m in re.finditer(r"session_account_admits\(", body)]
    rows = [m.start() for m in re.finditer(r"session_from_row\(", body)]
    call = re.search(r"if \(from_store && !session_account_admits\(key, \*session_copy\)\) "
                     r"\{? ?return std::nullopt;", body)
    last_expiry = body.rfind("if (expired_now(*session_copy))")
    insert = body.find("sessions_[key] = *session_copy;")
    if (len(gates) != 1 or not call or not rows or last_expiry == -1 or insert == -1
            or "user_exists(" in body
            or body.count("from_store = true;") != len(rows)
            or not (rows[-1] < last_expiry < gates[0] < insert)):
        fails.append("(iv) validate_session_durable must pass every store-built session through "
                     "exactly one `if (from_store && !session_account_admits(key, *session_copy)) "
                     "return std::nullopt;`, after the last session_from_row and its expiry test, "
                     "before the cache insert, with `from_store = true;` after each "
                     "session_from_row and no user_exists call of its own")
    helper = function_body(flat, "AuthManager::session_account_admits(")
    if helper is None:
        fails.append("(iv) AuthManager::session_account_admits not found")
    else:
        refuse = re.search(r"if \(!admit\) \{[^}]*sessions_\.erase\(key\);", helper)
        if (helper.count("auth_db_->user_exists(") != 1
                or "note_session_store_degrade(" not in helper
                or helper.count("auth_source ==") != 3
                or not refuse or "return admit;" not in helper):
            fails.append("(iv) session_account_admits must call auth_db_->user_exists exactly "
                         "once, count a store degrade, compare auth_source exactly three times "
                         "(local, oidc, saml), erase the cached entry under `if (!admit)` and "
                         "return admit")
    # (v)
    inserts = re.findall(r"sessions_\[key\] = \*session_copy;", body)
    guarded = re.findall(
        r"if \( ?session_cache_epoch_ == cache_epoch\) sessions_\[key\] = \*session_copy;", body)
    if len(inserts) != 1 or len(guarded) != 1:
        fails.append("(v) the validate tail's cache insert must be the only "
                     "`sessions_[key] = *session_copy` and be guarded by "
                     "`if (session_cache_epoch_ == cache_epoch)`")
    # (vi)
    if flat.count("sessions_.clear();") != 1 or "sessions_.clear(); ++session_cache_epoch_;" not in flat:
        fails.append("(vi) the single sessions_.clear() must be followed by "
                     "`++session_cache_epoch_;` in the same block")
    return fails


def _selfcheck() -> None:
    # Explicit raises, not `assert`: python3 -O strips asserts.
    soft_ok = {SOFT_DELETE_FILE: 'x = "UPDATE auth.users SET is_active = FALSE WHERE a";\n'}
    if check_soft_delete_literals(soft_ok):
        raise SystemExit("selfcheck: (i) rejected the good shape")
    if not check_soft_delete_literals({**soft_ok, "a.cpp": 'y = "UPDATE auth.users SET is_active = FALSE";'}):
        raise SystemExit("selfcheck: (i) missed a second literal writer")
    if check_soft_delete_literals({**soft_ok, "a.cpp": "// is_active = FALSE in a comment\n"}):
        raise SystemExit("selfcheck: (i) counted a comment")
    owner = ("AccountDeactivationResult\nRbacAdminAuthorityOwner::deactivate_account(const std::string& u,"
             " SessionGenerationMode session_mode) const { auto s = auth_sql::soft_delete_user_in_txn(c, u, e);"
             " if (session_mode == SessionGenerationMode::kBumpSessionGeneration &&\n"
             " !session_sql::bump_generation_in_txn(c)) { return false; } return true; }\n")
    if check_owner(owner):
        raise SystemExit("selfcheck: (ii) rejected the good shape")
    if not check_owner(owner.replace("kBumpSessionGeneration &&", "kNoSessionStore &&")):
        raise SystemExit("selfcheck: (ii) missed a wrong mode")
    if not check_owner(owner.replace("soft_delete_user_in_txn(c, u, e);",
                                     "x;").replace("return true; }", "auth_sql::soft_delete_user_in_txn(c,u,e); return true; }")):
        raise SystemExit("selfcheck: (ii) missed a bump before the soft delete")
    auth = ("auto r = rbac_store_->deactivate_account(u, session_store_ ? SessionGenerationMode::kBumpSessionGeneration"
            " : SessionGenerationMode::kNoSessionStore);\n"
            "void f() { sessions_.clear();\n ++session_cache_epoch_; }\n"
            "bool AuthManager::session_account_admits(const std::string& key, const Session& s) const {\n"
            " bool admit = false;\n"
            " if (s.auth_source == \"local\") { if (!auth_db_) { admit = true; } else {\n"
            "  auto a = auth_db_->user_exists(s.username);\n"
            "  if (!a) { note_session_store_degrade(op); } else if (!*a) { x(); } else { admit = true; } }\n"
            " } else if (s.auth_source == \"oidc\" || s.auth_source == \"saml\") { admit = true; }\n"
            " else { y(); }\n"
            " if (!admit) { std::unique_lock w(mu_); sessions_.erase(key); }\n"
            " return admit; }\n"
            "std::optional<Session> AuthManager::validate_session_durable(const std::string& t) const {\n"
            " auto s = session_from_row(row, now); from_store = true;\n"
            " if (expired_now(*session_copy)) { return std::nullopt; }\n"
            " if (from_store && !session_account_admits(key, *session_copy))\n"
            "  return std::nullopt;\n"
            " { std::unique_lock w(mu_); if (session_cache_epoch_ == cache_epoch)\n"
            "   sessions_[key] = *session_copy; }\n return session_copy; }\n")
    if check_auth(auth):
        raise SystemExit(f"selfcheck: (iii)-(vi) rejected the good shape: {check_auth(auth)}")
    bad = {
        "(iii) bare literal": auth.replace(TERNARY, "SessionGenerationMode::kNoSessionStore"),
        "(iii) second mention": auth + "x(SessionGenerationMode::kNoSessionStore);\n",
        "(iv) gate call removed": auth.replace(
            "if (from_store && !session_account_admits(key, *session_copy))\n  return std::nullopt;",
            ""),
        "(iv) gate before the expiry test": auth.replace(
            "if (from_store && !session_account_admits(key, *session_copy))\n  return std::nullopt;\n",
            "").replace(
            " if (expired_now(*session_copy)) { return std::nullopt; }\n",
            " if (from_store && !session_account_admits(key, *session_copy))\n"
            "  return std::nullopt;\n if (expired_now(*session_copy)) { return std::nullopt; }\n"),
        "(iv) a store row not marked from_store": auth.replace(" from_store = true;\n", "\n"),
        "(iv) account read outside the helper": auth.replace(
            " auto s = session_from_row(row, now);",
            " auto q = auth_db_->user_exists(n); auto s = session_from_row(row, now);"),
        "(iv) no erase on refusal": auth.replace("sessions_.erase(key);", ""),
        "(iv) fourth source arm": auth.replace('s.auth_source == "oidc"',
                                               's.auth_source == "x" || s.auth_source == "oidc"'),
        "(v) epoch guard removed": auth.replace("if (session_cache_epoch_ == cache_epoch)", ""),
        "(vi) increment removed": auth.replace("++session_cache_epoch_;", ""),
        "(vi) increment moved": auth.replace("sessions_.clear();\n ++session_cache_epoch_;",
                                             "sessions_.clear(); foo(); ++session_cache_epoch_;"),
    }
    for name, text in bad.items():
        if not check_auth(text):
            raise SystemExit(f"selfcheck: the scan missed: {name}")


def main() -> int:
    _selfcheck()
    tracked = subprocess.run(
        ["git", "ls-files", "--", "server"], cwd=REPO_ROOT, capture_output=True, text=True,
        check=True,
    ).stdout.splitlines()
    sources = {f: (REPO_ROOT / f).read_text(encoding="utf-8", errors="replace")
               for f in tracked if f.endswith((".cpp", ".hpp"))}
    failures = []
    failures += check_soft_delete_literals(sources)
    for rel, check in ((OWNER, check_owner), (AUTH, check_auth)):
        if rel not in sources:
            failures.append(f"{rel} is not tracked; nothing to check")
        else:
            failures += check(sources[rel])
    if failures:
        print("FAIL: the session account gate wiring changed shape (#7223):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("OK: session account gate wiring intact (soft-delete literal, owner bump, mode ternary, "
          "gate position, epoch guard and increment)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
