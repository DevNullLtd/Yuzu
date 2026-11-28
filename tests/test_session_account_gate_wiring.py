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
        comparisons) and erases the cached entry on every refusal (`if (!admit)`, through the epoch helper).
  (v)   the validate tail's cache insert is the only `sessions_[key] = *session_copy` and is
        guarded by `session_cache_epoch_ == cache_epoch`.
  (vi)  the cache epoch is incremented in the same block as the single `sessions_.clear()`.
  (vii) in `validate_session_durable` the `cache_epoch = session_cache_epoch_;` capture appears
        BEFORE the first `session_store_->find(`: a capture taken after the store read would let
        a revoke that landed in between go unnoticed by the guarded insert.
  (viii) targeted erases go through the epoch-advancing helpers: the two helpers each pair the
        erase with `++session_cache_epoch_;`, and `sessions_.erase(` / `erase_if(sessions_` appear
        nowhere else in auth.cpp except the cache-hygiene drops in `validate_session` and
        `validate_session_durable` (expired or idle entries, not a revocation).

  (ix)  `RbacAdminAuthorityOwner::unassign_role` ends the target's durable elevation in its own
        transaction, in the one safe order: `set_txn_timeouts` BEFORE the first lock, then
        `session_sql::lock_user_session_rows_in_txn`, then `session_sql::clear_user_elevations_in_txn`,
        then the RBAC `bump_generation_in_txn(c)`, then exactly ONE `session_sql::bump_generation_in_txn`
        (session_meta LAST, nothing after it). The owner body names no `session_store.` SQL literal:
        every session statement goes through the `session_sql::` helpers.
  (x)   production code never calls the test-only opt-out `use_no_session_store_for_test(`
        (everything under server/ except the declaration in rbac_store.hpp): a production
        RbacStore in `kNoSessionStore` mode would answer an Administrator unassign with success
        while the elevation survives. Also: `server.cpp` never names `kNoSessionStore`.

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


def check_unassign(owner_src: str):
    """(ix): the user Administrator unassign's elevation clear, in order."""
    # Comment-free text with each string literal replaced by a numbered placeholder, so braces
    # inside SQL cannot unbalance the body scan and the literals can still be inspected.
    lits, parts = [], []
    for kind, t in _lexer.tokenize(owner_src):
        if kind == "string":
            parts.append(f'"S{len(lits)}"')
            lits.append(t)
        else:
            parts.append(t)
    flat = re.sub(r"\s+", " ", "".join(parts)).strip()
    body = function_body(flat, "RbacAdminAuthorityOwner::unassign_role(")
    if body is None:
        return ["(ix) RbacAdminAuthorityOwner::unassign_role not found"]
    fails = []
    for k in {int(m) for m in re.findall(r'"S(\d+)"', body)}:
        if re.search(r"\bsession_store\.", lits[k]):
            fails.append("(ix) unassign_role names a `session_store.` SQL literal: every session "
                         "statement belongs in session_store_sql_helpers.hpp (session_sql::)")
            break
    timeouts = body.find("set_txn_timeouts(")
    first_lock = body.find("lock_authenticatable_admin_grants(")
    lock = body.find("session_sql::lock_user_session_rows_in_txn(")
    clear = body.find("session_sql::clear_user_elevations_in_txn(")
    rbac_bumps = [m.start() for m in re.finditer(r"(?<!session_sql::)bump_generation_in_txn\(c\)", body)]
    session_bumps = [m.start() for m in re.finditer(r"session_sql::bump_generation_in_txn\(c\)", body)]
    if (body.count("set_txn_timeouts(") != 1 or first_lock == -1 or timeouts > first_lock):
        fails.append("(ix) unassign_role must call set_txn_timeouts exactly once, before the "
                     "first lock (lock_authenticatable_admin_grants)")
    if (body.count("session_sql::lock_user_session_rows_in_txn(") != 1
            or body.count("session_sql::clear_user_elevations_in_txn(") != 1
            or not (first_lock < lock < clear)):
        fails.append("(ix) unassign_role must call session_sql::lock_user_session_rows_in_txn "
                     "then session_sql::clear_user_elevations_in_txn, once each, after the "
                     "grant lock")
    if len(rbac_bumps) != 1 or len(session_bumps) != 1 or body.count("bump_generation_in_txn(") != 2:
        fails.append("(ix) unassign_role must call the RBAC bump_generation_in_txn(c) exactly "
                     "once and session_sql::bump_generation_in_txn(c) exactly once")
    elif not (clear < rbac_bumps[0] < session_bumps[0]):
        fails.append("(ix) order must be: clear elevations, RBAC bump, then the session_meta "
                     "bump LAST")
    else:
        tail = body[session_bumps[0] + len("session_sql::bump_generation_in_txn(c)"):]
        end = tail.find("});")
        tail = tail if end == -1 else tail[:end]
        if end == -1 or re.search(r"exec_params\(|_in_txn\(|lock_\w*\(|with_txn", tail):
            fails.append("(ix) nothing may follow the session_meta bump but its own failure "
                         "branch and `return true;`: session_meta is the lock every session "
                         "writer shares, so no statement may wait after it")
    return fails


FOR_TEST_OPT_OUT = re.compile(r"\buse_no_session_store_for_test\s*\(")


def check_no_production_opt_out(files):
    """(x): `files` maps path -> text. The opt-out is declared in rbac_store.hpp and called only
    by tests (tests/ is not scanned: this runs over server/ only); `server.cpp` never names
    kNoSessionStore."""
    fails = []
    for rel, text in files.items():
        if rel == "server/core/src/rbac_store.hpp":
            continue
        if FOR_TEST_OPT_OUT.search(_lexer.code(text)):
            fails.append(f"(x) {rel} calls use_no_session_store_for_test(): test-only, never "
                         "production")
    server = files.get("server/core/src/server.cpp")
    if server is not None and "kNoSessionStore" in _lexer.code(server):
        fails.append("(x) server.cpp must never name kNoSessionStore: production passes the "
                     "durable mode (the RbacStore default)")
    return fails


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
        refuse = re.search(r"if \(!admit\) \{[^}]*drop_cached_session_locked\(key\);", helper)
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
    # (vii)
    capture = body.find("cache_epoch = session_cache_epoch_;")
    first_find = body.find("session_store_->find(")
    if capture == -1 or first_find == -1 or capture > first_find:
        fails.append("(vii) in validate_session_durable `cache_epoch = session_cache_epoch_;` must "
                     "come before the first `session_store_->find(`")
    # (viii)
    one = function_body(flat, "AuthManager::drop_cached_session_locked(")
    many = function_body(flat, "AuthManager::drop_cached_user_sessions_locked(")
    if (one is None or many is None or "sessions_.erase(key); ++session_cache_epoch_;" not in one
            or "++session_cache_epoch_;" not in many or "erase_if(sessions_" not in many):
        fails.append("(viii) drop_cached_session_locked and drop_cached_user_sessions_locked must "
                     "each erase from sessions_ and advance ++session_cache_epoch_")
    else:
        rest = flat
        for sig in ("AuthManager::drop_cached_session_locked(",
                    "AuthManager::drop_cached_user_sessions_locked(",
                    "AuthManager::validate_session(", "AuthManager::validate_session_durable("):
            part = function_body(rest, sig)
            if part is not None:
                rest = rest.replace(part, "", 1)
        raw = len(re.findall(r"sessions_\.erase\(|erase_if\( ?sessions_", rest))
        if raw:
            fails.append(f"(viii) {raw} raw sessions_ erase(s) outside the epoch helpers and the "
                         "validate cache-hygiene drops: use drop_cached_session_locked / "
                         "drop_cached_user_sessions_locked")
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
    unassign = (
        'RbacAdminAuthorityOwner::UnassignOutcome\nRbacAdminAuthorityOwner::unassign_role(const std::string& t,'
        ' const std::string& p, const std::string& r, SessionGenerationMode m) const {\n'
        ' const bool ok = pool_.with_txn_for(w, [&](PGconn* c) -> bool {\n'
        '  if (u && !set_txn_timeouts(c, lt, err)) return false;\n'
        '  auto locked = lock_authenticatable_admin_grants(c, e);\n'
        '  pg::exec_params(c, "DELETE FROM rbac_store.principal_roles WHERE a", v);\n'
        '  if (x) { if (!session_sql::lock_user_session_rows_in_txn(c, p, err)) return false;\n'
        '   auto k = session_sql::clear_user_elevations_in_txn(c, p, err); if (!k) return false; }\n'
        '  new_gen = bump_generation_in_txn(c); if (!new_gen.has_value()) return false;\n'
        '  if (x && n > 0 && !session_sql::bump_generation_in_txn(c)) { err = "e"; return false; }\n'
        '  return true;\n });\n UnassignOutcome out{ok}; return out; }\n')
    if check_unassign(unassign):
        raise SystemExit(f"selfcheck: (ix) rejected the good shape: {check_unassign(unassign)}")
    bad_unassign = {
        "(ix) session_store literal": unassign.replace(
            '"DELETE FROM rbac_store.principal_roles WHERE a"',
            '"UPDATE session_store.sessions SET a"'),
        "(ix) no timeouts": unassign.replace("set_txn_timeouts(c, lt, err)", "true"),
        "(ix) timeouts after the lock": unassign.replace(
            "  if (u && !set_txn_timeouts(c, lt, err)) return false;\n", "").replace(
            "  pg::exec_params(", "  set_txn_timeouts(c, lt, err);\n  pg::exec_params(", 1),
        "(ix) lock removed": unassign.replace("session_sql::lock_user_session_rows_in_txn(c, p, err)", "true"),
        "(ix) clear before lock": unassign.replace(
            "session_sql::lock_user_session_rows_in_txn", "session_sql::TMP").replace(
            "session_sql::clear_user_elevations_in_txn", "session_sql::lock_user_session_rows_in_txn").replace(
            "session_sql::TMP", "session_sql::clear_user_elevations_in_txn"),
        "(ix) session bump before the RBAC bump": unassign.replace(
            "  new_gen = bump_generation_in_txn(c);",
            "  session_sql::bump_generation_in_txn(c); new_gen = bump_generation_in_txn(c);").replace(
            "!session_sql::bump_generation_in_txn(c)", "!true"),
        "(ix) second session bump": unassign.replace(
            "return true;\n });", "session_sql::bump_generation_in_txn(c); return true;\n });"),
        "(ix) statement after the session bump": unassign.replace(
            "return false; }\n  return true;", "return false; }\n  pg::exec_params(c, \"SELECT 1\", v);\n  return true;"),
    }
    for name, text in bad_unassign.items():
        if not check_unassign(text):
            raise SystemExit(f"selfcheck: the scan missed: {name}")
    if check_no_production_opt_out({"server/core/src/rbac_store.hpp": "void use_no_session_store_for_test() noexcept {}",
                                    "server/core/src/server.cpp": "// kNoSessionStore in a comment\nint x;"}):
        raise SystemExit("selfcheck: (x) rejected the good shape")
    if not check_no_production_opt_out({"server/core/src/server.cpp": "rbac_store_->use_no_session_store_for_test();"}):
        raise SystemExit("selfcheck: (x) missed a production call")
    if not check_no_production_opt_out({"server/core/src/server.cpp": "auto m = SessionGenerationMode::kNoSessionStore;"}):
        raise SystemExit("selfcheck: (x) missed kNoSessionStore in server.cpp")
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
            " if (!admit) { std::unique_lock w(mu_); drop_cached_session_locked(key); }\n"
            " return admit; }\n"
            "void AuthManager::drop_cached_session_locked(const std::string& key) const {\n"
            " sessions_.erase(key);\n ++session_cache_epoch_; }\n"
            "std::size_t AuthManager::drop_cached_user_sessions_locked(const std::string& u) const {\n"
            " std::erase_if(sessions_, pred);\n ++session_cache_epoch_; return 0; }\n"
            "std::optional<Session> AuthManager::validate_session_durable(const std::string& t) const {\n"
            " { std::shared_lock l(mu_); cache_epoch = session_cache_epoch_; }\n"
            " auto f = session_store_->find(key);\n"
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
        "(iv) no erase on refusal": auth.replace(
            " if (!admit) { std::unique_lock w(mu_); drop_cached_session_locked(key); }\n", ""),
        "(vii) capture after the store read": auth.replace(
            " { std::shared_lock l(mu_); cache_epoch = session_cache_epoch_; }\n", "").replace(
            " auto s = session_from_row(row, now);",
            " { std::shared_lock l(mu_); cache_epoch = session_cache_epoch_; }"
            " auto s = session_from_row(row, now);"),
        "(vii) capture removed": auth.replace(
            " { std::shared_lock l(mu_); cache_epoch = session_cache_epoch_; }\n", ""),
        "(viii) helper without the epoch bump": auth.replace(
            " sessions_.erase(key);\n ++session_cache_epoch_; }\n", " sessions_.erase(key); }\n"),
        "(viii) raw erase in a revoke path": auth + "void AuthManager::invalidate_session(t) {"
                                                    " sessions_.erase(key); }\n",
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
    failures += check_no_production_opt_out(sources)
    for rel, check in ((OWNER, check_owner), (OWNER, check_unassign), (AUTH, check_auth)):
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
          "gate position, epoch guard and increment, every targeted erase through the epoch "
          "helpers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
