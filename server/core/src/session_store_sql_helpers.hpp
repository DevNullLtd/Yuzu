#pragma once

/// @file session_store_sql_helpers.hpp
/// Internal OWN-SCHEMA libpq helpers shared by `SessionStore` (session_store.cpp)
/// and the ADR-0012 §3 query owners `CredentialChangeOwner`
/// (credential_change_owner.cpp, #5342) and `RbacAdminAuthorityOwner` (`deactivate_account` calls
/// `bump_generation_in_txn`; the user Administrator `unassign_role` calls
/// `lock_user_session_rows_in_txn`, `clear_user_elevations_in_txn` and `bump_generation_in_txn`),
/// mirroring rbac_store_sql_helpers.hpp's role for `RbacStore`/`RbacAdminAuthorityOwner`: one
/// definition of each statement, with ONE known exception: the statement in
/// `clear_user_elevations_in_txn` is also written out in `SessionStore::clear_user_elevations`
/// (session_store.cpp), see the note on that helper. Not a public API. Every function runs on the
/// CALLER's already-open transaction (`PGconn*` from `with_txn_for`) and issues only
/// `session_store`-schema SQL; cross-schema SQL never belongs here.
///
/// Lock note for callers: `bump_generation_in_txn` takes the row lock on the
/// single `session_store.session_meta` `write_generation` row and holds it to
/// the caller's COMMIT. Every session create/revoke takes that same row, so a
/// caller that holds it must not then WAIT on ANY other lock: whatever it waits
/// on, every session writer in the fleet waits behind it. Take it LAST, right
/// before COMMIT. `CredentialChangeOwner` therefore runs
/// `delete_user_sessions_in_txn` early and `bump_generation_in_txn` only after
/// its audit INSERTs — order `auth.users` row → `session_store.sessions` rows →
/// `audit_store.audit_events` (INSERT) → this row → COMMIT (#5342 Gate 8 T1′:
/// with the bump before the audit INSERT, a lock held on `audit_events` stalled
/// every unrelated session create/revoke). No session writer takes any other
/// schema's lock, which keeps that order acyclic. `RbacAdminAuthorityOwner::deactivate_account`
/// takes it last too (`rbac_enabled` → grant rows → one `auth.users` row → this row →
/// COMMIT).
///
/// A cross-schema caller that must revoke a user's elevation inside its own transaction
/// (today only the user Administrator unassign in `RbacAdminAuthorityOwner`) uses
/// `lock_user_session_rows_in_txn`, then `clear_user_elevations_in_txn`,
/// and calls `bump_generation_in_txn` LAST. Required order: `principal_roles` rows → one
/// `auth.users` row (when taken) → the target's `session_store.sessions` rows (ordered by
/// `token_hash`) → the RBAC `rbac_meta` write-generation → this `session_meta` row →
/// COMMIT. The sessions rows are a lock class the grant path did not previously take.
/// Single-row session writers take one sessions row and then only `session_meta`, so the
/// order stays acyclic; two multi-row writers on one user's rows (`invalidate_user`, the
/// reaper's DELETE, `delete_user_sessions_in_txn`, `SessionStore::clear_user_elevations`, which
/// the eligibility revoke runs) can still deadlock on row order, and
/// Postgres aborts one victim, which the caller's rollback turns into a retryable failure.
/// There is no per-user cap on session rows, so the row lock and the clear touch as many rows as
/// the user holds; that count is bounded only by the 8 h absolute session lifetime
/// (`AuthManager::kSessionDuration`), the session reaper and the per-IP login rate limit, and
/// was not measured.

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::session_sql {

/// Bump the durable write-generation IN THE CALLER'S TXN. Every authz-affecting
/// session mutation calls this so a replica's validate-cache sees the change on
/// its next generation refresh. Mirrors `rbac_sql::bump_generation_in_txn`.
inline bool bump_generation_in_txn(PGconn* c) {
    pg::PgResult r = pg::exec_params(
        c,
        "INSERT INTO session_store.session_meta (key, value) VALUES ('write_generation', '1') "
        "ON CONFLICT (key) DO UPDATE SET value = "
        "(session_store.session_meta.value::bigint + 1)::text",
        std::vector<std::string>{});
    return r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK;
}

/// Take a row lock on EVERY durable session row of `username`, IN THE CALLER'S TXN,
/// with NO elevation predicate and in `token_hash` order. Purpose: block a concurrent
/// `SessionStore::set_elevation` (or any other writer) on an EXISTING row until the
/// caller commits, so a following `clear_user_elevations_in_txn` (a SEPARATE statement,
/// which takes a fresh READ COMMITTED snapshot) cannot miss an elevation that commits
/// between the caller's earlier statements and the clear. It does not stop a later
/// elevation or a newly created session. Succeeds (true) when the user has no
/// sessions. On a statement failure sets `err` and returns false; the caller must then
/// abort its transaction. Does not touch `session_meta`: see the lock note above.
inline bool lock_user_session_rows_in_txn(PGconn* c, const std::string& username,
                                          std::string& err) {
    pg::PgResult r = pg::exec_params(c,
                                     "SELECT token_hash FROM session_store.sessions "
                                     "WHERE username=$1 ORDER BY token_hash FOR UPDATE",
                                     std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        err = std::string("session row lock failed: ") + PQerrorMessage(c);
        return false;
    }
    return true;
}

/// Zero both elevation columns of every session of `username` whose
/// `elevated_until_ms` is nonzero, IN THE CALLER'S TXN, WITHOUT bumping the
/// write-generation. Returns the number of rows changed, or nullopt (with `err` set)
/// on a statement failure; the caller must then abort its transaction. The predicate
/// is `<>0`, so an EXPIRED but not yet reaped (nonzero) window is matched and counted: the
/// count is the number of session rows that held a nonzero window, not of windows still live.
/// A caller that sees a count above zero MUST call `bump_generation_in_txn`, LAST,
/// before it commits (see the lock note above); a 0-row clear needs no bump.
/// NOTE: this duplicates the statement in `SessionStore::clear_user_elevations`
/// (session_store.cpp), which keeps its own copy and its own bump; keep the two in step.
inline std::optional<int> clear_user_elevations_in_txn(PGconn* c, const std::string& username,
                                                       std::string& err) {
    pg::PgResult r = pg::exec_params(
        c,
        "UPDATE session_store.sessions SET elevated_until_ms=0, elevation_issued_ms=0 "
        "WHERE username=$1 AND elevated_until_ms<>0 RETURNING token_hash",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        err = std::string("session elevation clear failed: ") + PQerrorMessage(c);
        return std::nullopt;
    }
    return PQntuples(r.get());
}

/// Delete every durable session of `username`, IN THE CALLER'S TXN, WITHOUT
/// bumping the write-generation. Returns the number of sessions deleted, or
/// nullopt (with `err` set) on a statement failure — the caller must then abort
/// its transaction. The ONE copy of the delete-by-user statement: used alone by
/// `CredentialChangeOwner::commit` (which bumps the generation itself, LAST —
/// see the lock note above) and inside `invalidate_user_in_txn`. A caller of
/// this alone MUST still call `bump_generation_in_txn` before it commits, or a
/// replica's validate-cache never learns the sessions are gone.
inline std::optional<int> delete_user_sessions_in_txn(PGconn* c, const std::string& username,
                                                      std::string& err) {
    pg::PgResult r = pg::exec_params(
        c, "DELETE FROM session_store.sessions WHERE username=$1 RETURNING token_hash",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        err = std::string("session delete-by-user failed: ") + PQerrorMessage(c);
        return std::nullopt;
    }
    return PQntuples(r.get());
}

/// Delete every durable session of `username` and bump the write-generation, IN
/// THE CALLER'S TXN — the composite `SessionStore::invalidate_user` runs in its
/// own transaction. Returns the number of sessions deleted, or nullopt (with
/// `err` set) on any statement failure. Always bumps, even on a 0-row delete
/// (the historical `invalidate_user` behaviour, kept byte-identical).
inline std::optional<int> invalidate_user_in_txn(PGconn* c, const std::string& username,
                                                 std::string& err) {
    const auto count = delete_user_sessions_in_txn(c, username, err);
    if (!count)
        return std::nullopt;
    if (!bump_generation_in_txn(c)) {
        err = std::string("session write-generation bump failed: ") + PQerrorMessage(c);
        return std::nullopt;
    }
    return count;
}

} // namespace yuzu::server::session_sql
