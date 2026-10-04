#pragma once

/// @file session_store_sql_helpers.hpp
/// Internal OWN-SCHEMA libpq helpers shared by `SessionStore` (session_store.cpp)
/// and the ADR-0012 §3 query owner `CredentialChangeOwner`
/// (credential_change_owner.cpp, #5342), mirroring rbac_store_sql_helpers.hpp's
/// role for `RbacStore`/`RbacAdminAuthorityOwner`: ONE definition of each
/// statement, never a second copy. Not a public API. Every function runs on the
/// CALLER's already-open transaction (`PGconn*` from `with_txn_for`) and issues
/// only `session_store`-schema SQL; cross-schema SQL never belongs here.
///
/// Lock note for callers: `bump_generation_in_txn` takes the row lock on the
/// single `session_store.session_meta` `write_generation` row and holds it to
/// the caller's COMMIT. Every session create/revoke takes that same row, so a
/// caller that holds it must not then WAIT on a lock some session writer could
/// hold while waiting on `session_meta` (no session writer takes any other
/// schema's lock, which is what keeps `CredentialChangeOwner`'s order —
/// `auth.users` row, then `session_store` rows, then this row — acyclic).

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

/// Delete every durable session of `username` and bump the write-generation, IN
/// THE CALLER'S TXN. Returns the number of sessions deleted, or nullopt (with
/// `err` set) on any statement failure — the caller must then abort its
/// transaction. The ONE copy of "revoke every session of a user", shared by
/// `SessionStore::invalidate_user` (its own transaction) and
/// `CredentialChangeOwner::commit` (inside the credential-change transaction).
/// Always bumps, even on a 0-row delete (the historical `invalidate_user`
/// behaviour, kept byte-identical).
inline std::optional<int> invalidate_user_in_txn(PGconn* c, const std::string& username,
                                                 std::string& err) {
    pg::PgResult r = pg::exec_params(
        c, "DELETE FROM session_store.sessions WHERE username=$1 RETURNING token_hash",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        err = std::string("session delete-by-user failed: ") + PQerrorMessage(c);
        return std::nullopt;
    }
    const int count = PQntuples(r.get());
    if (!bump_generation_in_txn(c)) {
        err = std::string("session write-generation bump failed: ") + PQerrorMessage(c);
        return std::nullopt;
    }
    return count;
}

} // namespace yuzu::server::session_sql
