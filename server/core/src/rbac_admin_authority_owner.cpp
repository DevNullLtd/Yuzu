#include "rbac_admin_authority_owner.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store_sql_helpers.hpp"

#include <libpq-fe.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {
using rbac_sql::bump_generation_in_txn;
using rbac_sql::kWriteTimeout;
using rbac_sql::text_col;
using rbac_sql::to_bool;
using rbac_sql::to_i64;

// THE definition of "an authenticatable Administrator grant". The unassign guard
// below locks and counts through this one fragment, so the LOCK set and the COUNT
// set cannot drift apart; the enforcement toggle's caller-survives guard is
// expected to reuse it rather than carry a second copy of this JOIN.
constexpr std::string_view kAuthenticatableAdminGrantsFrom =
    "FROM rbac_store.principal_roles pr "
    "JOIN auth.users u ON u.username = pr.principal_id "
    "WHERE pr.role_name = 'Administrator' AND pr.principal_type = 'user' "
    "AND u.is_active";

// "SELECT pr.principal_id " + kAuthenticatableAdminGrantsFrom + " FOR UPDATE OF pr"
// Returns the principal_ids of the rows ACTUALLY LOCKED (nullopt on query error,
// with `err` set from the connection). The unassign guard uses the result as the
// membership test for "was the row being deleted itself one of the counted rows".
std::optional<std::vector<std::string>> lock_authenticatable_admin_grants(PGconn* c,
                                                                          std::string& err) {
    const std::string sql = std::string("SELECT pr.principal_id ") +
                            std::string(kAuthenticatableAdminGrantsFrom) + " FOR UPDATE OF pr";
    pg::PgResult r = pg::exec_params(c, sql.c_str(), std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    std::vector<std::string> ids;
    ids.reserve(static_cast<size_t>(PQntuples(r.get())));
    for (int i = 0; i < PQntuples(r.get()); ++i)
        ids.push_back(text_col(r.get(), i, 0));
    return ids;
}

// "SELECT count(*) " + kAuthenticatableAdminGrantsFrom
// Lock-free. nullopt on a query error or an unexpected row count, with `err` set
// from the connection.
std::optional<std::int64_t> count_authenticatable_admin_grants(PGconn* c, std::string& err) {
    const std::string sql =
        std::string("SELECT count(*) ") + std::string(kAuthenticatableAdminGrantsFrom);
    pg::PgResult r = pg::exec_params(c, sql.c_str(), std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return to_i64(PQgetvalue(r.get(), 0, 0));
}
} // namespace

RbacAdminAuthorityOwner::UnassignOutcome
RbacAdminAuthorityOwner::unassign_role(const std::string& principal_type,
                                       const std::string& principal_id,
                                       const std::string& role_name) const {
    std::optional<std::uint64_t> new_gen;
    bool last_admin_reject = false;
    bool removed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // A2 last-Administrator guard ("A2 — Global human
        // role assignment/unassignment"). Scoped to role_name=="Administrator"
        // ONLY — every other unassign (including both existing engine-only
        // callers, rest_api_v1.cpp:3274 and mcp_server.cpp:21915) stays a pure
        // DELETE with no extra behavior. Unconditional would be WRONG, not
        // just unnecessary: a fresh install holds ZERO Administrator
        // `principal_roles` rows until A2's own assign route bootstraps the
        // first one, so an unconditional post-delete count would spuriously
        // reject unassigning e.g. a Viewer grant on a store that has never
        // had an Administrator row at all.
        //
        // `principal_type = 'user'` ONLY (adversarial-review PR1/A2 finding
        // — was `IN ('user', 'group')`): the admin GATE this guard exists to
        // protect (`rbac_admin_predicate.hpp::is_rbac_administrator`) never
        // resolves a group-held Administrator row — group membership is a
        // documented, deliberate exclusion there. Counting a group row as a
        // "surviving" Administrator here, while the gate can never actually
        // pass through one, would let the last GATE-PASSING (user) admin be
        // removed whenever a group row also exists — a false sense of safety
        // from a row nothing can authenticate as. Match the gate exactly.
        //
        // JOIN auth.users u ON u.username = pr.principal_id, WHERE u.is_active (governance
        // BLOCKING #1, full-pipeline review on 765bc7ec1): a bare `principal_roles` row count
        // is a count of GRANTS, not of administrators who are even potentially authenticatable
        // — `is_active` is a NECESSARY precondition every LOCAL PASSWORD login path filters
        // on, not a sufficient one (see auth_db.cpp's `migrations()` comment on
        // `users.is_active` for what else gates the local path, and for why an OIDC/SAML
        // session never reads this column at all). A2 explicitly permits pre-provisioning
        // (assigning Administrator to a username with no `auth.users` row yet — see
        // `target_provisioned` at the assign route), and `AuthDB::remove_user` is a SOFT
        // delete (`UPDATE auth.users
        // SET is_active = FALSE ...`, auth_db.cpp — there is no hard-delete/cascade path
        // anywhere in this codebase), so BOTH a ghost (never-logged-in) row AND a
        // deactivated/removed account would previously count as a "surviving" administrator
        // when neither is even a candidate to authenticate as one (a ghost row has no
        // credentials to authenticate with at all; a deactivated account fails the `is_active`
        // precondition every LOCAL PASSWORD login path enforces). The JOIN excludes a
        // nonexistent username (no matching row) and `u.is_active` excludes both deactivated
        // and (soft-)deleted accounts
        // — the same filter covers all three sub-cases named in the finding. This is safe ONLY
        // because `RbacStore` and `AuthDB` are ALWAYS constructed
        // on the SAME PgPool/database in production — ONE `--postgres-dsn`,
        // ONE `pg_pool_` member, both stores built from it
        // (server.cpp:4603,6118; ADR-0006) — so `auth.users` is guaranteed
        // reachable from this same transaction/connection, never a
        // cross-database call. A degraded/missing `auth` schema fails the
        // whole SELECT (the status check in `lock_authenticatable_admin_grants`),
        // which aborts this transaction and returns `unexpected` — fail-closed
        // by construction, no separate degraded-vs-absent branch needed.
        //
        // Concurrency: lock the CANDIDATE Administrator rows with `FOR
        // UPDATE OF pr` (the `principal_roles` alias only — never lock the
        // candidate SET of `auth.users` rows here, which would serialize
        // unassigns against unrelated logins/role-changes. The one narrow
        // exception is the single deleted principal's own `auth.users` row,
        // locked by the post-DELETE recheck further down)
        // before the DELETE. Without this, two concurrent unassigns each
        // removing one of the last two Administrator grants can both read
        // "1 remaining" under READ COMMITTED (neither sees the other's
        // still-uncommitted delete) and both commit, landing at zero — the
        // exact TOCTOU a route-level pre-check would also be vulnerable to.
        // `FOR UPDATE OF pr` blocks the second transaction on the first's
        // row lock until it commits/rolls back, so the second re-evaluates
        // the count against the first's now-durable delete. The LOCK set
        // and the COUNT set below both go through the identical JOIN (shared
        // as `kAuthenticatableAdminGrantsFrom`), so the lock always covers
        // exactly the rows the count depends on.
        // Doomgoose external review, PR #4985 (governance ledger a2-p7-doomgoose-1):
        // the lock query's own result set is the ONLY correct membership test
        // for "was the row being deleted itself one of the counted rows" — a
        // ghost/deactivated Administrator grant that never appears here (it
        // fails the `auth.users`/`is_active` JOIN) must never trip the
        // post-delete refusal below, because deleting a row that was never
        // counted cannot be what drove the count from >0 to 0. Capture the
        // locked principal_ids so the refusal can be scoped to "this delete
        // was itself one of them" rather than "the count is now 0" alone —
        // the two are NOT equivalent when the count was already 0 going in
        // (e.g. the only Administrator row left is a ghost/deactivated one).
        // (cpp-safety re-review, PR #4985 fix round: this reasoning assumes
        // `auth.users.is_active` is stable between the lock SELECT above and
        // the DELETE below, and it is not: the candidate `auth.users` rows are
        // deliberately left unlocked (see the note further up). The scenario
        // this narrowing newly permits is a principal reactivated inside that
        // window who is also the fleet's sole Administrator grant. That was a
        // real exposure, not a theoretical one (Doomgoose external review,
        // PR #4985, finding #1): "the fleet was already at zero COUNTED admins
        // at lock time" does not make removing a since-reactivated sole
        // admin's grant safe. It is closed for an EXISTING `auth.users` row by
        // the post-DELETE recheck further down, which locks the deleted
        // principal's own row; that comment lists what remains open.)
        std::unordered_set<std::string> locked_admin_principal_ids;
        if (role_name == "Administrator") {
            std::string lock_err;
            const auto locked = lock_authenticatable_admin_grants(c, lock_err);
            if (!locked) {
                err = lock_err;
                return false;
            }
            locked_admin_principal_ids.insert(locked->begin(), locked->end());
        }

        pg::PgResult r = pg::exec_params(
            c,
            "DELETE FROM rbac_store.principal_roles WHERE principal_type = $1 AND principal_id = $2 "
            "AND role_name = $3",
            std::vector<std::string>{principal_type, principal_id, role_name});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        removed = std::string(PQcmdTuples(r.get())) != "0";

        // Only fire the count when this DELETE actually removed a row that was
        // itself among the locked/counted rows above — an idempotent no-op
        // unassign (the principal never held the role) must not spuriously
        // reject, and neither must removing a row the count never included in
        // the first place (a ghost/deactivated grant: `principal_type` isn't
        // "user", or the principal_id never matched the JOIN/`is_active`
        // filter above). Only `principal_type == "user"` rows are ever placed
        // in `locked_admin_principal_ids`, so this also naturally excludes a
        // group-held "Administrator" row per the "match the gate exactly"
        // rule above.
        //
        // TOCTOU close (Doomgoose external review, PR #4985, finding #1):
        // `locked_admin_principal_ids` is a snapshot taken BEFORE the DELETE, and
        // the candidate `auth.users` rows are deliberately left unlocked, so a row
        // that was ghost/deactivated at lock time (and therefore excluded from the
        // locked set) can be reactivated by an independent, concurrent transaction
        // (e.g. `AuthDB::reactivate_user`) after the lock query. If that principal
        // is the fleet's ONLY real Administrator, trusting the snapshot alone would
        // evaluate `removed_a_counted_admin` false and skip the recount below,
        // removing a grant the principal can already begin to use: `AuthDB::get_user`
        // filters `is_active = TRUE` (necessary for login, not sufficient), and this
        // transaction's DELETE is invisible to the admin gate until it commits.
        // Close this with a fresh recheck of the SPECIFIC deleted principal's
        // `auth.users` row, run after the DELETE in the same transaction, with
        // FOR UPDATE. Under READ COMMITTED a reactivation that already committed
        // is seen; one still in flight makes this statement wait and re-read its
        // committed version; one that starts later blocks on this row lock until
        // this transaction commits or rolls back, so it cannot commit between the
        // recheck and our COMMIT. The WHERE deliberately has NO `is_active`
        // filter: the re-read of a concurrently updated row must be able to return
        // it. Only needed when the principal wasn't already in the locked set; if
        // it was, the recount below fires regardless.
        bool reactivated_since_lock = false;
        if (role_name == "Administrator" && removed && principal_type == "user" &&
            locked_admin_principal_ids.count(principal_id) == 0) {
            pg::PgResult fresh_active = pg::exec_params(
                c, "SELECT is_active FROM auth.users WHERE username = $1 FOR UPDATE",
                std::vector<std::string>{principal_id});
            if (fresh_active.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }
            reactivated_since_lock = PQntuples(fresh_active.get()) == 1 &&
                                     to_bool(PQgetvalue(fresh_active.get(), 0, 0));
        }
        // NOT closed by this recheck (disclosed, not claimed closed):
        //  (1) a pre-provisioned grant whose `auth.users` row is CREATED
        //      concurrently: with no row to lock, the INSERT in
        //      `AuthDB::upsert_user` (or `upsert_sso_identity`; `is_active`
        //      defaults TRUE) can commit after this SELECT returns zero rows;
        //  (2) deactivation of a SURVIVING counted Administrator between the
        //      recount below and this transaction's COMMIT (#4966: `remove_user`
        //      has no last-Administrator guard).
        // Lock order in this transaction: `principal_roles` rows, then this one
        // `auth.users` row, then the `rbac_meta` `write_generation` row (taken by
        // `bump_generation_in_txn` at the end). A path that holds an `auth.users`
        // row lock and then waits on `principal_roles` or `rbac_meta` would deadlock
        // against it. auth_db.cpp has no `principal_roles` or `rbac_store` SQL, and
        // #4966's fix must honour this order (or use one shared
        // transaction-scoped advisory lock) rather than invert it. A lock
        // wait here is bounded by the pool's `lock_timeout` (10 s by default, unless
        // the DSN sets its own `options`); on timeout the statement errors and this
        // transaction rolls back. REST answers 503; the MCP twin answers an
        // internal error with a retry hint.
        const bool removed_a_counted_admin =
            removed && principal_type == "user" &&
            (locked_admin_principal_ids.count(principal_id) > 0 || reactivated_since_lock);
        if (role_name == "Administrator" && removed_a_counted_admin) {
            std::string count_err;
            const auto remaining = count_authenticatable_admin_grants(c, count_err);
            if (!remaining) {
                err = count_err;
                return false;
            }
            if (*remaining == 0) {
                last_admin_reject = true;
                return false; // aborts the transaction — the DELETE above rolls back
            }
        }

        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    return {ok, last_admin_reject, removed, new_gen, err};
}

} // namespace yuzu::server
