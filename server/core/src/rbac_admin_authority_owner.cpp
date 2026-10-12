#include "rbac_admin_authority_owner.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "auth_db_sql_helpers.hpp" // kActiveLocalAdminPredicate: ONE copy of the column floor's population
#include "pg/pg_raii.hpp"
#include "rbac_store_sql_helpers.hpp"

#include <yuzu/server/auth_db.hpp> // is_valid_username — provision_first_admin's own
                                    // pre-INSERT guard (rbac_admin_predicate.hpp already
                                    // establishes this cross-inclusion is sanctioned for
                                    // RBAC-adjacent code)

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {
using rbac_sql::bump_generation_in_txn;
using rbac_sql::kReadTimeout;
using rbac_sql::kWriteTimeout;
using rbac_sql::read_rbac_enabled_for_update;
using rbac_sql::read_rbac_enabled_lockfree;
using rbac_sql::text_col;
using rbac_sql::to_bool;
using rbac_sql::to_i64;
using rbac_sql::write_rbac_enabled_in_txn;

// THE definition of "an authenticatable Administrator grant". The unassign guard
// below locks and counts through this one fragment, so the LOCK set and the COUNT
// set cannot drift apart; the RBAC enable/disable toggle (A1) is expected to
// reuse it rather than carry a second copy of this JOIN.
constexpr std::string_view kAuthenticatableAdminGrantsFrom =
    "FROM rbac_store.principal_roles pr "
    "JOIN auth.users u ON u.username = pr.principal_id "
    "WHERE pr.role_name = 'Administrator' AND pr.principal_type = 'user' "
    "AND u.is_active";

// "SELECT pr.principal_id " + kAuthenticatableAdminGrantsFrom +
// " ORDER BY pr.principal_id FOR UPDATE OF pr"
// Returns the principal_ids of the rows ACTUALLY LOCKED (nullopt on query error,
// with `err` set from the connection). The unassign guard uses the result as the
// membership test for "was the row being deleted itself one of the counted rows".
// The ORDER BY makes every locker of this set (`unassign_role`, `deactivate_account`,
// and `set_enforcement`'s enable direction) take the row locks in the same
// deterministic order, so two of them cannot wait on each other in a cycle through
// THIS set. It is appended AFTER the shared fragment, which stays byte-identical, so
// the lock and count sets still share one definition.
std::optional<std::vector<std::string>> lock_authenticatable_admin_grants(PGconn* c,
                                                                          std::string& err) {
    const std::string sql = std::string("SELECT pr.principal_id ") +
                            std::string(kAuthenticatableAdminGrantsFrom) +
                            " ORDER BY pr.principal_id FOR UPDATE OF pr";
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
// Lock-free. nullopt on a query error or an unexpected row count; `err` is the
// connection's error text (empty for an unexpected row count).
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

// "SELECT pr.principal_id " + kAuthenticatableAdminGrantsFrom (no FOR UPDATE).
// Lock-free sibling of lock_authenticatable_admin_grants — A1's
// set_enforcement DISABLE direction's SOURCE-regime check (Gate 7 Fix 1):
// the enable branch already reads the durable-ON regime's authority set via
// lock_authenticatable_admin_grants (for its own destination check), but a
// disable transition needs to know the SAME set without taking the FOR
// UPDATE lock unassign_role serializes against — that lock exists to
// protect the destination-survival guarantee on the enable path, and taking
// it again here (over the same candidate rows, with no ORDER BY) on every
// disable would add contention with no corresponding write on this path.
// Keeps the "principal_roles FOR UPDATE (enable only)" lock-order clause in
// this file's header banner true: this call reads principal_roles but never
// locks it. ALSO used by `regime_authority`'s own fresh read (its own
// lock-free lease, never inside set_enforcement's transaction).
std::optional<std::vector<std::string>> list_authenticatable_admin_grants(PGconn* c,
                                                                          std::string& err) {
    const std::string sql =
        std::string("SELECT pr.principal_id ") + std::string(kAuthenticatableAdminGrantsFrom);
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

// Disable direction (auth.users only; `role` stores the literal
// 'admin'/'user', auth_db.cpp). The population is `auth_sql::kActiveLocalAdminPredicate`,
// the one copy shared with `auth_sql::count_active_local_admin_accounts`. ONE statement, same reason as above:
// membership and count from one snapshot, never two queries that can
// observe two account states. Deliberately NO FOR SHARE / FOR UPDATE (A2
// parity — see set_enforcement's own doc comment on why no auth.users row
// lock is taken).
std::optional<std::vector<std::string>> list_active_local_admin_accounts(PGconn* c,
                                                                         std::string& err) {
    const std::string sql = "SELECT username FROM auth.users WHERE " +
                            std::string(auth_sql::kActiveLocalAdminPredicate);
    pg::PgResult r = pg::exec_params(c, sql.c_str(), std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    std::vector<std::string> names;
    names.reserve(static_cast<size_t>(PQntuples(r.get())));
    for (int i = 0; i < PQntuples(r.get()); ++i)
        names.push_back(text_col(r.get(), i, 0));
    return names;
}

// The longest a LIFECYCLE guard transaction (`deactivate_account` and `set_local_role`, the two
// that call `set_txn_timeouts`) may sit idle BETWEEN statements. The first lock each of them takes
// is the fleet-wide `rbac_enabled` row lock, so a holder whose client died without closing the
// connection (an orphaned backend, until the OS TCP keepalive reaps it) would otherwise block
// every guarded lifecycle write for that long. A lock WAIT is not idle time (the backend is
// executing a statement), so a waiter is unaffected; only a holder that stops sending statements
// is cut. Fixed, not configurable. It does NOT cover `unassign_role`, `set_enforcement` or
// `provision_first_admin`: those transactions keep only the pool defaults. A transaction-local
// setting also OVERRIDES a stricter operator-set `idle_in_transaction_session_timeout` upward to
// 15 s for these two transactions.
constexpr std::chrono::milliseconds kLifecycleIdleInTxnTimeout{15000};

// Installs the bound on EVERY lock wait inside `deactivate_account` and `set_local_role` (the
// `rbac_enabled` row, the counted grant set, the target's grant row, the target's `auth.users`
// row) as the FIRST statement of each transaction, plus the idle-in-transaction bound above.
// #4966 installs 2000 ms (`kDefaultLifecycleLockTimeout` in rbac_store.hpp; `RbacStore`'s
// constructor parameter lets a test shorten it, production never does). `rbac_sql::kWriteTimeout`
// (4000 ms) bounds only the pool ACQUIRE and the pool's own `lock_timeout` defaults to 10000 ms
// (and is not injected at all when the DSN or `PGOPTIONS` carries its own), so without this a
// stuck lock holder could pin a pooled connection for 10 s per lock or unbounded. There is no
// ordering constraint on the value against `AuthDB::recheck_role_locked` (2000 ms) or
// `CredentialChangeOwner` (1500 ms): those wait on the `auth.users` row this owner takes LAST
// and holds only across lock-free recounts and the COMMIT, and this owner never waits on a lock
// either of them holds while holding the `auth.users` row, so no chain of waits forms.
//
// SQL: "SELECT set_config('lock_timeout', $1, true)" and the idle-in-transaction setting: both
// transaction-local (never leak to the pooled connection), bound parameters, the same shape
// `AuthDB`'s own transaction-scoped bound uses.
bool set_txn_timeouts(PGconn* c, std::chrono::milliseconds lock_timeout, std::string& err) {
    pg::PgResult r = pg::exec_params(
        c, "SELECT set_config('lock_timeout', $1, true)",
        std::vector<std::string>{std::to_string(lock_timeout.count()) + "ms"});
    if (r.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return false;
    }
    pg::PgResult idle = pg::exec_params(
        c, "SELECT set_config('idle_in_transaction_session_timeout', $1, true)",
        std::vector<std::string>{std::to_string(kLifecycleIdleInTxnTimeout.count()) + "ms"});
    if (idle.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return false;
    }
    return true;
}

// "SELECT 1 FROM rbac_store.principal_roles WHERE ... FOR UPDATE" for ONE principal's own
// fleet-wide Administrator grant row. Returns whether the row exists (and is now locked),
// nullopt on a query error. Takes the lock whether or not the principal's account is active:
// `deactivate_account` needs to know about a grant the counted-set lock query could not have
// seen (an INSERT committed after that query's snapshot, or a grant whose account was inactive
// at that time).
std::optional<bool> lock_target_administrator_grant(PGconn* c, const std::string& username,
                                                    std::string& err) {
    pg::PgResult r = pg::exec_params(
        c,
        "SELECT 1 FROM rbac_store.principal_roles WHERE principal_type = 'user' "
        "AND principal_id = $1 AND role_name = 'Administrator' FOR UPDATE",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return PQntuples(r.get()) > 0;
}

// A TARGET's membership in the column floor's population, taking that one `auth.users` row's
// lock when it is a member: is `username` an ACTIVE local `role = 'admin'` account
// (`auth_sql::kActiveLocalAdminPredicate`, the one copy). A non-member is left unlocked here (a
// role write needs the `rbac_enabled` lock this transaction already holds, so it cannot become
// a member mid-transaction; the soft delete that follows locks the row anyway). nullopt on a
// query error.
std::optional<bool> lock_target_if_active_local_admin(PGconn* c, const std::string& username,
                                                      std::string& err) {
    const std::string sql = "SELECT 1 FROM auth.users WHERE username = $1 AND " +
                            std::string(auth_sql::kActiveLocalAdminPredicate) + " FOR UPDATE";
    pg::PgResult r = pg::exec_params(c, sql.c_str(), std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return PQntuples(r.get()) > 0;
}

// True iff `members` is exactly {username}: the sole-member test the advisory check uses on a
// list read that already holds only active, counted members (a member list holds a username at
// most once: principal_roles' PRIMARY KEY and auth.users.username's UNIQUE).
bool is_sole_member(const std::vector<std::string>& members, const std::string& username) {
    return members.size() == 1 && members.front() == username;
}

// The text a failed lifecycle transaction reports: the lambda's own `err` when it set one, else
// the pool's best-effort last error, else a symptom-only fallback. `err` is empty when
// `with_txn_for` returns false without the lambda having set it, which covers a PRE-lambda
// failure (acquire timeout, connect backoff, BEGIN failure) AND a POST-lambda one the lambda
// never observes (the abort guard, or a failed COMMIT: the mutation may then already be durable
// server-side, ack loss), so the fallback names the symptom, not a cause.
std::string lifecycle_failure_text(pg::PgPool& pool, const std::string& err, std::string_view what) {
    if (!err.empty())
        return err;
    const std::string pool_err = pool.last_error();
    return std::string(what) + " failed: " +
           (pool_err.empty() ? "transaction did not complete (no further detail)" : pool_err);
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
        // callers, the engine-principal unassign in rest_api_v1.cpp and mcp_server.cpp) stays a pure
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
        // (server.cpp; ADR-0006) — so `auth.users` is guaranteed
        // reachable from this same transaction/connection, never a
        // cross-database call. A degraded/missing `auth` schema fails the
        // whole SELECT (the status check in `lock_authenticatable_admin_grants`),
        // which aborts this transaction (`ok=false` here, `unexpected` from RbacStore) — fail-closed
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
        // as `kAuthenticatableAdminGrantsFrom`), so they use one predicate and
        // cannot drift apart. That is a shared predicate, not a shared snapshot:
        // under READ COMMITTED an account can become active between the lock and
        // the count and then be counted without having been locked (which only
        // ever raises the count). A deactivation that commits before the count is
        // seen by it; one that commits after the count is residual (2) below (closed for
        // `deactivate_account`).
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
        //      concurrently: with no row to lock, an INSERT
        //      by an `AuthDB` writer such as `upsert_user`, `upsert_sso_identity` or
        //      the first-admin seed (`is_active` defaults TRUE) can commit after this
        //      SELECT returns zero rows;
        //  (2) (closed by #4966 for every deactivation that goes through
        //      `deactivate_account`, the sole production path via
        //      `AuthManager::remove_user_checked`) deactivation of a SURVIVING counted
        //      Administrator between the recount below and this transaction's COMMIT:
        //      `deactivate_account` locks the same counted grant set FOR UPDATE, in the same
        //      `ORDER BY`, before writing, so it waits behind this transaction and then
        //      re-counts against its outcome. Still outside it: direct SQL against
        //      `auth.users`, which is break-glass.
        // Lock order in this transaction: `principal_roles` rows, then this one
        // `auth.users` row, then the `rbac_meta` `write_generation` row (taken by
        // `bump_generation_in_txn` at the end). A path that holds an `auth.users`
        // row lock and then waits on `principal_roles` or `rbac_meta` would deadlock
        // against it. auth_db.cpp has no `principal_roles` or `rbac_store` SQL (the
        // `auth_db*` seam rule in tests/test_rbac_query_owner_seam.py pins that), and
        // `deactivate_account` / `set_local_role` (#4966) honour this order rather than
        // invert it. A lock
        // wait here is bounded by the pool's `lock_timeout` (10 s by default; the
        // pool does not inject it when the DSN sets its own `options` or `PGOPTIONS` is
        // set, and the wait is then bounded only if that setting, or the server or role
        // default, sets a `lock_timeout`); on timeout the statement errors and this
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

// See this file's header banner for the full rule and lock order. Guard
// summary: a REAL transition (previous != enabled; the idempotent no-op
// path below evaluates neither guard) is refused unless the CALLER passes
// BOTH:
//   (1) SOURCE-regime authority (Gate 7 Fix 1) — matching whichever regime
//       is durably true RIGHT NOW (`previous`): an authenticatable
//       Administrator grant if currently ON, local role='admin'+active if
//       currently OFF. Closes a cross-replica cache-staleness gap: the
//       outer is_rbac_administrator gate that admits a caller to this route
//       at all reads a replica-local view of `rbac_enabled_` that can lag a
//       real commit by up to kRbacGenerationRefreshMs, and this route is
//       the thing that FLIPS the value that gate reads — so it cannot be
//       the sole regime check for itself. Deliberately does NOT call
//       `regime_authority()` below — that acquires its OWN lease, and
//       nesting a second acquire inside this method's `with_txn_for` lambda
//       is forbidden (this file's header banner: "no nested acquire"); it
//       also needs to read the SAME FOR-UPDATE-locked `previous`, not a
//       fresh lock-free re-read, which `regime_authority()` always does.
//       Duplicated read-then-check logic between the two methods is the
//       accepted cost of honouring that constraint, not a defect.
//   (2) DESTINATION-regime survival (pre-existing) — enable requires the
//       caller's own authenticatable (auth.users-joined, active) fleet-wide
//       Administrator grant; disable requires the caller's own local
//       account to hold role='admin' AND active.
// Lock order: rbac_meta('rbac_enabled') -> principal_roles (enable direction
// locks it via lock_authenticatable_admin_grants for its destination check;
// disable direction reads the SAME rows unlocked via
// list_authenticatable_admin_grants for its source check — never both on
// one call, since source and destination regimes are always opposite on a
// genuine transition) -> rbac_meta('write_generation') [inside
// bump_generation_in_txn]. The FOR UPDATE lock, when taken, is the SAME
// principal_roles JOIN + FOR UPDATE OF pr lock unassign_role takes
// (kAuthenticatableAdminGrantsFrom, shared above), taken over the identical
// candidate rows, so the two guards serialize against each other under READ
// COMMITTED: a grant committed after this transaction's lock query ran is
// not in the locked set (refused; the operator retries and it is then
// locked), and a grant that IS in the set is held FOR UPDATE, so a
// concurrent unassign_role of it blocks behind this transaction's lock and
// re-evaluates its own count against this transaction's committed outcome
// (and vice versa). Every locker of this set (this method's enable
// direction, `unassign_role`, `deactivate_account`) takes the rows in the
// same `ORDER BY pr.principal_id` order, appended after the shared fragment
// (which stays byte-identical), so two of them cannot wait on each other in
// a cycle through THIS set. That is not a claim of PG-level deadlock
// freedom in general (a lock outside this set can still participate in a
// cycle). If PG's detector fires, or `lock_timeout` expires, ONE side's
// transaction aborts and surfaces here as a store failure (never a hang,
// never a half-applied write).
//
// The guarantee is honestly point-in-time, not enduring: the caller was
// eligible under the destination regime AS OBSERVED INSIDE this transaction,
// never "the caller survives at commit" — A2 deliberately never locks
// `auth.users` (it would serialize unrelated logins/role changes) and A1
// keeps that parity, so a demotion/deactivation/unassign committing
// immediately after this transaction is the accepted residual (#4966). The
// SAME accepted property applies to the disable direction's lock-free
// SOURCE-regime check (Gate 8 HIGH follow-up) — it too observes the
// caller's authenticatable-Administrator-grant membership AS OF ITS OWN
// unlocked read, not "the caller still holds it at commit"; a concurrent
// unassign of that very grant committing immediately after is the identical
// point-in-time residual, not a new one.
RbacAdminAuthorityOwner::EnforcementOutcome
RbacAdminAuthorityOwner::set_enforcement(bool enabled, const std::string& caller_username) const {
    EnforcementOutcome result;
    bool refused = false;
    EnforcementOutcome::RefusalKind refused_kind = EnforcementOutcome::RefusalKind::kDestinationSurvivor;
    std::string refusal_message;
    std::string err;
    std::optional<std::uint64_t> new_gen;

    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // The row ALWAYS exists on an open store (seed_defaults' `('rbac_enabled','false')
        // ON CONFLICT DO NOTHING` plus the rbac_meta_enabled_canonical CHECK), so an
        // absent/non-canonical read here means corruption, not a fresh install.
        const auto previous = read_rbac_enabled_for_update(c, err);
        if (!previous)
            return false; // err set by read_rbac_enabled_for_update; maps to a store failure

        result.previous_enabled = *previous;
        result.enabled = enabled;

        if (*previous == enabled) {
            // Idempotent no-op: report the direction-appropriate count for the
            // response WITHOUT taking any row lock beyond the rbac_enabled one
            // already held above — a response-only count must never block a
            // concurrent unassign_role. No UPDATE, no bump_generation_in_txn.
            if (enabled) {
                const auto count = count_authenticatable_admin_grants(c, err);
                if (!count)
                    return false;
                result.post_transition_administrators = *count;
            } else {
                const auto admins = list_active_local_admin_accounts(c, err);
                if (!admins)
                    return false;
                result.post_transition_administrators = static_cast<std::int64_t>(admins->size());
            }
            result.changed = false;
            return true;
        }

        // Gate 7 Fix 1 (security-guardian, HIGH): SOURCE-regime authority
        // check — reached ONLY on a real transition (the no-op path above
        // already returned), matching whichever regime is durably true RIGHT
        // NOW (`*previous`), not the destination regime evaluated below. The
        // outer is_rbac_administrator gate that admitted the caller to this
        // route reads a replica-local cached view of `rbac_enabled_` that
        // can lag a real commit by up to kRbacGenerationRefreshMs; without
        // this check, a caller admitted under a STALE view (e.g. a session
        // with only local role='admin', wrongly admitted because the cache
        // still thought RBAC was off, while it is durably ON) could disable
        // enforcement purely by satisfying the destination check below —
        // fail-open on disable. Source and destination regimes are always
        // opposite on a genuine transition, so this is always a second,
        // distinct query from the destination check further down — never a
        // second query of the SAME set.
        if (*previous) {
            const auto source_admins = list_authenticatable_admin_grants(c, err);
            if (!source_admins)
                return false;
            if (std::find(source_admins->begin(), source_admins->end(), caller_username) ==
                source_admins->end()) {
                refused = true;
                refused_kind = EnforcementOutcome::RefusalKind::kSourceRegime;
                refusal_message =
                    "refused: caller does not currently hold a fleet-wide Administrator grant, "
                    "required to change enforcement while it is on";
                return false; // rolls back — no write, no bump
            }
        } else {
            const auto source_local_admins = list_active_local_admin_accounts(c, err);
            if (!source_local_admins)
                return false;
            if (std::find(source_local_admins->begin(), source_local_admins->end(),
                          caller_username) == source_local_admins->end()) {
                refused = true;
                refused_kind = EnforcementOutcome::RefusalKind::kSourceRegime;
                refusal_message =
                    "refused: caller does not currently hold the local admin role, required to "
                    "change enforcement while it is off";
                return false; // rolls back — no write, no bump
            }
        }

        if (enabled) {
            const auto locked = lock_authenticatable_admin_grants(c, err);
            if (!locked)
                return false;
            if (std::find(locked->begin(), locked->end(), caller_username) == locked->end()) {
                refused = true;
                refused_kind = EnforcementOutcome::RefusalKind::kDestinationSurvivor;
                refusal_message =
                    "refused: enabling RBAC enforcement would leave the caller with no "
                    "fleet-wide Administrator grant; assign yourself Administrator first";
                return false; // rolls back — no write, no bump
            }
            result.post_transition_administrators = static_cast<std::int64_t>(locked->size());
        } else {
            const auto admins = list_active_local_admin_accounts(c, err);
            if (!admins)
                return false;
            if (std::find(admins->begin(), admins->end(), caller_username) == admins->end()) {
                refused = true;
                refused_kind = EnforcementOutcome::RefusalKind::kDestinationSurvivor;
                refusal_message =
                    "refused: disabling RBAC enforcement would leave the caller without the "
                    "local admin role that is the only durable administrator authority while "
                    "enforcement is off";
                return false; // rolls back — no write, no bump
            }
            result.post_transition_administrators = static_cast<std::int64_t>(admins->size());
        }

        if (!write_rbac_enabled_in_txn(c, enabled, err))
            return false;
        new_gen = bump_generation_in_txn(c);
        if (!new_gen) {
            if (err.empty())
                err = "write_generation bump failed";
            return false;
        }
        result.changed = true;
        return true;
    });

    result.ok = ok || refused; // a business-rule refusal is a clean rollback, not a store fault
    result.refused = refused;
    result.refusal_kind = refused_kind;
    result.refusal_message = refusal_message;
    result.new_gen = new_gen;
    result.err = err;
    return result;
}

// A single connection lease serves BOTH reads below, back-to-back with no
// intervening work — but each is its own autocommit statement (no
// `pool_.with_txn_for`/`BEGIN`), so this is NOT one shared point-in-time
// snapshot: under READ COMMITTED, a commit landing between the two
// statements is visible to the second read but not the first. Deliberately
// not wrapped in a transaction to force a true single snapshot — both
// cpp-safety and security-guardian independently assessed this residual as
// low-exploitability and already-accepted-class (the same shape as every
// other point-in-time, not-enduring guarantee in this file).
RbacRegimeAuthority
RbacAdminAuthorityOwner::regime_authority(const std::string& caller_username) const {
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return RbacRegimeAuthority::kUnavailable;
    std::string err;
    const auto durable_enabled = read_rbac_enabled_lockfree(lease.get(), err);
    if (!durable_enabled)
        return RbacRegimeAuthority::kUnavailable;

    if (*durable_enabled) {
        const auto admins = list_authenticatable_admin_grants(lease.get(), err);
        if (!admins)
            return RbacRegimeAuthority::kUnavailable;
        return std::find(admins->begin(), admins->end(), caller_username) != admins->end()
                   ? RbacRegimeAuthority::kAuthorized
                   : RbacRegimeAuthority::kNotAuthorized;
    }
    const auto local_admins = list_active_local_admin_accounts(lease.get(), err);
    if (!local_admins)
        return RbacRegimeAuthority::kUnavailable;
    return std::find(local_admins->begin(), local_admins->end(), caller_username) !=
                   local_admins->end()
               ? RbacRegimeAuthority::kAuthorized
               : RbacRegimeAuthority::kNotAuthorized;
}

namespace {
// Same advisory-lock key as `AuthDB`'s `kSeedAdminLockSql` (auth_db.cpp,
// anonymous-namespace, so not reachable from this translation unit — no
// shared header exists between the two, the same duplicated-literal
// precedent auth_db.cpp's own `kEngineReservedPrefix` comment documents for
// itself). MUST match byte-for-byte: `provision_first_admin` and
// `AuthDB::seed_admin_if_empty` serialize against EACH OTHER, and against
// every other replica's concurrent `provision_first_admin` call, through
// this exact lock key — a divergent literal here would compute a different
// lock and let two processes race the "first account" INSERT concurrently.
constexpr const char* kProvisionFirstAdminLockSql = "SELECT pg_advisory_xact_lock(2037545589, 1)";
} // namespace

// See the header's own doc comment for the full contract (the HA "another
// replica already won" no-op case, atomicity of account+grant).
// `is_valid_username` runs BEFORE any query — this is the SOLE production
// validator now, since `main.cpp` no longer calls
// `AuthDB::seed_admin_if_empty` at all (that method's production caller was
// removed; it stays exported only for AuthDB's own unit tests) — an
// unvalidated INSERT here would otherwise poison `auth.users` with a bad
// row before any validation ever ran, and every later boot would keep
// hitting the same fatal path with the row already stuck in place.
RbacAdminAuthorityOwner::ProvisionFirstAdminOutcome
RbacAdminAuthorityOwner::provision_first_admin(const std::string& username,
                                               const std::string& password_hash,
                                               const std::string& salt_hex) const {
    ProvisionFirstAdminOutcome result;
    if (!is_valid_username(username)) {
        result.err = "provision_first_admin: invalid username";
        return result; // ok=false, provisioned=false — a genuine refusal, mirrors
                        // seed_admin_if_empty's own InvalidUsername unexpected()
    }

    bool provisioned = false;
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult lock_res{PQexec(c, kProvisionFirstAdminLockSql)};
        if (lock_res.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        // Exact SQL text `AuthDB::seed_admin_if_empty` uses (auth_db.cpp) —
        // deliberately the SAME shape, not a paraphrase, so the two stay
        // byte-identical in intent even though they live in separate
        // translation units with no shared header for it.
        pg::PgResult res = pg::exec_params(
            c,
            "INSERT INTO auth.users (username, password_hash, salt_hex, role) "
            "SELECT $1, $2, $3, 'admin' WHERE NOT EXISTS (SELECT 1 FROM auth.users) "
            "RETURNING id",
            std::vector<std::string>{username, password_hash, salt_hex});
        if (res.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(res.get()) == 0) {
            // Not the first account: another replica's provision_first_admin
            // call already won (seed_admin_if_empty has no production
            // caller and cannot be the winner here), or auth.users was
            // never empty. Clean no-op, not an error — the transaction commits
            // (or rolls back; either is harmless, nothing was written) with
            // the advisory lock released either way.
            return true;
        }
        provisioned = true;

        // Same idempotent INSERT shape RbacStore::assign_role uses
        // (rbac_store.cpp) — ON CONFLICT DO NOTHING here is a defensive
        // belt, not load-bearing, since the auth.users INSERT above already
        // established this is genuinely the first account.
        pg::PgResult grant = pg::exec_params(
            c,
            "INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
            "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            std::vector<std::string>{"user", username, "Administrator"});
        if (grant.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }

        new_gen = bump_generation_in_txn(c);
        if (!new_gen) {
            if (err.empty())
                err = "provision_first_admin: write_generation bump failed";
            return false;
        }
        return true;
    });

    result.ok = ok;
    result.provisioned = provisioned && ok;
    if (result.provisioned)
        result.username = username;
    result.new_gen = new_gen;
    result.err = err;
    return result;
}

// See the header's doc comment for the contract, the two floors and why each applies where it
// does. Steps are numbered as there. Every recount (6, 7) is a SEPARATE statement issued after
// the write: a fresh READ COMMITTED snapshot that also sees this transaction's own uncommitted
// UPDATE. A recount folded into the write's statement (or issued before it) would count the
// target itself.
AccountDeactivationResult
RbacAdminAuthorityOwner::deactivate_account(const std::string& username) const {
    // A name `is_valid_username` rejects can never be a stored account (every writer validates),
    // so it is `kNotFound` BEFORE any statement runs: an embedded NUL would truncate at the libpq
    // parameter boundary and an over-long name is not a row. Same gate `provision_first_admin`
    // applies.
    if (!is_valid_username(username))
        return {AccountDeactivationResult::Kind::kNotFound, {}};
    bool refused = false;
    bool removed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // 0.
        if (!set_txn_timeouts(c, lifecycle_lock_timeout_, err))
            return false;

        // 1.
        const auto rbac_enabled = read_rbac_enabled_for_update(c, err);
        if (!rbac_enabled)
            return false;

        // 2. Locked in BOTH regimes: a concurrent unassign_role of any counted grant must wait
        // and re-count (its residual (2) comment relies on this). Under OFF the lock decides
        // nothing here, but dropping it would let this deactivation commit AFTER an
        // unassign_role recount that did not see it.
        const auto locked = lock_authenticatable_admin_grants(c, err);
        if (!locked)
            return false;
        const bool in_counted_grants =
            std::find(locked->begin(), locked->end(), username) != locked->end();

        // 3.
        const auto target_has_grant = lock_target_administrator_grant(c, username, err);
        if (!target_has_grant)
            return false;

        // 4. Both regimes: the column floor protects its population whatever `rbac_enabled` says.
        const auto in_local_admins = lock_target_if_active_local_admin(c, username, err);
        if (!in_local_admins)
            return false;

        // 5.
        const auto soft_deleted = auth_sql::soft_delete_user_in_txn(c, username, err);
        if (!soft_deleted)
            return false;
        if (!*soft_deleted)
            return true; // unknown or already inactive: nothing changed, nothing to guard

        // 6. GRANT floor, RBAC ON only. Fires only when the target was itself a counted grant
        // (step 2) or held a grant at all (step 3, catches one the step-2 snapshot missed): a
        // target outside the population is never refused on its account, and an already-empty
        // population never blocks.
        if (*rbac_enabled && (in_counted_grants || *target_has_grant)) {
            const auto remaining = count_authenticatable_admin_grants(c, err);
            if (!remaining)
                return false;
            if (*remaining == 0) {
                refused = true;
                return false; // aborts the transaction: the soft delete rolls back
            }
        }

        // 7. COLUMN floor, BOTH regimes. Independent of step 6 (a refusal from either aborts).
        // Takes no new lock: the recount is a plain SELECT and every decreaser of this
        // population holds the `rbac_enabled` lock taken at step 1.
        if (*in_local_admins) {
            const auto remaining = auth_sql::count_active_local_admin_accounts(c, err);
            if (!remaining)
                return false;
            if (*remaining == 0) {
                refused = true;
                return false;
            }
        }
        removed = true;
        return true;
    });

    AccountDeactivationResult out;
    if (refused) {
        out.kind = AccountDeactivationResult::Kind::kLastAdministratorRefused;
    } else if (!ok) {
        out.kind = AccountDeactivationResult::Kind::kStoreFailure;
        out.err = lifecycle_failure_text(pool_, err, "deactivate_account");
    } else {
        out.kind = removed ? AccountDeactivationResult::Kind::kDeactivated
                           : AccountDeactivationResult::Kind::kNotFound;
    }
    return out;
}

// See the header's doc comment. The role literals are the column's own ('admin' / 'user').
LocalRoleChangeResult RbacAdminAuthorityOwner::set_local_role(const std::string& username,
                                                              auth::Role role) const {
    using Kind = LocalRoleChangeResult::Kind;
    if (!is_valid_username(username)) // see deactivate_account: not a possible account
        return {Kind::kNotFound, {}};
    const bool make_admin = (role == auth::Role::admin);
    Kind kind = Kind::kStoreFailure;
    bool refused = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // 0.
        if (!set_txn_timeouts(c, lifecycle_lock_timeout_, err))
            return false;

        // 1. The regime value is not used; the row LOCK is the point (see the header banner).
        if (!read_rbac_enabled_for_update(c, err))
            return false;

        // 2. The one `auth.users` row lock, the last lock this method takes.
        pg::PgResult row = pg::exec_params(
            c, "SELECT role, is_active FROM auth.users WHERE username = $1 FOR UPDATE",
            std::vector<std::string>{username});
        if (row.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(row.get()) == 0) {
            kind = Kind::kNotFound;
            return true;
        }
        const bool previous_admin = text_col(row.get(), 0, 0) == "admin";
        const bool was_active = to_bool(PQgetvalue(row.get(), 0, 1));

        // 3. Classify before writing.
        if (previous_admin == make_admin) {
            kind = Kind::kUnchanged; // nothing written, even for an inactive row
            return true;
        }
        if (make_admin && !was_active) {
            kind = Kind::kInactivePromotionRefused; // never re-arm an inactive account
            return true;
        }

        // 4. `match_inactive` only when demoting, so an inactive elevated account can be
        // demoted (recovery) but never promoted.
        const auto written = auth_sql::set_role_in_txn(c, username, make_admin ? "admin" : "user",
                                                       /*match_inactive=*/!make_admin, err);
        if (!written)
            return false;
        if (!*written) {
            // The row was read and locked above, so a write that matches nothing is an anomaly.
            err = "set_local_role: the locked row matched no write (anomaly)";
            return false;
        }

        // 5. COLUMN floor, both regimes: ONLY when the demotion actually removed a member of the
        // population (an ACTIVE admin became non-admin). A SEPARATE statement after the write.
        // An inactive admin's demotion is never refused: it was not counted.
        if (previous_admin && was_active && !make_admin) {
            const auto remaining = auth_sql::count_active_local_admin_accounts(c, err);
            if (!remaining)
                return false;
            if (*remaining == 0) {
                refused = true;
                return false; // aborts the transaction: the role write rolls back
            }
        }
        kind = Kind::kChanged;
        return true;
    });

    LocalRoleChangeResult out;
    if (refused) {
        out.kind = Kind::kLastAdministratorRefused;
    } else if (!ok) {
        out.kind = Kind::kStoreFailure;
        out.err = lifecycle_failure_text(pool_, err, "set_local_role");
    } else {
        out.kind = kind;
    }
    return out;
}

// See the header's doc comment. Membership in a counted/active set already implies "active"
// (both statements filter `is_active`), so an unknown or already-inactive username falls out as
// "in neither set" without a separate existence read. Every read reuses a helper the guard or
// `regime_authority` already runs: the ONE `kAuthenticatableAdminGrantsFrom` fragment (via
// list_authenticatable_admin_grants), the lock-free regime read and the active-local-admin list.
WouldStrandResult
RbacAdminAuthorityOwner::would_strand_last_administrator(const std::string& username) const {
    WouldStrandResult out;
    if (!is_valid_username(username)) {
        // Not a possible account, so not a member of any protected population: a definite "no".
        out.ok = true;
        out.would_strand = false;
        return out;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        const std::string pool_err = pool_.last_error();
        out.err = "would_strand_last_administrator failed: " +
                  (pool_err.empty() ? std::string("could not acquire a connection") : pool_err);
        return out;
    }
    std::string err;
    const auto fail = [&]() {
        out.err = "would_strand_last_administrator failed: " +
                  (err.empty() ? std::string("query did not complete (no further detail)") : err);
        return out;
    };
    const auto rbac_enabled = read_rbac_enabled_lockfree(lease.get(), err);
    if (!rbac_enabled)
        return fail();

    // Step 6's twin, the GRANT floor: RBAC ON only.
    bool grant_floor = false;
    if (*rbac_enabled) {
        const auto grants = list_authenticatable_admin_grants(lease.get(), err);
        if (!grants)
            return fail();
        grant_floor = is_sole_member(*grants, username);
    }
    // Step 7's twin, the COLUMN floor: both regimes. Read even when the grant floor already says
    // strand, so a store fault is never half-reported as a verdict.
    const auto local_admins = list_active_local_admin_accounts(lease.get(), err);
    if (!local_admins)
        return fail();
    out.ok = true;
    out.would_strand = grant_floor || is_sole_member(*local_admins, username);
    return out;
}

} // namespace yuzu::server
