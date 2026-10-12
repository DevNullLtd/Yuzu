/**
 * test_rbac_account_lifecycle_guard.cpp -- the last-Administrator guard for ACCOUNT lifecycle
 * (#4966): RbacAdminAuthorityOwner::deactivate_account / set_local_role /
 * would_strand_last_administrator, reached through RbacStore, and the AuthManager entry points
 * remove_user_checked / update_role_checked that are the production way in.
 *
 * Two floors, stated once so each case below can name the one it exercises:
 *   - COLUMN floor, BOTH regimes: the active local `role='admin'` population.
 *   - GRANT floor, RBAC ON only: the authenticatable Administrator grant population.
 * A floor rejects only a mutation that removes a member of ITS population and leaves it
 * empty; an already-empty population never blocks.
 *
 * Every case runs against a real throwaway Postgres (AuthDbPg + an RbacStore on the SAME
 * pool, the production shape) and SKIPs green without YUZU_TEST_POSTGRES_DSN, so a run is
 * only evidence once the PG case count is non-zero. Interleavings are made deterministic by
 * holding a row lock from a raw connection and polling pg_stat_activity for the blocked
 * backends (never a sleep-and-hope). The wall-clock assertions are few and each separates a
 * bounded wait from a 10 s pool default: the lock-timeout case waits out the production
 * constant (2 s) once and asserts 1.5 s <= elapsed < 8 s; the zero-clamp section asserts
 * < 3 s; the would_strand_last_administrator lock-free case asserts < 2 s. The
 * mu_-not-held-across-the-owner-call case carries no timing bound (it checks that both
 * backends are still lock-blocked when has_users() returns).
 *
 * Tags: [pg][auth_db][lifecycle_guard]. `[auth_db]` keeps these in the catch-all PG shard
 * (the shard partition lists exclude by tag; a new tag lands there too, but [rbac_store] is
 * the whale of shard B and must not grow).
 */

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "session_store.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "test_auth_db_pg_helper.hpp"
#include "test_auth_db_rbac_pg_template.hpp" // clone already carries the rbac_store schema
#include "test_principal_lock_gate.hpp" // Workers, SessionWipeFault, kLockWait*
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <expected>
#include <functional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;
using yuzu::server::auth::Role;
using DKind = AccountDeactivationResult::Kind;
using RKind = LocalRoleChangeResult::Kind;

namespace {

// One AuthDbPg + one RbacStore on its pool: the production composition (ONE pg_pool_).
#define LIFECYCLE_FIXTURE(store_var, auth_var)                                                    \
    yuzu::test::AuthDbPg auth_var{0, false, &yuzu::test::auth_db_rbac_pg_template};               \
    RbacStore store_var{auth_var.pool()};                                                         \
    REQUIRE(store_var.is_open())

void seed(yuzu::test::AuthDbPg& db, const std::string& name, Role role) {
    REQUIRE(db->upsert_user(name, "hash", "salt", role).has_value());
}

void grant(RbacStore& store, const std::string& name) {
    REQUIRE(store.assign_role({"user", name, "Administrator"}).has_value());
}

// Raw single-column text query on a fresh lease; the test-side reader that does not go through
// the production statements it is checking.
std::vector<std::string> query_col(PgPool& pool, const char* sql) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql, std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    std::vector<std::string> out;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        out.emplace_back(PQgetvalue(r.get(), i, 0));
    return out;
}

void exec_raw(PgPool& pool, const std::string& sql, std::vector<std::string> params = {}) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

// Survivor SET (not a count): the usernames of the active local role='admin' accounts.
std::vector<std::string> active_column_admins(PgPool& pool) {
    return query_col(pool, "SELECT username FROM auth.users WHERE role = 'admin' AND is_active "
                           "ORDER BY username");
}

// The authenticatable Administrator grant holders, written out here independently of the owner's
// fragment (this is the test's own oracle).
std::vector<std::string> counted_grant_holders(PgPool& pool) {
    return query_col(pool,
                     "SELECT pr.principal_id FROM rbac_store.principal_roles pr "
                     "JOIN auth.users u ON u.username = pr.principal_id "
                     "WHERE pr.role_name = 'Administrator' AND pr.principal_type = 'user' "
                     "AND u.is_active ORDER BY pr.principal_id");
}

bool account_active(PgPool& pool, const std::string& name) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), "SELECT is_active FROM auth.users WHERE username = $1",
                                     std::vector<std::string>{name});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0)[0] == 't';
}

std::string role_column(PgPool& pool, const std::string& name) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), "SELECT role FROM auth.users WHERE username = $1",
                                     std::vector<std::string>{name});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

// pids of backends currently waiting on a Postgres lock, other than `own_pid`. Opens its OWN
// connection: pg_stat_activity is snapshotted once per transaction, so probing through the lock
// holder's open transaction would re-read a frozen, pre-block snapshot forever.
std::vector<int> blocked_backend_pids(const std::string& dsn, int own_pid) {
    pg::PgConn probe{PQconnectdb(dsn.c_str())};
    std::vector<int> pids;
    if (PQstatus(probe.get()) != CONNECTION_OK)
        return pids;
    pg::PgResult r = pg::exec_params(probe.get(),
                                     "SELECT pid FROM pg_stat_activity WHERE datname = "
                                     "current_database() AND wait_event_type = 'Lock' AND pid <> $1 "
                                     "ORDER BY pid",
                                     std::vector<std::string>{std::to_string(own_pid)});
    if (!r.ok())
        return pids;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        pids.push_back(std::atoi(PQgetvalue(r.get(), i, 0)));
    return pids;
}

// Event-driven wait (poll, no fixed sleep-and-assume) until >= n backends are lock-blocked.
// Bounded by the shared `kLockWaitDeadline`, then returns whatever it saw so the REQUIRE reports
// the shortfall.
std::vector<int> wait_for_blocked_backends(const std::string& dsn, int own_pid, std::size_t n) {
    std::vector<int> pids;
    const auto end = std::chrono::steady_clock::now() + yuzu::test::kLockWaitDeadline;
    while (std::chrono::steady_clock::now() < end) {
        pids = blocked_backend_pids(dsn, own_pid);
        if (pids.size() >= n)
            return pids;
        std::this_thread::sleep_for(yuzu::test::kLockWaitPoll);
    }
    return pids;
}

using yuzu::test::HeldLocks;
using yuzu::test::SessionWipeFault;
using yuzu::test::Workers;

struct Acct {
    std::string name;
    Role role{Role::user};
    bool grant{false};
    bool active{true};
};

// Wipe accounts and Administrator grants between table rows (raw: the test's own break-glass
// reset), then build the world the row describes.
void build_world(yuzu::test::AuthDbPg& db, RbacStore& store, bool rbac_on,
                 const std::vector<Acct>& accts) {
    exec_raw(db.pool(), "DELETE FROM rbac_store.principal_roles WHERE role_name = 'Administrator'");
    exec_raw(db.pool(), "DELETE FROM auth.mfa_recovery_codes");
    exec_raw(db.pool(), "DELETE FROM auth.users");
    for (const auto& a : accts) {
        seed(db, a.name, a.role);
        if (a.grant)
            grant(store, a.name);
        if (!a.active)
            REQUIRE(db->remove_user(a.name).has_value());
    }
    REQUIRE(store.set_rbac_enabled(rbac_on).has_value());
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════════════════════
// deactivate_account: the two floors, regime by regime
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("lifecycle guard: regime table (OFF/ON x column/grant floor), and would_strand agrees "
          "with the guard on every row",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    struct Row {
        const char* why;
        bool rbac_on;
        std::vector<Acct> accts;
        std::string target;
        DKind expect;
    };
    const std::vector<Row> rows = {
        // ── RBAC OFF: the column floor only ──
        {"OFF: sole column admin is refused", false, {{"a", Role::admin}}, "a", DKind::kLastAdministratorRefused},
        {"OFF: one of two column admins goes", false, {{"a", Role::admin}, {"b", Role::admin}}, "a",
         DKind::kDeactivated},
        {"OFF: the sole GRANT holder goes while a column admin remains (grant floor is ON-only)", false,
         {{"g", Role::user, true}, {"c", Role::admin}}, "g", DKind::kDeactivated},
        {"OFF: the sole column admin is refused even though a grant holder remains", false,
         {{"c", Role::admin}, {"g", Role::user, true}}, "c", DKind::kLastAdministratorRefused},
        {"OFF: a column admin that also holds the only grant is refused (column floor)", false,
         {{"a", Role::admin, true}}, "a", DKind::kLastAdministratorRefused},
        {"OFF: no administrators at all never blocks an unrelated deactivation", false, {{"x", Role::user}}, "x",
         DKind::kDeactivated},
        {"OFF: zero column admins, the sole grant holder is not blocked", false, {{"g", Role::user, true}}, "g",
         DKind::kDeactivated},
        // ── RBAC ON: both floors ──
        {"ON: the sole grant holder is refused (grant floor)", true,
         {{"g", Role::user, true}, {"c", Role::admin}}, "g", DKind::kLastAdministratorRefused},
        {"ON: one of two grant holders goes", true, {{"g", Role::user, true}, {"h", Role::user, true}}, "g",
         DKind::kDeactivated},
        {"ON: the sole column admin is refused even though grant holders remain (column floor, both regimes)",
         true, {{"c", Role::admin}, {"g", Role::user, true}}, "c", DKind::kLastAdministratorRefused},
        {"ON: sole column admin + sole grant holder in one account is refused", true,
         {{"c", Role::admin, true}, {"d", Role::user}}, "c", DKind::kLastAdministratorRefused},
        {"ON: sole grant holder is refused although a second column admin exists", true,
         {{"c", Role::admin, true}, {"d", Role::admin}}, "c", DKind::kLastAdministratorRefused},
        {"ON: an account in both populations goes when each keeps a survivor", true,
         {{"c", Role::admin, true}, {"d", Role::admin, true}}, "c", DKind::kDeactivated},
        {"ON: no administrators at all never blocks an unrelated deactivation", true, {{"x", Role::user}}, "x",
         DKind::kDeactivated},
        {"ON: a non-member is never refused on another population's account", true,
         {{"c", Role::admin}, {"g", Role::user, true}, {"x", Role::user}}, "x", DKind::kDeactivated},
        // ── absent / inactive targets ──
        {"unknown username is NotFound", false, {{"a", Role::admin}}, "nobody", DKind::kNotFound},
        {"already-inactive account is NotFound (idempotent)", true,
         {{"a", Role::admin, true}, {"gone", Role::user, false, false}}, "gone", DKind::kNotFound},
    };
    for (const auto& row : rows) {
        INFO("row: " << row.why);
        {
            build_world(auth_db, store, row.rbac_on, row.accts);
            const auto before_admins = active_column_admins(auth_db.pool());
            const auto before_grants = counted_grant_holders(auth_db.pool());

            const auto advice = store.would_strand_last_administrator(row.target);
            REQUIRE(advice.ok);
            CHECK(advice.would_strand == (row.expect == DKind::kLastAdministratorRefused));

            const auto got = store.deactivate_account(row.target);
            CHECK(got.err.empty());
            REQUIRE(got.kind == row.expect);
            if (row.expect == DKind::kDeactivated) {
                CHECK_FALSE(account_active(auth_db.pool(), row.target));
            } else {
                // Refusal / no-op: nothing changed, both populations are exactly as before.
                CHECK(active_column_admins(auth_db.pool()) == before_admins);
                CHECK(counted_grant_holders(auth_db.pool()) == before_grants);
            }
        }
    }
}

TEST_CASE("lifecycle guard: a refused deactivation leaves the row present and active, and the "
          "survivor SET is exactly the expected one",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/false,
                {{"adm1", Role::admin}, {"adm2", Role::admin}, {"plain", Role::user}});
    REQUIRE(store.deactivate_account("adm1").kind == DKind::kDeactivated);
    CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"adm2"});

    const auto refused = store.deactivate_account("adm2");
    REQUIRE(refused.kind == DKind::kLastAdministratorRefused);
    CHECK(refused.err.empty());
    // The row is still there, still active, still an admin, and was not touched by the rollback.
    CHECK(account_active(auth_db.pool(), "adm2"));
    CHECK(role_column(auth_db.pool(), "adm2") == "admin");
    CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"adm2"});
    // A repeat is still refused (the refusal is stable, not a one-shot).
    CHECK(store.deactivate_account("adm2").kind == DKind::kLastAdministratorRefused);
}

TEST_CASE("lifecycle guard: a ghost grant (no auth.users row) and an inactive holder are not "
          "survivors under RBAC ON",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/true,
                {{"real", Role::user, true}, {"retired", Role::user, true, false}});
    // A pre-provisioned grant naming an account that does not exist (A2 permits it).
    grant(store, "ghost_never_logged_in");
    REQUIRE(counted_grant_holders(auth_db.pool()) == std::vector<std::string>{"real"});

    // `real` is the only COUNTED holder: the ghost and the retired holder do not rescue it.
    CHECK(store.would_strand_last_administrator("real").would_strand);
    CHECK(store.deactivate_account("real").kind == DKind::kLastAdministratorRefused);
    CHECK(account_active(auth_db.pool(), "real"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Deterministic interleavings
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("lifecycle guard: two deactivations of the last two column admins serialize on the "
          "rbac_enabled lock, exactly one wins (deterministic)",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/false, {{"race1", Role::admin}, {"race2", Role::admin}});

    HeldLocks hold(auth_db.pool());
    hold.lock_rbac_enabled();
    AccountDeactivationResult r1, r2;
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { r1 = store.deactivate_account("race1"); });
    workers.add([&] { r2 = store.deactivate_account("race2"); });
    // BOTH are parked at the first lock (not yet past it): without the rbac_enabled mutex they
    // would each run their recount against a snapshot that still shows the other as a survivor.
    REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 2).size() >= 2);
    CHECK(active_column_admins(auth_db.pool()).size() == 2);

    hold.rollback();
    workers.join_all();

    const int deactivated = (r1.kind == DKind::kDeactivated) + (r2.kind == DKind::kDeactivated);
    const int refused = (r1.kind == DKind::kLastAdministratorRefused) +
                        (r2.kind == DKind::kLastAdministratorRefused);
    CHECK(deactivated == 1);
    CHECK(refused == 1);
    CHECK(active_column_admins(auth_db.pool()).size() == 1);
}

TEST_CASE("lifecycle guard: a burst of paired concurrent deactivations never empties the column "
          "population",
          "[pg][auth_db][lifecycle_guard]") {
    // Probabilistic companion to the deterministic case above: no lock is held, the two calls are
    // released together by a start flag. Cheap (a few ms per round); the invariant is checked on
    // the resulting survivor SET every round.
    LIFECYCLE_FIXTURE(store, auth_db);
    seed(auth_db, "burn_p", Role::admin);
    seed(auth_db, "burn_q", Role::admin);
    for (int round = 0; round < 20; ++round) {
        // Reset to exactly the pair (raw break-glass), both active admins.
        exec_raw(auth_db.pool(), "UPDATE auth.users SET role = 'user'");
        exec_raw(auth_db.pool(), "UPDATE auth.users SET role = 'admin', is_active = TRUE "
                                 "WHERE username IN ('burn_p', 'burn_q')");
        std::atomic<bool> go{false};
        AccountDeactivationResult rp, rq;
        {
            // If creating the second thread throws, the first spins on `go`: release it before the
            // destructor joins, or the test hangs.
            Workers workers([&] { go = true; });
            workers.add([&] {
                while (!go.load())
                    std::this_thread::yield();
                rp = store.deactivate_account("burn_p");
            });
            workers.add([&] {
                while (!go.load())
                    std::this_thread::yield();
                rq = store.deactivate_account("burn_q");
            });
            go = true;
            workers.join_all();
        }
        INFO("round " << round);
        REQUIRE(active_column_admins(auth_db.pool()).size() == 1);
        REQUIRE(((rp.kind == DKind::kDeactivated) + (rq.kind == DKind::kDeactivated)) == 1);
    }
}

TEST_CASE("lifecycle guard: a grant that commits between the counted-set lock and the target's own "
          "grant lock still protects the target (target-grant recheck)",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    // ON; `old_holder` is the only COUNTED grant at the deactivation's snapshot; `target` has none.
    build_world(auth_db, store, /*rbac_on=*/true, {{"old_holder", Role::user, true}, {"target", Role::user}});

    // A transaction holds old_holder's grant row, so the deactivation's counted-set lock query
    // (step 2) parks on it. While it is parked, A hands the Administrator grant over: deletes
    // old_holder's and inserts target's (an INSERT does not conflict with the parked lock), then
    // commits. Step 2 resumes with the snapshot taken BEFORE target's grant existed (the locked set
    // is empty), so only the separate lock on the target's own grant row (step 3) can see it.
    HeldLocks hold(auth_db.pool());
    hold.lock_counted_grants();
    AccountDeactivationResult got;
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { got = store.deactivate_account("target"); });
    REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
    hold.run("DELETE FROM rbac_store.principal_roles WHERE principal_id = 'old_holder' AND "
             "role_name = 'Administrator'");
    hold.run("INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
             "VALUES ('user', 'target', 'Administrator')");
    hold.commit();
    workers.join_all();

    // After the handover `target` is the fleet's only administrator: deactivating it must refuse.
    CHECK(got.kind == DKind::kLastAdministratorRefused);
    CHECK(account_active(auth_db.pool(), "target"));
    CHECK(counted_grant_holders(auth_db.pool()) == std::vector<std::string>{"target"});
}

TEST_CASE("lifecycle guard: unassign_role vs deactivate_account of the last two grant holders "
          "never leaves zero (both orders of the lock queue)",
          "[pg][auth_db][lifecycle_guard]") {
    // Both calls park on the counted-set lock held here: unassign (its lock query) and
    // deactivate (its step 2). The lock queue is FIFO, so starting one call and waiting until its
    // backend is blocked BEFORE starting the other makes the queue order deterministic; the loop
    // runs both orders. Their result is order-dependent, the invariant is not.
    for (const bool unassign_queued_first : {true, false}) {
        INFO((unassign_queued_first ? "unassign queued first" : "deactivation queued first"));
        {
            LIFECYCLE_FIXTURE(store, auth_db);
            build_world(auth_db, store, /*rbac_on=*/true,
                        {{"gA", Role::user, true}, {"gB", Role::user, true}});

            HeldLocks hold(auth_db.pool());
            hold.lock_counted_grants();
            std::expected<bool, std::string> unassigned = false;
            AccountDeactivationResult deactivated;
            const auto start_unassign = [&] {
                unassigned = store.unassign_role("user", "gB", "Administrator");
            };
            const auto start_deactivate = [&] { deactivated = store.deactivate_account("gA"); };
            Workers workers([&] { hold.rollback(); });
            if (unassign_queued_first) {
                workers.add(start_unassign);
                REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
                workers.add(start_deactivate);
            } else {
                workers.add(start_deactivate);
                REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
                workers.add(start_unassign);
            }
            REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 2).size() >= 2);
            hold.rollback();
            workers.join_all();

            const bool unassign_ok = unassigned.has_value();
            const bool deactivate_ok = (deactivated.kind == DKind::kDeactivated);
            // Exactly one wins; the loser is the typed last-Administrator refusal, never a store
            // fault.
            CHECK(unassign_ok != deactivate_ok);
            if (!unassign_ok) {
                CHECK(is_rbac_last_admin_refusal(unassigned.error()));
            }
            if (!deactivate_ok) {
                CHECK(deactivated.kind == DKind::kLastAdministratorRefused);
            }
            CHECK(counted_grant_holders(auth_db.pool()).size() == 1);
        }
    }
}

TEST_CASE("lifecycle guard: set_enforcement vs deactivation of the sole grant holder never ends "
          "ON with zero counted administrators (both orders)",
          "[pg][auth_db][lifecycle_guard]") {
    for (const bool toggle_queued_first : {true, false}) {
        INFO((toggle_queued_first ? "toggle queued first" : "deactivation queued first"));
        {
            LIFECYCLE_FIXTURE(store, auth_db);
            // OFF. `root` is a column admin AND the only grant holder; `root2` is a second column
            // admin without a grant. Deactivating root alone is fine under OFF (root2 survives the
            // column floor; the grant floor is ON-only). Enabling needs root active. They exclude
            // each other: after enforcement is ON, root is the sole counted grant.
            build_world(auth_db, store, /*rbac_on=*/false,
                        {{"root", Role::admin, true}, {"root2", Role::admin}});

            HeldLocks hold(auth_db.pool());
            hold.lock_rbac_enabled();
            std::expected<RbacEnforcementTransition, RbacEnforcementError> toggled =
                std::unexpected(RbacEnforcementError{});
            AccountDeactivationResult deactivated;
            const auto start_toggle = [&] { toggled = store.set_rbac_enforcement(true, "root"); };
            const auto start_deactivate = [&] { deactivated = store.deactivate_account("root"); };
            Workers workers([&] { hold.rollback(); });
            if (toggle_queued_first) {
                workers.add(start_toggle);
                REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
                workers.add(start_deactivate);
            } else {
                workers.add(start_deactivate);
                REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
                workers.add(start_toggle);
            }
            REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 2).size() >= 2);
            hold.rollback();
            workers.join_all();

            const bool toggle_ok = toggled.has_value();
            const bool deactivate_ok = (deactivated.kind == DKind::kDeactivated);
            // Whichever ran first, the other is refused: never both, never neither.
            CHECK(toggle_ok != deactivate_ok);
            const bool enforcement_on = store.is_rbac_enabled();
            const auto counted = counted_grant_holders(auth_db.pool());
            CHECK_FALSE((enforcement_on && counted.empty()));
            if (deactivate_ok) {
                CHECK_FALSE(toggle_ok);
                CHECK_FALSE(enforcement_on);
            } else {
                CHECK(deactivated.kind == DKind::kLastAdministratorRefused);
                CHECK(enforcement_on);
                CHECK(counted == std::vector<std::string>{"root"});
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Failure reporting: a lock timeout / lost connection is a store failure, never a hang or half write
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("lifecycle guard: a lock wait that expires is reported as a store failure within the "
          "transaction-local bound, nothing is written, and the pool is not wedged",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/false,
                {{"to_a", Role::admin}, {"to_b", Role::admin}, {"to_u", Role::user}});

    HeldLocks hold(auth_db.pool());
    hold.lock_rbac_enabled();
    AccountDeactivationResult dres;
    LocalRoleChangeResult rres;
    std::chrono::milliseconds d_elapsed{0}, r_elapsed{0};
    Workers workers([&] { hold.rollback(); });
    workers.add([&] {
        const auto t0 = std::chrono::steady_clock::now();
        dres = store.deactivate_account("to_a");
        d_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    });
    workers.add([&] {
        const auto t0 = std::chrono::steady_clock::now();
        rres = store.set_local_role("to_b", Role::user);
        r_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    });
    // Both threads wait out the same 2 s together, so this costs one 2 s wait, not two.
    workers.join_all();

    CHECK(dres.kind == DKind::kStoreFailure);
    CHECK(rres.kind == RKind::kStoreFailure);
    CHECK_FALSE(dres.err.empty());
    CHECK_FALSE(rres.err.empty());
    CHECK(dres.err.find("lock timeout") != std::string::npos);
    CHECK(rres.err.find("lock timeout") != std::string::npos);
    // The transaction-local 2000 ms applied (the pool's own default is 10 s and would fail this
    // upper bound): ~2 s, with generous slack for a loaded runner.
    CHECK(d_elapsed >= std::chrono::milliseconds(1500));
    CHECK(d_elapsed < std::chrono::milliseconds(8000));
    CHECK(r_elapsed >= std::chrono::milliseconds(1500));
    CHECK(r_elapsed < std::chrono::milliseconds(8000));
    // No half write.
    CHECK(account_active(auth_db.pool(), "to_a"));
    CHECK(role_column(auth_db.pool(), "to_b") == "admin");
    // The pool still works once the lock is gone.
    hold.rollback();
    CHECK(store.deactivate_account("to_a").kind == DKind::kDeactivated);
}

TEST_CASE("lifecycle guard: the lifecycle lock timeout is clamped into [1 ms, 60 s], so zero does "
          "not disable the bound and a negative or oversized value does not fail every write",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(seeding_store, auth_db);
    build_world(auth_db, seeding_store, /*rbac_on=*/false,
                {{"cl_a", Role::admin}, {"cl_b", Role::admin}, {"cl_c", Role::admin}});

    SECTION("zero: a held lock fails fast instead of waiting on the pool's own, longer, bound") {
        RbacStore store{auth_db.pool(), std::chrono::milliseconds(0)};
        REQUIRE(store.is_open());
        HeldLocks hold(auth_db.pool());
        hold.lock_rbac_enabled();
        AccountDeactivationResult dres;
        std::chrono::milliseconds elapsed{0};
        Workers workers([&] { hold.rollback(); });
        workers.add([&] {
            const auto t0 = std::chrono::steady_clock::now();
            dres = store.deactivate_account("cl_a");
            elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0);
        });
        workers.join_all();
        CHECK(dres.kind == DKind::kStoreFailure);
        // Unclamped, lock_timeout=0 waits for the pool's 10 s statement bound; clamped, it is 1 ms.
        CHECK(elapsed < std::chrono::milliseconds(3000));
        CHECK(account_active(auth_db.pool(), "cl_a"));
    }
    SECTION("negative: the write still works (an unclamped negative value is a statement error)") {
        RbacStore store{auth_db.pool(), std::chrono::milliseconds(-5)};
        REQUIRE(store.is_open());
        CHECK(store.deactivate_account("cl_b").kind == DKind::kDeactivated);
        CHECK_FALSE(account_active(auth_db.pool(), "cl_b"));
    }
    SECTION("above 2^31 ms: the write still works (an unclamped value is a statement error)") {
        // Postgres rejects a lock_timeout above 2^31-1 ms; the constructor clamps to the 60 s
        // ceiling (kMaxLifecycleLockTimeout), so the guarded write is not failed by the setting.
        RbacStore store{auth_db.pool(), std::chrono::milliseconds(3'000'000'000LL)};
        REQUIRE(store.is_open());
        CHECK(store.deactivate_account("cl_c").kind == DKind::kDeactivated);
        CHECK_FALSE(account_active(auth_db.pool(), "cl_c"));
    }
    SECTION("the maximum representable duration is clamped too") {
        RbacStore store{auth_db.pool(), std::chrono::milliseconds::max()};
        REQUIRE(store.is_open());
        CHECK(store.deactivate_account("cl_c").kind == DKind::kDeactivated);
    }
}

TEST_CASE("lifecycle guard: a connection lost mid-transaction rolls back cleanly as a store failure",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/false, {{"k1", Role::admin}, {"k2", Role::admin}});

    HeldLocks hold(auth_db.pool());
    hold.lock_rbac_enabled();
    AccountDeactivationResult got;
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { got = store.deactivate_account("k1"); });
    const auto pids = wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1);
    REQUIRE(pids.size() >= 1);
    hold.run("SELECT pg_terminate_backend(" + std::to_string(pids.front()) + ")");
    workers.join_all();

    CHECK(got.kind == DKind::kStoreFailure);
    CHECK_FALSE(got.err.empty());
    CHECK(account_active(auth_db.pool(), "k1"));
    hold.rollback();
    // Not wedged: the next call runs, and with two admins present it succeeds.
    CHECK(store.deactivate_account("k1").kind == DKind::kDeactivated);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// set_local_role: the demotion floor
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("lifecycle guard: set_local_role refuses to demote the last active column admin, in "
          "both regimes",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    for (const bool rbac_on : {false, true}) {
        INFO((rbac_on ? "RBAC ON" : "RBAC OFF"));
        {
            // ON: grant holders elsewhere do NOT rescue the column population (column floor only).
            build_world(auth_db, store, rbac_on,
                        {{"d1", Role::admin}, {"d2", Role::admin}, {"gh", Role::user, true}});
            REQUIRE(store.set_local_role("d1", Role::user).kind == RKind::kChanged);
            CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"d2"});

            const auto refused = store.set_local_role("d2", Role::user);
            CHECK(refused.kind == RKind::kLastAdministratorRefused);
            CHECK(refused.err.empty());
            // Rolled back: still admin, still the exact survivor.
            CHECK(role_column(auth_db.pool(), "d2") == "admin");
            CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"d2"});
        }
    }
}

TEST_CASE("lifecycle guard: set_local_role classification (not found, unchanged, promotion, "
          "inactive accounts) and the already-zero population",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/false,
                {{"adm", Role::admin}, {"plain", Role::user}, {"retired_adm", Role::admin, false, false},
                 {"retired_user", Role::user, false, false}});

    CHECK(store.set_local_role("nobody", Role::user).kind == RKind::kNotFound);
    CHECK(store.set_local_role("adm", Role::admin).kind == RKind::kUnchanged);
    CHECK(store.set_local_role("plain", Role::user).kind == RKind::kUnchanged);

    // An INACTIVE account is never re-armed by a role write...
    CHECK(store.set_local_role("retired_user", Role::admin).kind == RKind::kInactivePromotionRefused);
    CHECK(role_column(auth_db.pool(), "retired_user") == "user");
    // ...but an inactive elevated tombstone CAN be demoted, and its demotion is never refused: it
    // was not counted (the active survivor `adm` is untouched).
    CHECK(store.set_local_role("retired_adm", Role::user).kind == RKind::kChanged);
    CHECK(role_column(auth_db.pool(), "retired_adm") == "user");
    CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"adm"});

    // Promotion of an active account grows the population; then the first admin can be demoted.
    CHECK(store.set_local_role("plain", Role::admin).kind == RKind::kChanged);
    CHECK(store.set_local_role("adm", Role::user).kind == RKind::kChanged);
    CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"plain"});

    // Already-zero population: nobody is a member, so a no-op-by-membership demotion never blocks.
    exec_raw(auth_db.pool(), "UPDATE auth.users SET role = 'user'");
    REQUIRE(active_column_admins(auth_db.pool()).empty());
    CHECK(store.set_local_role("plain", Role::user).kind == RKind::kUnchanged);
}

TEST_CASE("lifecycle guard: a demotion racing a deactivation of the last two column admins leaves "
          "exactly one (both orders of the lock queue)",
          "[pg][auth_db][lifecycle_guard]") {
    // Starting one call and waiting until its backend is blocked before starting the other makes
    // the FIFO lock-queue order deterministic; the loop runs both orders.
    for (const bool demotion_queued_first : {true, false}) {
        INFO((demotion_queued_first ? "demotion queued first" : "deactivation queued first"));
        {
            LIFECYCLE_FIXTURE(store, auth_db);
            build_world(auth_db, store, /*rbac_on=*/false,
                        {{"m1", Role::admin}, {"m2", Role::admin}});

            HeldLocks hold(auth_db.pool());
            hold.lock_rbac_enabled();
            LocalRoleChangeResult demoted;
            AccountDeactivationResult deactivated;
            const auto start_demote = [&] { demoted = store.set_local_role("m1", Role::user); };
            const auto start_deactivate = [&] { deactivated = store.deactivate_account("m2"); };
            Workers workers([&] { hold.rollback(); });
            if (demotion_queued_first) {
                workers.add(start_demote);
                REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
                workers.add(start_deactivate);
            } else {
                workers.add(start_deactivate);
                REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
                workers.add(start_demote);
            }
            REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 2).size() >= 2);
            hold.rollback();
            workers.join_all();

            const bool demote_ok = (demoted.kind == RKind::kChanged);
            const bool deactivate_ok = (deactivated.kind == DKind::kDeactivated);
            CHECK(demote_ok != deactivate_ok);
            CHECK(active_column_admins(auth_db.pool()).size() == 1);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// would_strand_last_administrator
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("lifecycle guard: would_strand_last_administrator takes no lock, whatever is held",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/true, {{"ws_a", Role::admin, true}, {"ws_b", Role::user}});

    HeldLocks hold(auth_db.pool());
    hold.lock_rbac_enabled();
    hold.lock_counted_grants();
    hold.run("SELECT 1 FROM auth.users WHERE username IN ('ws_a', 'ws_b') FOR UPDATE");

    // Runs on THIS thread with every lock held by the other connection. A call that waited on any
    // of them would block until the pool's 10 s lock_timeout fired, which the bound catches.
    const auto t0 = std::chrono::steady_clock::now();
    const auto a = store.would_strand_last_administrator("ws_a");
    const auto b = store.would_strand_last_administrator("ws_b");
    const auto unknown = store.would_strand_last_administrator("nobody");
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < std::chrono::seconds(2));

    REQUIRE(a.ok);
    CHECK(a.would_strand); // sole column admin and sole grant holder
    REQUIRE(b.ok);
    CHECK_FALSE(b.would_strand);
    REQUIRE(unknown.ok);
    CHECK_FALSE(unknown.would_strand);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// AuthManager: remove_user_checked / update_role_checked (the production entry to the guard)
// ═════════════════════════════════════════════════════════════════════════════════════════════

namespace {

using yuzu::server::auth::AuthManager;
using yuzu::server::auth::RemoveUserOutcome;
using yuzu::server::auth::UpdateRoleOutcome;

// The production composition: AuthDB + RbacStore + SessionStore on ONE pool, wired into an
// AuthManager. `wire_rbac = false` reproduces a server that forgot the injection.
struct ManagerFx {
    yuzu::test::AuthDbPg db{0, false, &yuzu::test::auth_db_rbac_pg_template};
    RbacStore rbac;
    yuzu::server::SessionStore sessions{db.pool()};
    SessionWipeFault wipe_fault{db.pool()}; // RAII: repaired even when a REQUIRE unwinds
    yuzu::MetricsRegistry metrics;
    AuthManager mgr;

    // `lock_timeout` is the lifecycle guard's lock bound: the production 2000 ms by default, a
    // short value for a case that only needs a lock wait to EXPIRE (not the 2000 ms itself).
    explicit ManagerFx(bool wire_rbac = true,
                       std::chrono::milliseconds lock_timeout = kDefaultLifecycleLockTimeout)
        : rbac(db.pool(), lock_timeout) {
        REQUIRE(rbac.is_open());
        REQUIRE(sessions.is_open());
        mgr.set_auth_db(db.get());
        mgr.set_session_store(&sessions);
        mgr.set_metrics_registry(&metrics);
        if (wire_rbac)
            mgr.set_rbac_store(&rbac);
    }
    // `yuzu_server_rbac_lifecycle_store_failure_total{op}` as the lifecycle wrappers count it.
    double store_failures(const char* op) {
        return metrics.counter("yuzu_server_rbac_lifecycle_store_failure_total", {{"op", op}})
            .value();
    }
    ~ManagerFx() {
        mgr.set_metrics_registry(nullptr);
        mgr.set_rbac_store(nullptr);
        mgr.set_session_store(nullptr);
        mgr.set_auth_db(nullptr);
    }
    ManagerFx(const ManagerFx&) = delete;
    ManagerFx& operator=(const ManagerFx&) = delete;

    int durable_sessions_of(const std::string& user) {
        return static_cast<int>(
            query_col(db.pool(),
                      ("SELECT 1 FROM session_store.sessions WHERE username = '" + user + "'").c_str())
                .size());
    }
    // A REAL fault in the throwaway database: the durable session table is moved aside, so the
    // post-commit wipe's DELETE genuinely fails while the guarded account write is unaffected.
    // RAII-scoped through `wipe_fault` (idempotent repair, noexcept destructor).
    void break_session_wipe() { wipe_fault.arm(); }
    void repair_session_wipe() { wipe_fault.repair(); }
};

} // namespace

TEST_CASE("AuthManager lifecycle guard: the unwired decision is exactly 'AuthDB set, RbacStore not'",
          "[lifecycle_guard][auth]") {
    // The ONE decision shared by the runtime fail-closed arms and the boot self-check.
    CHECK(AuthManager::lifecycle_guard_unwired(true, false));
    CHECK_FALSE(AuthManager::lifecycle_guard_unwired(true, true));
    CHECK_FALSE(AuthManager::lifecycle_guard_unwired(false, false)); // config-file-only mode
    CHECK_FALSE(AuthManager::lifecycle_guard_unwired(false, true));
}

TEST_CASE("AuthManager lifecycle guard: config-file mode (no AuthDB) keeps the in-memory path "
          "and needs no guard",
          "[lifecycle_guard][auth]") {
    AuthManager mgr; // no AuthDB, no RbacStore: nothing to dereference
    REQUIRE_FALSE(mgr.has_rbac_store());
    REQUIRE(mgr.upsert_user("cfguser", "a-sufficiently-long-password-1", Role::user));
    REQUIRE(mgr.upsert_user("cfgadmin", "a-sufficiently-long-password-2", Role::admin));

    CHECK(mgr.update_role_checked("cfguser", Role::admin) == UpdateRoleOutcome::Updated);
    CHECK(mgr.get_user_role("cfguser") == Role::admin);
    CHECK(mgr.update_role_checked("nobody", Role::admin) == UpdateRoleOutcome::NotFound);
    CHECK_FALSE(mgr.update_role("nobody", Role::admin));

    // No last-Administrator floor in config-file mode: there is no DB population to protect and
    // the in-memory behaviour is unchanged.
    CHECK(mgr.remove_user_checked("cfgadmin") == RemoveUserOutcome::Removed);
    CHECK(mgr.remove_user_checked("cfgadmin") == RemoveUserOutcome::NotFound);
    CHECK_FALSE(mgr.remove_user("cfgadmin"));
    CHECK(mgr.remove_user("cfguser"));
}

TEST_CASE("AuthManager lifecycle guard: with an AuthDB and NO RbacStore both writes fail CLOSED, "
          "never the unguarded AuthDB path",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f(/*wire_rbac=*/false);
    seed(f.db, "fc_admin", Role::admin);
    seed(f.db, "fc_user", Role::user);
    REQUIRE_FALSE(f.mgr.has_rbac_store());

    CHECK(f.mgr.remove_user_checked("fc_user") == RemoveUserOutcome::StoreFailure);
    CHECK_FALSE(f.mgr.remove_user("fc_user"));
    CHECK(account_active(f.db.pool(), "fc_user")); // the unguarded soft delete did not run
    CHECK(f.mgr.update_role_checked("fc_user", Role::admin) == UpdateRoleOutcome::StoreFailure);
    CHECK_FALSE(f.mgr.update_role("fc_user", Role::admin));
    CHECK(role_column(f.db.pool(), "fc_user") == "user"); // nor the unguarded role write
    CHECK(active_column_admins(f.db.pool()) == std::vector<std::string>{"fc_admin"});
}

TEST_CASE("AuthManager lifecycle guard: remove_user_checked outcomes (Removed, NotFound, refused)",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f;
    seed(f.db, "ou_admin", Role::admin);
    seed(f.db, "ou_user", Role::user);
    const auto user_session = f.mgr.create_local_session_for_test("ou_user", Role::user, false);
    const auto admin_session = f.mgr.create_local_session_for_test("ou_admin", Role::admin, false);
    REQUIRE_FALSE(user_session.empty());
    REQUIRE_FALSE(admin_session.empty());
    REQUIRE(f.durable_sessions_of("ou_user") == 1);

    // Refused: the sole active column admin. NOTHING changes, in particular its session lives on.
    CHECK(f.mgr.remove_user_checked("ou_admin") == RemoveUserOutcome::LastAdministratorRefused);
    CHECK_FALSE(f.mgr.remove_user("ou_admin"));
    CHECK(account_active(f.db.pool(), "ou_admin"));
    CHECK(f.mgr.validate_session(admin_session).has_value());
    CHECK(f.durable_sessions_of("ou_admin") == 1);

    // Removed: committed first, then caches and BOTH session copies are gone.
    CHECK(f.mgr.remove_user_checked("ou_user") == RemoveUserOutcome::Removed);
    CHECK_FALSE(account_active(f.db.pool(), "ou_user"));
    CHECK_FALSE(f.mgr.validate_session(user_session).has_value());
    CHECK(f.durable_sessions_of("ou_user") == 0);

    // Idempotent: the row is already inactive, and an unknown name is the same answer.
    CHECK(f.mgr.remove_user_checked("ou_user") == RemoveUserOutcome::NotFound);
    CHECK(f.mgr.remove_user_checked("ou_nobody") == RemoveUserOutcome::NotFound);
    CHECK_FALSE(f.mgr.remove_user("ou_nobody"));
}

TEST_CASE("AuthManager lifecycle guard: RemovedSessionWipeFailed says the row IS deactivated, and "
          "a retry converges",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f;
    seed(f.db, "wf_admin", Role::admin);
    seed(f.db, "wf_user", Role::user);
    const auto token = f.mgr.create_local_session_for_test("wf_user", Role::user, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE(f.durable_sessions_of("wf_user") == 1);

    f.break_session_wipe();
    // The guarded write committed; only the durable wipe failed. NOT StoreFailure: that would
    // lie that the row is untouched.
    CHECK(f.mgr.remove_user_checked("wf_user") == RemoveUserOutcome::RemovedSessionWipeFailed);
    CHECK_FALSE(account_active(f.db.pool(), "wf_user"));
    // The bool wrapper stays false (the pre-existing fail-closed return).
    // A retry with the store still broken: the row is already inactive, nothing was removed BY
    // THIS CALL, and the wipe failed again.
    CHECK(f.mgr.remove_user_checked("wf_user") == RemoveUserOutcome::StoreFailure);

    f.repair_session_wipe();
    // Converges: the wipe now succeeds on the already-inactive row, and the durable row is gone.
    CHECK(f.mgr.remove_user_checked("wf_user") == RemoveUserOutcome::NotFound);
    CHECK(f.durable_sessions_of("wf_user") == 0);
    CHECK_FALSE(f.mgr.validate_session(token).has_value());
}

TEST_CASE("AuthManager lifecycle guard: a store failure inside the guard is StoreFailure, and "
          "AuthManager::mu_ is NOT held across the owner call",
          "[pg][auth_db][lifecycle_guard]") {
    // A shortened lock bound: this case needs the waits to EXPIRE, not the 2000 ms value (the
    // lock-timeout case above pins that). 800 ms still leaves the probe ample time to see both
    // workers blocked together.
    ManagerFx f(/*wire_rbac=*/true, std::chrono::milliseconds(800));
    seed(f.db, "mu_a", Role::admin);
    seed(f.db, "mu_b", Role::admin);

    HeldLocks hold(f.db.pool());
    hold.lock_rbac_enabled();
    RemoveUserOutcome removed = RemoveUserOutcome::Removed;
    UpdateRoleOutcome updated = UpdateRoleOutcome::Updated;
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { removed = f.mgr.remove_user_checked("mu_a"); });
    workers.add([&] { updated = f.mgr.update_role_checked("mu_b", Role::user); });
    REQUIRE(wait_for_blocked_backends(f.db.dsn(), hold.pid(), 2).size() >= 2);

    // Both workers are INSIDE the owner call right now. An AuthManager accessor that takes
    // mu_ must still answer at once; had remove_user_checked held mu_ across the call (the
    // deadlock shape with recheck_role_after_credential_check), this call would wait until the
    // workers' lock_timeout (800 ms here) expired and they released it, and a login-path reader
    // would be stalled behind an admin's lock wait. No wall-clock bound: the proof is that both
    // backends are STILL lock-blocked when the call returns (a held mu_ could only have been
    // released after the workers' waits ended).
    (void)f.mgr.has_users(); // takes mu_ shared; a held unique mu_ would block it here
    CHECK(wait_for_blocked_backends(f.db.dsn(), hold.pid(), 2).size() >= 2);

    workers.join_all(); // both wait out the (shortened) transaction-local lock_timeout together
    CHECK(removed == RemoveUserOutcome::StoreFailure);
    CHECK(updated == UpdateRoleOutcome::StoreFailure);
    CHECK(account_active(f.db.pool(), "mu_a"));
    CHECK(role_column(f.db.pool(), "mu_b") == "admin");
}

TEST_CASE("AuthManager lifecycle guard: update_role_checked outcomes",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f;
    seed(f.db, "ur_admin", Role::admin);
    seed(f.db, "ur_user", Role::user);
    seed(f.db, "ur_gone", Role::user);
    REQUIRE(f.db->remove_user("ur_gone").has_value());
    const auto token = f.mgr.create_local_session_for_test("ur_user", Role::user, false);
    REQUIRE_FALSE(token.empty());

    CHECK(f.mgr.update_role_checked("ur_nobody", Role::admin) == UpdateRoleOutcome::NotFound);
    CHECK_FALSE(f.mgr.update_role("ur_nobody", Role::admin));
    // Never re-arm an inactive account.
    CHECK(f.mgr.update_role_checked("ur_gone", Role::admin) == UpdateRoleOutcome::InactivePromotionRefused);
    CHECK(role_column(f.db.pool(), "ur_gone") == "user");
    // The sole active column admin cannot be demoted; nothing changes.
    CHECK(f.mgr.update_role_checked("ur_admin", Role::user) == UpdateRoleOutcome::LastAdministratorRefused);
    CHECK(role_column(f.db.pool(), "ur_admin") == "admin");

    // A real change wipes the user's sessions so they pick up the new role.
    CHECK(f.mgr.update_role_checked("ur_user", Role::admin) == UpdateRoleOutcome::Updated);
    CHECK(role_column(f.db.pool(), "ur_user") == "admin");
    CHECK_FALSE(f.mgr.validate_session(token).has_value());
    // With two admins the first can now be demoted; the bool wrapper agrees.
    CHECK(f.mgr.update_role("ur_admin", Role::user));
    CHECK(active_column_admins(f.db.pool()) == std::vector<std::string>{"ur_user"});
}

TEST_CASE("AuthManager lifecycle guard: UpdatedSessionWipeFailed says the role IS changed, and a "
          "retry converges (the row already holds the role)",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f;
    seed(f.db, "uw_admin", Role::admin);
    seed(f.db, "uw_user", Role::user);
    const auto token = f.mgr.create_local_session_for_test("uw_user", Role::user, false);
    REQUIRE_FALSE(token.empty());

    f.break_session_wipe();
    CHECK(f.mgr.update_role_checked("uw_user", Role::admin) == UpdateRoleOutcome::UpdatedSessionWipeFailed);
    CHECK(role_column(f.db.pool(), "uw_user") == "admin"); // committed
    CHECK_FALSE(f.mgr.update_role("uw_user", Role::admin)); // wrapper: not a clean success

    f.repair_session_wipe();
    // The retry finds the role already set (Unchanged inside), still wipes, and succeeds.
    CHECK(f.mgr.update_role_checked("uw_user", Role::admin) == UpdateRoleOutcome::Updated);
    CHECK(f.durable_sessions_of("uw_user") == 0);
    CHECK_FALSE(f.mgr.validate_session(token).has_value());
}

TEST_CASE("lifecycle guard: a name is_valid_username rejects is NotFound / not a member, before "
          "any statement runs (embedded NUL, over-long, empty, forbidden characters)",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, /*rbac_on=*/true, {{"iv_admin", Role::admin, true}});

    std::string with_nul = "iv_admin";
    with_nul.push_back('\0');
    with_nul += "x"; // a libpq parameter would be cut at the NUL, aliasing the real "iv_admin"
    const std::vector<std::string> bad = {with_nul, std::string(65, 'a'), "", "iv admin",
                                          "iv_admin;--", "oidc:iss#sub"};
    for (const auto& name : bad) {
        CAPTURE(name.size());
        CHECK(store.deactivate_account(name).kind == DKind::kNotFound);
        CHECK(store.set_local_role(name, Role::user).kind == RKind::kNotFound);
        CHECK(store.set_local_role(name, Role::admin).kind == RKind::kNotFound);
        const auto strand = store.would_strand_last_administrator(name);
        CHECK(strand.ok);
        CHECK_FALSE(strand.would_strand);
    }
    // The real account was never touched by any of them.
    CHECK(account_active(auth_db.pool(), "iv_admin"));
    CHECK(role_column(auth_db.pool(), "iv_admin") == "admin");
    CHECK(counted_grant_holders(auth_db.pool()) == std::vector<std::string>{"iv_admin"});
}

TEST_CASE("AuthManager lifecycle guard: a StoreFailure from the guarded removal evicts the "
          "TARGET's sessions (fail toward re-authentication), still answers StoreFailure, and is "
          "counted",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f(/*wire_rbac=*/true, std::chrono::milliseconds(300));
    seed(f.db, "ev_a", Role::admin);
    seed(f.db, "ev_b", Role::admin);
    seed(f.db, "ev_bystander", Role::user);
    const auto target = f.mgr.create_local_session_for_test("ev_a", Role::admin, false);
    const auto bystander = f.mgr.create_local_session_for_test("ev_bystander", Role::user, false);
    REQUIRE_FALSE(target.empty());
    REQUIRE_FALSE(bystander.empty());
    REQUIRE(f.durable_sessions_of("ev_a") == 1);

    HeldLocks hold(f.db.pool());
    hold.lock_rbac_enabled();
    RemoveUserOutcome out = RemoveUserOutcome::Removed;
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { out = f.mgr.remove_user_checked("ev_a"); });
    workers.join_all(); // the guarded write waits out the (shortened) lock_timeout and fails

    CHECK(out == RemoveUserOutcome::StoreFailure);
    CHECK(f.store_failures("deactivate") == 1.0);
    CHECK(account_active(f.db.pool(), "ev_a")); // nothing committed
    // The target's possibly-committed removal is not served stale: its session is gone in memory
    // AND durably; a bystander's is untouched.
    CHECK_FALSE(f.mgr.validate_session(target).has_value());
    CHECK(f.durable_sessions_of("ev_a") == 0);
    CHECK(f.mgr.validate_session(bystander).has_value());
    CHECK(f.durable_sessions_of("ev_bystander") == 1);
}

TEST_CASE("AuthManager lifecycle guard: a StoreFailure from the guarded role write evicts the "
          "TARGET's sessions, leaves the stored role alone, and is counted",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f(/*wire_rbac=*/true, std::chrono::milliseconds(300));
    seed(f.db, "er_a", Role::admin);
    seed(f.db, "er_b", Role::admin);
    const auto target = f.mgr.create_local_session_for_test("er_b", Role::admin, false);
    REQUIRE_FALSE(target.empty());

    HeldLocks hold(f.db.pool());
    hold.lock_rbac_enabled();
    UpdateRoleOutcome out = UpdateRoleOutcome::Updated;
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { out = f.mgr.update_role_checked("er_b", Role::user); });
    workers.join_all();

    CHECK(out == UpdateRoleOutcome::StoreFailure);
    CHECK(f.store_failures("set_role") == 1.0);
    CHECK(role_column(f.db.pool(), "er_b") == "admin"); // nothing committed
    CHECK_FALSE(f.mgr.validate_session(target).has_value());
    CHECK(f.durable_sessions_of("er_b") == 0);
}

TEST_CASE("AuthManager lifecycle guard: the unwired fail-closed arm counts a store failure but "
          "evicts nothing (nothing was attempted)",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f(/*wire_rbac=*/false);
    seed(f.db, "uw2_user", Role::user);
    const auto token = f.mgr.create_local_session_for_test("uw2_user", Role::user, false);
    REQUIRE_FALSE(token.empty());

    CHECK(f.mgr.remove_user_checked("uw2_user") == RemoveUserOutcome::StoreFailure);
    CHECK(f.mgr.update_role_checked("uw2_user", Role::admin) == UpdateRoleOutcome::StoreFailure);
    CHECK(f.store_failures("deactivate") == 1.0);
    CHECK(f.store_failures("set_role") == 1.0);
    CHECK(f.mgr.validate_session(token).has_value()); // the session survives: no write was tried
}

TEST_CASE("AuthManager lifecycle guard: the advisory read and the grant read count their own "
          "store failures",
          "[pg][auth_db][lifecycle_guard]") {
    ManagerFx f;
    seed(f.db, "sf_user", Role::user);
    // Healthy first: both answer and neither counts.
    REQUIRE(f.mgr.would_strand_last_administrator("sf_user").has_value());
    REQUIRE(f.mgr.holds_administrator_grant("sf_user").has_value());
    CHECK(f.store_failures("would_strand") == 0.0);
    CHECK(f.store_failures("grant_read") == 0.0);
    {
        yuzu::test::SqlFault meta(f.db.pool(),
                                  "ALTER TABLE rbac_store.rbac_meta RENAME TO rbac_meta_gone",
                                  "ALTER TABLE rbac_store.rbac_meta_gone RENAME TO rbac_meta");
        meta.arm();
        CHECK_FALSE(f.mgr.would_strand_last_administrator("sf_user").has_value());
        CHECK(f.store_failures("would_strand") == 1.0);
    }
    {
        yuzu::test::GrantReadFault grants(f.db.pool());
        grants.arm();
        CHECK_FALSE(f.mgr.holds_administrator_grant("sf_user").has_value());
        CHECK(f.store_failures("grant_read") == 1.0);
    }
    CHECK(f.store_failures("deactivate") == 0.0);
    CHECK(f.store_failures("set_role") == 0.0);
}


TEST_CASE("lifecycle guard: both guarded transactions run under the lock and idle-in-transaction "
          "bounds, transaction-locally",
          "[pg][auth_db][lifecycle_guard]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    seed(auth_db, "bound_a", Role::user);
    seed(auth_db, "bound_b", Role::user);
    // A BEFORE UPDATE trigger on auth.users records the session settings in force INSIDE the
    // guarded transaction (the only place the owner's set_config calls are observable). The
    // throwaway database is private to this case, so nothing needs undoing.
    exec_raw(auth_db.pool(), "CREATE TABLE public.yuzu_test_bound_probe (op text, idle text, lock text)");
    exec_raw(auth_db.pool(),
             "CREATE FUNCTION public.yuzu_test_bound_probe_fn() RETURNS trigger LANGUAGE plpgsql AS "
             "$$ BEGIN INSERT INTO public.yuzu_test_bound_probe VALUES (TG_OP, "
             "current_setting('idle_in_transaction_session_timeout'), "
             "current_setting('lock_timeout')); RETURN NEW; END $$");
    exec_raw(auth_db.pool(),
             "CREATE TRIGGER yuzu_test_bound_probe_trg BEFORE UPDATE ON auth.users FOR EACH ROW "
             "EXECUTE FUNCTION public.yuzu_test_bound_probe_fn()");

    REQUIRE(store.deactivate_account("bound_a").kind == DKind::kDeactivated);
    REQUIRE(store.set_local_role("bound_b", Role::admin).kind == RKind::kChanged);

    const auto idle = query_col(auth_db.pool(), "SELECT idle FROM public.yuzu_test_bound_probe");
    const auto lock = query_col(auth_db.pool(), "SELECT lock FROM public.yuzu_test_bound_probe");
    REQUIRE(idle.size() >= 2); // one row per guarded write
    for (const auto& v : idle)
        CHECK(v == "15s");
    for (const auto& v : lock)
        CHECK(v == "2s");

    // Transaction-local: NO pooled connection sees either bound afterwards. Deterministic, not a
    // sample of a FIFO pool: lease EVERY connection at once (the pool has `size()` of them, so
    // each lease is a distinct connection) and read the setting on each.
    std::vector<decltype(auth_db.pool().acquire())> leases;
    for (std::size_t i = 0; i < auth_db.pool().size(); ++i) {
        // Bounded, so a leaked lease fails here fast instead of hanging the suite.
        leases.push_back(auth_db.pool().try_acquire_for(std::chrono::seconds(5)));
        REQUIRE(leases.back());
    }
    for (auto& lease : leases) {
        pg::PgResult r = pg::exec_params(lease.get(), "SHOW idle_in_transaction_session_timeout",
                                         std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(r.get()) == 1);
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) != "15s");
    }
}
