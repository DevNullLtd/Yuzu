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
#include <stdexcept>
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
// This file exercises the guard, not the session cache: no SessionStore is wired.
constexpr auto kNoSessionStore = SessionGenerationMode::kNoSessionStore;

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

            const auto got = store.deactivate_account(row.target, kNoSessionStore);
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
    REQUIRE(store.deactivate_account("adm1", kNoSessionStore).kind == DKind::kDeactivated);
    CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"adm2"});

    const auto refused = store.deactivate_account("adm2", kNoSessionStore);
    REQUIRE(refused.kind == DKind::kLastAdministratorRefused);
    CHECK(refused.err.empty());
    // The row is still there, still active, still an admin, and was not touched by the rollback.
    CHECK(account_active(auth_db.pool(), "adm2"));
    CHECK(role_column(auth_db.pool(), "adm2") == "admin");
    CHECK(active_column_admins(auth_db.pool()) == std::vector<std::string>{"adm2"});
    // A repeat is still refused (the refusal is stable, not a one-shot).
    CHECK(store.deactivate_account("adm2", kNoSessionStore).kind == DKind::kLastAdministratorRefused);
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
    CHECK(store.deactivate_account("real", kNoSessionStore).kind == DKind::kLastAdministratorRefused);
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
    workers.add([&] { r1 = store.deactivate_account("race1", kNoSessionStore); });
    workers.add([&] { r2 = store.deactivate_account("race2", kNoSessionStore); });
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
                rp = store.deactivate_account("burn_p", kNoSessionStore);
            });
            workers.add([&] {
                while (!go.load())
                    std::this_thread::yield();
                rq = store.deactivate_account("burn_q", kNoSessionStore);
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
    workers.add([&] { got = store.deactivate_account("target", kNoSessionStore); });
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
            // The Administrator unassign clears durable elevations: it needs the session schema.
            yuzu::server::SessionStore sessions{auth_db.pool()};
            REQUIRE(sessions.is_open());
            build_world(auth_db, store, /*rbac_on=*/true,
                        {{"gA", Role::user, true}, {"gB", Role::user, true}});

            HeldLocks hold(auth_db.pool());
            hold.lock_counted_grants();
            std::expected<bool, std::string> unassigned = false;
            AccountDeactivationResult deactivated;
            const auto start_unassign = [&] {
                unassigned = store.unassign_role("user", "gB", "Administrator");
            };
            const auto start_deactivate = [&] { deactivated = store.deactivate_account("gA", kNoSessionStore); };
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
            const auto start_deactivate = [&] { deactivated = store.deactivate_account("root", kNoSessionStore); };
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
        dres = store.deactivate_account("to_a", kNoSessionStore);
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
    CHECK(store.deactivate_account("to_a", kNoSessionStore).kind == DKind::kDeactivated);
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
            dres = store.deactivate_account("cl_a", kNoSessionStore);
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
        CHECK(store.deactivate_account("cl_b", kNoSessionStore).kind == DKind::kDeactivated);
        CHECK_FALSE(account_active(auth_db.pool(), "cl_b"));
    }
    SECTION("above 2^31 ms: the write still works (an unclamped value is a statement error)") {
        // Postgres rejects a lock_timeout above 2^31-1 ms; the constructor clamps to the 60 s
        // ceiling (kMaxLifecycleLockTimeout), so the guarded write is not failed by the setting.
        RbacStore store{auth_db.pool(), std::chrono::milliseconds(3'000'000'000LL)};
        REQUIRE(store.is_open());
        CHECK(store.deactivate_account("cl_c", kNoSessionStore).kind == DKind::kDeactivated);
        CHECK_FALSE(account_active(auth_db.pool(), "cl_c"));
    }
    SECTION("the maximum representable duration is clamped too") {
        RbacStore store{auth_db.pool(), std::chrono::milliseconds::max()};
        REQUIRE(store.is_open());
        CHECK(store.deactivate_account("cl_c", kNoSessionStore).kind == DKind::kDeactivated);
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
    workers.add([&] { got = store.deactivate_account("k1", kNoSessionStore); });
    const auto pids = wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1);
    REQUIRE(pids.size() >= 1);
    hold.run("SELECT pg_terminate_backend(" + std::to_string(pids.front()) + ")");
    workers.join_all();

    CHECK(got.kind == DKind::kStoreFailure);
    CHECK_FALSE(got.err.empty());
    CHECK(account_active(auth_db.pool(), "k1"));
    hold.rollback();
    // Not wedged: the next call runs, and with two admins present it succeeds.
    CHECK(store.deactivate_account("k1", kNoSessionStore).kind == DKind::kDeactivated);
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
            const auto start_deactivate = [&] { deactivated = store.deactivate_account("m2", kNoSessionStore); };
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
        CHECK(store.deactivate_account(name, kNoSessionStore).kind == DKind::kNotFound);
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

    REQUIRE(store.deactivate_account("bound_a", kNoSessionStore).kind == DKind::kDeactivated);
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

// ═════════════════════════════════════════════════════════════════════════════════════════════
// The session write-generation in the deactivation transaction (#7223)
//
// `deactivate_account` in `SessionGenerationMode::kBumpSessionGeneration` bumps
// `session_store.session_meta.write_generation` as the LAST statement of the same transaction, so
// every replica's validate cache is cleared by its next poll whether or not the caller's later
// durable session wipe succeeds. The cases below pin: exactly one bump per deactivation and none
// otherwise (T11), a failed bump aborting the whole deactivation (T12 + T-R6), the generation
// moving although the wipe failed (T3), and a smoke run of the new lock edge (T13).
// ═════════════════════════════════════════════════════════════════════════════════════════════

namespace {

constexpr auto kBumpSessionGeneration = SessionGenerationMode::kBumpSessionGeneration;

// The durable write generation, read raw (the test's own oracle; "0" when the row is absent).
long long session_write_generation(PgPool& pool) {
    const auto v = query_col(
        pool, "SELECT value FROM session_store.session_meta WHERE key = 'write_generation'");
    return v.empty() ? 0 : std::stoll(v.front());
}

// One text column summarising the MFA state the soft delete rewrites, plus the recovery codes.
std::string mfa_state(PgPool& pool, const std::string& name) {
    const auto v = query_col(
        pool, ("SELECT concat_ws('|', encode(mfa_totp_secret, 'hex'), "
               "(mfa_enrolled_at IS NOT NULL)::text, mfa_last_counter::text, "
               "(mfa_disabled_at IS NOT NULL)::text, "
               "(SELECT count(*) FROM auth.mfa_recovery_codes WHERE username = '" +
               name + "')::text) FROM auth.users WHERE username = '" + name + "'")
                  .c_str());
    REQUIRE(v.size() == 1);
    return v.front();
}

} // namespace

TEST_CASE("deactivate_account: the session generation moves exactly once per deactivation and not "
          "on not-found or a refusal (T11)",
          "[pg][auth_db][lifecycle_guard][session_generation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, /*rbac_on=*/false,
                {{"t11_admin", Role::admin}, {"t11_user", Role::user}, {"t11_user2", Role::user}});

    const long long g0 = session_write_generation(auth_db.pool());

    CHECK(store.deactivate_account("t11_user", kBumpSessionGeneration).kind == DKind::kDeactivated);
    CHECK(session_write_generation(auth_db.pool()) == g0 + 1);

    // Already inactive, unknown and not-a-possible-name: nothing was written, nothing bumps.
    CHECK(store.deactivate_account("t11_user", kBumpSessionGeneration).kind == DKind::kNotFound);
    CHECK(store.deactivate_account("t11_nobody", kBumpSessionGeneration).kind == DKind::kNotFound);
    CHECK(store.deactivate_account("not a name", kBumpSessionGeneration).kind == DKind::kNotFound);
    CHECK(session_write_generation(auth_db.pool()) == g0 + 1);

    // A refusal rolls the whole transaction back: the sole active column admin stays, no bump.
    CHECK(store.deactivate_account("t11_admin", kBumpSessionGeneration).kind ==
          DKind::kLastAdministratorRefused);
    CHECK(account_active(auth_db.pool(), "t11_admin"));
    CHECK(session_write_generation(auth_db.pool()) == g0 + 1);

    // The no-store mode touches no session_store object, so it never bumps.
    CHECK(store.deactivate_account("t11_user2", kNoSessionStore).kind == DKind::kDeactivated);
    CHECK(session_write_generation(auth_db.pool()) == g0 + 1);
}

TEST_CASE("deactivate_account: a failed generation bump aborts the deactivation and leaves the "
          "account and its MFA state untouched (T12 + T-R6)",
          "[pg][auth_db][lifecycle_guard][session_generation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, /*rbac_on=*/false,
                {{"t12_admin", Role::admin}, {"t12_user", Role::user}});
    // Give the target a TOTP enrollment and a recovery code: the soft delete clears them, so a
    // half-applied deactivation would show here.
    exec_raw(auth_db.pool(),
             "UPDATE auth.users SET mfa_totp_secret = '\\x0102'::bytea, mfa_enrolled_at = now(), "
             "mfa_last_counter = 7 WHERE username = 't12_user'");
    exec_raw(auth_db.pool(),
             "INSERT INTO auth.mfa_recovery_codes (username, code_hash, code_salt) "
             "VALUES ('t12_user', 'h', 's')");
    const std::string before = mfa_state(auth_db.pool(), "t12_user");
    REQUIRE(before == "0102|true|7|false|1");

    {
        // The session generation table moved aside: the bump (and only the bump) fails.
        yuzu::test::SqlFault meta_gone{
            auth_db.pool(), "ALTER TABLE session_store.session_meta RENAME TO session_meta_gone",
            "ALTER TABLE session_store.session_meta_gone RENAME TO session_meta"};
        meta_gone.arm();
        const auto res = store.deactivate_account("t12_user", kBumpSessionGeneration);
        CHECK(res.kind == DKind::kStoreFailure);
        CHECK_FALSE(res.err.empty());
        meta_gone.repair();
    }
    CHECK(account_active(auth_db.pool(), "t12_user"));
    CHECK(mfa_state(auth_db.pool(), "t12_user") == before);

    // Repaired: the same call now succeeds, so the failure above left nothing behind.
    CHECK(store.deactivate_account("t12_user", kBumpSessionGeneration).kind ==
          DKind::kDeactivated);
    CHECK_FALSE(account_active(auth_db.pool(), "t12_user"));
}

TEST_CASE("AuthManager lifecycle guard: the session generation moves with the deactivation even "
          "when the durable session wipe fails (T3)",
          "[pg][auth_db][lifecycle_guard][session_generation][auth]") {
    ManagerFx f;
    seed(f.db, "t3_admin", Role::admin);
    seed(f.db, "t3_user", Role::user);
    const auto token = f.mgr.create_local_session_for_test("t3_user", Role::user, false);
    REQUIRE_FALSE(token.empty());
    const auto g0 = f.sessions.read_generation();
    REQUIRE(g0.has_value());

    f.break_session_wipe();
    CHECK(f.mgr.remove_user_checked("t3_user") == RemoveUserOutcome::RemovedSessionWipeFailed);
    f.repair_session_wipe();

    // The wipe bumps nothing when it fails, so the one increment is the deactivation's own.
    const auto g1 = f.sessions.read_generation();
    REQUIRE(g1.has_value());
    CHECK(*g1 == *g0 + 1);
    CHECK_FALSE(account_active(f.db.pool(), "t3_user"));
}

TEST_CASE("AuthManager lifecycle guard: concurrent session creates and deactivations finish "
          "all complete without a lock timeout (T13, smoke only)",
          "[pg][auth_db][lifecycle_guard][session_generation][auth]") {
    // SMOKE ONLY. This shows the session_meta row edge does not stall the pair of workloads; it
    // proves nothing about publication or the lock graph, and the DDL fault trigger is
    // deliberately not used here.
    ManagerFx f;
    seed(f.db, "t13_admin", Role::admin);
    constexpr int kUsers = 6;
    for (int i = 0; i < kUsers; ++i)
        seed(f.db, "t13_u" + std::to_string(i), Role::user);

    std::atomic<int> removed{0};
    std::atomic<int> other{0};
    {
        Workers workers({});
        for (int i = 0; i < kUsers; ++i) {
            workers.add([&, i] {
                const auto outcome = f.mgr.remove_user_checked("t13_u" + std::to_string(i));
                (outcome == RemoveUserOutcome::Removed ? removed : other)++;
            });
        }
        for (int t = 0; t < 3; ++t) {
            workers.add([&, t] {
                for (int n = 0; n < 12; ++n)
                    (void)f.mgr.create_local_session_for_test(
                        "t13_u" + std::to_string((t + n) % kUsers), Role::user, false);
            });
        }
        workers.join_all();
    }

    // Every removal completing with Removed (none timed out into another outcome) IS the check;
    // a wall-clock bound here would only make the case flaky on a loaded runner.
    CHECK(removed.load() == kUsers);
    CHECK(other.load() == 0);
    for (int i = 0; i < kUsers; ++i)
        CHECK_FALSE(account_active(f.db.pool(), "t13_u" + std::to_string(i)));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Removing a user's Administrator grant ends that user's durable JIT elevation in the SAME
// transaction. The store runs in its DEFAULT durable mode here (a real SessionStore on
// the one pool); the oracle reads the session and generation rows raw. Not covered here: a
// re-elevation after the unassign (`/elevate` is unchanged and stays possible).
// ═════════════════════════════════════════════════════════════════════════════════════════════

namespace {

yuzu::server::SessionWriteParams elev_params(const std::string& hash, const std::string& user) {
    yuzu::server::SessionWriteParams p;
    p.token_hash = hash;
    p.username = user;
    p.display_name = "Test User";
    p.role = "user";
    p.auth_source = "local";
    p.principal_kind = "human";
    p.session_lifetime_ms = 8LL * 3600 * 1000;
    return p;
}

// A durable session for `user`, elevated for ten minutes.
void make_elevated(yuzu::server::SessionStore& sessions, const std::string& hash,
                   const std::string& user) {
    REQUIRE(sessions.create(elev_params(hash, user)).has_value());
    const auto set = sessions.set_elevation(hash, 600'000);
    REQUIRE(set.has_value());
    REQUIRE(set->has_value());
}

// "until|issued" for every session of `user`, in token order.
std::vector<std::string> elevation_cols(PgPool& pool, const std::string& user) {
    return query_col(pool, ("SELECT elevated_until_ms::text || '|' || elevation_issued_ms::text "
                            "FROM session_store.sessions WHERE username = '" + user +
                            "' ORDER BY token_hash")
                               .c_str());
}

long long rbac_write_generation(PgPool& pool) {
    const auto v = query_col(
        pool, "SELECT value FROM rbac_store.rbac_meta WHERE key = 'write_generation'");
    return v.empty() ? 0 : std::stoll(v.front());
}

bool has_grant(PgPool& pool, const std::string& type, const std::string& name) {
    return !query_col(pool, ("SELECT 1 FROM rbac_store.principal_roles WHERE principal_type = '" +
                             type + "' AND principal_id = '" + name +
                             "' AND role_name = 'Administrator'")
                                .c_str())
                .empty();
}

} // namespace

TEST_CASE("unassign Administrator: both of the target's elevated sessions end, one session "
          "generation bump, one RBAC bump (S10-1)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, /*rbac_on=*/true,
                {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    make_elevated(sessions, "s10-h1", "s10_tgt");
    make_elevated(sessions, "s10-h2", "s10_tgt");
    make_elevated(sessions, "s10-other", "s10_adm"); // another user's elevation must survive
    const auto other_before = elevation_cols(auth_db.pool(), "s10_adm");
    const long long sg0 = session_write_generation(auth_db.pool());
    const long long rg0 = rbac_write_generation(auth_db.pool());

    const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(res.has_value());
    CHECK(res->removed);
    CHECK(res->elevations_cleared == 2);
    CHECK_FALSE(has_grant(auth_db.pool(), "user", "s10_tgt"));
    CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == std::vector<std::string>{"0|0", "0|0"});
    CHECK(elevation_cols(auth_db.pool(), "s10_adm") == other_before);
    CHECK(session_write_generation(auth_db.pool()) == sg0 + 1);
    CHECK(rbac_write_generation(auth_db.pool()) == rg0 + 1);
}

TEST_CASE("unassign Administrator: an EXPIRED but nonzero elevation window is matched, counted "
          "and cleared (S10-2)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    REQUIRE(sessions.create(elev_params("s10-exp", "s10_tgt")).has_value());
    // A window that lapsed but was never reaped: nonzero, in the past.
    exec_raw(auth_db.pool(),
             "UPDATE session_store.sessions SET elevated_until_ms = 1000, elevation_issued_ms = 500 "
             "WHERE token_hash = 's10-exp'");
    const long long sg0 = session_write_generation(auth_db.pool());

    const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(res.has_value());
    CHECK(res->elevations_cleared == 1);
    CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == std::vector<std::string>{"0|0"});
    CHECK(session_write_generation(auth_db.pool()) == sg0 + 1);
}

TEST_CASE("unassign Administrator: a target with no elevation removes the grant and bumps only the "
          "RBAC generation (S10-3)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    REQUIRE(sessions.create(elev_params("s10-plain", "s10_tgt")).has_value()); // never elevated
    const long long sg0 = session_write_generation(auth_db.pool());
    const long long rg0 = rbac_write_generation(auth_db.pool());

    const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(res.has_value());
    CHECK(res->removed);
    CHECK(res->elevations_cleared == 0);
    CHECK(session_write_generation(auth_db.pool()) == sg0);
    CHECK(rbac_write_generation(auth_db.pool()) == rg0 + 1);
}

TEST_CASE("unassign of a non-Administrator role, a never-held grant and an engine principal touch "
          "no session row and no session generation (S10-4)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    REQUIRE(store.assign_role({"user", "s10_tgt", "Viewer"}).has_value());
    make_elevated(sessions, "s10-v1", "s10_tgt");
    make_elevated(sessions, "s10-e1", "s10_eng");
    const auto tgt_before = elevation_cols(auth_db.pool(), "s10_tgt");
    const auto eng_before = elevation_cols(auth_db.pool(), "s10_eng");
    const long long sg0 = session_write_generation(auth_db.pool());

    SECTION("Viewer unassign") {
        const auto res = store.unassign_role_detailed("user", "s10_tgt", "Viewer");
        REQUIRE(res.has_value());
        CHECK(res->removed);
        CHECK(res->elevations_cleared == 0);
        CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == tgt_before);
    }
    SECTION("a user who never held Administrator") {
        const long long rg0 = rbac_write_generation(auth_db.pool());
        const auto res = store.unassign_role_detailed("user", "s10_nobody", "Administrator");
        REQUIRE(res.has_value());
        CHECK_FALSE(res->removed);
        CHECK(res->elevations_cleared == 0);
        // The owner's RBAC bump is unconditional (existing behaviour), the session one is not.
        CHECK(rbac_write_generation(auth_db.pool()) == rg0 + 1);
    }
    SECTION("an engine principal") {
        const auto res = store.unassign_role_detailed("engine", "s10_eng", "Administrator");
        REQUIRE(res.has_value());
        CHECK(res->elevations_cleared == 0);
        CHECK(elevation_cols(auth_db.pool(), "s10_eng") == eng_before);
    }
    CHECK(session_write_generation(auth_db.pool()) == sg0);
}

TEST_CASE("unassign Administrator: the last-Administrator refusal changes nothing, in either "
          "generation (S10-5)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_sole", Role::user, true}});
    make_elevated(sessions, "s10-sole1", "s10_sole");
    const auto before = elevation_cols(auth_db.pool(), "s10_sole");
    const long long sg0 = session_write_generation(auth_db.pool());
    const long long rg0 = rbac_write_generation(auth_db.pool());

    const auto res = store.unassign_role_detailed("user", "s10_sole", "Administrator");
    REQUIRE_FALSE(res.has_value());
    CHECK(is_rbac_last_admin_refusal(res.error()));
    CHECK(has_grant(auth_db.pool(), "user", "s10_sole"));
    CHECK(elevation_cols(auth_db.pool(), "s10_sole") == before);
    CHECK(session_write_generation(auth_db.pool()) == sg0);
    CHECK(rbac_write_generation(auth_db.pool()) == rg0);
}

TEST_CASE("unassign Administrator: a failed session lock/clear or session_meta bump rolls the "
          "grant removal back (S10-6)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    make_elevated(sessions, "s10-f1", "s10_tgt");
    const auto before = elevation_cols(auth_db.pool(), "s10_tgt");
    const long long rg0 = rbac_write_generation(auth_db.pool());
    const long long sg0 = session_write_generation(auth_db.pool());
    int drop_calls = 0;
    REQUIRE(store.set_local_session_drop([&](const std::string&) { ++drop_calls; }));

    SECTION("the sessions table is unreachable: the row lock statement fails") {
        std::expected<yuzu::server::RbacStore::UnassignResult, std::string> res;
        {
            SessionWipeFault fault{auth_db.pool()};
            fault.arm();
            res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
            fault.repair();
        }
        REQUIRE_FALSE(res.has_value());
        CHECK_FALSE(res.error().empty());
        CHECK(res.error().find("session row lock failed") != std::string::npos);
    }
    SECTION("only session_meta is unreachable: the LAST statement fails, everything before it "
            "rolls back") {
        std::expected<yuzu::server::RbacStore::UnassignResult, std::string> res;
        {
            yuzu::test::SqlFault meta_gone{
                auth_db.pool(),
                "ALTER TABLE session_store.session_meta RENAME TO session_meta_gone",
                "ALTER TABLE session_store.session_meta_gone RENAME TO session_meta"};
            meta_gone.arm();
            res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
            meta_gone.repair();
        }
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error().find("session write-generation bump failed") != std::string::npos);
    }
    SECTION("only the elevation clear statement fails: the row lock before it passed") {
        std::expected<yuzu::server::RbacStore::UnassignResult, std::string> res;
        {
            yuzu::test::SqlFault clear_gone{
                auth_db.pool(),
                "ALTER TABLE session_store.sessions RENAME COLUMN elevation_issued_ms TO "
                "elevation_issued_ms_gone",
                "ALTER TABLE session_store.sessions RENAME COLUMN elevation_issued_ms_gone TO "
                "elevation_issued_ms"};
            clear_gone.arm();
            res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
            clear_gone.repair();
        }
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error().find("session elevation clear failed") != std::string::npos);
    }
    // Repaired: the grant is still there, the elevation is intact, and the RBAC generation did
    // not move (the whole transaction rolled back). A statement failure never runs the callback.
    CHECK(drop_calls == 0);
    CHECK(has_grant(auth_db.pool(), "user", "s10_tgt"));
    CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == before);
    CHECK(rbac_write_generation(auth_db.pool()) == rg0);
    CHECK(session_write_generation(auth_db.pool()) == sg0);
    // And the same call now succeeds: the failure left nothing behind.
    const auto again = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(again.has_value());
    CHECK(again->elevations_cleared == 1);
}

TEST_CASE("unassign Administrator: the local-drop callback runs once after a committed user "
          "Administrator removal and never on a refusal, a Viewer or an engine (S10-7)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    REQUIRE(store.assign_role({"user", "s10_tgt", "Viewer"}).has_value());
    std::vector<std::string> dropped;
    REQUIRE(store.set_local_session_drop([&](const std::string& u) { dropped.push_back(u); }));
    // A second non-empty set is refused: the first one stays.
    CHECK_FALSE(store.set_local_session_drop([](const std::string&) {}));

    // Not invoked: a Viewer unassign, an engine unassign, a never-held grant.
    REQUIRE(store.unassign_role_detailed("user", "s10_tgt", "Viewer").has_value());
    REQUIRE(store.unassign_role_detailed("engine", "s10_eng", "Administrator").has_value());
    REQUIRE(store.unassign_role_detailed("user", "s10_nobody", "Administrator").has_value());
    CHECK(dropped.empty());
    // Not invoked: the last-Administrator refusal (drop s10_tgt first so s10_adm is the last).
    REQUIRE(store.unassign_role_detailed("user", "s10_tgt", "Administrator").has_value());
    REQUIRE(dropped == std::vector<std::string>{"s10_tgt"});
    dropped.clear();
    REQUIRE_FALSE(store.unassign_role_detailed("user", "s10_adm", "Administrator").has_value());
    CHECK(dropped.empty());
}

TEST_CASE("unassign Administrator: a throwing local-drop callback is counted and the committed "
          "removal still reports success (S10-8)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    make_elevated(sessions, "s10-t1", "s10_tgt");
    REQUIRE(store.set_local_session_drop(
        [](const std::string&) { throw std::runtime_error("drop failed"); }));
    CHECK(store.local_session_drop_failures() == 0);

    const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(res.has_value());
    CHECK(res->removed);
    CHECK(res->elevations_cleared == 1);
    CHECK_FALSE(has_grant(auth_db.pool(), "user", "s10_tgt"));
    CHECK(store.local_session_drop_failures() == 1);
}

TEST_CASE("unassign Administrator: a statement failure rolls back and does NOT run the "
          "local-drop callback (the indeterminate-commit arm is not simulated here) (S10-9)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    make_elevated(sessions, "s10-r1", "s10_tgt");
    int calls = 0;
    REQUIRE(store.set_local_session_drop([&](const std::string&) { ++calls; }));
    {
        SessionWipeFault fault{auth_db.pool()};
        fault.arm();
        REQUIRE_FALSE(store.unassign_role_detailed("user", "s10_tgt", "Administrator").has_value());
        fault.repair();
    }
    CHECK(calls == 0);
    CHECK(has_grant(auth_db.pool(), "user", "s10_tgt"));
}

TEST_CASE("unassign Administrator: the test opt-out issues no session_store SQL and still runs "
          "the local-drop callback (S10-10)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    // NO SessionStore is constructed: the opt-out store never names a session_store object,
    // so the unassign succeeds on a database that has no such schema.
    LIFECYCLE_FIXTURE(store, auth_db);
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    CHECK(query_col(auth_db.pool(), "SELECT 1 FROM information_schema.schemata WHERE "
                                    "schema_name = 'session_store'")
              .empty());
    store.use_no_session_store_for_test();
    std::vector<std::string> dropped;
    REQUIRE(store.set_local_session_drop([&](const std::string& u) { dropped.push_back(u); }));

    const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(res.has_value());
    CHECK(res->removed);
    CHECK(res->elevations_cleared == 0);
    CHECK(dropped == std::vector<std::string>{"s10_tgt"});
}

TEST_CASE("unassign Administrator: the clear needs removed==true, the Administrator role and a user "
          "principal; a no-op unassign ends NO elevation (ruled behaviour) (S10-11)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    // s10_tgt holds NO Administrator grant here; s10_adm is the one counted Administrator.
    build_world(auth_db, store, true,
                {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, false}});
    make_elevated(sessions, "s10-c1", "s10_tgt");
    const auto before = elevation_cols(auth_db.pool(), "s10_tgt");
    const long long sg0 = session_write_generation(auth_db.pool());
    int drop_calls = 0;
    REQUIRE(store.set_local_session_drop([&](const std::string&) { ++drop_calls; }));

    SECTION("a user who never held the grant but has an elevated session: removed=false, nothing "
            "is cleared (a later docs change states this)") {
        const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
        REQUIRE(res.has_value());
        CHECK_FALSE(res->removed);
        CHECK(res->elevations_cleared == 0);
    }
    SECTION("a GROUP principal of the same name holding Administrator: only the group row goes") {
        REQUIRE(store.assign_role({"group", "s10_tgt", "Administrator"}).has_value());
        const auto res = store.unassign_role_detailed("group", "s10_tgt", "Administrator");
        REQUIRE(res.has_value());
        CHECK(res->removed);
        CHECK(res->elevations_cleared == 0);
        CHECK_FALSE(has_grant(auth_db.pool(), "group", "s10_tgt"));
    }
    SECTION("an ENGINE principal of the same name holding Administrator (raw row: assign_role "
            "refuses a built-in role for an engine): only the engine row goes") {
        exec_raw(auth_db.pool(),
                 "INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
                 "VALUES ('engine', 's10_tgt', 'Administrator')");
        REQUIRE(has_grant(auth_db.pool(), "engine", "s10_tgt"));
        const auto res = store.unassign_role_detailed("engine", "s10_tgt", "Administrator");
        REQUIRE(res.has_value());
        CHECK(res->removed);
        CHECK(res->elevations_cleared == 0);
        CHECK_FALSE(has_grant(auth_db.pool(), "engine", "s10_tgt"));
    }
    // In every section the same-named USER's elevation is untouched, no session generation moved
    // and the local drop (a user Administrator removal only) never ran.
    CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == before);
    CHECK(session_write_generation(auth_db.pool()) == sg0);
    CHECK(drop_calls == 0);
}

TEST_CASE("unassign Administrator: a COMMIT that fails (empty err) still runs the local-drop "
          "callback and reports an error; a non-Administrator unassign does not (S10-12)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    REQUIRE(store.assign_role({"user", "s10_tgt", "Viewer"}).has_value());
    std::vector<std::string> dropped;
    REQUIRE(store.set_local_session_drop([&](const std::string& u) { dropped.push_back(u); }));

    // A deferred constraint trigger raises when the transaction COMMITs after it deleted a
    // principal_roles row, so every statement succeeds and only the COMMIT fails: the owner
    // reports ok=false with an EMPTY err, the same shape as a lost COMMIT acknowledgement.
    // (Here the failed COMMIT rolls back, so the grant stays; a real lost acknowledgement may
    // have committed, which is exactly why the store fails toward re-authentication.)
    yuzu::test::SqlFault commit_fault{
        auth_db.pool(),
        "DO $do$ BEGIN "
        "EXECUTE $f$CREATE OR REPLACE FUNCTION public.yuzu_test_commit_fault() "
        "RETURNS trigger LANGUAGE plpgsql AS $b$ BEGIN "
        "RAISE EXCEPTION 'yuzu_test commit fault'; END $b$$f$; "
        "EXECUTE $f$CREATE CONSTRAINT TRIGGER yuzu_test_commit_fault AFTER DELETE ON "
        "rbac_store.principal_roles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        "EXECUTE FUNCTION public.yuzu_test_commit_fault()$f$; END $do$",
        "DO $do$ BEGIN "
        "DROP TRIGGER IF EXISTS yuzu_test_commit_fault ON rbac_store.principal_roles; "
        "DROP FUNCTION IF EXISTS public.yuzu_test_commit_fault(); END $do$"};
    commit_fault.arm();

    SECTION("a user Administrator removal: the callback runs once, the result is an error") {
        const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error() == "unassign_role failed");
        CHECK(dropped == std::vector<std::string>{"s10_tgt"});
    }
    SECTION("a Viewer removal: the same failed COMMIT does not run the callback") {
        const auto res = store.unassign_role_detailed("user", "s10_tgt", "Viewer");
        REQUIRE_FALSE(res.has_value());
        CHECK(dropped.empty());
    }
    commit_fault.repair();
    // The failed COMMIT rolled back: the Administrator grant is still there.
    CHECK(has_grant(auth_db.pool(), "user", "s10_tgt"));
}

TEST_CASE("unassign Administrator: a blocked session-row lock fails within the lifecycle lock bound, "
          "rolls the removal back, and a retry succeeds once the lock is gone (S10-13)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    yuzu::MetricsRegistry metrics;
    LIFECYCLE_FIXTURE(seeding_store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, seeding_store, true,
                {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    make_elevated(sessions, "s10-l1", "s10_tgt");
    const auto before = elevation_cols(auth_db.pool(), "s10_tgt");
    const long long rg0 = rbac_write_generation(auth_db.pool());
    const long long sg0 = session_write_generation(auth_db.pool());

    // A SHORT bound: the 2000 ms production value is pinned by the lock-timeout case above for
    // deactivation; this case needs the bound installed on the unassign transaction and a failure
    // far inside the pool's own 10 s lock_timeout.
    RbacStore store{auth_db.pool(), std::chrono::milliseconds(200)};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    int drop_calls = 0;
    REQUIRE(store.set_local_session_drop([&](const std::string&) { ++drop_calls; }));
    const auto unassign_faults = [&] {
        return metrics
            .counter("yuzu_server_rbac_lifecycle_store_failure_total", {{"op", "unassign"}})
            .value();
    };

    yuzu::test::HeldLocks hold(auth_db.pool());
    hold.run("SELECT token_hash FROM session_store.sessions WHERE username = 's10_tgt' "
             "ORDER BY token_hash FOR UPDATE");

    const auto t0 = std::chrono::steady_clock::now();
    const auto res = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);

    REQUIRE_FALSE(res.has_value());
    CHECK(res.error().find("session row lock failed") != std::string::npos);
    CHECK(res.error().find("lock timeout") != std::string::npos);
    // Bounded by the 200 ms transaction-local value (the pool's own 10 s would fail the upper bound).
    CHECK(elapsed >= std::chrono::milliseconds(150));
    CHECK(elapsed < std::chrono::milliseconds(5000));
    CHECK(has_grant(auth_db.pool(), "user", "s10_tgt"));
    CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == before);
    CHECK(rbac_write_generation(auth_db.pool()) == rg0);
    CHECK(session_write_generation(auth_db.pool()) == sg0);
    CHECK(drop_calls == 0);
    CHECK(unassign_faults() == 1.0);

    hold.rollback();
    const auto again = store.unassign_role_detailed("user", "s10_tgt", "Administrator");
    REQUIRE(again.has_value());
    CHECK(again->removed);
    CHECK(again->elevations_cleared == 1);
    CHECK(drop_calls == 1);
    CHECK(unassign_faults() == 1.0);
}

TEST_CASE("unassign: only a store fault counts yuzu_server_rbac_lifecycle_store_failure_total"
          "{op=unassign}; a refusal, a refused value and a success do not (S10-14)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    yuzu::MetricsRegistry metrics;
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    store.set_metrics(&metrics);
    make_elevated(sessions, "s10-m1", "s10_tgt");
    const auto unassign_faults = [&] {
        return metrics
            .counter("yuzu_server_rbac_lifecycle_store_failure_total", {{"op", "unassign"}})
            .value();
    };
    CHECK(unassign_faults() == 0.0);

    SECTION("a refused value (not clean text) is a caller mistake, not a store fault") {
        const auto res = store.unassign_role_detailed("user", "s10_tgt", "Admin\nrole=Viewer");
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error() == "invalid role name");
        CHECK(unassign_faults() == 0.0);
    }
    SECTION("a statement failure that rolled back counts once") {
        {
            SessionWipeFault fault{auth_db.pool()};
            fault.arm();
            REQUIRE_FALSE(store.unassign_role_detailed("user", "s10_tgt", "Administrator").has_value());
            fault.repair();
        }
        CHECK(unassign_faults() == 1.0);
        // The repaired retry succeeds and adds nothing; the now-sole Administrator is refused
        // (a business-rule refusal) and adds nothing either.
        REQUIRE(store.unassign_role_detailed("user", "s10_tgt", "Administrator").has_value());
        const auto refused = store.unassign_role_detailed("user", "s10_adm", "Administrator");
        REQUIRE_FALSE(refused.has_value());
        CHECK(is_rbac_last_admin_refusal(refused.error()));
        CHECK(unassign_faults() == 1.0);
    }
}

TEST_CASE("unassign Administrator: an elevation write in flight on the target's session row is "
          "waited for, and the clear then ends it (S10-15)",
          "[pg][auth_db][lifecycle_guard][session_generation][unassign_elevation]") {
    // `lock_user_session_rows_in_txn` exists so a writer that holds (or is about to take) a
    // session row cannot slip an elevation past the clear that follows. A held transaction that
    // has UPDATEd the row to an elevated state but not committed stands in for that writer (a
    // real `set_elevation` is one autocommit statement: there is no window to park in). The
    // unassign must block on the row lock, and once the writer commits its clear must see the
    // committed elevation and zero it. The other ordering (the unassign takes the row lock first
    // and the writer waits) cannot be forced from outside the transaction; the lock-before-clear
    // order is pinned by the source-text tripwire in tests/test_session_account_gate_wiring.py.
    // The row starts unelevated, so without the lock statement the clear's own UPDATE (which
    // skips a zero row) would not wait: the case goes red there, at the blocked-backend wait.
    // Timing: this store keeps the default 2000 ms lifecycle lock timeout, so the unassign's
    // row-lock wait can time out (and `res` then holds the failure) if more than 2000 ms passes
    // between the unassign blocking (which the blocked-backend poll waits for) and the commit
    // below; normally that is milliseconds, but a heavily stalled runner (a sanitizer build,
    // for example) could flake it.
    LIFECYCLE_FIXTURE(store, auth_db);
    yuzu::server::SessionStore sessions{auth_db.pool()};
    REQUIRE(sessions.is_open());
    build_world(auth_db, store, true, {{"s10_adm", Role::user, true}, {"s10_tgt", Role::user, true}});
    REQUIRE(sessions.create(elev_params("s10-w1", "s10_tgt")).has_value()); // not elevated
    REQUIRE(elevation_cols(auth_db.pool(), "s10_tgt") == std::vector<std::string>{"0|0"});

    HeldLocks hold(auth_db.pool());
    hold.run("UPDATE session_store.sessions SET "
             "elevated_until_ms = (extract(epoch from now()) * 1000)::bigint + 600000, "
             "elevation_issued_ms = (extract(epoch from now()) * 1000)::bigint "
             "WHERE username = 's10_tgt'");

    std::expected<RbacStore::UnassignResult, std::string> res = std::unexpected("not run");
    Workers workers([&] { hold.rollback(); });
    workers.add([&] { res = store.unassign_role_detailed("user", "s10_tgt", "Administrator"); });
    // Parked on the writer's row lock: the unassign has neither committed nor failed.
    REQUIRE(wait_for_blocked_backends(auth_db.dsn(), hold.pid(), 1).size() >= 1);
    CHECK(has_grant(auth_db.pool(), "user", "s10_tgt"));

    hold.commit(); // the writer's elevation lands first
    workers.join_all();

    REQUIRE(res.has_value());
    CHECK(res->removed);
    CHECK(res->elevations_cleared == 1);
    CHECK_FALSE(has_grant(auth_db.pool(), "user", "s10_tgt"));
    CHECK(elevation_cols(auth_db.pool(), "s10_tgt") == std::vector<std::string>{"0|0"});
}
