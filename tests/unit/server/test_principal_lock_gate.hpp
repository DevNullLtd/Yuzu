#pragma once

// test_principal_lock_gate.hpp - a deterministic seam between a route's credential revoke and the
// guarded account write that follows it (#4966).
//
// The ADR-2001 deprovision order is credentials-first: `ApiTokenStore::revoke_for_principal` runs
// BEFORE `AuthManager::remove_user_checked`. The best-effort early refusal (`would_strand`) runs
// before the revoke, so the LATE refusal (the guard saying no after credentials were already
// revoked) needs state to change in the window between them. `revoke_for_principal` takes
// `pg_advisory_xact_lock(hashtext(principal_id))`, so a test that holds the same session-level
// advisory lock parks the request exactly there, mutates the world, and releases. No production
// seam, hook or test-only member is involved.
//
// Usage:
//   PrincipalLockGate gate(pool, "alice");          // takes the lock
//   Workers workers([&] { gate.release(); });       // declared AFTER the gate (see Workers)
//   workers.add([&] { res = h.delete_user("alice"); });
//   REQUIRE(gate.wait_until_contended());           // the request is parked in the revoke
//   ...change state with the normal guarded API...
//   gate.release();                                 // the request resumes
//   workers.join_all();

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace yuzu::test {

/// The deadline and poll interval shared by the "wait until a backend is lock-blocked" polls in
/// the #4966 tests (this header and `test_rbac_account_lifecycle_guard.cpp`). Only these values
/// are shared: the two pollers read `pg_stat_activity` through different queries. The poll is
/// event-style (there is no event to wait on in a different backend); the deadline only bounds a
/// failing test.
inline constexpr std::chrono::milliseconds kLockWaitDeadline{10000};
inline constexpr std::chrono::milliseconds kLockWaitPoll{5};

/// Runs `before_join` (release the held locks / roll back the held transaction) and then joins
/// every worker thread when it goes out of scope, so a failing REQUIRE can neither leave a
/// joinable std::thread behind (std::terminate) nor wait out a full lock_timeout.
///
/// DECLARE IT AFTER the gate / held-locks object it releases: members are destroyed in reverse
/// order, so the Workers (declared later) is destroyed first, runs the release callback while the
/// gate still exists, and only then joins. This is why it is NOT a std::jthread: a jthread
/// declared after the gate joins immediately on destruction, with nothing having released the
/// lock its parked request is waiting on, so a failing REQUIRE would block until the request's
/// own timeout instead of unwinding.
class Workers {
public:
    explicit Workers(std::function<void()> before_join) : before_join_(std::move(before_join)) {}
    ~Workers() {
        if (before_join_)
            before_join_();
        join_all();
    }
    Workers(const Workers&) = delete;
    Workers& operator=(const Workers&) = delete;
    void add(std::function<void()> fn) { threads_.emplace_back(std::move(fn)); }
    /// Joins only; a test releases its held locks first when it wants the workers to proceed.
    void join_all() {
        for (auto& t : threads_)
            if (t.joinable())
                t.join();
    }

private:
    std::function<void()> before_join_;
    std::vector<std::thread> threads_;
};

/// True once some backend of THIS database is blocked waiting on an advisory lock or on another
/// transaction's row/index lock (`wait_event` `advisory` / `transactionid`: the two waits the
/// gates below create). Polls pg_stat_activity until `kLockWaitDeadline`. The probe lease is taken
/// with a bounded wait, never the deadline-less `acquire()`, so a drained pool fails the wait
/// instead of hanging the test. `events` is the quoted SQL list of `wait_event` values to count
/// (a caller waiting on a table lock passes "'relation'").
inline bool wait_for_lock_waiter(yuzu::server::pg::PgPool& pool,
                                 std::chrono::milliseconds deadline = kLockWaitDeadline,
                                 std::string_view events = "'advisory', 'transactionid'") {
    const auto end = std::chrono::steady_clock::now() + deadline;
    const std::string sql =
        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
        "AND wait_event_type = 'Lock' AND wait_event IN (" +
        std::string(events) + ")";
    while (std::chrono::steady_clock::now() < end) {
        if (auto probe = pool.try_acquire_for(std::chrono::milliseconds(100))) {
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
                probe.get(), sql.c_str(), std::vector<std::string>{});
            if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
                std::atoi(PQgetvalue(r.get(), 0, 0)) > 0)
                return true;
        }
        std::this_thread::sleep_for(kLockWaitPoll);
    }
    return false;
}

class PrincipalLockGate {
public:
    PrincipalLockGate(yuzu::server::pg::PgPool& pool, std::string principal)
        : pool_(pool), principal_(std::move(principal)), lease_(pool.acquire()) {
        REQUIRE(lease_);
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease_.get(), "SELECT pg_advisory_lock(hashtext($1))",
            std::vector<std::string>{principal_});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        held_ = true;
    }

    PrincipalLockGate(const PrincipalLockGate&) = delete;
    PrincipalLockGate& operator=(const PrincipalLockGate&) = delete;

    // A session-level advisory lock outlives the lease (the connection returns to the pool still
    // holding it), so the destructor must unlock explicitly.
    ~PrincipalLockGate() { release(); }

    /// True once the request under test is parked in the revoke.
    [[nodiscard]] bool wait_until_contended() { return wait_for_lock_waiter(pool_); }

    void release() {
        if (!held_)
            return;
        held_ = false;
        // The argument vector allocates, which can throw; this runs from the destructor and from
        // the pre-join callback of `Workers`, both implicitly noexcept, so a throw would
        // terminate. A destructor cannot REQUIRE either. A failed unlock would leave the lock on a
        // pooled connection and strand a later test's request, so say so loudly instead of
        // ignoring it.
        try {
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
                lease_.get(), "SELECT pg_advisory_unlock(hashtext($1))",
                std::vector<std::string>{principal_});
            if (r.status() != PGRES_TUPLES_OK)
                std::fprintf(stderr, "PrincipalLockGate: pg_advisory_unlock('%s') failed\n",
                             principal_.c_str());
        } catch (...) {
            std::fprintf(stderr, "PrincipalLockGate: pg_advisory_unlock('%s') threw\n",
                         principal_.c_str());
        }
    }

private:
    yuzu::server::pg::PgPool& pool_;
    std::string principal_;
    yuzu::server::pg::PgPool::Lease lease_;
    bool held_{false};
};

/// An OPEN transaction holding one uncommitted `scim_store.scim_resources` row. A concurrent
/// `ScimStore::create_resource` that collides on its `external_id` (the partial unique index)
/// blocks until this resolves, and then fails with a unique violation once it commits. That parks
/// a SCIM POST between its account creation and its mapping write, which is where the genuine
/// compensation (the guarded undo) lives.
class UncommittedScimRowGate {
public:
    UncommittedScimRowGate(yuzu::server::pg::PgPool& pool, const std::string& external_id)
        : pool_(pool), lease_(pool.acquire()) {
        REQUIRE(lease_);
        yuzu::server::pg::PgResult begin = yuzu::server::pg::exec_params(
            lease_.get(), "BEGIN", std::vector<std::string>{});
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        // From here a failing REQUIRE still rolls back: the destructor of an object whose
        // constructor threw does not run, but `lease_` (a fully constructed member) is destroyed
        // and the pool's release path rolls an open transaction back before the connection is
        // reused.
        open_ = true;
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease_.get(),
            "INSERT INTO scim_store.scim_resources (scim_id, external_id, username) "
            "VALUES ('gate-resource-id', $1, 'gate-other-user')",
            std::vector<std::string>{external_id});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    UncommittedScimRowGate(const UncommittedScimRowGate&) = delete;
    UncommittedScimRowGate& operator=(const UncommittedScimRowGate&) = delete;
    ~UncommittedScimRowGate() { finish("ROLLBACK"); }

    [[nodiscard]] bool wait_until_contended() { return wait_for_lock_waiter(pool_); }
    void commit() { finish("COMMIT"); }
    /// Ends the transaction WITHOUT the row: the parked request's insert then succeeds. Used as
    /// the pre-join callback of a `Workers` declared after this gate (see `Workers`).
    void rollback() { finish("ROLLBACK"); }

private:
    void finish(const char* sql) {
        if (!open_)
            return;
        open_ = false;
        // Same shape as `PrincipalLockGate::release`: the argument vector allocates and this runs
        // from the implicitly noexcept destructor and from the `Workers` pre-join callback, so a
        // throw would terminate.
        try {
            yuzu::server::pg::PgResult r =
                yuzu::server::pg::exec_params(lease_.get(), sql, std::vector<std::string>{});
            if (r.status() != PGRES_COMMAND_OK)
                std::fprintf(stderr, "UncommittedScimRowGate: %s failed\n", sql);
        } catch (...) {
            std::fprintf(stderr, "UncommittedScimRowGate: %s threw\n", sql);
        }
    }

    yuzu::server::pg::PgPool& pool_;
    yuzu::server::pg::PgPool::Lease lease_;
    bool open_{false};
};

/// A REAL, RAII-scoped fault in the throwaway database: `apply_sql` breaks something (renames a
/// table or column aside) and `undo_sql` puts it back. `repair()` is idempotent and noexcept and
/// the destructor calls it, so a failing REQUIRE between `arm()` and the explicit repair can
/// never leave the schema broken for a later test sharing the database. Declare it AFTER the
/// pool owner (it borrows the pool) and BEFORE nothing that outlives the pool.
class SqlFault {
public:
    /// How long `repair()` waits for a connection before it gives up and says so on stderr.
    static constexpr std::chrono::milliseconds kRepairAcquireTimeout{4000};

    SqlFault(yuzu::server::pg::PgPool& pool, std::string apply_sql, std::string undo_sql)
        : pool_(pool), apply_(std::move(apply_sql)), undo_(std::move(undo_sql)) {}
    SqlFault(const SqlFault&) = delete;
    SqlFault& operator=(const SqlFault&) = delete;
    ~SqlFault() noexcept { repair(); }

    void arm() {
        if (armed_)
            return;
        auto lease = pool_.acquire();
        REQUIRE(lease);
        yuzu::server::pg::PgResult r =
            yuzu::server::pg::exec_params(lease.get(), apply_.c_str(), std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
        armed_ = true;
    }

    void repair() noexcept {
        if (!armed_)
            return;
        // `armed_` is cleared only once the undo SUCCEEDED, so a failed explicit repair() is
        // retried by the destructor instead of being forgotten.
        try {
            // A bounded wait, never the deadline-less acquire(): a drained pool must not hang a
            // destructor. A null lease means the schema is STILL BROKEN for the next test sharing
            // the database, so it is reported rather than swallowed.
            auto lease = pool_.try_acquire_for(kRepairAcquireTimeout);
            if (!lease) {
                std::fprintf(stderr, "SqlFault: repair could not acquire a connection: %s\n",
                             undo_.c_str());
                return;
            }
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
                lease.get(), undo_.c_str(), std::vector<std::string>{});
            if (r.status() != PGRES_COMMAND_OK)
                std::fprintf(stderr, "SqlFault: repair failed: %s\n", undo_.c_str());
            else
                armed_ = false;
        } catch (...) {
            std::fprintf(stderr, "SqlFault: repair threw: %s\n", undo_.c_str());
        }
    }

private:
    yuzu::server::pg::PgPool& pool_;
    std::string apply_;
    std::string undo_;
    bool armed_{false};
};

/// The durable `session_store.sessions` table moved aside: `AuthManager::wipe_user_sessions_durable`'s
/// DELETE genuinely fails while every other store keeps working (needs a SessionStore wired).
class SessionWipeFault : public SqlFault {
public:
    explicit SessionWipeFault(yuzu::server::pg::PgPool& pool)
        : SqlFault(pool, "ALTER TABLE session_store.sessions RENAME TO sessions_gone",
                   "ALTER TABLE session_store.sessions_gone RENAME TO sessions") {}
};

/// `rbac_store.principal_roles` moved aside: every RbacStore grant read fails (the SCIM
/// pre-provisioning Administrator-grant read answers "could not confirm").
class GrantReadFault : public SqlFault {
public:
    explicit GrantReadFault(yuzu::server::pg::PgPool& pool)
        : SqlFault(pool, "ALTER TABLE rbac_store.principal_roles RENAME TO principal_roles_gone",
                   "ALTER TABLE rbac_store.principal_roles_gone RENAME TO principal_roles") {}
};

/// The `auth.users.role` column moved aside: a read of a user's role fails while the other
/// columns (provisioning_source, is_active) still answer.
class RoleColumnFault : public SqlFault {
public:
    explicit RoleColumnFault(yuzu::server::pg::PgPool& pool)
        : SqlFault(pool, "ALTER TABLE auth.users RENAME COLUMN role TO role_gone",
                   "ALTER TABLE auth.users RENAME COLUMN role_gone TO role") {}
};

/// A raw connection holding row locks inside an open transaction. Rolls back on destruction so a
/// failing REQUIRE never leaves a worker blocked for a full lock_timeout. Declare it BEFORE the
/// `Workers` that run requests against it (so the Workers are destroyed first and release it).
class HeldLocks {
public:
    explicit HeldLocks(yuzu::server::pg::PgPool& pool) : lease_(pool.acquire()) {
        REQUIRE(lease_);
        pid_ = PQbackendPID(lease_.get());
        REQUIRE(pid_ > 0);
        run("BEGIN");
    }
    ~HeldLocks() { rollback(); }
    HeldLocks(const HeldLocks&) = delete;
    HeldLocks& operator=(const HeldLocks&) = delete;

    [[nodiscard]] int pid() const noexcept { return pid_; }

    /// The `rbac_enabled` row every guarded lifecycle write locks FOR UPDATE first.
    void lock_rbac_enabled() {
        run("SELECT value FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled' FOR UPDATE");
    }
    /// The production lock statement, ORDER BY included.
    void lock_counted_grants() {
        run("SELECT pr.principal_id FROM rbac_store.principal_roles pr "
            "JOIN auth.users u ON u.username = pr.principal_id "
            "WHERE pr.role_name = 'Administrator' AND pr.principal_type = 'user' AND u.is_active "
            "ORDER BY pr.principal_id FOR UPDATE OF pr");
    }
    void run(const std::string& sql) {
        yuzu::server::pg::PgResult r =
            yuzu::server::pg::exec_params(lease_.get(), sql.c_str(), std::vector<std::string>{});
        REQUIRE(r.ok());
    }
    void commit() {
        run("COMMIT");
        lease_.reset();
    }
    void rollback() noexcept {
        if (lease_) {
            try {
                // The argument vector allocates, which can throw; this runs from destructors.
                (void)yuzu::server::pg::exec_params(lease_.get(), "ROLLBACK",
                                                    std::vector<std::string>{});
            } catch (...) {
                std::fprintf(stderr, "HeldLocks: ROLLBACK threw; releasing the lease anyway\n");
            }
            lease_.reset();
        }
    }

private:
    yuzu::server::pg::PgPool::Lease lease_;
    int pid_{0};
};

} // namespace yuzu::test
