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
#include <thread>
#include <utility>
#include <vector>

namespace yuzu::test {

/// ONE bound for every "wait until a backend is lock-blocked" poll in the #4966 tests (this
/// header and `test_rbac_account_lifecycle_guard.cpp`), so the two cannot drift apart. The poll is
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
/// instead of hanging the test.
inline bool wait_for_lock_waiter(yuzu::server::pg::PgPool& pool,
                                 std::chrono::milliseconds deadline = kLockWaitDeadline) {
    const auto end = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < end) {
        if (auto probe = pool.try_acquire_for(std::chrono::milliseconds(100))) {
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
                probe.get(),
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND wait_event_type = 'Lock' AND wait_event IN ('advisory', 'transactionid')",
                std::vector<std::string>{});
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
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease_.get(), "SELECT pg_advisory_unlock(hashtext($1))",
            std::vector<std::string>{principal_});
        // A destructor cannot REQUIRE. A failed unlock would leave the lock on a pooled
        // connection and strand a later test's request, so say so loudly instead of ignoring it.
        if (r.status() != PGRES_TUPLES_OK)
            std::fprintf(stderr, "PrincipalLockGate: pg_advisory_unlock('%s') failed\n",
                         principal_.c_str());
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
        open_ = true; // from here a failing REQUIRE still rolls back in the destructor
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
        yuzu::server::pg::PgResult r =
            yuzu::server::pg::exec_params(lease_.get(), sql, std::vector<std::string>{});
        if (r.status() != PGRES_COMMAND_OK)
            std::fprintf(stderr, "UncommittedScimRowGate: %s failed\n", sql);
    }

    yuzu::server::pg::PgPool& pool_;
    yuzu::server::pg::PgPool::Lease lease_;
    bool open_{false};
};

/// A REAL, RAII-scoped fault in the throwaway database: the durable `session_store.sessions`
/// table is renamed aside, so `AuthManager::wipe_user_sessions_durable`'s DELETE genuinely fails
/// while every other store keeps working. `repair()` is idempotent and noexcept and the
/// destructor calls it, so a failing REQUIRE between `arm()` and the explicit repair can never
/// leave the table renamed for a later test sharing the database.
class SessionWipeFault {
public:
    explicit SessionWipeFault(yuzu::server::pg::PgPool& pool) : pool_(pool) {}
    SessionWipeFault(const SessionWipeFault&) = delete;
    SessionWipeFault& operator=(const SessionWipeFault&) = delete;
    ~SessionWipeFault() noexcept { repair(); }

    void arm() {
        if (armed_)
            return;
        auto lease = pool_.acquire();
        REQUIRE(lease);
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease.get(), "ALTER TABLE session_store.sessions RENAME TO sessions_gone",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
        armed_ = true;
    }

    void repair() noexcept {
        if (!armed_)
            return;
        armed_ = false;
        try {
            auto lease = pool_.acquire();
            if (!lease)
                return;
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
                lease.get(), "ALTER TABLE session_store.sessions_gone RENAME TO sessions",
                std::vector<std::string>{});
            if (r.status() != PGRES_COMMAND_OK)
                std::fprintf(stderr, "SessionWipeFault: repair failed\n");
        } catch (...) {
            std::fprintf(stderr, "SessionWipeFault: repair threw\n");
        }
    }

private:
    yuzu::server::pg::PgPool& pool_;
    bool armed_{false};
};

} // namespace yuzu::test
