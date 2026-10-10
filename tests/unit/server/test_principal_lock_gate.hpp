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
//   std::thread req([&] { res = h.delete_user("alice"); });
//   REQUIRE(gate.wait_until_contended());           // the request is parked in the revoke
//   ...change state with the normal guarded API...
//   gate.release();                                 // the request resumes
//   req.join();

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::test {

/// True once some backend of THIS database is blocked waiting on a heavyweight lock (advisory,
/// transactionid, tuple...). Polls pg_stat_activity with a short bounded back-off; there is no
/// event to wait on in a different backend.
inline bool wait_for_lock_waiter(yuzu::server::pg::PgPool& pool,
                                 std::chrono::milliseconds deadline =
                                     std::chrono::milliseconds(5000)) {
    const auto end = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < end) {
        if (auto probe = pool.acquire()) {
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
                probe.get(),
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND wait_event_type = 'Lock'",
                std::vector<std::string>{});
            if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
                std::atoi(PQgetvalue(r.get(), 0, 0)) > 0)
                return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
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
        (void)r;
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
        exec("BEGIN");
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease_.get(),
            "INSERT INTO scim_store.scim_resources (scim_id, external_id, username) "
            "VALUES ('gate-resource-id', $1, 'gate-other-user')",
            std::vector<std::string>{external_id});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
        open_ = true;
    }

    UncommittedScimRowGate(const UncommittedScimRowGate&) = delete;
    UncommittedScimRowGate& operator=(const UncommittedScimRowGate&) = delete;
    ~UncommittedScimRowGate() { finish("ROLLBACK"); }

    [[nodiscard]] bool wait_until_contended() { return wait_for_lock_waiter(pool_); }
    void commit() { finish("COMMIT"); }

private:
    void exec(const char* sql) {
        yuzu::server::pg::PgResult r =
            yuzu::server::pg::exec_params(lease_.get(), sql, std::vector<std::string>{});
        (void)r;
    }
    void finish(const char* sql) {
        if (!open_)
            return;
        open_ = false;
        exec(sql);
    }

    yuzu::server::pg::PgPool& pool_;
    yuzu::server::pg::PgPool::Lease lease_;
    bool open_{false};
};

} // namespace yuzu::test
