#pragma once

// test_events_table_lock.hpp - holds ACCESS EXCLUSIVE on the Guardian events table from a
// SEPARATE connection, so any read of that table blocks until its statement timeout fires
// (SQLSTATE 57014, #7217). It is the real backlog-shaped failure, not an injected one: the
// per-device unrepresented-pending read is the only read of the per-device Guardian routes that
// touches `guaranteed_state_store.guaranteed_state_events`.
//
// The lock is taken synchronously in the constructor (BEGIN, then LOCK TABLE, each REQUIREd) and
// released synchronously by release() (ROLLBACK, then the connection is closed). release() is
// idempotent and the destructor calls it, so a failing REQUIRE cannot leave the table locked for
// the rest of the test database's life.
//
// Usage:
//   yuzu::test::EventsTableLock lock(db.dsn());
//   store.set_unrepresented_pending_timeout_ms_for_test(50);   // reach 57014 quickly
//   ... the read that must time out ...
//   lock.release();
//   store.set_unrepresented_pending_timeout_ms_for_test(5000); // restore the production budget
//   ... the follow-up read that must succeed ...
//
// A test that lowers the timeout MUST restore 5000 (the production budget) after release() and
// BEFORE its follow-up read, so the follow-up read is judged against the production setting.
//
// Sibling precedent: test_principal_lock_gate.hpp (a held lock as a deterministic test seam).

#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>

namespace yuzu::test {

class EventsTableLock {
public:
    explicit EventsTableLock(const std::string& dsn)
        : conn_{PQconnectdb(dsn.c_str())} {
        REQUIRE(PQstatus(conn_.get()) == CONNECTION_OK);
        run("BEGIN");
        run("LOCK TABLE guaranteed_state_store.guaranteed_state_events IN ACCESS EXCLUSIVE MODE");
        held_ = true;
    }
    EventsTableLock(const EventsTableLock&) = delete;
    EventsTableLock& operator=(const EventsTableLock&) = delete;
    ~EventsTableLock() { release(); }

    /// Roll the holding transaction back and close the connection. Idempotent.
    void release() noexcept {
        if (!conn_)
            return;
        if (held_) {
            held_ = false;
            yuzu::server::pg::PgResult r{PQexec(conn_.get(), "ROLLBACK")};
        }
        conn_.reset();
    }

private:
    void run(const char* sql) {
        yuzu::server::pg::PgResult r{PQexec(conn_.get(), sql)};
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
    }

    yuzu::server::pg::PgConn conn_;
    bool held_{false};
};

} // namespace yuzu::test
