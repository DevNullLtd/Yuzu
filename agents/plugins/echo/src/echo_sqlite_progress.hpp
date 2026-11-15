#pragma once

// echo_sqlite_progress.hpp -- RAII guard around sqlite3_progress_handler, shared by the
// fold's GC passes and EchoDatabase::execute_user_query so there is one copy of the
// "interrupt a statement once a deadline has passed" mechanism.

#include <functional>
#include <utility>

#include <sqlite3.h>

namespace yuzu::echo {

// Installs a progress handler for the guard's lifetime and clears it on every exit path.
// `expired` is polled every 1000 VM instructions; a true result interrupts the running
// statement (SQLITE_INTERRUPT). The handler is per-connection, so the guard must not
// outlive `db`, and `expired` must not throw (a throw is treated as expired). Not re-entrant: at
// most one guard per connection at a time (a nested guard replaces the outer handler and its
// destructor clears it).
struct ScopedProgressHandler {
    std::function<bool()> expired;
    sqlite3* db;
    ScopedProgressHandler(sqlite3* d, std::function<bool()> f) : expired(std::move(f)), db(d) {
        sqlite3_progress_handler(
            db, 1000,
            [](void* p) noexcept -> int {
                try {
                    return (*static_cast<std::function<bool()>*>(p))() ? 1 : 0;
                } catch (...) {
                    return 1;
                }
            },
            &expired);
    }
    ~ScopedProgressHandler() { sqlite3_progress_handler(db, 0, nullptr, nullptr); }
    ScopedProgressHandler(const ScopedProgressHandler&) = delete;
    ScopedProgressHandler& operator=(const ScopedProgressHandler&) = delete;
};

} // namespace yuzu::echo
