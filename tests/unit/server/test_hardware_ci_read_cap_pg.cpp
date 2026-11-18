// #7949: the bulk device-CI read's concurrency cap keeps pool connections free for authorization
// and the audit write, proved on a REAL pool. One small pool is shared by an RbacStore, an
// AuditStore and the "bulk readers" (a Reader that holds a real leased connection until the test
// lets it go), exactly as production shares them.
//
// Two cases (control + capped) hold readers on real leased connections; two more (below) lock the
// audit table. They share the pool shape. The CONTROL has no cap: readers equal to the pool size starve the
// authorization read and the audit write (the defect). The CAPPED case holds the same pool under
// the same reader burst with the cap in place: the surplus readers are refused as busy, and an
// unrelated authorised read and its audit write still obtain a connection.
//
// Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it).

#include "audit_store.hpp"
#include "bulk_read_slots.hpp"
#include "hardware_ci_page_model.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
namespace hcp = yuzu::server::hardware_ci_page;
using pg::PgPool;
using namespace std::chrono_literals;

namespace {

yuzu::test::PgTestTemplate cap_tpl{"hwci_read_cap", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 2}};
    RbacStore rbac{pool};
    AuditStore audit{pool};
    if (!rbac.is_open() || !audit.is_open())
        throw std::runtime_error("hwci read cap template: a store failed to migrate");
}};

constexpr int kPool = 4;

// A Reader that checks out a real connection and holds it until `release()`. `holding()` is how
// many are parked right now.
class BlockedReaders {
  public:
    explicit BlockedReaders(PgPool& pool) : pool_(pool) {}
    ~BlockedReaders() { release(); }

    hcp::Reader reader() {
        return [this](const DeviceCiKeysetQuery&) -> std::optional<std::vector<DeviceCiRecord>> {
            auto lease = pool_.acquire();
            if (!lease)
                return std::nullopt;
            holding_.fetch_add(1);
            {
                std::unique_lock lk(mu_);
                cv_.wait(lk, [&] { return released_; });
            }
            holding_.fetch_sub(1);
            return std::vector<DeviceCiRecord>{};
        };
    }
    void release() {
        {
            std::lock_guard lk(mu_);
            released_ = true;
        }
        cv_.notify_all();
    }
    int holding() const { return holding_.load(); }
    bool wait_for_holding(int n) const {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (holding() < n) {
            if (std::chrono::steady_clock::now() > deadline)
                return false;
            std::this_thread::sleep_for(5ms);
        }
        return true;
    }

  private:
    PgPool& pool_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool released_{false};
    std::atomic<int> holding_{0};
};

// Unwinds a test safely when a REQUIRE fails with reader threads still parked: release the readers
// first (they wait on a condition variable), then join every thread. Declare it AFTER the threads
// vector and the BlockedReaders so it is destroyed first. std::thread only (never std::jthread).
struct JoinGuard {
    BlockedReaders& readers;
    std::vector<std::thread>& threads;
    ~JoinGuard() {
        readers.release();
        for (auto& t : threads)
            if (t.joinable())
                t.join();
    }
};

AuditEvent a_row() {
    AuditEvent e;
    e.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    e.principal = "tester";
    e.action = "inventory.devices.ci";
    e.target_type = "Inventory";
    e.target_id = "fleet";
    e.detail = "hardware CI records (REST): rows=0 scope=fleet";
    e.result = "success";
    return e;
}

} // namespace

TEST_CASE("bulk read cap [control]: with no cap, bulk readers equal to the pool starve authorization "
          "and the audit write",
          "[pg][hardware_ci][bulk_read_slots]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, cap_tpl);
    PgPool pool{{.conninfo = db_.dsn(), .size = kPool}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    AuditStore audit{pool};
    REQUIRE(rbac.is_open());
    REQUIRE(audit.is_open());

    BlockedReaders readers{pool};
    std::vector<std::thread> threads;
    JoinGuard guard{readers, threads};
    for (int i = 0; i < kPool; ++i)
        threads.emplace_back([&] {
            (void)hcp::read_page(readers.reader(), {}, std::nullopt, nullptr, /*slots=*/nullptr, hcp::kRestRowBudgetBytes);
        });
    REQUIRE(readers.wait_for_holding(kPool)); // every pooled connection is held by a bulk read

    // An unrelated authorization read and the audit write both lose their connection: #7949.
    const auto authz = rbac.user_rbac_group_names_checked("tester");
    CHECK_FALSE(authz.has_value());
    CHECK_FALSE(audit.log(a_row()));

    readers.release();
    for (auto& t : threads)
        t.join();
}

TEST_CASE("bulk read cap: a saturated cap leaves connections for authorization and the audit write "
          "(pool larger than the cap)",
          "[pg][hardware_ci][bulk_read_slots]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, cap_tpl);
    PgPool pool{{.conninfo = db_.dsn(), .size = kPool}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    AuditStore audit{pool};
    REQUIRE(rbac.is_open());
    REQUIRE(audit.is_open());

    // The effective cap for this pool when the flag is unset would be 1; an explicit 2 is the
    // largest value the boot rule allows (half the pool).
    const auto resolved = resolve_bulk_read_cap(2, kPool);
    REQUIRE(resolved.has_value());
    BulkReadSlots slots{resolved->cap, 100ms};
    BlockedReaders readers{pool};

    // Fill the cap with readers that hold real connections.
    std::vector<std::optional<hcp::ReadError>> outcome(kPool);
    std::vector<std::thread> threads;
    std::atomic<int> surplus_done{0}; // surplus readers that have returned (outcome is written)
    JoinGuard guard{readers, threads}; // after everything the reader threads touch
    auto run_reader = [&](int i) {
        const auto page = hcp::read_page(readers.reader(), {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
        if (!page)
            outcome[static_cast<std::size_t>(i)] = page.error();
        if (i >= resolved->cap)
            surplus_done.fetch_add(1);
    };
    for (int i = 0; i < resolved->cap; ++i)
        threads.emplace_back(run_reader, i);
    REQUIRE(readers.wait_for_holding(resolved->cap));
    CHECK(slots.in_use() == resolved->cap);

    // The rest of a burst as large as the pool is refused as busy: no connection is taken for it.
    for (int i = resolved->cap; i < kPool; ++i)
        threads.emplace_back(run_reader, i);
    // Wait for the surplus outcomes with a deadline: a cap regression would let a surplus reader
    // park on the store instead of returning, and a bare join here would hang the suite. The
    // guard releases the readers and joins when the REQUIRE fails.
    const int surplus = kPool - resolved->cap;
    const auto surplus_deadline = std::chrono::steady_clock::now() + 10s;
    while (surplus_done.load() < surplus && std::chrono::steady_clock::now() < surplus_deadline)
        std::this_thread::sleep_for(5ms);
    REQUIRE(surplus_done.load() == surplus);
    for (int i = resolved->cap; i < kPool; ++i)
        threads[static_cast<std::size_t>(i)].join();
    for (int i = resolved->cap; i < kPool; ++i) {
        INFO("surplus reader " << i);
        REQUIRE(outcome[static_cast<std::size_t>(i)].has_value());
        CHECK(*outcome[static_cast<std::size_t>(i)] == hcp::ReadError::kBusy);
    }
    CHECK(readers.holding() == resolved->cap); // the surplus never reached the store
    CHECK(slots.in_use() == resolved->cap);

    // With the cap's worth of connections held, an unrelated authorised read AND the audit write
    // still obtain a connection inside their normal acquire timeouts.
    const auto authz = rbac.user_rbac_group_names_checked("tester");
    CHECK(authz.has_value());
    CHECK(audit.log(a_row()));

    readers.release();
    for (int i = 0; i < resolved->cap; ++i)
        threads[static_cast<std::size_t>(i)].join();
    for (int i = 0; i < resolved->cap; ++i)
        CHECK_FALSE(outcome[static_cast<std::size_t>(i)].has_value()); // the held readers were served
    CHECK(slots.in_use() == 0);
}

// #7951: an audit table that is locked (migration DDL, VACUUM FULL) makes every served read's audit
// INSERT wait while it holds a pooled connection. The slot is held through that write, so only `cap`
// such writers can pile up and the rest of the pool stays usable. The CONTROL gives the slot back
// right after the read (the earlier behaviour): the same burst then parks one audit writer per
// pooled connection and authorization loses its connection.
namespace {

struct AuditLockRun {
    bool authz_ok{false};
    int audit_writers_parked{0}; // served reads that went on to their audit write (see `waiting`)
    int busy{0};
    int served{0};
    int audit_ok{0};
};

AuditLockRun run_with_locked_audit_table(const std::string& dsn, int cap, bool hold_slot_through_audit) {
    PgPool pool{{.conninfo = dsn, .size = kPool}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    AuditStore audit{pool};
    REQUIRE(rbac.is_open());
    REQUIRE(audit.is_open());
    BulkReadSlots slots{cap, 100ms};

    // A session OUTSIDE the pool takes the audit table lock, the way migration DDL would.
    pg::PgConn locker{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() == PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(), "LOCK TABLE audit_store.audit_events IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    bool locked = true;
    auto unlock = [&] {
        if (locked) {
            (void)pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{});
            locked = false;
        }
    };

    std::atomic<int> parked{0}, busy{0}, served{0}, audit_ok{0};
    std::vector<std::thread> threads;
    // Declared after `threads` and the atomics they touch: on any exit path the lock is released
    // first (the stalled INSERTs then finish), then every thread is joined.
    struct Cleanup {
        std::function<void()>& unlock;
        std::vector<std::thread>& threads;
        ~Cleanup() {
            unlock();
            for (auto& t : threads)
                if (t.joinable())
                    t.join();
        }
    };
    // Declared BEFORE `cleanup`: the thread bodies capture it by reference, so it must outlive the
    // joins on every exit path.
    const hcp::Reader instant = [](const DeviceCiKeysetQuery&) -> std::optional<std::vector<DeviceCiRecord>> {
        return std::vector<DeviceCiRecord>{};
    };
    std::function<void()> unlock_fn = unlock;
    Cleanup cleanup{unlock_fn, threads};

    for (int i = 0; i < kPool; ++i)
        threads.emplace_back([&] {
            auto page = hcp::read_page(instant, {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
            if (!page) {
                busy.fetch_add(1);
                return;
            }
            served.fetch_add(1);
            if (!hold_slot_through_audit)
                page->release_slot(); // the earlier behaviour: the slot is gone before the audit write
            parked.fetch_add(1);
            if (audit.log(a_row()))
                audit_ok.fetch_add(1);
            page->release_slot();
        });

    // Wait for the burst to settle: every thread has either been refused or is waiting on the lock.
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (busy.load() + parked.load() < kPool && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(5ms);
    // Then wait until the server REPORTS that many audit INSERTs ungranted on the locked table
    // (pg_locks, read from the locker's own session), instead of sleeping and hoping they got there.
    const int expected_waiters = hold_slot_through_audit ? cap : kPool;
    int waiting = 0;
    const auto lock_deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < lock_deadline) {
        auto r = pg::exec_params(
            locker.get(),
            "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE NOT l.granted AND n.nspname = 'audit_store' AND c.relname = 'audit_events'",
            std::vector<std::string>{});
        if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1)
            waiting = std::atoi(PQgetvalue(r.get(), 0, 0));
        if (waiting >= expected_waiters)
            break;
        std::this_thread::sleep_for(10ms);
    }
    CHECK(waiting == expected_waiters); // the writers really are parked on the lock

    AuditLockRun out;
    out.authz_ok = rbac.user_rbac_group_names_checked("tester").has_value();
    out.audit_writers_parked = parked.load();
    out.busy = busy.load();
    out.served = served.load();

    unlock();
    for (auto& t : threads)
        t.join();
    out.audit_ok = audit_ok.load();
    CHECK(slots.in_use() == 0);
    return out;
}

} // namespace

TEST_CASE("bulk read cap [control]: giving the slot back before the audit write lets a locked audit "
          "table park a writer per pooled connection and starve authorization",
          "[pg][hardware_ci][bulk_read_slots][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, cap_tpl);
    const auto r = run_with_locked_audit_table(db_.dsn(), /*cap=*/2, /*hold_slot_through_audit=*/false);
    CHECK(r.served == kPool);
    CHECK(r.busy == 0);
    CHECK_FALSE(r.authz_ok); // every pooled connection is parked in an audit INSERT
    CHECK(r.audit_ok == kPool); // the writes complete once the lock is released
}

TEST_CASE("bulk read cap: a locked audit table parks at most `cap` audit writers, so authorization "
          "keeps a connection",
          "[pg][hardware_ci][bulk_read_slots][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, cap_tpl);
    const auto resolved = resolve_bulk_read_cap(2, kPool);
    REQUIRE(resolved.has_value());
    const auto r = run_with_locked_audit_table(db_.dsn(), resolved->cap, /*hold_slot_through_audit=*/true);
    CHECK(r.served == resolved->cap);
    CHECK(r.busy == kPool - resolved->cap); // the rest were refused: no read, no audit write
    CHECK(r.audit_writers_parked == resolved->cap);
    CHECK(r.authz_ok);
    CHECK(r.audit_ok == resolved->cap);
}

