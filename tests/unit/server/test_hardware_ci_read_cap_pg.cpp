// #7949: the bulk device-CI read's concurrency cap keeps pool connections free for authorization
// and the audit write, proved on a REAL pool. One small pool is shared by an RbacStore, an
// AuditStore and the "bulk readers" (a Reader that holds a real leased connection until the test
// lets it go), exactly as production shares them.
//
// Two cases share one rig shape. The CONTROL has no cap: readers equal to the pool size starve the
// authorization read and the audit write (the defect). The CAPPED case holds the same pool under
// the same reader burst with the cap in place: the surplus readers are refused as busy, and an
// unrelated authorised read and its audit write still obtain a connection.
//
// Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it).

#include "audit_store.hpp"
#include "bulk_read_slots.hpp"
#include "hardware_ci_page_model.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
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

TEST_CASE("bulk read cap: a saturated cap leaves connections for authorization and the audit write",
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
    std::vector<std::thread> threads;
    std::vector<std::optional<hcp::ReadError>> outcome(kPool);
    auto run_reader = [&](int i) {
        const auto page = hcp::read_page(readers.reader(), {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
        if (!page)
            outcome[static_cast<std::size_t>(i)] = page.error();
    };
    for (int i = 0; i < resolved->cap; ++i)
        threads.emplace_back(run_reader, i);
    REQUIRE(readers.wait_for_holding(resolved->cap));
    CHECK(slots.in_use() == resolved->cap);

    // The rest of a burst as large as the pool is refused as busy: no connection is taken for it.
    for (int i = resolved->cap; i < kPool; ++i)
        threads.emplace_back(run_reader, i);
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
