// The bulk device-CI read's concurrency cap (#7949, #7951): the slots type
// (bulk_read_slots.hpp), the boot arithmetic for the effective cap, and how
// `hardware_ci_page::read_page` takes a slot and hands it back in `Page::hold`. Hermetic: no Postgres, no sockets. The
// store is the in-memory fake; a slot is observed through `BulkReadSlots::in_use()` from inside a
// hand-written Reader, so "held across the store call and handed back in Page::hold" is asserted, not assumed.
// The REST and MCP transports are covered beside their other tests (test_mcp_tools_hardware.cpp,
// tag [bulk_read_slots]); the real-pool proof is test_hardware_ci_read_cap_pg.cpp.

#include "bulk_read_slots.hpp"
#include "yuzu/server/server.hpp" // Config
#include "hardware_ci_page_model.hpp"
#include "test_fake_ci_keyset_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace hcp = yuzu::server::hardware_ci_page;
using yuzu::server::pg::CollationGate;
using namespace std::chrono_literals;

static_assert(!std::is_copy_constructible_v<BulkReadSlots>);
static_assert(!std::is_copy_assignable_v<BulkReadSlots>);
static_assert(!std::is_copy_constructible_v<BulkReadSlots::Slot>);
static_assert(!std::is_copy_assignable_v<BulkReadSlots::Slot>);
static_assert(std::is_nothrow_move_constructible_v<BulkReadSlots::Slot>);
// A served Page carries the slot (Page::hold), so it is move-only: a copy would double-release.
static_assert(!std::is_copy_constructible_v<hcp::Page>);
static_assert(!std::is_copy_assignable_v<hcp::Page>);
static_assert(std::is_nothrow_move_constructible_v<hcp::Page>);

TEST_CASE("bulk read cap: the Config default is the resolver's unset sentinel",
          "[bulk_read_slots]") {
    // Config is not a literal type, so this cannot be a static_assert.
    CHECK(yuzu::server::Config{}.hardware_ci_read_concurrency == kBulkReadCapUnset);
}

namespace {

using Clock = std::chrono::steady_clock;

// A short wait keeps the refusal cases fast; the production default is kBulkReadSlotWait.
constexpr auto kShortWait = 30ms;

yuzu::server::test::FakeCiKeysetStore seeded(std::initializer_list<const char*> ids) {
    yuzu::server::test::FakeCiKeysetStore s;
    for (const auto* id : ids)
        s.add(id);
    return s;
}

} // namespace

// ── the slots type ────────────────────────────────────────────────────────────

TEST_CASE("bulk read slots: the cap is a hard bound and a release frees exactly one",
          "[bulk_read_slots]") {
    BulkReadSlots slots{2, kShortWait};
    CHECK(slots.cap() == 2);
    CHECK(slots.in_use() == 0);
    auto a = slots.try_acquire();
    auto b = slots.try_acquire();
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(slots.in_use() == 2);
    CHECK_FALSE(slots.try_acquire().has_value()); // the third finds none
    CHECK(slots.in_use() == 2);                   // a refusal holds nothing
    a.reset();
    CHECK(slots.in_use() == 1);
    auto c = slots.try_acquire();
    CHECK(c.has_value());
    CHECK_FALSE(slots.try_acquire().has_value());
}

TEST_CASE("bulk read slots: the cap is clamped into 1..kMaxBulkReadSlots", "[bulk_read_slots]") {
    CHECK(BulkReadSlots{0, kShortWait}.cap() == 1);
    CHECK(BulkReadSlots{-5, kShortWait}.cap() == 1);
    CHECK(BulkReadSlots{kMaxBulkReadSlots, kShortWait}.cap() == kMaxBulkReadSlots);
    CHECK(BulkReadSlots{kMaxBulkReadSlots + 1, kShortWait}.cap() == kMaxBulkReadSlots);
    // the clamped-to-ceiling object really holds that many
    BulkReadSlots all{1000, kShortWait};
    std::vector<std::optional<BulkReadSlots::Slot>> held;
    for (int i = 0; i < kMaxBulkReadSlots; ++i) {
        held.push_back(all.try_acquire());
        REQUIRE(held.back().has_value());
    }
    CHECK_FALSE(all.try_acquire().has_value());
}

TEST_CASE("bulk read slots: a refusal waits the bounded time, then gives up", "[bulk_read_slots]") {
    BulkReadSlots slots{1, 50ms};
    auto held = slots.try_acquire();
    REQUIRE(held.has_value());
    const auto t0 = Clock::now();
    CHECK_FALSE(slots.try_acquire().has_value());
    // It waited (a semaphore wait never returns early on timeout); the bound is not asserted
    // from above, which would only measure the machine's scheduling.
    CHECK(Clock::now() - t0 >= 45ms);
}

TEST_CASE("bulk read slots: a waiter is admitted when a slot frees inside the wait",
          "[bulk_read_slots]") {
    BulkReadSlots slots{1, 2000ms};
    auto held = slots.try_acquire();
    REQUIRE(held.has_value());
    std::thread releaser([&] {
        std::this_thread::sleep_for(30ms);
        held.reset();
    });
    const auto got = slots.try_acquire(); // parked until the releaser frees the slot
    releaser.join();
    CHECK(got.has_value());
}

TEST_CASE("bulk read slots: the slot is released on scope exit and when the guarded code throws",
          "[bulk_read_slots]") {
    BulkReadSlots slots{1, kShortWait};
    {
        auto s = slots.try_acquire();
        REQUIRE(s.has_value());
        CHECK(slots.in_use() == 1);
    }
    CHECK(slots.in_use() == 0);
    CHECK_THROWS_AS(
        [&] {
            auto s = slots.try_acquire();
            REQUIRE(s.has_value());
            throw std::runtime_error("the guarded read threw");
        }(),
        std::runtime_error);
    CHECK(slots.in_use() == 0);
    CHECK(slots.try_acquire().has_value()); // the one slot is usable again
}

TEST_CASE("bulk read slots: a moved Slot releases once, from its new owner", "[bulk_read_slots]") {
    BulkReadSlots slots{2, kShortWait};
    auto a = slots.try_acquire();
    REQUIRE(a.has_value());
    std::optional<BulkReadSlots::Slot> moved{std::move(*a)};
    a.reset(); // the moved-from Slot holds nothing
    CHECK(slots.in_use() == 1);
    // Move-assigning over a held slot releases the old one first.
    auto b = slots.try_acquire();
    REQUIRE(b.has_value());
    CHECK(slots.in_use() == 2);
    *moved = std::move(*b);
    CHECK(slots.in_use() == 1);
    moved.reset();
    CHECK(slots.in_use() == 0);
}

// ── the boot arithmetic ───────────────────────────────────────────────────────

TEST_CASE("bulk read cap: an unset flag derives min(2, max(1, pool/4)) from the pool size",
          "[bulk_read_slots][boot]") {
    struct Row {
        int pool;
        int cap;
    };
    // Pool 1, 2 and 4 get 1 (the HA rig boots with --postgres-pool-size 2); 8 and the 16 default
    // get 2; a large pool stays at 2.
    for (const Row r : {Row{1, 1}, Row{2, 1}, Row{3, 1}, Row{4, 1}, Row{7, 1}, Row{8, 2}, Row{16, 2},
                        Row{100, 2}}) {
        INFO("pool " << r.pool);
        const auto got = resolve_bulk_read_cap(kBulkReadCapUnset, r.pool);
        REQUIRE(got.has_value());
        CHECK(got->cap == r.cap);
        CHECK(got->defaulted);
    }
    // A non-positive pool (the flag's own validation forbids it) reads as the smallest pool.
    CHECK(resolve_bulk_read_cap(kBulkReadCapUnset, 0)->cap == 1);
}

TEST_CASE("bulk read cap: an explicit value must be in 1..8 and at most max(1, pool/2)",
          "[bulk_read_slots][boot]") {
    struct Row {
        int pool;
        int ceiling; // max(1, pool / 2)
    };
    for (const Row r : {Row{1, 1}, Row{2, 1}, Row{4, 2}, Row{16, 8}}) {
        INFO("pool " << r.pool);
        for (int v = 1; v <= kMaxBulkReadSlots; ++v) {
            INFO("explicit " << v);
            const auto got = resolve_bulk_read_cap(v, r.pool);
            if (v <= r.ceiling) {
                REQUIRE(got.has_value());
                CHECK(got->cap == v);
                CHECK_FALSE(got->defaulted);
            } else {
                REQUIRE_FALSE(got.has_value());
                // the refusal names the flag, the ceiling and the pool flag to raise
                CHECK(got.error().find("--hardware-ci-read-concurrency") != std::string::npos);
                CHECK(got.error().find("--postgres-pool-size") != std::string::npos);
            }
        }
    }
    // Outside 1..8 is refused whatever the pool: zero, negative (other than the unset sentinel,
    // which is -1 and means "not given"), and one past the compile-time ceiling.
    for (const int bad : {0, -2, kMaxBulkReadSlots + 1, 1000}) {
        INFO("explicit " << bad);
        const auto got = resolve_bulk_read_cap(bad, 1000);
        REQUIRE_FALSE(got.has_value());
        CHECK(got.error().find("outside 1..8") != std::string::npos);
    }
}

// ── read_page and the slot ────────────────────────────────────────────────────

TEST_CASE("read_page: the slot is held across the store call and handed back in Page::hold",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, kShortWait};
    auto store = seeded({"a", "b", "c"});
    int in_use_inside = -1;
    bool second_refused_inside = false;
    const hcp::Reader reader = [&](const DeviceCiKeysetQuery& q) {
        in_use_inside = slots.in_use();
        // While the read runs the one slot is taken: a concurrent bulk read would be refused.
        second_refused_inside = !slots.try_acquire().has_value();
        return store.read(q);
    };
    CHECK(slots.in_use() == 0);
    auto page = hcp::read_page(reader, {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
    REQUIRE(page.has_value());
    CHECK(page->rows.size() == 3);
    CHECK(in_use_inside == 1);
    CHECK(second_refused_inside);
    // Still held on return: the caller's access-audit write counts against the cap (#7951).
    CHECK(page->hold.has_value());
    CHECK(slots.in_use() == 1);
    CHECK_FALSE(slots.try_acquire().has_value());
    page->release_slot();
    CHECK(slots.in_use() == 0);
    page->release_slot(); // idempotent
    CHECK(slots.in_use() == 0);
}

TEST_CASE("read_page: dropping the served Page releases the slot on every exit path",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, kShortWait};
    auto store = seeded({"a"});
    {
        auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, &slots,
                                   hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(slots.in_use() == 1);
    }
    CHECK(slots.in_use() == 0);
}

TEST_CASE("read_page: a point read and a null cap hand back no slot",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, kShortWait};
    auto store = seeded({"a", "b"});
    hcp::Request point;
    point.agent_id = "a";
    const auto p = hcp::read_page(store.reader(), point, std::nullopt, nullptr, &slots,
                                  hcp::kRestRowBudgetBytes);
    REQUIRE(p.has_value());
    CHECK_FALSE(p->hold.has_value());
    CHECK(slots.in_use() == 0);
    const auto n = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, /*slots=*/nullptr,
                                  hcp::kRestRowBudgetBytes);
    REQUIRE(n.has_value());
    CHECK_FALSE(n->hold.has_value());
}

TEST_CASE("read_page: a store failure and a throwing reader both release the slot",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, kShortWait};
    const hcp::Reader failing = [](const DeviceCiKeysetQuery&) { return std::nullopt; };
    const auto degraded = hcp::read_page(failing, {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(degraded.has_value());
    CHECK(degraded.error() == hcp::ReadError::kDegraded);
    CHECK(slots.in_use() == 0);

    const hcp::Reader throwing =
        [](const DeviceCiKeysetQuery&) -> std::optional<std::vector<DeviceCiRecord>> {
        throw std::runtime_error("store threw");
    };
    CHECK_THROWS_AS(hcp::read_page(throwing, {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes), std::runtime_error);
    CHECK(slots.in_use() == 0);
}

TEST_CASE("read_page: a saturated cap is kBusy, reads nothing, and waits the bounded time",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, 50ms};
    auto held = slots.try_acquire();
    REQUIRE(held.has_value());
    auto store = seeded({"a", "b"});
    const auto t0 = Clock::now();
    const auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(page.has_value());
    CHECK(page.error() == hcp::ReadError::kBusy);
    CHECK(Clock::now() - t0 >= 45ms);
    CHECK(store.reads == 0);
    CHECK(slots.in_use() == 1); // only the test's own slot; the refusal took none
    // Once the slot frees, the same call serves.
    held.reset();
    const auto again = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
    REQUIRE(again.has_value());
    CHECK(store.reads == 1);
}

TEST_CASE("read_page: a refusal that needs no read takes no slot, so a saturated cap does not "
          "turn it into busy",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, kShortWait};
    auto held = slots.try_acquire();
    REQUIRE(held.has_value());
    auto store = seeded({"a", "b"});

    SECTION("a refusing collation gate") {
        const std::atomic<CollationGate> mismatch{CollationGate::Mismatch};
        const auto page = hcp::read_page(store.reader(), {}, std::nullopt, &mismatch, &slots, hcp::kRestRowBudgetBytes);
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error() == hcp::ReadError::kOrderingUnverified);
    }
    SECTION("a malformed cursor") {
        hcp::Request rq;
        rq.cursor = "garbage";
        const auto page = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error() == hcp::ReadError::kCursorMalformed);
    }
    SECTION("a cursor bound to another filter") {
        hcp::Request other;
        other.agent_id = "a";
        hcp::Request rq;
        rq.cursor = hcp::encode_cursor({"a"}, hcp::filter_fingerprint(other)); // issued for agent_id=a
        const auto page = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error() == hcp::ReadError::kCursorFilterMismatch);
    }
    SECTION("a scope too wide for pushdown with no agent_id") {
        std::unordered_set<std::string> ids;
        for (std::size_t i = 0; i <= hcp::kMaxPushdownScopeIds; ++i)
            ids.insert("d" + std::to_string(i));
        const auto page = hcp::read_page(store.reader(), {}, authz::VisibleSet{std::move(ids)}, nullptr, &slots, hcp::kRestRowBudgetBytes);
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error() == hcp::ReadError::kScopeTooWide);
    }
    SECTION("a named device outside the caller's scope") {
        hcp::Request rq;
        rq.agent_id = "a";
        const auto page = hcp::read_page(store.reader(), rq,
                                         authz::VisibleSet{std::unordered_set<std::string>{"z"}},
                                         nullptr, &slots, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(page->target_denied);
    }
    CHECK(store.reads == 0);
    CHECK(slots.in_use() == 1); // the test's own slot only
}

TEST_CASE("read_page: a point read (agent_id) takes no slot and is served while the cap is full",
          "[bulk_read_slots][hardware_ci_page]") {
    BulkReadSlots slots{1, kShortWait};
    auto held = slots.try_acquire(); // a long walk holds every slot
    REQUIRE(held.has_value());
    auto store = seeded({"a", "b"});
    int in_use_inside = -1;
    const hcp::Reader reader = [&](const DeviceCiKeysetQuery& q) {
        in_use_inside = slots.in_use();
        return store.read(q);
    };
    hcp::Request rq;
    rq.agent_id = "b";
    const auto page = hcp::read_page(reader, rq, std::nullopt, nullptr, &slots, hcp::kRestRowBudgetBytes);
    REQUIRE(page.has_value());
    CHECK(page->rows.size() == 1);
    CHECK(page->rows[0].agent_id == "b");
    CHECK(in_use_inside == 1); // still only the test's own slot: the point read took none
    CHECK(slots.in_use() == 1);
}

TEST_CASE("read_page: a null slots pointer is no cap and serves", "[bulk_read_slots][hardware_ci_page]") {
    auto store = seeded({"a"});
    const auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE(page.has_value());
    CHECK(page->rows.size() == 1);
}
