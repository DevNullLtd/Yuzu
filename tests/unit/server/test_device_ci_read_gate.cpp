// device_ci read gate (#7730): the ONE mapping from the collation gate to "may a device_ci read
// answer?" (device_ci_read_gate.hpp), and its use by the bulk page model. Hermetic: the gate is a
// plain atomic flipped by the test, the store is the in-memory fake with a call counter. The REST
// and MCP transports are covered beside their other tests (test_hardware_routes.cpp,
// test_mcp_tools_hardware.cpp, tag [collation_gate]); the per-id and roster closures live in
// server.cpp and are pinned lexically (test_hw_ci_detail_wiring_lexical.cpp).

#include "device_ci_read_gate.hpp"
#include "hardware_ci_page_model.hpp"
#include "inventory_ci_join.hpp"
#include "pg/pg_collation_check.hpp"
#include "test_fake_ci_keyset_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace gate = yuzu::server::device_ci_read_gate;
namespace hcp = yuzu::server::hardware_ci_page;
using yuzu::server::pg::CollationGate;

TEST_CASE("device_ci read gate: Trusted serves, Mismatch and Unproven refuse", "[collation_gate]") {
    CHECK(gate::decide(CollationGate::Trusted) == gate::Decision::kServe);
    CHECK(gate::decide(CollationGate::Mismatch) == gate::Decision::kRefuse);
    CHECK(gate::decide(CollationGate::Unproven) == gate::Decision::kRefuse);
    // an out-of-range value fails closed
    CHECK(gate::decide(static_cast<CollationGate>(99)) == gate::Decision::kRefuse);
}

TEST_CASE("device_ci read gate: the pointer form reads the published value; null means no gate",
          "[collation_gate]") {
    CHECK_FALSE(gate::refuses(nullptr));
    CHECK(gate::decide(static_cast<const std::atomic<CollationGate>*>(nullptr)) == gate::Decision::kServe);

    std::atomic<CollationGate> g{pg::kInitialCollationGate};
    CHECK(gate::refuses(&g)); // a boot with no conclusive answer is Unproven, which refuses
    g.store(CollationGate::Trusted);
    CHECK_FALSE(gate::refuses(&g));
    g.store(CollationGate::Mismatch);
    CHECK(gate::refuses(&g));
}

TEST_CASE("device_ci read gate: the refusal's retry hint is the recheck's unsettled interval",
          "[collation_gate]") {
    CHECK(gate::kOrderingRetryAfterMs == 60000);
    CHECK(gate::kOrderingRetryAfterMs ==
          std::chrono::duration_cast<std::chrono::milliseconds>(kCollationUnsettledRecheckInterval).count());
}

TEST_CASE("device_ci read gate: read_page refuses under Mismatch and Unproven and makes no store call",
          "[collation_gate][hardware_ci_page]") {
    yuzu::server::test::FakeCiKeysetStore store;
    store.add("a");
    store.add("b");
    std::atomic<CollationGate> g{CollationGate::Trusted};

    SECTION("Trusted serves") {
        const auto page = hcp::read_page(store.reader(), {}, std::nullopt, &g, nullptr);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 2);
        CHECK(store.reads == 1);
    }
    SECTION("Mismatch and Unproven refuse before the store is asked") {
        for (const auto refused : {CollationGate::Mismatch, CollationGate::Unproven}) {
            g.store(refused);
            const auto page = hcp::read_page(store.reader(), {}, std::nullopt, &g, nullptr);
            REQUIRE_FALSE(page.has_value());
            CHECK(page.error() == hcp::ReadError::kOrderingUnverified);
            CHECK(store.reads == 0); // refused before the store was asked
            // a named device, and a confined scope, are refused the same way
            hcp::Request named;
            named.agent_id = "a";
            const auto one = hcp::read_page(store.reader(), named, authz::VisibleSet{std::unordered_set<std::string>{"a"}}, &g, nullptr);
            REQUIRE_FALSE(one.has_value());
            CHECK(one.error() == hcp::ReadError::kOrderingUnverified);
            CHECK(store.reads == 0);
        }
    }
    SECTION("a null gate (none wired) serves, whatever any gate holds") {
        g.store(CollationGate::Mismatch);
        const auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 2);
    }
    SECTION("a scope refusal that needs no read keeps its own answer under a refusing gate") {
        g.store(CollationGate::Mismatch);
        authz::VisibleSet wide = std::unordered_set<std::string>{};
        for (std::size_t i = 0; i <= hcp::kMaxPushdownScopeIds; ++i)
            wide->insert("x" + std::to_string(i));
        const auto page = hcp::read_page(store.reader(), {}, wide, &g, nullptr);
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error() == hcp::ReadError::kScopeTooWide);
    }
}

// The roster-keyed columns: server.cpp's keyed closure returns nullopt while the gate refuses, and
// `apply_ci_read` turns that into `ci_degraded` with every ci_* column blank. This mirrors the
// closure (the real one is pinned lexically); it proves the existing degrade state is what a
// refusal produces and that the store is not asked.
TEST_CASE("device_ci read gate: a refusing gate degrades the roster CI columns without a store read",
          "[collation_gate][ci_join]") {
    yuzu::server::test::FakeCiKeysetStore store;
    store.add("a");
    std::atomic<CollationGate> g{CollationGate::Mismatch};
    int store_calls = 0;
    CiKeyedReadFn read = [&](const std::vector<std::string>&) -> std::optional<std::vector<DeviceCiRecord>> {
        if (gate::refuses(&g))
            return std::nullopt;
        ++store_calls;
        return store.rows;
    };
    InventoryDevicesResult result;
    InventoryDeviceRow row;
    row.agent_id = "a";
    result.rows.push_back(row);

    apply_ci_read(result, read);
    CHECK(result.ci_degraded);
    CHECK(store_calls == 0);
    CHECK(result.rows[0].ci_serial.empty());

    g.store(CollationGate::Trusted);
    InventoryDevicesResult ok;
    ok.rows.push_back(row);
    apply_ci_read(ok, read);
    CHECK_FALSE(ok.ci_degraded);
    CHECK(store_calls == 1);
    CHECK(ok.rows[0].ci_serial == "SN-a");
}
