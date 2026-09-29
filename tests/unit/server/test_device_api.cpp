/**
 * test_device_api.cpp — the FOURTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031 WS-A4, family=`device`).
 * `LocalDeviceApi` (device_api.cpp) is the store-free DATA PROVIDER behind
 * `GET /api/v1/devices[/{id}]` + MCP `list_agents`/`get_agent_details`.
 * Exercised only through the public `DeviceApi` interface via
 * `make_local_device_api` — never the concrete class (matches how the real
 * REST/MCP/dashboard consumers use it).
 *
 * Contract points pinned here:
 *   - list_devices returns the UNFILTERED registry rows (the 5-field public
 *     shape); confinement is the consumer's job, not this layer's.
 *   - lookup_device is an O(1) point lookup: a HIT returns detail, a genuine
 *     MISS returns an engaged-expected empty optional (NOT an error), and the
 *     two not-found sub-cases are indistinguishable here (#3564).
 *   - a degraded tag-store read on the detail path surfaces as
 *     DeviceReadError::kDegraded (so the REST consumer can 503); a NULL
 *     TagStore is NOT degraded — it yields an empty tags vector.
 */

#include "device_api_local.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"
#include "test_tag_store_pg_helper.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using yuzu::server::DeviceReadError;
using yuzu::server::TagStore;
using yuzu::server::make_local_device_api;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo make_info(const std::string& id, const std::string& os) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname(id + ".local");
    info.mutable_platform()->set_os(os);
    info.mutable_platform()->set_arch("x86_64");
    return info;
}

} // namespace

TEST_CASE("DeviceApi: list_devices returns the fleet's public 5-field rows", "[device_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    REQUIRE(registry.register_agent(make_info("agent-a", "linux")).has_value());
    REQUIRE(registry.register_agent(make_info("agent-b", "windows")).has_value());

    auto api = make_local_device_api(registry, nullptr);
    const auto rows = api->list_devices();
    REQUIRE(rows.size() == 2);

    const auto* a = &rows[0];
    if (rows[0].agent_id != "agent-a")
        a = &rows[1];
    CHECK(a->agent_id == "agent-a");
    CHECK(a->hostname == "agent-a.local");
    CHECK(a->os == "linux");
    CHECK(a->arch == "x86_64");
}

TEST_CASE("DeviceApi: lookup_device miss returns an engaged empty optional, not an error",
          "[device_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    auto api = make_local_device_api(registry, nullptr);
    const auto res = api->lookup_device("nonexistent-agent");
    REQUIRE(res.has_value());     // NOT a DeviceReadError
    CHECK_FALSE(res->has_value()); // engaged optional, empty (genuine miss)
}

TEST_CASE("DeviceApi: lookup_device hit with a null TagStore yields empty tags, no error",
          "[device_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    REQUIRE(registry.register_agent(make_info("agent-nt", "darwin")).has_value());

    auto api = make_local_device_api(registry, /*tags=*/nullptr);
    const auto res = api->lookup_device("agent-nt");
    REQUIRE(res.has_value());
    REQUIRE(res->has_value());
    CHECK((*res)->row.agent_id == "agent-nt");
    CHECK((*res)->row.os == "darwin");
    CHECK((*res)->tags.empty()); // null store degrades tags to empty, not an error
}

TEST_CASE("DeviceApi: lookup_device hit resolves operator tags from the TagStore",
          "[pg][device_api]") {
    yuzu::test::TagStorePg tag_bundle;
    TagStore& tags = *tag_bundle;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    REQUIRE(registry.register_agent(make_info("agent-t", "linux")).has_value());
    REQUIRE(tags.set_tag("agent-t", "dept", "eng", "operator").has_value());

    auto api = make_local_device_api(registry, &tags);
    const auto res = api->lookup_device("agent-t");
    REQUIRE(res.has_value());
    REQUIRE(res->has_value());
    const auto& detail = **res;
    CHECK(detail.row.agent_id == "agent-t");
    const bool has_dept = std::any_of(detail.tags.begin(), detail.tags.end(), [](const auto& t) {
        return t.key == "dept" && t.value == "eng" && t.source == "operator";
    });
    CHECK(has_dept);
}
