/**
 * test_network_api.cpp — the FIRST per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4/WS-A2r pilot).
 * `LocalNetworkApi` (network_api.cpp) is the store-reaching assembly
 * previously inline in server.cpp's `net_perf_uncached` lambda + `NetPerfMemo`
 * — moved verbatim behind the `NetworkApi` seam so it is independently
 * testable. Every behaviour the move promises to preserve gets its own case
 * here: cohort STORE-FIRST precedence, C-S1 health-only devices, the
 * null-TagStore degrade posture, and the 5s TTL memo. Only reached through
 * the public `NetworkApi` interface (`fleet_now`/`device_list`) — the class
 * itself (`LocalNetworkApi`) is deliberately private to network_api.cpp, so
 * this file uses only `make_local_network_api`, matching how a real
 * presentation/MCP caller will use it.
 */

#include "network_api_local.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"
#include "test_tag_store_pg_helper.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <google/protobuf/map.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::NetCoocFilter;
using yuzu::server::NetDeviceQuery;
using yuzu::server::NetPerfMetric;
using yuzu::server::TagStore;
using yuzu::server::make_local_network_api;
using yuzu::server::detail::AgentHealthStore;
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

/// Heartbeat a device's network facts straight into the REAL AgentHealthStore
/// (a real `google::protobuf::Map` upsert — the same seam
/// test_agent_health_store.cpp's `[real]` case drives — so this file cannot
/// be fooled by a reproduction of the store).
void beat_net(AgentHealthStore& health, const std::string& id, double rtt_ms,
             double retrans_pct = -1.0, bool degraded = false, double cpu_pct = -1.0) {
    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.net_rtt_p50_ms"] = std::to_string(rtt_ms);
    if (retrans_pct >= 0.0)
        tags["yuzu.net_retrans_pct"] = std::to_string(retrans_pct);
    if (degraded)
        tags["yuzu.net_degraded"] = "1";
    if (cpu_pct >= 0.0)
        tags["yuzu.perf_cpu_pct"] = std::to_string(cpu_pct);
    health.upsert(id, tags);
}

} // namespace

TEST_CASE("NetworkApi: null TagStore degrades to no cohort resolution / empty available_keys",
          "[network_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    auto info = make_info("agent-a", "linux");
    (*info.mutable_scopable_tags())["dept"] = "eng";
    REQUIRE(registry.register_agent(info).has_value());
    beat_net(health, "agent-a", 12.5);

    auto api = make_local_network_api(health, registry, /*tags=*/nullptr);

    const auto now = api->fleet_now("dept");
    CHECK(now.online == 1);
    CHECK(now.reporting == 1);
    CHECK(now.available_keys.empty()); // no store to ask -> honestly empty, no crash

    // Cohort resolution still falls back to the session's own scopable_tags
    // claim when there is no store to consult at all (the deliberate
    // asymmetry the tag: resolver documents — a null store is a legitimate
    // "nothing to ask", not a degraded one).
    NetDeviceQuery q;
    q.cohort_key = "dept";
    const auto rows = api->device_list(q);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].agent_id == "agent-a");
    CHECK(rows[0].cohort == "eng");
}

TEST_CASE("NetworkApi: cohort STORE-FIRST precedence over session scopable_tags",
          "[pg][network_api]") {
    yuzu::test::TagStorePg tag_bundle;
    TagStore& tags = *tag_bundle;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    auto info = make_info("agent-b", "windows");
    (*info.mutable_scopable_tags())["dept"] = "eng"; // session's own (weaker) claim
    REQUIRE(registry.register_agent(info).has_value());
    beat_net(health, "agent-b", 20.0);

    REQUIRE(tags.set_tag("agent-b", "dept", "finance", "operator").has_value());

    auto api = make_local_network_api(health, registry, &tags);

    NetDeviceQuery q;
    q.cohort_key = "dept";
    const auto rows = api->device_list(q);
    REQUIRE(rows.size() == 1);
    // The operator-declared store row wins over the agent's in-memory claim.
    CHECK(rows[0].cohort == "finance");

    const auto now = api->fleet_now("dept");
    CHECK(std::find(now.available_keys.begin(), now.available_keys.end(), "dept") !=
         now.available_keys.end());
}

TEST_CASE("NetworkApi: C-S1 health-only device (session reaped) still appears",
          "[network_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    // No register_agent call at all — the heartbeat facts exist, but the
    // session has (or never had) an entry in the live registry, mirroring a
    // reaped session with a still-fresh heartbeat.
    beat_net(health, "ghost-1", 33.0);

    auto api = make_local_network_api(health, registry, nullptr);

    const auto now = api->fleet_now("");
    CHECK(now.online == 1);
    CHECK(now.reporting == 1);

    NetDeviceQuery q;
    const auto rows = api->device_list(q);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].agent_id == "ghost-1");
    // Health-only devices have no session to resolve a platform from.
    CHECK(rows[0].platform.empty());
}

TEST_CASE("NetworkApi: 5s TTL memo returns the cached snapshot", "[network_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    beat_net(health, "agent-c", 10.0);

    auto api = make_local_network_api(health, registry, nullptr);

    const auto first = api->fleet_now("");
    REQUIRE(first.reporting == 1);

    // Mutate the underlying store directly (bypassing the API) — if the memo
    // were NOT caching, the very next call would observe this immediately.
    beat_net(health, "agent-d", 11.0);

    const auto second = api->fleet_now("");
    CHECK(second.reporting == 1); // still the memoized snapshot, not re-walked

    // A device_list() call within the same TTL window shares the same memo
    // key ("") and must also see the cached (pre-mutation) population.
    NetDeviceQuery q;
    const auto rows = api->device_list(q);
    CHECK(rows.size() == 1);
}

TEST_CASE("NetworkApi: fleet_now/device_list produce the expected derived shapes",
          "[network_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    REQUIRE(registry.register_agent(make_info("agent-lo", "linux")).has_value());
    REQUIRE(registry.register_agent(make_info("agent-hi", "linux")).has_value());
    // Under device pressure AND network-degraded -> "also_device" co-occurrence.
    beat_net(health, "agent-hi", /*rtt_ms=*/100.0, /*retrans_pct=*/5.0, /*degraded=*/true,
            /*cpu_pct=*/95.0);
    beat_net(health, "agent-lo", /*rtt_ms=*/5.0);

    auto api = make_local_network_api(health, registry, nullptr);

    const auto now = api->fleet_now("");
    REQUIRE(now.rtt.has_value());
    CHECK(now.rtt->n == 2);
    CHECK(now.reporting == 2);
    CHECK(now.online == 2);
    CHECK(now.cooc.degraded == 1);
    CHECK(now.cooc.also_device == 1);
    CHECK(now.cooc.network_only == 0);

    NetDeviceQuery q;
    q.metric = NetPerfMetric::kRtt;
    const auto worst = api->device_list(q);
    REQUIRE(worst.size() == 2);
    // Worst-by-RTT first.
    CHECK(worst[0].agent_id == "agent-hi");
    CHECK(worst[0].under_pressure);
    CHECK(worst[0].fleet_pctile >= 0);
    CHECK_FALSE(worst[1].under_pressure);

    NetDeviceQuery cooc_q;
    cooc_q.cooc = NetCoocFilter::kAlsoDevice;
    const auto cooc_rows = api->device_list(cooc_q);
    REQUIRE(cooc_rows.size() == 1);
    CHECK(cooc_rows[0].agent_id == "agent-hi");
}

// Governance BLOCKING (2026-09-10, 4 agents): available_keys must be populated
// on the KEY-LESS fleet call, because both public fleet surfaces
// (GET /api/v1/network/fleet, MCP get_network_fleet) call fleet_now("") and the
// OpenAPI/MCP schema mark available_keys as carrying the fleet's tag keys. The
// original cut gated it on !cohort_key.empty(), so it was structurally always []
// on those surfaces. This case fails against that cut and locks the fix (the
// distinct-KEY namespace does not depend on the cohort key).
TEST_CASE("NetworkApi: fleet_now(\"\") populates available_keys (key-less fleet surface)",
          "[pg][network_api]") {
    yuzu::test::TagStorePg tag_bundle;
    TagStore& tags = *tag_bundle;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    REQUIRE(registry.register_agent(make_info("agent-ak", "linux")).has_value());
    beat_net(health, "agent-ak", 12.0);
    REQUIRE(tags.set_tag("agent-ak", "dept", "eng", "operator").has_value());
    REQUIRE(tags.set_tag("agent-ak", "region", "emea", "operator").has_value());

    auto api = make_local_network_api(health, registry, &tags);

    // The fleet endpoints call fleet_now with an EMPTY cohort key.
    const auto now = api->fleet_now("");
    CHECK(std::find(now.available_keys.begin(), now.available_keys.end(), "dept") !=
          now.available_keys.end());
    CHECK(std::find(now.available_keys.begin(), now.available_keys.end(), "region") !=
          now.available_keys.end());
}

// cpp-safety SHOULD (2026-09-10): the mutable 5s memo is the one genuinely
// concurrent surface the seam adds (httplib is thread-per-connection, so the
// three consumer surfaces call the shared shared_ptr<const NetworkApi> from many
// threads at once). Hammer fleet_now/device_list across threads with distinct +
// shared cohort keys (forcing memo eviction past the 8-entry cap) so nightly
// TSan proves the lock discipline; also asserts results stay well-formed.
TEST_CASE("NetworkApi: concurrent fleet_now/device_list are memo-race-free", "[network_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    for (int i = 0; i < 6; ++i) {
        REQUIRE(registry.register_agent(make_info("agent-" + std::to_string(i), "linux"))
                    .has_value());
        beat_net(health, "agent-" + std::to_string(i), 10.0 + i);
    }

    auto api = make_local_network_api(health, registry, nullptr);

    constexpr int kThreads = 8;
    constexpr int kIters = 200;
    std::atomic<int> ok{0};
    std::vector<std::thread> ts;
    ts.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&, t] {
            for (int i = 0; i < kIters; ++i) {
                // >8 distinct keys forces eviction under the 8-entry memo cap;
                // key "" is the shared hot key both fleet surfaces use.
                const std::string key = (i % 3 == 0) ? std::string{}
                                                      : ("k" + std::to_string((t * kIters + i) % 16));
                const auto now = api->fleet_now(key);
                NetDeviceQuery q;
                q.cohort_key = key;
                const auto rows = api->device_list(q);
                if (now.reporting == 6 && rows.size() == 6)
                    ok.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& th : ts)
        th.join();
    // Every iteration sees the full, consistent population (no torn/partial
    // snapshot from a memo data race).
    CHECK(ok.load() == kThreads * kIters);
}
