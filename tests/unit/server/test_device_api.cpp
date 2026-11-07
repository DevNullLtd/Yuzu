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
 *   - list_devices returns the UNFILTERED registry rows (the public shape: five
 *     registry-derived fields plus the heartbeat-derived guardian_backend);
 *     confinement is the consumer's job, not this layer's.
 *   - guardian_backend (#2240) is read from the REAL AgentHealthStore through the
 *     same closed-set parse the fleet gauge uses; absent, empty, forged and stale
 *     values are nullopt and NEVER "legacy". These are the only cases that go red
 *     if the health-store call in LocalDeviceApi is deleted: the REST/MCP doubles
 *     feed the field by hand and cannot.
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
#include "guardian_backend_fleet_tags.hpp" // the SHIPPED token table (no parallel repro)
#include "tag_store.hpp"

#include "../test_helpers.hpp"
#include "test_tag_store_pg_helper.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using yuzu::server::DeviceReadError;
using yuzu::server::TagStore;
using yuzu::server::make_local_device_api;
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

} // namespace

TEST_CASE("DeviceApi: list_devices returns the fleet's public rows", "[device_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;

    REQUIRE(registry.register_agent(make_info("agent-a", "linux")).has_value());
    REQUIRE(registry.register_agent(make_info("agent-b", "windows")).has_value());

    auto api = make_local_device_api(registry, nullptr, health);
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
    AgentHealthStore health;

    auto api = make_local_device_api(registry, nullptr, health);
    const auto res = api->lookup_device("nonexistent-agent");
    REQUIRE(res.has_value());     // NOT a DeviceReadError
    CHECK_FALSE(res->has_value()); // engaged optional, empty (genuine miss)
}

TEST_CASE("DeviceApi: lookup_device hit with a null TagStore yields empty tags, no error",
          "[device_api]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;
    REQUIRE(registry.register_agent(make_info("agent-nt", "darwin")).has_value());

    auto api = make_local_device_api(registry, /*tags=*/nullptr, health);
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
    AgentHealthStore health;
    REQUIRE(registry.register_agent(make_info("agent-t", "linux")).has_value());
    REQUIRE(tags.set_tag("agent-t", "dept", "eng", "operator").has_value());

    auto api = make_local_device_api(registry, &tags, health);
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

// ── #2240: guardian_backend, driven through the REAL AgentHealthStore ────────────────────

namespace {

void beat(AgentHealthStore& health, const std::string& id,
          const std::optional<std::string>& backend) {
    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    if (backend)
        tags["yuzu.guardian_backend"] = *backend;
    health.upsert(id, tags);
}

const yuzu::server::DeviceListRow* row_for(const std::vector<yuzu::server::DeviceListRow>& rows,
                                           const std::string& id) {
    for (const auto& r : rows)
        if (r.agent_id == id)
            return &r;
    return nullptr;
}

} // namespace

TEST_CASE("DeviceApi guardian_backend: a reported token reaches the list row and the detail",
          "[device_api][guardian_backend]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;
    REQUIRE(registry.register_agent(make_info("gb-spark", "linux")).has_value());
    REQUIRE(registry.register_agent(make_info("gb-failed", "linux")).has_value());
    beat(health, "gb-spark", "spark");
    beat(health, "gb-failed", "spark_failed");

    auto api = make_local_device_api(registry, nullptr, health);
    const auto rows = api->list_devices();
    REQUIRE(rows.size() == 2);
    const auto* spark = row_for(rows, "gb-spark");
    const auto* failed = row_for(rows, "gb-failed");
    REQUIRE(spark != nullptr);
    REQUIRE(failed != nullptr);
    REQUIRE(spark->guardian_backend.has_value());
    CHECK(*spark->guardian_backend == "spark");
    REQUIRE(failed->guardian_backend.has_value());
    CHECK(*failed->guardian_backend == "spark_failed");

    const auto detail = api->lookup_device("gb-failed");
    REQUIRE(detail.has_value());
    REQUIRE(detail->has_value());
    REQUIRE((*detail)->row.guardian_backend.has_value());
    CHECK(*(*detail)->row.guardian_backend == "spark_failed");
}

TEST_CASE("DeviceApi guardian_backend: no tag, no heartbeat, or a forged value is null, never legacy",
          "[device_api][guardian_backend]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;
    for (const char* id : {"gb-none", "gb-nobeat", "gb-empty", "gb-case", "gb-pad", "gb-huge",
                           "gb-ok"})
        REQUIRE(registry.register_agent(make_info(id, "linux")).has_value());
    beat(health, "gb-none", std::nullopt);   // beat without the tag (old agent / faulted group)
    // gb-nobeat: registered, never heartbeated -> not in the health store at all
    beat(health, "gb-empty", std::string{});
    beat(health, "gb-case", "Legacy");
    beat(health, "gb-pad", " legacy");
    beat(health, "gb-huge", std::string(4u * 1024u * 1024u, 'x'));
    beat(health, "gb-ok", "legacy");

    auto api = make_local_device_api(registry, nullptr, health);
    const auto rows = api->list_devices();
    REQUIRE(rows.size() == 7);
    for (const char* id : {"gb-none", "gb-nobeat", "gb-empty", "gb-case", "gb-pad", "gb-huge"}) {
        INFO("agent: " << id);
        const auto* r = row_for(rows, id);
        REQUIRE(r != nullptr);
        CHECK_FALSE(r->guardian_backend.has_value());
        const auto d = api->lookup_device(id);
        REQUIRE(d.has_value());
        REQUIRE(d->has_value());
        CHECK_FALSE((*d)->row.guardian_backend.has_value());
    }
    // The one honest legacy is the only non-null row.
    const auto* ok = row_for(rows, "gb-ok");
    REQUIRE(ok != nullptr);
    REQUIRE(ok->guardian_backend.has_value());
    CHECK(*ok->guardian_backend == "legacy");
}

TEST_CASE("DeviceApi guardian_backend: the registry is the population, the health store the attribute",
          "[device_api][guardian_backend]") {
    // An agent in the health store but not in the registry (disconnected, not yet pruned) is
    // neither listed nor found; a registered agent is listed whether or not it has a beat.
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;
    REQUIRE(registry.register_agent(make_info("gb-live", "linux")).has_value());
    beat(health, "gb-live", "unwired");
    beat(health, "gb-ghost", "legacy");

    auto api = make_local_device_api(registry, nullptr, health);
    const auto rows = api->list_devices();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].agent_id == "gb-live");
    const auto ghost = api->lookup_device("gb-ghost");
    REQUIRE(ghost.has_value());
    CHECK_FALSE(ghost->has_value());

    // HARD RULE (#2240): the registry's own JSON snapshot, which feeds the unauthenticated legacy
    // GET /api/agents and the dashboard, never carries the field. This catches an unconditional
    // key only (the fixture sets no health tag on the registered session); the lexical gate
    // tests/test_guardian_backend_wiring_lexical.py backs it for the other spellings and files.
    const auto snapshot = registry.to_json_obj();
    REQUIRE(snapshot.is_array());
    REQUIRE_FALSE(snapshot.empty());
    for (const auto& entry : snapshot)
        CHECK_FALSE(entry.contains("guardian_backend"));
}

TEST_CASE("DeviceApi basic list and connected count: same population, no backend, no health read",
          "[device_api][guardian_backend]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    AgentHealthStore health;
    auto api = make_local_device_api(registry, nullptr, health);

    // Empty fleet: both views agree, nothing to build.
    CHECK(api->list_devices_basic().empty());
    CHECK(api->connected_count() == 0);

    REQUIRE(registry.register_agent(make_info("bc-spark", "linux")).has_value());
    REQUIRE(registry.register_agent(make_info("bc-none", "windows")).has_value());
    REQUIRE(registry.register_agent(make_info("bc-ghost-free", "linux")).has_value());
    beat(health, "bc-spark", "spark");
    beat(health, "bc-orphan", "legacy"); // in the health store only: never listed or counted

    const auto full = api->list_devices();
    const auto basic = api->list_devices_basic();
    REQUIRE(full.size() == 3);
    REQUIRE(basic.size() == full.size());
    CHECK(api->connected_count() == full.size());
    for (std::size_t i = 0; i < full.size(); ++i) {
        INFO("index " << i);
        // Same rows in the same order; only the backend differs.
        CHECK(basic[i].agent_id == full[i].agent_id);
        CHECK(basic[i].hostname == full[i].hostname);
        CHECK(basic[i].os == full[i].os);
        CHECK(basic[i].arch == full[i].arch);
        CHECK(basic[i].agent_version == full[i].agent_version);
        CHECK_FALSE(basic[i].guardian_backend.has_value());
    }
    // The full list does carry the one reported token, so the basic list's null is not vacuous.
    const auto* spark = row_for(full, "bc-spark");
    REQUIRE(spark != nullptr);
    REQUIRE(spark->guardian_backend.has_value());
    CHECK(*spark->guardian_backend == "spark");
}

namespace {
// A seam implementation that only overrides list_devices(), like every route-test double.
class ListOnlyDeviceApi final : public yuzu::server::DeviceApi {
public:
    [[nodiscard]] std::vector<yuzu::server::DeviceListRow> list_devices() const override {
        yuzu::server::DeviceListRow a;
        a.agent_id = "d1";
        a.guardian_backend = "spark";
        yuzu::server::DeviceListRow b;
        b.agent_id = "d2";
        return {a, b};
    }
    [[nodiscard]] std::expected<std::optional<yuzu::server::DeviceDetail>,
                                yuzu::server::DeviceReadError>
    lookup_device(const std::string&) const override {
        return std::optional<yuzu::server::DeviceDetail>{std::nullopt};
    }
};
} // namespace

TEST_CASE("DeviceApi defaults: a list-only double gets a basic list and a count for free",
          "[device_api][guardian_backend]") {
    ListOnlyDeviceApi api;
    const auto basic = api.list_devices_basic();
    REQUIRE(basic.size() == 2);
    CHECK(basic[0].agent_id == "d1");
    CHECK_FALSE(basic[0].guardian_backend.has_value()); // cleared by the default
    CHECK(api.connected_count() == 2);
    REQUIRE(api.list_devices()[0].guardian_backend.has_value()); // the full list still has it
}

TEST_CASE("AgentHealthStore guardian_backend_for: results stay aligned across lock slices",
          "[device_api][guardian_backend]") {
    using yuzu::server::detail::kGuardianBackendSlice;
    using yuzu::server::detail::kGuardianBackendTokens;
    // Two full slices plus a ragged tail, so both slice boundaries are crossed.
    const std::size_t n = (2 * kGuardianBackendSlice) + 7;
    AgentHealthStore health;
    std::vector<std::string> ids;
    ids.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        ids.push_back("sl-" + std::to_string(i));
        // i % 5: four valid tokens, and every fifth id is NOT in the store at all.
        if (i % 5 != 4)
            beat(health, ids.back(), std::string{kGuardianBackendTokens[i % 5]});
    }
    const auto out = health.guardian_backend_for(ids, std::chrono::seconds{300});
    REQUIRE(out.size() == n);
    for (std::size_t i = 0; i < n; ++i) {
        INFO("index " << i);
        if (i % 5 == 4) {
            CHECK_FALSE(out[i].has_value());
        } else {
            REQUIRE(out[i].has_value());
            CHECK(*out[i] == kGuardianBackendTokens[i % 5]);
        }
    }
    // The ids on either side of each slice boundary are the ones a slicing bug would shift.
    for (const std::size_t edge : {kGuardianBackendSlice, 2 * kGuardianBackendSlice})
        for (const std::size_t i : {edge - 1, edge, edge + 1})
            CHECK(out[i].has_value() == (i % 5 != 4));
    // An empty list and a list shorter than one slice behave as before.
    CHECK(health.guardian_backend_for({}, std::chrono::seconds{300}).empty());
    const std::vector<std::string> two{ids[0], ids[4]};
    const auto small = health.guardian_backend_for(two, std::chrono::seconds{300});
    REQUIRE(small.size() == 2);
    CHECK(small[0].has_value());
    CHECK_FALSE(small[1].has_value());
}

TEST_CASE("AgentHealthStore guardian_backend_for: entries no writer touches stay exact under "
          "concurrent upserts and removes",
          "[device_api][guardian_backend]") {
    using yuzu::server::detail::kGuardianBackendSlice;
    using yuzu::server::detail::kGuardianBackendTokens;
    const std::size_t n = (2 * kGuardianBackendSlice) + 100;
    AgentHealthStore health;
    std::vector<std::string> ids;
    ids.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        ids.push_back("cc-" + std::to_string(i));
        beat(health, ids.back(), std::string{kGuardianBackendTokens[0]});
    }

    // The writer touches ONLY even indices (upserts, garbage values, and remove-then-re-add), so
    // every odd index must read back as exactly kGuardianBackendTokens[0] on every round: that
    // is a content assertion that does not depend on timing, and it can fail if a slice shifts
    // the alignment into a mutated neighbour (the deterministic alignment case above is what pins
    // the boundaries). An even index may be nullopt (removed), a rejected value (nullopt) or any
    // table token.
    //
    // HONEST LIMIT: in a plain build this cannot show that the lock is doing anything; the data
    // race it exists to expose is visible only to a ThreadSanitizer build.
    std::atomic<bool> stop{false};
    std::atomic<std::size_t> upserts{0};
    std::thread writer([&] {
        std::size_t k = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            const auto& id = ids[2 * ((k * 7919) % (n / 2))];
            if (k % 5 == 0)
                health.remove(id);
            else
                beat(health, id,
                     (k % 3 == 0) ? std::string{"garbage"}
                                  : std::string{kGuardianBackendTokens[k % 4]});
            upserts.fetch_add(1, std::memory_order_relaxed);
            ++k;
        }
    });
    // A REQUIRE below throws; the guard sets `stop` and joins so a failure is reported by Catch2
    // and never reaches std::terminate through a joinable std::thread destructor.
    struct JoinGuard {
        std::atomic<bool>& stop;
        std::thread& t;
        ~JoinGuard() {
            stop.store(true, std::memory_order_relaxed);
            if (t.joinable())
                t.join();
        }
    } guard{stop, writer};

    // Best-effort overlap: wait (bounded, never asserted, so a starved CI runner cannot flake)
    // for the writer to have done something before the first round.
    for (int spin = 0; spin < 100000 && upserts.load(std::memory_order_relaxed) == 0; ++spin)
        std::this_thread::yield();
    const std::size_t started_at = upserts.load(std::memory_order_relaxed);

    for (int round = 0; round < 200; ++round) {
        if (round >= 12 && upserts.load(std::memory_order_relaxed) - started_at >= 1000)
            break; // enough real overlap observed
        const auto out = health.guardian_backend_for(ids, std::chrono::seconds{300});
        REQUIRE(out.size() == n);
        for (std::size_t i = 0; i < n; ++i) {
            if (i % 2 == 1) {
                REQUIRE(out[i].has_value());
                REQUIRE(*out[i] == kGuardianBackendTokens[0]);
            } else if (out[i]) {
                const bool known = std::any_of(
                    std::begin(kGuardianBackendTokens), std::end(kGuardianBackendTokens),
                    [&](const char* t) { return *out[i] == std::string_view{t}; });
                REQUIRE(known);
            }
        }
    }
}

TEST_CASE("AgentHealthStore guardian_backend accessors: staleness uses the sweep's clock and parse",
          "[device_api][guardian_backend]") {
    AgentHealthStore health;
    beat(health, "gb-a", "spark");
    beat(health, "gb-b", "garbage");
    beat(health, "gb-c", std::nullopt);
    const std::vector<std::string> ids{"gb-a", "gb-b", "gb-c", "gb-unknown"};

    // Live window: aligned by index, only the valid token is present.
    const auto live = health.guardian_backend_for(ids, std::chrono::seconds{300});
    REQUIRE(live.size() == 4);
    REQUIRE(live[0].has_value());
    CHECK(*live[0] == "spark");
    CHECK_FALSE(live[1].has_value()); // rejected
    CHECK_FALSE(live[2].has_value()); // no tag
    CHECK_FALSE(live[3].has_value()); // unknown id
    REQUIRE(health.guardian_backend_of("gb-a", std::chrono::seconds{300}).has_value());
    CHECK(*health.guardian_backend_of("gb-a", std::chrono::seconds{300}) == "spark");
    CHECK_FALSE(health.guardian_backend_of("gb-b", std::chrono::seconds{300}).has_value());
    CHECK_FALSE(health.guardian_backend_of("gb-unknown", std::chrono::seconds{300}).has_value());

    // The sweep prunes only every 15 s, so the accessor filters by age itself: a zero window
    // makes every entry stale (the same predicate recompute_metrics prunes by).
    const auto stale = health.guardian_backend_for(ids, std::chrono::seconds{0});
    for (const auto& v : stale)
        CHECK_FALSE(v.has_value());
    CHECK_FALSE(health.guardian_backend_of("gb-a", std::chrono::seconds{0}).has_value());

    // The returned view points into the constexpr token table, not into the store, so it
    // survives the store's mutation and the mutex release.
    const auto token = *health.guardian_backend_of("gb-a", std::chrono::seconds{300});
    beat(health, "gb-a", "legacy");
    CHECK(token == "spark");
    CHECK(yuzu::server::detail::guardian_backend_token_view(
              yuzu::server::detail::kGuardianBackendIdxSpark) == token);
    // Pointer identity, not just equality: a view into the store's status_tags would still read
    // "spark" after the mutation above unless a sanitizer is watching the freed node.
    CHECK(token.data() ==
          yuzu::server::detail::kGuardianBackendTokens[yuzu::server::detail::kGuardianBackendIdxSpark]);
}
