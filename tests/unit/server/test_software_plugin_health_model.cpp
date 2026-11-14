#include <catch2/catch_test_macros.hpp>

#include "software_plugin_health_model.hpp"

#include <yuzu/metrics.hpp>

using namespace yuzu::server;
namespace sph = yuzu::server::software_plugin_health;

namespace {
FacetHealth make(std::string facet, std::map<std::string, std::int64_t> by) {
    FacetHealth h;
    h.facet = std::move(facet);
    h.devices_by_status = std::move(by);
    return h;
}
} // namespace

TEST_CASE("plugin_health_json: shares, plugin name and null denominators",
          "[software_plugin_health][model]") {
    FacetHealth a = make("installed_software.dpkg", {{"full", 6}, {"timeout", 2}, {"constrained", 1},
                                                      {"oversize", 1}, {"not_collected", 10}});
    a.slowest.push_back({"agent-1", 900});
    a.slowest.push_back({"agent-2", 800});
    const FacetHealth empty = make("component_inventory", {});

    const auto j = sph::plugin_health_json({a, empty}, {{"agent-1", "host-1"}}, 1234, "");
    REQUIRE(j["as_of"] == 1234);
    REQUIRE(j["omitted"].is_null());
    const auto& f0 = j["facets"][0];
    CHECK(f0["plugin"] == "installed_software");
    CHECK(f0["collecting"] == 10);
    CHECK(f0["timeout_share"].get<double>() == 0.2);
    CHECK(f0["failing_share"].get<double>() == 0.4);
    CHECK(f0["not_collected_share"].get<double>() == 0.5);
    CHECK(f0["disabled_share"].get<double>() == 0.0);
    CHECK(f0["devices"]["delta"] == 0);
    CHECK(f0["slowest"][0]["hostname"] == "host-1");
    CHECK(f0["slowest"][1]["hostname"].is_null());

    const auto& f1 = j["facets"][1];
    CHECK(f1["plugin"] == "component_inventory");
    CHECK(f1["collecting"] == 0);
    CHECK(f1["timeout_share"].is_null());
    CHECK(f1["failing_share"].is_null());
    CHECK(f1["disabled_share"].is_null());
    CHECK(f1["not_collected_share"].is_null());
}

TEST_CASE("plugin_health_json: omitted reason is carried", "[software_plugin_health][model]") {
    const auto j = sph::plugin_health_json({}, {}, 5, "scope");
    CHECK(j["omitted"] == "scope");
    CHECK(j["facets"].empty());
}

TEST_CASE("publish_facet_health_gauges: all seven statuses, zeros included, no agent label",
          "[software_plugin_health][model]") {
    yuzu::MetricsRegistry m;
    FacetHealth a = make("installed_software.dpkg", {{"timeout", 3}});
    a.duration_ms_p50 = 40;
    a.duration_ms_p95 = 90;
    a.slowest.push_back({"agent-secret", 90});
    sph::publish_facet_health_gauges(m, {a});

    const auto text = m.serialize();
    for (const auto st : kV3AllStatuses) {
        CHECK(text.find(std::string("yuzu_software_facet_devices{facet=\"installed_software.dpkg\","
                                    "status=\"") +
                        std::string(v3_status_name(st)) + "\"}") != std::string::npos);
    }
    CHECK(text.find("status=\"timeout\"} 3") != std::string::npos);
    CHECK(text.find("status=\"full\"} 0") != std::string::npos);
    CHECK(text.find("quantile=\"0.5\"} 40") != std::string::npos);
    CHECK(text.find("quantile=\"0.95\"} 90") != std::string::npos);
    CHECK(text.find("agent-secret") == std::string::npos);
}
