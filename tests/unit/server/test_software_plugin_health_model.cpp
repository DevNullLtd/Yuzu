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

TEST_CASE("plugin_health_json: duration and bytes distributions keep p50, p95 and max apart",
          "[software_plugin_health][model]") {
    // Six distinct values, so a swap of any two columns in the model or in the store's in-order
    // parse is a red test. A non-zero delta count also pins the "delta" status key.
    FacetHealth a = make("installed_software.dpkg", {{"full", 3}, {"delta", 4}});
    a.duration_ms_p50 = 11;
    a.duration_ms_p95 = 22;
    a.duration_ms_max = 33;
    a.bytes_read_p50 = 4400;
    a.bytes_read_p95 = 5500;
    a.bytes_read_max = 6600;

    const auto j = sph::plugin_health_json({a}, {}, 1, "");
    const auto& f = j["facets"][0];
    CHECK(f["devices"]["delta"] == 4);
    CHECK(f["collecting"] == 7);
    CHECK(f["duration_ms"]["p50"] == 11);
    CHECK(f["duration_ms"]["p95"] == 22);
    CHECK(f["duration_ms"]["max"] == 33);
    CHECK(f["bytes_read"]["p50"] == 4400);
    CHECK(f["bytes_read"]["p95"] == 5500);
    CHECK(f["bytes_read"]["max"] == 6600);
}

TEST_CASE("publish_facet_health_gauges: a facet absent from the next sweep goes absent",
          "[software_plugin_health][model]") {
    yuzu::MetricsRegistry m;
    FacetHealth a = make("installed_software.dpkg", {{"timeout", 3}});
    FacetHealth b = make("installed_software.rpm", {{"full", 2}});
    sph::publish_facet_health_gauges(m, {a, b});
    REQUIRE(m.serialize().find("installed_software.dpkg") != std::string::npos);

    sph::publish_facet_health_gauges(m, {b});
    const auto text = m.serialize();
    CHECK(text.find("installed_software.dpkg") == std::string::npos);
    CHECK(text.find("yuzu_software_facet_devices{facet=\"installed_software.rpm\","
                    "status=\"full\"} 2") != std::string::npos);
}
