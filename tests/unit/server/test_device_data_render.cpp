/// @file test_device_data_render.cpp
/// Pure-renderer tests for the Hardware record's custom-properties and property-schema
/// panels (device_data_render.hpp). No httplib, no store.

#include "device_data_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuDeviceDataJs; // static/yuzu-device-data.js (build-time embed)
}

using namespace yuzu::server::device_data;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

PropertiesView base_view() {
    PropertiesView v;
    v.agent_id = "agent-1";
    v.properties = std::vector<PropertyRow>{};
    v.schemas = std::vector<SchemaRow>{};
    return v;
}

constexpr const char* kPlanted = "<img src=x onerror=1>";

} // namespace

TEST_CASE("device data render: empty properties and empty schemas are explicit rather than blank",
          "[device_data][render]") {
    const auto html = render_properties_panels(base_view());
    CHECK(contains(html, "No properties set."));
    CHECK(contains(html, "No schemas defined."));
    CHECK(contains(html, "Schemas apply to every device."));
    // Read-only viewer: no mutation control at all.
    CHECK_FALSE(contains(html, "data-act="));
}

TEST_CASE("device data render: a degraded read is a banner and never the empty note",
          "[device_data][render]") {
    PropertiesView v = base_view();
    v.properties = Unavailable{};
    v.schemas = Unavailable{};
    v.can_write_properties = true;
    v.can_write_schemas = true;
    const auto html = render_properties_panels(v);
    CHECK(contains(html, "Custom properties could not be read."));
    CHECK(contains(html, "Property schemas could not be read."));
    CHECK_FALSE(contains(html, "No properties set."));
    CHECK_FALSE(contains(html, "No schemas defined."));
    // Write controls are withheld when the list they would edit could not be read.
    CHECK_FALSE(contains(html, "data-act="));
}

TEST_CASE("device data render: a denied read names the grant and offers no control",
          "[device_data][render]") {
    PropertiesView v = base_view();
    v.properties = Denied{};
    v.schemas = Denied{};
    v.can_write_properties = true;
    v.can_write_schemas = true;
    const auto html = render_properties_panels(v);
    CHECK(contains(html, "<b>Infrastructure:Read</b> permission for this device"));
    CHECK(contains(html, "fleet-wide <b>Infrastructure:Read</b> grant"));
    CHECK_FALSE(contains(html, "data-act="));
    CHECK_FALSE(contains(html, "No properties set."));
}

TEST_CASE("device data render: write controls appear only for a writer with escaped data attributes",
          "[device_data][render]") {
    PropertiesView v = base_view();
    v.properties = std::vector<PropertyRow>{{"owner", kPlanted, "string", 1700000000}};
    v.schemas = std::vector<SchemaRow>{{"owner", "Owner <b>", "string", kPlanted, "^[a-z]+$"}};

    const auto read_only = render_properties_panels(v);
    CHECK_FALSE(contains(read_only, "data-act="));
    CHECK(contains(read_only, "Owner &lt;b&gt;")); // schema display name labels the row

    v.can_write_properties = true;
    v.can_write_schemas = true;
    const auto html = render_properties_panels(v);
    CHECK(contains(html, "data-act=\"prop-add\""));
    CHECK(contains(html, "data-act=\"prop-set\""));
    CHECK(contains(html, "data-act=\"prop-delete\""));
    CHECK(contains(html, "data-act=\"schema-save\""));
    CHECK(contains(html, "data-schema-type=\"string\""));
    CHECK(contains(html, "data-schema-key=\"owner\""));
    CHECK(contains(html, "2023-11-14T22:13:20Z"));
}

TEST_CASE("device data render: every operator and agent string is escaped and no inline handler",
          "[device_data][render]") {
    PropertiesView v = base_view();
    v.agent_id = "a\"><script>1</script>";
    v.properties = std::vector<PropertyRow>{{"k<k>", kPlanted, "str<>", 1}};
    v.schemas = std::vector<SchemaRow>{{"s\"x", kPlanted, kPlanted, kPlanted, kPlanted}};
    v.can_write_properties = true;
    v.can_write_schemas = true;
    const auto html = render_properties_panels(v);
    CHECK_FALSE(contains(html, "<img"));
    CHECK_FALSE(contains(html, "<script"));
    CHECK_FALSE(contains(html, "onclick"));
    CHECK_FALSE(contains(html, "hx-on"));
    CHECK(contains(html, "&lt;img src=x onerror=1&gt;"));
}

// Bundle pin: the delegated listener is the only entry point and no server string can
// reach a markup or code sink. Kills: an innerHTML write or a second listener per control.
TEST_CASE("device data js: one delegated listener, no markup or dynamic-code sink",
          "[device_data][js]") {
    const auto& js = yuzu::server::kYuzuDeviceDataJs;
    REQUIRE(js.size() > 2000);
    for (const char* sink : {"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function(",
                             "document.write", "hx-on", "window.confirm"})
        CHECK_FALSE(contains(js, sink));
    CHECK(contains(js, "data-act"));
    CHECK(contains(js, "document.addEventListener('click'"));
    // Exactly one document-level listener.
    CHECK(js.find("addEventListener('click'") == js.rfind("addEventListener('click'"));
    // Path segments are encoded and the property key regex matches the server's.
    CHECK(contains(js, "'/api/agents/' + enc(agent) + '/properties/' + enc(key)"));
    CHECK(contains(js, "/^[A-Za-z0-9_.:-]{1,64}$/"));
    // These routes ignore the audit result (A2): no audit-failed banner here.
    CHECK_FALSE(contains(js, "auditFailed"));
}
