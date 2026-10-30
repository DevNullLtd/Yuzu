/**
 * @file test_developer_render.cpp
 * @brief Pure tests for the System > Developer and API renderers
 *        (developer_render.{hpp,cpp}). Fixture JSON in, HTML out: no registry,
 *        no store, no route.
 */

#include "developer_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>

using namespace yuzu::server::developer;
using nlohmann::json;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

json routes_fixture() {
    return json{{"count", 3},
                {"routes",
                 json::array({
                     {{"method", "GET"},
                      {"path", "/api/v1/devices"},
                      {"summary", "List devices"},
                      {"tags", json::array({"Devices"})},
                      {"description", "SECRET-RBAC-TEXT Requires Inventory:Read"}},
                     {{"method", "POST"},
                      {"path", "/api/v1/scope/preview"},
                      {"summary", "Preview a scope"},
                      {"tags", json::array({"Scope"})},
                      {"description", ""}},
                     {{"method", "PUT"},
                      {"path", "/api/v1/tags"},
                      {"summary", "Set <img src=x onerror=1>"},
                      {"tags", json::array()},
                      {"description", ""}},
                 })}};
}

} // namespace

TEST_CASE("developer api panel: live count, never a hard-coded number, 0 is unavailable",
          "[developer][render]") {
    const auto ok = render_api_panel(245);
    CHECK(has(ok, "Operations documented in OpenAPI"));
    CHECK(has(ok, "<b>245</b>"));
    CHECK(has(ok, "/api/v1/openapi.json"));
    CHECK(has(ok, "maintained by hand"));
    CHECK_FALSE(has(ok, "184")); // no MCP tool count
    CHECK_FALSE(has(ok, "could not be read"));

    const auto bad = render_api_panel(0);
    CHECK(has(bad, "Unavailable"));
    CHECK(has(bad, "The route catalogue could not be read."));
    CHECK_FALSE(has(bad, "<b>0</b>")); // count 0 must not read as "no routes"
}

TEST_CASE("developer routes table: rows, summary line, tags, no description", "[developer][render]") {
    const auto html = render_routes_table(routes_fixture(), "");
    CHECK(has(html, "/api/v1/devices"));
    CHECK(has(html, "List devices"));
    CHECK(has(html, "<span class=\"pill info\">Devices</span>"));
    CHECK_FALSE(has(html, "SECRET-RBAC-TEXT")); // description is free text, never rendered
    CHECK(has(html, "REST v1 only"));
}

TEST_CASE("developer routes table: escapes agent/document text and filters case-insensitively",
          "[developer][render][security]") {
    const auto all = render_routes_table(routes_fixture(), "");
    CHECK_FALSE(has(all, "<img src=x"));
    CHECK(has(all, "&lt;img src=x onerror=1&gt;"));

    const auto some = render_routes_table(routes_fixture(), "PREVIEW");
    CHECK(has(some, "/api/v1/scope/preview"));
    CHECK_FALSE(has(some, "/api/v1/devices"));

    // The echoed filter is escaped.
    const auto none = render_routes_table(routes_fixture(), "<b>zzz");
    CHECK(has(none, "No operation matches"));
    CHECK_FALSE(has(none, "<b>zzz"));
    CHECK(has(none, "&lt;b&gt;zzz"));
}

TEST_CASE("developer routes table: an unserved operation keeps its row and is marked unavailable",
          "[developer][render]") {
    const json doc{{"count", 2},
                   {"routes",
                    json::array({
                        {{"method", "GET"},
                         {"path", "/api/v1/devices"},
                         {"summary", "List devices"},
                         {"tags", json::array({"Devices"})}},
                        {{"method", "GET"},
                         {"path", "/api/v1/licenses"},
                         {"summary", "List <b>licenses</b>"},
                         {"tags", json::array({"License"})},
                         {"unavailable", "not registered: <i>license store</i> not wired"}},
                    })}};
    const auto html = render_routes_table(doc, "");
    // The row stays (the catalogue count is unchanged) and carries the marker, escaped.
    CHECK(has(html, "/api/v1/licenses"));
    CHECK(has(html, "<span class=\"pill warn\">unavailable</span>"));
    CHECK(has(html, "not registered: &lt;i&gt;license store&lt;/i&gt; not wired"));
    CHECK_FALSE(has(html, "<i>license store"));
    // Exactly one marker: the served row has none.
    const auto first = html.find("<span class=\"pill warn\">unavailable</span>");
    REQUIRE(first != std::string::npos);
    CHECK(html.find("<span class=\"pill warn\">unavailable</span>", first + 1) == std::string::npos);
    CHECK(html.find("/api/v1/devices") < first);

    // An empty marker string is not a marker.
    json blank = doc;
    blank["routes"][1]["unavailable"] = "";
    CHECK_FALSE(has(render_routes_table(blank, ""), "pill warn"));
}

TEST_CASE("developer api panel: links the API reference page beside the raw document",
          "[developer][render]") {
    const auto ok = render_api_panel(245);
    CHECK(has(ok, "href=\"/swagger\""));
    CHECK(has(ok, "Open API reference"));
    CHECK(has(ok, "href=\"/api/v1/openapi.json\""));
    CHECK(has(ok, "Open OpenAPI document"));
    // New-tab links to a same-origin page still carry rel=noopener.
    CHECK(has(ok, "href=\"/swagger\" target=\"_blank\" rel=\"noopener\""));
    // The link does not depend on the catalogue being readable.
    CHECK(has(render_api_panel(0), "href=\"/swagger\""));
}

TEST_CASE("developer routes table: cap banner and degraded catalogue", "[developer][render]") {
    json rows = json::array();
    for (std::size_t i = 0; i < kRoutesCap + 5; ++i)
        rows.push_back({{"method", "GET"}, {"path", "/api/v1/r" + std::to_string(i)},
                        {"summary", ""}, {"tags", json::array()}});
    const json big{{"count", rows.size()}, {"routes", rows}};
    const auto html = render_routes_table(big, "");
    CHECK(has(html, "Showing 300 of 305. Narrow the filter."));
    CHECK(has(html, "/api/v1/r299"));
    CHECK_FALSE(has(html, "/api/v1/r300"));

    // count 0 with HTTP 200 is how build_routes_catalog reports a parse failure.
    const auto bad = render_routes_table(json{{"count", 0}, {"routes", json::array()}}, "");
    CHECK(has(bad, "could not be read"));
    CHECK(has(render_routes_table(json(), ""), "could not be read"));
}

TEST_CASE("clean_filter bounds length and strips control characters", "[developer][render]") {
    CHECK(clean_filter(std::string(500, 'a')).size() == kFilterMaxLen);
    CHECK(clean_filter(std::string("a\nb\tc")) == "a b c");
}

namespace {
json perms_fixture() {
    return json{{"securable_types", json::array({"Execution", "Policy"})},
                {"operations", json::array({"Read", "Execute"})},
                {"roles",
                 json::array({
                     {{"name", "Administrator"},
                      {"permissions", json::array({
                                          {{"securable_type", "Execution"}, {"operation", "Execute"}, {"effect", "allow"}},
                                          {{"securable_type", "Policy"}, {"operation", "Read"}, {"effect", "allow"}},
                                      })}},
                     {{"name", "Viewer<x>"},
                      {"permissions", json::array({
                                          {{"securable_type", "Policy"}, {"operation", "Read"}, {"effect", "allow"}},
                                          {{"securable_type", "Execution"}, {"operation", "Execute"}, {"effect", "deny"}},
                                      })}},
                 })}};
}
} // namespace

TEST_CASE("developer permissions table: Securable:Operation with the roles that allow it",
          "[developer][render]") {
    const auto html = render_permissions_table(perms_fixture(), "");
    CHECK(has(html, "2 securable types, 2 operations"));
    CHECK(has(html, "<td class=\"mono\">Execution:Execute</td><td>Administrator</td>"));
    // Document order of roles, escaped.
    CHECK(has(html, "<td class=\"mono\">Policy:Read</td><td>Administrator, Viewer&lt;x&gt;</td>"));
    // A pair no role allows is not listed; a denied pair is not "used by".
    CHECK_FALSE(has(html, "Execution:Read"));
    CHECK_FALSE(has(html, "Policy:Execute"));
    CHECK(has(html, "RBAC enforcement"));
    // The artboard's invented names must not appear.
    CHECK_FALSE(has(html, "instruction.execute"));
}

TEST_CASE("developer permissions table: roles_omitted is a denied note, not an empty table",
          "[developer][render]") {
    json doc = perms_fixture();
    doc.erase("roles");
    doc["roles_omitted"] = true;
    const auto html = render_permissions_table(doc, "");
    CHECK(has(html, "2 securable types, 2 operations")); // taxonomy counts still shown
    CHECK(has(html, "data-state=\"denied\""));
    CHECK(has(html, "UserManagement:Read"));
    CHECK_FALSE(has(html, "<table"));
}

TEST_CASE("developer permissions table: filter and unreadable catalogue", "[developer][render]") {
    const auto some = render_permissions_table(perms_fixture(), "polic");
    CHECK(has(some, "Policy:Read"));
    CHECK_FALSE(has(some, "Execution:Execute"));
    CHECK(has(render_permissions_table(perms_fixture(), "nomatch"), "No permission matches"));
    CHECK(has(render_permissions_table(json(), ""), "This is not an empty list."));
}

namespace {
json docs_fixture() {
    return json{{"skipped_invalid", 0},
                {"plugins",
                 json::array({
                     {{"name", "chargen"},
                      {"description", "Streams <b>test</b> text"},
                      {"kind", {{"collector", false}, {"gathered", true}, {"mutating", true}}},
                      {"platforms", {{"linux", "supported"}, {"macos", "constrained"}, {"windows", "planned"}}}},
                     {{"name", "weird"},
                      {"description", ""},
                      {"kind", {{"collector", true}, {"gathered", true}, {"mutating", false}}},
                      {"platforms", {{"linux", "mystery"}}}},
                 })}};
}
} // namespace

TEST_CASE("developer plugins table: three fixed OS names with the manifest value in words",
          "[developer][render]") {
    const auto html = render_plugins_table(docs_fixture());
    CHECK(has(html, "Linux supported, macOS constrained, Windows planned"));
    // An unknown or missing value reads "unknown", never blank.
    CHECK(has(html, "Linux unknown, macOS unknown, Windows unknown"));
    CHECK(has(html, "Changes devices"));
    CHECK(has(html, "Collector"));
    CHECK(has(html, "&lt;b&gt;test&lt;/b&gt;")); // manifest text escaped
    CHECK(has(html, "href=\"/api/v1/discover/plugin-docs/chargen\""));
    CHECK(has(html, "hx-get=\"/fragments/settings/developer/plugins/observed\""));
}

TEST_CASE("developer plugins table: skipped manifests are shown, unreadable catalogue fails",
          "[developer][render]") {
    json d = docs_fixture();
    d["skipped_invalid"] = 2;
    CHECK(has(render_plugins_table(d), "2 plugin manifests in this build could not be read."));
    CHECK(has(render_plugins_table(json()), "could not be read"));
}

TEST_CASE("developer observed plugins: link only names in the compiled catalogue",
          "[developer][render][security]") {
    const json observed{{"plugins", json::array({
                                        {{"name", "chargen"}},
                                        {{"name", "../../etc/passwd"}},
                                        {{"name", "<script>alert(1)</script>"}},
                                        {{"name", "chargen"}}, // duplicate collapses
                                    })}};
    const auto html = render_observed_plugins(observed, docs_fixture());
    CHECK(has(html, "href=\"/api/v1/discover/plugin-docs/chargen\""));
    CHECK_FALSE(has(html, "plugin-docs/..")); // agent-reported text is never a path
    CHECK_FALSE(has(html, "<script>"));
    CHECK(has(html, "&lt;script&gt;"));
    CHECK(has(html, "No manifest"));
    std::size_t n = 0;
    for (auto p = html.find("chargen</td>"); p != std::string::npos; p = html.find("chargen</td>", p + 1))
        ++n;
    CHECK(n == 1);
}

TEST_CASE("developer observed plugins: no device is not 'no plugins exist'", "[developer][render]") {
    const auto html = render_observed_plugins(json{{"plugins", json::array()}}, docs_fixture());
    CHECK(has(html, "No device is connected, so no plugins are being reported."));
    CHECK(has(html, "documented in this build are listed above"));
    CHECK(has(render_observed_plugins(json(), docs_fixture()), "could not be read"));
}
