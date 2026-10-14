/**
 * @file test_developer_routes.cpp
 * @brief Route tests for System > Developer and API (developer_routes.{hpp,cpp}):
 *        the page gate, the per-fragment Infrastructure:Read gate, the
 *        no-store header, and the null-store degraded states. In-process
 *        TestRouteSink; no socket, no Postgres.
 */

#include "developer_routes.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

namespace {

struct DeveloperHarness {
    yuzu::server::test::TestRouteSink sink;
    bool allow_admin{true};
    bool allow_perm{true};
    std::string last_securable, last_operation;
    int perm_calls{0};

    // A real (empty) registry: build_plugins_catalog only reads help_json().
    detail::EventBus bus;
    yuzu::MetricsRegistry metrics;
    detail::AgentRegistry registry{bus, metrics};

    explicit DeveloperHarness(bool with_registry = true) {
        developer::Deps deps;
        deps.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (allow_admin)
                return true;
            res.status = 403;
            return false;
        };
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& s, const std::string& o) {
            ++perm_calls;
            last_securable = s;
            last_operation = o;
            if (allow_perm)
                return true;
            res.status = 403;
            res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
            return false;
        };
        deps.rbac_store = nullptr;
        deps.registry = with_registry ? &registry : nullptr;
        developer::register_developer_routes(sink, std::move(deps));
    }
};

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("developer page: admin gets the page, a non-admin is redirected away",
          "[developer][routes]") {
    DeveloperHarness h;
    auto ok = h.sink.Get("/settings/developer");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(has(ok->body, "Developer and API"));
    // Four loaders, one per fragment; no dispatch panel on this page.
    CHECK(has(ok->body, "hx-get=\"/fragments/settings/developer/api\""));
    CHECK(has(ok->body, "hx-get=\"/fragments/settings/developer/routes\""));
    CHECK(has(ok->body, "hx-get=\"/fragments/settings/developer/permissions\""));
    CHECK(has(ok->body, "hx-get=\"/fragments/settings/developer/plugins\""));
    CHECK_FALSE(has(ok->body, "/api/command"));
    CHECK_FALSE(has(ok->body, "/events"));

    h.allow_admin = false;
    auto denied = h.sink.Get("/settings/developer");
    REQUIRE(denied);
    CHECK(denied->status != 200);
    CHECK_FALSE(has(denied->body, "Developer and API"));
}

TEST_CASE("developer page template: no inline handlers, hx-on, eval or innerHTML of data",
          "[developer][routes][security]") {
    DeveloperHarness h;
    const auto body = h.sink.Get("/settings/developer")->body;
    CHECK_FALSE(has(body, "hx-on"));
    CHECK_FALSE(has(body, " onclick="));
    CHECK_FALSE(has(body, "eval("));
    CHECK_FALSE(has(body, "new Function"));
    CHECK_FALSE(has(body, ".innerHTML"));
    CHECK_FALSE(has(body, "unsafe-eval"));
}

TEST_CASE("developer fragments gate on Infrastructure:Read and answer no-store",
          "[developer][routes]") {
    const char* kPaths[] = {
        "/fragments/settings/developer/api",
        "/fragments/settings/developer/routes",
        "/fragments/settings/developer/permissions",
        "/fragments/settings/developer/plugins",
        "/fragments/settings/developer/plugins/observed",
    };
    for (const char* path : kPaths) {
        INFO(path);
        DeveloperHarness h;
        auto ok = h.sink.Get(path);
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(h.last_securable == "Infrastructure");
        CHECK(h.last_operation == "Read");
        CHECK(ok->get_header_value("Cache-Control") == "no-store");

        DeveloperHarness d;
        d.allow_perm = false;
        auto denied = d.sink.Get(path);
        REQUIRE(denied);
        CHECK(denied->status == 403);
        CHECK(d.perm_calls == 1); // gate first; no probe, no work for a denied caller
    }
}

TEST_CASE("developer routes fragment: real OpenAPI catalogue, filter echoed escaped",
          "[developer][routes]") {
    DeveloperHarness h;
    auto all = h.sink.Get("/fragments/settings/developer/routes");
    REQUIRE(all);
    CHECK(has(all->body, "/api/v1/"));
    CHECK_FALSE(has(all->body, "could not be read"));

    auto none = h.sink.Get("/fragments/settings/developer/routes?q=%3Cimg%20src%3Dx%3E");
    REQUIRE(none);
    CHECK(has(none->body, "No operation matches"));
    CHECK_FALSE(has(none->body, "<img src=x>"));
}

TEST_CASE("developer api fragment: live count from the shared builder", "[developer][routes]") {
    DeveloperHarness h;
    auto r = h.sink.Get("/fragments/settings/developer/api");
    REQUIRE(r);
    CHECK(has(r->body, "Operations documented in OpenAPI"));
    CHECK_FALSE(has(r->body, "Unavailable"));
}

TEST_CASE("developer permissions fragment: unavailable store is a fixed sentence, not empty",
          "[developer][routes]") {
    DeveloperHarness h; // rbac_store is null
    auto r = h.sink.Get("/fragments/settings/developer/permissions");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(has(r->body, "could not be read. This is not an empty list."));
    CHECK_FALSE(has(r->body, "<table"));
    CHECK(h.perm_calls == 1); // never reaches the UserManagement:Read probe
}

TEST_CASE("developer plugins fragments: build-embedded list needs no registry; observed degrades",
          "[developer][routes]") {
    DeveloperHarness h(/*with_registry=*/false);
    auto docs = h.sink.Get("/fragments/settings/developer/plugins");
    REQUIRE(docs);
    CHECK(docs->status == 200);
    CHECK(has(docs->body, "Manifest (JSON)"));

    auto observed = h.sink.Get("/fragments/settings/developer/plugins/observed");
    REQUIRE(observed);
    CHECK(observed->status == 200);
    CHECK(has(observed->body, "could not be read"));

    // With a registry and no connected device: a fixed "no device" sentence.
    DeveloperHarness w;
    auto empty = w.sink.Get("/fragments/settings/developer/plugins/observed");
    REQUIRE(empty);
    CHECK(has(empty->body, "No device is connected"));
}
