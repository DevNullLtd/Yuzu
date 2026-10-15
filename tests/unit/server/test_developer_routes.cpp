/**
 * @file test_developer_routes.cpp
 * @brief Route tests for System > Developer and API (developer_routes.{hpp,cpp}):
 *        the page gate, the per-fragment Infrastructure:Read gate, the
 *        no-store header, and the degraded states. In-process TestRouteSink;
 *        no socket. Only the [pg]-tagged permissions cases need Postgres (an
 *        open RbacStore); the rest run without it.
 */

#include "developer_routes.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>

using namespace yuzu::server;

namespace {

struct DeveloperHarness {
    yuzu::server::test::TestRouteSink sink;
    bool allow_admin{true};
    bool allow_perm{true};
    bool deny_user_mgmt{false}; ///< deny only the UserManagement:Read grid probe
    std::string last_securable, last_operation;
    int perm_calls{0};  ///< auditing gate calls (perm_fn)
    int probe_calls{0}; ///< non-auditing probe calls (probe_fn)
    int admin_calls{0};

    // A real (empty) registry: build_plugins_catalog only reads help_json().
    detail::EventBus bus;
    yuzu::MetricsRegistry metrics;
    detail::AgentRegistry registry{bus, metrics};

    explicit DeveloperHarness(bool with_registry = true, RbacStore* rbac = nullptr,
                              bool with_probe = true) {
        developer::Deps deps;
        deps.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
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
        if (with_probe) {
            deps.probe_fn = [this](const httplib::Request&, const std::string& s,
                                   const std::string& o) {
                ++probe_calls;
                last_securable = s;
                last_operation = o;
                return !(deny_user_mgmt && s == "UserManagement");
            };
        }
        deps.rbac_store = rbac;
        deps.registry = with_registry ? &registry : nullptr;
        developer::register_developer_routes(sink, std::move(deps));
    }
};

// Pre-migrated RbacStore template; shares the "rbacstore" key with
// test_rbac_store.cpp and test_discovery_routes.cpp (identical setup).
yuzu::test::PgTestTemplate developer_rbac_tpl{
    "rbacstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac template: store failed to migrate/seed");
    }};

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

TEST_CASE("developer fragments gate on admin then Infrastructure:Read and answer no-store",
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

        // Infrastructure:Read alone is not enough: a caller the admin gate refuses (the RBAC-off
        // default admits any authenticated caller to the flat Read gate) gets nothing, and the
        // Read gate and every builder behind it are never reached.
        DeveloperHarness n;
        n.allow_admin = false;
        auto not_admin = n.sink.Get(path);
        REQUIRE(not_admin);
        CHECK(not_admin->status == 403);
        CHECK(n.admin_calls == 1);
        CHECK(n.perm_calls == 0);
        CHECK(n.probe_calls == 0);
        CHECK_FALSE(has(not_admin->body, "<table"));

        DeveloperHarness d;
        d.allow_perm = false;
        auto denied = d.sink.Get(path);
        REQUIRE(denied);
        CHECK(denied->status == 403);
        CHECK(d.perm_calls == 1); // gate first; no probe, no work for a denied caller
        CHECK(d.probe_calls == 0);
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
    CHECK(h.probe_calls == 0);
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

TEST_CASE("developer permissions fragment: live RBAC catalogue with the role grid",
          "[developer][routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, developer_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());

    DeveloperHarness h(/*with_registry=*/true, &rbac);
    auto r = h.sink.Get("/fragments/settings/developer/permissions");
    REQUIRE(r);
    CHECK(r->status == 200);
    // The Infrastructure:Read gate audits; the grid's UserManagement:Read check is the
    // non-auditing probe, so a denied caller leaves no denial row per page load.
    CHECK(h.perm_calls == 1);
    CHECK(h.probe_calls == 1);
    CHECK(h.last_securable == "UserManagement");
    CHECK(has(r->body, "<table"));
    CHECK(has(r->body, "Administrator")); // a seeded role, from the live store
    CHECK(has(r->body, "Infrastructure:Read"));
    CHECK_FALSE(has(r->body, "could not be read"));
}

TEST_CASE("developer permissions fragment: denied UserManagement:Read keeps the taxonomy, drops the grid",
          "[developer][routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, developer_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());

    DeveloperHarness h(/*with_registry=*/true, &rbac);
    h.deny_user_mgmt = true;
    auto r = h.sink.Get("/fragments/settings/developer/permissions");
    REQUIRE(r);
    CHECK(r->status == 200); // the probe denial never 403s the fragment
    CHECK(has(r->body, "securable types"));
    CHECK(has(r->body, "UserManagement:Read"));
    CHECK_FALSE(has(r->body, "<table"));
    CHECK_FALSE(has(r->body, "Administrator"));
    CHECK(h.perm_calls == 1); // the denial went to the probe, never the auditing gate
    CHECK(h.probe_calls == 1);
}

TEST_CASE("developer permissions fragment: no probe wired withholds the grid",
          "[developer][routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, developer_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());

    DeveloperHarness h(/*with_registry=*/true, &rbac, /*with_probe=*/false);
    auto r = h.sink.Get("/fragments/settings/developer/permissions");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_FALSE(has(r->body, "<table"));
    CHECK_FALSE(has(r->body, "Administrator"));
}
