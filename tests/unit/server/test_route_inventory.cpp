/**
 * test_route_inventory.cpp — `HttplibRouteSink` records every registration in
 * `RouteInventory`, keyed by the wrapped `httplib::Server`
 * (server/core/src/route_inventory.hpp, http_route_sink.hpp).
 *
 * A bare `httplib::Server` is constructed and never listens: no port, no thread (#438).
 */

#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/route_inventory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

using yuzu::server::HttplibRouteSink;
using yuzu::server::RouteInventory;

namespace {

const httplib::Server::Handler kNoop = [](const httplib::Request&, httplib::Response&) {};

bool has(const std::vector<RouteInventory::Route>& routes, const std::string& method,
         const std::string& pattern) {
    return std::find(routes.begin(), routes.end(), RouteInventory::Route{method, pattern}) !=
           routes.end();
}

} // namespace

TEST_CASE("route inventory: a sink records the method and the exact pattern of every verb",
          "[routeinv]") {
    httplib::Server svr;
    RouteInventory::instance().forget(&svr);
    HttplibRouteSink sink(svr);
    sink.Get("/yuzu_test_get", kNoop);
    sink.Post(R"(/yuzu_test/([^/]+)/post)", kNoop);
    sink.Put("/yuzu_test_put", kNoop);
    sink.Delete("/yuzu_test_delete", kNoop);
    sink.Patch("/yuzu_test_patch", kNoop);
    sink.Options("/yuzu_test_options", kNoop);

    const auto routes = RouteInventory::instance().routes_for(&svr);
    CHECK(routes.size() == 6);
    CHECK(has(routes, "GET", "/yuzu_test_get"));
    CHECK(has(routes, "POST", R"(/yuzu_test/([^/]+)/post)"));
    CHECK(has(routes, "PUT", "/yuzu_test_put"));
    CHECK(has(routes, "DELETE", "/yuzu_test_delete"));
    CHECK(has(routes, "PATCH", "/yuzu_test_patch"));
    CHECK(has(routes, "OPTIONS", "/yuzu_test_options"));
    RouteInventory::instance().forget(&svr);
}

TEST_CASE("route inventory: registrations are keyed by server and de-duplicated", "[routeinv]") {
    httplib::Server a;
    httplib::Server b;
    RouteInventory::instance().forget(&a);
    RouteInventory::instance().forget(&b);
    HttplibRouteSink sink_a(a);
    HttplibRouteSink sink_b(b);

    sink_a.Post("/yuzu_test_dup", kNoop);
    sink_a.Post("/yuzu_test_dup", kNoop); // the same route twice is one entry
    sink_b.Post("/yuzu_test_only_b", kNoop);

    const auto ra = RouteInventory::instance().routes_for(&a);
    const auto rb = RouteInventory::instance().routes_for(&b);
    CHECK(ra.size() == 1);
    CHECK(has(ra, "POST", "/yuzu_test_dup"));
    CHECK_FALSE(has(ra, "POST", "/yuzu_test_only_b"));
    CHECK(rb.size() == 1);
    CHECK(has(rb, "POST", "/yuzu_test_only_b"));
    RouteInventory::instance().forget(&a);
    RouteInventory::instance().forget(&b);
}

TEST_CASE("route inventory: forget drops one server and an unknown server reads empty",
          "[routeinv]") {
    httplib::Server svr;
    HttplibRouteSink sink(svr);
    sink.Post("/yuzu_test_forget", kNoop);
    REQUIRE(RouteInventory::instance().routes_for(&svr).size() == 1);

    RouteInventory::instance().forget(&svr);
    CHECK(RouteInventory::instance().routes_for(&svr).empty());

    httplib::Server never_registered;
    CHECK(RouteInventory::instance().routes_for(&never_registered).empty());
}
