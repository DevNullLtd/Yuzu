/**
 * test_route_inventory.cpp: `HttplibRouteSink` records every registration in
 * `RouteInventory`, keyed by the wrapped `httplib::Server`
 * (server/core/src/route_inventory.hpp, http_route_sink.hpp).
 *
 * A bare `httplib::Server` is constructed and never listens: no port, no thread (#438).
 */

#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/route_inventory.hpp"
#include "../../../server/core/src/step_up_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <iterator>
#include <stdexcept>
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
    // A new server may reuse a destroyed one's address (route_inventory.hpp, `forget`), and other
    // tests (test_health_routes.cpp, test_step_up_wiring.cpp) record four routes on a stack server
    // and never forget it, so clear the address before counting: a stale four-route entry here
    // reads `5 == 1`.
    RouteInventory::instance().forget(&svr);
    HttplibRouteSink sink(svr);
    sink.Post("/yuzu_test_forget", kNoop);
    REQUIRE(RouteInventory::instance().routes_for(&svr).size() == 1);

    RouteInventory::instance().forget(&svr);
    CHECK(RouteInventory::instance().routes_for(&svr).empty());

    httplib::Server never_registered;
    RouteInventory::instance().forget(&never_registered); // a reused address may carry stale rows
    CHECK(RouteInventory::instance().routes_for(&never_registered).empty());
}

// ── sealing: a late mutating registration needs a step-up policy row ─────────────────────────

namespace {

using Registrar = void (HttplibRouteSink::*)(const std::string&, httplib::Server::Handler);

struct Verb {
    const char* method;
    Registrar fn;
};

// `const`, not `constexpr`: pointers to virtual member functions are not constant expressions
// on every compiler (MSVC), and nothing here needs one.
const Verb kMutatingVerbs[] = {{"POST", &HttplibRouteSink::Post},
                               {"PUT", &HttplibRouteSink::Put},
                               {"DELETE", &HttplibRouteSink::Delete},
                               {"PATCH", &HttplibRouteSink::Patch}};

} // namespace

TEST_CASE("route inventory: a sealed server refuses a mutating registration with no policy row",
          "[routeinv][seal]") {
    httplib::Server svr;
    RouteInventory::instance().forget(&svr);
    HttplibRouteSink sink(svr);
    sink.Post("/yuzu_test_before_seal", kNoop); // unsealed: unclassified is recorded as before
    RouteInventory::instance().seal(&svr);
    REQUIRE(RouteInventory::instance().is_sealed(&svr));

    for (const auto& verb : kMutatingVerbs) {
        const std::string pattern = std::string("/yuzu_test_late_") + verb.method;
        INFO(verb.method);
        CHECK_THROWS_AS((sink.*verb.fn)(pattern, kNoop), std::logic_error);
        CHECK_FALSE(has(RouteInventory::instance().routes_for(&svr), verb.method, pattern));
    }
    // Only the pre-seal registration is on record.
    CHECK(RouteInventory::instance().routes_for(&svr).size() == 1);
    RouteInventory::instance().forget(&svr);
}

TEST_CASE("route inventory: a sealed server still accepts a classified or non-mutating route",
          "[routeinv][seal]") {
    httplib::Server svr;
    RouteInventory::instance().forget(&svr);
    HttplibRouteSink sink(svr);
    RouteInventory::instance().seal(&svr);

    // Every row of the real table is admitted after the seal, whatever its class.
    for (const auto& row : yuzu::server::kStepUpPolicy) {
        const std::string method(row.method);
        const std::string pattern(row.pattern);
        INFO(method << " " << pattern);
        const auto it = std::find_if(std::begin(kMutatingVerbs), std::end(kMutatingVerbs),
                                     [&](const Verb& v) { return method == v.method; });
        REQUIRE(it != std::end(kMutatingVerbs));
        CHECK_NOTHROW((sink.*(it->fn))(pattern, kNoop));
        CHECK(has(RouteInventory::instance().routes_for(&svr), method, pattern));
    }
    // Read verbs are not mutating registrations and need no row.
    CHECK_NOTHROW(sink.Get("/yuzu_test_sealed_get", kNoop));
    CHECK_NOTHROW(sink.Options("/yuzu_test_sealed_options", kNoop));
    CHECK(has(RouteInventory::instance().routes_for(&svr), "GET", "/yuzu_test_sealed_get"));
    // The same method with a pattern that merely resembles a row is not a row (exact key).
    const std::string near_miss = std::string(yuzu::server::kStepUpPolicy[0].pattern) + "x";
    CHECK_THROWS_AS(sink.Post(near_miss, kNoop), std::logic_error);
    RouteInventory::instance().forget(&svr);
}

TEST_CASE("route inventory: an unsealed server and per-server keying are unaffected by a seal",
          "[routeinv][seal]") {
    httplib::Server sealed_svr;
    httplib::Server open_svr;
    RouteInventory::instance().forget(&sealed_svr);
    RouteInventory::instance().forget(&open_svr);
    HttplibRouteSink sealed_sink(sealed_svr);
    HttplibRouteSink open_sink(open_svr);
    RouteInventory::instance().seal(&sealed_svr);

    CHECK(RouteInventory::instance().is_sealed(&sealed_svr));
    CHECK_FALSE(RouteInventory::instance().is_sealed(&open_svr));
    CHECK_THROWS_AS(sealed_sink.Post("/yuzu_test_late", kNoop), std::logic_error);
    CHECK_NOTHROW(open_sink.Post("/yuzu_test_late", kNoop));
    CHECK(has(RouteInventory::instance().routes_for(&open_svr), "POST", "/yuzu_test_late"));

    // forget() drops the seal with the routes, so a server reusing the address starts open.
    RouteInventory::instance().forget(&sealed_svr);
    CHECK_FALSE(RouteInventory::instance().is_sealed(&sealed_svr));
    CHECK_NOTHROW(sealed_sink.Post("/yuzu_test_after_forget", kNoop));
    RouteInventory::instance().forget(&sealed_svr);
    RouteInventory::instance().forget(&open_svr);
}
