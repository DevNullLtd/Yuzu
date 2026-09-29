/**
 * test_legacy_events_routes.cpp — route-handler coverage for the legacy
 * `GET /events` SSE stream (#2542 PR-12), driven in-process through
 * TestRouteSink (no httplib acceptor, #438), mirroring
 * `test_rest_api_events.cpp`'s split for its `/api/v1/events` sibling.
 *
 * Two surfaces under test:
 *   1. The synchronous handler phase (deny_service_scoped_fn gate ->
 *      best-effort resolve_session_fn -> admission-control try_acquire ->
 *      headers -> bus subscribe -> set_chunked_content_provider
 *      registration) via TestRouteSink. TestRouteSink does NOT invoke the
 *      chunked content provider, so wire-level assertions stop at the
 *      handler-returned response state (status, headers, subscription side
 *      effect on `deps.event_bus`) — same boundary
 *      `test_rest_api_events.cpp`'s own file header documents for its
 *      sibling.
 *   2. Admission control (ADR-0034): this route leases from the SAME
 *      `StreamBudget` instance/`SseSurface::kLegacyEvents` key every other
 *      streaming surface does — the 429 + Retry-After shape, and that a
 *      budget rejection never subscribes to the bus.
 *
 * What is deliberately NOT covered here: end-to-end SSE wire framing — see
 * `test_rest_api_events.cpp`'s file header for why (the #438 TSan trap this
 * fixture exists to dodge). No Postgres needed anywhere in this module.
 */

#include "legacy_events_routes.hpp"
#include "test_route_sink.hpp"

#include "event_bus.hpp"
#include "stream_budget.hpp"
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::StreamBudget;

namespace {

struct DenyCall {
    std::string action, message, target_type, target_id;
};

/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
///
/// Also: `bus`/`budget` (owned OUTSIDE this struct by the test, passed in
/// as pointers) must outlive `sink` too. TestRouteSink's synthesized
/// `httplib::Response` fires the resource releaser in its OWN destructor
/// (the handler's body comment: "`lease` dies here"), which calls back into
/// `*deps.event_bus` to unsubscribe. Each TEST_CASE below keeps `bus`/
/// `budget` as locals declared BEFORE the harness, so they outlive every
/// `Response` the sink hands back.
struct Harness {
    EventBus* bus;
    StreamBudget* budget{nullptr};

    bool deny_service_scoped{false};
    std::vector<DenyCall> deny_calls;

    std::optional<auth::Session> session_to_return;

    yuzu::server::test::TestRouteSink sink;

    explicit Harness(EventBus* b) : bus(b) {}

    void wire() {
        legacy_events::Deps deps;
        deps.event_bus = bus;
        deps.stream_budget = budget;
        deps.deny_service_scoped_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string& action,
                   const std::string& message, const std::string& target_type,
                   const std::string& target_id) -> bool {
            deny_calls.push_back({action, message, target_type, target_id});
            if (deny_service_scoped) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return true;
            }
            return false;
        };
        deps.resolve_session_fn = [this](const httplib::Request&) { return session_to_return; };
        legacy_events::register_legacy_events_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("legacy_events_routes: registers exactly 1 route",
          "[server][routes][legacy_events_routes]") {
    EventBus bus;
    Harness h{&bus};
    h.wire();
    CHECK(h.sink.route_count() == 1);
}

// ── deny_service_scoped_fn gate ─────────────────────────────────────────

TEST_CASE("legacy_events_routes: a service-scoped-token denial 403s before subscribing, "
          "with the documented action/message and empty target_type/target_id",
          "[server][routes][legacy_events_routes]") {
    EventBus bus;
    Harness h{&bus};
    h.deny_service_scoped = true;
    h.wire();

    auto res = h.sink.Get("/events");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(bus.listener_count() == 0);

    REQUIRE(h.deny_calls.size() == 1);
    CHECK(h.deny_calls[0].action == "events.stream.access_denied");
    CHECK(h.deny_calls[0].message ==
          "service-scoped tokens may not open the fleet-wide legacy event stream");
    CHECK(h.deny_calls[0].target_type.empty());
    CHECK(h.deny_calls[0].target_id.empty());
}

// ── Happy path: subscribes, sets the documented headers ────────────────

TEST_CASE("legacy_events_routes: an admitted request sets Cache-Control/X-Accel-Buffering "
          "and subscribes to the event bus",
          "[server][routes][legacy_events_routes]") {
    EventBus bus;
    Harness h{&bus};
    auth::Session s;
    s.username = "alice";
    h.session_to_return = s;
    h.wire();

    CHECK(bus.listener_count() == 0);
    {
        auto res = h.sink.Get("/events"); // kept alive: see Harness's header comment
        REQUIRE(res);
        CHECK(res->status == 200); // TestRouteSink pre-sets 200; handler never overrides it here
        CHECK(res->get_header_value("Cache-Control") == "no-cache");
        CHECK(res->get_header_value("X-Accel-Buffering") == "no");
        CHECK(bus.listener_count() == 1);
    }
    // Response destruction fires httplib's content_provider_resource_releaser_,
    // which is where the subscription's cleanup lives -- confirm it actually
    // unsubscribes rather than just trusting the releaser exists.
    CHECK(bus.listener_count() == 0);
}

TEST_CASE("legacy_events_routes: resolve_session_fn is best-effort -- an unresolvable "
          "session still gets admitted (anonymous bucket), never a 401",
          "[server][routes][legacy_events_routes]") {
    EventBus bus;
    Harness h{&bus};
    h.session_to_return = std::nullopt; // "who is this" lookup fails
    h.wire();

    auto res = h.sink.Get("/events");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(bus.listener_count() == 1);
}

// ── Admission control (ADR-0034) ────────────────────────────────────────

TEST_CASE("legacy_events_routes: 429 with Retry-After once the shared budget is exhausted, "
          "and no subscription is made",
          "[server][routes][legacy_events_routes]") {
    EventBus bus;
    StreamBudget budget{StreamBudget::Config{/*global_cap=*/1}};
    auto held = budget.try_acquire(yuzu::server::detail::SseSurface::kLegacyEvents,
                                   "someone-else", yuzu::server::detail::kPerPrincipalDashboard);
    REQUIRE(held.lease);

    Harness h{&bus};
    h.budget = &budget;
    h.wire();

    auto res = h.sink.Get("/events");
    REQUIRE(res);
    CHECK(res->status == 429);
    CHECK(res->get_header_value("Retry-After") == "5");
    CHECK(bus.listener_count() == 0); // lease taken before subscribe -- a reject subscribes nothing
    CHECK(budget.active() == 1);      // the pre-seeded holder's lease, unaffected
}

TEST_CASE("legacy_events_routes: a null stream_budget is an unmetered seam -- request still "
          "serves",
          "[server][routes][legacy_events_routes]") {
    EventBus bus;
    Harness h{&bus}; // budget stays nullptr
    h.wire();

    auto res = h.sink.Get("/events");
    REQUIRE(res);
    CHECK(res->status != 429);
    CHECK(bus.listener_count() == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("legacy_events_routes: wiring -- server.cpp still calls "
          "register_legacy_events_routes",
          "[server][routes][legacy_events_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_legacy_events_routes(") != std::string::npos);
}
