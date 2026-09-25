/// @file test_health_routes.cpp
/// HTTP-level coverage for the 6-route Health/Infra cluster (#2542 PR-10) —
/// driven in-process through TestRouteSink (no httplib acceptor, #438),
/// mirroring test_result_set_routes.cpp's / test_page_routes.cpp's Harness
/// shape. None of these 6 routes touches Postgres directly through this
/// harness (every store pointer defaults to null and the handlers'
/// `store && store->is_open()` idiom degrades to "not open" — a REAL
/// degraded-dependency case, not a mock), so every case here runs without
/// YUZU_TEST_POSTGRES_DSN.
///
/// AUTH POSTURE under test (see health_routes.hpp's header comment):
///   - /metrics, /livez, /readyz never call auth_fn/resolve_session_fn/
///     deny_service_scoped_fn at all — reachable with no session, matching
///     the pre-routing exemption that (deliberately) lives in server.cpp,
///     not this module.
///   - /health, /api/health call ONLY resolve_session_fn (non-blocking) —
///     always 200, response SHAPE differs by session presence.
///   - /fragments/health/summary calls deny_service_scoped_fn THEN auth_fn
///     (blocking) — the one route in this cluster that actually gates.

#include "health_routes.hpp"
#include "pg_reachability_probe.hpp"
#include "test_route_sink.hpp"

#include "agent_registry.hpp"
#include "default_certs.hpp"
#include "event_bus.hpp"
#include "nvd_db.hpp"
#include "process_health.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// All providers injected and re-read per call, mirroring
/// test_result_set_routes.cpp's Harness shape. Every store pointer in
/// `health::Deps` defaults to null and is left that way unless a test
/// explicitly needs otherwise — this cluster has no owning store of its
/// own to instantiate against Postgres.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `deps` (by value, which
/// itself holds pointers into this struct's other members), so those
/// members must outlive it.
struct Harness {
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    yuzu::server::detail::EventBus bus;
    yuzu::server::detail::AgentRegistry registry{bus, metrics};
    yuzu::server::detail::ProcessHealthSampler sampler;
    auth::AuthManager auth_mgr{};
    DefaultCertSet default_cert_set{};
    std::atomic<bool> draining{false};
    PgReachabilityProbe* pg_probe{nullptr}; // HA WS-8: null = fail-closed
    NvdDatabase* nvd_db{nullptr}; // null unless a case wires one

    bool session_present{true};
    std::string session_username{"alice"};
    bool auth_fn_called{false};
    bool resolve_session_fn_called{false};

    bool deny_scoped{false};
    bool deny_scoped_fn_called{false};
    std::string last_deny_action, last_deny_target_type, last_deny_target_id;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        health::Deps deps;
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            auth_fn_called = true;
            if (!session_present) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthenticated"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::user;
            return s;
        };
        deps.resolve_session_fn =
            [this](const httplib::Request&) -> std::optional<auth::Session> {
            resolve_session_fn_called = true;
            if (!session_present)
                return std::nullopt;
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::user;
            return s;
        };
        deps.deny_service_scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                                             const std::string& action, const std::string&,
                                             const std::string& target_type,
                                             const std::string& target_id) -> bool {
            deny_scoped_fn_called = true;
            last_deny_action = action;
            last_deny_target_type = target_type;
            last_deny_target_id = target_id;
            if (deny_scoped) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"service-scoped tokens may not do this"}})",
                    "application/json");
                return true;
            }
            return false;
        };
        deps.cfg = &cfg;
        deps.metrics = &metrics;
        deps.registry = &registry;
        deps.process_health_sampler = &sampler;
        deps.auth_mgr = &auth_mgr;
        deps.default_cert_set = &default_cert_set;
        deps.draining = &draining;
        deps.pg_reachability_probe = pg_probe;
        deps.server_start_time = std::chrono::steady_clock::now();
        deps.nvd_db = nvd_db;
        // Every other store pointer stays null — see file header comment.
        health::register_health_routes(sink, deps);
    }

    void reset_gate_tracking() {
        auth_fn_called = false;
        resolve_session_fn_called = false;
        deny_scoped_fn_called = false;
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("health_routes: registers exactly 6 routes", "[server][routes][health_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 6);
}

TEST_CASE("health_routes: throws std::invalid_argument if cfg or metrics is unbound",
          "[server][routes][health_routes]") {
    {
        yuzu::server::test::TestRouteSink sink;
        health::Deps deps;
        deps.metrics = nullptr; // never bound
        Config cfg{};
        deps.cfg = &cfg;
        CHECK_THROWS_AS(health::register_health_routes(sink, deps), std::invalid_argument);
    }
    {
        yuzu::server::test::TestRouteSink sink;
        health::Deps deps;
        yuzu::MetricsRegistry m;
        deps.metrics = &m;
        deps.cfg = nullptr; // never bound
        CHECK_THROWS_AS(health::register_health_routes(sink, deps), std::invalid_argument);
    }
}

TEST_CASE("health_routes: throws std::invalid_argument if any of the three hoisted "
          "closures is unbound",
          "[server][routes][health_routes]") {
    // Same rationale as cfg/metrics above (see health_routes.hpp's "DEPS
    // NULL-SAFETY" header comment) — an unbound std::function is a wiring
    // bug that should fail loud at registration, not throw
    // std::bad_function_call on the first request that reaches it.
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    auto valid_deps = [&]() {
        health::Deps deps;
        deps.cfg = &cfg;
        deps.metrics = &metrics;
        deps.auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            return std::nullopt;
        };
        deps.resolve_session_fn =
            [](const httplib::Request&) -> std::optional<auth::Session> { return std::nullopt; };
        deps.deny_service_scoped_fn = [](const httplib::Request&, httplib::Response&,
                                         const std::string&, const std::string&,
                                         const std::string&, const std::string&) -> bool {
            return false;
        };
        return deps;
    };
    {
        yuzu::server::test::TestRouteSink sink;
        auto deps = valid_deps();
        deps.auth_fn = nullptr;
        CHECK_THROWS_AS(health::register_health_routes(sink, deps), std::invalid_argument);
    }
    {
        yuzu::server::test::TestRouteSink sink;
        auto deps = valid_deps();
        deps.resolve_session_fn = nullptr;
        CHECK_THROWS_AS(health::register_health_routes(sink, deps), std::invalid_argument);
    }
    {
        yuzu::server::test::TestRouteSink sink;
        auto deps = valid_deps();
        deps.deny_service_scoped_fn = nullptr;
        CHECK_THROWS_AS(health::register_health_routes(sink, deps), std::invalid_argument);
    }
}

// ── /metrics — unauthenticated, no gate ─────────────────────────────────────

TEST_CASE("health_routes: GET /metrics is reachable with no session and emits "
          "real Prometheus text",
          "[server][routes][health_routes]") {
    Harness h;
    h.session_present = false;
    // A fresh MetricsRegistry with nothing registered serializes to an EMPTY
    // string (no built-in process/build metrics) — register one counter
    // directly on the SAME registry instance the handler will call
    // serialize() on, so the response body proves a real serialize() call
    // reached this exact registry, not a stub/empty response that would
    // pass either way.
    h.metrics.counter("yuzu_test_health_routes_probe").increment();
    h.wire();

    auto r = h.sink.Get("/metrics");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_FALSE(h.auth_fn_called);
    CHECK_FALSE(h.resolve_session_fn_called);
    CHECK_FALSE(h.deny_scoped_fn_called);
    CHECK(r->get_header_value("Content-Type").find("text/plain") != std::string::npos);
    CHECK(r->body.find("yuzu_test_health_routes_probe") != std::string::npos);
}

TEST_CASE("health_routes: GET /metrics with a null mgmt_group_store/nvd_db "
          "still serializes cleanly (gauges just skipped)",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire(); // mgmt_group_store, nvd_db, nvd_sync all null by construction

    auto r = h.sink.Get("/metrics");
    REQUIRE(r);
    CHECK(r->status == 200);
}

// ── /livez — trivial, no gate, no deps ──────────────────────────────────────

TEST_CASE("health_routes: GET /livez is reachable with no session and always ok",
          "[server][routes][health_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/livez");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(json::parse(r->body)["status"] == "ok");
    CHECK_FALSE(h.auth_fn_called);
    CHECK_FALSE(h.resolve_session_fn_called);
}

// ── /readyz — unauthenticated, real degraded-dependency case ───────────────

TEST_CASE("health_routes: GET /readyz is reachable with no session", "[server][routes][health_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    CHECK_FALSE(h.auth_fn_called);
    CHECK_FALSE(h.resolve_session_fn_called);
    CHECK_FALSE(h.deny_scoped_fn_called);
}

TEST_CASE("health_routes: GET /readyz with every store pointer null reports "
          "503 not-ready with the failed_stores list — a REAL degraded-"
          "dependency case (null store == not open, exactly how production "
          "degrades on a construction failure)",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire(); // every store field left null

    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    CHECK(r->status == 503);
    auto body = json::parse(r->body);
    CHECK(body["status"] == "not ready");
    REQUIRE(body.contains("failed_stores"));
    // A representative sample from both the /health-and-/readyz set and the
    // /readyz-only set (proves the union, not just one branch, is wired).
    auto failed = body["failed_stores"].get<std::vector<std::string>>();
    CHECK(std::find(failed.begin(), failed.end(), "response_store") != failed.end());
    CHECK(std::find(failed.begin(), failed.end(), "api_token_store") != failed.end());
    CHECK(std::find(failed.begin(), failed.end(), "fleet_topology_store") != failed.end());
    CHECK(std::find(failed.begin(), failed.end(), "pg_pool") != failed.end());
    // scim_store's check is opt-in gated (cfg.scim_enable defaults false) —
    // must NOT appear in failed_stores despite the pointer being null.
    CHECK(std::find(failed.begin(), failed.end(), "scim_store") == failed.end());
    // ca_store/ca_root gate on cfg.using_default_certs, which defaults false
    // (Config's own in-class default) — must NOT appear despite the
    // pointer being null, same "opt-in feature, off by default" shape as
    // scim_store above.
    CHECK(std::find(failed.begin(), failed.end(), "ca_store") == failed.end());
    CHECK(std::find(failed.begin(), failed.end(), "ca_root") == failed.end());
}

TEST_CASE("health_routes: GET /readyz reports a dead nvd_db as degraded, never "
          "as a failed store",
          "[server][routes][health_routes]") {
    // nvd_db is fail-open by design: a broken CVE cache must be visible to
    // on-call without pulling the node out of rotation.
    Harness h;
    h.wire(); // nvd_db left null == not open
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    auto body = json::parse(r->body);
    REQUIRE(body.contains("degraded"));
    auto degraded = body["degraded"].get<std::vector<std::string>>();
    CHECK(std::find(degraded.begin(), degraded.end(), "nvd_db") != degraded.end());
    REQUIRE(body.contains("failed_stores"));
    auto failed = body["failed_stores"].get<std::vector<std::string>>();
    CHECK(std::find(failed.begin(), failed.end(), "nvd_db") == failed.end());
}

TEST_CASE("health_routes: GET /readyz does not report an open nvd_db as degraded",
          "[server][routes][health_routes]") {
    // The other arm of the nvd_db notice: pins the predicate to is_open(), so a
    // regression to a constant false (always degraded) fails here.
    NvdDatabase db(":memory:");
    REQUIRE(db.is_open());
    Harness h;
    h.nvd_db = &db;
    h.wire();
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    auto body = json::parse(r->body);
    if (body.contains("degraded")) {
        auto degraded = body["degraded"].get<std::vector<std::string>>();
        CHECK(std::find(degraded.begin(), degraded.end(), "nvd_db") == degraded.end());
    }
}

TEST_CASE("health_routes: GET /readyz reports draining when deps.draining is "
          "set, before any store check",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire();
    h.draining.store(true, std::memory_order_release);

    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(json::parse(r->body)["status"] == "draining");
}

TEST_CASE("health_routes: GET /readyz with a null draining pointer degrades "
          "to 'not draining' (test-harness-only null-safety, never null in "
          "production)",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire();
    // Simulate an unwired deps.draining by re-registering with it left null.
    yuzu::server::test::TestRouteSink sink2;
    health::Deps deps;
    deps.cfg = &h.cfg;
    deps.metrics = &h.metrics;
    deps.auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<auth::Session> {
        return std::nullopt;
    };
    deps.resolve_session_fn =
        [](const httplib::Request&) -> std::optional<auth::Session> { return std::nullopt; };
    deps.deny_service_scoped_fn = [](const httplib::Request&, httplib::Response&,
                                     const std::string&, const std::string&, const std::string&,
                                     const std::string&) -> bool { return false; };
    // deps.draining intentionally left null
    health::register_health_routes(sink2, deps);

    auto r = sink2.dispatch("GET", "/readyz");
    REQUIRE(r);
    // Not "draining" — falls through to the (also-null) store checks, so
    // 503 "not ready" rather than 200, but definitely not the draining body.
    CHECK(r->status != 200);
    CHECK(json::parse(r->body)["status"] != "draining");
}

// ── /health, /api/health — same handler instance, unauthenticated-reachable,
//    response SHAPE differs by session presence ────────────────────────────

TEST_CASE("health_routes: GET /health and GET /api/health are BOTH reachable "
          "with no session (200, cheap probe shape only)",
          "[server][routes][health_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    for (const std::string& path : {std::string("/health"), std::string("/api/health")}) {
        INFO("path: " << path);
        h.reset_gate_tracking();
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(h.resolve_session_fn_called); // non-blocking resolve DOES run
        CHECK_FALSE(h.auth_fn_called);       // but the blocking gate never does
        CHECK_FALSE(h.deny_scoped_fn_called);
        auto body = json::parse(r->body);
        CHECK(body.contains("status"));
        CHECK(body.contains("uptime_seconds"));
        CHECK(body["agents"].contains("online"));
        CHECK_FALSE(body["agents"].contains("pending")); // authed-only field
        CHECK_FALSE(body.contains("executions"));         // authed-only field
        CHECK_FALSE(body.contains("system"));             // authed-only field
        CHECK(body.contains("tls"));                      // unauthenticated, always present
        CHECK(body["version"].is_string());
    }
}

TEST_CASE("health_routes: GET /health with a session gets the heavier "
          "authenticated-only fields",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire(); // session_present defaults true

    auto r = h.sink.Get("/health");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(h.resolve_session_fn_called);
    auto body = json::parse(r->body);
    CHECK(body["agents"].contains("pending"));
    CHECK(body.contains("executions"));
    CHECK(body.contains("system"));
}

TEST_CASE("health_routes: /health and /api/health status flips to 'degraded' "
          "with every store null (union of health_handler's own store list)",
          "[server][routes][health_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/health");
    REQUIRE(r);
    CHECK(r->status == 200); // never gates on store health, unlike /readyz
    auto body = json::parse(r->body);
    CHECK(body["status"] == "degraded");
    CHECK(body["stores"]["pg_pool"] == "error");
    CHECK(body["stores"]["responses"] == "error");
}

TEST_CASE("health_routes: /health's TLS block degrades gracefully with a "
          "null default_cert_set (deliberate non-verbatim null-guard)",
          "[server][routes][health_routes]") {
    yuzu::server::test::TestRouteSink sink;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    health::Deps deps;
    deps.cfg = &cfg;
    deps.metrics = &metrics;
    deps.resolve_session_fn = [](const httplib::Request&) -> std::optional<auth::Session> {
        return std::nullopt;
    };
    deps.auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<auth::Session> {
        return std::nullopt;
    };
    deps.deny_service_scoped_fn = [](const httplib::Request&, httplib::Response&,
                                     const std::string&, const std::string&, const std::string&,
                                     const std::string&) -> bool { return false; };
    // default_cert_set intentionally left null
    health::register_health_routes(sink, deps);

    auto r = sink.dispatch("GET", "/health");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto body = json::parse(r->body);
    CHECK(body["tls"]["ca_fingerprint"] == "");
}

// ── /fragments/health/summary — the one route in this cluster that gates ───

TEST_CASE("health_routes: /fragments/health/summary gates on "
          "deny_service_scoped_fn BEFORE auth_fn",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire();

    h.reset_gate_tracking();
    auto r = h.sink.Get("/fragments/health/summary");
    REQUIRE(r);
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called); // deny_scoped==false -> falls through to auth_fn
    CHECK(h.last_deny_action == "health.fragment.access_denied");
    CHECK(h.last_deny_target_type.empty()); // no single target for this route
    CHECK(h.last_deny_target_id.empty());
}

TEST_CASE("health_routes: /fragments/health/summary 403s a service-scoped "
          "token before auth_fn runs",
          "[server][routes][health_routes]") {
    Harness h;
    h.deny_scoped = true;
    h.wire();

    auto r = h.sink.Get("/fragments/health/summary");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK_FALSE(h.auth_fn_called);
}

TEST_CASE("health_routes: /fragments/health/summary 401s an unauthenticated "
          "caller (after the scoped-deny gate)",
          "[server][routes][health_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/fragments/health/summary");
    REQUIRE(r);
    CHECK(r->status == 401);
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called);
}

TEST_CASE("health_routes: /fragments/health/summary renders the WARN strip "
          "when every store is null (a null store is a degraded store, not "
          "a healthy one)",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/fragments/health/summary");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type").find("text/html") != std::string::npos);
    CHECK(r->body.find("health-warn") != std::string::npos);
    CHECK(r->body.find("Stores degraded") != std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_health_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_health_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 6 routes (custom_properties_routes'/
// result_set_routes' PR-4/PR-5 precedent for this tripwire).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("health_routes: wiring -- server.cpp still calls "
          "register_health_routes",
          "[server][routes][health_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_health_routes(") != std::string::npos);
}

// ---------------------------------------------------------------------------
// HA WS-8 (ADR-2002 §12): the runtime pg_reachable row
// ---------------------------------------------------------------------------

namespace {
bool has(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}
PgReachabilityProbe::PingFn fixed_ping(PgReachabilityProbe::PingResult::Kind k) {
    return [k](const std::atomic<bool>&) {
        return PgReachabilityProbe::PingResult{k, "t"};
    };
}
} // namespace

TEST_CASE("health_routes: /readyz fails closed on pg_reachable when no probe is wired",
          "[server][routes][health_routes][readyz]") {
    Harness h;
    h.wire();
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    CHECK(r->status == 503);
    auto body = json::parse(r->body);
    CHECK(has(body["failed_stores"].get<std::vector<std::string>>(), "pg_reachable"));
    CHECK(body["pg"] == "not_yet_probed");
}

TEST_CASE("health_routes: /readyz reports pg_reachable ok when the probe is Ready — and the "
          "body carries no pg reason",
          "[server][routes][health_routes][readyz]") {
    PgReachabilityProbe probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::Ok));
    probe.probe_once();
    Harness h;
    h.pg_probe = &probe;
    h.wire();
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    // Still 503 — every store pointer in this harness is null — but NOT for
    // Postgres reachability.
    auto body = json::parse(r->body);
    CHECK_FALSE(has(body["failed_stores"].get<std::vector<std::string>>(), "pg_reachable"));
    CHECK_FALSE(body.contains("pg"));
}

TEST_CASE("health_routes: /readyz names the pg reason when reachability fails, and no detail",
          "[server][routes][health_routes][readyz]") {
    PgReachabilityProbe probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::ReadOnly));
    probe.probe_once();
    Harness h;
    h.pg_probe = &probe;
    h.wire();
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    CHECK(r->status == 503);
    auto body = json::parse(r->body);
    CHECK(has(body["failed_stores"].get<std::vector<std::string>>(), "pg_reachable"));
    CHECK(body["pg"] == "read_only");
    // The ping's operator detail ("t") must never reach the unauthenticated body.
    CHECK(r->body.find("\"t\"") == std::string::npos);
}

TEST_CASE("health_routes: draining still wins over pg_reachable",
          "[server][routes][health_routes][readyz]") {
    Harness h;
    h.wire();
    h.draining.store(true, std::memory_order_release);
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(json::parse(r->body)["status"] == "draining");
}

TEST_CASE("health_routes: /health mirrors pg_reachable",
          "[server][routes][health_routes][readyz]") {
    PgReachabilityProbe probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::Failed));
    probe.probe_once();
    probe.probe_once();
    Harness h;
    h.pg_probe = &probe;
    h.wire();
    auto r = h.sink.Get("/health");
    REQUIRE(r);
    CHECK(json::parse(r->body)["stores"]["pg_reachable"] == "error");
}

TEST_CASE("health_routes: /metrics exports the reachability gauges on scrape",
          "[server][routes][health_routes][readyz]") {
    PgReachabilityProbe probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::Ok));
    probe.probe_once();
    Harness h;
    h.pg_probe = &probe;
    h.wire();
    auto r = h.sink.Get("/metrics");
    REQUIRE(r);
    CHECK(r->body.find("yuzu_server_pg_reachable 1") != std::string::npos);
    CHECK(r->body.find("yuzu_server_pg_reachability_last_success_age_seconds") !=
          std::string::npos);
}
