/// @file test_health_routes.cpp
/// HTTP-level coverage for the 7-route Health/Infra cluster (#2542 PR-10) —
/// driven in-process through TestRouteSink (no httplib acceptor, #438),
/// mirroring test_result_set_routes.cpp's / test_page_routes.cpp's Harness
/// shape — except the one [live] case at the end, which binds a real loopback
/// listener to cover install_plaintext_redirect_pre_routing. None of
/// these 7 routes touches Postgres directly through this harness (every store
/// pointer defaults to null and the handlers'
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
///     (blocking) — one of the two routes in this cluster that gate on a session
///     (with /fragments/dashboard/health).

#include "health_routes.hpp"
#include "http_route_sink.hpp"
#include "pg_reachability_probe.hpp"
#include "principal_class.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

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
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <string>
#include <vector>

// #5906 [live] case: httplib's acceptor crashes under TSan with no report (#438).
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_HEALTH_ROUTES_LIVE_TSAN 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define YUZU_HEALTH_ROUTES_LIVE_TSAN 1
#endif

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
    std::string last_deny_action, last_deny_message, last_deny_target_type, last_deny_target_id;

    // HM-2 /fragments/dashboard/health: the optional Execution:Read fleet gate.
    bool fleet_wired{false};
    bool fleet_admit{true};
    bool fleet_scoped{false};
    std::vector<std::string> fleet_calls; // "Securable:Op"

    // #5906: the plaintext redirect-listener sink. `plain_wired` registers the
    // four probes on `plain_sink`; `plain_override` points at some other sink (the
    // real-listener case); `main_serving` is read live by the 503 gate.
    bool plain_wired{false};
    std::atomic<bool> main_serving{true}; // read by an httplib worker in the [live] case
    HttpRouteSink* plain_override{nullptr};

    // Both sinks LAST (sink-last rule): their handlers capture `deps`.
    yuzu::server::test::TestRouteSink sink;
    yuzu::server::test::TestRouteSink plain_sink;

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
                                             const std::string& action, const std::string& message,
                                             const std::string& target_type,
                                             const std::string& target_id) -> bool {
            deny_scoped_fn_called = true;
            last_deny_action = action;
            last_deny_message = message;
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
        if (fleet_wired)
            deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                        const std::string& sec,
                                        const std::string& op) -> authz::FleetReadGate {
                fleet_calls.push_back(sec + ":" + op);
                if (!fleet_admit) {
                    res.status = 403;
                    return {};
                }
                authz::FleetReadGate g;
                g.admitted = true;
                g.scope = fleet_scoped ? authz::VisibleSet{std::unordered_set<std::string>{"a1"}}
                                       : authz::VisibleSet{std::nullopt};
                return g;
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
        deps.plaintext_probe_sink =
            plain_override ? plain_override : (plain_wired ? &plain_sink : nullptr);
        deps.main_listener_serving_fn = [this] { return main_serving.load(); };
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

TEST_CASE("health_routes: registers exactly 7 routes", "[server][routes][health_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 7);
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

TEST_CASE("health_routes: GET /readyz reports a crypto dashboard layout store that did not open "
          "as degraded, never as a failed store",
          "[server][routes][health_routes]") {
    // ADR-0071 degrade posture (owner decision 2026-10-19): server.cpp resets a layout store
    // that did not open to null and boots; /readyz must keep that node in rotation while still
    // naming the store.
    Harness h;
    h.wire(); // crypto_dashboard_layout_store left null == did not open at boot
    auto r = h.sink.Get("/readyz");
    REQUIRE(r);
    auto body = json::parse(r->body);
    REQUIRE(body.contains("degraded"));
    auto degraded = body["degraded"].get<std::vector<std::string>>();
    CHECK(std::find(degraded.begin(), degraded.end(), "crypto_dashboard_layout_store") !=
          degraded.end());
    REQUIRE(body.contains("failed_stores"));
    auto failed = body["failed_stores"].get<std::vector<std::string>>();
    CHECK(std::find(failed.begin(), failed.end(), "crypto_dashboard_layout_store") ==
          failed.end());
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
    // WS-6 6.2: this harness's AuthManager has no AuthDB attached, so the pending
    // count is UNKNOWN (JSON null) — never a `0` that reads as "nothing awaiting
    // approval" when the enrollment store could not be read.
    CHECK(body["agents"]["pending"].is_null());
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

// ── /fragments/health/summary — one of the two routes in this cluster that gate ──

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
// the real server 404s all 7 routes (custom_properties_routes'/
// result_set_routes' PR-4/PR-5 precedent for this tripwire). It also pins the
// #5906 wiring the unit harness cannot see (ServerImpl needs Postgres): the
// plaintext redirect listener's probe routes and their 503 gate.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("health_routes: wiring -- server.cpp still calls "
          "register_health_routes and wires the plaintext probe listener",
          "[server][routes][health_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_health_routes(") != std::string::npos);

    // Compare with all whitespace removed so a clang-format re-wrap of a call site
    // can neither redden nor greenwash the tripwire.
    const auto squeeze = [](std::string s) {
        std::erase_if(s, [](unsigned char c) { return std::isspace(c) != 0; });
        return s;
    };
    const auto flat = squeeze(src);
    const auto occurrences = [&](const std::string& needle) {
        const auto n = squeeze(needle);
        std::size_t count = 0;
        for (auto pos = flat.find(n); pos != std::string::npos; pos = flat.find(n, pos + 1))
            ++count;
        return count;
    };
    const auto expect = [&](const char* needle, std::size_t want, const char* behaviour) {
        INFO(behaviour);
        CHECK(occurrences(needle) == want);
    };

    // The redirect listener's 301/probe pre-routing lives in health_routes.cpp; server.cpp
    // must install it.
    expect("install_plaintext_redirect_pre_routing(*redirect_server_", 1,
           "server.cpp installs the redirect pre-routing from health_routes");
    // The probe routes must be handed the plaintext sink and the 503 gate.
    expect(".plaintext_probe_sink = redirect_sink_.get()", 1,
           "register_health_routes receives the redirect listener's sink");
    expect(".main_listener_serving_fn = [this] { return web_server_ && "
           "web_server_->is_running(); }",
           1, "the plaintext probes are gated on the HTTPS listener actually running");
    // One closed probe set shared by the main pre-routing chokepoint.
    expect("if (yuzu::server::health::is_probe_path(req.path)) {", 1,
           "main pre-routing exempts probes through the one shared predicate");
    // The sink the probes register on must exist before register_health_routes is handed it:
    // deleting the construction leaves a null sink, which silently registers nothing.
    expect("redirect_sink_ = std::make_unique<HttplibRouteSink>(*redirect_server_)", 1,
           "the redirect listener's route sink is built");
    {
        const auto built =
            flat.find(squeeze("redirect_sink_ = std::make_unique<HttplibRouteSink>("));
        const auto handed = flat.find(squeeze(".plaintext_probe_sink = redirect_sink_.get()"));
        CHECK(built != std::string::npos);
        CHECK(handed != std::string::npos);
        CHECK(built < handed);
    }
    // #5906 gate fixes: the redirect listener's eager fixed pool, its security headers and
    // request counter, and the bounded shutdown wait that covers its thread.
    expect("redirect_server_->new_task_queue = [redirect_pool]", 1,
           "the redirect listener has its own fixed pool, not httplib's dynamic default");
    // The pool size is a value, not just a shape: 0 or 1 threads would wedge or starve the probe
    // port, and an uncapped size scales with the host's core count (a pids-limit boot failure).
    expect("const std::size_t redirect_pool = "
           "std::min<std::size_t>(CPPHTTPLIB_THREAD_POOL_MAX_COUNT, 64);",
           1, "the redirect pool is httplib's maximum capped at 64 threads");
    expect("new httplib::ThreadPool(redirect_pool, redirect_pool)", 1,
           "base == max: the dynamic-growth branch stays dead");
    expect("install_plaintext_post_routing(*redirect_server_", 1,
           "the redirect listener installs the shared post-routing handler");
    expect("HeaderBundle::make(cfg_.csp_extra_sources, /*https_enabled=*/false), "
           "count_http_request);",
           1, "the redirect listener's headers carry no HSTS, and it is handed the shared counter");
    // The request counter has ONE spelling (name + all three labels), and the main
    // post-routing handler calls it: dropping the increment, a label, or either call leaves the
    // injected-callback live test green, so the production wiring is pinned here instead.
    expect(R"(auto count_http_request = [this](const httplib::Request& req,
                                         const httplib::Response& res) {
            metrics_.counter("yuzu_http_requests_total",
                {{"method", std::string(http_method_label(req.method))},
                {"status", std::to_string(res.status)},
                {"principal_class", std::string(principal_class_resolved(req))}}).increment();
        };)",
           1, "the shared counter lambda carries the metric name and all three labels");
    // The method label is normalised: a rejected request's raw request-line token is
    // attacker-controlled on the plain port, so a revert to req.method must redden on its own,
    // by name, not only via the exact-spelling check above (#5906, adversarial review round 3).
    expect("http_method_label(req.method)", 1,
           "the request counter's method label is bounded, never the raw request-line token");
    expect("count_http_request(req, res);", 1,
           "the main post-routing handler counts through the shared lambda");
    expect("std::lock_guard<std::mutex> lk(web_thread_done_mtx_); redirect_thread_done_ = true; } "
           "web_thread_done_cv_.notify_all();",
           1, "the redirect thread sets its flag under the mutex and wakes stop()'s bounded wait");
    expect("return (web_thread_done_ || !web_thread_.joinable()) && "
           "(redirect_thread_done_ || !redirect_thread_.joinable());",
           1, "stop() waits for BOTH listener threads inside the one 15s bound");
    expect("const bool web_wedged = web_thread_.joinable() && !web_thread_done_;", 1,
           "the web thread's wedged state reads the web flag");
    expect("const bool redirect_wedged = redirect_thread_.joinable() && !redirect_thread_done_;", 1,
           "the redirect thread's wedged state reads the redirect flag");
    expect(R"(const char* const who = web_wedged ? (redirect_wedged
                                                          ? "web and redirect listener threads"
                                                          : "web listener thread")
                                                   : "redirect listener thread";)",
           1, "the force-exit line names the thread(s) that are actually wedged");
    // The bound and the force-exit line are what an operator sees on a wedged shutdown. The
    // behaviour itself is proven by a real-process shutdown run (the redirect-trickle probe),
    // which the unit suite cannot host (ServerImpl needs Postgres), so these are source-text
    // pins: weaker evidence than a lifecycle test, but they redden on a changed bound, a lost
    // thread name, or a force-exit that no longer follows the message.
    expect("web_thread_done_cv_.wait_for(lk, std::chrono::seconds(15), [this] {", 1,
           "one 15s bound covers both listener threads");
    expect(R"("web and redirect listener threads")", 1, "the both-wedged name is reported");
    expect(R"("web listener thread")", 1, "the web-only-wedged name is reported");
    expect(R"("redirect listener thread")", 1, "the redirect-only-wedged name is reported");
    expect("(#2703 Gate 7 item 2, #5906) - force-exiting.", 1,
           "the force-exit message keeps its text");
    expect("emit(kPrefix); emit(who); emit(kSuffix); std::_Exit(1);", 1,
           "the message is written, whole and immediately, before the force-exit");
    expect("no plausible hang scenario", 0,
           "the false 'cannot hang' comment (and its bare join) stays gone");
    expect("listener failed to bind or exited with an error", 2,
           "both listen() results are checked and logged");
    expect("if (!redirect_server_->listen(cfg_.web_address, cfg_.web_port))", 1,
           "a failed redirect bind or accept error is the branch that logs");
    expect("if (!web_server_->listen(cfg_.web_address, listen_port))", 1,
           "a failed web bind or accept error is the branch that logs");
    // The redirect listener exists only behind the guard, and is built at exactly one site.
    expect("if (cfg_.https_enabled && cfg_.https_redirect)", 1,
           "the redirect listener is built only when HTTPS and the redirect are on");
    expect("redirect_server_ = std::make_unique<httplib::Server>()", 1,
           "no second, unguarded redirect listener construction site");
    // The pre-routing lambda must not be re-forked inline in server.cpp.
    expect("redirect_server_->set_pre_routing_handler", 0,
           "the redirect pre-routing is not re-forked in server.cpp");
    // httplib REPLACES a re-set handler, so a later post-routing registration on the redirect
    // listener would silently drop its headers and request counter.
    expect("redirect_server_->set_post_routing_handler", 0,
           "the redirect post-routing is installed once, through install_plaintext_post_routing");
    // stop() must stop the redirect listener, or its thread never returns and every shutdown
    // burns the whole 15 s bound before the force-exit.
    expect("redirect_server_->stop();", 1, "stop() stops the redirect listener");
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

// ---------------------------------------------------------------------------
// HM-2: /fragments/dashboard/health (Dashboard "Server health" panel)
// ---------------------------------------------------------------------------

TEST_CASE("health_routes: /fragments/dashboard/health denies a service-scoped token first, as a 200 note",
          "[server][routes][health_routes][home]") {
    Harness h;
    h.deny_scoped = true;
    h.wire();
    auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.last_deny_action == "dashboard.fragment.access_denied");
    // The audited denial names the panel (this text is the audit detail, not the page).
    CHECK(h.last_deny_message == "service-scoped tokens may not read the Dashboard health panel");
    CHECK_FALSE(h.auth_fn_called); // deny runs BEFORE auth_fn
    CHECK(r->body.find("service-scoped tokens") == std::string::npos); // gate text never reaches the page
    CHECK(r->body.find("id=\"dash-health\"") != std::string::npos);
    CHECK(r->body.find("You do not have access to this panel.") != std::string::npos);
    CHECK(r->body.find("Agents connected to this server") == std::string::npos);
    CHECK(r->get_header_value("Cache-Control") == "no-store");
}

TEST_CASE("health_routes: /fragments/dashboard/health without a session writes 401 and no panel",
          "[server][routes][health_routes][home]") {
    Harness h;
    h.session_present = false;
    h.wire();
    auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
    REQUIRE(r);
    CHECK(r->status == 401);
}

TEST_CASE("health_routes: /fragments/dashboard/health renders real rows, executions row only when unscoped",
          "[server][routes][health_routes][home]") {
    SECTION("unbound fleet gate omits the executions row") {
        Harness h;
        h.wire();
        auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("id=\"dash-health\"") != std::string::npos);
        CHECK(r->body.find("Agents connected to this server") != std::string::npos);
        CHECK(r->body.find("Executions running") == std::string::npos);
        CHECK(h.fleet_calls.empty());
    }
    SECTION("admitted and unscoped shows it, gate asked for Execution:Read") {
        Harness h;
        h.fleet_wired = true;
        h.wire();
        auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
        REQUIRE(r);
        CHECK(r->body.find("Executions running") != std::string::npos);
        REQUIRE(h.fleet_calls.size() == 1);
        CHECK(h.fleet_calls[0] == "Execution:Read");
    }
    SECTION("engaged scope omits it") {
        Harness h;
        h.fleet_wired = true;
        h.fleet_scoped = true;
        h.wire();
        auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
        REQUIRE(r);
        CHECK(r->body.find("Executions running") == std::string::npos);
        CHECK(r->body.find("Agents connected to this server") != std::string::npos);
    }
    SECTION("denied omits it") {
        Harness h;
        h.fleet_wired = true;
        h.fleet_admit = false;
        h.wire();
        auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
        REQUIRE(r);
        CHECK(r->body.find("Executions running") == std::string::npos);
    }
}

TEST_CASE("health_routes: /fragments/dashboard/health never renders system, tls or pending-agent fields",
          "[server][routes][health_routes][home]") {
    Harness h;
    h.fleet_wired = true;
    h.wire();
    auto r = h.sink.dispatch("GET", "/fragments/dashboard/health");
    REQUIRE(r);
    for (const char* banned : {"cpu_percent", "rss", "tls", "pending", "command_queue_depth"})
        CHECK(r->body.find(banned) == std::string::npos);
}

TEST_CASE("health_routes: /fragments/dashboard/health agrees with /api/health on healthy versus degraded",
          "[server][routes][health_routes][home]") {
    // Kills: a panel that re-derives "healthy" instead of reusing the health document's decision.
    PgReachabilityProbe ok_probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::Ok));
    ok_probe.probe_once();
    PgReachabilityProbe bad_probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::Failed));
    bad_probe.probe_once();
    bad_probe.probe_once();
    for (PgReachabilityProbe* probe : {static_cast<PgReachabilityProbe*>(nullptr), &ok_probe, &bad_probe}) {
        Harness h;
        h.pg_probe = probe;
        h.wire();
        auto doc = h.sink.dispatch("GET", "/api/health");
        auto panel = h.sink.dispatch("GET", "/fragments/dashboard/health");
        REQUIRE(doc);
        REQUIRE(panel);
        const std::string status = json::parse(doc->body)["status"].get<std::string>();
        const bool healthy_pill = panel->body.find(">Healthy<") != std::string::npos;
        const bool degraded_pill = panel->body.find(">Degraded<") != std::string::npos;
        CHECK(healthy_pill == (status == "healthy"));
        CHECK(degraded_pill == (status != "healthy"));
    }
}

// ── #5906: the plaintext redirect listener's four probes ───────────────────

TEST_CASE("health_routes: with no plaintext sink nothing registers there and the main sink "
          "still has exactly 7 routes",
          "[server][routes][health_routes][plaintext]") {
    Harness h;
    h.wire();
    CHECK(h.plain_sink.route_count() == 0);
    CHECK(h.sink.route_count() == 7);
}

TEST_CASE("health_routes: a plaintext sink gets exactly the four probe routes",
          "[server][routes][health_routes][plaintext]") {
    Harness h;
    h.plain_wired = true;
    h.wire();
    CHECK(h.plain_sink.route_count() == 4);
    CHECK(h.sink.route_count() == 7);
    for (const char* path : {"/livez", "/readyz", "/health", "/api/health"}) {
        INFO("path: " << path);
        CHECK(h.plain_sink.Get(path) != nullptr);
    }
    CHECK(h.plain_sink.Get("/metrics") == nullptr);
    CHECK(h.plain_sink.Get("/fragments/health/summary") == nullptr);
}

TEST_CASE("health_routes: a plaintext sink without main_listener_serving_fn is a wiring bug and "
          "throws",
          "[server][routes][health_routes][plaintext]") {
    yuzu::server::test::TestRouteSink sink, plain;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    health::Deps deps;
    deps.cfg = &cfg;
    deps.metrics = &metrics;
    deps.auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        return std::nullopt;
    };
    deps.resolve_session_fn = [](const httplib::Request&) -> std::optional<auth::Session> {
        return std::nullopt;
    };
    deps.deny_service_scoped_fn = [](const httplib::Request&, httplib::Response&,
                                     const std::string&, const std::string&, const std::string&,
                                     const std::string&) -> bool { return false; };
    deps.plaintext_probe_sink = &plain;
    CHECK_THROWS_AS(health::register_health_routes(sink, deps), std::invalid_argument);
}

TEST_CASE("health_routes: plaintext /health never resolves a session - even with a valid cookie",
          "[server][routes][health_routes][plaintext]") {
    Harness h;
    h.plain_wired = true;
    h.wire(); // session_present defaults true

    for (const char* path : {"/health", "/api/health"}) {
        INFO("path: " << path);
        h.reset_gate_tracking();
        auto r = h.plain_sink.Get(path, {{"Authorization", "Bearer abc"}, {"Cookie", "session=x"}});
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(h.resolve_session_fn_called);
        CHECK_FALSE(h.auth_fn_called);
        auto body = json::parse(r->body);
        CHECK(body.contains("status"));
        CHECK(body.contains("uptime_seconds"));
        CHECK(body["agents"].contains("online"));
        CHECK_FALSE(body["agents"].contains("pending"));
        CHECK_FALSE(body.contains("executions"));
        CHECK_FALSE(body.contains("system"));
        // An allowlist, not just a denylist: a future unauthenticated top-level key would
        // otherwise start travelling over plaintext untested.
        std::set<std::string> keys;
        for (const auto& [k, v] : body.items())
            keys.insert(k);
        CHECK(keys == std::set<std::string>{"status", "uptime_seconds", "agents", "stores",
                                            "version", "tls"});
        CHECK(body["agents"] == json{{"online", 0}});
    }

    // The main sink on the same harness still shows the authenticated-only fields.
    auto main_r = h.sink.Get("/health");
    REQUIRE(main_r);
    auto main_body = json::parse(main_r->body);
    CHECK(main_body.contains("executions"));
    CHECK(main_body.contains("system"));
}

TEST_CASE("health_routes: plaintext /api/health has the same shape as plaintext /health",
          "[server][routes][health_routes][plaintext]") {
    Harness h;
    h.plain_wired = true;
    h.wire();
    auto a = h.plain_sink.Get("/health");
    auto b = h.plain_sink.Get("/api/health");
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->status == b->status);
    auto ja = json::parse(a->body);
    auto jb = json::parse(b->body);
    ja.erase("uptime_seconds");
    jb.erase("uptime_seconds");
    CHECK(ja == jb);
}

TEST_CASE("health_routes: every plaintext answer is 503 while the HTTPS listener is not serving",
          "[server][routes][health_routes][plaintext]") {
    Harness h;
    h.plain_wired = true;
    h.main_serving = false;
    h.wire();
    for (const char* path : {"/livez", "/readyz", "/health", "/api/health"}) {
        INFO("path: " << path);
        auto r = h.plain_sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 503);
        auto body = json::parse(r->body);
        CHECK(body["status"] == "not ready");
        CHECK(body["reason"] == "https_listener_not_serving");
    }
    auto main_livez = h.sink.Get("/livez"); // the main sink is not gated
    REQUIRE(main_livez);
    CHECK(main_livez->status == 200);
}

TEST_CASE("health_routes: plaintext /livez and /readyz are the main handlers once serving",
          "[server][routes][health_routes][plaintext]") {
    Harness h;
    h.plain_wired = true;
    h.wire();
    auto livez = h.plain_sink.Get("/livez");
    REQUIRE(livez);
    CHECK(livez->status == 200);
    CHECK(json::parse(livez->body)["status"] == "ok");

    h.draining = true;
    auto readyz = h.plain_sink.Get("/readyz");
    REQUIRE(readyz);
    CHECK(readyz->status == 503);
    CHECK(json::parse(readyz->body)["status"] == "draining");
}

TEST_CASE("health_routes: is_probe_path matches the closed set exactly",
          "[server][routes][health_routes][plaintext]") {
    for (const char* p : {"/livez", "/readyz", "/health", "/api/health"})
        CHECK(health::is_probe_path(p));
    for (const char* p : {"/livez/", "/health/detailed", "/LIVEZ", "", "/metrics", "/api/healthz"})
        CHECK_FALSE(health::is_probe_path(p));
}

TEST_CASE("health_routes: is_plaintext_probe_request admits GET/HEAD on a probe with no body "
          "headers",
          "[server][routes][health_routes][plaintext]") {
    auto make = [](const char* method, const char* path) {
        httplib::Request r;
        r.method = method;
        r.path = path;
        return r;
    };
    CHECK(health::is_plaintext_probe_request(make("GET", "/livez")));
    CHECK(health::is_plaintext_probe_request(make("HEAD", "/readyz")));
    CHECK_FALSE(health::is_plaintext_probe_request(make("POST", "/livez")));
    CHECK_FALSE(health::is_plaintext_probe_request(make("PUT", "/livez")));
    CHECK_FALSE(health::is_plaintext_probe_request(make("GET", "/login")));

    auto cl = make("GET", "/livez");
    cl.set_header("Content-Length", "0");
    CHECK_FALSE(health::is_plaintext_probe_request(cl));
    auto te = make("GET", "/livez");
    te.set_header("Transfer-Encoding", "chunked");
    CHECK_FALSE(health::is_plaintext_probe_request(te));
}

#ifndef YUZU_HEALTH_ROUTES_LIVE_TSAN
TEST_CASE("health_routes: the production redirect pre-routing serves probes and 301s the rest",
          "[server][routes][health_routes][plaintext][live]") {
    httplib::Server srv;
    health::install_plaintext_redirect_pre_routing(srv, "127.0.0.1", 8443);
    // The request counter's view: one (method, status) per response, recorded on the worker
    // thread before the reply is written.
    std::mutex seen_mu;
    std::vector<std::pair<std::string, int>> seen;
    health::install_plaintext_post_routing(
        srv, security::HeaderBundle::make("", /*https_enabled=*/false),
        [&](const httplib::Request& req, const httplib::Response& res) {
            std::lock_guard<std::mutex> lk(seen_mu);
            seen.emplace_back(req.method, res.status);
        });
    HttplibRouteSink plain{srv};

    Harness h;
    h.plain_override = &plain;
    h.wire();

    const int port = srv.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&] { srv.listen_after_bind(); });
    // Order is load-bearing: stop() is a no-op until the accept loop is running, so a
    // join() after an early stop() would hang. See test_mcp_body_cap.cpp for the full
    // account of why the wait sits inside the joinable() test.
    yuzu::test::ScopeExit joiner{[&] {
        if (th.joinable()) {
            srv.wait_until_ready();
            srv.stop();
            th.join();
        }
    }};
    srv.wait_until_ready();
    REQUIRE(srv.is_running());

    httplib::Client cli("127.0.0.1", port);
    cli.set_follow_location(false);
    // No content coding, so the HEAD Content-Length equals the decoded GET body size.
    cli.set_default_headers({{"Accept-Encoding", "identity"}});

    // The five security headers ride every answer, probe or redirect, and never HSTS.
    const auto expect_security_headers = [](const httplib::Result& r) {
        REQUIRE(r);
        CHECK(r->has_header("Content-Security-Policy"));
        CHECK(r->get_header_value("X-Frame-Options") == "DENY");
        CHECK(r->get_header_value("X-Content-Type-Options") == "nosniff");
        CHECK(r->has_header("Referrer-Policy"));
        CHECK(r->has_header("Permissions-Policy"));
        CHECK_FALSE(r->has_header("Strict-Transport-Security"));
    };
    // Exactly one counter observation per request, with that request's status.
    const auto counted = [&](std::size_t n, const char* method, int status) {
        std::lock_guard<std::mutex> lk(seen_mu);
        REQUIRE(seen.size() == n);
        CHECK(seen.back().first == method);
        CHECK(seen.back().second == status);
    };

    auto get = cli.Get("/livez");
    REQUIRE(get);
    CHECK(get->status == 200);
    CHECK(json::parse(get->body)["status"] == "ok");
    expect_security_headers(get);
    counted(1, "GET", 200);

    auto head = cli.Head("/livez");
    REQUIRE(head);
    CHECK(head->status == 200);
    CHECK(head->body.empty());
    CHECK(head->get_header_value("Content-Length") == std::to_string(get->body.size()));
    counted(2, "HEAD", 200);

    auto post = cli.Post("/livez", "", "application/json");
    REQUIRE(post);
    CHECK(post->status == 301);
    counted(3, "POST", 301);

    // A GET /livez carrying a Content-Length header (even 0) stays a 301:
    // is_plaintext_probe_request declines it. That httplib runs pre-routing before reading a
    // body (so this listener never buffers one) is a property of the pinned httplib, proven by
    // test_body_cap_policy.cpp's raw-socket case; this case proves only the predicate's answer.
    // Content-Length: 0 and no body byte: the predicate declines any Content-Length, and
    // sending a real byte to a listener that answers before reading it risks the RST that loses
    // the buffered reply on Windows (#2757, test_loopback_http.hpp).
    httplib::Request with_body;
    with_body.method = "GET";
    with_body.path = "/livez";
    with_body.set_header("Content-Length", "0");
    auto sent = cli.send(with_body);
    REQUIRE(sent);
    CHECK(sent->status == 301);
    counted(4, "GET", 301);

    auto login = cli.Get("/login");
    REQUIRE(login);
    CHECK(login->status == 301);
    CHECK(login->get_header_value("Location") == "https://127.0.0.1:8443/login");
    expect_security_headers(login);
    counted(5, "GET", 301);

    // A decoded control byte makes set_redirect a silent no-op (empty 200); it must answer 400.
    // Mutation: drop the status check in the redirect handler and this reads 200.
    auto ctrl = cli.Get("/livez%00");
    REQUIRE(ctrl);
    CHECK(ctrl->status == 400);
    counted(6, "GET", 400);

    // Two distinct request-line methods httplib REJECTS (400) are still handed to post-routing
    // with the raw token; the counter must collapse them into one label (#5906, adversarial
    // review round 3).
    // The client writes req.method verbatim and no body byte is sent (no #2757 RST hazard).
    // This case injects its own callback, so it cannot observe the production lambda: it proves
    // the parser hands rejected tokens to post-routing and that http_method_label collapses
    // them; the production wiring is pinned by the server.cpp tripwire below.
    for (const char* bad : {"BAD000001", "BAD000002"}) {
        httplib::Request r;
        r.method = bad;
        r.path = "/";
        auto rejected = cli.send(r);
        REQUIRE(rejected);
        CHECK(rejected->status == 400);
    }
    {
        std::lock_guard<std::mutex> lk(seen_mu);
        REQUIRE(seen.size() == 8);
        CHECK(seen[6].first == "BAD000001");
        CHECK(seen[7].first == "BAD000002");
        CHECK(seen[6].second == 400);
        CHECK(seen[7].second == 400);
        CHECK(http_method_label(seen[6].first) == "UNKNOWN");
        CHECK(http_method_label(seen[7].first) == "UNKNOWN");
    }

    auto query = cli.Get("/login?x=1");
    REQUIRE(query);
    CHECK(query->status == 301);
    counted(9, "GET", 301);
    const auto loc = query->get_header_value("Location");
    CHECK(loc.size() >= 4);
    CHECK(loc.substr(loc.size() - 4) == "?x=1");

    h.main_serving = false;
    auto down = cli.Get("/readyz");
    REQUIRE(down);
    CHECK(down->status == 503);
    CHECK(json::parse(down->body)["reason"] == "https_listener_not_serving");
    expect_security_headers(down);
    counted(10, "GET", 503);
}
#endif // !YUZU_HEALTH_ROUTES_LIVE_TSAN
