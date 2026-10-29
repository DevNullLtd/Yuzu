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
///   - /health, /api/health call ONLY resolve_session_fn (non-blocking), and only
///     when the request carries a Cookie, Authorization or X-Yuzu-Token header;
///     always 200, response SHAPE differs by session presence. A request with no
///     credential header makes ZERO resolve_session_fn calls.
///   - /fragments/health/summary calls deny_service_scoped_fn THEN auth_fn
///     (blocking) — one of the two routes in this cluster that gate on a session
///     (with /fragments/dashboard/health).

#include "enablement_store.hpp"
#include "health_routes.hpp"
#include "http_route_sink.hpp"
#include "key_provider.hpp"
#include "leader_elector.hpp"
#include "leader_metrics.hpp"
#include "pg/secret_codec.hpp"
#include "pg_reachability_probe.hpp"
#include "plugin_config_store.hpp"
#include "principal_class.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include "agent_registry.hpp"
#include "default_certs.hpp"
#include "event_bus.hpp"
#include "nvd_db.hpp"
#include "pg/pg_pool.hpp"
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
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <utility>
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
    const LeaderElector* leader{nullptr}; // HA WS-11: /metrics only; null = no elector
    const std::atomic<std::uint64_t>* leader_loop_errors{nullptr}; // HA WS-11
    NvdDatabase* nvd_db{nullptr}; // null unless a case wires one
    EnablementStore* enablement_store{nullptr}; // null unless a case wires one

    bool session_present{true};
    std::string session_username{"alice"};
    bool auth_fn_called{false};
    bool resolve_session_fn_called{false};
    int resolve_session_calls{0};

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
            ++resolve_session_calls;
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
        deps.leader_elector = leader;
        deps.leader_loop_errors = leader_loop_errors;
        deps.server_start_time = std::chrono::steady_clock::now();
        deps.nvd_db = nvd_db;
        deps.enablement_store = enablement_store;
        deps.plaintext_probe_sink =
            plain_override ? plain_override : (plain_wired ? &plain_sink : nullptr);
        deps.main_listener_serving_fn = [this] { return main_serving.load(); };
        // Every other store pointer stays null — see file header comment.
        health::register_health_routes(sink, deps);
    }

    void reset_gate_tracking() {
        auth_fn_called = false;
        resolve_session_fn_called = false;
        resolve_session_calls = 0;
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
    // ADR-0070 R1: the registered-CRL-source store is GATING (fail-closed at boot), unlike the
    // /crypto layout store: a null pointer here is a failed store, never a "degraded" notice.
    CHECK(std::find(failed.begin(), failed.end(), "revocation_source_store") != failed.end());
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

// ── ADR-3006: the enablement store on /readyz and /healthz ──────────────

namespace {
// A store that is NOT open (an unparseable DSN gives an invalid pool), so the cases below need
// no Postgres: only the I/O-free regression cache and the open/not-open verdict are exercised.
struct ClosedEnablementStore {
    yuzu::server::pg::PgPool pool{{.conninfo = "this is not a conninfo string"}};
    EnablementStore store{pool, enablement::UnitOverlay{}, {}};
};

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + 1))
        ++n;
    return n;
}
} // namespace

TEST_CASE("health_routes: GET /readyz fails on a null or not-open enablement_store and names it",
          "[server][routes][health_routes][enablement]") {
    SECTION("null: listed and no `enablement` member at all") {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/readyz");
        REQUIRE(r);
        CHECK(r->status == 503);
        const auto body = json::parse(r->body);
        const auto failed = body["failed_stores"].get<std::vector<std::string>>();
        CHECK(std::find(failed.begin(), failed.end(), "enablement_store") != failed.end());
        CHECK_FALSE(body.contains("enablement"));
    }
    SECTION("wired but not open: still listed") {
        ClosedEnablementStore closed;
        REQUIRE_FALSE(closed.store.is_open());
        Harness h;
        h.enablement_store = &closed.store;
        h.wire();
        auto r = h.sink.Get("/readyz");
        REQUIRE(r);
        CHECK(r->status == 503);
        const auto failed = json::parse(r->body)["failed_stores"].get<std::vector<std::string>>();
        CHECK(std::find(failed.begin(), failed.end(), "enablement_store") != failed.end());
    }
}

TEST_CASE("health_routes: GET /readyz carries exactly one `enablement` object with three booleans "
          "that reflect the cache",
          "[server][routes][health_routes][enablement]") {
    ClosedEnablementStore closed;
    Harness h;
    h.enablement_store = &closed.store;
    h.wire();

    const auto fetch = [&] {
        auto r = h.sink.Get("/readyz");
        REQUIRE(r);
        return r->body;
    };

    SECTION("all quiet") {
        const auto raw = fetch();
        CHECK(count_of(raw, "\"enablement\"") == 1); // never two members with the same key
        const auto e = json::parse(raw)["enablement"];
        CHECK(e["regression_pending"] == false);
        CHECK(e["anchor_unwitnessed_at_boot"] == false);
        CHECK(e["report_ahead"] == false);
    }
    SECTION("all three at once are all visible and none changes the verdict") {
        // The verdict is derived solely from `failed_stores`, so that is what is pinned: with the
        // store closed the body is "not ready" in every case and none of these states may add an
        // entry. A mutant folding a regression into the `enablement_store` row needs an OPEN
        // store to tell apart: the [pg] case below pins that.
        const auto quiet = json::parse(fetch());
        const auto baseline = quiet["failed_stores"];
        const auto baseline_status = quiet["status"];
        REQUIRE(baseline.is_array());
        CHECK(baseline_status == "not ready");

        for (const auto& [label, st] :
             std::vector<std::pair<const char*, EnablementStore::RegressionState>>{
                 {"regressed alone", {.regressed = true, .reason = "store_behind"}},
                 {"unwitnessed alone", {.anchor_unwitnessed = true}},
                 {"report-ahead alone", {.report_ahead_endpoints = 3}},
                 {"all three",
                  {.regressed = true,
                   .reason = "store_behind",
                   .anchor_unwitnessed = true,
                   .report_ahead_endpoints = 3}}}) {
            INFO(label);
            closed.store.set_regression_state_for_test(st);
            const auto raw = fetch();
            CHECK(count_of(raw, "\"enablement\"") == 1);
            const auto body = json::parse(raw);
            CHECK(body["failed_stores"] == baseline);
            CHECK(body["status"] == baseline_status);
            CHECK(body["enablement"]["regression_pending"] == st.regressed);
            CHECK(body["enablement"]["anchor_unwitnessed_at_boot"] == st.anchor_unwitnessed);
            CHECK(body["enablement"]["report_ahead"] == (st.report_ahead_endpoints > 0));
        }
    }
}

TEST_CASE("health_routes: /health lists plugin_config_store and enablement_store and flags a regression",
          "[server][routes][health_routes][enablement]") {
    ClosedEnablementStore closed;
    Harness h;
    h.session_present = false;
    h.enablement_store = &closed.store;
    h.wire();

    auto r = h.sink.Get("/health");
    REQUIRE(r);
    auto body = json::parse(r->body);
    CHECK(body["status"] == "degraded");
    CHECK(body["stores"]["plugin_config_store"] == "error"); // null here: not open
    CHECK(body["stores"]["enablement_store"] == "error");    // wired but not open
    CHECK(body["enablement_regressed"] == false);

    EnablementStore::RegressionState st;
    st.regressed = true;
    closed.store.set_regression_state_for_test(st);
    body = json::parse(h.sink.Get("/health")->body);
    CHECK(body["enablement_regressed"] == true);

    // Unwired entirely: the flag is present and false.
    Harness bare;
    bare.session_present = false;
    bare.wire();
    CHECK(json::parse(bare.sink.Get("/api/health")->body)["enablement_regressed"] == false);
}

namespace {
// A pre-migrated clone for the one health case that needs an OPEN enablement store: the
// plugin_config_store v1..v3 schema the store smoke-reads.
yuzu::test::PgTestTemplate health_enablement_tpl{"health_enablement", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore pcs{pool, codec};
    if (!pcs.is_open())
        throw std::runtime_error("health enablement template: plugin_config_store did not migrate");
}};
} // namespace

TEST_CASE("health_routes: a declared regression on an OPEN enablement store never gates readiness",
          "[server][pg][routes][health_routes][enablement]") {
    YUZU_REQUIRE_PG_DB_TPL(db, health_enablement_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    EnablementStore store{pool, enablement::UnitOverlay{}, {}};
    REQUIRE(store.is_open());

    const auto failed_of = [](const std::string& raw) {
        return json::parse(raw)["failed_stores"].get<std::vector<std::string>>();
    };
    const auto lists = [](const std::vector<std::string>& v, const char* name) {
        return std::find(v.begin(), v.end(), name) != v.end();
    };

    // Baseline: the same harness with the store unwired lists it. Every other store is unwired
    // too (the harness wires none), so the body is "not ready" throughout and the verdict is
    // read from `failed_stores`: the ONLY difference an open store may make is leaving this list.
    Harness unwired;
    unwired.wire();
    const auto unwired_failed = failed_of(unwired.sink.Get("/readyz")->body);
    REQUIRE(lists(unwired_failed, "enablement_store"));

    Harness h;
    h.enablement_store = &store;
    h.wire();
    auto quiet = h.sink.Get("/readyz");
    REQUIRE(quiet);
    const auto quiet_failed = failed_of(quiet->body);
    CHECK_FALSE(lists(quiet_failed, "enablement_store"));
    CHECK(quiet_failed.size() + 1 == unwired_failed.size());
    CHECK(json::parse(quiet->body)["enablement"]["regression_pending"] == false);

    // Declare a regression through the store, as the boot continuity check does.
    REQUIRE(store.set_regressed("store_behind"));
    auto declared = h.sink.Get("/readyz");
    REQUIRE(declared);
    const auto body = json::parse(declared->body);
    CHECK(failed_of(declared->body) == quiet_failed); // still not listed: it does not gate
    CHECK(body["enablement"]["regression_pending"] == true);
    CHECK(body["enablement"]["anchor_unwitnessed_at_boot"] == false);
    CHECK(body["enablement"]["report_ahead"] == false);

    // /health agrees: the store is ok, and the regression is reported next to it.
    h.session_present = false;
    const auto health = json::parse(h.sink.Get("/health")->body);
    CHECK(health["stores"]["enablement_store"] == "ok");
    CHECK(health["enablement_regressed"] == true);
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
        CHECK(h.resolve_session_calls == 0); // no credential header: no session lookup
        CHECK_FALSE(h.auth_fn_called);       // and the blocking gate never runs
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

    auto r = h.sink.Get("/health", {{"Cookie", "yuzu_session=abc"}});
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

TEST_CASE("health_routes: /health and /api/health resolve a session only for a request that "
          "carries a credential header",
          "[server][routes][health_routes]") {
    Harness h;
    h.wire(); // a session WOULD resolve, so any skipped call is the guard's doing

    for (const std::string& path : {std::string("/health"), std::string("/api/health")}) {
        INFO("path: " << path);

        // No credential at all: zero resolve_session_fn calls, unauthenticated body.
        h.reset_gate_tracking();
        auto bare = h.sink.Get(path);
        REQUIRE(bare);
        CHECK(bare->status == 200);
        CHECK(h.resolve_session_calls == 0);
        auto bare_body = json::parse(bare->body);
        CHECK_FALSE(bare_body["agents"].contains("pending"));
        CHECK_FALSE(bare_body.contains("executions"));
        CHECK_FALSE(bare_body.contains("system"));

        // Headers that are not credentials do not count.
        h.reset_gate_tracking();
        auto other = h.sink.Get(path, {{"Accept", "application/json"}, {"User-Agent", "probe"}});
        REQUIRE(other);
        CHECK(h.resolve_session_calls == 0);

        // Each credential source resolve_session reads still resolves, exactly once, and
        // gets the authenticated body.
        const std::vector<std::pair<std::string, std::string>> credentials{
            {"Cookie", "yuzu_session=abc"},
            {"Authorization", "Bearer abc"},
            {"X-Yuzu-Token", "abc"}};
        for (const auto& [name, value] : credentials) {
            INFO("header: " << name);
            h.reset_gate_tracking();
            auto r = h.sink.Get(path, {{name, value}});
            REQUIRE(r);
            CHECK(r->status == 200);
            CHECK(h.resolve_session_calls == 1);
            auto body = json::parse(r->body);
            CHECK(body["agents"].contains("pending"));
            CHECK(body.contains("executions"));
            CHECK(body.contains("system"));
        }

        // A credential that does not resolve still yields the unauthenticated body.
        h.session_present = false;
        h.reset_gate_tracking();
        auto stale = h.sink.Get(path, {{"Cookie", "yuzu_session=stale"}});
        REQUIRE(stale);
        CHECK(h.resolve_session_calls == 1);
        CHECK_FALSE(json::parse(stale->body).contains("system"));
        h.session_present = true;
    }
}

TEST_CASE("health_routes: request_carries_credential matches the three sources resolve_session reads",
          "[server][routes][health_routes]") {
    httplib::Request none;
    CHECK_FALSE(health::request_carries_credential(none));
    for (const char* name : {"Cookie", "Authorization", "X-Yuzu-Token"}) {
        INFO("header: " << name);
        httplib::Request r;
        r.set_header(name, "x");
        CHECK(health::request_carries_credential(r));
    }
    httplib::Request unrelated;
    unrelated.set_header("Accept", "*/*");
    CHECK_FALSE(health::request_carries_credential(unrelated));
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
// Source-text pin helpers. `strip_comments` drops `//` and `/* */` comments from C++ source
// (string, character and raw-string literals are kept verbatim, so a literal that merely
// contains `//` is not truncated) so a pin cannot be satisfied by commented-out code. It
// understands: ordinary strings with escapes; raw strings with an optional encoding prefix
// (`R"`, `u8R"`, `uR"`, `UR"`, `LR"`); character literals with an optional encoding prefix
// (`'x'`, `L'x'`, `u'x'`, `U'x'`, `u8'x'`); digit separators (`1'000`), which are not
// character literals; and a `//` comment continued onto the next line by a trailing
// backslash. It is a lexer for the shapes this repo uses, not a full preprocessor; the
// self-test case below states exactly which shapes are covered.
// ═══════════════════════════════════════════════════════════════════════════
namespace {

bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

// The identifier run that ends just before index `i` (empty when in[i-1] is not an
// identifier character).
std::string ident_run_before(const std::string& in, std::size_t i) {
    std::size_t k = i;
    while (k > 0 && is_ident_char(in[k - 1]))
        --k;
    return in.substr(k, i - k);
}

// True when the run is empty or is exactly an encoding prefix, i.e. a following `R"` or `'`
// opens a literal rather than continuing an identifier or a number.
bool opens_literal(const std::string& run) {
    return run.empty() || run == "u8" || run == "u" || run == "U" || run == "L";
}

std::string strip_comments(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    std::size_t i = 0;
    while (i < in.size()) {
        const char c = in[i];
        if (c == '/' && i + 1 < in.size() && in[i + 1] == '/') {
            // Line comment; a trailing backslash (optionally before a CR) continues it.
            while (i < in.size()) {
                if (in[i] == '\n') {
                    const bool continued = (i >= 1 && in[i - 1] == '\\') ||
                                           (i >= 2 && in[i - 1] == '\r' && in[i - 2] == '\\');
                    if (!continued)
                        break;
                }
                ++i;
            }
        } else if (c == '/' && i + 1 < in.size() && in[i + 1] == '*') {
            const auto end = in.find("*/", i + 2);
            i = end == std::string::npos ? in.size() : end + 2;
            out.push_back(' ');
        } else if (c == 'R' && i + 1 < in.size() && in[i + 1] == '"' &&
                   opens_literal(ident_run_before(in, i))) {
            // Raw string: R"delim( ... )delim" (any encoding prefix is already in `out`).
            const auto open = in.find('(', i + 2);
            if (open == std::string::npos) {
                out.append(in, i, std::string::npos);
                break;
            }
            const std::string close = ")" + in.substr(i + 2, open - (i + 2)) + "\"";
            const auto end = in.find(close, open + 1);
            const auto stop = end == std::string::npos ? in.size() : end + close.size();
            out.append(in, i, stop - i);
            i = stop;
        } else if (c == '"' || (c == '\'' && opens_literal(ident_run_before(in, i)))) {
            // Ordinary string or character literal. A `'` inside an identifier or number
            // (`1'000`) is a digit separator, not a literal.
            std::size_t j = i + 1;
            while (j < in.size() && in[j] != c) {
                if (in[j] == '\\')
                    ++j;
                ++j;
            }
            const auto stop = std::min(j + 1, in.size());
            out.append(in, i, stop - i);
            i = stop;
        } else {
            out.push_back(c);
            ++i;
        }
    }
    return out;
}

std::string squeeze_ws(std::string s) {
    std::erase_if(s, [](unsigned char c) { return std::isspace(c) != 0; });
    return s;
}

std::string read_server_src(const char* file) {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / file);
    REQUIRE(in.is_open());
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("health_routes: the source-text pin lexer strips comments and keeps literals",
          "[server][routes][health_routes]") {
    const auto check = [](const std::string& in, const std::string& want) {
        INFO("input: " << in);
        CHECK(strip_comments(in) == want);
    };

    SECTION("a line comment is dropped, the newline stays") {
        check("a; // c\nb;\n", "a; \nb;\n");
    }
    SECTION("// inside an ordinary string is kept; the real comment after it is dropped") {
        check("x = \"a // b\"; // c\n", "x = \"a // b\"; \n");
    }
    SECTION("an escaped quote does not end a string early") {
        check("x = \"a\\\" // b\"; // c\n", "x = \"a\\\" // b\"; \n");
    }
    SECTION("a block comment becomes one space; /* */ inside a string is kept") {
        check("s = \"/* x */\" /* real */ y;", "s = \"/* x */\"   y;");
        check("/* a // b */ c", "  c");
    }
    SECTION("a raw string holding quotes and // is kept whole") {
        // Both an odd and an even number of quotes: with an odd number, reading the raw
        // string as an ordinary one would leave a quote open and swallow the real comment
        // boundary, so the output would differ.
        check("auto s = R\"x(he said \"hi\" // not)x\"; // c\nint y;",
              "auto s = R\"x(he said \"hi\" // not)x\"; \nint y;");
        check("auto s = R\"x(a \" // not)x\"; // c\nint y;",
              "auto s = R\"x(a \" // not)x\"; \nint y;");
    }
    SECTION("an encoding-prefixed raw string is a raw string") {
        for (const char* prefix : {"u8R", "uR", "UR", "LR"}) {
            // One quote inside: only a correct raw-string read keeps the quotes balanced.
            const std::string in =
                std::string("auto s = ") + prefix + "\"(a \" // z)\"; // c\nint y;";
            const std::string want =
                std::string("auto s = ") + prefix + "\"(a \" // z)\"; \nint y;";
            check(in, want);
        }
    }
    SECTION("an identifier ending in R is not a raw string prefix") {
        // `fooR"` is the identifier `fooR` followed by an ordinary string; the quote inside
        // the ordinary string's escape must not be read as a raw delimiter.
        check("fooR\"a\\\"b\" // c\n", "fooR\"a\\\"b\" \n");
    }
    SECTION("digit separators are not character literals") {
        check("int n = 1'000'000; // c\n", "int n = 1'000'000; \n");
        check("int h = 0xFF'FF; // c\n", "int h = 0xFF'FF; \n");
    }
    SECTION("a character literal holding a quote does not open a string") {
        check("char q = '\"'; // c\n", "char q = '\"'; \n");
    }
    SECTION("an encoding-prefixed character literal holding a quote is a literal") {
        for (const char* prefix : {"L", "u", "U", "u8"}) {
            const std::string in = std::string("auto q = ") + prefix + "'\"'; // c\nint y;";
            const std::string want = std::string("auto q = ") + prefix + "'\"'; \nint y;";
            check(in, want);
        }
    }
    SECTION("a // comment continued by a trailing backslash swallows the next line") {
        check("a // c \\\n still comment\nb\n", "a \nb\n");
        check("a // c \\\r\n still comment\r\nb\n", "a \nb\n");
        // A backslash that is not the last character on the line does not continue it.
        check("a // c \\ x\nb\n", "a \nb\n");
    }
    SECTION("an unterminated block comment drops the rest of the input") {
        check("a /* never closed", "a  ");
    }
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
    const std::string src = read_server_src("server.cpp");

    // Comments are dropped first so a needle that only survives inside a comment, such as a
    // call that was commented out, cannot satisfy the pin. The lexer has its own self-test
    // below.
    const std::string code = strip_comments(src);
    CHECK(code.find("register_health_routes(") != std::string::npos);

    // Compare with all whitespace removed so a clang-format re-wrap of a call site
    // can neither redden nor greenwash the tripwire.
    const auto squeeze = [](std::string s) { return squeeze_ws(std::move(s)); };
    const auto flat = squeeze(code);
    const auto occurrences = [&](const std::string& needle) {
        // A needle that spells an inline argument-name comment is compared as code too.
        const auto n = squeeze(strip_comments(needle));
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
    // The /health + /api/health per-source budget is checked inside the probe branch, once,
    // on the `--rate-limit` limiter, before the body cap; the general 429 body has one
    // definition (write_rate_limited_response), not a second literal in server.cpp.
    // The refusal must actually end the request: a call whose result is ignored, or whose
    // `return` was dropped, would still compile and still charge the bucket.
    expect("if (!yuzu::server::health::admit_probe_request(api_rate_limiter_, req, res)) "
           "return httplib::Server::HandlerResponse::Handled;",
           1, "the pre-routing probe branch applies the /health rate limit and returns Handled");
    // The whole probe branch, contiguous: budget (refusal ends the request), then the body cap
    // (refusal ends the request), then the exempt-from-the-rest return. Being one contiguous
    // needle that must occur exactly once, it also fixes the order branch < budget < cap, so
    // no separate position comparison is needed.
    expect("if (yuzu::server::health::is_probe_path(req.path)) { "
           "if (!yuzu::server::health::admit_probe_request(api_rate_limiter_, req, res)) "
           "return httplib::Server::HandlerResponse::Handled; "
           "if (enforce_pre_auth_body_cap()) "
           "return httplib::Server::HandlerResponse::Handled; "
           "return httplib::Server::HandlerResponse::Unhandled; }",
           1, "the probe branch is: budget, then body cap, then Unhandled");
    expect("rate limit exceeded", 0, "the 429 body lives only in write_rate_limited_response");
    expect("write_rate_limited_response(res);", 1,
           "the general limiter site uses the shared 429 writer");
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

// ═══════════════════════════════════════════════════════════════════════════
// Credential-source pin. `health::request_carries_credential` decides which /health and
// /api/health requests resolve a session and are charged against the per-source budget; it
// must name exactly the headers `AuthRoutes::resolve_session` reads. The behavioural case
// above checks that the three known names count; it cannot notice a FOURTH header being
// added to resolve_session. This case reads both sources as text (comments stripped by the
// lexer pinned above) and compares the header names they read.
//
// Known limits of this pin:
//  - It sees only header reads written directly in the bodies of resolve_session and
//    extract_session_cookie. A header read made through a new helper function or macro is
//    not seen, and the mirror comment inside resolve_session is the remaining guard. The
//    req-argument check below narrows this (a new helper taking `req` fails the pin) but
//    cannot close it (a helper reached through a captured or stored request is not seen).
//  - A `//` comment ending with a backslash plus trailing whitespace is not treated as a
//    line continuation by strip_comments.
//  - function_body does not skip raw string literals when it counts braces.
// ═══════════════════════════════════════════════════════════════════════════
namespace {

// Body (outer braces excluded) of the one function in comment-stripped `code` whose
// definition contains `signature`; nullopt when it is absent, ambiguous or unbalanced.
// String and character literals are skipped while counting braces; raw strings are not
// handled, which is fine for the small bodies this is pointed at.
std::optional<std::string> function_body(const std::string& code, const std::string& signature) {
    const auto at = code.find(signature);
    if (at == std::string::npos || code.find(signature, at + 1) != std::string::npos)
        return std::nullopt;
    const auto open = code.find('{', at + signature.size());
    if (open == std::string::npos)
        return std::nullopt;
    int depth = 0;
    for (std::size_t i = open; i < code.size(); ++i) {
        const char c = code[i];
        if (c == '"' || (c == '\'' && opens_literal(ident_run_before(code, i)))) {
            std::size_t j = i + 1;
            while (j < code.size() && code[j] != c) {
                if (code[j] == '\\')
                    ++j;
                ++j;
            }
            i = j;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}' && --depth == 0) {
            return code.substr(open + 1, i - open - 1);
        }
    }
    return std::nullopt;
}

// Lower-cased header names a function body reads through `get_header_value*(` or
// `has_header(`. A call whose argument is not a string literal, or any direct use of the
// header map, is reported as a marker no expected set contains, so it fails loudly.
std::set<std::string> header_names_read(const std::string& body) {
    std::set<std::string> names;
    const auto lower = [](std::string v) {
        std::transform(v.begin(), v.end(), v.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return v;
    };
    for (const std::string call : {"get_header_value", "has_header"}) {
        for (auto pos = body.find(call); pos != std::string::npos; pos = body.find(call, pos + 1)) {
            // Skip the rest of an identifier such as get_header_value_count, then whitespace.
            auto k = pos + call.size();
            while (k < body.size() && is_ident_char(body[k]))
                ++k;
            while (k < body.size() && std::isspace(static_cast<unsigned char>(body[k])) != 0)
                ++k;
            if (k >= body.size() || body[k] != '(') {
                names.insert("<unrecognised use of " + call + ">");
                continue;
            }
            ++k;
            while (k < body.size() && std::isspace(static_cast<unsigned char>(body[k])) != 0)
                ++k;
            const auto close = k < body.size() && body[k] == '"' ? body.find('"', k + 1)
                                                                 : std::string::npos;
            if (close == std::string::npos)
                names.insert("<non-literal argument to " + call + ">");
            else
                names.insert(lower(body.substr(k + 1, close - k - 1)));
        }
    }
    for (const char* raw : {".headers", "get_header_map"}) {
        if (body.find(raw) != std::string::npos)
            names.insert(std::string("<direct use of ") + raw + ">");
    }
    return names;
}

// Names of the functions a body passes the request `req` to as an argument: for each use of
// the identifier `req` that is not a member access (`req.`), the identifier before the
// nearest unmatched '(' to its left. A use with no enclosing call is reported as
// "<not a call argument>" so it fails loudly.
std::set<std::string> req_argument_callees(const std::string& body) {
    std::set<std::string> callees;
    for (auto pos = body.find("req"); pos != std::string::npos; pos = body.find("req", pos + 1)) {
        const bool starts_ident = pos == 0 || !is_ident_char(body[pos - 1]);
        const auto end = pos + 3;
        if (!starts_ident || (end < body.size() && is_ident_char(body[end])))
            continue;
        auto after = end;
        while (after < body.size() && std::isspace(static_cast<unsigned char>(body[after])) != 0)
            ++after;
        if (after < body.size() && body[after] == '.')
            continue; // member access: header_names_read covers the header reads
        int depth = 0;
        std::size_t open = std::string::npos;
        for (std::size_t i = pos; i > 0; --i) {
            const char c = body[i - 1];
            if (c == ')') {
                ++depth;
            } else if (c == '(' && depth-- == 0) {
                open = i - 1;
                break;
            }
        }
        if (open == std::string::npos) {
            callees.insert("<not a call argument>");
            continue;
        }
        auto name_end = open;
        while (name_end > 0 && std::isspace(static_cast<unsigned char>(body[name_end - 1])) != 0)
            --name_end;
        auto name_begin = name_end;
        while (name_begin > 0 && is_ident_char(body[name_begin - 1]))
            --name_begin;
        callees.insert(body.substr(name_begin, name_end - name_begin));
    }
    return callees;
}

std::string join_names(const std::set<std::string>& names) {
    std::string out;
    for (const auto& n : names)
        out += (out.empty() ? "" : ", ") + n;
    return out;
}

} // namespace

TEST_CASE("health_routes: resolve_session and request_carries_credential read the same credential "
          "headers",
          "[server][routes][health_routes]") {
    const std::set<std::string> expected{"cookie", "authorization", "x-yuzu-token"};
    const std::string how_to_fix =
        "Update BOTH AuthRoutes::resolve_session (auth_routes.cpp) and "
        "health::request_carries_credential (health_routes.hpp), then this test's expected set.";

    const auto auth_code = strip_comments(read_server_src("auth_routes.cpp"));
    // The credential walk lives in `resolve_session_unbound`; `resolve_session` wraps it with the
    // per-request principal binding (pinned below).
    const auto resolve = function_body(
        auth_code, "AuthRoutes::resolve_session_unbound(const httplib::Request& req)");
    REQUIRE(resolve.has_value()); // signature moved or renamed: re-point this pin
    const auto wrapper = function_body(
        auth_code, "AuthRoutes::resolve_session(const httplib::Request& req)");
    REQUIRE(wrapper.has_value());
    const auto cookie_fn = function_body(
        auth_code, "AuthRoutes::extract_session_cookie(const httplib::Request& req)");
    REQUIRE(cookie_fn.has_value());
    const auto health_code = strip_comments(read_server_src("health_routes.hpp"));
    const auto probe_fn = function_body(
        health_code, "request_carries_credential(const httplib::Request& req)");
    REQUIRE(probe_fn.has_value());

    // resolve_session reads the cookie only through extract_session_cookie, which itself
    // must read nothing but the Cookie header.
    CHECK(resolve->find("extract_session_cookie(") != std::string::npos);
    const auto cookie_reads = header_names_read(*cookie_fn);
    INFO("extract_session_cookie reads: " << join_names(cookie_reads) << ". " << how_to_fix);
    CHECK(cookie_reads == std::set<std::string>{"cookie"});

    auto resolve_reads = header_names_read(*resolve);
    resolve_reads.insert("cookie"); // via extract_session_cookie, checked above
    INFO("resolve_session reads: " << join_names(resolve_reads) << ". " << how_to_fix);
    CHECK(resolve_reads == expected);

    // A helper that takes the request could read a header this pin cannot see. The only
    // functions resolve_session may hand `req` to: extract_session_cookie (checked above) and
    // audit_log_for_principal (builds an audit row; reads User-Agent and, through
    // extract_session_cookie, the session cookie, and no other credential header).
    const std::set<std::string> req_callees_allowed{"extract_session_cookie",
                                                    "audit_log_for_principal"};
    const auto req_callees = req_argument_callees(*resolve);
    INFO("resolve_session passes req to: " << join_names(req_callees) << ". " << how_to_fix);
    for (const auto& callee : req_callees)
        CHECK(req_callees_allowed.count(callee) == 1);

    const auto probe_reads = header_names_read(*probe_fn);
    INFO("request_carries_credential names: " << join_names(probe_reads) << ". " << how_to_fix);
    CHECK(probe_reads == expected);

    // The wrapper reads no credential itself: it walks via `resolve_session_unbound` and applies
    // the per-request binding to whatever that returns, so no path of the walk can skip it.
    CHECK(header_names_read(*wrapper).empty());
    const std::set<std::string> wrapper_callees{"resolve_session_unbound",
                                                "step_up_binding_admits"};
    CHECK(req_argument_callees(*wrapper) == wrapper_callees);
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
// HA WS-11 (#4014): leader-election observability on /metrics, and the recorded
// decision that LEADERSHIP IS NOT READINESS.
// ---------------------------------------------------------------------------

namespace {
// A fail-closed elector (empty dsn) is constructible with no Postgres and is the
// "elector never opened" condition the YuzuLeaderNoLeader alert exists for.
std::unique_ptr<LeaderElector> make_closed_elector() {
    return std::make_unique<LeaderElector>(
        LeaderElector::Config{.dsn = "", .holder_id = "holder-a"});
}
} // namespace

TEST_CASE("health_routes: /metrics exports the seeded leader series for a non-open elector",
          "[server][routes][health_routes][leader-metrics]") {
    auto elector = make_closed_elector();
    REQUIRE_FALSE(elector->is_open());
    (void)elector->try_acquire(); // one failed connect attempt
    std::atomic<std::uint64_t> loop_errors{3};
    Harness h;
    seed_leader_metrics(h.metrics);
    h.leader = elector.get();
    h.leader_loop_errors = &loop_errors;
    h.wire();
    auto r = h.sink.Get("/metrics");
    REQUIRE(r);
    CHECK(r->body.find("yuzu_server_leader_is_leader 0\n") != std::string::npos);
    CHECK(r->body.find("yuzu_server_leader_epoch 0\n") != std::string::npos);
    CHECK(r->body.find("yuzu_server_leader_acquire_failures_total{cause=\"connect\"} 1\n") !=
          std::string::npos);
    CHECK(r->body.find("yuzu_server_leader_acquire_failures_total{cause=\"lock_query\"} 0\n") !=
          std::string::npos);
    CHECK(r->body.find("yuzu_server_leader_loop_errors_total 3\n") != std::string::npos);
    // Never answered a query: ABSENT, not a fabricated 0.
    CHECK(r->body.find("yuzu_server_leader_last_ok_age_seconds ") == std::string::npos);

    // A second scrape of an unchanged elector does not move the counters.
    auto r2 = h.sink.Get("/metrics");
    REQUIRE(r2);
    CHECK(r2->body.find("yuzu_server_leader_acquire_failures_total{cause=\"connect\"} 1\n") !=
          std::string::npos);
    // The next failed attempt shows on the next scrape (pull model).
    (void)elector->try_acquire();
    auto r3 = h.sink.Get("/metrics");
    REQUIRE(r3);
    CHECK(r3->body.find("yuzu_server_leader_acquire_failures_total{cause=\"connect\"} 2\n") !=
          std::string::npos);
}

TEST_CASE("health_routes: /metrics with no elector wired exports no leader series and survives",
          "[server][routes][health_routes][leader-metrics]") {
    Harness h; // leader == nullptr, nothing seeded: a server with no elector
    h.wire();
    auto r = h.sink.Get("/metrics");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("yuzu_server_leader_") == std::string::npos);
}

TEST_CASE("health_routes: LEADERSHIP IS NOT READINESS -- a non-open elector changes neither "
          "/readyz nor /health",
          "[server][routes][health_routes][readyz][leader-metrics]") {
    // DECISION PIN (#4014, extended to "the elector is not open"): a replica that
    // cannot lead is a ready follower. The harness cannot make every store ok (they
    // need Postgres), so the pin compares the full response with and without a
    // non-open elector wired: any readiness input derived from the elector changes
    // the status, a body field, or the failed list.
    auto elector = make_closed_elector();
    REQUIRE_FALSE(elector->is_open());
    PgReachabilityProbe probe(fixed_ping(PgReachabilityProbe::PingResult::Kind::Ok));
    probe.probe_once();

    Harness without;
    without.pg_probe = &probe;
    without.wire();
    Harness with;
    with.pg_probe = &probe;
    with.leader = elector.get();
    with.wire();

    for (const char* path : {"/readyz", "/health"}) {
        INFO(path);
        auto a = without.sink.Get(path);
        auto b = with.sink.Get(path);
        REQUIRE(a);
        REQUIRE(b);
        CHECK(a->status == b->status);
        auto ja = json::parse(a->body);
        auto jb = json::parse(b->body);
        // Volatile fields (uptime) legitimately differ between two harnesses.
        for (auto* j : {&ja, &jb}) {
            j->erase("uptime_seconds");
            j->erase("uptime");
        }
        CHECK(ja == jb);
        CHECK(b->body.find("leader") == std::string::npos);
    }
}

TEST_CASE("health_routes: leader wiring pins -- /metrics reads the elector only through stats()",
          "[server][routes][health_routes][leader-metrics]") {
    const auto code = strip_comments(read_server_src("health_routes.cpp"));
    // Every reference to the elector is `if (deps.leader_elector)` or
    // `deps.leader_elector->stats()`. In particular never is_open() (takes the
    // elector's mu_, which the election loop holds across blocking libpq calls:
    // a stalled coordination probe would stall every scrape), is_leader(),
    // heartbeat() or try_acquire(). Scoped to the `deps.leader_elector` token so
    // the unrelated command_outbox_store->is_open() on the same handler does not
    // false-fire it.
    const std::string tok = "deps.leader_elector";
    std::size_t refs = 0;
    for (auto pos = code.find(tok); pos != std::string::npos; pos = code.find(tok, pos + 1)) {
        ++refs;
        const auto rest = code.substr(pos + tok.size(), 16);
        INFO("reference: " << tok << rest);
        const bool null_check = rest.rfind(")", 0) == 0;
        const bool stats_call = rest.rfind("->stats()", 0) == 0;
        CHECK((null_check || stats_call));
    }
    CHECK(refs == 2);
    // And it is never a /readyz or /health store check.
    const auto flat = squeeze_ws(code);
    CHECK(flat.find("{\"leader") == std::string::npos);
    CHECK(flat.find("deps.leader_elector&&") == std::string::npos);
    // The scrape-time age is `now - last_ok`. The handler must hand the publisher
    // the Stats snapshot AND the elector's own clock, as the last argument: a 0 or
    // a different clock here pins the age at 0 (or garbage) and silently kills
    // YuzuLeaderCoordinationStale, and the closed non-open elector these route
    // tests can build never has a last_ok to expose it. Pinned lexically.
    CHECK(flat.find("leader_publisher->publish(*deps.metrics,deps.leader_elector->stats(),") !=
          std::string::npos);
    CHECK(flat.find("yuzu::server::LeaderMetricsPublisher::steady_now_ns());") != std::string::npos);
    CHECK(count_of(flat, "steady_now_ns()") == 1);

    const auto server = squeeze_ws(strip_comments(read_server_src("server.cpp")));
    const auto occurrences = [&](const std::string& needle) {
        const auto n = squeeze_ws(needle);
        std::size_t count = 0;
        for (auto pos = server.find(n); pos != std::string::npos; pos = server.find(n, pos + 1))
            ++count;
        return count;
    };
    CHECK(occurrences(".leader_elector = leader_elector_.get()") == 1);
    CHECK(occurrences(".leader_loop_errors = &leader_loop_errors_") == 1);
    CHECK(occurrences("seed_leader_metrics(metrics_);") == 1);
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
    // Every section sends the credential a real panel request carries (the in-process health
    // document only includes `executions` for a request that resolves a session), so an
    // omission below is the panel's own gate decision and not an artefact of a bare request.
    const std::unordered_map<std::string, std::string> kPanelCredential{
        {"Cookie", "yuzu_session=abc"}};
    SECTION("unbound fleet gate omits the executions row") {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/fragments/dashboard/health", kPanelCredential);
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
        auto r = h.sink.Get("/fragments/dashboard/health", kPanelCredential);
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
        auto r = h.sink.Get("/fragments/dashboard/health", kPanelCredential);
        REQUIRE(r);
        REQUIRE(h.fleet_calls.size() == 1); // the gate was consulted and its scope decided
        CHECK(r->body.find("Executions running") == std::string::npos);
        CHECK(r->body.find("Agents connected to this server") != std::string::npos);
    }
    SECTION("denied omits it") {
        Harness h;
        h.fleet_wired = true;
        h.fleet_admit = false;
        h.wire();
        auto r = h.sink.Get("/fragments/dashboard/health", kPanelCredential);
        REQUIRE(r);
        REQUIRE(h.fleet_calls.size() == 1); // the gate was consulted and refused
        CHECK(r->body.find("Executions running") == std::string::npos);
    }
}

TEST_CASE("health_routes: /fragments/dashboard/health never renders system, tls or pending-agent fields",
          "[server][routes][health_routes][home]") {
    Harness h;
    h.fleet_wired = true;
    h.wire();
    // With a credential the in-process health document does carry those fields, so their
    // absence from the panel is the panel's own filtering.
    auto r = h.sink.Get("/fragments/dashboard/health", {{"Cookie", "yuzu_session=abc"}});
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
        const std::unordered_map<std::string, std::string> credential{
            {"Cookie", "yuzu_session=abc"}};
        auto doc = h.sink.Get("/api/health", credential);
        auto panel = h.sink.Get("/fragments/dashboard/health", credential);
        REQUIRE(doc);
        REQUIRE(panel);
        const std::string status = json::parse(doc->body)["status"].get<std::string>();
        const bool healthy_pill = panel->body.find(">Healthy<") != std::string::npos;
        const bool degraded_pill = panel->body.find(">Degraded<") != std::string::npos;
        CHECK(healthy_pill == (status == "healthy"));
        CHECK(degraded_pill == (status != "healthy"));
    }
}

// ── The per-source rate limit on /health and /api/health ───────────────────
//
// Timing note: RateLimiter refills continuously (`rate` tokens per second) and has no
// injectable clock. Every test below that expects a refusal uses a limiter built with a rate
// of 1, so a refusal can only turn into an admission if the thread is descheduled for more
// than a full second between two adjacent calls; a larger rate would shrink that margin to
// `1/rate` seconds.

namespace {
httplib::Request probe_request(const char* path, const char* addr = "10.0.0.7",
                               bool credential = true) {
    httplib::Request r;
    r.method = "GET";
    r.path = path;
    r.remote_addr = addr;
    if (credential)
        r.set_header("Cookie", "yuzu_session=probe");
    return r;
}
} // namespace

TEST_CASE("health_routes: a credentialed request over the budget on /health is refused with the "
          "standard 429",
          "[server][routes][health_routes][ratelimit]") {
    RateLimiter limiter(1);
    for (const char* path : {"/health", "/api/health"}) {
        INFO("path: " << path);
        const auto addr = std::string("10.1.0.") + (path[1] == 'h' ? "1" : "2");
        int admitted = 0;
        httplib::Response last;
        for (int i = 0; i < 8; ++i) {
            httplib::Response res;
            if (health::admit_probe_request(limiter, probe_request(path, addr.c_str()), res))
                ++admitted;
            else
                last = std::move(res);
        }
        CHECK(admitted == 1);
        // The refusal is the exact response the general limiter sends.
        CHECK(last.status == 429);
        CHECK(last.get_header_value("Content-Type").find("application/json") !=
              std::string::npos);
        CHECK(last.get_header_value("Retry-After") == "1");
        const auto body = json::parse(last.body);
        CHECK(body["error"]["code"] == 429);
        CHECK(body["error"]["message"] == "rate limit exceeded");
        CHECK(body["meta"]["api_version"] == "v1");
        // The full A4 envelope: the body's correlation_id is the X-Correlation-Id header.
        const auto cid = last.get_header_value("X-Correlation-Id");
        CHECK_FALSE(cid.empty());
        REQUIRE(body["error"].contains("correlation_id"));
        CHECK(body["error"]["correlation_id"] == cid);
        REQUIRE(body["error"].contains("retry_after_ms"));
        CHECK(body["error"]["retry_after_ms"] == 1000);
    }
}

TEST_CASE("health_routes: write_rate_limited_response keeps a correlation id an earlier gate set",
          "[server][routes][health_routes][ratelimit]") {
    httplib::Response res;
    res.set_header("X-Correlation-Id", "req-upstream-1");
    write_rate_limited_response(res);
    CHECK(res.status == 429);
    CHECK(res.get_header_value("X-Correlation-Id") == "req-upstream-1");
    CHECK(json::parse(res.body)["error"]["correlation_id"] == "req-upstream-1");

    // Two refusals that mint their own ids do not share one.
    httplib::Response a;
    httplib::Response b;
    write_rate_limited_response(a);
    write_rate_limited_response(b);
    CHECK(a.get_header_value("X-Correlation-Id") != b.get_header_value("X-Correlation-Id"));
}

TEST_CASE("health_routes: a request with no credential header is never charged against the "
          "probe budget",
          "[server][routes][health_routes][ratelimit]") {
    RateLimiter limiter(1);
    for (const char* path : {"/health", "/api/health"}) {
        INFO("path: " << path);
        for (int i = 0; i < 1000; ++i) {
            httplib::Response res;
            REQUIRE(health::admit_probe_request(
                limiter, probe_request(path, "10.3.0.1", /*credential=*/false), res));
            REQUIRE(res.status == -1); // untouched: no 429, nothing written
        }
    }
    // No bucket was created for the source either: a credential-less caller costs no state.
    CHECK(limiter.bucket_count() == 0);

    // The same source with a credential IS charged, and its credential-less polling stays
    // unaffected once that bucket is spent.
    httplib::Response first;
    CHECK(health::admit_probe_request(limiter, probe_request("/health", "10.3.0.1"), first));
    httplib::Response second;
    CHECK_FALSE(health::admit_probe_request(limiter, probe_request("/health", "10.3.0.1"), second));
    CHECK(limiter.bucket_count() == 1);
    httplib::Response bare;
    CHECK(health::admit_probe_request(
        limiter, probe_request("/health", "10.3.0.1", /*credential=*/false), bare));
}

TEST_CASE("health_routes: each credential source counts as a credential for the probe budget",
          "[server][routes][health_routes][ratelimit]") {
    for (const char* name : {"Cookie", "Authorization", "X-Yuzu-Token"}) {
        INFO("header: " << name);
        RateLimiter limiter(1);
        auto req = probe_request("/health", "10.3.1.1", /*credential=*/false);
        req.set_header(name, "x");
        httplib::Response first;
        CHECK(health::admit_probe_request(limiter, req, first));
        httplib::Response second;
        CHECK_FALSE(health::admit_probe_request(limiter, req, second));
        CHECK(second.status == 429);
    }
}

TEST_CASE("health_routes: /livez and /readyz are never charged against the probe budget",
          "[server][routes][health_routes][ratelimit]") {
    RateLimiter limiter(1);
    for (int i = 0; i < 50; ++i) {
        for (const char* path : {"/livez", "/readyz"}) {
            httplib::Response res;
            CHECK(health::admit_probe_request(limiter, probe_request(path), res));
            CHECK(res.status == -1); // untouched
        }
    }
    CHECK(limiter.bucket_count() == 0);
}

TEST_CASE("health_routes: the probe budget is a bucket of its own, per source",
          "[server][routes][health_routes][ratelimit]") {
    RateLimiter limiter(1);
    // Drain one source's probe bucket.
    httplib::Response drain;
    REQUIRE(health::admit_probe_request(limiter, probe_request("/health", "10.2.0.1"), drain));
    httplib::Response refused;
    CHECK_FALSE(health::admit_probe_request(limiter, probe_request("/health", "10.2.0.1"), refused));
    // /health and /api/health share the one probe bucket for a source.
    httplib::Response alias;
    CHECK_FALSE(
        health::admit_probe_request(limiter, probe_request("/api/health", "10.2.0.1"), alias));
    // The same source's ordinary API budget is untouched by it.
    CHECK(limiter.allow("10.2.0.1"));
    // Another source is unaffected.
    httplib::Response other;
    CHECK(health::admit_probe_request(limiter, probe_request("/health", "10.2.0.2"), other));
    // Draining a source's API bucket does not refuse its probe.
    REQUIRE(limiter.allow("10.2.0.3"));
    CHECK_FALSE(limiter.allow("10.2.0.3"));
    httplib::Response probe;
    CHECK(health::admit_probe_request(limiter, probe_request("/health", "10.2.0.3"), probe));
}

TEST_CASE("health_routes: a normal credentialed probe cadence is never limited at the default "
          "--rate-limit",
          "[server][routes][health_routes][ratelimit]") {
    // The limiter is built from the default `--rate-limit` (100/s per source). A fleet of load
    // balancers behind one NAT address probing every second is tens of requests per second.
    RateLimiter limiter(Config{}.rate_limit);
    CHECK(Config{}.rate_limit == 100);
    for (int i = 0; i < 60; ++i) {
        httplib::Response res;
        CHECK(health::admit_probe_request(limiter, probe_request("/health", "192.0.2.10"), res));
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
        // enablement_regressed (ADR-3006) is one boolean, the same fact the plaintext
        // /readyz `enablement` object already carries; it was added to this allowlist
        // deliberately, not drifted in.
        CHECK(keys == std::set<std::string>{"status", "uptime_seconds", "agents", "stores",
                                            "version", "tls", "enablement_regressed"});
        CHECK(body["agents"] == json{{"online", 0}});
    }

    // The main sink on the same harness still shows the authenticated-only fields.
    auto main_r = h.sink.Get("/health", {{"Cookie", "yuzu_session=abc"}});
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
