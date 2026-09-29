/**
 * test_settings_read_twins.cpp — HTTP-level coverage for the eight Settings
 * REST read-twins (#4028, api-parity programme #2146):
 *   GET /api/v1/settings/tls|https|gateway|server-config|mcp|data-retention|analytics
 *   GET /api/v2/agent/plugin-policy (plugin-signing's twin, hardened by #4028)
 *
 * #4144 review fix: the plugin-policy twin above is /v2/, not /v1/ — #4028
 * originally hardened it in place at /v1/, which violated
 * docs/api-versioning-policy.md (a breaking envelope-shape change with no
 * version bump). GET /api/v1/agent/plugin-policy is now a SEPARATE,
 * deprecated, frozen-shape route (its own TEST_CASEs below), not this file's
 * read-twin under test.
 *
 * Pattern matches test_settings_routes_users.cpp / test_discovery_routes.cpp:
 * register SettingsRoutes against an in-process TestRouteSink and dispatch
 * synthesized httplib::Request objects through the captured handlers. No
 * real HTTP server, no acceptor thread (#438 TSan trap).
 *
 * Coverage:
 *   - 200 success shape (A4 {data, meta} envelope) per route
 *   - 403 when the route's RBAC securable/operation is denied
 *   - fail-closed 503 (A4 error envelope) on audit-persist failure, for the
 *     four routes wired to it (tls, https, analytics, plugin-policy) — and
 *     that the other four never call the audit hook at all
 *   - the ClickHouse URL userinfo-sanitization end to end through the REST
 *     route (settings_model.hpp carries the pure-function unit coverage;
 *     this is the route-wiring regression test)
 */

#include "settings_routes.hpp"

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/secret_codec.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;

namespace {

struct AuditReadCall {
    std::string action, result, target_type, target_id, detail;
};

/// Harness: register every SettingsRoutes route (including the 8 read-twins
/// under test) against an in-process TestRouteSink. `allow_perm` toggles
/// every `perm_fn_` gate at once (each route's OWN securable/operation is
/// captured per-call into `last_perm_*` so a test can assert the right pair
/// was checked); `audit_read_ok` toggles the fail-closed audit hook's
/// persisted-or-not return.
struct SettingsReadTwinsHarness {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    SettingsRoutes routes;

    yuzu::server::test::TestRouteSink sink;

    bool allow_perm{true};
    std::string last_perm_securable, last_perm_operation;
    // #4144 review fix: GET /api/v1/agent/plugin-policy is frozen back onto
    // admin_fn_ (never perm_fn_) — see that route's own comment. A separate
    // toggle from allow_perm so a test can deny v1 without also denying
    // every perm_fn_-gated route.
    bool allow_admin{true};
    bool audit_read_ok{true};
    std::vector<AuditReadCall> audit_read_calls;
    std::size_t gateway_sessions{7};

    /// `runtime_config_store` defaults to nullptr (the pre-existing
    /// behaviour every other test in this file relies on: `required` reads
    /// as false, no 503, no "status unknown" state). Passing a real
    /// (possibly deliberately-failed-to-open) store lets a test exercise
    /// `RuntimeConfigStore::get()`'s error branch — #4028 fix-round finding
    /// (sre, consistency-auditor, Gate 8): the prior nullptr-only harness
    /// meant that branch shipped with zero test coverage despite being the
    /// BLOCKING fix's own new code path.
    explicit SettingsReadTwinsHarness(RuntimeConfigStore* runtime_config_store = nullptr) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (allow_admin)
                return true;
            res.status = 403;
            res.set_content(R"({"error":{"code":403,"message":"admin required"}})",
                            "application/json");
            return false;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& op) {
            last_perm_securable = securable;
            last_perm_operation = op;
            if (allow_perm)
                return true;
            res.status = 403;
            res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
            return false;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {};
        auto gateway_count_fn = [this]() -> std::size_t { return gateway_sessions; };
        auto agents_json_fn = []() -> std::string { return "[]"; };
        auto audit_read_fn = [this](const httplib::Request&, const std::string& action,
                                    const std::string& result, const std::string& target_type,
                                    const std::string& target_id,
                                    const std::string& detail) -> bool {
            audit_read_calls.push_back({action, result, target_type, target_id, detail});
            return audit_read_ok;
        };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr, runtime_config_store,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/true, gateway_count_fn, agents_json_fn, oidc_mu,
                               oidc_provider,
                               /*metrics_registry=*/nullptr,
                               /*step_up_fn=*/{}, audit_read_fn);
    }
};

} // namespace

// ── 200 success shape, one per route ─────────────────────────────────────

TEST_CASE("GET /api/v1/settings/tls returns the A4 envelope and TlsConfig:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.cfg.tls_enabled = true;
    h.cfg.tls_server_cert = "/etc/yuzu/certs/server.pem";

    auto res = h.sink.Get("/api/v1/settings/tls");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "TlsConfig");
    CHECK(h.last_perm_operation == "Read");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("meta").at("api_version").get<std::string>() == "v1");
    CHECK(body.at("data").at("enabled").get<bool>() == true);
    CHECK(body.at("data").at("server_cert_path").get<std::string>() ==
          "/etc/yuzu/certs/server.pem");
}

TEST_CASE("GET /api/v1/settings/https returns the A4 envelope and TlsConfig:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.cfg.https_enabled = true;
    h.cfg.https_port = 8443;

    auto res = h.sink.Get("/api/v1/settings/https");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "TlsConfig");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("port").get<int>() == 8443);
}

TEST_CASE("GET /api/v1/settings/gateway returns the A4 envelope and ServerConfig:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.cfg.gateway_upstream_address = "0.0.0.0:50053";
    h.gateway_sessions = 3;

    auto res = h.sink.Get("/api/v1/settings/gateway");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "ServerConfig");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("enabled").get<bool>() == true);
    CHECK(body.at("data").at("listen_address").get<std::string>() == "0.0.0.0:50053");
    CHECK(body.at("data").at("active_sessions").get<int>() == 3);
}

TEST_CASE("GET /api/v1/settings/server-config returns the A4 envelope and ServerConfig:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.cfg.max_agents = 12345;

    auto res = h.sink.Get("/api/v1/settings/server-config");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "ServerConfig");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("max_agents").get<std::int64_t>() == 12345);
}

TEST_CASE("GET /api/v1/settings/mcp returns the A4 envelope and ServerConfig:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.cfg.mcp_disable = false;
    h.cfg.mcp_read_only = true;

    auto res = h.sink.Get("/api/v1/settings/mcp");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "ServerConfig");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("enabled").get<bool>() == true);
    CHECK(body.at("data").at("read_only").get<bool>() == true);
    CHECK(body.at("data").contains("endpoint_url"));
}

TEST_CASE("GET /api/v1/settings/data-retention returns the A4 envelope and ServerConfig:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.cfg.response_retention_days = 90;
    h.cfg.audit_retention_days = 365;

    auto res = h.sink.Get("/api/v1/settings/data-retention");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "ServerConfig");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("response_retention_days").get<int>() == 90);
    CHECK(body.at("data").at("audit_retention_days").get<int>() == 365);
}

TEST_CASE("GET /api/v1/settings/analytics sanitizes the ClickHouse URL and gates on "
          "AnalyticsConfig:Read",
          "[settings][rest][settings-read-twins][security]") {
    SettingsReadTwinsHarness h;
    h.cfg.clickhouse_url = "clickhouse://admin:s3cr3t@host:9000/yuzu";
    h.cfg.clickhouse_password = "s3cr3t";

    auto res = h.sink.Get("/api/v1/settings/analytics");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_perm_securable == "AnalyticsConfig");

    // The raw secret must never appear anywhere in the response body.
    CHECK(res->body.find("s3cr3t") == std::string::npos);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("clickhouse_url").get<std::string>() ==
          "clickhouse://host:9000/yuzu");
    CHECK(body.at("data").at("clickhouse_password_set").get<bool>() == true);
    CHECK(!body.at("data").contains("clickhouse_password"));
}

TEST_CASE("GET /api/v2/agent/plugin-policy (plugin-signing's REST twin) returns 200 with no "
          "bundle on disk and gates on PluginSigning:Read",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;

    auto res = h.sink.Get("/api/v2/agent/plugin-policy");
    REQUIRE(res);
    CHECK(res->status == 200); // absent bundle is a normal state, not 404/500
    CHECK(h.last_perm_securable == "PluginSigning");
    CHECK(h.last_perm_operation == "Read");

    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("meta").at("api_version").get<std::string>() == "v1");
    CHECK(body.at("data").at("enabled").get<bool>() == false);
    CHECK(body.at("data").at("trust_bundle_pem").get<std::string>().empty());
}

// #4144 review fix (BLOCKING, docs/api-versioning-policy.md): v1 is FROZEN
// at its pre-#4028 flat-body shape and gates on admin_fn_, not perm_fn_/RBAC
// — see the route's own comment in settings_routes.cpp. This is the
// regression test proving the freeze actually holds.
TEST_CASE("GET /api/v1/agent/plugin-policy (DEPRECATED, frozen shape) returns the old flat "
          "body and gates on admin_fn_, not RBAC",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;

    auto res = h.sink.Get("/api/v1/agent/plugin-policy");
    REQUIRE(res);
    CHECK(res->status == 200); // absent bundle is a normal state, not 404/500
    // v1 never calls perm_fn_ at all — the frozen route uses admin_fn_ only.
    CHECK(h.last_perm_securable.empty());
    CHECK(h.last_perm_operation.empty());

    auto body = nlohmann::json::parse(res->body);
    CHECK_FALSE(body.contains("meta")); // no A4 envelope on the frozen shape
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("enabled").get<bool>() == false);
    CHECK(body.at("trust_bundle_pem").get<std::string>().empty());

    SECTION("admin_fn_ denial still 403s") {
        SettingsReadTwinsHarness h2;
        h2.allow_admin = false;
        auto denied = h2.sink.Get("/api/v1/agent/plugin-policy");
        REQUIRE(denied);
        CHECK(denied->status == 403);
    }
}

// ── 403 when the RBAC securable/operation is denied ──────────────────────

TEST_CASE("Every Settings REST read-twin denies with 403 when its permission check fails",
          "[settings][rest][settings-read-twins]") {
    SettingsReadTwinsHarness h;
    h.allow_perm = false;

    // #4144 review fix: /api/v1/agent/plugin-policy is deliberately absent
    // here — it is frozen onto admin_fn_, not perm_fn_ (see the dedicated
    // admin_fn_-denial SECTION above). Its RBAC-gated successor,
    // /api/v2/agent/plugin-policy, is covered by this same perm_fn_ loop.
    for (const std::string& path :
        {std::string("/api/v1/settings/tls"), std::string("/api/v1/settings/https"),
         std::string("/api/v1/settings/gateway"), std::string("/api/v1/settings/server-config"),
         std::string("/api/v1/settings/mcp"), std::string("/api/v1/settings/data-retention"),
         std::string("/api/v1/settings/analytics"), std::string("/api/v2/agent/plugin-policy")}) {
        INFO("path=" << path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}

// ── Fail-closed audit posture (§4) ────────────────────────────────────────

TEST_CASE("The four high-sensitivity read-twins fail closed (503) on an audit-persist failure",
          "[settings][rest][settings-read-twins][audit]") {
    SettingsReadTwinsHarness h;
    h.audit_read_ok = false;

    // #4144 review fix: v1's frozen shape never calls the audit hook at
    // all (see the dedicated v1 test above) — v2 is this loop's coverage.
    for (const std::string& path :
        {std::string("/api/v1/settings/tls"), std::string("/api/v1/settings/https"),
         std::string("/api/v1/settings/analytics"), std::string("/api/v2/agent/plugin-policy")}) {
        INFO("path=" << path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
        // A4 error envelope: correlation_id present, not a bare {"error":"..."} string.
        auto body = nlohmann::json::parse(res->body);
        CHECK(body.at("error").contains("correlation_id"));
    }
}

TEST_CASE("The four operational read-twins never call the audit hook at all",
          "[settings][rest][settings-read-twins][audit]") {
    SettingsReadTwinsHarness h;

    for (const std::string& path :
        {std::string("/api/v1/settings/gateway"), std::string("/api/v1/settings/server-config"),
         std::string("/api/v1/settings/mcp"), std::string("/api/v1/settings/data-retention")}) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    CHECK(h.audit_read_calls.empty());
}

TEST_CASE("The four audited read-twins each call the audit hook exactly once with the "
          "documented verb",
          "[settings][rest][settings-read-twins][audit]") {
    SettingsReadTwinsHarness h;

    auto res_tls = h.sink.Get("/api/v1/settings/tls");
    REQUIRE(res_tls);
    CHECK(res_tls->status == 200);
    REQUIRE(h.audit_read_calls.size() == 1);
    CHECK(h.audit_read_calls.back().action == "settings.tls.read");

    auto res_https = h.sink.Get("/api/v1/settings/https");
    REQUIRE(res_https);
    REQUIRE(h.audit_read_calls.size() == 2);
    CHECK(h.audit_read_calls.back().action == "settings.https.read");

    auto res_analytics = h.sink.Get("/api/v1/settings/analytics");
    REQUIRE(res_analytics);
    REQUIRE(h.audit_read_calls.size() == 3);
    CHECK(h.audit_read_calls.back().action == "settings.analytics.read");

    // #4144 review fix: the audited plugin-policy twin is now v2 — v1 is
    // frozen and never calls the audit hook (see the dedicated v1 test).
    auto res_policy = h.sink.Get("/api/v2/agent/plugin-policy");
    REQUIRE(res_policy);
    REQUIRE(h.audit_read_calls.size() == 4);
    // Same domain verb as GET /api/v1/settings/... — both routes read the
    // same underlying resource (recipe §4: prefer the domain verb over
    // mcp.<tool_name>/route-specific naming so the audit log is queryable
    // by capability, not transport).
    CHECK(h.audit_read_calls.back().action == "settings.plugin_signing.read");
}

// ── Fragment/REST parity spot-check (Rule 1: same builder, same data) ────

TEST_CASE("The analytics HTML fragment sanitizes the ClickHouse URL identically to its REST twin",
          "[settings][rest][settings-read-twins][security]") {
    SettingsReadTwinsHarness h;
    h.cfg.clickhouse_url = "clickhouse://admin:s3cr3t@host:9000/yuzu";
    h.cfg.clickhouse_password = "s3cr3t";

    auto res = h.sink.Get("/fragments/settings/analytics");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("s3cr3t") == std::string::npos);
    CHECK(res->body.find("host:9000/yuzu") != std::string::npos);
}

// ── Degraded runtime_config_store (UP-3/CH-2 fix, Gate 8 coverage gap) ────
//
// A `PgPool` built on an invalid conninfo fails PgPool's own parse step and
// never attempts a network connection (documented in
// test_runtime_config_store.cpp: "valid() is false and every acquire
// returns an empty lease"), so `RuntimeConfigStore::is_open()` is
// immediately false and every read returns `unexpected` -- fast,
// deterministic, no real Postgres required. This is the exact scenario the
// #4028 fix round's `get()` migration exists to handle; the harness above
// only ever passes `runtime_config_store=nullptr`, which takes a DIFFERENT
// code path (`if (runtime_config_store_)` is false, `required` reads as a
// plain default false, no 503) and never touched the `!rc.has_value()`
// branch this fix introduced.

namespace {
struct DegradedRuntimeConfigFixture {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider key_provider{keys.path};
    yuzu::server::pg::SecretCodec codec{key_provider};
    yuzu::server::pg::PgPool pool{{.conninfo = "this is not a valid conninfo :::", .size = 1}};
    yuzu::server::RuntimeConfigStore store{pool, codec};

    DegradedRuntimeConfigFixture() {
        REQUIRE_FALSE(pool.valid());
        REQUIRE_FALSE(store.is_open());
    }
};
} // namespace

TEST_CASE("GET /api/v2/agent/plugin-policy fails closed (503) when runtime_config_store is down",
          "[settings][rest][settings-read-twins][security]") {
    DegradedRuntimeConfigFixture fixture;
    SettingsReadTwinsHarness h{&fixture.store};

    auto res = h.sink.Get("/api/v2/agent/plugin-policy");
    REQUIRE(res);
    CHECK(res->status == 503);
    nlohmann::json body = nlohmann::json::parse(res->body);
    CHECK(body.at("error").at("code").get<int>() == 503);
    CHECK(body.at("error").at("retry_after_ms").get<std::int64_t>() == 5000);
    CHECK(body.at("error").at("message").get<std::string>().find("could not be determined") !=
          std::string::npos);
}

// #4144 review fix: v1's FROZEN shape reverted to the pre-#4028 get_value()
// API, which silently collapses a degraded read to "" (no 503) — this is
// exactly the UP-3/CH-2 gap #4028 fixed, now reintroduced deliberately on
// v1 by the freeze (v2 above keeps the fix). Pinning this so a future
// refactor can't accidentally "fix" v1 back into a breaking-change round 2.
TEST_CASE("GET /api/v1/agent/plugin-policy (frozen shape) silently reads required=false "
          "when runtime_config_store is down, unlike v2",
          "[settings][rest][settings-read-twins][security]") {
    DegradedRuntimeConfigFixture fixture;
    SettingsReadTwinsHarness h{&fixture.store};

    auto res = h.sink.Get("/api/v1/agent/plugin-policy");
    REQUIRE(res);
    CHECK(res->status == 200);
    nlohmann::json body = nlohmann::json::parse(res->body);
    CHECK(body.at("required").get<bool>() == false);
}

TEST_CASE("The plugin-signing fragment shows a distinct status-unknown state when "
          "runtime_config_store is down",
          "[settings][rest][settings-read-twins][security]") {
    DegradedRuntimeConfigFixture fixture;
    SettingsReadTwinsHarness h{&fixture.store};

    auto res = h.sink.Get("/fragments/settings/plugin-signing");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("status unknown") != std::string::npos);
    // NOTE: this fixture has no trust bundle on disk (`enabled=false`), so
    // it cannot exercise the write-path fix (consistency-auditor/
    // unhappy-path, Gate 8: the toggle-and-Save form is now ALSO gated on
    // `!required_status_unknown`, not just `enabled`) -- that additionally
    // needs a bundle present, and `trust_bundle_path()` resolves to a real,
    // non-test-overridable filesystem location (`auth::default_cert_dir()`)
    // that a unit test must not write into. Verified instead by direct code
    // read (settings_routes.cpp's toggle-form `if` condition) rather than
    // by execution; flagged here so a future reader knows why this gap is
    // deliberate, not missed.
}
