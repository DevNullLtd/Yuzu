/**
 * test_same_site_write_gate_pg.cpp - cookie-session writes require a same-site Origin or Referer,
 * proven against the REAL session resolver.
 *
 * test_same_site_write_gate.cpp drives the gate behind a MODEL of the resolver's precedence. This
 * file covers the credential combinations that decide whether a request is a
 * cookie-session request at all: it runs `AuthRoutes::resolve_session` (cookie, Bearer and
 * X-Yuzu-Token arms) over a real Postgres-backed AuthDB, durable SessionStore and ApiTokenStore,
 * then applies `detail::apply_same_site_write_gate` in the production order (probe and
 * pre-session paths first, resolve, 401 when there is no session, then the gate), on a real
 * httplib::Server bound to an ephemeral loopback port.
 *
 * The production pre-routing lambda lives inside the server class and cannot be instantiated in
 * a unit test, so the lambda below is a model of the ORDER only; the call site itself is pinned
 * by the source-text gate. Everything the gate's decision depends on (which credential wins, what
 * counts as a session, what the resolved auth_source is) is production code here.
 *
 * Paths are neutral canaries. Needs YUZU_TEST_POSTGRES_DSN; without it the case SKIPS (it is
 * tagged [pg] so it lands in an existing Postgres shard).
 *
 * Whole file compiled out under TSan: loopback httplib hits #2504 there.
 */
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "health_routes.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "same_site_write_gate.hpp"
#include "session_store.hpp"
#include "test_auth_db_rbac_pg_template.hpp"
#include "test_loopback_http.hpp"
#include "web_utils.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_TSAN_BUILD 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define YUZU_TSAN_BUILD 1
#endif

#ifndef YUZU_TSAN_BUILD

namespace {

using namespace yuzu::server;
using json = nlohmann::json;

constexpr const char* kCanary = "/api/v1/canary";
constexpr const char* kUser = "canary_user";
constexpr const char* kPassword = "canary-password-0123456789";

struct RealResolverPipeline {
    // Members destruct in reverse declaration order, including when the constructor throws
    // (where the destructor body never runs). Everything auth_mgr and ar point at is therefore
    // declared BEFORE them, so they are destroyed first and no store outlives a user of it.
    yuzu::test::AuthDbPg auth_db{0, false, &yuzu::test::auth_db_rbac_pg_template};
    std::unique_ptr<RbacStore> rbac;
    std::unique_ptr<SessionStore> session_store;
    std::unique_ptr<ApiTokenStore> tokens;
    std::unique_ptr<AuditStore> audit;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    auth::AuthManager auth_mgr;
    std::unique_ptr<AuthRoutes> ar;
    std::vector<std::string> trusted_origins;
    detail::SameSitePrincipalAuditFn audit_fn;

    httplib::Server svr;
    std::thread server_thread;
    int port{0};

    std::atomic<int> gate_rejections{0}; // witness for expect_pre_routing_rejection
    std::atomic<int> handler_hits{0};
    std::mutex mu;
    std::string last_source; // auth_source of the session the last admitted request resolved to

    RealResolverPipeline() {
        auth_mgr.set_auth_db(auth_db.get());
        rbac = std::make_unique<RbacStore>(auth_db.pool());
        REQUIRE(rbac->is_open());
        auth_mgr.set_rbac_store(rbac.get());
        auth_mgr.set_metrics_registry(&metrics);

        session_store = std::make_unique<SessionStore>(auth_db.pool());
        REQUIRE(session_store->is_open());
        auth_mgr.set_session_store(session_store.get());

        tokens = std::make_unique<ApiTokenStore>(auth_db.pool());
        REQUIRE(tokens->is_open());
        audit = std::make_unique<AuditStore>(auth_db.pool());
        REQUIRE(audit->is_open());

        REQUIRE(auth_mgr.upsert_user(kUser, kPassword, auth::Role::user));

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, rbac.get(), tokens.get(), audit.get(),
                                          /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

        trusted_origins = normalise_trusted_origins({});
        // Same shape as the production sink: stamps the principal the gate already holds.
        audit_fn = [this](const httplib::Request& r, const std::string& action,
                          const std::string& result, const detail::SameSiteAuditPrincipal& p,
                          const std::string& tt, const std::string& tid, const std::string& d) {
            return ar->audit_log_for_principal(r, action, result, p.id, p.role, tt, tid, d, p.cls);
        };

        auto ok = [this](const httplib::Request&, httplib::Response& res) {
            handler_hits.fetch_add(1);
            res.set_content(R"({"ok":true})", "application/json");
        };
        svr.Get(kCanary, ok);
        svr.Post(kCanary, ok);

        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res)
                                        -> httplib::Server::HandlerResponse {
            if (health::is_probe_path(req.path))
                return httplib::Server::HandlerResponse::Unhandled;
            if (is_login_exempt_path(req.path))
                return httplib::Server::HandlerResponse::Unhandled;

            const auto session = ar->resolve_session(req); // the REAL resolver
            if (!session) {
                res.status = 401;
                res.set_content(
                    R"({"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            {
                std::lock_guard lk(mu);
                last_source = session->auth_source;
            }
            if (detail::apply_same_site_write_gate(req, res, *session, trusted_origins, metrics,
                                                   audit_fn)) {
                gate_rejections.fetch_add(1);
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0); // before the thread exists: a throw here has nothing to join
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        svr.wait_until_ready();
        if (!svr.is_running()) {
            // Join first: REQUIRE throws out of the constructor, and a joinable std::thread
            // member destroyed by that unwind would std::terminate().
            svr.stop();
            server_thread.join();
        }
        REQUIRE(svr.is_running());
    }

    ~RealResolverPipeline() {
        // Stop serving and join before any member a handler touches is destroyed.
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }

    [[nodiscard]] std::string origin() const { return "http://127.0.0.1:" + std::to_string(port); }

    [[nodiscard]] httplib::Result post(const httplib::Headers& h) const {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        cli.set_write_timeout(5);
        return cli.Post(kCanary, h, "{}", "application/json");
    }

    [[nodiscard]] std::string source() {
        std::lock_guard lk(mu);
        return last_source;
    }

    [[nodiscard]] std::string login() {
        auto cookie = auth_mgr.authenticate(kUser, kPassword);
        REQUIRE(cookie.has_value());
        return *cookie;
    }

    [[nodiscard]] std::string mint_token() {
        auto raw = tokens->create_token("same-site-canary", kUser);
        REQUIRE(raw.has_value());
        return *raw;
    }

    [[nodiscard]] std::size_t denied_rows() {
        AuditQuery q;
        q.action = "csrf.denied";
        auto rows = audit->query(q);
        REQUIRE(rows.has_value());
        return rows->size();
    }

    /// Every refusal in this file is a write with no Origin and no Referer, so every row must
    /// carry the fixed text plus that one reason token.
    void check_denied_row_details() {
        AuditQuery q;
        q.action = "csrf.denied";
        auto rows = audit->query(q);
        REQUIRE(rows.has_value());
        for (const auto& r : *rows) {
            CHECK(r.detail == "cross-site or header-less browser write refused; "
                              "reason=no_origin_no_referer");
            CHECK(r.target_id == std::string("POST ") + kCanary);
            CHECK(r.result == "denied");
        }
    }
};

/// Windows can lose a pre-routing 4xx to a connection reset (#2757, test_loopback_http.hpp):
/// tolerated only for an RST-class error; returns false so the caller skips response-level
/// assertions while still asserting rows and handler deltas. POSIX: a missing response fails.
bool response_or_tolerated_loss(const httplib::Result& r) {
    if (r)
        return true;
    INFO("no response read; httplib error = " << httplib::to_string(r.error()));
#ifdef _WIN32
    const auto err = r.error();
    REQUIRE((err == httplib::Error::Read || err == httplib::Error::Write ||
             err == httplib::Error::ConnectionClosed));
    WARN("Windows: a pre-routing answer was lost to a connection reset (#2757)");
    return false;
#else
    REQUIRE(r);
    return false;
#endif
}

/// A refusal: 403 from the gate, one audit row naming the cookie principal, the canary never ran.
void expect_gated(RealResolverPipeline& f, const httplib::Headers& h) {
    const auto rows_before = f.denied_rows();
    const int hits_before = f.handler_hits.load();
    std::optional<httplib::Response> got;
    yuzu::test::expect_pre_routing_rejection(
        [&] {
            auto r = f.post(h);
            if (r)
                got = *r;
            return r;
        },
        403, f.gate_rejections);
#ifndef _WIN32
    REQUIRE(got.has_value());
#endif
    if (got) {
        const auto j = json::parse(got->body, nullptr, false);
        REQUIRE_FALSE(j.is_discarded());
        CHECK(j["error"]["message"] == "cross-site request refused");
    }
    CHECK(f.source() == "local"); // the cookie session won, not the token session
    CHECK(f.denied_rows() == rows_before + 1);
    CHECK(f.handler_hits.load() == hits_before);
}

/// No session: 401 from the pre-routing handler before the gate, no audit row, canary not run.
/// No witness is passed to the Windows loss tolerance: that 401 is not counted anywhere, so
/// there is nothing to advance. A lost answer skips only the status check; the gate, row and
/// handler deltas are still asserted.
void expect_unauthenticated(RealResolverPipeline& f, const httplib::Headers& h) {
    const auto rows_before = f.denied_rows();
    const int gate_before = f.gate_rejections.load();
    const int hits_before = f.handler_hits.load();
    auto r = f.post(h);
    if (response_or_tolerated_loss(r))
        CHECK(r->status == 401);
    CHECK(f.gate_rejections.load() == gate_before);
    CHECK(f.denied_rows() == rows_before);
    CHECK(f.handler_hits.load() == hits_before);
}

/// Admitted: the canary ran, the resolved session came from `expected_source`, nothing refused.
void expect_admitted(RealResolverPipeline& f, const httplib::Headers& h,
                     const std::string& expected_source) {
    const auto rows_before = f.denied_rows();
    const int gate_before = f.gate_rejections.load();
    const int hits_before = f.handler_hits.load();
    auto r = f.post(h);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(f.source() == expected_source);
    CHECK(f.gate_rejections.load() == gate_before);
    CHECK(f.denied_rows() == rows_before);
    CHECK(f.handler_hits.load() == hits_before + 1);
}

} // namespace

TEST_CASE("same-site gate over the real session resolver (skips without YUZU_TEST_POSTGRES_DSN)",
          "[pg][auth_routes][csrf][same_site]") {
    RealResolverPipeline f; // SKIPs here when the DSN is unset
    const std::string cookie = f.login();
    const std::string token = f.mint_token();
    const std::string cookie_hdr = "yuzu_session=" + cookie;
    const std::string bearer = "Bearer " + token;
    const auto rows_at_start = f.denied_rows();

    // Control: a token on its own is not gated (Bearer and X-Yuzu-Token arms).
    expect_admitted(f, {{"Authorization", bearer}}, "api_token");
    expect_admitted(f, {{"X-Yuzu-Token", token}}, "api_token");

    // (1) A valid session cookie wins over a valid token: the request is a cookie-session
    // request, so a write with no Origin or Referer is refused (Bearer and X-Yuzu-Token alike).
    expect_gated(f, {{"Cookie", cookie_hdr}, {"Authorization", bearer}});
    expect_gated(f, {{"Cookie", cookie_hdr}, {"X-Yuzu-Token", token}});
    expect_gated(f, {{"Cookie", cookie_hdr}});

    // (5) The same cookie with a same-site Origin is admitted, and so is a same-site Referer.
    // Refused above and admitted here on the SAME cookie: each refusal wrote exactly one row and
    // left the session valid.
    CHECK(f.denied_rows() == rows_at_start + 3);
    f.check_denied_row_details();
    expect_admitted(f, {{"Cookie", cookie_hdr}, {"Origin", f.origin()}}, "local");
    expect_admitted(f, {{"Cookie", cookie_hdr}, {"Referer", f.origin() + "/page"}}, "local");
    expect_admitted(f, {{"Cookie", cookie_hdr}, {"Authorization", bearer}, {"Origin", f.origin()}},
                    "local");

    // (2) A stale cookie (a once-valid session that has been invalidated) resolves to no session
    // at the cookie arm, so the request falls through to the token arm and is not gated.
    REQUIRE(f.auth_mgr.invalidate_session(cookie));
    expect_admitted(f, {{"Cookie", cookie_hdr}, {"Authorization", bearer}}, "api_token");
    expect_unauthenticated(f, {{"Cookie", cookie_hdr}}); // and on its own it is just 401

    // (3) An oversized cookie value yields no session before the Bearer arm is tried: 401, even
    // with a valid token alongside.
    const std::string oversized =
        "yuzu_session=" + std::string(auth::kMaxSessionTokenLength + 16, 'a');
    expect_unauthenticated(f, {{"Cookie", oversized}, {"Authorization", bearer}});

    // (4) An API token value presented only as the session cookie is not a session and not a
    // token: 401, neither gated nor admitted.
    expect_unauthenticated(f, {{"Cookie", "yuzu_session=" + token}});
}

#endif // YUZU_TSAN_BUILD
