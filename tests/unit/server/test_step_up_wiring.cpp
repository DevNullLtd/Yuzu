/**
 * test_step_up_wiring.cpp — the MFA step-up chokepoint as wired into the pre-request handler,
 * driven through a REAL httplib::Server over a loopback socket.
 *
 * test_step_up_gate.cpp proves the pieces (decide, render, `apply_step_up_chokepoint`) with
 * hand-built `httplib::Request`s. None of that proves that httplib hands the pre-request handler
 * a `matched_route` equal to the registered pattern for a regex route, that the refusal reaches the
 * client with its headers, or that a pass is visible to the route handler on the same worker
 * thread. This file installs `detail::run_pre_request_stage` (step_up_wiring.hpp, the function
 * `server.cpp`'s `set_pre_request_handler` lambda calls) on a real server, with a stubbed session
 * resolver and MFA store and no Postgres, and sends real requests.
 *
 * Mutation check (recorded in the commit message): making `run_pre_request_stage` skip
 * `apply_step_up_chokepoint` turns the refusal test red.
 */

#include "../../../server/core/src/step_up_policy.hpp"
#include "../../../server/core/src/step_up_wiring.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

// The sanitizer builds interpose httplib's worker threads in ways the other loopback fixtures in
// this directory already opt out of; keep this one consistent with them.
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_TSAN_BUILD 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define YUZU_TSAN_BUILD 1
#endif

#ifndef YUZU_TSAN_BUILD

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;
using namespace std::chrono_literals;

namespace {

// A kRequired row whose registered pattern is a regex with a capture group.
constexpr std::string_view kRotatePattern = R"(/api/v1/tokens/([^/]+)/rotate)";
constexpr std::string_view kRotateLabel = "POST /api/v1/tokens/{id}/rotate";
// A route with a body-cap row but no step-up row of its own to be evaluated by the chokepoint.
constexpr std::string_view kUnclassifiedPath = "/api/v1/step-up-wiring-test/unclassified";
// A real small-cap class (see body_cap_policy.hpp): used to prove the cap still precedes the
// chokepoint inside the extracted function.
constexpr std::string_view kSmallCapPath = "/api/v1/users/elevation-eligibility";

auth::Session make_session(const std::string& user, const std::string& source, Role role,
                           std::chrono::seconds proof_age) {
    auth::Session s;
    s.username = user;
    s.role = role;
    s.auth_source = source;
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const std::int64_t verified_ms = now - std::chrono::milliseconds(proof_age).count();
    AuthManager::derive_session_deadlines(s, now, now + 3600'000, now, verified_ms,
                                          /*elevated_until*/ 0, /*issued*/ 0, now);
    return s;
}

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct WiringServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};

    // Per-request inputs, mutated between requests by the test thread and read by worker threads.
    std::mutex mu;
    std::optional<auth::Session> session;
    std::vector<AuditRow> audits;

    // Observations written by the route handlers (worker threads).
    std::atomic<int> rotate_handler_calls{0};
    std::atomic<int> unclassified_handler_calls{0};
    std::atomic<int> small_cap_handler_calls{0};
    std::atomic<bool> handler_consumed_pass{false};
    std::atomic<bool> consume_in_handler{true};

    yuzu::MetricsRegistry metrics;

    MfaStatusFn mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        AuthDB::MfaStatus st;
        st.enrolled = true;
        return st;
    };
    StepUpSessionFn resolver = [this](const httplib::Request&) -> std::optional<auth::Session> {
        std::lock_guard lk(mu);
        return session;
    };
    StepUpAuditFn audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                                 const std::string&, const std::string& ti,
                                 const std::string& d) -> bool {
        std::lock_guard lk(mu);
        audits.push_back({a, r, ti, d});
        return true;
    };

    WiringServer() {
        // Mirrors server.cpp's pre-routing top: a stash left by a prior request on this worker
        // thread must not be seen by this one.
        svr.set_pre_routing_handler([](const httplib::Request&, httplib::Response&) {
            detail::clear_step_up_pass();
            return httplib::Server::HandlerResponse::Unhandled;
        });
        // The SAME function server.cpp's set_pre_request_handler lambda calls. The deps are built
        // per request, as in production.
        svr.set_pre_request_handler(
            [this](const httplib::Request& req,
                   httplib::Response& res) -> httplib::Server::HandlerResponse {
                const StepUpChokepointDeps deps{.resolve_session = &resolver,
                                                .auth_db = nullptr,
                                                .mfa_status = &mfa_status,
                                                .audit_fn = &audit,
                                                .metrics = &metrics,
                                                .window_secs = 300,
                                                .mfa_enforcement = "optional"};
                return detail::run_pre_request_stage(req, res, deps);
            });
        // Mirrors server.cpp's post-routing handler: an unconsumed pass on a 2xx is counted, and
        // the stash is always cleared.
        svr.set_post_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            detail::finish_step_up_pass(req, res, &metrics);
        });

        svr.Post(std::string(kRotatePattern),
                 [this](const httplib::Request& req, httplib::Response& res) {
                     rotate_handler_calls.fetch_add(1);
                     // What the in-handler StepUpFn does first in production.
                     if (consume_in_handler.load())
                         handler_consumed_pass.store(
                             detail::consume_step_up_pass(req, std::string(kRotateLabel)));
                     res.status = 200;
                     res.set_content("{\"ok\":true}", "application/json");
                 });
        svr.Post(std::string(kUnclassifiedPath),
                 [this](const httplib::Request&, httplib::Response& res) {
                     unclassified_handler_calls.fetch_add(1);
                     res.status = 200;
                     res.set_content("{\"ok\":true}", "application/json");
                 });
        svr.Post(std::string(kSmallCapPath),
                 [this](const httplib::Request&, httplib::Response& res) {
                     small_cap_handler_calls.fetch_add(1);
                     res.status = 200;
                 });

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        svr.wait_until_ready();
        REQUIRE(svr.is_running());
    }

    ~WiringServer() {
        // wait_until_ready first: stop() racing a listener that has not started its loop yet
        // would leave join() waiting forever.
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }

    void set_session(std::optional<auth::Session> s) {
        std::lock_guard lk(mu);
        session = std::move(s);
    }

    std::vector<AuditRow> audit_rows() {
        std::lock_guard lk(mu);
        return audits;
    }

    double gate_count(std::string_view outcome, std::string_view source, std::string_view surface) {
        return metrics
            .counter("yuzu_auth_mfa_step_up_gate_total", {{"outcome", std::string(outcome)},
                                                          {"source", std::string(source)},
                                                          {"surface", std::string(surface)}})
            .value();
    }

    httplib::Result post(const std::string& path, const std::string& body = "{}") {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(5, 0);
        cli.set_write_timeout(5, 0);
        return cli.Post(path, body, "application/json");
    }
};

} // namespace

TEST_CASE("wiring: a stale-proof local session is refused on a regex kRequired route before the "
          "handler runs",
          "[stepup][wiring]") {
    // Guard the premise: this is a real kRequired row and the registered pattern is the table key.
    const auto* row = step_up_policy_for("POST", kRotatePattern);
    REQUIRE(row != nullptr);
    REQUIRE(row->cls == StepUpClass::kRequired);
    REQUIRE(row->action_label == kRotateLabel);

    WiringServer s;
    s.set_session(make_session("alice", "local", Role::admin, 1h));

    auto r = s.post("/api/v1/tokens/abc123/rotate");
    REQUIRE(r);
    CHECK(r->status == 401);
    CHECK_FALSE(r->get_header_value("X-Correlation-Id").empty());
    // Parse without throwing or asserting so a missing refusal body fails this case cleanly.
    const auto body = nlohmann::json::parse(r->body, nullptr, /*allow_exceptions=*/false);
    REQUIRE(body.is_object());
    REQUIRE(body.contains("meta"));
    REQUIRE(body.contains("error"));
    CHECK(body["meta"].value("mfa_step_up_required", false) == true);
    CHECK(body["error"].value("correlation_id", "") == r->get_header_value("X-Correlation-Id"));

    // The handler never ran.
    CHECK(s.rotate_handler_calls.load() == 0);
    CHECK_FALSE(s.handler_consumed_pass.load());

    // One audit row, from the pre-authz stage, naming the matched row.
    const auto rows = s.audit_rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].action == "mfa.step_up.required");
    CHECK(rows[0].target_id == kRotateLabel);
    CHECK(rows[0].detail.ends_with(" stage=pre_authz"));
    CHECK(s.gate_count("refused", "local", "rest") == 1);
    CHECK(s.gate_count("pass", "local", "rest") == 0);
}

TEST_CASE("wiring: a fresh proof reaches the handler, which consumes the pass on the same worker "
          "thread",
          "[stepup][wiring]") {
    WiringServer s;
    s.set_session(make_session("alice", "local", Role::admin, 5s));

    auto r = s.post("/api/v1/tokens/abc123/rotate");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(s.rotate_handler_calls.load() == 1);
    // The stash armed in the pre-request handler was visible to the route handler (same thread).
    CHECK(s.handler_consumed_pass.load());
    CHECK(s.audit_rows().empty());
    CHECK(s.gate_count("pass", "local", "rest") == 1);
    // Consumed, so the post-routing report-only counter stays at zero.
    CHECK(s.gate_count("handler_skipped", "local", "rest") == 0);
}

TEST_CASE("wiring: a handler that never runs its own gate is counted handler_skipped",
          "[stepup][wiring]") {
    WiringServer s;
    s.consume_in_handler.store(false);
    s.set_session(make_session("alice", "local", Role::admin, 5s));

    auto r = s.post("/api/v1/tokens/abc123/rotate");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(s.rotate_handler_calls.load() == 1);
    CHECK(s.gate_count("handler_skipped", "local", "rest") == 1);
}

TEST_CASE("wiring: a route with no step-up row reaches the handler whatever the proof age",
          "[stepup][wiring]") {
    REQUIRE(step_up_policy_for("POST", kUnclassifiedPath) == nullptr);

    WiringServer s;
    // A stale proof that WOULD be refused on a kRequired row: the chokepoint must not evaluate it.
    s.set_session(make_session("alice", "local", Role::admin, 1h));

    auto r = s.post(std::string(kUnclassifiedPath));
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(s.unclassified_handler_calls.load() == 1);
    CHECK(s.audit_rows().empty());
    CHECK(s.gate_count("refused", "local", "rest") == 0);
    CHECK(s.gate_count("pass", "local", "rest") == 0);
}

TEST_CASE("wiring: a bearer principal passes a kRequired route and an unresolved caller is a 401",
          "[stepup][wiring]") {
    WiringServer s;

    SECTION("api_token with a long-stale proof field passes (issuing the token was the step-up)") {
        s.set_session(make_session("tok-owner", "api_token", Role::admin, 1h));
        auto r = s.post("/api/v1/tokens/abc123/rotate");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.rotate_handler_calls.load() == 1);
        CHECK(s.gate_count("pass", "api_token", "rest") == 1);
    }
    SECTION("no session at all is refused 401 with a correlation id and the handler is not run") {
        s.set_session(std::nullopt);
        auto r = s.post("/api/v1/tokens/abc123/rotate");
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK_FALSE(r->get_header_value("X-Correlation-Id").empty());
        CHECK(s.rotate_handler_calls.load() == 0);
    }
}

TEST_CASE("wiring: an over-cap body is refused 413 by the body cap, before the chokepoint",
          "[stepup][wiring]") {
    WiringServer s;
    // A session that the chokepoint would also refuse if it ever ran on this route; the route
    // is not a step-up row, so the only refusal possible is the cap.
    s.set_session(make_session("alice", "local", Role::admin, 1h));

    const auto cap = resolve_body_cap("POST", kSmallCapPath).max_body_bytes;
    REQUIRE(cap < 1024u * 1024u); // a small class: keeps the request small
    const std::string big(cap + 1, 'x');

    auto r = s.post(std::string(kSmallCapPath), big);
    // An httplib client can lose the response on a refusal while a large body is in flight; the
    // body is small here (cap + 1 of a small class) so the response is read.
    REQUIRE(r);
    CHECK(r->status == 413);
    CHECK(s.small_cap_handler_calls.load() == 0);
    CHECK(s.audit_rows().empty());
}

#endif // !YUZU_TSAN_BUILD
