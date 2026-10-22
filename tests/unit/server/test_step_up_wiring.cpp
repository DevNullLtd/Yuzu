/**
 * test_step_up_wiring.cpp - the MFA step-up chokepoint as wired into the pre-request handler,
 * driven through a REAL httplib::Server over a loopback socket.
 *
 * test_step_up_gate.cpp proves the pieces (decide, render, `apply_step_up_chokepoint`) with
 * hand-built `httplib::Request`s. None of that proves that httplib hands the pre-request handler
 * a `matched_route` equal to the registered pattern for a regex route, that the refusal reaches the
 * client with its headers, or that a pass is visible to the route handler on the same worker
 * thread. This file installs `detail::run_pre_request_stage` (step_up_wiring.hpp, the function
 * `server.cpp`'s `set_pre_request_handler` lambda calls) on a real server, with a stubbed session
 * resolver and MFA store, and sends real requests. It needs no Postgres except for the one `[pg]`
 * case that gives the approval handler a real `ApprovalManager`.
 *
 * Mutation check (recorded in the commit message): making `run_pre_request_stage` skip
 * `apply_step_up_chokepoint` turns the refusal test red.
 */

#include "../../../server/core/src/approval_manager.hpp"
#include "../../../server/core/src/approval_routes.hpp"
#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/same_site_write_gate.hpp"
#include "../../../server/core/src/step_up_policy.hpp"
#include "../../../server/core/src/step_up_wiring.hpp"

#include "auth_routes.hpp"
#include "oidc_provider.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_approval_manager_pg_helper.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/interfaces/catch_interfaces_capture.hpp>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
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
// The Guardian policy-generation raise row, registered with a STUB handler below (see the case that
// uses it for what that does and does not cover).
constexpr std::string_view kRaisePath = "/api/v1/guaranteed-state/policy-generation/raise";
constexpr std::string_view kRaiseLabel = "POST /api/v1/guaranteed-state/policy-generation/raise";
// A route with a body-cap row but no step-up row of its own to be evaluated by the chokepoint.
constexpr std::string_view kUnclassifiedPath = "/api/v1/step-up-wiring-test/unclassified";

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
    REQUIRE(AuthManager::derive_session_deadlines(s, now, now + 3600'000, now, verified_ms,
                                                  /*elevated_until*/ 0, /*issued*/ 0, now));
    return s;
}

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Stops and joins the listener thread on every exit path. Declared as the LAST member of
// WiringServer, so it is destroyed FIRST: the handlers that run on the worker threads (and the
// members they touch) outlive the join. A constructor that throws after the thread started would
// otherwise destroy a joinable std::thread, which is std::terminate.
//
// httplib's `Server::stop()` is a no-op while the server is not yet running, and it ASSERTS (debug
// builds) if called a second time on a running one, whose listening socket the first call already
// took. `listen_after_bind` returns at once, without ever running, when `decommission()` was called
// first. So the destructor calls stop() at most ONCE, only after it observes the loop running, and
// calls decommission() on every pass for a listener that has not entered its loop yet; it repeats
// until the thread reports (via `done`) that `listen_after_bind` has returned, under a 30 s
// ceiling. Past the ceiling the process aborts with a message on stderr: the listener thread still
// references this fixture and its Server, so neither detaching it (a use-after-free once the
// fixture is destroyed, which no timeout would catch) nor joining it (an unbounded hang) is safe.
// A loud, attributable abort is the only outcome that cannot be mistaken for a pass.
struct ListenerThread {
    httplib::Server& svr;
    std::thread thread;
    std::atomic<bool> done{false};
    explicit ListenerThread(httplib::Server& s) : svr(s) {}
    void start() {
        thread = std::thread([this]() {
            svr.listen_after_bind();
            done.store(true);
        });
    }
    /// True once the listener is accepting; bounded (5 s) so a listener that never starts cannot
    /// hang the test the way an unbounded `Server::wait_until_ready()` would.
    [[nodiscard]] bool wait_running() const {
        for (int i = 0; i < 5000 && !svr.is_running() && !done.load(); ++i)
            std::this_thread::sleep_for(1ms);
        return svr.is_running();
    }
    ~ListenerThread() {
        if (!thread.joinable())
            return;
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        bool stopped = false;
        while (!done.load() && std::chrono::steady_clock::now() < deadline) {
            if (!stopped && svr.is_running()) {
                svr.stop(); // closes the listening socket; the accept loop then returns
                stopped = true;
            }
            svr.decommission(); // a listener that has not entered its loop yet returns at once
            std::this_thread::sleep_for(1ms);
        }
        if (done.load()) {
            thread.join();
            return;
        }
        std::fprintf(stderr,
                     "FATAL: ListenerThread: listen_after_bind did not return within 30 s of "
                     "stop(); aborting (the listener thread still references the destroyed "
                     "fixture); test: %s\n",
                     Catch::getResultCapture().getCurrentTestName().c_str());
        std::fflush(stderr);
        std::abort();
    }
    ListenerThread(const ListenerThread&) = delete;
    ListenerThread& operator=(const ListenerThread&) = delete;
};

struct WiringServer {
    httplib::Server svr;
    int port{0};

    // Per-request inputs, mutated between requests by the test thread and read by worker threads.
    std::mutex mu;
    std::optional<auth::Session> session;
    // When set, every resolution from index `later_from` on in one request returns this instead of
    // `session`. Resolution 0 is the central check's; later ones are the handler's own, so a test
    // can make the handler resolve a different principal than the one the central check decided on.
    std::optional<auth::Session> later_session;
    std::atomic<int> later_from{1};
    // When set, the resolver applies the per-request binding to what it returns, with the same
    // function `AuthRoutes::resolve_session` applies on every credential path.
    std::atomic<bool> apply_binding{false};
    // When set, the raise stub resolves the way a production handler does: once for its `auth_fn`,
    // once inside `perm_fn`'s own gate, and the step-up call is made with the FIRST session.
    std::atomic<bool> three_resolves{false};
    // When set, the raise stub resolves once more AFTER the step-up call, as a handler does for
    // provenance (`created_by`, the audit row's principal), and refuses 401 on no session.
    std::atomic<bool> resolve_after_consume{false};
    // When false the pre-routing handler does NOT clear the stash, so a case can show that the
    // post-routing clear alone ends a request's binding.
    std::atomic<bool> pre_routing_clears{true};
    // Set by the unclassified route's handler: whether its own resolution returned a session.
    std::atomic<bool> unclassified_resolved{false};
    // Set by the unclassified route's handler: whether the worker thread's stash still held a
    // binding when the handler started (read from the same thread_local the worker owns).
    std::atomic<bool> unclassified_saw_binding{false};
    std::atomic<int> resolutions{0};
    std::vector<AuditRow> audits;

    // Observations written by the route handlers (worker threads).
    std::atomic<int> raise_mutations{0};
    std::atomic<int> rotate_handler_calls{0};
    std::atomic<int> unclassified_handler_calls{0};
    std::atomic<int> raise_handler_calls{0};
    std::atomic<bool> raise_consumed_pass{false};
    std::atomic<bool> handler_consumed_pass{false};
    // Set by the unclassified route's handler: whether it could consume a pass for the rotate row.
    std::atomic<bool> unclassified_consumed_rotate_pass{false};
    std::atomic<bool> consume_in_handler{true};
    // The httplib::Request address each handler saw (compared, never dereferenced).
    std::atomic<const void*> rotate_req_addr{nullptr};
    std::atomic<const void*> raise_req_addr{nullptr};
    std::atomic<std::thread::id> raise_thread{};
    std::atomic<std::thread::id> unclassified_thread{};
    std::atomic<const void*> unclassified_req_addr{nullptr};

    yuzu::MetricsRegistry metrics;

    MfaStatusFn mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        AuthDB::MfaStatus st;
        st.enrolled = true;
        return st;
    };
    StepUpSessionFn resolver = [this](const httplib::Request& req) -> std::optional<auth::Session> {
        const int n = resolutions.fetch_add(1);
        std::optional<auth::Session> resolved;
        {
            std::lock_guard lk(mu);
            resolved = (n >= later_from.load() && later_session) ? later_session : session;
        }
        if (resolved && apply_binding.load() && !detail::step_up_binding_admits(req, *resolved))
            return std::nullopt;
        return resolved;
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
        svr.set_pre_routing_handler([this](const httplib::Request&, httplib::Response&) {
            resolutions.store(0);
            if (pre_routing_clears.load())
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
                     rotate_req_addr.store(&req);
                     // What the in-handler StepUpFn does first in production, with the session
                     // the handler resolves itself.
                     if (consume_in_handler.load()) {
                         const auto handler_session = resolver(req);
                         handler_consumed_pass.store(
                             handler_session &&
                             detail::consume_step_up_pass(req, *handler_session,
                                                          std::string(kRotateLabel)));
                     }
                     res.status = 200;
                     res.set_content("{\"ok\":true}", "application/json");
                 });
        svr.Post(std::string(kRaisePath), [this](const httplib::Request& req,
                                                 httplib::Response& res) {
            raise_handler_calls.fetch_add(1);
            raise_req_addr.store(&req);
            raise_thread.store(std::this_thread::get_id());
            // The production shape of a kRequired handler with no class guard of its own: resolve
            // the session, consume the central pass for it, otherwise evaluate that session afresh
            // (`require_mfa_step_up` is decide + effects + render over a real store; this stub
            // injects the status function the same way the chokepoint's deps do).
            const auto handler_session = resolver(req);
            if (!handler_session) {
                res.status = 401;
                return;
            }
            if (three_resolves.load()) {
                // `perm_fn`'s own gate resolves the session again before the step-up call.
                const auto gate_session = resolver(req);
                if (!gate_session) {
                    res.status = 401;
                    return;
                }
            }
            const bool consumed =
                detail::consume_step_up_pass(req, *handler_session, std::string(kRaiseLabel));
            raise_consumed_pass.store(consumed);
            if (resolve_after_consume.load() && !resolver(req)) {
                res.status = 401;
                return;
            }
            if (!consumed) {
                const auto verdict = decide_step_up(*handler_session, mfa_status, 300, "optional");
                if (!verdict.passed()) {
                    emit_step_up_refusal_effects(req, verdict, audit, std::string(kRaiseLabel), {},
                                                 &metrics);
                    render_step_up_refusal(req, res, verdict, StepUpSurface::kRest);
                    return;
                }
            }
            raise_mutations.fetch_add(1);
            res.status = 200;
            res.set_content("{\"ok\":true}", "application/json");
        });
        svr.Post(std::string(kUnclassifiedPath),
                 [this](const httplib::Request& req, httplib::Response& res) {
                     unclassified_handler_calls.fetch_add(1);
                     unclassified_req_addr.store(&req);
                     unclassified_saw_binding.store(detail::tls_step_up_pass().bound);
                     unclassified_thread.store(std::this_thread::get_id());
                     const auto handler_session = resolver(req);
                     unclassified_resolved.store(handler_session.has_value());
                     unclassified_consumed_rotate_pass.store(
                         handler_session &&
                         detail::consume_step_up_pass(req, *handler_session,
                                                      std::string(kRotateLabel)));
                     res.status = 200;
                     res.set_content("{\"ok\":true}", "application/json");
                 });

        // Nothing below the thread start may throw (a failed REQUIRE throws): the bind, which
        // can fail, is checked BEFORE the thread exists, and after it only non-throwing CHECKs
        // run. The listener thread is joined by `listener`'s destructor regardless.
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        listener.start();
        CHECK(listener.wait_running());
    }

    void set_session(std::optional<auth::Session> s) {
        std::lock_guard lk(mu);
        session = std::move(s);
    }
    void set_later_session(std::optional<auth::Session> s) {
        std::lock_guard lk(mu);
        later_session = std::move(s);
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

    // LAST member: destroyed first (see ListenerThread).
    ListenerThread listener{svr};
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

TEST_CASE("wiring: a pass armed by one request is not consumable by the next on the same "
          "connection",
          "[stepup][wiring]") {
    WiringServer s;
    s.consume_in_handler.store(false); // request A's handler skips its gate and leaves the pass
    s.set_session(make_session("alice", "local", Role::admin, 5s));

    // One keep-alive connection is served by one worker thread, so both requests see the same
    // thread_local stash (and, often, the same httplib::Request address).
    httplib::Client cli("127.0.0.1", s.port);
    cli.set_keep_alive(true);
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(5, 0);

    auto a = cli.Post("/api/v1/tokens/abc123/rotate", "{}", "application/json");
    REQUIRE(a);
    REQUIRE(a->status == 200);
    // The control: A really armed a pass that its handler left unconsumed (the post-routing
    // handler counted it before clearing). Without this the "B cannot consume it" check below
    // would also pass if the chokepoint never armed anything.
    REQUIRE(s.rotate_handler_calls.load() == 1);
    CHECK(s.gate_count("pass", "local", "rest") == 1);
    CHECK(s.gate_count("handler_skipped", "local", "rest") == 1);

    // B is a different route whose handler asks for A's row: the pass must be gone by then.
    auto b = cli.Post(std::string(kUnclassifiedPath), "{}", "application/json");
    REQUIRE(b);
    CHECK(b->status == 200);
    CHECK(s.unclassified_handler_calls.load() == 1);
    CHECK_FALSE(s.unclassified_consumed_rotate_pass.load());
    // The premise of "the address is not a key" is that both requests were served at the SAME
    // httplib::Request address, so an address match alone would have admitted B. Whether the two
    // land on one address is the allocator's and the sanitizer runtime's choice (ASan's
    // detect_stack_use_after_return may place the per-request object differently), so it is
    // reported, never asserted: the assertion above (B cannot consume A's pass) holds either way,
    // and the same-address sequence is pinned deterministically at the unit level
    // (test_step_up_gate.cpp, "pass stash lifecycle: a pass armed by request A is not consumable by
    // request B at the same address").
    CHECK(s.rotate_req_addr.load() != nullptr);
    CHECK(s.unclassified_req_addr.load() != nullptr);
    if (s.rotate_req_addr.load() != s.unclassified_req_addr.load())
        WARN("the two requests were served at different httplib::Request addresses in this "
             "build, so this case did not exercise the same-address premise (the unit-level "
             "case does)");
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

namespace {

// The REAL approval routes (approval_routes.cpp) behind the same pre-request stage as production.
// With no ApprovalManager wired (the default), a request that gets past the handler's class check
// answers 503 ("service unavailable") before the handler's own step-up call, so no store is
// needed to see WHERE each caller class is stopped. With a real manager (the `[pg]` case) the
// handler runs to its decision. The handler's step-up closure records the label it is handed and
// then makes the production decision (`detail::run_in_handler_step_up`, with no auth store: it
// consumes the chokepoint's pass for exactly that label, and any other call fails closed 503).
struct ApprovalWiringServer {
    httplib::Server svr;
    int port{0};

    ApprovalManager* approval_manager{nullptr};
    int window_secs{300};

    std::mutex mu;
    std::optional<auth::Session> session;
    // See WiringServer: every resolution after the first in one request returns this instead.
    std::optional<auth::Session> later_session;
    std::atomic<int> resolutions{0};
    std::vector<AuditRow> chokepoint_audits;
    std::vector<std::string> handler_step_up_labels;
    std::vector<AuditRow> handler_audits;
    // The server-wide same-site gate, as server.cpp's pre-routing handler applies it. Off by
    // default (the older cases below exercise the step-up check alone); a test turns it on
    // before its first request. It reads the harness session directly (never `resolve_next`),
    // so it does not disturb the per-request resolution count the step-up cases depend on.
    std::atomic<bool> central_same_site{false};
    std::vector<AuditRow> same_site_audits;

    std::atomic<int> perm_calls{0};
    std::atomic<int> handler_step_up_calls{0};
    std::atomic<int> handler_audit_rows{0};

    yuzu::MetricsRegistry metrics;

    MfaStatusFn mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        AuthDB::MfaStatus st;
        st.enrolled = true;
        return st;
    };
    std::optional<auth::Session> resolve_next() {
        const int n = resolutions.fetch_add(1);
        std::lock_guard lk(mu);
        return (n >= 1 && later_session) ? later_session : session;
    }
    StepUpSessionFn resolver = [this](const httplib::Request&) -> std::optional<auth::Session> {
        return resolve_next();
    };
    StepUpAuditFn audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                                 const std::string&, const std::string& ti,
                                 const std::string& d) -> bool {
        std::lock_guard lk(mu);
        chokepoint_audits.push_back({a, r, ti, d});
        return true;
    };
    detail::SameSitePrincipalAuditFn same_site_audit =
        [this](const httplib::Request&, const std::string& a, const std::string& r,
               const detail::SameSiteAuditPrincipal&, const std::string&, const std::string& ti,
               const std::string& d) -> bool {
        std::lock_guard lk(mu);
        same_site_audits.push_back({a, r, ti, d});
        return true;
    };
    std::vector<std::string> no_trusted_origins;

    explicit ApprovalWiringServer(ApprovalManager* mgr = nullptr, int window = 300)
        : approval_manager(mgr), window_secs(window) {
        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            resolutions.store(0);
            detail::clear_step_up_pass();
            if (central_same_site.load()) {
                std::optional<auth::Session> held;
                {
                    std::lock_guard lk(mu);
                    held = session;
                }
                if (held && detail::apply_same_site_write_gate(req, res, *held, no_trusted_origins,
                                                               /*listener_is_tls=*/false, metrics,
                                                               same_site_audit))
                    return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });
        svr.set_pre_request_handler(
            [this](const httplib::Request& req,
                   httplib::Response& res) -> httplib::Server::HandlerResponse {
                const StepUpChokepointDeps deps{.resolve_session = &resolver,
                                                .auth_db = nullptr,
                                                .mfa_status = &mfa_status,
                                                .audit_fn = &audit,
                                                .metrics = &metrics,
                                                .window_secs = window_secs,
                                                .mfa_enforcement = "optional"};
                return detail::run_pre_request_stage(req, res, deps);
            });
        svr.set_post_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            detail::finish_step_up_pass(req, res, &metrics);
        });

        approval::Deps deps;
        deps.approval_manager = approval_manager;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response&, const std::string&,
                              const std::string&) {
            perm_calls.fetch_add(1);
            return true;
        };
        deps.resolve_session_fn = [this](const httplib::Request&) -> std::optional<auth::Session> {
            return resolve_next();
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string&, const std::string& ti, const std::string& d) {
            handler_audit_rows.fetch_add(1);
            std::lock_guard lk(mu);
            handler_audits.push_back({a, r, ti, d});
            return true;
        };
        deps.emit_event_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                                const nlohmann::json&) {};
        deps.step_up_fn = [this](const httplib::Request& req, httplib::Response& res,
                                 const auth::Session& sess, const std::string& label) {
            handler_step_up_calls.fetch_add(1);
            {
                std::lock_guard lk(mu);
                handler_step_up_labels.push_back(label);
            }
            return detail::run_in_handler_step_up(req, res, sess, label, /*auth_db=*/nullptr,
                                                  window_secs, audit, "optional", &metrics);
        };
        HttplibRouteSink sink(svr);
        approval::register_approval_routes(sink, std::move(deps));

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        listener.start();
        CHECK(listener.wait_running());
    }

    void set_session(std::optional<auth::Session> s) {
        std::lock_guard lk(mu);
        session = std::move(s);
    }
    void set_later_session(std::optional<auth::Session> s) {
        std::lock_guard lk(mu);
        later_session = std::move(s);
    }

    double gate_count(std::string_view outcome, std::string_view source) {
        return metrics
            .counter("yuzu_auth_mfa_step_up_gate_total", {{"outcome", std::string(outcome)},
                                                          {"source", std::string(source)},
                                                          {"surface", "dashboard"}})
            .value();
    }

    httplib::Result post(const std::string& path, bool same_site_origin,
                         const std::string& foreign_origin = {}) {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(5, 0);
        cli.set_write_timeout(5, 0);
        httplib::Headers h;
        if (!foreign_origin.empty())
            h.emplace("Origin", foreign_origin);
        else if (same_site_origin)
            h.emplace("Origin", "http://127.0.0.1:" + std::to_string(port));
        return cli.Post(path, h, "{}", "application/json");
    }

    // LAST member: destroyed first (see ListenerThread).
    ListenerThread listener{svr};
};

} // namespace

TEST_CASE("wiring: the approve and reject routes compose with the central step-up check",
          "[stepup][wiring][approval_routes]") {
    for (const char* verb : {"approve", "reject"}) {
        const std::string path = std::string("/api/approvals/abc123/") + verb;
        INFO(path);
        const auto* row = step_up_policy_for("POST", std::string("/api/approvals/([^/]+)/") + verb);
        REQUIRE(row != nullptr);
        REQUIRE(row->cls == StepUpClass::kRequired);
        CHECK(row->action_label == std::string("POST /api/approvals/{id}/") + verb);

        SECTION(std::string(verb) + ": a stale cookie proof is a 401 before any handler check") {
            ApprovalWiringServer s;
            s.set_session(make_session("alice", "local", Role::admin, 1h));
            auto r = s.post(path, /*same_site_origin=*/true);
            REQUIRE(r);
            CHECK(r->status == 401);
            const auto body = nlohmann::json::parse(r->body, nullptr, /*allow_exceptions=*/false);
            REQUIRE(body.is_object());
            CHECK(body["meta"].value("mfa_step_up_required", false) == true);
            CHECK(s.perm_calls.load() == 0); // the handler never ran
            CHECK(s.handler_audit_rows.load() == 0);
            CHECK(s.gate_count("refused", "local") == 1);
        }
        SECTION(std::string(verb) + ": an engine principal is a 403 engine_principal_denied from "
                                    "the central check") {
            ApprovalWiringServer s;
            auto engine = make_session("engine:ci", "engine_token", Role::admin, 5s);
            engine.principal_kind = "engine";
            s.set_session(engine);
            auto r = s.post(path, /*same_site_origin=*/false);
            REQUIRE(r);
            CHECK(r->status == 403);
            CHECK(s.perm_calls.load() == 0);
            CHECK(s.handler_audit_rows.load() == 0);
            bool engine_row = false;
            std::lock_guard lk(s.mu);
            for (const auto& a : s.chokepoint_audits)
                engine_row = engine_row || (a.action == "mfa.step_up.required" &&
                                            a.detail.find("engine_principal_denied") !=
                                                std::string::npos);
            CHECK(engine_row);
        }
        SECTION(std::string(verb) + ": an API-token session passes the central check and the "
                                    "handler still refuses it 403") {
            ApprovalWiringServer s;
            s.set_session(make_session("tok-owner", "api_token", Role::admin, 1h));
            auto r = s.post(path, /*same_site_origin=*/false);
            REQUIRE(r);
            CHECK(r->status == 403);
            CHECK(s.gate_count("pass", "api_token") == 1);
            CHECK(s.perm_calls.load() == 1); // the handler ran and refused it
            CHECK(r->body.find("approver_assurance_required:non_interactive_session") !=
                  std::string::npos);
            CHECK(s.handler_step_up_calls.load() == 0);
        }
        SECTION(std::string(verb) + ": a fresh cookie proof reaches the handler") {
            ApprovalWiringServer s;
            s.set_session(make_session("alice", "local", Role::admin, 5s));
            auto r = s.post(path, /*same_site_origin=*/true);
            REQUIRE(r);
            // No ApprovalManager is wired, so the handler answers 503 after the class check.
            CHECK(r->status == 503);
            CHECK(s.perm_calls.load() == 1);
            CHECK(s.gate_count("pass", "local") == 1);
            CHECK(s.gate_count("refused", "local") == 0);
        }
    }
}

TEST_CASE("wiring: a SAML session is refused 403 by the central check on approve and reject, "
          "and the handler never runs",
          "[stepup][wiring][approval_routes]") {
    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        ApprovalWiringServer s;
        s.set_session(make_session("saml-user", "saml", Role::admin, 5s));
        auto r = s.post(std::string("/api/approvals/abc123/") + verb, /*same_site_origin=*/true);
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(s.perm_calls.load() == 0);
        CHECK(s.handler_audit_rows.load() == 0);
        CHECK(s.handler_step_up_calls.load() == 0);
        CHECK(s.gate_count("refused", "saml") == 1);
        CHECK(s.gate_count("pass", "saml") == 0);
        bool row = false;
        std::lock_guard lk(s.mu);
        for (const auto& a : s.chokepoint_audits)
            row = row || (a.action == "mfa.step_up.required" &&
                          a.target_id == std::string("POST /api/approvals/{id}/") + verb);
        CHECK(row);
    }
}

TEST_CASE("wiring: with the step-up window disabled every non-engine caller passes the central "
          "check and the handler's own checks decide",
          "[stepup][wiring][approval_routes]") {
    for (const char* verb : {"approve", "reject"}) {
        const std::string path = std::string("/api/approvals/abc123/") + verb;
        INFO(path);

        SECTION(std::string(verb) + ": a cookie session with a stale proof reaches the handler") {
            ApprovalWiringServer s(nullptr, /*window=*/0);
            s.set_session(make_session("alice", "local", Role::admin, 1h));
            auto r = s.post(path, /*same_site_origin=*/true);
            REQUIRE(r);
            // Past the permission, same-site and class checks; no manager is wired, so 503.
            CHECK(r->status == 503);
            CHECK(s.perm_calls.load() == 1);
            CHECK(s.gate_count("pass", "local") == 1);
            CHECK(s.gate_count("refused", "local") == 0);
        }
        SECTION(std::string(verb) + ": a SAML cookie session reaches the handler") {
            ApprovalWiringServer s(nullptr, /*window=*/0);
            s.set_session(make_session("saml-user", "saml", Role::admin, 1h));
            auto r = s.post(path, /*same_site_origin=*/true);
            REQUIRE(r);
            CHECK(r->status == 503);
            CHECK(s.perm_calls.load() == 1);
            CHECK(s.gate_count("pass", "saml") == 1);
            CHECK(s.gate_count("refused", "saml") == 0);
        }
        SECTION(std::string(verb) +
                ": an engine principal is still a 403 engine_principal_denied") {
            ApprovalWiringServer s(nullptr, /*window=*/0);
            auto engine = make_session("engine:ci", "engine_token", Role::admin, 5s);
            engine.principal_kind = "engine";
            s.set_session(engine);
            auto r = s.post(path, /*same_site_origin=*/false);
            REQUIRE(r);
            CHECK(r->status == 403);
            CHECK(s.perm_calls.load() == 0);
            CHECK(s.handler_audit_rows.load() == 0);
            bool engine_row = false;
            std::lock_guard lk(s.mu);
            for (const auto& a : s.chokepoint_audits)
                engine_row =
                    engine_row || (a.action == "mfa.step_up.required" &&
                                   a.detail.find("engine_principal_denied") != std::string::npos);
            CHECK(engine_row);
        }
        SECTION(std::string(verb) + ": an API-token session is still refused by the handler") {
            ApprovalWiringServer s(nullptr, /*window=*/0);
            s.set_session(make_session("tok-owner", "api_token", Role::admin, 1h));
            auto r = s.post(path, /*same_site_origin=*/false);
            REQUIRE(r);
            CHECK(r->status == 403);
            CHECK(s.perm_calls.load() == 1); // the handler ran and refused it
            CHECK(r->body.find("approver_assurance_required:non_interactive_session") !=
                  std::string::npos);
            CHECK(s.handler_step_up_calls.load() == 0);
        }
    }
}

// The one place the handler's own step-up call is reached: a real ApprovalManager (Postgres) so
// the request runs past the store check. The handler's closure makes the production decision
// (consume the chokepoint's pass for EXACTLY the label it is handed, else fail closed), so a
// handler that passed the wrong verb's label, skipped the call, or took a second evaluation would
// answer 503 or leave a recorded label that differs. Swapping the two literal labels in
// approval_routes.cpp turns the label assertions and the 200 below red.
TEST_CASE("wiring: the approve and reject handlers consume the central pass with their own label",
          "[stepup][wiring][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;

    for (const char* verb : {"approve", "reject"}) {
        const bool is_approve = std::string_view(verb) == "approve";
        // At the default window a fresh proof is needed; with the window disabled a stale proof
        // passes the central check and the handler still consumes that pass.
        for (const int window : {300, 0}) {
            const auto proof_age =
                window > 0 ? std::chrono::seconds(5) : std::chrono::seconds(3600);
            INFO(verb << " window=" << window);
            auto id =
                mgr->submit(std::string("def-wiring-") + verb + std::to_string(window),
                            "submitter1", "ostype = 'windows'", "", ApprovalOrigin::kInstruction);
            REQUIRE(id.has_value());

            ApprovalWiringServer s(mgr.get(), window);
            s.set_session(make_session("alice", "local", Role::admin, proof_age));
            auto r = s.post("/api/approvals/" + *id + "/" + verb, /*same_site_origin=*/true);
            REQUIRE(r);
            CHECK(r->status == 200);
            CHECK(r->body.find(is_approve ? "approved" : "rejected") != std::string::npos);

            // The chokepoint passed it once, the handler's call consumed that pass (no
            // handler_skipped), and the label is the verb's own.
            CHECK(s.gate_count("pass", "local") == 1);
            CHECK(s.gate_count("refused", "local") == 0);
            CHECK(s.gate_count("handler_skipped", "local") == 0);
            CHECK(s.handler_step_up_calls.load() == 1);
            {
                std::lock_guard lk(s.mu);
                REQUIRE(s.handler_step_up_labels.size() == 1);
                CHECK(s.handler_step_up_labels[0] ==
                      std::string("POST /api/approvals/{id}/") + verb);
                CHECK(s.chokepoint_audits.empty()); // no refusal row anywhere
            }
            CHECK(s.perm_calls.load() == 1);
            CHECK(s.handler_audit_rows.load() == 2); // attempted + success

            auto row = mgr->get(*id);
            REQUIRE(row.has_value());
            CHECK(row->status == (is_approve ? "approved" : "rejected"));
        }
    }
}

// The approve handler resolves its own session after the central check. When that session is a
// different principal than the one the central check passed, the pass is not consumed: the shared
// in-handler decision evaluates the handler's session afresh (this harness has no auth store, so
// that evaluation fails closed 503) and the ticket is not decided. The control is the same case
// with one principal at both sites above ("consume the central pass with their own label").
TEST_CASE("wiring: the approve handler does not consume a pass earned by another principal",
          "[stepup][wiring][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-wiring-identity", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    ApprovalWiringServer s(mgr.get(), 300);
    s.set_session(make_session("alice", "local", Role::admin, 5s));
    s.set_later_session(make_session("bob", "local", Role::admin, 5s));
    auto r = s.post("/api/approvals/" + *id + "/approve", /*same_site_origin=*/true);
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(s.gate_count("pass", "local") == 1);
    CHECK(s.handler_step_up_calls.load() == 1);
    // The refused pass was spent, so no skipped gate is reported for this request.
    CHECK(s.gate_count("handler_skipped", "local") == 0);
    // Nothing was decided: no `attempted` audit row and the ticket is still pending.
    CHECK(s.handler_audit_rows.load() == 0);
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

// COVERAGE NOTE (policy-generation raise). The real route's handler (rest_api_v1.cpp) is driven
// by test_guardian_generation_raise.cpp through RbacRoleHarness, whose `TestRouteSink` does not run
// the pre-request stage, so a test of the REAL handler behind the REAL central check would need the
// harness re-plumbed onto a socket-backed sink and its stores. That is not done here. What covers
// the route instead: the kRequired table row and its label (test_step_up_route_inventory.cpp pins
// the row and that the handler's call site carries the same label), the handler's own refusals
// (test_guardian_generation_raise.cpp), and this case, which registers a STUB handler at the real
// path so the central decision for that row (engine, stale proof, fresh proof) runs through the
// production pre-request stage over a socket. It proves the chokepoint's behaviour for the row, not
// the handler's.
TEST_CASE("wiring: the policy-generation raise row is decided by the central check before the "
          "handler",
          "[stepup][wiring]") {
    const auto* row = step_up_policy_for("POST", kRaisePath);
    REQUIRE(row != nullptr);
    REQUIRE(row->cls == StepUpClass::kRequired);
    REQUIRE(row->action_label == kRaiseLabel);

    SECTION("an engine principal is a 403 audited as mfa.step_up.required with the route label") {
        WiringServer s;
        auto engine = make_session("engine:ci", "engine_token", Role::admin, 5s);
        engine.principal_kind = "engine";
        s.set_session(engine);
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(s.raise_handler_calls.load() == 0);
        bool engine_row = false;
        for (const auto& a : s.audit_rows())
            engine_row =
                engine_row || (a.action == "mfa.step_up.required" && a.target_id == kRaiseLabel &&
                               a.detail.find("engine_principal_denied") != std::string::npos);
        CHECK(engine_row);
    }
    SECTION("a stale cookie proof is a 401 and the handler is not run") {
        WiringServer s;
        s.set_session(make_session("alice", "local", Role::admin, 1h));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_handler_calls.load() == 0);
    }
    SECTION("a fresh cookie proof reaches the handler, which can consume the pass") {
        WiringServer s;
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.raise_handler_calls.load() == 1);
        CHECK(s.raise_consumed_pass.load());
    }
}

// A step-up pass is honoured only for the principal that earned it. The handler resolves its own
// session, which is not guaranteed to be the principal the central check decided on; the resolver
// here returns session A on its first call per request (the central check's) and session B
// afterwards (the handler's). This pins the consume-time identity check on its own, with a
// resolver that does not apply the per-request binding (the next case does). The raise stub is a
// kRequired route with no class guard of its own, so only the pass decides whether it mutates.
TEST_CASE("wiring: the in-request pass is honoured only for the principal that earned it",
          "[stepup][wiring]") {
    const auto* row = step_up_policy_for("POST", kRaisePath);
    REQUIRE(row != nullptr);
    REQUIRE(row->cls == StepUpClass::kRequired);

    SECTION("control: the same principal at both sites consumes the pass and mutates once") {
        WiringServer s;
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.raise_consumed_pass.load());
        CHECK(s.raise_mutations.load() == 1);
        CHECK(s.audit_rows().empty());
        CHECK(s.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("an engine principal at the handler is refused 403 and nothing mutates") {
        WiringServer s;
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        auto engine = make_session("engine:ci", "engine_token", Role::admin, 5s);
        engine.principal_kind = "engine";
        s.set_later_session(engine);
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(s.raise_handler_calls.load() == 1);
        CHECK_FALSE(s.raise_consumed_pass.load());
        CHECK(s.raise_mutations.load() == 0);
        bool engine_row = false;
        for (const auto& a : s.audit_rows())
            engine_row =
                engine_row || (a.action == "mfa.step_up.required" && a.target_id == kRaiseLabel &&
                               a.detail.find("engine_principal_denied") != std::string::npos);
        CHECK(engine_row);
        // The central check passed A once; the refused pass was spent, so no skipped gate is
        // reported for a request the handler answered itself.
        CHECK(s.gate_count("pass", "local", "rest") == 1);
        CHECK(s.gate_count("handler_skipped", "local", "rest") == 0);
        CHECK(s.gate_count("handler_skipped", "engine_token", "rest") == 0);
    }
    SECTION("a different human with a fresh proof is evaluated afresh, allowed, and not reported "
            "as a skipped gate") {
        WiringServer s;
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(make_session("bob", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(s.raise_consumed_pass.load()); // alice's pass was not bob's to consume
        CHECK(s.raise_mutations.load() == 1);      // bob's own fresh proof allowed it
        CHECK(s.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("a different human with a stale proof is evaluated afresh and refused 401") {
        WiringServer s;
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(make_session("bob", "local", Role::admin, 1h));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK_FALSE(s.raise_consumed_pass.load());
        CHECK(s.raise_mutations.load() == 0);
        bool row_seen = false;
        for (const auto& a : s.audit_rows())
            row_seen = row_seen || (a.action == "mfa.step_up.required" && a.target_id == kRaiseLabel);
        CHECK(row_seen);
    }
}

// One principal per request. A handler resolves its session more than once (its `auth_fn`, then
// `perm_fn`'s own gate, then the step-up call with the first session). Once the central check has
// passed a gated request, every later resolution yields the same principal or none, so a request
// is never authorised by one principal on the strength of a step-up pass earned by another. The
// stub's resolver applies the binding with the function `AuthRoutes::resolve_session` applies, on
// the resolution sequence central -> A, `auth_fn` -> A, `perm_fn` -> second principal.
TEST_CASE("wiring: every resolution after the central check yields the principal it passed, or none",
          "[stepup][wiring][stepbind]") {
    const auto* row = step_up_policy_for("POST", kRaisePath);
    REQUIRE(row != nullptr);
    REQUIRE(row->cls == StepUpClass::kRequired);

    auto engine = make_session("engine:ci", "engine_token", Role::admin, 5s);
    engine.principal_kind = "engine";

    SECTION("control: the same principal at all three resolutions mutates once") {
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.resolutions.load() == 3);
        CHECK(s.raise_mutations.load() == 1);
        CHECK(s.raise_consumed_pass.load());
        CHECK(s.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("an engine principal at the third resolution is refused 401 and nothing mutates") {
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.later_from.store(2);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(engine);
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_handler_calls.load() == 1);
        CHECK(s.raise_mutations.load() == 0);
        CHECK_FALSE(s.raise_consumed_pass.load());
        CHECK(s.gate_count("pass", "local", "rest") == 1);
    }
    SECTION("a different human at the third resolution is refused 401 and nothing mutates") {
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.later_from.store(2);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(make_session("bob", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_mutations.load() == 0);
    }
    SECTION("a different principal at the second resolution is refused 401 as well") {
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.later_from.store(1);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(engine);
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_mutations.load() == 0);
    }
    SECTION("control: the same principal at a resolution after the pass is spent mutates once") {
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.resolve_after_consume.store(true);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.resolutions.load() == 4);
        CHECK(s.raise_consumed_pass.load());
        CHECK(s.raise_mutations.load() == 1);
    }
    SECTION("another principal at a resolution after the pass is spent is refused 401") {
        // The binding outlives the pass: spending it does not release the request.
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.resolve_after_consume.store(true);
        s.later_from.store(3);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(make_session("bob", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_consumed_pass.load()); // the pass was honoured for the principal that earned it
        CHECK(s.raise_mutations.load() == 0);
        CHECK(s.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("harness control: a resolver that does not apply the binding is not constrained") {
        // Anchors the cases above: the 401s come from the binding, not from the stub.
        WiringServer s;
        s.three_resolves.store(true);
        s.later_from.store(2);
        s.set_session(make_session("alice", "local", Role::admin, 5s));
        s.set_later_session(make_session("bob", "local", Role::admin, 5s));
        auto r = s.post(std::string(kRaisePath));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.raise_mutations.load() == 1);
    }
    SECTION("the binding does not outlive the request: an ungated request on the same worker "
            "resolves freely") {
        WiringServer s;
        s.apply_binding.store(true);
        s.three_resolves.store(true);
        s.later_from.store(2);
        // The pre-routing clear is off, so only the post-routing clear can end the binding.
        s.pre_routing_clears.store(false);
        s.set_session(make_session("alice", "local", Role::admin, 5s));

        // One keep-alive connection is served by one worker thread, so both requests see the same
        // thread_local stash (and, often, the same httplib::Request address). The first request
        // succeeds so the connection stays open.
        httplib::Client cli("127.0.0.1", s.port);
        cli.set_keep_alive(true);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(5, 0);

        auto first = cli.Post(std::string(kRaisePath), "{}", "application/json");
        REQUIRE(first);
        REQUIRE(first->status == 200); // gated: the binding was armed for alice
        REQUIRE(s.raise_mutations.load() == 1);

        // An UNGATED route resolves a different principal through a binding-applying resolver:
        // admitted, because the first request's binding is gone.
        s.set_session(make_session("carol", "local", Role::admin, 5s));
        auto second = cli.Post(std::string(kUnclassifiedPath), "{}", "application/json");
        REQUIRE(second);
        CHECK(second->status == 200);
        CHECK(s.unclassified_handler_calls.load() == 1);
        CHECK(s.unclassified_resolved.load());
        // Read from the worker's own thread_local, so a leaked binding is seen whatever address
        // the second request was served at.
        CHECK_FALSE(s.unclassified_saw_binding.load());
        // A leaked binding is only visible when both requests ran on one worker thread. One
        // keep-alive connection is normally served by one worker, but that is httplib's
        // behaviour, not a contract, so a different thread is reported rather than asserted. The
        // deterministic pins are the unit-level lifecycle cases in test_step_up_gate.cpp.
        if (s.raise_thread.load() != s.unclassified_thread.load())
            WARN("the two requests were served by different worker threads in this build, so this "
                 "case did not exercise the same-thread premise (the unit-level case does)");
        // The `httplib::Request` is a stack local per request, so on one connection its address is
        // normally the same, but a build may place it differently (a sanitizer's stack handling,
        // say). The resolution check above needs the same address, so say so when it differs; the
        // stash read above does not.
        if (s.raise_req_addr.load() != s.unclassified_req_addr.load())
            WARN("the two requests were served at different httplib::Request addresses in this "
                 "build, so this case did not exercise the same-address premise");
    }
}

namespace {
// The same shape over the REAL `AuthRoutes::resolve_session`: a cookie session and a token
// credential on one request, the cookie ceasing to validate between two resolutions.
struct RealResolveServer {
    httplib::Server svr;
    int port{0};

    yuzu::test::ApiTokenStorePg api_tokens;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> routes;
    yuzu::MetricsRegistry metrics;

    std::string alice_cookie;
    std::string bob_token;
    // Set by the test: end alice's cookie session between the handler's two resolutions.
    std::atomic<bool> end_cookie_between{false};
    std::atomic<int> raise_mutations{0};

    MfaStatusFn mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return AuthDB::MfaStatus{}; // not enrolled: the central check passes any proof age
    };
    StepUpSessionFn resolver = [this](const httplib::Request& req) -> std::optional<auth::Session> {
        return routes->resolve_session(req);
    };
    StepUpAuditFn audit = [](const httplib::Request&, const std::string&, const std::string&,
                             const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };

    RealResolveServer() {
        routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                              api_tokens.get(), /*audit_store=*/nullptr,
                                              /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                              /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
        REQUIRE(auth_mgr.upsert_user("yuzu_test_alice", "password1234", Role::admin));
        REQUIRE(auth_mgr.upsert_user("yuzu_test_bob", "password1234", Role::admin));
        alice_cookie =
            auth_mgr.create_local_session_for_test("yuzu_test_alice", Role::admin, true);
        const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        const auto raw = api_tokens->create_token("wiring-bob", "yuzu_test_bob", now_s + 3600, "", "");
        REQUIRE(raw.has_value());
        bob_token = *raw;

        svr.set_pre_routing_handler([](const httplib::Request&, httplib::Response&) {
            detail::clear_step_up_pass();
            return httplib::Server::HandlerResponse::Unhandled;
        });
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
        svr.set_post_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            detail::finish_step_up_pass(req, res, &metrics);
        });
        svr.Post(std::string(kRaisePath), [this](const httplib::Request& req,
                                                 httplib::Response& res) {
            const auto first = routes->resolve_session(req); // `auth_fn`
            if (!first) {
                res.status = 401;
                return;
            }
            if (end_cookie_between.load())
                (void)auth_mgr.invalidate_session(alice_cookie);
            const auto gate = routes->resolve_session(req); // `perm_fn`'s own gate
            if (!gate) {
                res.status = 401;
                return;
            }
            (void)detail::consume_step_up_pass(req, *first, std::string(kRaiseLabel));
            raise_mutations.fetch_add(1);
            res.status = 200;
            res.set_content("{\"ok\":true}", "application/json");
        });

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        listener.start();
        CHECK(listener.wait_running());
    }

    httplib::Result post(const std::string& token_header) {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(5, 0);
        cli.set_write_timeout(5, 0);
        httplib::Headers h;
        h.emplace("Cookie", "yuzu_session=" + alice_cookie);
        if (token_header == "Authorization")
            h.emplace("Authorization", "Bearer " + bob_token);
        else
            h.emplace("X-Yuzu-Token", bob_token);
        return cli.Post(std::string(kRaisePath), h, "{}", "application/json");
    }

    // LAST member: destroyed first (see ListenerThread).
    ListenerThread listener{svr};
};
} // namespace

namespace {
// The REAL `AuthRoutes::resolve_session` behind the real pre-request stage with no ApiTokenStore
// (no Postgres): cookie sessions only. The handler replaces the request's Cookie header with
// another principal's session between its two resolutions, as a later resolution that lands on a
// different credential would see.
struct CookieResolveServer {
    httplib::Server svr;
    int port{0};

    Config cfg{};
    auth::AuthManager auth_mgr{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> routes;
    yuzu::MetricsRegistry metrics;

    std::string alice_cookie;
    std::string bob_cookie;
    std::atomic<bool> swap_cookie_between{false};
    std::atomic<int> raise_mutations{0};

    MfaStatusFn mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return AuthDB::MfaStatus{}; // not enrolled: the central check passes any proof age
    };
    StepUpSessionFn resolver = [this](const httplib::Request& req) -> std::optional<auth::Session> {
        return routes->resolve_session(req);
    };
    StepUpAuditFn audit = [](const httplib::Request&, const std::string&, const std::string&,
                             const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };

    CookieResolveServer() {
        routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                              /*api_token_store=*/nullptr, /*audit_store=*/nullptr,
                                              /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                              /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
        REQUIRE(auth_mgr.upsert_user("yuzu_test_alice", "password1234", Role::admin));
        REQUIRE(auth_mgr.upsert_user("yuzu_test_bob", "password1234", Role::admin));
        alice_cookie = auth_mgr.create_local_session_for_test("yuzu_test_alice", Role::admin, true);
        bob_cookie = auth_mgr.create_local_session_for_test("yuzu_test_bob", Role::admin, true);

        svr.set_pre_routing_handler([](const httplib::Request&, httplib::Response&) {
            detail::clear_step_up_pass();
            return httplib::Server::HandlerResponse::Unhandled;
        });
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
        svr.set_post_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            detail::finish_step_up_pass(req, res, &metrics);
        });
        svr.Post(std::string(kRaisePath), [this](const httplib::Request& req,
                                                 httplib::Response& res) {
            const auto first = routes->resolve_session(req); // `auth_fn`
            if (!first) {
                res.status = 401;
                return;
            }
            if (swap_cookie_between.load()) {
                // The request is non-const underneath: httplib owns it for the whole dispatch.
                auto& headers = const_cast<httplib::Request&>(req).headers;
                headers.erase("Cookie");
                headers.emplace("Cookie", "yuzu_session=" + bob_cookie);
            }
            const auto gate = routes->resolve_session(req); // `perm_fn`'s own gate
            if (!gate) {
                res.status = 401;
                return;
            }
            (void)detail::consume_step_up_pass(req, *first, std::string(kRaiseLabel));
            raise_mutations.fetch_add(1);
            res.status = 200;
            res.set_content("{\"ok\":true}", "application/json");
        });

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        listener.start();
        CHECK(listener.wait_running());
    }

    httplib::Result post() {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(5, 0);
        cli.set_write_timeout(5, 0);
        httplib::Headers h;
        h.emplace("Cookie", "yuzu_session=" + alice_cookie);
        return cli.Post(std::string(kRaisePath), h, "{}", "application/json");
    }

    // LAST member: destroyed first (see ListenerThread).
    ListenerThread listener{svr};
};
} // namespace

TEST_CASE("wiring: with real cookie resolution, a different session mid-request is a 401, not a "
          "different principal",
          "[stepup][wiring][stepbind]") {
    CookieResolveServer s;

    SECTION("control: the same cookie at every resolution, so one principal mutates once") {
        auto r = s.post();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.raise_mutations.load() == 1);
    }
    SECTION("another principal's session at the second resolution: refused 401, nothing mutates") {
        s.swap_cookie_between.store(true);
        auto r = s.post();
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_mutations.load() == 0);
    }
}

TEST_CASE("wiring: with real session resolution, a credential change mid-request is a 401, not a "
          "different principal",
          "[stepup][wiring][stepbind][pg]") {
    const auto header = GENERATE(as<std::string>{}, "Authorization", "X-Yuzu-Token");
    INFO("token header: " << header);
    RealResolveServer s;

    SECTION("control: the cookie validates at every resolution, so one principal mutates once") {
        auto r = s.post(header);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(s.raise_mutations.load() == 1);
    }
    SECTION("the cookie stops validating between two resolutions: the request is refused 401") {
        s.end_cookie_between.store(true);
        auto r = s.post(header);
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(s.raise_mutations.load() == 0);
    }
}

// Anchor for the step-up-alone check below: with a FRESH proof the central check passes, the
// handler runs and its own same-site copy audits `csrf.denied` for the foreign Origin (this
// harness has no server-wide gate unless a case turns one on). This is the row that check asserts
// the absence of, so a harness that never emitted it could not make that check fail.
TEST_CASE("wiring: a fresh cookie proof with a foreign Origin reaches the handler, whose cross-site "
          "check audits csrf.denied",
          "[stepup][wiring][approval_routes]") {
    ApprovalWiringServer s;
    s.set_session(make_session("alice", "local", Role::admin, 5s));
    auto r = s.post("/api/approvals/abc123/approve", /*same_site_origin=*/false,
                    "https://other-site.example");
    REQUIRE(r);
    CHECK(s.gate_count("pass", "local") == 1);
    bool csrf_row = false;
    {
        std::lock_guard lk(s.mu);
        for (const auto& a : s.handler_audits)
            csrf_row = csrf_row || a.action == "csrf.denied";
    }
    CHECK(csrf_row);
}

// The step-up check alone: it reads neither Origin nor Referer. This harness installs NO
// server-wide same-site gate, so a stale cookie proof with a foreign Origin is answered by the
// step-up check (401, step-up envelope) and the handler's own same-site copy, which would audit
// a `csrf.denied` row, never runs. In production the server-wide gate answers a cross-site cookie
// write first; the next case drives that order.
TEST_CASE("wiring: the step-up check does not read Origin (a stale cookie proof with a foreign "
          "Origin is a step-up 401 when no same-site gate is in front)",
          "[stepup][wiring][approval_routes]") {
    ApprovalWiringServer s;
    s.set_session(make_session("alice", "local", Role::admin, 1h));
    auto r = s.post("/api/approvals/abc123/approve", /*same_site_origin=*/false,
                    "https://other-site.example");
    REQUIRE(r);
    CHECK(r->status == 401);
    const auto body = nlohmann::json::parse(r->body, nullptr, /*allow_exceptions=*/false);
    REQUIRE(body.is_object());
    CHECK(body["meta"].value("mfa_step_up_required", false) == true);
    CHECK(s.perm_calls.load() == 0);
    CHECK(s.handler_audit_rows.load() == 0);
    std::lock_guard lk(s.mu);
    for (const auto& a : s.handler_audits)
        CHECK(a.action != "csrf.denied");
    bool step_up_row = false;
    for (const auto& a : s.chokepoint_audits)
        step_up_row = step_up_row || a.action == "mfa.step_up.required";
    CHECK(step_up_row);
}

// Production order for a cookie session: the server-wide same-site gate (pre-routing) answers a
// cross-site write BEFORE the step-up check. A stale proof with a foreign Origin is therefore a
// 403 `cross-site request refused` with one `csrf.denied` row; no step-up is evaluated (no
// `mfa.step_up.required` row, no gate metric), and no handler runs. A same-site Origin with the
// same stale proof is the control: the gate admits it and the step-up check answers 401.
TEST_CASE("wiring: with the server-wide same-site gate in front, a cross-site cookie write is "
          "refused 403 before the step-up check",
          "[stepup][wiring][approval_routes][same_site]") {
    ApprovalWiringServer s;
    s.central_same_site.store(true);
    s.set_session(make_session("alice", "local", Role::admin, 1h));

    SECTION("foreign Origin: same-site 403, no step-up evaluated") {
        auto r = s.post("/api/approvals/abc123/approve", /*same_site_origin=*/false,
                        "https://other-site.example");
        REQUIRE(r);
        CHECK(r->status == 403);
        const auto body = nlohmann::json::parse(r->body, nullptr, /*allow_exceptions=*/false);
        REQUIRE(body.is_object());
        CHECK(body["error"].value("message", "") == "cross-site request refused");
        CHECK(body["meta"].value("mfa_step_up_required", false) == false);
        CHECK(s.gate_count("refused", "local") == 0);
        CHECK(s.gate_count("pass", "local") == 0);
        CHECK(s.perm_calls.load() == 0);
        CHECK(s.handler_step_up_calls.load() == 0);
        CHECK(s.handler_audit_rows.load() == 0);
        std::lock_guard lk(s.mu);
        CHECK(s.chokepoint_audits.empty());
        REQUIRE(s.same_site_audits.size() == 1);
        CHECK(s.same_site_audits[0].action == "csrf.denied");
    }
    SECTION("no Origin or Referer: the same refusal") {
        auto r = s.post("/api/approvals/abc123/approve", /*same_site_origin=*/false);
        REQUIRE(r);
        CHECK(r->status == 403);
        std::lock_guard lk(s.mu);
        CHECK(s.chokepoint_audits.empty());
        CHECK(s.same_site_audits.size() == 1);
    }
    SECTION("control: a same-site Origin passes the gate and the stale proof is a step-up 401") {
        auto r = s.post("/api/approvals/abc123/approve", /*same_site_origin=*/true);
        REQUIRE(r);
        CHECK(r->status == 401);
        std::lock_guard lk(s.mu);
        CHECK(s.same_site_audits.empty());
        bool step_up_row = false;
        for (const auto& a : s.chokepoint_audits)
            step_up_row = step_up_row || a.action == "mfa.step_up.required";
        CHECK(step_up_row);
    }
}

TEST_CASE("wiring: an over-cap body is refused 413 by the body cap, before the chokepoint",
          "[stepup][wiring]") {
    // A kRequired route and a session whose proof is STALE: if the chokepoint ran first (or the
    // cap were skipped) this request would be a 401 with an audit row, so only the stage order
    // "cap, then chokepoint" yields the 413 below.
    const auto* row = step_up_policy_for("POST", kRotatePattern);
    REQUIRE(row != nullptr);
    REQUIRE(row->cls == StepUpClass::kRequired);

    WiringServer s;
    s.set_session(make_session("alice", "local", Role::admin, 1h));

    const std::string path = "/api/v1/tokens/abc123/rotate";
    const auto cap = resolve_body_cap("POST", path).max_body_bytes;
    // The /api/v1 default class (a few MiB): large enough to be a real over-cap body, small
    // enough to send over loopback. The guard keeps a future raise of the class from turning this
    // case into a multi-hundred-MiB upload.
    REQUIRE(cap <= 8u * 1024 * 1024);
    const std::string big(cap + 1, 'x');

    auto r = s.post(path, big);
    // The server reads the whole body before the pre-request handler runs (that is why the cap
    // is a post-read stage here), so the 413 is written after the upload completes.
    REQUIRE(r);
    CHECK(r->status == 413);
    CHECK(s.rotate_handler_calls.load() == 0);
    CHECK(s.audit_rows().empty());
    CHECK(s.gate_count("refused", "local", "rest") == 0);

    // The control: the same session and route with a body inside the cap IS the chokepoint's 401,
    // so the 413 above is the cap's doing and not an artefact of the route or the session.
    auto within = s.post(path, std::string(cap, 'x'));
    REQUIRE(within);
    CHECK(within->status == 401);
    CHECK(s.audit_rows().size() == 1);
}

#endif // !YUZU_TSAN_BUILD

// ── server.cpp's own call sites ──────────────────────────────────────────────────────────────
//
// The fixture above mirrors the pre-routing and post-routing handlers it needs; it cannot prove
// server.cpp makes the same calls. These source-text pins do, for the three sites the stash
// lifecycle depends on. They are a floor, not a behaviour test: they fail if a call is deleted,
// duplicated or moved out of its handler, not if one is made ineffective.

namespace {

std::string read_server_cpp() {
    std::ifstream in(std::string(YUZU_SERVER_SRC_DIR) + "/server.cpp", std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::size_t count_of(const std::string& hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1))
        ++n;
    return n;
}

} // namespace

TEST_CASE("wiring: server.cpp clears the pass stash at the pre-routing top and post-routing, and "
          "installs the extracted pre-request stage once",
          "[stepup][wiring][lexical]") {
    const std::string src = read_server_cpp();
    constexpr std::string_view kClear = "detail::clear_step_up_pass();";
    constexpr std::string_view kFinish = "detail::finish_step_up_pass(req, res, &metrics_);";
    constexpr std::string_view kStage = "detail::run_pre_request_stage(req, res, step_up_deps);";

    REQUIRE(count_of(src, kClear) == 1);
    REQUIRE(count_of(src, kFinish) == 1);
    REQUIRE(count_of(src, kStage) == 1);

    const auto pre_routing = src.find("web_server_->set_pre_routing_handler(");
    const auto clear = src.find(kClear);
    const auto pre_request = src.find("web_server_->set_pre_request_handler(");
    const auto stage = src.find(kStage);
    const auto post_routing = src.find("web_server_->set_post_routing_handler(");
    const auto finish = src.find(kFinish);
    REQUIRE(pre_routing != std::string::npos);
    REQUIRE(pre_request != std::string::npos);
    REQUIRE(post_routing != std::string::npos);

    // Pre-routing top: the clear sits in the pre-routing handler, next to the quota-slot reset
    // that has the same worker-thread-affinity reasoning, and before the pre-request handler.
    CHECK(pre_routing < clear);
    CHECK(clear < pre_request);
    const auto quota_reset = src.rfind("detail::tls_quota_slot().reset();", clear);
    REQUIRE(quota_reset != std::string::npos);
    CHECK(clear - quota_reset < 1200);

    // The stage is called from the pre-request handler, not from anywhere else.
    CHECK(pre_request < stage);
    CHECK(stage < post_routing);

    // Post-routing: the finish call sits in the post-routing handler, after the handler's
    // first-local scope guard, before the quota-slot release and before the response headers are
    // written, so the stash and the binding are cleared before any later code in the lambda runs.
    CHECK(post_routing < finish);
    const auto guard = src.find("} engine_class_stash_clear;", post_routing);
    REQUIRE(guard != std::string::npos);
    CHECK(guard < finish);
    const auto post_quota_reset = src.find("detail::tls_quota_slot().reset();", post_routing);
    REQUIRE(post_quota_reset != std::string::npos);
    CHECK(finish < post_quota_reset);
    const auto headers = src.find("security_headers.apply(res);", finish);
    REQUIRE(headers != std::string::npos);
    CHECK(finish < headers);
}

namespace {

bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

struct Stripped {
    std::string text;
    bool clean{true}; // false if the scan ended inside a comment, string or character literal
};

// Source text with comments removed and string and character literals blanked, so a mention in a
// comment or a message cannot count as a call. A character literal opens only when the preceding
// identifier run is empty or one of the encoding prefixes (a digit separator, as in 120'000, is
// not one), and a raw string (`R"delim( ... )delim"`, with the u8/u/U/L prefixes) ends at its own
// delimiter, not at the next quote.
Stripped strip_comments_and_literals(const std::string& in) {
    Stripped r;
    auto& out = r.text;
    out.reserve(in.size());
    const auto n = in.size();
    const auto ident_before = [&](std::size_t i) {
        auto b = i;
        while (b > 0 && is_ident_char(in[b - 1]))
            --b;
        return in.substr(b, i - b);
    };
    for (std::size_t i = 0; i < n;) {
        const char c = in[i];
        if (c == '/' && i + 1 < n && in[i + 1] == '/') {
            while (i < n && in[i] != '\n')
                ++i;
        } else if (c == '/' && i + 1 < n && in[i + 1] == '*') {
            const auto end = in.find("*/", i + 2);
            if (end == std::string::npos) {
                r.clean = false;
                break;
            }
            out += ' ';
            i = end + 2;
        } else if (c == '"') {
            const auto id = ident_before(i);
            if (id == "R" || id == "u8R" || id == "uR" || id == "UR" || id == "LR") {
                const auto open = in.find('(', i + 1);
                if (open == std::string::npos || open - (i + 1) > 16) {
                    r.clean = false;
                    break;
                }
                const std::string close = ")" + in.substr(i + 1, open - (i + 1)) + "\"";
                const auto end = in.find(close, open + 1);
                if (end == std::string::npos) {
                    r.clean = false;
                    break;
                }
                out += "\"\"";
                i = end + close.size();
            } else {
                ++i;
                while (i < n && in[i] != '"') {
                    if (in[i] == '\\')
                        ++i;
                    ++i;
                }
                if (i >= n) {
                    r.clean = false;
                    break;
                }
                out += "\"\"";
                ++i;
            }
        } else if (c == '\'') {
            const auto id = ident_before(i);
            if (!id.empty() && id != "L" && id != "u" && id != "U" && id != "u8") {
                out += c; // a digit separator, not a literal
                ++i;
            } else {
                ++i;
                while (i < n && in[i] != '\'') {
                    if (in[i] == '\\')
                        ++i;
                    ++i;
                }
                if (i >= n) {
                    r.clean = false;
                    break;
                }
                out += "''";
                ++i;
            }
        } else {
            out += c;
            ++i;
        }
    }
    return r;
}

// Member-call sites of `name`: the whole identifier, then optional whitespace and `(`, directly
// after `.` or `->` (whitespace, including newlines, allowed around the name). A declaration, a
// `Class::name(` definition and a longer identifier ending in `name` are not call sites.
std::size_t member_calls_of(const std::string& code, std::string_view name) {
    std::size_t n = 0;
    for (auto at = code.find(name); at != std::string::npos; at = code.find(name, at + 1)) {
        const auto end = at + name.size();
        if (end < code.size() && is_ident_char(code[end]))
            continue;
        auto k = end;
        while (k < code.size() && std::isspace(static_cast<unsigned char>(code[k])) != 0)
            ++k;
        if (k >= code.size() || code[k] != '(')
            continue;
        auto b = at;
        while (b > 0 && std::isspace(static_cast<unsigned char>(code[b - 1])) != 0)
            --b;
        const bool dot = b >= 1 && code[b - 1] == '.';
        const bool arrow = b >= 2 && code[b - 1] == '>' && code[b - 2] == '-';
        if (dot || arrow)
            ++n;
    }
    return n;
}

// The body of the function whose signature starts at `signature`, by brace matching.
std::string body_of(const std::string& code, std::string_view signature) {
    const auto at = code.find(signature);
    REQUIRE(at != std::string::npos);
    const auto open = code.find('{', at);
    REQUIRE(open != std::string::npos);
    int depth = 0;
    for (auto i = open; i < code.size(); ++i) {
        if (code[i] == '{')
            ++depth;
        else if (code[i] == '}' && --depth == 0)
            return code.substr(open, i - open + 1);
    }
    FAIL("unbalanced braces after " << signature);
    return {};
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

// The stripper behind the validator floor below. A desync (a digit separator read as the start of
// a character literal, a raw string ended at an inner quote) would hide a real call from the floor
// without any other symptom, so each failure mode has its own case.
TEST_CASE("wiring: the validator floor's source stripper handles digit separators, raw strings and "
          "split calls",
          "[stepup][wiring][lexical][stepbind]") {
    const auto count = [](const std::string& src, std::string_view name = "validate_session") {
        const auto stripped = strip_comments_and_literals(src);
        CHECK(stripped.clean);
        return member_calls_of(stripped.text, name);
    };

    SECTION("a digit separator does not open a character literal") {
        CHECK(count("int n = 120'000; a.validate_session(n); char c = 'z';") == 1);
        CHECK(count("auto x = 1'000'000; b->validate_session(x); auto y = 0xFF'FF;") == 1);
    }
    SECTION("a raw string ends at its own delimiter, whatever quotes it holds") {
        CHECK(count(R"TEST(auto s = R"x(he said "hi" and 'it's)x"; a.validate_session(1);)TEST") == 1);
        CHECK(count(R"TEST(auto s = u8R"(a "q" b)"; a.validate_session(1);)TEST") == 1);
    }
    SECTION("text inside a raw string, a string or a comment is not a call") {
        CHECK(count(R"TEST(auto s = R"(a.validate_session(1))";)TEST") == 0);
        CHECK(count("auto s = \"a.validate_session(1)\";") == 0);
        CHECK(count("// a.validate_session(1)\n/* b->validate_session(2) */") == 0);
    }
    SECTION("a call split across lines, or with a space before the parenthesis, counts") {
        CHECK(count("a\n  .validate_session\n  (x);") == 1);
        CHECK(count("a->validate_session (x);") == 1);
        CHECK(count("a  .  validate_session(x);") == 1);
    }
    SECTION("only member calls of the whole identifier count") {
        CHECK(count("validate_session(x);") == 0);
        CHECK(count("a.revalidate_session(x);") == 0);
        CHECK(count("std::optional<S> AuthManager::validate_session(const T& t) const {}") == 0);
        CHECK(count("a.validate_token_checked(x);", "validate_token") == 0);
        CHECK(count("a.validate_token_checked(x);", "validate_token_checked") == 1);
    }
    SECTION("a quote in a character literal or an apostrophe in a comment does not desync") {
        CHECK(count("char q = '\"'; a.validate_session(1);") == 1);
        CHECK(count("auto w = L'\"'; a.validate_session(1);") == 1);
        CHECK(count("// don't\na.validate_session(1);") == 1);
        CHECK(count("auto s = \"it's\"; a.validate_session(1);") == 1);
    }
    SECTION("an unterminated construct is reported, not silently accepted") {
        CHECK_FALSE(strip_comments_and_literals("a.validate_session(1); /* open").clean);
        CHECK_FALSE(strip_comments_and_literals("auto s = \"open").clean);
        CHECK_FALSE(strip_comments_and_literals("auto s = R\"x(open").clean);
    }
}

// A direct credential validator in server/core/src decides a principal WITHOUT passing through
// `AuthRoutes::resolve_session`, so it is not covered by the per-request principal binding. The
// documented direct validators are listed here with the reason each does not authorise a gated
// (kRequired) handler. A new one fails this test: route it through `resolve_session`, or add it
// here with its reason. It is a source-text floor over member calls of `validate_session(`,
// `validate_token(` and `validate_token_checked(` (not other types' free functions).
TEST_CASE("wiring: every direct session or token validator is either the resolve_session walk or a "
          "documented non-gated call site",
          "[stepup][wiring][lexical][stepbind]") {
    namespace fs = std::filesystem;
    struct Count {
        std::size_t session{0};
        std::size_t token{0};
        std::size_t token_checked{0};
    };
    std::map<std::string, Count> found;
    std::size_t files = 0;
    for (const auto& entry : fs::recursive_directory_iterator(YUZU_SERVER_SRC_DIR)) {
        const auto ext = entry.path().extension();
        if (!entry.is_regular_file() || (ext != ".cpp" && ext != ".hpp"))
            continue;
        ++files;
        const auto rel = fs::relative(entry.path(), YUZU_SERVER_SRC_DIR).generic_string();
        const auto stripped = strip_comments_and_literals(read_file(entry.path()));
        // A scan that ended inside a comment or literal desynced, and everything after the
        // desync point is unscanned.
        INFO("stripper desynced on " << rel);
        REQUIRE(stripped.clean);
        Count c{member_calls_of(stripped.text, "validate_session"),
                member_calls_of(stripped.text, "validate_token"),
                member_calls_of(stripped.text, "validate_token_checked")};
        if (c.session != 0 || c.token != 0 || c.token_checked != 0)
            found[rel] = c;
    }
    REQUIRE(files > 100); // the scan really walked the tree

    const auto auth_code =
        strip_comments_and_literals(read_file(std::string(YUZU_SERVER_SRC_DIR) + "/auth_routes.cpp"))
            .text;
    // The credential walk behind resolve_session: the one place the cookie and token credentials
    // are validated for a request, bound by `resolve_session`'s wrapper.
    const auto walk = body_of(auth_code, "AuthRoutes::resolve_session_unbound(");
    CHECK(member_calls_of(walk, "validate_session") == 1);
    CHECK(member_calls_of(walk, "validate_token") == 2);
    CHECK(member_calls_of(walk, "validate_token_checked") == 0);

    // Everything else, by file. auth_routes.cpp (outside the walk): revalidate_stream (stream
    // liveness, not a handler gate; its token check is the one `validate_token_checked`), the
    // login and SSO callbacks that mint a session (pre-session), POST /api/v1/elevate (kOwnGate)
    // and POST /api/v1/elevate/revoke (kExempt), all validating their own cookie only.
    // settings_routes.cpp: the MFA enrolment confirm (kExempt), which compares the cookie
    // session's username and auth source with the resolved session before stamping proof on it.
    // scim_routes.cpp: the SCIM bearer store (SCIM rows are kExempt).
    std::map<std::string, Count> allowed{
        {"auth_routes.cpp", {1 + 5, 2, 1}},
        {"settings_routes.cpp", {1, 0, 0}},
        {"scim_routes.cpp", {0, 1, 0}},
    };
    for (const auto& [file, c] : found) {
        INFO("file: " << file << " (validate_session calls " << c.session << ", validate_token calls "
                      << c.token << ", validate_token_checked calls " << c.token_checked
                      << "). A new direct validator is not covered by the one-principal-per-request "
                         "binding: route it through AuthRoutes::resolve_session, or add it to this "
                         "allowlist with the reason it does not authorise a gated handler.");
        const auto it = allowed.find(file);
        REQUIRE(it != allowed.end());
        CHECK(c.session == it->second.session);
        CHECK(c.token == it->second.token);
        CHECK(c.token_checked == it->second.token_checked);
    }
    for (const auto& [file, c] : allowed) {
        INFO("allowlisted file no longer has these calls: " << file);
        CHECK(found.count(file) == 1);
    }
}

TEST_CASE("wiring: server.cpp's in-handler StepUpFn and the pre-request deps name the right "
          "sources",
          "[stepup][wiring][lexical]") {
    const std::string src = read_server_cpp();
    // Each needle is a single line, so a CRLF checkout cannot split it.
    constexpr std::string_view kCall = "detail::run_in_handler_step_up(req, res, session, action_label,";
    REQUIRE(count_of(src, kCall) == 1);
    const auto call = src.find(kCall);

    // The call sits inside the `step_up_fn` lambda, before the next owner is wired.
    const auto lambda = src.rfind("StepUpFn step_up_fn = [this]", call);
    REQUIRE(lambda != std::string::npos);
    CHECK(call - lambda < 3000);
    const auto settings = src.find("settings_routes_ = std::make_unique<SettingsRoutes>();", call);
    REQUIRE(settings != std::string::npos);

    // Its arguments, in order: the live auth store read per request, the configured window and
    // enforcement mode, and the metrics registry.
    const std::string args = src.substr(call, settings - call);
    const auto db = args.find("auth_mgr_.auth_db_ptr(),");
    const auto window = args.find("cfg_.mfa_step_up_window_secs");
    const auto enforcement = args.find("cfg_.mfa_enforcement");
    const auto metrics = args.find("&metrics_");
    REQUIRE(db != std::string::npos);
    REQUIRE(window != std::string::npos);
    REQUIRE(enforcement != std::string::npos);
    REQUIRE(metrics != std::string::npos);
    CHECK(db < window);
    CHECK(window < enforcement);
    CHECK(enforcement < metrics);

    // The pre-request deps block, built per request inside the pre-request handler.
    const auto pre_request = src.find("web_server_->set_pre_request_handler(");
    const auto deps = src.find("const StepUpChokepointDeps step_up_deps{", pre_request);
    REQUIRE(pre_request != std::string::npos);
    REQUIRE(deps != std::string::npos);
    const auto stage = src.find("detail::run_pre_request_stage(req, res, step_up_deps);", deps);
    REQUIRE(stage != std::string::npos);
    const std::string block = src.substr(deps, stage - deps);
    for (const std::string_view needle :
         {".resolve_session = &step_up_resolve,", ".auth_db = auth_mgr_.auth_db_ptr(),",
          ".audit_fn = &step_up_audit,", ".metrics = &metrics_,",
          ".window_secs = cfg_.mfa_step_up_window_secs,", ".mfa_enforcement = cfg_.mfa_enforcement"}) {
        INFO("missing from the deps block: " << needle);
        CHECK(block.find(needle) != std::string::npos);
    }
}
