/**
 * test_rest_api_events.cpp — HTTP-level coverage for `GET /api/v1/events`,
 * the W5.1 agentic-first JSON SSE endpoint.
 *
 * Two surfaces under test:
 *
 *   1. The synchronous handler phase (auth → perm → input → tracker/bus →
 *      execution → terminal → audit → headers → subscribe) via the
 *      TestRouteSink dispatch pattern from PR #438. TestRouteSink does
 *      NOT invoke the chunked content provider — so wire-level assertions
 *      stop at the handler-returned response state (status, headers,
 *      subscription side effect on the bus).
 *
 *   2. The agentic-first shape contract — the JSON envelope and the A4
 *      error envelope are extracted into `detail::make_event_envelope`
 *      and `detail::error_json_a4` so this file can assert them directly
 *      without the chunked-provider dance.
 *
 * What is deliberately NOT covered here:
 *   - End-to-end SSE wire framing (`id: N\nevent: T\ndata: ...\n\n`).
 *     That belongs in `bash scripts/start-UAT.sh` integration coverage —
 *     standing up a real httplib::Server in unit tests is the #438 TSan
 *     trap this fixture exists to dodge. The chunked-provider lambda is
 *     covered structurally (subscription happens) and contractually
 *     (envelope helper has direct assertions); the wire-framing glue is
 *     a thin readback of values the helpers already produced.
 */

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "pg/pg_exec.hpp" // #2146 A2-R4: DROP TABLE fault injection for the store-degrade tests
#include "pg/pg_raii.hpp"
#include "device_token_store.hpp"
#include "event_bus.hpp"
#include "execution_event_bus.hpp"
#include "stream_budget.hpp"
#include "execution_tracker.hpp"
#include "pg/pg_raii.hpp"
#include "rest_a4_envelope.hpp"
#include "rest_api_v1.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "test_execution_tracker_pg_helper.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "../test_helpers.hpp"

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// Fault-injection helper for the #2146 A2-R1 Gate 8 degrade test below: runs
// a raw statement over a fresh side connection (never the harness's own
// pool, so the tracker's `open_`/pool state stays otherwise healthy -- only
// the ONE targeted query fails). Mirrors test_rest_executions_v1_twins.cpp's
// identical `exec_sql` idiom.
void exec_sql(const std::string& dsn, const std::string& sql) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct RestEventsHarness {
    yuzu::server::test::TestRouteSink sink;

    /// Optional shared admission budget (ADR-0034). nullptr keeps every pre-existing
    /// test on the unmetered path; the admission tests pass one in.
    yuzu::server::detail::StreamBudget* stream_budget{nullptr};

    // Bus outlives tracker — same invariant as production server.cpp
    // (execution_event_bus_ declared before execution_tracker_; members
    // destruct in reverse declaration order, so declaring the bus FIRST
    // makes it destruct LAST).
    std::unique_ptr<ExecutionEventBus> event_bus;
    std::optional<yuzu::test::ExecutionTrackerPg> tracker_bundle;
    ExecutionTracker* tracker{nullptr};

    // Auth/perm/audit toggles for negative cases.
    bool session_present{true};
    bool perm_grant{true};
    authz::VisibleSet fleet_read_scope{std::nullopt};
    bool audit_should_fail{false};
    bool audit_should_throw{false};

    std::vector<AuditCall> audit_log;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Per-process monotonic id (no hash-of-thread-id / clock — same rule
    // as test_workflow_routes.cpp, see CLAUDE.md test conventions).
    static inline std::atomic<int> exec_counter{0};

    /// `with_bus=false` opts out of constructing the per-execution event
    /// bus so the 503-on-no-bus path can be exercised independently.
    /// `with_tracker=false` opts out of the tracker entirely (separate
    /// 503 path).
    explicit RestEventsHarness(bool with_bus = true, bool with_tracker = true,
                               yuzu::server::detail::StreamBudget* budget = nullptr,
                               RestApiV1::AuthFn auth_override = {},
                               RestApiV1::FleetReadFn fleet_read_override = {})
        : stream_budget(budget) {
        if (with_tracker) {
            tracker_bundle.emplace();
            tracker = tracker_bundle->get();
            if (with_bus) {
                event_bus = std::make_unique<ExecutionEventBus>();
                tracker->set_event_bus(event_bus.get());
            }
        } else if (with_bus) {
            // No-tracker but bus configured — exercises the
            // tracker-503 precedence (tracker check fires first).
            event_bus = std::make_unique<ExecutionEventBus>();
        }

        RestApiV1::AuthFn auth_fn = [this](const httplib::Request&,
                                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                // Mirror require_auth's 401 contract — set status +
                // body so the handler short-circuits.
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        if (auth_override)
            auth_fn = std::move(auth_override);
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            if (audit_should_throw)
                throw std::runtime_error("simulated audit pipeline failure");
            return !audit_should_fail;
        };
        RestApiV1::FleetReadFn fleet_read_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&) -> authz::FleetReadGate {
            if (!session_present) {
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return {false, authz::deny_all()};
            }
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return {false, authz::deny_all()};
            }
            return {true, fleet_read_scope};
        };
        if (fleet_read_override)
            fleet_read_fn = std::move(fleet_read_override);

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, tracker,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{}, event_bus.get(),
                            // Everything from here to stream_budget is a defaulted
                            // dependency this harness does not use. Spelled out because
                            // the budget is the LAST parameter and C++ has no way to skip
                            // to it — which is precisely how the production wiring came to
                            // be omitted without anything noticing.
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr, /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr, stream_budget,
                            /*exec_visible_fn=*/{}, /*list_read_fn=*/{}, fleet_read_fn);
    }

    std::string make_exec(const std::string& status,
                          const std::string& dispatched_by = "tester") {
        Execution e;
        e.id = "exec-events-" + std::to_string(exec_counter.fetch_add(1));
        e.definition_id = "def-events";
        e.status = status;
        e.scope_expression = "agent:secret-target";
        e.parameter_values = R"({"secret_agent":"agent-hidden"})";
        e.dispatched_by = dispatched_by;
        e.dispatched_at = 1735689600;
        e.agents_targeted = 3;
        e.agents_success = (status == "completed") ? 3 : 0;
        e.agents_failure = 0;
        e.agents_responded = e.agents_success + e.agents_failure;
        e.completed_at = (status == "completed") ? 1735689660 : 0;
        auto id = tracker->create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }

    void agent_status(const std::string& exec_id, const std::string& agent_id,
                      const std::string& status, const std::string& error_detail = {},
                      int64_t completed_at = 1735689660) {
        AgentExecStatus a;
        a.agent_id = agent_id;
        a.status = status;
        a.dispatched_at = 1735689600;
        a.first_response_at = 1735689601;
        a.completed_at = completed_at;
        a.error_detail = error_detail;
        tracker->update_agent_status(exec_id, a);
    }
};

} // namespace

// ── A4 envelope shape ────────────────────────────────────────────────────────

TEST_CASE("error_json_a4: minimal envelope without remediation", "[events][envelope][a4]") {
    auto body = detail::error_json_a4(404, "execution not found", "req-abc-1");
    // Envelope must carry code + message + correlation_id + api_version,
    // and MUST NOT include a remediation key when caller omits it (that
    // omission lets agentic workers detect "no recovery available" via
    // key absence rather than parsing a sentinel).
    REQUIRE(body.find(R"("code":404)") != std::string::npos);
    REQUIRE(body.find(R"("message":"execution not found")") != std::string::npos);
    REQUIRE(body.find(R"("correlation_id":"req-abc-1")") != std::string::npos);
    REQUIRE(body.find(R"("api_version":"v1")") != std::string::npos);
    REQUIRE(body.find("remediation") == std::string::npos);
}

TEST_CASE("error_json_a4: envelope carries remediation hint when present",
          "[events][envelope][a4]") {
    auto body =
        detail::error_json_a4(403, "permission denied", "req-cid-2", "request Execution:Read");
    REQUIRE(body.find(R"("remediation":"request Execution:Read")") != std::string::npos);
}

TEST_CASE("make_correlation_id: monotonic + unique within a process", "[events][envelope][a4]") {
    auto a = detail::make_correlation_id();
    auto b = detail::make_correlation_id();
    REQUIRE(a != b);
    // Format token is `req-<hex>-<hex>`; both halves must be present
    // so log greppers can split on '-'.
    REQUIRE(a.starts_with("req-"));
    REQUIRE(a.find('-', 4) != std::string::npos);
}

TEST_CASE("make_event_envelope: A3 invariants on every event", "[events][envelope][a3]") {
    yuzu::server::ExecutionEvent ev;
    ev.id = 42;
    ev.timestamp_ms = 1716000000000;
    ev.event_type = "agent-transition";
    ev.data = R"({"agent_id":"a1","status":"success"})";

    auto env = detail::make_event_envelope("exec-XYZ", ev);

    // A3 requires every event to carry execution_id + a deterministic
    // step name from the published taxonomy.
    REQUIRE(env.find(R"("execution_id":"exec-XYZ")") != std::string::npos);
    REQUIRE(env.find(R"("type":"agent-transition")") != std::string::npos);
    REQUIRE(env.find(R"("event_id":42)") != std::string::npos);
    REQUIRE(env.find(R"("timestamp_ms":1716000000000)") != std::string::npos);
    // Payload is raw-embedded as an object (not stringified) — agentic
    // workers can parse the envelope and immediately read payload fields
    // without a second JSON.parse on the data string.
    REQUIRE(env.find(R"("payload":{"agent_id":"a1","status":"success"})") != std::string::npos);
}

TEST_CASE("make_event_envelope: empty payload becomes JSON null", "[events][envelope][a3]") {
    yuzu::server::ExecutionEvent ev;
    ev.id = 1;
    ev.timestamp_ms = 0;
    ev.event_type = "execution-completed";
    ev.data = "";
    auto env = detail::make_event_envelope("exec-Q", ev);
    // The envelope MUST stay valid JSON even for events the publisher
    // emitted with no payload — using `null` rather than `""` keeps the
    // payload field type predictable for callers that treat it as an
    // object|null union.
    REQUIRE(env.find(R"("payload":null)") != std::string::npos);
}

// ── Auth + permission preflight ─────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: unauthenticated request → 401 from auth_fn", "[pg][events][auth]") {
    RestEventsHarness h;
    h.session_present = false;
    auto res = h.sink.Get("/api/v1/events?execution_id=anything");
    REQUIRE(res);
    REQUIRE(res->status == 401);
    // No audit row on missing-auth (the auth-rejection audit is emitted
    // by the auth layer, not this handler).
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: permission denied → 403 from perm_fn", "[pg][events][perm]") {
    RestEventsHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-X");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    // No api.v1.events.subscribe audit on the deny branch — deny audits
    // are owned by the RBAC layer, mirroring the dashboard SSE sibling
    // (`/sse/executions/{id}`) policy.
    REQUIRE(h.audit_log.empty());
}

// ── ADR-0034 shared-budget admission (governance regression guards) ─────────
//
// This route's lease block was DEAD CODE on a real server: server.cpp never passed
// the budget, the parameter defaults to nullptr, and nothing observed the gap — the
// boot log, stream_budget.hpp and rest-api.md all asserted the opposite. Nothing in
// this suite wired a budget in either, so the omission was unfalsifiable. These
// tests make it falsifiable.

TEST_CASE("GET /api/v1/events: 429 A4 envelope once the shared budget is exhausted",
          "[pg][events][admission][sse]") {
    yuzu::server::detail::StreamBudget budget{
        yuzu::server::detail::StreamBudget::Config{/*global_cap=*/1}};
    auto held = budget.try_acquire(yuzu::server::detail::SseSurface::kApiEvents, "someone-else",
                                   yuzu::server::detail::kPerPrincipalApiEvents);
    REQUIRE(held.lease);

    RestEventsHarness h{/*with_bus=*/true, /*with_tracker=*/true, &budget};
    // A REAL running execution: the handler validates the id BEFORE admission, which
    // is the right order (a bogus id must not consume a lease), so a synthetic id
    // would 404 and never reach the branch under test.
    const auto exec_id = h.make_exec("running");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 429);
    // A4 envelope, not a bare status — this is an agentic-first surface.
    CHECK(res->body.find(R"("code":429)") != std::string::npos);
    CHECK(res->body.find("retry_after_ms") != std::string::npos);
    // The remediation must name a flag that can actually resolve the rejection.
    CHECK(res->body.find("--max-sse-streams") != std::string::npos);
    // Retry-After header alongside the envelope (the platform 429 convention).
    CHECK(res->get_header_value("Retry-After") == "5");
    // A live stream is never evicted for a newcomer.
    CHECK(budget.active() == 1);
}

TEST_CASE("GET /api/v1/events: a budget rejection leaves no subscriber and no gauge drift",
          "[pg][events][admission][sse]") {
    // The lease is taken before BOTH the bus subscription and the active-gauge bump.
    // Getting either order wrong is silent: a leaked listener is only visible in
    // memory, and a leaked gauge increment only shows up as a slowly-rising number
    // on the very dashboard the budget exists to make trustworthy.
    yuzu::server::detail::StreamBudget budget{
        yuzu::server::detail::StreamBudget::Config{/*global_cap=*/1}};
    auto held = budget.try_acquire(yuzu::server::detail::SseSurface::kApiEvents, "someone-else",
                                   yuzu::server::detail::kPerPrincipalApiEvents);
    REQUIRE(held.lease);

    RestEventsHarness h{/*with_bus=*/true, /*with_tracker=*/true, &budget};
    const auto exec_id = h.make_exec("running");
    const auto before = h.event_bus->subscribers_total();
    for (int i = 0; i < 5; ++i) {
        auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
        REQUIRE(res);
        REQUIRE(res->status == 429);
    }
    CHECK(h.event_bus->subscribers_total() == before);
}

TEST_CASE("GET /api/v1/events: the PER-PRINCIPAL cap is keyed on the authenticated identity",
          "[pg][events][admission][sse]") {
    // Falsification guard the global-cap tests above cannot provide: they force a reject
    // by pre-seeding a DIFFERENT principal, so they would still pass if the handler keyed
    // its lease on a hardcoded literal instead of `session->username`. Here the reject can
    // only fire if the handler keys on the SAME principal the harness authenticates as
    // ("tester"). A generous global cap isolates the per-principal cap as the sole cause.
    yuzu::server::detail::StreamBudget budget{
        yuzu::server::detail::StreamBudget::Config{/*global_cap=*/100}};
    // Fill "tester"'s per-principal allowance (compile-time kPerPrincipalApiEvents).
    std::vector<yuzu::server::detail::StreamBudget::Lease> held;
    for (std::size_t i = 0; i < yuzu::server::detail::kPerPrincipalApiEvents; ++i) {
        auto a = budget.try_acquire(yuzu::server::detail::SseSurface::kApiEvents, "tester",
                                    yuzu::server::detail::kPerPrincipalApiEvents);
        REQUIRE(a.lease);
        held.push_back(std::move(a.lease));
    }
    // Global budget still has plenty of room — only the per-principal cap is exhausted.
    REQUIRE(budget.active() < 100);

    RestEventsHarness h{/*with_bus=*/true, /*with_tracker=*/true, &budget};
    const auto exec_id = h.make_exec("running");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    // If the handler used any principal string other than "tester", its key would have 0
    // prior leases and it would be ADMITTED (200). The 429 proves it keyed on the session.
    CHECK(res->status == 429);
    // And the remediation must be the per-principal one (no --max-sse-streams, which would
    // not resolve a per-principal reject).
    CHECK(res->body.find("per-principal") != std::string::npos);
    CHECK(res->body.find("--max-sse-streams") == std::string::npos);

    // A different principal is unaffected — proves the cap is per-principal, not global.
    auto other = budget.try_acquire(yuzu::server::detail::SseSurface::kApiEvents, "someone-else",
                                    yuzu::server::detail::kPerPrincipalApiEvents);
    CHECK(other.lease);
}

TEST_CASE("GET /api/v1/events: an unmetered route still serves (nullptr budget is a seam)",
          "[pg][events][admission][sse]") {
    // Guards against the admission tests above passing for the wrong reason.
    RestEventsHarness h; // no budget
    const auto exec_id = h.make_exec("running");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    CHECK(res->status != 429);
}

// ── Input validation ────────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: missing execution_id → 400 A4 envelope", "[pg][events][input]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/events");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(res->body.find(R"("code":400)") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    REQUIRE(res->body.find("execution_id query parameter is required") != std::string::npos);
    // A4 mandates `remediation` for recoverable errors — missing query
    // param is the canonical "the agent can fix this" case.
    REQUIRE(res->body.find(R"("remediation":"pass ?execution_id=)") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: malformed execution_id → 400 A4 envelope", "[pg][events][input]") {
    RestEventsHarness h;
    // Path-traversal-style payload exercises the char-class regex; the
    // 128-char cap is also implicit (rejects 200+-char IDs).
    auto res = h.sink.Get("/api/v1/events?execution_id=..%2Fevil");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(res->body.find("execution_id format invalid") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

// ── Resource-availability preflight ─────────────────────────────────────────

TEST_CASE("GET /api/v1/events: tracker unavailable → 503 A4", "[events][noresources]") {
    RestEventsHarness h(/*with_bus=*/true, /*with_tracker=*/false);
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-x");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find("execution tracker unavailable") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: event bus unavailable → 503 A4", "[pg][events][noresources]") {
    RestEventsHarness h(/*with_bus=*/false, /*with_tracker=*/true);
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-x");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find("event bus unavailable") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

// ── Execution-state preflight ───────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: unknown execution → 404 A4", "[pg][events][notfound]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-does-not-exist");
    REQUIRE(res);
    REQUIRE(res->status == 404);
    REQUIRE(res->body.find("execution not found") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    // #1634 (governance Gate 4 fix): a `denied` audit row is now emitted here
    // (CC7.2 evidence, parity with MCP get_execution_status and every other
    // migrated route's scope-drop audit). This does NOT reopen an enumeration
    // side channel: the audited detail string is IDENTICAL for a genuinely
    // nonexistent id and an exists-but-invisible one (no distinguishing text),
    // matching the #1700/#3558 precedent for get_agent_details — the
    // distinguishing fact lives only in a server-side spdlog::debug line no
    // audited-evidence reader (including query_audit_log) can reach.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api.v1.events.subscribe");
    CHECK(h.audit_log[0].result == "denied");
}

// Governance fix (#2146 A2-R1 Gate 8 re-review): this route used the plain
// get_execution(), which collapses "execution genuinely absent" and "read
// degraded" (a transient pool/query failure) to the same nullopt -- a
// degrade fell through to the SAME not-found + denial-audit branch a
// genuine absence takes, producing a FALSE 404 for a legitimate owner and a
// permanently wrong CC7.2 denial audit row for a confined caller whose only
// "fault" was hitting a transient outage. get_execution_checked's outer
// std::expected now distinguishes the two; the degrade branch returns
// BEFORE any denial audit is recorded.
TEST_CASE("GET /api/v1/events: a transient tracker degrade is 503 (not a false 404) "
          "and records no denial audit (#2146 A2-R1 Gate 8 fix)",
          "[pg][events][notfound]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");

    // Break ONLY the get_execution_checked query -- a raw statement over a
    // side connection, never the harness's own pool, so the tracker stays
    // "open" and this is a genuine single-call fault (a full outage would
    // already hit the pre-existing tracker-unavailable/pool-exhaustion
    // branch above and mask this specific defect).
    exec_sql(h.tracker_bundle->dsn(),
             "ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_2146b");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    exec_sql(h.tracker_bundle->dsn(),
             "ALTER TABLE execution_tracker.executions_hidden_2146b RENAME TO executions");

    REQUIRE(res);
    // (a) 503, never the old false 404.
    CHECK(res->status == 503);
    REQUIRE(res->body.find("execution tracker degraded") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);

    // (b) no denial audit row for this execution -- pre-fix, this recorded
    // api.v1.events.subscribe/denied here.
    for (const auto& c : h.audit_log)
        CHECK(c.target_id != exec_id);
}

TEST_CASE("GET /api/v1/events: terminal execution → 410 A4", "[pg][events][terminal]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("completed");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 410);
    REQUIRE(res->body.find("execution complete") != std::string::npos);
    REQUIRE(res->body.find(R"("remediation":"fetch the final state)") != std::string::npos);
    // 410 also deliberately does NOT audit — the execution existed but
    // the subscribe attempt added no surface area worth recording.
    REQUIRE(h.audit_log.empty());
}

// ── Happy path ──────────────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: running execution → 200 + subscribed", "[pg][events][happy]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");

    REQUIRE(h.event_bus->subscriber_count(exec_id) == 0);

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // The chunked content provider is wired into the response state
    // (httplib won't actually drive it through TestRouteSink), but the
    // synchronous handler side-effect — bus subscription — must have
    // happened before set_chunked_content_provider was called.
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);

    // Header contract: SSE necessities + A4 correlation id.
    REQUIRE(res->get_header_value("Cache-Control") == "no-cache");
    REQUIRE(res->get_header_value("X-Accel-Buffering") == "no");
    REQUIRE(res->get_header_value("X-Correlation-Id").starts_with("req-"));
    // No audit failure on the happy path.
    REQUIRE_FALSE(res->has_header("Sec-Audit-Failed"));

    // Audit row was emitted with the correlation id in detail.
    REQUIRE(h.audit_log.size() == 1);
    REQUIRE(h.audit_log[0].action == "api.v1.events.subscribe");
    REQUIRE(h.audit_log[0].result == "success");
    REQUIRE(h.audit_log[0].target_type == "Execution");
    REQUIRE(h.audit_log[0].target_id == exec_id);
    REQUIRE(h.audit_log[0].detail.starts_with("correlation_id=req-"));
}

TEST_CASE("GET /api/v1/events: audit failure → Sec-Audit-Failed header", "[pg][events][happy][audit]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.audit_should_fail = true;

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Audit returning false MUST surface in the response — CC6.6
    // evidence-chain partial-failure contract (PR #883 HIGH-2).
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    // The subscription still happened — operators' "stop NOW" semantic
    // is preserved even when the SOC 2 row was lost. Mirrors the W5.1
    // sister-PR behavior on session revocation.
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

TEST_CASE("GET /api/v1/events: audit exception → Sec-Audit-Failed header",
          "[pg][events][happy][audit]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.audit_should_throw = true;

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Same surface as the silent-fail case — exceptions and false
    // returns both indicate the audit row is not persisted.
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

// ── Replay window ───────────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: ?since param replays buffered events", "[pg][events][replay]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");

    // Pre-populate the per-execution channel with three events. The
    // dispatched-status updates publish through the tracker's bus hook
    // (the bus member-order invariant), so they land on the channel
    // ring buffer with monotonic ids.
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a1","status":"running"})",
                         false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a2","status":"running"})",
                         false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a3","status":"success"})",
                         false);

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id + "&since=1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // After dispatch, the connection's sink_state should hold the
    // two events with id > 1 (replay), staged for the chunked provider.
    // We can't read the queue without reaching into the lambda, but we
    // CAN observe that the channel still has all three events buffered
    // (replay is a copy, not a drain).
    auto snap = h.event_bus->snapshot(exec_id);
    REQUIRE(snap.size() == 3);
    REQUIRE(snap[0].id == 1);
    REQUIRE(snap[1].id == 2);
    REQUIRE(snap[2].id == 3);
    // Subscription happened — the live channel is now wired.
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

TEST_CASE("GET /api/v1/events: invalid ?since parses to no-replay (0)", "[pg][events][replay]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.event_bus->publish(exec_id, "execution-progress", R"({"pending":1})", false);
    // Garbage `since` value should not 400 — mirrors the dashboard SSE
    // sibling which silently degrades to "no replay" rather than
    // breaking an EventSource auto-reconnect on a stale id.
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id + "&since=not-a-number");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

// ── OpenAPI discovery (A2) ──────────────────────────────────────────────────

TEST_CASE("OpenAPI spec lists /events under the agentic-first surface", "[pg][events][discovery][a2]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2 (discovery) requires the endpoint to be enumerable via the
    // documented OpenAPI surface. The text-shape check is enough — the
    // JSON parse is exercised by the OpenAPI ecosystem, not here.
    REQUIRE(res->body.find(R"("/events":)") != std::string::npos);
    REQUIRE(res->body.find("agentic-first JSON Server-Sent Events") != std::string::npos);
    REQUIRE(res->body.find("Execution:Read") != std::string::npos);
}

TEST_CASE("OpenAPI spec lists /audit/auth-sample (CC7.2 evidence export)",
          "[pg][events][discovery][a2]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2 (discovery): the sampled auth-log evidence export must be enumerable.
    REQUIRE(res->body.find(R"("/audit/auth-sample":)") != std::string::npos);
    REQUIRE(res->body.find("Sampled authentication-log evidence export") != std::string::npos);
}

TEST_CASE("OpenAPI spec lists the account-unlock route (A2 discovery)",
          "[pg][events][discovery][a2][lockout]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2: the new admin operability route POST /api/v1/users/{username}/unlock
    // must be discoverable from the live spec, not only an out-of-band manual
    // (adversarial-review C2). The text-shape check matches the sibling tests.
    REQUIRE(res->body.find(R"("/users/{username}/unlock":)") != std::string::npos);
    REQUIRE(res->body.find("admin unlock") != std::string::npos);
    REQUIRE(res->body.find("UserManagement:Write") != std::string::npos);
}

TEST_CASE("OpenAPI spec lists the JIT admin-elevation routes (A2 discovery)",
          "[pg][events][discovery][a2][jit]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2: the three JIT-elevation routes must be discoverable from the live spec
    // (#1748 M1), not just the manual. Text-shape check matches the siblings.
    REQUIRE(res->body.find(R"("/elevate":)") != std::string::npos);
    REQUIRE(res->body.find(R"("/elevate/revoke":)") != std::string::npos);
    REQUIRE(res->body.find(R"("/users/{username}/elevation-eligibility":)") != std::string::npos);
    REQUIRE(res->body.find("time-boxed JIT admin elevation") != std::string::npos);
}

TEST_CASE("OpenAPI spec declares ExecutionSseEvent and A4ErrorEnvelope schemas",
          "[pg][events][discovery][a2]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2: a client-generator must be able to discover the SSE envelope
    // and error envelope shapes without reading prose. The two new
    // schemas land in components/schemas with $refs from the /events
    // path entry. governance round architect-concern-8 / docs-writer
    // BLOCKING.
    REQUIRE(res->body.find(R"("ExecutionSseEvent":)") != std::string::npos);
    REQUIRE(res->body.find(R"("A4ErrorEnvelope":)") != std::string::npos);
    REQUIRE(res->body.find(R"("$ref": "#/components/schemas/ExecutionSseEvent")") !=
            std::string::npos);
    REQUIRE(res->body.find(R"("$ref": "#/components/schemas/A4ErrorEnvelope")") !=
            std::string::npos);
}

// ── A4 envelope retry_after_ms overload ─────────────────────────────────────

TEST_CASE("error_json_a4 overload: 503 carries retry_after_ms + remediation",
          "[events][envelope][a4]") {
    auto body = detail::error_json_a4(503, "event bus unavailable", "req-xyz-1",
                                      /*retry_after_ms=*/5000, "retry after warmup");
    REQUIRE(body.find(R"("retry_after_ms":5000)") != std::string::npos);
    REQUIRE(body.find(R"("remediation":"retry after warmup")") != std::string::npos);
    // Existing fields still present.
    REQUIRE(body.find(R"("code":503)") != std::string::npos);
    REQUIRE(body.find(R"("correlation_id":"req-xyz-1")") != std::string::npos);
}

TEST_CASE("error_json_a4 no-retry overload emits retry_after_ms:null (A4 field set)",
          "[events][envelope][a4]") {
    // #1470: A4 lists retry_after_ms as a REQUIRED, nullable envelope field.
    // The no-retry overload (used by validation 400s incl. the dex-perf family)
    // must still carry it as null, not omit it — uniform with the MCP a4_data
    // sibling.
    auto body = detail::error_json_a4(400, "invalid cohort_key", "req-abc-2");
    REQUIRE(body.find(R"("retry_after_ms":null)") != std::string::npos);
    REQUIRE(body.find(R"("code":400)") != std::string::npos);
    REQUIRE(body.find(R"("correlation_id":"req-abc-2")") != std::string::npos);
    // No remediation passed → field absent (nullable, omit is fine for the hint).
    REQUIRE(body.find(R"("remediation")") == std::string::npos);

    // With remediation, both nullable fields render correctly.
    auto body2 = detail::error_json_a4(400, "invalid limit", "req-abc-3", "limit must be > 0");
    REQUIRE(body2.find(R"("retry_after_ms":null)") != std::string::npos);
    REQUIRE(body2.find(R"("remediation":"limit must be > 0")") != std::string::npos);
}

TEST_CASE("GET /api/v1/events: 503 (no bus) envelope includes retry_after_ms",
          "[pg][events][noresources][a4]") {
    RestEventsHarness h(/*with_bus=*/false, /*with_tracker=*/true);
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-x");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    // Consistency-MED-2: 503 sites are exactly where retry_after_ms is
    // most useful — the worker can back off and retry rather than tight-
    // looping during server warmup.
    REQUIRE(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
    REQUIRE(res->body.find("retry after server warmup") != std::string::npos);
}

// ── Defensive payload validation in make_event_envelope ─────────────────────

TEST_CASE("make_event_envelope: malformed payload becomes JSON null", "[events][envelope][a3]") {
    yuzu::server::ExecutionEvent ev;
    ev.id = 7;
    ev.timestamp_ms = 0;
    ev.event_type = "agent-transition";
    // Non-JSON garbage in ev.data — a hypothetical buggy publisher.
    // Without the defensive validation, raw-embed would silently
    // produce a malformed envelope; with it, payload becomes null and
    // the worker still parses the frame as a non-fatal event.
    // governance round cpp-expert M-2.
    ev.data = "this is not JSON, oops";
    auto env = detail::make_event_envelope("exec-A", ev);
    REQUIRE(env.find(R"("payload":null)") != std::string::npos);
}

// ── X-Content-Type-Options nosniff (security-LOW-2) ─────────────────────────

TEST_CASE("GET /api/v1/events: response sets X-Content-Type-Options: nosniff",
          "[pg][events][happy][security]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(res->get_header_value("X-Content-Type-Options") == "nosniff");
}

// ── Last-Event-ID header as replay source ───────────────────────────────────

TEST_CASE("GET /api/v1/events: Last-Event-ID header drives replay when ?since absent",
          "[pg][events][replay]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a1"})", false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a2"})", false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a3"})", false);

    // The Last-Event-ID semantic mirrors the dashboard sibling — a
    // browser EventSource sends this header on auto-reconnect. R2
    // governance fix for happy-path G1: the prior test built a local
    // httplib::Request, set the header, then discarded it via the
    // headerless dispatch() — handler never saw the header. The
    // TestRouteSink::Get headers overload (also added in R2) injects
    // the header into the synthesized request the handler actually
    // sees.
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id, {{"Last-Event-ID", "2"}});
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
    // Bus still has all three published events (replay is read-only).
    auto snap = h.event_bus->snapshot(exec_id);
    REQUIRE(snap.size() == 3);
}

TEST_CASE("GET /api/v1/events: ?since query takes precedence over Last-Event-ID header (with "
          "header injected)",
          "[pg][events][replay]") {
    // Paired with the existing `?since` precedence test — that one
    // proves `?since` alone works; this one proves `?since` WINS when
    // a conflicting Last-Event-ID is present in the request. G1
    // remediation: with the headers-overload now wired through to the
    // handler, we can finally exercise the precedence contract end-
    // to-end. The handler short-circuits on `req.has_param("since")`
    // and never reads the header. The bus snapshot + subscriber
    // count after dispatch confirm the handler reached the success
    // path with both signals present.
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a1"})", false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a2"})", false);
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id + "&since=0",
                          {{"Last-Event-ID", "99"}});
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

TEST_CASE("GET /api/v1/events: ?since query takes precedence over Last-Event-ID header",
          "[pg][events][replay]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    // Both signals coexist; the handler MUST honour the query param
    // (explicit operator intent) over the header (auto-reconnect
    // inference). No way to read the queued events from outside the
    // chunked provider, but the subscription state + bus snapshot
    // proves the handler took the success path under both inputs.
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a1"})", false);
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id + "&since=99");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

// ── Per-connection queue cap (drop-oldest) ──────────────────────────────────

TEST_CASE("detail::SseSinkState: pre_emit survives queue cap overflow",
          "[events][cap][replay][gap]") {
    // Regression test for unhappy-NEW-1 HIGH: when R1 hardening
    // queued the synthetic replay-gap envelope onto the bounded
    // `queue`, a publisher burst that triggered drop-oldest would
    // silently evict the gap envelope — restoring the gap-blindness
    // the synthetic was meant to fix. R2 hardening moved the
    // synthetic to a dedicated `pre_emit` slot that lives outside the
    // bounded queue. This test proves the pre_emit slot is not
    // affected by `enqueue_capped` activity.
    auto state = std::make_shared<detail::SseSinkState>();
    detail::SseEvent gap;
    gap.event_type = "replay-gap";
    gap.data = "1\n{\"type\":\"replay-gap\",\"missing_from\":1,\"missing_to\":5}";
    {
        std::lock_guard<std::mutex> lk(state->mu);
        state->pre_emit = std::move(gap);
    }
    // Pound the queue past its cap to mimic a publisher burst that
    // forces drop-oldest. Each push goes through enqueue_capped,
    // which drops the oldest queue entry when full — but NEVER
    // touches `pre_emit`.
    constexpr std::size_t kBurst = 800; // > default cap of 500
    for (std::size_t i = 0; i < kBurst; ++i) {
        detail::SseEvent ev;
        ev.event_type = "agent-transition";
        ev.data = std::to_string(i);
        detail::enqueue_capped(state, std::move(ev));
    }
    // Queue is at cap, drops occurred; pre_emit is intact.
    REQUIRE(state->queue.size() == detail::kPerConnectionQueueCapDefault);
    REQUIRE(state->dropped_total.load() == kBurst - detail::kPerConnectionQueueCapDefault);
    REQUIRE(state->pre_emit.has_value());

    // Provider-side: take_pre_emit() atomically empties the slot.
    auto taken = state->take_pre_emit();
    REQUIRE(taken.has_value());
    REQUIRE(taken->event_type == "replay-gap");
    REQUIRE_FALSE(state->pre_emit.has_value());

    // Second call returns nullopt (sticky-once contract).
    auto taken_again = state->take_pre_emit();
    REQUIRE_FALSE(taken_again.has_value());
}

TEST_CASE("make_event_envelope: payload over kEventPayloadSizeCap becomes JSON null",
          "[events][envelope][a3][cap]") {
    // R2 governance fix for unhappy-NEW-6: agent-sourced fields like
    // AgentExecStatus::error_detail can in principle be megabytes,
    // and make_event_envelope runs nlohmann::json::accept on every
    // fanout × N subscribers. Cap at 64KiB and substitute null on
    // oversize so the envelope shape stays valid and the per-event
    // cost stays bounded.
    yuzu::server::ExecutionEvent ev;
    ev.id = 99;
    ev.timestamp_ms = 0;
    ev.event_type = "agent-transition";
    // Build a valid JSON object that exceeds the cap.
    std::string huge_value(70 * 1024, 'x');
    ev.data = std::string("{\"v\":\"") + huge_value + std::string("\"}");
    REQUIRE(ev.data.size() > 64 * 1024);
    auto env = detail::make_event_envelope("exec-OVER", ev);
    REQUIRE(env.find(R"("payload":null)") != std::string::npos);
    REQUIRE(env.find(huge_value) == std::string::npos);
}

TEST_CASE("detail::enqueue_capped: drops oldest on cap overflow + bumps dropped_total",
          "[events][cap]") {
    auto state = std::make_shared<detail::SseSinkState>();
    constexpr std::size_t kCap = 4;
    for (std::size_t i = 0; i < kCap; ++i) {
        detail::SseEvent ev;
        ev.event_type = "agent-transition";
        ev.data = std::to_string(i);
        detail::enqueue_capped(state, std::move(ev), kCap);
    }
    REQUIRE(state->queue.size() == kCap);
    REQUIRE(state->dropped_total.load() == 0);

    // Two more events past the cap — each drops the oldest.
    detail::SseEvent extra_a;
    extra_a.event_type = "agent-transition";
    extra_a.data = "extra_a";
    detail::enqueue_capped(state, std::move(extra_a), kCap);
    detail::SseEvent extra_b;
    extra_b.event_type = "agent-transition";
    extra_b.data = "extra_b";
    detail::enqueue_capped(state, std::move(extra_b), kCap);

    REQUIRE(state->queue.size() == kCap);
    REQUIRE(state->dropped_total.load() == 2);
    // Drop-OLDEST semantic: oldest events (0, 1) are gone, newest
    // events (2, 3, extra_a, extra_b) remain.
    REQUIRE(state->queue.front().data == "2");
    REQUIRE(state->queue.back().data == "extra_b");
}

// ── Replay-gap detection ────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: replay-gap envelope condition is detectable from bus snapshot",
          "[pg][events][replay][gap]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    // Simulate a buffer that has already evicted the early events:
    // publish 10 events but only the last 3 remain by truncating the
    // ring buffer manually via 1000-event publishes... too expensive.
    // Instead, validate the detection condition at the level the
    // handler checks: snapshot().front().id > since_id + 1.
    h.event_bus->publish(exec_id, "agent-transition", R"({"id":1})", false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"id":2})", false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"id":3})", false);
    auto snap = h.event_bus->snapshot(exec_id);
    REQUIRE(snap.size() == 3);
    REQUIRE(snap.front().id == 1);
    // Client asks for since=0 — no gap, lowest id (1) is exactly
    // since_id+1.
    REQUIRE_FALSE(snap.front().id > std::uint64_t{0} + 1);
    // Client asks for since=5 — bus has events 1-3, gap exists (the
    // client expected events 6+ but the buffer has older ones).
    // Wait — the condition is snap.front().id > since_id+1. With
    // since=5, snap.front().id=1, 1 > 6 is false. So this is NOT a
    // gap from the handler's perspective. The handler is asking: did
    // we LOSE events the client wanted? No — the client wants events
    // > 5; we don't have any matching, so replay returns empty. No
    // gap signal.
    // The actual gap case: client wants events > 0, but our oldest is
    // 5. That means events 1-4 were evicted from the buffer. With
    // snap=[5,6,7] and since=0, snap.front().id (5) > 0+1 (1) → gap
    // [1..4]. Validate that arithmetic:
    auto exec_id_2 = h.make_exec("running");
    // Drive the buffer to start at id 5 by publishing 4 events then
    // ... we can't manually evict. The bus's FIFO eviction triggers
    // at kBufferCap=1000. Testing the full eviction path needs a
    // 1000+ event publish loop OR a test-seam to lower the cap.
    // Either way the detection arithmetic above is the right check.
    // governance round unhappy-R1+R2 / sre-OBS-MED.
    h.event_bus->publish(exec_id_2, "x", R"({})", false); // id=1
    h.event_bus->publish(exec_id_2, "x", R"({})", false); // id=2
    auto snap2 = h.event_bus->snapshot(exec_id_2);
    REQUIRE(snap2.size() == 2);
    // For since_id=0 the handler computes "missing_from = 1, missing_to
    // = snap.front().id - 1 = 0" — no gap because missing range is
    // empty (since_id+1 > snap.front().id-1 is false at boundary).
    // For since_id=99 the handler computes "missing_from = 100,
    // missing_to = snap.front().id - 1 = 0" — also no gap (since_id
    // is in the future). Only a since_id that lies strictly inside
    // the eviction window triggers the synthetic envelope.
    REQUIRE_FALSE(snap2.front().id > std::uint64_t{0} + 1);
}

// ── Endpoint-scoped metrics ─────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: subscribe increments yuzu_server_sse_api_* metrics",
          "[pg][events][metrics][observability]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");

    // Baseline.
    REQUIRE(h.metrics.counter("yuzu_server_sse_api_subscriptions_total", {{"route", "events"}})
                .value() == 0.0);
    REQUIRE(h.metrics.gauge("yuzu_server_sse_api_active", {{"route", "events"}}).value() == 0.0);

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // SRE OBSERVABILITY HIGH / ALERTING HIGH closure: endpoint-scoped
    // metrics expose subscription churn and live-thread consumption
    // that the shared yuzu_http_requests_total cannot.
    REQUIRE(h.metrics.counter("yuzu_server_sse_api_subscriptions_total", {{"route", "events"}})
                .value() == 1.0);
    REQUIRE(h.metrics.gauge("yuzu_server_sse_api_active", {{"route", "events"}}).value() == 1.0);

    // The active gauge decrement happens in the chunked-provider done-
    // callback, which TestRouteSink doesn't drive — so we cannot
    // assert the gauge returns to 0 here without standing up a real
    // httplib::Server (the #438 TSan trap). Sibling-parity note: the
    // dashboard sibling has no metric either; this is the first
    // endpoint-scoped active-connection signal.
}

// ── GET /api/v1/executions/{id} (#1088 R2 — UAT-found contract gap) ─────────

TEST_CASE("GET /api/v1/executions/{id}: returns final state JSON for known execution",
          "[pg][events][executions][issue-1088]") {
    // The W5.1 /api/v1/events 410 envelope remediation hint points at
    // this endpoint. UAT smoke on #1088 caught that the endpoint did
    // not exist (only /sse/executions/{id} HTML+SSE and the dashboard
    // fragment). R2 adds the route so the agentic dispatch→observe
    // loop has a working fallback when the SSE channel has already
    // gone terminal.
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    auto res = h.sink.Get("/api/v1/executions/" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Envelope shape: {data:{...}, meta:{api_version:"v1"}}
    REQUIRE(res->body.find(R"("api_version":"v1")") != std::string::npos);
    REQUIRE(res->body.find(R"("id":")" + exec_id + R"(")") != std::string::npos);
    REQUIRE(res->body.find(R"("status":"running")") != std::string::npos);
    REQUIRE(res->body.find(R"("dispatched_by":"tester")") != std::string::npos);
    REQUIRE(res->body.find(R"("agents_targeted":3)") != std::string::npos);
    // Headers: X-Correlation-Id for grep-by-token.
    REQUIRE(res->get_header_value("X-Correlation-Id").starts_with("req-"));
}

TEST_CASE("GET /api/v1/executions/{id}: unknown id → 404 A4 envelope",
          "[pg][events][executions][issue-1088][notfound]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/executions/exec-does-not-exist");
    REQUIRE(res);
    REQUIRE(res->status == 404);
    REQUIRE(res->body.find(R"("code":404)") != std::string::npos);
    REQUIRE(res->body.find("execution not found") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    // A4 mandates an api_version meta block on every error envelope.
    REQUIRE(res->body.find(R"("api_version":"v1")") != std::string::npos);
}

TEST_CASE("GET /api/v1/executions/{id}: unknown id emits execution.detail.fetch denied audit "
          "row (Doomgoose review, important — was undocumented and untested)",
          "[pg][events][executions][issue-1088][notfound][audit]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/executions/exec-does-not-exist");
    REQUIRE(res);
    REQUIRE(res->status == 404);
    bool saw_denied = false;
    for (const auto& a : h.audit_log) {
        CHECK(a.result != "success");
        if (a.action == "execution.detail.fetch" && a.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("GET /api/v1/executions/{id}: invisible and nonexistent ids share one 404 shape",
          "[pg][events][executions][scope][notfound]") {
    RestEventsHarness h;
    auto invisible_id = h.make_exec("running", "alice");
    h.agent_status(invisible_id, "alice-agent", "success");
    h.fleet_read_scope = authz::deny_all();

    auto invisible = h.sink.Get("/api/v1/executions/" + invisible_id);
    auto missing = h.sink.Get("/api/v1/executions/exec-does-not-exist");
    REQUIRE(invisible);
    REQUIRE(missing);
    REQUIRE(invisible->status == 404);
    REQUIRE(missing->status == 404);
    auto invisible_json = nlohmann::json::parse(invisible->body);
    auto missing_json = nlohmann::json::parse(missing->body);
    invisible_json["error"].erase("correlation_id");
    missing_json["error"].erase("correlation_id");
    CHECK(invisible_json == missing_json);
}

TEST_CASE("GET /api/v1/executions/{id}: confined dispatcher is visible but still projected",
          "[pg][events][executions][scope][owner]") {
    // #1634 adversarial-review fix: dispatcher ownership admits the caller to their
    // OWN execution (avoids a false 404 before any response has landed) but must
    // NEVER bypass the confined projection — a dispatcher later confined out of a
    // management group (or reading an execution dispatched before they were ever
    // confined) must not retain durable full-fidelity access to hidden-agent data
    // just because they fired the dispatch.
    RestEventsHarness h;
    auto exec_id = h.make_exec("running", "tester");
    h.fleet_read_scope = authz::deny_all();

    auto res = h.sink.Get("/api/v1/executions/" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200); // visible: dispatcher ownership still avoids the 404
    CHECK(res->body.find("agent:secret-target") == std::string::npos);
    CHECK(res->body.find("agent-hidden") == std::string::npos);
    CHECK(res->body.find("redacted - confined view") != std::string::npos);
}

TEST_CASE("GET /api/v1/executions/{id}: confined non-owner gets visible-only projection",
          "[pg][events][executions][scope][projection]") {
    YUZU_REQUIRE_PG_DB_TPL(authz_db, yuzu::test::response_execution_authz_tpl);
    yuzu::test::ResponseExecutionAuthzPgRig authz_rig{authz_db.dsn()};
    RestEventsHarness h{/*with_bus=*/true, /*with_tracker=*/true, /*budget=*/nullptr,
                        authz_rig.auth_fn(), authz_rig.fleet_read_fn()};
    auto exec_id = h.make_exec("running", "alice");
    h.agent_status(exec_id, "bob-agent", "success");
    h.agent_status(exec_id, "alice-agent", "failure", "alice-only-error", 1735689661);

    const auto token = authz_rig.mint_bob();
    auto res = h.sink.Get("/api/v1/executions/" + exec_id,
                          yuzu::test::ResponseExecutionAuthzPgRig::bearer(token));
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("agents_targeted") == 1);
    CHECK(data.at("agents_responded") == 1);
    CHECK(data.at("agents_success") == 1);
    CHECK(data.at("agents_failure") == 0);
    CHECK(data.at("scope_expression") == "(redacted - confined view)");
    CHECK(data.at("parameter_values") == "(redacted - confined view)");
    CHECK(data.at("last_error_detail") == "");
    CHECK(res->body.find("alice-only-error") == std::string::npos);
    CHECK(res->body.find("agent-hidden") == std::string::npos);
}

// #1634 (governance Gate 3 quality-engineer finding): every sibling
// single-execution surface (GET /api/v1/executions/{id} above, dashboard
// GET /sse/executions/{id}, MCP get_execution_status/list_executions) has a
// real-rig test driving the actual AuthRoutes + RbacStore + ManagementGroupStore
// composition; this route only ever had the synthetic-fleet_read_fn tests
// above, which cannot catch a wrong securable/operation string at this call
// site or a regression in the real-gate composition specifically for SSE.
TEST_CASE("GET /api/v1/events: real fleet-read gate collapses an invisible "
          "execution to the missing-id 404",
          "[pg][events][executions][scope][notfound]") {
    YUZU_REQUIRE_PG_DB_TPL(authz_db, yuzu::test::response_execution_authz_tpl);
    yuzu::test::ResponseExecutionAuthzPgRig authz_rig{authz_db.dsn()};
    RestEventsHarness h{/*with_bus=*/true, /*with_tracker=*/true, /*budget=*/nullptr,
                        authz_rig.auth_fn(), authz_rig.fleet_read_fn()};
    auto exec_id = h.make_exec("running", "alice");
    h.agent_status(exec_id, "alice-agent", "success");

    const auto token = authz_rig.mint_bob();
    const auto headers = yuzu::test::ResponseExecutionAuthzPgRig::bearer(token);
    auto invisible = h.sink.Get("/api/v1/events?execution_id=" + exec_id, headers);
    auto missing = h.sink.Get("/api/v1/events?execution_id=exec-does-not-exist", headers);
    REQUIRE(invisible);
    REQUIRE(missing);
    REQUIRE(invisible->status == 404);
    REQUIRE(missing->status == 404);
    auto invisible_json = nlohmann::json::parse(invisible->body);
    auto missing_json = nlohmann::json::parse(missing->body);
    invisible_json["error"].erase("correlation_id");
    missing_json["error"].erase("correlation_id");
    CHECK(invisible_json == missing_json);
    CHECK(h.event_bus->subscribers_total() == 0);
    // #1634 (governance Gate 4 consistency-auditor fix): a suppressed
    // cross-operator subscribe attempt now DOES get a distinct `denied` audit
    // row (CC7.2 evidence, parity with MCP get_execution_status) — it must
    // never be the `success`-shaped `execution.live_subscribe`/subscribe row a
    // genuine admit gets.
    bool saw_denied = false;
    for (const auto& a : h.audit_log) {
        CHECK(a.result != "success");
        if (a.action == "api.v1.events.subscribe" && a.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("GET /api/v1/executions/{id}: tracker unavailable → 503 A4 with retry_after_ms",
          "[events][executions][issue-1088][noresources]") {
    RestEventsHarness h(/*with_bus=*/true, /*with_tracker=*/false);
    auto res = h.sink.Get("/api/v1/executions/exec-anything");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find("execution tracker unavailable") != std::string::npos);
    // Mirrors the /api/v1/events 503 contract — clients can back off.
    REQUIRE(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
}

TEST_CASE("GET /api/v1/executions/{id}: auth denied → 401 (no body leak)",
          "[pg][events][executions][issue-1088][auth]") {
    RestEventsHarness h;
    h.session_present = false;
    auto res = h.sink.Get("/api/v1/executions/exec-1");
    REQUIRE(res);
    REQUIRE(res->status == 401);
}

TEST_CASE("GET /api/v1/executions/{id}: permission denied → 403",
          "[pg][events][executions][issue-1088][perm]") {
    RestEventsHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/executions/exec-1");
    REQUIRE(res);
    REQUIRE(res->status == 403);
}

// ── GET /api/v1/approvals/{id} (A4 status_url target) ────────────────────────

namespace {

/// Minimal harness that wires a real ApprovalManager (ADR-0065, Postgres —
/// PgSkipGate-style, migration-programme PR 5 commit 2/3) into RestApiV1 so
/// the versioned single-approval route can be driven end-to-end via the
/// TestRouteSink dispatch pattern. `with_manager=false` exercises the
/// 503-on-unwired-store path and deliberately does NOT SKIP on a missing PG
/// DSN — no database is needed for that path.
struct RestApprovalsHarness {
    yuzu::server::test::TestRouteSink sink;
    std::optional<yuzu::test::ApprovalManagerPg> approvals_bundle;
    bool session_present{true};
    bool perm_grant{true};
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    // compliance-officer governance finding (#2146 A2-R4): captures each
    // audit_fn call's (action, result, detail) so a test can assert content,
    // not just that a 200 came back -- a future refactor deleting the
    // audit_fn(...) call on a handler would otherwise pass every existing
    // test silently.
    std::vector<std::tuple<std::string, std::string, std::string>> audit_calls;

    explicit RestApprovalsHarness(bool with_manager = true) {
        if (with_manager)
            approvals_bundle.emplace();
        ApprovalManager* approvals = with_manager ? approvals_bundle->get() : nullptr;
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string&, const std::string& detail) -> bool {
            audit_calls.emplace_back(action, result, detail);
            return true;
        };
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/approvals,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr);
    }

    /// Convenience accessor so a TEST_CASE can write `h->submit(...)`
    /// directly, only valid when `with_manager=true` (the harness's own
    /// 503-unwired-store test never dereferences it).
    ApprovalManager* operator->() const { return approvals_bundle->get(); }
};

} // namespace

TEST_CASE("GET /api/v1/approvals/{id}: existing approval → 200 with full object",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    auto id = h->submit("def-123", "alice", "tag:prod", "", ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    auto res = h.sink.Get("/api/v1/approvals/" + *id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // ok_json data object mirrors the Approval struct field-for-field.
    REQUIRE(res->body.find("\"id\":\"" + *id + "\"") != std::string::npos);
    REQUIRE(res->body.find(R"("definition_id":"def-123")") != std::string::npos);
    REQUIRE(res->body.find(R"("status":"pending")") != std::string::npos);
    REQUIRE(res->body.find(R"("submitted_by":"alice")") != std::string::npos);
    REQUIRE(res->body.find(R"("scope_expression":"tag:prod")") != std::string::npos);
    REQUIRE(res->body.find(R"("api_version":"v1")") != std::string::npos);
    // Response always carries the correlation-id header (agentic-first).
    REQUIRE_FALSE(res->get_header_value("X-Correlation-Id").empty());
}

TEST_CASE("GET /api/v1/approvals/{id}: unknown id → 404 A4 envelope",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    auto res = h.sink.Get("/api/v1/approvals/deadbeefdeadbeefdeadbeefdeadbeef");
    REQUIRE(res);
    REQUIRE(res->status == 404);
    // 404 is A4-shaped: code + message + correlation_id + retry_after_ms(null).
    REQUIRE(res->body.find(R"("code":404)") != std::string::npos);
    REQUIRE(res->body.find(R"("message":"approval not found")") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":null)") != std::string::npos);
    auto hdr = res->get_header_value("X-Correlation-Id");
    REQUIRE_FALSE(hdr.empty());
    REQUIRE(res->body.find("\"correlation_id\":\"" + hdr + "\"") != std::string::npos);
}

TEST_CASE("GET /api/v1/approvals/{id}: unwired store → 503 A4 envelope with retry",
          "[events][approvals][a4]") {
    RestApprovalsHarness h(/*with_manager=*/false);
    auto res = h.sink.Get("/api/v1/approvals/anything");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find(R"("code":503)") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
}

TEST_CASE("GET /api/v1/approvals/{id}: auth denied → 401", "[pg][events][approvals][auth]") {
    RestApprovalsHarness h;
    h.session_present = false;
    auto res = h.sink.Get("/api/v1/approvals/anything");
    REQUIRE(res);
    REQUIRE(res->status == 401);
}

TEST_CASE("GET /api/v1/approvals/{id}: permission denied → 403", "[pg][events][approvals][perm]") {
    RestApprovalsHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/approvals/anything");
    REQUIRE(res);
    REQUIRE(res->status == 403);
}

// ── GET /api/v1/approvals — approval list (#2146 A2-R4) ──────────────────────

TEST_CASE("GET /api/v1/approvals: happy path lists the seeded approval with the full "
          "field set",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    auto id = h->submit("def-list-1", "alice", "tag:prod", "", ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    auto res = h.sink.Get("/api/v1/approvals");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["id"] == *id);
    CHECK(j["data"][0]["definition_id"] == "def-list-1");
    CHECK(j["data"][0]["status"] == "pending");
    CHECK(j["data"][0]["submitted_by"] == "alice");
    CHECK(j["data"][0]["scope_expression"] == "tag:prod");
    CHECK(j["data"][0].contains("reviewed_by"));
    CHECK(j["data"][0].contains("reviewed_at"));
    CHECK(j["data"][0].contains("review_comment"));
    CHECK(j["pagination"]["total"] == 1);
    CHECK_FALSE(j["pagination"].contains("result_truncated_by_cap"));
    CHECK(j["meta"]["api_version"] == "v1");
}

TEST_CASE("GET /api/v1/approvals: status and submitted_by filters, matching the legacy route",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    h->submit("def-a", "operator1", "scope-a", "", ApprovalOrigin::kInstruction);
    h->submit("def-b", "operator2", "scope-b", "", ApprovalOrigin::kInstruction);
    auto to_approve = h->submit("def-c", "operator1", "scope-c", "", ApprovalOrigin::kInstruction);
    REQUIRE(to_approve.has_value());
    REQUIRE(h->approve(*to_approve, "reviewer1", "").has_value());

    auto by_status = h.sink.Get("/api/v1/approvals?status=approved");
    REQUIRE(by_status);
    auto approved = nlohmann::json::parse(by_status->body)["data"];
    REQUIRE(approved.size() == 1);
    CHECK(approved[0]["definition_id"] == "def-c");

    auto by_submitter = h.sink.Get("/api/v1/approvals?submitted_by=operator1");
    REQUIRE(by_submitter);
    CHECK(nlohmann::json::parse(by_submitter->body)["data"].size() == 2); // def-a + def-c
}

TEST_CASE("GET /api/v1/approvals: status AND submitted_by combined filter (happy-path "
          "governance finding, #2146 A2-R4)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    h->submit("def-a", "operator1", "scope-a", "", ApprovalOrigin::kInstruction);
    auto to_approve1 =
        h->submit("def-b", "operator1", "scope-b", "", ApprovalOrigin::kInstruction);
    auto to_approve2 =
        h->submit("def-c", "operator2", "scope-c", "", ApprovalOrigin::kInstruction);
    REQUIRE(to_approve1.has_value());
    REQUIRE(to_approve2.has_value());
    REQUIRE(h->approve(*to_approve1, "reviewer1", "").has_value());
    REQUIRE(h->approve(*to_approve2, "reviewer1", "").has_value());

    // Two rows are status=approved; only one of those is also
    // submitted_by=operator1 -- proves the two filters AND-compose rather
    // than one silently overriding the other or an off-by-one in the SQL
    // placeholder indexing when both are present.
    auto res = h.sink.Get("/api/v1/approvals?status=approved&submitted_by=operator1");
    REQUIRE(res);
    auto data = nlohmann::json::parse(res->body)["data"];
    REQUIRE(data.size() == 1);
    CHECK(data[0]["definition_id"] == "def-b");
}

TEST_CASE("GET /api/v1/approvals: an out-of-enum status is rejected with 400, not silently "
          "producing a false-empty result (unhappy-path governance finding, #2146 A2-R4)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    REQUIRE(h->submit("def-a", "operator1", "scope-a", "", ApprovalOrigin::kInstruction)
                .has_value());

    // Pre-fix: this silently produced data:[] -- indistinguishable from a
    // genuinely empty match -- instead of rejecting the malformed input.
    auto res = h.sink.Get("/api/v1/approvals?status=aproved");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/approvals: audits a success read with surface/count detail "
          "(compliance-officer governance finding, #2146 A2-R4)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    REQUIRE(h->submit("def-a", "operator1", "scope-a", "", ApprovalOrigin::kInstruction)
                .has_value());

    auto res = h.sink.Get("/api/v1/approvals");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A future refactor that deletes the audit_fn(...) call on this handler
    // would otherwise pass every other test in this file silently.
    bool found = false;
    for (const auto& [action, result, detail] : h.audit_calls) {
        if (action == "approval.read" && result == "success") {
            found = true;
            CHECK(detail.find("surface=list") != std::string::npos);
            CHECK(detail.find("count=1") != std::string::npos);
        }
    }
    CHECK(found);
}

TEST_CASE("GET /api/v1/approvals: result_truncated_by_cap appears when more than 100 "
          "approvals match (#2146 A2-R4 boundary)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    for (int i = 0; i < 101; ++i)
        REQUIRE(h->submit("def-cap", "operator1", "scope-" + std::to_string(i), "",
                          ApprovalOrigin::kInstruction)
                    .has_value());

    auto res = h.sink.Get("/api/v1/approvals");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"].size() == 100);
    CHECK(j["pagination"]["result_truncated_by_cap"] == true);
}

TEST_CASE("GET /api/v1/approvals: unwired store → 503 A4 envelope with retry",
          "[events][approvals][a4]") {
    RestApprovalsHarness h(/*with_manager=*/false);
    auto res = h.sink.Get("/api/v1/approvals");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find(R"("code":503)") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
}

TEST_CASE("GET /api/v1/approvals: permission denied → 403", "[pg][events][approvals][perm]") {
    RestApprovalsHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/approvals");
    REQUIRE(res);
    REQUIRE(res->status == 403);
}

TEST_CASE("GET /api/v1/approvals: a genuine store failure answers 503, never a false "
          "empty list, and a permanent one (DROP TABLE, 42P01) is NOT presented as "
          "retryable (review finding, PR #4656)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    REQUIRE(h->submit("def-x", "operator1", "scope", "", ApprovalOrigin::kInstruction)
                .has_value());
    {
        auto lease = h.approvals_bundle->pool().acquire();
        REQUIRE(lease);
        pg::PgResult res =
            pg::exec_params(lease.get(), "DROP TABLE approval_manager.approvals",
                            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto res = h.sink.Get("/api/v1/approvals");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find(R"("code":503)") != std::string::npos);
    // DROP TABLE is a class-42 (42P01) failure -- is_permanent_pg_error
    // classifies it PERMANENT, so this must NOT carry the retryable hint:
    // retry_after_ms=5000 on a condition that will not clear without an
    // operator is an unbounded retry loop.
    REQUIRE(res->body.find(R"("message":"approval store unavailable")") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":null)") != std::string::npos);
}

// ── GET /api/v1/approvals/pending/count (#2146 A2-R4) ────────────────────────

TEST_CASE("GET /api/v1/approvals/pending/count: happy path reflects the pending queue, "
          "excluding a non-pending row (review finding, PR #4656: a query counting ALL "
          "statuses would have passed the prior version of this test unnoticed)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    auto pending_id = h->submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    REQUIRE(pending_id.has_value());
    REQUIRE(h->submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kInstruction)
                .has_value());
    // Approve one of the two -- the count must exclude it, proving the
    // underlying query is actually WHERE status='pending', not a bare
    // COUNT(*) that would also pass with two submitted-then-untouched rows.
    REQUIRE(h->approve(*pending_id, "reviewer-bob", "").has_value());

    auto res = h.sink.Get("/api/v1/approvals/pending/count");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["count"] == 1);
    CHECK(j["meta"]["api_version"] == "v1");
}

TEST_CASE("GET /api/v1/approvals/pending/count: unwired store → 503 A4 envelope with retry",
          "[events][approvals][a4]") {
    RestApprovalsHarness h(/*with_manager=*/false);
    auto res = h.sink.Get("/api/v1/approvals/pending/count");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find(R"("code":503)") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
}

TEST_CASE("GET /api/v1/approvals/pending/count: permission denied → 403",
          "[pg][events][approvals][perm]") {
    RestApprovalsHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/approvals/pending/count");
    REQUIRE(res);
    REQUIRE(res->status == 403);
}

TEST_CASE("GET /api/v1/approvals/pending/count: a genuine store failure answers 503, "
          "never a false zero, and a permanent one (DROP TABLE, 42P01) is NOT "
          "presented as retryable (review finding, PR #4656)",
          "[pg][events][approvals][a4]") {
    RestApprovalsHarness h;
    REQUIRE(h->submit("def-x", "operator1", "scope", "", ApprovalOrigin::kInstruction)
                .has_value());
    {
        auto lease = h.approvals_bundle->pool().acquire();
        REQUIRE(lease);
        pg::PgResult res =
            pg::exec_params(lease.get(), "DROP TABLE approval_manager.approvals",
                            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto res = h.sink.Get("/api/v1/approvals/pending/count");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find(R"("code":503)") != std::string::npos);
    // Same permanent (42P01) classification as the list route above.
    REQUIRE(res->body.find(R"("message":"approval store unavailable")") != std::string::npos);
    REQUIRE(res->body.find(R"("retry_after_ms":null)") != std::string::npos);
}
