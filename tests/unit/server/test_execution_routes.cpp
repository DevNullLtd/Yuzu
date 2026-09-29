/// @file test_execution_routes.cpp
/// HTTP-level coverage for the 7-route legacy pre-v1 Executions API (#2542
/// PR-7) — driven in-process through TestRouteSink (no httplib acceptor,
/// #438), mirroring test_custom_properties_routes.cpp's /
/// test_result_set_routes.cpp's Harness shape.
///
/// #3789 confinement is already exhaustively covered at the pure-function
/// level (`execution_scope_rules.hpp`'s `execution_visible`/
/// `confined_projection`/`admit_confined_mutation`) and via source
/// tripwires in `test_legacy_executions_scope_authz.cpp` — this file does
/// NOT re-derive that logic. It proves the HTTP SEAM instead: that each
/// route calls the right gate in the right order (`deps.perm_fn` THEN
/// `deps.fleet_read_fn` on rerun/cancel, `deps.fleet_read_fn` alone on the
/// five GET routes — see execution_routes.hpp's header comment for why
/// that stacking is deliberate, not the same-tuple pairing
/// `require_fleet_read`'s own doc comment forbids), that a gate denial
/// short-circuits before the store is touched, that the null-tracker 503
/// degrade is uniform, and that the audit-row ASYMMETRIES
/// execution_routes.hpp documents (rerun's un-audited store-level failure;
/// cancel's unconfined-404 non-audit; the GET routes' scope-gated-only
/// denial audit) survive the move.
///
/// Split by whether a case needs a live Postgres-backed `ExecutionTracker`
/// (it has no virtual seam — `Deps::execution_tracker` is a concrete
/// pointer, per #2542 PR-7):
///   - Every gate-denial pin, the gate-ordering pin, and the null-tracker
///     503 degrade run WITHOUT Postgres — each returns before the tracker
///     would be dereferenced.
///   - Every round-trip (unconfined and confined) and every audit-row
///     assertion needs a real store, via
///     `test_execution_tracker_pg_helper.hpp`'s shared `ExecutionTrackerPg`
///     fixture (same `"exectracker"` PgTestTemplate
///     `test_execution_tracker.cpp` uses).

#include "execution_routes.hpp"
#include "test_route_sink.hpp"

#include "execution_tracker.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct EmitRow {
    std::string event_type;
    json attrs;
    json payload_data;
};

Execution make_execution(const std::string& definition_id = "def-001",
                         const std::string& dispatched_by = "admin") {
    Execution exec;
    exec.definition_id = definition_id;
    exec.scope_expression = "ostype = 'windows'";
    exec.parameter_values = R"({"a":1})";
    exec.dispatched_by = dispatched_by;
    exec.status = "running";
    return exec;
}

AgentExecStatus make_status(const std::string& agent_id, const std::string& status) {
    AgentExecStatus a;
    a.agent_id = agent_id;
    a.status = status;
    return a;
}

/// All providers injected and re-read per call, mirroring
/// test_custom_properties_routes.cpp's Harness shape.
/// `execution_tracker` defaults to null — every case that must NOT need
/// Postgres leaves it null and relies on the route returning 503 before it
/// would be dereferenced.
///
/// `fleet_admitted`/`fleet_scope` drive the `deps.fleet_read_fn` stub:
/// `fleet_admitted=false` mimics `require_fleet_read` already having
/// written a denial to `res` (403 here, matching the shape every OTHER
/// harness in this campaign uses for a gate denial); `fleet_scope`
/// (default `std::nullopt` = unconfined/TOP) is returned verbatim as
/// `FleetReadGate::scope` on an admitted call.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    ExecutionTracker* execution_tracker{nullptr};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    bool fleet_admitted{true};
    authz::VisibleSet fleet_scope; // nullopt = unconfined
    std::string last_fleet_type, last_fleet_op;
    int fleet_read_fn_calls{0};

    // deps.resolve_session_fn — non-blocking, never writes to `res`. Empty
    // means "no session resolved".
    std::string resolve_session_username{"bob"};

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    std::vector<EmitRow> emits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        execution::Deps deps;
        deps.execution_tracker = execution_tracker;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string& type,
                                    const std::string& op) -> authz::FleetReadGate {
            ++fleet_read_fn_calls;
            last_fleet_type = type;
            last_fleet_op = op;
            if (!fleet_admitted) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return authz::FleetReadGate{}; // admitted=false, scope=deny_all()
            }
            authz::FleetReadGate g;
            g.admitted = true;
            g.scope = fleet_scope;
            return g;
        };
        deps.resolve_session_fn =
            [this](const httplib::Request&) -> std::optional<auth::Session> {
            if (resolve_session_username.empty())
                return std::nullopt;
            auth::Session s;
            s.username = resolve_session_username;
            return s;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        deps.emit_event_fn = [this](const std::string& event_type, const httplib::Request&,
                                    const json& attrs, const json& payload_data) {
            emits.push_back({event_type, attrs, payload_data});
        };
        execution::register_execution_routes(sink, deps);
    }
};

json body(const std::string& s) { return json::parse(s); }

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("execution_routes: registers exactly 7 routes",
          "[server][routes][execution_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 7);
}

// ── Gate pinning (no Postgres needed) ───────────────────────────────────────

TEST_CASE("execution_routes: the 5 GET routes gate on fleet_read_fn(Execution, Read) "
          "alone -- never touching perm_fn",
          "[server][routes][execution_routes]") {
    Harness h;
    h.wire();

    h.sink.Get("/api/executions");
    CHECK(h.last_fleet_type == "Execution");
    CHECK(h.last_fleet_op == "Read");
    CHECK(h.last_perm_type.empty());

    h.sink.Get("/api/executions/exec-1");
    CHECK(h.last_fleet_type == "Execution");
    CHECK(h.last_fleet_op == "Read");

    h.sink.Get("/api/executions/exec-1/summary");
    CHECK(h.last_fleet_type == "Execution");
    CHECK(h.last_fleet_op == "Read");

    h.sink.Get("/api/executions/exec-1/agents");
    CHECK(h.last_fleet_type == "Execution");
    CHECK(h.last_fleet_op == "Read");

    h.sink.Get("/api/executions/exec-1/children");
    CHECK(h.last_fleet_type == "Execution");
    CHECK(h.last_fleet_op == "Read");

    CHECK(h.last_perm_type.empty()); // still never touched across all 5
}

TEST_CASE("execution_routes: rerun/cancel gate on perm_fn(Execution, Execute) THEN "
          "fleet_read_fn(Execution, Read) -- a perm_fn denial short-circuits before "
          "the fleet gate is ever called",
          "[server][routes][execution_routes]") {
    Harness h; // execution_tracker stays null -- a dereference would crash
    h.perm_allow = false;
    h.wire();

    auto r1 = h.sink.Post("/api/executions/exec-1/rerun", "{}");
    REQUIRE(r1);
    CHECK(r1->status == 403);
    CHECK(h.last_perm_type == "Execution");
    CHECK(h.last_perm_op == "Execute");
    CHECK(h.fleet_read_fn_calls == 0); // never reached

    auto r2 = h.sink.Post("/api/executions/exec-1/cancel", "{}");
    REQUIRE(r2);
    CHECK(r2->status == 403);
    CHECK(h.fleet_read_fn_calls == 0);
}

TEST_CASE("execution_routes: rerun/cancel DO reach fleet_read_fn(Execution, Read) once "
          "perm_fn admits",
          "[server][routes][execution_routes]") {
    Harness h; // execution_tracker stays null -- the fleet-admit path 503s next, not a crash
    h.wire();

    h.sink.Post("/api/executions/exec-1/rerun", "{}");
    CHECK(h.fleet_read_fn_calls == 1);
    CHECK(h.last_fleet_type == "Execution");
    CHECK(h.last_fleet_op == "Read");

    h.sink.Post("/api/executions/exec-1/cancel", "{}");
    CHECK(h.fleet_read_fn_calls == 2);
}

TEST_CASE("execution_routes: a fleet_read_fn denial short-circuits every route before "
          "the tracker is touched",
          "[server][routes][execution_routes]") {
    Harness h; // execution_tracker stays null -- a dereference would crash
    h.fleet_admitted = false;
    h.wire();

    for (auto [method, path] :
        {std::pair{std::string("GET"), std::string("/api/executions")},
         std::pair{std::string("GET"), std::string("/api/executions/exec-1")},
         std::pair{std::string("GET"), std::string("/api/executions/exec-1/summary")},
         std::pair{std::string("GET"), std::string("/api/executions/exec-1/agents")},
         std::pair{std::string("GET"), std::string("/api/executions/exec-1/children")}}) {
        auto r = h.sink.dispatch(method, path);
        REQUIRE(r);
        CHECK(r->status == 403);
    }
    CHECK(h.audits.empty());
}

TEST_CASE("execution_routes: a null tracker answers 503 on every route without crashing, "
          "once the gates admit",
          "[server][routes][execution_routes]") {
    Harness h;
    h.wire();

    auto r1 = h.sink.Get("/api/executions");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Get("/api/executions/exec-1");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Get("/api/executions/exec-1/summary");
    REQUIRE(r3);
    CHECK(r3->status == 503);

    auto r4 = h.sink.Get("/api/executions/exec-1/agents");
    REQUIRE(r4);
    CHECK(r4->status == 503);

    auto r5 = h.sink.Get("/api/executions/exec-1/children");
    REQUIRE(r5);
    CHECK(r5->status == 503);

    auto r6 = h.sink.Post("/api/executions/exec-1/rerun", "{}");
    REQUIRE(r6);
    CHECK(r6->status == 503);

    auto r7 = h.sink.Post("/api/executions/exec-1/cancel", "{}");
    REQUIRE(r7);
    CHECK(r7->status == 503);

    CHECK(h.audits.empty());
}

// ── [pg] cases: real ExecutionTracker ───────────────────────────────────────

TEST_CASE("execution_routes: unconfined LIST/detail/summary/agents/children round-trip "
          "over HTTP, unaudited on success",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.fleet_scope = std::nullopt; // unconfined
    h.wire();

    auto id = tracker->create_execution(make_execution("def-list", "bob"));
    REQUIRE(id.has_value());
    tracker->update_agent_status(*id, make_status("bob-agent", "success"));

    auto list = h.sink.Get("/api/executions");
    REQUIRE(list);
    CHECK(list->status == 200);
    bool found = false;
    for (const auto& e : body(list->body)["executions"])
        found = found || (e["id"] == *id);
    CHECK(found);

    auto detail = h.sink.Get("/api/executions/" + *id);
    REQUIRE(detail);
    CHECK(detail->status == 200);
    auto detail_body = body(detail->body);
    CHECK(detail_body["id"] == *id);
    // Unconfined -- scope_expression/parameter_values are truthful, not redacted.
    CHECK(detail_body["scope_expression"] == "ostype = 'windows'");
    CHECK(detail_body["parameter_values"] == R"({"a":1})");

    auto summary = h.sink.Get("/api/executions/" + *id + "/summary");
    REQUIRE(summary);
    CHECK(summary->status == 200);
    CHECK(body(summary->body)["id"] == *id);

    auto agents = h.sink.Get("/api/executions/" + *id + "/agents");
    REQUIRE(agents);
    CHECK(agents->status == 200);
    REQUIRE(body(agents->body)["agents"].size() == 1);
    CHECK(body(agents->body)["agents"][0]["agent_id"] == "bob-agent");

    auto rerun_child = tracker->create_rerun(*id, "bob", false);
    REQUIRE(rerun_child.has_value());
    auto children = h.sink.Get("/api/executions/" + *id + "/children");
    REQUIRE(children);
    CHECK(children->status == 200);
    REQUIRE(body(children->body)["children"].size() == 1);
    CHECK(body(children->body)["children"][0]["id"] == *rerun_child);

    CHECK(h.audits.empty()); // every read above succeeded -- none of the five GET routes audit success
}

TEST_CASE("execution_routes: an unknown id 404s on every GET route without an audit row "
          "when the caller is unconfined",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.fleet_scope = std::nullopt;
    h.wire();

    for (const std::string& path :
        {std::string("/api/executions/does-not-exist"),
         std::string("/api/executions/does-not-exist/summary"),
         std::string("/api/executions/does-not-exist/agents"),
         std::string("/api/executions/does-not-exist/children")}) {
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 404);
    }
    CHECK(h.audits.empty()); // unconfined + genuinely-nonexistent -> ordinary 404, no audit
}

TEST_CASE("execution_routes: a confined caller's invisible execution 404s WITH an audited "
          "'denied' row, on every GET route",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.resolve_session_username = "bob";
    h.wire();

    auto id = tracker->create_execution(make_execution("def-hidden", "alice"));
    REQUIRE(id.has_value());
    tracker->update_agent_status(*id, make_status("alice-agent", "success"));

    // Engaged scope that does NOT include alice-agent -- bob cannot see this
    // execution (not the dispatcher, no visible-agent row).
    h.fleet_scope = authz::VisibleSet{std::unordered_set<std::string>{"bob-agent"}};

    auto detail = h.sink.Get("/api/executions/" + *id);
    REQUIRE(detail);
    CHECK(detail->status == 404);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "execution.read");
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].target_type == "Execution"); // PascalCase on the GET routes

    auto summary = h.sink.Get("/api/executions/" + *id + "/summary");
    REQUIRE(summary);
    CHECK(summary->status == 404);
    REQUIRE(h.audits.size() == 2);

    auto agents = h.sink.Get("/api/executions/" + *id + "/agents");
    REQUIRE(agents);
    CHECK(agents->status == 404);
    REQUIRE(h.audits.size() == 3);

    auto children = h.sink.Get("/api/executions/" + *id + "/children");
    REQUIRE(children);
    CHECK(children->status == 404);
    REQUIRE(h.audits.size() == 4);
    for (const auto& row : h.audits)
        CHECK(row.result == "denied");
}

TEST_CASE("execution_routes: a confined caller with an empty resolved username fails "
          "closed with 503, never falling through to agent-only visibility",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.fleet_scope = authz::deny_all(); // engaged
    h.resolve_session_username = "";   // resolve failed
    h.wire();

    auto id = tracker->create_execution(make_execution("def-x", "bob"));
    REQUIRE(id.has_value());

    auto r = h.sink.Get("/api/executions/" + *id);
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(body(r->body)["error"]["message"] ==
          "unable to resolve caller identity for a confined read");
    CHECK(h.audits.empty()); // fails closed before the audit-eligible branch is even reached
}

TEST_CASE("execution_routes: a confined caller sees a REDACTED detail view -- "
          "scope_expression/parameter_values replaced, counts recomputed from only "
          "in-scope rows",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.resolve_session_username = "bob";
    h.wire();

    auto id = tracker->create_execution(make_execution("def-redact", "bob"));
    REQUIRE(id.has_value());
    tracker->update_agent_status(*id, make_status("bob-agent", "success"));
    tracker->update_agent_status(*id, make_status("alice-agent", "success"));
    tracker->refresh_counts(*id);

    h.fleet_scope = authz::VisibleSet{std::unordered_set<std::string>{"bob-agent"}};
    auto detail = h.sink.Get("/api/executions/" + *id);
    REQUIRE(detail);
    CHECK(detail->status == 200); // bob is the dispatcher -- visible
    auto j = body(detail->body);
    CHECK(j["scope_expression"] == "(redacted - confined view)");
    CHECK(j["parameter_values"] == "(redacted - confined view)");
    CHECK(j["agents_targeted"] == 1); // only bob-agent's row, not alice-agent's

    auto agents = h.sink.Get("/api/executions/" + *id + "/agents");
    REQUIRE(agents);
    REQUIRE(body(agents->body)["agents"].size() == 1); // filtered to in-scope
    CHECK(body(agents->body)["agents"][0]["agent_id"] == "bob-agent");
}

TEST_CASE("execution_routes: rerun success round-trip audits + emits; a store-level "
          "rejection is a plain 400 with NO audit call",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.fleet_scope = std::nullopt;
    h.wire();

    auto id = tracker->create_execution(make_execution("def-rerun", "bob"));
    REQUIRE(id.has_value());

    auto ok = h.sink.Post("/api/executions/" + *id + "/rerun", "{}");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "execution.rerun");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "execution"); // lowercase on rerun/cancel
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "execution.created");
    CHECK(h.emits[0].payload_data["parent_id"] == *id);
    CHECK(h.emits[0].payload_data["trigger"] == "rerun");

    // create_rerun's own existence check rejects an unknown id with a plain
    // 400 -- unaudited (the store-level failure branch, not the confined-
    // mutation-denied branch, which DOES audit).
    auto bad = h.sink.Post("/api/executions/does-not-exist/rerun", "{}");
    REQUIRE(bad);
    CHECK(bad->status == 400);
    CHECK(h.audits.size() == 1); // unchanged -- no new row
}

TEST_CASE("execution_routes: a confined caller's incomplete-cohort rerun/cancel is "
          "denied with a uniform 404 + audited 'denied' row",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.resolve_session_username = "bob";
    h.wire();

    auto id = tracker->create_execution(make_execution("def-partial", "bob"));
    REQUIRE(id.has_value());
    REQUIRE(tracker->set_agents_targeted(*id, 2));
    tracker->update_agent_status(*id, make_status("bob-agent", "success"));
    // Only 1 of 2 targeted agents has reported -- an incomplete ledger,
    // admit_confined_mutation must deny even though the one existing row
    // (bob-agent) IS in scope.

    h.fleet_scope = authz::VisibleSet{std::unordered_set<std::string>{"bob-agent"}};

    auto rerun = h.sink.Post("/api/executions/" + *id + "/rerun", "{}");
    REQUIRE(rerun);
    CHECK(rerun->status == 404);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "execution.rerun");
    CHECK(h.audits[0].result == "denied");

    auto cancel = h.sink.Post("/api/executions/" + *id + "/cancel", "{}");
    REQUIRE(cancel);
    CHECK(cancel->status == 404);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "execution.cancel");
    CHECK(h.audits[1].result == "denied");
}

TEST_CASE("execution_routes: cancel success audits + emits; an unconfined caller's "
          "unknown id 404s WITHOUT an audit row",
          "[pg][server][routes][execution_routes]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Harness h;
    h.execution_tracker = tracker.get();
    h.fleet_scope = std::nullopt;
    h.wire();

    auto id = tracker->create_execution(make_execution("def-cancel", "bob"));
    REQUIRE(id.has_value());

    auto ok = h.sink.Post("/api/executions/" + *id + "/cancel", "{}");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "execution.cancel");
    CHECK(h.audits[0].result == "success");
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "execution.completed");
    CHECK(h.emits[0].attrs["status"] == "cancelled");

    // Cancelling an already-terminal execution -- mark_cancelled returns
    // false (PR #3842's RETURNING id + terminal-status guard) -> audited
    // "failure", 503.
    auto recancel = h.sink.Post("/api/executions/" + *id + "/cancel", "{}");
    REQUIRE(recancel);
    CHECK(recancel->status == 503);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "execution.cancel");
    CHECK(h.audits[1].result == "failure");

    // A genuinely unknown id, unconfined -- the defense-in-depth
    // `if (!exec_opt)` 404 fires and is NOT audited.
    auto unknown = h.sink.Post("/api/executions/does-not-exist/cancel", "{}");
    REQUIRE(unknown);
    CHECK(unknown->status == 404);
    CHECK(h.audits.size() == 2); // unchanged
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_execution_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_execution_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 7 routes.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("execution_routes: wiring -- server.cpp still calls register_execution_routes",
          "[server][routes][execution_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_execution_routes(") != std::string::npos);
}
