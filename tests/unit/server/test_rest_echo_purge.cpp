/**
 * test_rest_echo_purge.cpp — route-handler coverage for the REST Echo source-purge
 * endpoint POST /api/v1/echo/retention-paused/purge (governance remediation of the
 * PR #1781 adversarial review; finding #5 / issue #1779).
 *
 * Registers RestApiV1 over an in-process TestRouteSink (#438: no acceptor thread)
 * with stub scoped-perm / audit / command-dispatch, and drives the DESTRUCTIVE
 * endpoint end-to-end so a future refactor that drops one of its gates fails here:
 *   - source allowlist (only process/tcp/service/user),
 *   - per-device scope gate (Infrastructure:Delete via the typed scoped gate, fail-closed),
 *   - the metric vocabulary on surface=rest: every refusal class of the gate, every outage, and
 *     every outcome counts under its own result, with the status, body and audit row of each
 *     path unchanged,
 *   - audit-before-dispatch fail-closed (no dispatch if the evidence row is lost),
 *   - the success dispatch shape (echo/purge_source targeting the one device, {source}).
 *
 * The DashboardRoutes HTML fragment (/fragments/echo/retention-paused/purge) shares
 * these properties and has its own route-handler coverage since #1786 moved
 * DashboardRoutes onto HttpRouteSink — see test_dashboard_echo_fragments.cpp (the
 * fragment additionally gates a CSRF same-site check that this REST twin, being the
 * programmatic surface, does not). The fragment's render-time button gating is
 * covered in test_dashboard_echo_retention.cpp.
 */

#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <unordered_set>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

struct DispatchCall {
    std::string plugin, action;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
};
struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct PurgeHarness {
    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    bool scope_allow{true}; // the scoped gate's verdict
    /// The class the gate answers with when `scope_allow` is false, and the status and body the
    /// real gate writes for it (the route reads the class and leaves the response alone).
    ScopedGateOutcome scope_refusal{ScopedGateOutcome::Denied};
    bool audit_ok{true};    // AuditFn return (false → fail-closed 503, no dispatch)
    /// The `failure` outcome row alone is lost (the `requested` row persisted): the answer must
    /// carry `Sec-Audit-Failed`, since that row is the only evidence nothing was sent.
    bool drop_failure_row{false};
    /// #7110: withdraw the per-device grant INSIDE the `requested` row write, the window in which
    /// production lets a grant move.
    bool revoke_on_requested{false};
    /// #7110: the credentials stop resolving INSIDE the `requested` row write (the secondary
    /// caller's own resolution then fails, which the route answers as caller_unresolved).
    bool drop_session_on_requested{false};
    bool session_gone{false};
    int scoped_calls{0};
    /// #7114: the chokepoint's refusal, carried on the dispatch outcome (nothing sent).
    std::optional<yuzu::server::detail::DispatchDenial> dispatch_denied;
    int dispatch_sent{1};   // agents reached per dispatch
    /// #1788: what the route derived and handed to dispatch. The per-device
    /// scoped_perm_fn above remains this route's PRIMARY authorization — the
    /// VisibleSet is a second, independent confinement check at the seam.
    yuzu::server::authz::VisibleSet last_exec_visible;
    /// PR1.9c: the WHOLE caller the route handed to dispatch. `principal` is
    /// the half that matters — `build_classified_command` refuses an empty one
    /// as `AnonymousOperator` before the legacy-open bypass, so a route that
    /// derives a visible set but no identity dispatches to nobody.
    yuzu::server::DispatchCaller last_caller;
    /// The VisibleSet the wired derivation returns; nullopt = unfiltered.
    yuzu::server::authz::VisibleSet exec_visible_override{};
    /// false → register with an EMPTY `exec_visible_fn`, modelling a deployment
    /// that never wired the derivation. Not a synonym for `exec_visible_override`
    /// being nullopt: that is a callback ANSWERING "unfiltered".
    bool wire_exec_visible{true};

    /// @param with_exec_visible false: register with an EMPTY `exec_visible_fn`.
    /// @param wire_typed_gate false: leave the typed scoped gate unset (the route fails closed).
    /// @param with_dispatch false: register with an EMPTY dispatch function.
    explicit PurgeHarness(bool with_exec_visible = true, bool wire_typed_gate = true,
                          bool with_dispatch = true)
        : wire_exec_visible(with_exec_visible) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_gone)
                return std::nullopt;
            auth::Session s;
            s.username = "purge-op";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& tid,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, tid, d});
            if (r == "requested" && revoke_on_requested)
                scope_allow = false;
            if (r == "requested" && drop_session_on_requested)
                session_gone = true;
            if (r == "failure" && drop_failure_row)
                return false;
            return audit_ok;
        };
        RestApiV1::ScopedPermFn scoped =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&, const std::string&) -> bool {
            ++scoped_calls;
            if (!scope_allow) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"forbidden"},"meta":{"api_version":"v1"}})",
                    "application/json");
            }
            return scope_allow;
        };
        // The route authorizes through THIS gate: set before register_routes, as server.cpp does.
        if (wire_typed_gate) {
            api.set_scoped_gate_fn(
                [this](const httplib::Request&, httplib::Response& res, const std::string&,
                       const std::string&, const std::string&) -> ScopedGateOutcome {
                    ++scoped_calls;
                    if (scope_allow)
                        return ScopedGateOutcome::Admitted;
                    switch (scope_refusal) {
                        case ScopedGateOutcome::Unauthenticated: res.status = 401; break;
                        case ScopedGateOutcome::Unavailable: res.status = 503; break;
                        case ScopedGateOutcome::Denied:
                        case ScopedGateOutcome::MgmtGroupReadDegraded:
                        case ScopedGateOutcome::RbacReadDegraded:
                        case ScopedGateOutcome::Admitted: res.status = 403; break;
                    }
                    res.set_content(
                        R"({"error":{"code":403,"message":"forbidden"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return scope_refusal;
                });
        }
        RestApiV1::CommandDispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string&,
                   const std::unordered_map<std::string, std::string>& params, const std::string&,
                   const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            last_exec_visible = caller.exec_visible;
            last_caller = caller;
            calls.push_back({plugin, action, ids, params});
            if (dispatch_denied) {
                yuzu::server::ConfinedDispatchOutcome refused;
                refused.command_id = "cmd-" + std::to_string(calls.size());
                refused.denied = dispatch_denied;
                return refused;
            }
            // Model what the production seam does to the Ids arm, rather than
            // ignoring the set the route just handed us: a target the caller
            // cannot see is not reached. Without this the fake would report a
            // successful dispatch no matter what confinement said, which is
            // exactly how the handoff went unasserted in the first place.
            // exec_visible == nullopt (unfiltered) admits everything, so every
            // pre-existing case in this file is unaffected.
            const bool admitted =
                std::all_of(ids.begin(), ids.end(), [&](const std::string& id) {
                    return yuzu::server::authz::in_scope(caller.exec_visible, id);
                });
            return {.sent = admitted ? dispatch_sent : 0, .command_id = "cmd-" + std::to_string(calls.size())};
        };

        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr, /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr, /*license_store=*/nullptr,
            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
            with_dispatch ? dispatch : RestApiV1::CommandDispatchFn{},
            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{}, /*network_api=*/{},
            /*lockout_clear_fn=*/{}, /*baseline_store=*/nullptr, scoped,
            /*software_inventory_store=*/nullptr,
            /*response_scope_fn=*/{},
            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
            /*auth_db=*/nullptr, /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
            // #1788: by default wire a derivation that ANSWERS (nullopt =
            // unfiltered), so every pre-existing dispatch assertion in this
            // file keeps its meaning; `wire_exec_visible=false` models the
            // genuinely-unwired deployment.
            wire_exec_visible ? RestApiV1::ExecVisibleFn{[this](const auth::Session&)
                                                             -> yuzu::server::authz::VisibleSet {
                                    return exec_visible_override;
                                }}
                              : RestApiV1::ExecVisibleFn{});
    }

    nlohmann::json post(const std::string& body, int& status) {
        auto res = sink.dispatch("POST", "/api/v1/echo/retention-paused/purge", body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    int audits_for(const std::string& action) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.action == action)
                ++n;
        return n;
    }
    /// One series of the purge counter on this surface.
    double metric(const std::string& result) {
        return metrics
            .counter("yuzu_echo_source_purge_total", {{"result", result}, {"surface", "rest"}})
            .value();
    }
    /// The label-less `{result}` series the surface label replaced: it no longer moves.
    double metric_without_surface(const std::string& result) {
        return metrics.counter("yuzu_echo_source_purge_total", {{"result", result}}).value();
    }
};

} // namespace

TEST_CASE("REST purge: rejects non-JSON / missing fields / bad source (400, no dispatch)",
          "[server][echo][purge][rest]") {
    PurgeHarness h;
    int st = 0;
    h.post("not json", st);
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A"})", st); // missing source
    CHECK(st == 400);
    h.post(R"({"source":"process"})", st); // missing device
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A","source":""})", st); // present-but-empty source
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A","source":"evil"})", st); // not in the allowlist
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A","source":"software"})", st); // real source, deliberately not in the REST allowlist
    CHECK(st == 400);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("echo.source.purge") == 0); // never reached the pre-dispatch audit
}

TEST_CASE("REST purge: per-device scope gate denies (403, no dispatch, no audit)",
          "[server][echo][purge][rest]") {
    PurgeHarness h;
    h.scope_allow = false;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 403);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("echo.source.purge") == 0);
}

TEST_CASE("REST purge: audit fail-closed → 503, no dispatch",
          "[server][echo][purge][rest]") {
    PurgeHarness h;
    h.audit_ok = false;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 503);
    CHECK(h.calls.empty()); // must NOT dispatch when the evidence row is known lost
}

// ── #1788 per-device dispatch confinement ────────────────────────────────
// This route's PRIMARY authorization is the per-device `scoped_perm_fn` gate
// above; the derived VisibleSet is a SECOND, independent check at the dispatch
// seam. These cases exist because the handoff was added without any assertion
// reading it — a code review confirmed empirically that forcing the route to
// pass `nullopt` left this entire suite green, so the layer was unverifiable.

TEST_CASE("REST purge: the caller's confined VisibleSet reaches dispatch",
          "[server][echo][purge][rest][scope][1788]") {
    PurgeHarness h;
    h.exec_visible_override = std::unordered_set<std::string>{"dev-A", "dev-B"};
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    CHECK(st == 202);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.last_exec_visible.has_value()); // CONFINED, not unfiltered
    CHECK(h.last_exec_visible->count("dev-A") == 1);
    CHECK(h.last_exec_visible->count("dev-Z") == 0);
}

TEST_CASE("REST purge: a target the caller cannot see is not reached, even though the per-device "
          "gate admitted it",
          "[server][echo][purge][rest][scope][1788]") {
    // scope_allow stays TRUE — the primary gate admits dev-A — so the only
    // thing that can refuse this dispatch is the confinement layer under test.
    PurgeHarness h;
    h.scope_allow = true;
    h.exec_visible_override = std::unordered_set<std::string>{"dev-OTHER"};
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    CHECK(st == 404); // reported as unreachable, deliberately indistinguishable from offline
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.last_exec_visible.has_value());
    CHECK(h.last_exec_visible->count("dev-A") == 0);
}

TEST_CASE("REST purge: an UNWIRED ExecVisibleFn fails CLOSED (present-empty), never unfiltered",
          "[server][echo][purge][rest][scope][fail-closed][1788]") {
    // ADR-0033 §1 / routed-concern clause 2: a missing derivation must never be
    // read as "no filter". On this route class the substitute is present-empty
    // — the primary gate is what reports a misconfiguration, so this layer
    // denies quietly rather than 500ing.
    PurgeHarness h(/*with_exec_visible=*/false);
    h.scope_allow = true;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    CHECK(st == 404);
    REQUIRE(h.last_exec_visible.has_value()); // PRESENT (deny-all), not nullopt
    CHECK(h.last_exec_visible->empty());
}

TEST_CASE("REST purge: success dispatches echo/purge_source with {source} and returns 202",
          "[server][echo][purge][rest]") {
    PurgeHarness h;
    int st = 0;
    auto body = h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    CHECK(st == 202);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "echo");
    CHECK(h.calls[0].action == "purge_source");
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    REQUIRE(h.calls[0].params.count("source") == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
    // A4 envelope nests the payload under "data".
    REQUIRE(body.contains("data"));
    CHECK(body["data"].contains("command_id"));
    CHECK(body["data"].value("source", "") == "tcp");
    CHECK(h.audits_for("echo.source.purge") == 1); // the pre-dispatch "requested" row
}

TEST_CASE("REST purge: offline agent (0 reached) → 404 after dispatch attempt",
          "[server][echo][purge][rest]") {
    PurgeHarness h;
    h.dispatch_sent = 0;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 404);
    REQUIRE(h.calls.size() == 1); // dispatch was attempted, reached 0 agents
}

// ── PR1.9c regression: the PRODUCTION wiring must supply a principal ─────────
//
// This is the test the branch review's CRITICAL slipped past. `RestApiV1`'s
// dispatch callback used to end in a bare `VisibleSet`, so the route derived a
// confinement set and NO identity; `ServerImpl::build_classified_command`
// refuses an empty `DispatchCaller::principal` as `AnonymousOperator` BEFORE
// the legacy-open/RBAC-off bypass, so every REST v1 dispatch reached zero
// agents and surfaced as `503 "device offline"` against a healthy fleet.
//
// Nothing caught it because the existing coverage tests the two halves apart:
// `test_dispatch_chokepoint.cpp` proves the pure function REFUSES an empty
// principal, and every REST/MCP suite injects a fake dispatch lambda, so no
// test ever asked whether the real route SUPPLIES one. This case closes that
// seam — it drives the genuine `resolve_secondary_caller` path in
// rest_api_v1.cpp through a real `auth_fn` and asserts the identity actually
// arrives at the dispatch boundary.
TEST_CASE("REST purge: the route hands dispatch a NON-EMPTY principal (anonymous-operator "
          "regression)",
          "[server][echo][purge][rest]") {
    PurgeHarness h;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    REQUIRE(st == 202); // purge is accepted-and-dispatched, like its siblings above
    REQUIRE(h.calls.size() == 1);

    // The harness authenticates as "purge-op"; the route must carry that
    // through, not a default-constructed caller. An empty principal here means
    // production dispatch is dead on arrival regardless of what this test's
    // fake returns for `sent`.
    CHECK_FALSE(h.last_caller.principal.empty());
    CHECK(h.last_caller.principal == "purge-op");
    // `system` must stay false: this is an operator dispatch, and a true here
    // would route it under system authority — bypassing the system_reserved
    // guard the chokepoint applies only to non-system callers.
    CHECK_FALSE(h.last_caller.system);
}

TEST_CASE("POST /api/v1/echo/retention-paused/purge: Infrastructure:Delete withdrawn inside the "
          "requested-row write dispatches nothing and writes failure permission_revoked (#7110)",
          "[server][echo][purge][rest][security][7110]") {
    PurgeHarness h;
    h.revoke_on_requested = true;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 403);
    CHECK(h.calls.empty());
    // Admission, then the recheck after the requested row.
    CHECK(h.scoped_calls == 2);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "requested");
    CHECK(h.audits[1].action == "echo.source.purge");
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].detail.rfind("permission_revoked device=dev-A source=process cid=", 0) == 0);
    CHECK(h.metric("denied") == 1.0);
}

// Kills: reverting the recheck's `fail` lambda to a bare audit_fn call (the lost outcome row would
// leave `requested` reading as "dispatched, outcome unknown" with nothing on the answer).
TEST_CASE("REST purge: a lost failure row after a recheck refusal is flagged Sec-Audit-Failed; the "
          "403 and the no-dispatch hold (#7110)",
          "[server][echo][purge][rest][security][7110]") {
    PurgeHarness h;
    h.revoke_on_requested = true;
    h.drop_failure_row = true;
    auto res = h.sink.dispatch("POST", "/api/v1/echo/retention-paused/purge",
                               R"({"device_id":"dev-A","source":"process"})");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.calls.empty());
    REQUIRE(h.audits.size() == 2); // the write was attempted ...
    CHECK(h.audits[1].result == "failure"); // ... and its loss is on the answer, not silent
}

TEST_CASE("REST purge: a caller that stops resolving inside the requested-row write dispatches nothing "
          "and writes failure caller_unresolved (#7110)",
          "[server][echo][purge][rest][security][7110]") {
    PurgeHarness h;
    h.drop_session_on_requested = true;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(h.calls.empty());
    // The per-device gate passed twice (it consults no session here); the resolution is what failed.
    CHECK(h.scoped_calls == 2);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "requested");
    CHECK(h.audits[1].action == "echo.source.purge");
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].detail.rfind("caller_unresolved device=dev-A source=process cid=", 0) == 0);
    CHECK(h.metric("denied") == 1.0);
}

TEST_CASE("REST purge: a denied outcome is reported as dispatch_denied reason=<token> and counted, "
          "never as agent_not_connected (#7114)",
          "[server][echo][purge][rest][security][7114]") {
    namespace detail = yuzu::server::detail;
    struct Denial {
        const char* name;
        detail::DispatchDenial denial;
        int status;
        const char* token;
        const char* hint; // the remediation names the cause (403 rows only)
    };
    const std::vector<Denial> denials = {
        {"Forbidden answers 403",
         {detail::DispatchDenialReason::Forbidden, "Infrastructure",
          yuzu::server::authz::Operation::Delete},
         403, "forbidden", "lacks this grant"},
        {"KillSwitched answers 403",
         {detail::DispatchDenialReason::KillSwitched, "Infrastructure",
          yuzu::server::authz::Operation::Delete},
         403, "kill_switched", "emergency stop"},
        // 500, not the 400 describe_dispatch_denial gives a caller-named pair: the pair is a
        // server literal, so an Unclassified or Ambiguous one is a server catalogue fault.
        {"Unclassified answers 500 (server-literal pair)",
         {detail::DispatchDenialReason::Unclassified, {}, yuzu::server::authz::Operation::Read},
         500, "unclassified", ""},
        {"Ambiguous answers 500 (server-literal pair)",
         {detail::DispatchDenialReason::Ambiguous, {}, yuzu::server::authz::Operation::Read},
         500, "ambiguous", ""},
    };
    for (const auto& d : denials) {
        DYNAMIC_SECTION(d.name) {
            PurgeHarness h;
            h.dispatch_denied = d.denial;
            int st = 0;
            const auto body = h.post(R"({"device_id":"dev-A","source":"process"})", st);
            const std::string token = d.token;
            CHECK(st == d.status);
            CHECK(body["error"]["message"] == "dispatch denied: reason=" + token);
            // The 500 class is a server catalogue fault (the pair is a server literal): its hint
            // must not tell the caller to confirm a plugin/action name they never chose.
            const auto remediation = body["error"]["remediation"].get<std::string>();
            if (d.status == 500) {
                CHECK(remediation.find("server catalogue fault") != std::string::npos);
                CHECK(remediation.find("confirm the plugin/action name") == std::string::npos);
            } else {
                CHECK(remediation.find(d.hint) != std::string::npos);
            }
            REQUIRE(h.audits.size() == 2);
            CHECK(h.audits[1].result == "failure");
            CHECK(h.audits[1].detail.rfind("dispatch_denied reason=" + token +
                                               " device=dev-A source=process cid=", 0) == 0);
            CHECK(h.metric(token) == 1.0);
            CHECK(h.metric("agent_not_connected") == 0.0);
        }
    }
}

// ── #2536 / #2532: the metric vocabulary on surface=rest ─────────────────────────────────────
//
// One closed result set, shared with the dashboard fragments: every refusal class of the scoped
// gate, every outage and every outcome counts under its own result. Only the metric changed: the
// status, body and audit rows of each path are the ones this suite pinned before (the one audit
// detail that moved is the recheck's failure row under a degraded authorization read, which now
// carries the shared `store_unavailable store=` token).

TEST_CASE("REST purge: every refusal and outage counts under its own result on surface=rest",
          "[server][echo][purge][rest][2536][2532]") {
    static constexpr const char* kBody = R"({"device_id":"dev-A","source":"process"})";
    // Sequential posts on one harness: no step dispatches except the last, so none starts anything
    // the next depends on (this surface has no repeat bound at all).
    PurgeHarness h;
    int st = 0;
    // Posts one request and requires that `result` moved by exactly one.
    const auto expect = [&](const char* step, const char* result, int status,
                            const char* body = nullptr) {
        CAPTURE(step, result);
        const double before = h.metric(result);
        const auto json = h.post(body != nullptr ? std::string{body} : std::string{kBody}, st);
        if (status != 0) // 0: the status is the authenticator's, which this harness leaves unset
            CHECK(st == status);
        CHECK(h.metric(result) == before + 1.0);
        return json;
    };
    const auto reset = [&h] {
        h.scope_allow = true;
        h.scope_refusal = ScopedGateOutcome::Denied;
        h.revoke_on_requested = false;
        h.drop_session_on_requested = false;
        h.session_gone = false;
        h.audit_ok = true;
        h.dispatch_sent = 1;
    };

    // Malformed body: before any gate.
    expect("malformed body", "invalid_input", 400, "not json");

    // Admission, by the gate's class. The gate's own status and body are unchanged.
    h.scope_allow = false;
    auto body = expect("denied at admission", "scope_violation", 403);
    CHECK(body["error"]["message"] == "forbidden");
    h.scope_refusal = ScopedGateOutcome::Unauthenticated;
    expect("unauthenticated at admission", "denied", 401);
    CHECK(h.metric("scope_violation") == 1.0); // not a scope violation
    h.scope_refusal = ScopedGateOutcome::Unavailable;
    expect("unavailable at admission", "infra_unavailable", 503);
    for (const auto outcome : {ScopedGateOutcome::MgmtGroupReadDegraded,
                               ScopedGateOutcome::RbacReadDegraded}) {
        h.scope_refusal = outcome;
        body = expect("degraded read at admission", "store_unavailable", 403);
        CHECK(body["error"]["message"] == "forbidden"); // the gate's fail-closed 403, unchanged
    }
    CHECK(h.metric("scope_violation") == 1.0); // still just the plain denial above
    CHECK(h.audits_for("echo.source.purge") == 0); // every one refused before the requested row
    reset();

    // The requested row is not stored.
    h.audit_ok = false;
    expect("requested row not stored", "audit_unavailable", 503);
    reset();

    // The recheck, after the requested row. The failure row's detail is the shared token for a
    // degraded read, `scoped_gate_unavailable` for a gate 503 and `permission_revoked` otherwise.
    h.revoke_on_requested = true;
    expect("denied at the recheck", "denied", 403);
    CHECK(h.audits.back().detail.rfind("permission_revoked device=dev-A source=process cid=", 0) == 0);
    reset();
    h.revoke_on_requested = true;
    h.scope_refusal = ScopedGateOutcome::Unauthenticated;
    expect("unauthenticated at the recheck", "denied", 401);
    CHECK(h.audits.back().detail.rfind("permission_revoked device=dev-A source=process cid=", 0) == 0);
    reset();
    h.revoke_on_requested = true;
    h.scope_refusal = ScopedGateOutcome::Unavailable;
    expect("unavailable at the recheck", "infra_unavailable", 503);
    CHECK(h.audits.back().result == "failure");
    CHECK(h.audits.back().detail.rfind("scoped_gate_unavailable device=dev-A source=process cid=", 0) == 0);
    CHECK(h.calls.empty()); // fail closed: nothing was dispatched
    reset();
    h.revoke_on_requested = true;
    h.scope_refusal = ScopedGateOutcome::MgmtGroupReadDegraded;
    expect("management-group read degraded at the recheck", "store_unavailable", 403);
    CHECK(h.audits.back().result == "failure");
    CHECK(h.audits.back().detail.rfind(
              "store_unavailable store=mgmt_group_store device=dev-A source=process cid=", 0) == 0);
    CHECK(h.calls.empty());
    reset();
    h.revoke_on_requested = true;
    h.scope_refusal = ScopedGateOutcome::RbacReadDegraded;
    expect("RBAC read degraded at the recheck", "store_unavailable", 403);
    CHECK(h.audits.back().result == "failure");
    CHECK(h.audits.back().detail.rfind(
              "store_unavailable store=rbac_store device=dev-A source=process cid=", 0) == 0);
    CHECK(h.calls.empty());
    reset();

    // The caller stops resolving after the requested row.
    h.drop_session_on_requested = true;
    expect("caller_unresolved", "denied", 0);
    CHECK(h.audits.back().detail.rfind("caller_unresolved device=dev-A source=process cid=", 0) == 0);
    reset();

    // Dispatch outcomes.
    h.dispatch_sent = 0;
    expect("zero reach", "agent_not_connected", 404);
    reset();
    expect("success", "success", 202);

    // Both degrade classes were counted store_unavailable twice and once at the recheck apiece.
    CHECK(h.metric("store_unavailable") == 4.0);
    // The label-less series the surface label replaced no longer moves.
    for (const char* result : {"denied", "scope_violation", "infra_unavailable", "success",
                               "invalid_input", "audit_unavailable", "agent_not_connected"})
        CHECK(h.metric_without_surface(result) == 0.0);
    // The surface label is spelled exactly.
    CHECK(h.metrics
              .counter("yuzu_echo_source_purge_total", {{"result", "success"}, {"surface", "rest"}})
              .value() == 1.0);
}

TEST_CASE("REST purge: an unset typed gate answers the fail-closed 500 and counts infra_unavailable",
          "[server][echo][purge][rest][2536][2532]") {
    // The positional scoped function IS wired (so a route that still read it would admit); only
    // the typed gate is missing.
    PurgeHarness h(/*with_exec_visible=*/true, /*wire_typed_gate=*/false);
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 500);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("echo.source.purge") == 0);
    CHECK(h.metric("infra_unavailable") == 1.0);
    CHECK(h.metric_without_surface("denied") == 0.0);
}

TEST_CASE("REST purge: an unwired dispatch function answers 503 and counts infra_unavailable",
          "[server][echo][purge][rest][2536][2532]") {
    PurgeHarness h(/*with_exec_visible=*/true, /*wire_typed_gate=*/true, /*with_dispatch=*/false);
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 503);
    CHECK(h.audits_for("echo.source.purge") == 0); // refused before the requested row
    CHECK(h.metric("infra_unavailable") == 1.0);
    CHECK(h.metric("denied") == 0.0);
}
