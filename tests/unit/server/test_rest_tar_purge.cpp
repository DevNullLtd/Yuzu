/**
 * test_rest_tar_purge.cpp — route-handler coverage for the REST TAR source-purge
 * endpoint POST /api/v1/tar/retention-paused/purge (governance remediation of the
 * PR #1781 adversarial review; finding #5 / issue #1779).
 *
 * Registers RestApiV1 over an in-process TestRouteSink (#438: no acceptor thread)
 * with stub scoped-perm / audit / command-dispatch, and drives the DESTRUCTIVE
 * endpoint end-to-end so a future refactor that drops one of its gates fails here:
 *   - source allowlist (only process/tcp/service/user),
 *   - per-device scope gate (Infrastructure:Delete via scoped_perm_fn, fail-closed),
 *   - audit-before-dispatch fail-closed (no dispatch if the evidence row is lost),
 *   - the success dispatch shape (tar/purge_source targeting the one device, {source}).
 *
 * The DashboardRoutes HTML fragment (/fragments/tar/retention-paused/purge) shares
 * these properties and has its own route-handler coverage since #1786 moved
 * DashboardRoutes onto HttpRouteSink — see test_dashboard_tar_fragments.cpp (the
 * fragment additionally gates a CSRF same-site check that this REST twin, being the
 * programmatic surface, does not). The fragment's render-time button gating is
 * covered in test_dashboard_tar_retention.cpp.
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
    bool scope_allow{true}; // scoped_perm_fn verdict
    bool audit_ok{true};    // AuditFn return (false → fail-closed 503, no dispatch)
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

    explicit PurgeHarness(bool with_exec_visible = true) : wire_exec_visible(with_exec_visible) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
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
            return audit_ok;
        };
        RestApiV1::ScopedPermFn scoped =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&, const std::string&) -> bool {
            if (!scope_allow) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"forbidden"},"meta":{"api_version":"v1"}})",
                    "application/json");
            }
            return scope_allow;
        };
        RestApiV1::CommandDispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string&,
                   const std::unordered_map<std::string, std::string>& params, const std::string&,
                   const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            last_exec_visible = caller.exec_visible;
            last_caller = caller;
            calls.push_back({plugin, action, ids, params});
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
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr, dispatch,
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
        auto res = sink.dispatch("POST", "/api/v1/tar/retention-paused/purge", body);
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
};

} // namespace

TEST_CASE("REST purge: rejects non-JSON / missing fields / bad source (400, no dispatch)",
          "[server][tar][purge][rest]") {
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
    CHECK(h.audits_for("tar.source.purge") == 0); // never reached the pre-dispatch audit
}

TEST_CASE("REST purge: per-device scope gate denies (403, no dispatch, no audit)",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    h.scope_allow = false;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 403);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.purge") == 0);
}

TEST_CASE("REST purge: audit fail-closed → 503, no dispatch",
          "[server][tar][purge][rest]") {
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
          "[server][tar][purge][rest][scope][1788]") {
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
          "[server][tar][purge][rest][scope][1788]") {
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
          "[server][tar][purge][rest][scope][fail-closed][1788]") {
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

TEST_CASE("REST purge: success dispatches tar/purge_source with {source} and returns 202",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    int st = 0;
    auto body = h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    CHECK(st == 202);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "tar");
    CHECK(h.calls[0].action == "purge_source");
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    REQUIRE(h.calls[0].params.count("source") == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
    // A4 envelope nests the payload under "data".
    REQUIRE(body.contains("data"));
    CHECK(body["data"].contains("command_id"));
    CHECK(body["data"].value("source", "") == "tcp");
    CHECK(h.audits_for("tar.source.purge") == 1); // the pre-dispatch "requested" row
}

TEST_CASE("REST purge: offline agent (0 reached) → 404 after dispatch attempt",
          "[server][tar][purge][rest]") {
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
          "[server][tar][purge][rest]") {
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
