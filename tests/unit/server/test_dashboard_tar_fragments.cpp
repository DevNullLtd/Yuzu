/**
 * test_dashboard_tar_fragments.cpp — route-handler coverage for the TAR
 * retention-paused DASHBOARD FRAGMENT POSTs (issue #1786):
 *   - POST /fragments/tar/retention-paused/purge   (destructive)
 *   - POST /fragments/tar/retention-paused/reenable
 *
 * Until #1786 these two handlers were registered directly on a raw
 * httplib::Server, so the in-process route harness could not reach them and
 * their security gates were untested — a refactor that dropped one would not
 * fail any test. `DashboardRoutes::register_routes` now has an HttpRouteSink
 * overload (the httplib::Server& overload wraps + delegates to it), so the
 * handlers are drivable here with no acceptor thread (#438 TSan trap).
 *
 * Pinned per handler:
 *   - the permission tier — Infrastructure:Delete for purge, Execution:Execute
 *     for reenable (a tier downgrade must fail here), plus the denied audit +
 *     `result="denied"` metric on rejection,
 *   - the CSRF same-site gate — cross-origin AND header-less POSTs are 403'd
 *     BEFORE dispatch (these fragments are stricter than the shared
 *     `origin_is_same_site` helper, which permits header-less non-browser
 *     clients). For PURGE that strictness is free: a programmatic caller has
 *     the REST twin POST /api/v1/tar/retention-paused/purge. REENABLE HAS NO
 *     REST OR MCP TWIN, so pinning its header-less 403 also pins it as
 *     unreachable by any non-browser principal — a pre-existing gap in a
 *     grandfathered fragment, recorded here so the test is not mistaken for
 *     an endorsement of it,
 *   - the {process,tcp,service,user} source allowlist and the
 *     required-field check → 400, no dispatch,
 *   - the per-device RBAC visibility gate → 404 collapsed with the offline
 *     case (no existence oracle) + a `scope_violation` audit recording the
 *     real reason server-side,
 *   - the offline (0 agents reached) path → 404 + `agent_not_connected`,
 *   - the success dispatch shape — tar/purge_source {source} and
 *     tar/configure {<source>_enabled=true}, targeting the one device only.
 *
 * The REST twin (POST /api/v1/tar/retention-paused/purge) is covered by
 * test_rest_tar_purge.cpp; the render-time button gating by
 * test_dashboard_tar_retention.cpp.
 */

#include "dashboard_routes.hpp"
#include "management_group_store.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_real_capability_registry.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kUser = "frag-op";
constexpr const char* kHost = "yuzu.example:8080";
constexpr const char* kPurgePath = "/fragments/tar/retention-paused/purge";
constexpr const char* kReenablePath = "/fragments/tar/retention-paused/reenable";

struct DispatchCall {
    std::string plugin, action, scope_expr;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
    // CDX-R7-02: the exec_visible set the handler threaded into dispatch.
    yuzu::server::authz::VisibleSet exec_visible;
    // PLAN-006: the full DispatchCaller (identity + exec_visible) the handler
    // threaded into dispatch, so a test can assert the principal half too.
    yuzu::server::DispatchCaller caller;
};
struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};
struct PermCall {
    std::string securable_type, op;
};

/// Make `agents` visible to kUser: members of a group on which kUser holds a
/// role (get_visible_agents is the role-scoped join, and fails CLOSED with the
/// rbac_enabled_probe unset — same posture as production with RBAC on).
void grant_visibility(ManagementGroupStore& mg, std::initializer_list<std::string> agents) {
    ManagementGroup g;
    g.name = "All Devices";
    g.membership_type = "static";
    auto gid = mg.create_group(g);
    REQUIRE(gid.has_value());
    // Assert the membership writes land. A silently-failed add would leave
    // get_visible_agents empty, and the 404/scope_violation cases would then
    // pass for entirely the wrong reason.
    for (const auto& a : agents)
        REQUIRE(mg.add_member(*gid, a).has_value());
    GroupRoleAssignment ra;
    ra.group_id = *gid;
    ra.principal_type = "user";
    ra.principal_id = kUser;
    ra.role_name = "ITServiceOwner";
    REQUIRE(mg.assign_role(ra).has_value());
}

struct FragmentHarness {
    // `yuzu_test_` prefix so the path lands inside the Wee Tam Defender
    // exclusion wildcard `yuzu_*` (CLAUDE.md → Test conventions).
    //
    // MEMBER ORDER IS LOAD-BEARING: `sink` is declared LAST so it is destroyed
    // FIRST, while the `DashboardRoutes` whose `this` its handlers captured is
    // still alive. The reverse order (which most existing sink fixtures use)
    // leaves live handlers holding a destroyed owner. `mg`/`metrics` precede
    // `routes` because `routes` borrows both.
    yuzu::test::TempDbFile mg_db{"yuzu_test_tar_frag_mg_"};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    std::vector<PermCall> perms;
    bool perm_allow{true}; ///< perm_fn verdict (false → handler's 403 path)
    bool auth_ok{true};    ///< auth_fn verdict (false → handler returns early)
    int dispatch_sent{1};  ///< agents reached per dispatch (0 → offline 404)

    /// CDX-R7-02 / PLAN-006: the per-request DispatchCaller derivation the
    /// handlers consult for /api/dashboard/execute + tar-execute. Default
    /// returns a DispatchCaller whose exec_visible is nullopt (UNFILTERED) so
    /// pre-existing fragment tests keep the full-fleet path; a confinement
    /// test overrides it with a specific set; a fail-closed test sets it to
    /// `{}` (genuinely unwired → the production handler denies all).
    DashboardRoutes::CallerFn caller_fn{[](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{.exec_visible = yuzu::server::authz::VisibleSet{}};
    }};

    /// CDX-R7-02: what the harness resolve_fn returns for /api/dashboard/execute
    /// (empty → "unknown command", so the dispatch path is unreachable). A
    /// confinement test sets a valid (plugin, action) so dispatch is reached.
    std::pair<std::string, std::string> resolve_to{};

    /// @param with_dispatch false → register with an empty DispatchFn so the
    ///        "dispatch unavailable" 503 branch is reachable.
    /// @param wire_exec_visible false → register with an EMPTY CallerFn so
    ///        the production handler's own fail-closed branch (unwired → present-
    ///        empty deny-all) is exercised (CDX-R7-02).
    explicit FragmentHarness(bool with_dispatch = true, bool wire_exec_visible = true) {
        // A failed open would make get_visible_agents return empty and quietly
        // turn every scope assertion into a pass-for-the-wrong-reason.
        REQUIRE(mg.is_open());
        grant_visibility(mg, {"dev-A", "dev-B"});

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!auth_ok) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = kUser;
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            perms.push_back({type, op});
            if (!perm_allow)
                res.status = 403;
            return perm_allow;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& tid, const std::string& d) {
            audits.push_back({a, r, tt, tid, d});
        };
        DashboardRoutes::DispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string& scope,
                   const std::unordered_map<std::string, std::string>& params,
                   const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            calls.push_back({plugin, action, scope, ids, params, caller.exec_visible, caller});
            return {.sent = dispatch_sent, .command_id = "cmd-" + std::to_string(calls.size())};
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn,
                               /*response_store=*/nullptr, &mg, /*registry=*/nullptr,
                               /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                               /*agents_json_fn=*/[] { return std::string{"[]"}; },
                               with_dispatch ? dispatch : DashboardRoutes::DispatchFn{},
                               /*caller_fn=*/
                               wire_exec_visible
                                   ? DashboardRoutes::CallerFn{
                                         [this](const httplib::Request& req) -> yuzu::server::DispatchCaller {
                                             // Delegate to the reassignable member so
                                             // a test can override it after
                                             // construction (live read).
                                             return caller_fn ? caller_fn(req)
                                                              : yuzu::server::DispatchCaller{};
                                         }}
                                   : DashboardRoutes::CallerFn{},
                               /*resolve_fn=*/
                               [this](const std::string&) { return resolve_to; },
                               &metrics, /*instruction_store=*/nullptr);
        // Exactly one registration pass. Two overloads of register_routes now
        // exist; calling both (or either twice) would register every route
        // twice — first-match-wins would then serve handlers bound to the
        // FIRST call's dependencies while the members hold the second call's.
        // Nothing else would fail, so pin the count.
        // #4027: +1 for GET /api/v1/tar/retention-paused.
        REQUIRE(sink.route_count() == 13);

        // PR6.0b: `/api/dashboard/execute` now consults a `ClassifyFn` for the
        // Destructive TARGETING gate, and an UNWIRED one refuses every
        // dispatch (fail-closed, matching `McpServer::ClassifyFn`). Wire the
        // REAL production classifier here so the cases below keep testing what
        // they claim — caller/exec_visible threading and the CDX-R8-01
        // supplied-vs-omitted scope rule — rather than silently becoming six
        // more assertions about the classifier being absent. The pairs they
        // use are classify-misses, which take the gate's Policy-B
        // fall-through and dispatch unchanged; the gate's own behaviour is
        // bound in test_dashboard_destructive_gate.cpp.
        routes.set_capability_classify_fn(yuzu::test::real_classify_fn());
    }

    static std::unordered_map<std::string, std::string> same_site_headers() {
        return {{"Host", kHost}, {"Origin", std::string{"https://"} + kHost}};
    }

    std::unique_ptr<httplib::Response>
    post(const std::string& path, const std::string& body,
         const std::unordered_map<std::string, std::string>& headers = same_site_headers()) {
        auto res = sink.dispatch("POST", path, body, "application/x-www-form-urlencoded", headers);
        REQUIRE(res != nullptr);
        return res;
    }

    int audits_for(const std::string& action, const std::string& result) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                ++n;
        return n;
    }
    /// Detail string of the first audit row matching (action, result); "" if none.
    std::string audit_detail(const std::string& action, const std::string& result) const {
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                return a.detail;
        return {};
    }
    double metric(const std::string& name, const std::string& result) {
        return metrics.counter(name, {{"result", result}}).value();
    }
};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

// ── Permission tier ─────────────────────────────────────────────────────────

TEST_CASE("fragment purge: gates on Infrastructure:Delete; denial audits + counts, no dispatch",
          "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    h.perm_allow = false;
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 403);
    REQUIRE(h.perms.size() == 1);
    CHECK(h.perms[0].securable_type == "Infrastructure");
    CHECK(h.perms[0].op == "Delete");
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.purge", "denied") == 1);
    CHECK(h.audit_detail("tar.source.purge", "denied") == "rbac_denied");
    CHECK(h.metric("yuzu_tar_source_purge_total", "denied") == 1.0);
}

TEST_CASE("fragment reenable: gates on Execution:Execute; denial audits + counts, no dispatch",
          "[pg][server][tar][reenable][fragment]") {
    FragmentHarness h;
    h.perm_allow = false;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=process");
    CHECK(res->status == 403);
    REQUIRE(h.perms.size() == 1);
    CHECK(h.perms[0].securable_type == "Execution");
    CHECK(h.perms[0].op == "Execute");
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.reenable", "denied") == 1);
    CHECK(h.audit_detail("tar.source.reenable", "denied") == "rbac_denied");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "denied") == 1.0);
}

// ── CSRF same-site gate ─────────────────────────────────────────────────────

TEST_CASE("fragment purge: cross-origin and header-less POSTs are refused before dispatch",
          "[pg][server][tar][purge][fragment][csrf]") {
    SECTION("cross-origin Origin") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(contains(res->body, "Cross-origin request refused"));
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("tar.source.purge", "denied") == "csrf_cross_origin");
        CHECK(h.metric("yuzu_tar_source_purge_total", "denied") == 1.0);
    }
    SECTION("cross-origin Referer (no Origin)") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Referer", "https://evil.example/tar"}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
    }
    SECTION("neither Origin nor Referer — stricter than origin_is_same_site's default") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process", {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("tar.source.purge", "denied") == "csrf_cross_origin");
    }
    SECTION("same-site Referer is accepted") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Referer", std::string{"https://"} + kHost + "/tar"}});
        CHECK(res->status == 200);
        CHECK(h.calls.size() == 1);
    }
}

TEST_CASE("fragment reenable: cross-origin and header-less POSTs are refused before dispatch",
          "[pg][server][tar][reenable][fragment][csrf]") {
    SECTION("cross-origin") {
        FragmentHarness h;
        auto res = h.post(kReenablePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("tar.source.reenable", "denied") == "csrf_cross_origin");
        CHECK(h.metric("yuzu_tar_source_reenable_total", "denied") == 1.0);
    }
    SECTION("header-less") {
        FragmentHarness h;
        auto res = h.post(kReenablePath, "device_id=dev-A&source=process", {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
    }
}

// ── Input validation ────────────────────────────────────────────────────────

TEST_CASE("fragment purge: missing fields and forged sources are rejected 400, no dispatch",
          "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    CHECK(h.post(kPurgePath, "source=process")->status == 400);          // no device_id
    CHECK(h.post(kPurgePath, "device_id=dev-A")->status == 400);         // no source
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=")->status == 400); // empty source
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=evil")->status == 400);
    // A real TAR source deliberately outside the four-source frame scope.
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=software")->status == 400);
    CHECK(h.calls.empty());
    CHECK(h.metric("yuzu_tar_source_purge_total", "invalid_input") == 5.0);
}

TEST_CASE("fragment reenable: missing fields and forged sources are rejected 400, no dispatch",
          "[pg][server][tar][reenable][fragment]") {
    FragmentHarness h;
    CHECK(h.post(kReenablePath, "source=process")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=")->status == 400); // empty source
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=evil")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=software")->status == 400);
    CHECK(h.calls.empty());
    CHECK(h.metric("yuzu_tar_source_reenable_total", "invalid_input") == 5.0);
}

TEST_CASE("fragment reenable: every allowlisted source dispatches",
          "[pg][server][tar][reenable][fragment]") {
    // The negative cases above cannot tell "rejected because forged" from
    // "rejected because the allowlist rejects everything" — this is the
    // positive half that makes removing a source from the allowlist fail.
    FragmentHarness h;
    for (const char* src : {"process", "tcp", "service", "user"})
        CHECK(h.post(kReenablePath, std::string{"device_id=dev-A&source="} + src)->status == 200);
    REQUIRE(h.calls.size() == 4);
    for (std::size_t i = 0; i < h.calls.size(); ++i) {
        CHECK(h.calls[i].action == "configure");
        CHECK(h.calls[i].params.size() == 1); // per-source independence (#539)
    }
    CHECK(h.metric("yuzu_tar_source_reenable_total", "success") == 4.0);
}

TEST_CASE("fragment purge: every allowlisted source dispatches", "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    for (const char* src : {"process", "tcp", "service", "user"})
        CHECK(h.post(kPurgePath, std::string{"device_id=dev-A&source="} + src)->status == 200);
    CHECK(h.calls.size() == 4);
    CHECK(h.metric("yuzu_tar_source_purge_total", "success") == 4.0);
}

// ── RBAC device scope ───────────────────────────────────────────────────────

TEST_CASE("fragment purge: out-of-scope device 404s (no existence oracle) and audits the reason",
          "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    auto res = h.post(kPurgePath, "device_id=dev-OTHER&source=process");
    CHECK(res->status == 404);
    // Same body as the offline case — the response must not distinguish
    // "not yours" from "not connected".
    CHECK(contains(res->body, "Agent not reachable"));
    CHECK(h.calls.empty());
    CHECK(h.audit_detail("tar.source.purge", "failure") == "scope_violation source=process");
    CHECK(h.metric("yuzu_tar_source_purge_total", "scope_violation") == 1.0);
}

TEST_CASE("fragment reenable: out-of-scope device 404s and audits the reason",
          "[pg][server][tar][reenable][fragment]") {
    FragmentHarness h;
    auto res = h.post(kReenablePath, "device_id=dev-OTHER&source=tcp");
    CHECK(res->status == 404);
    CHECK(contains(res->body, "Agent not reachable"));
    CHECK(h.calls.empty());
    CHECK(h.audit_detail("tar.source.reenable", "failure") == "scope_violation source=tcp");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "scope_violation") == 1.0);
}

// ── Offline / unavailable ───────────────────────────────────────────────────

TEST_CASE("fragment purge: offline agent (0 reached) → 404 + agent_not_connected",
          "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    h.dispatch_sent = 0;
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 404);
    CHECK(contains(res->body, "Agent not reachable"));
    REQUIRE(h.calls.size() == 1); // dispatch was attempted, reached nobody
    CHECK(h.audit_detail("tar.source.purge", "failure") == "agent_not_connected source=process");
    CHECK(h.metric("yuzu_tar_source_purge_total", "agent_not_connected") == 1.0);
}

TEST_CASE("fragment reenable: offline agent (0 reached) → 404 + agent_not_connected",
          "[pg][server][tar][reenable][fragment]") {
    FragmentHarness h;
    h.dispatch_sent = 0;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=user");
    CHECK(res->status == 404);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.audit_detail("tar.source.reenable", "failure") == "agent_not_connected source=user");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "agent_not_connected") == 1.0);
}

TEST_CASE("fragment purge: the out-of-scope and offline 404s are byte-identical",
          "[pg][server][tar][purge][fragment]") {
    // The whole point of the collapse is that a caller cannot tell "not yours"
    // from "not connected". A substring check would still pass if a refactor
    // added a distinguishing class or marker to one of them, so compare the
    // full bodies AND the status.
    FragmentHarness h;
    auto out_of_scope = h.post(kPurgePath, "device_id=dev-OTHER&source=process");
    h.dispatch_sent = 0;
    auto offline = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(out_of_scope->status == offline->status);
    CHECK(out_of_scope->body == offline->body);
    // ...and the server-side audit detail still tells the two apart.
    CHECK(h.audits_for("tar.source.purge", "failure") == 2);
    CHECK(contains(h.audit_detail("tar.source.purge", "failure"), "scope_violation"));
}

TEST_CASE("fragment purge/reenable: no dispatch wiring → 503",
          "[pg][server][tar][purge][fragment]") {
    // No `calls.empty()` assertion here: with an empty DispatchFn nothing can
    // ever be recorded, so it would be a tautology rather than evidence.
    FragmentHarness h{/*with_dispatch=*/false};
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=process")->status == 503);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=process")->status == 503);
}

TEST_CASE("fragment purge/reenable: an unauthenticated session stops before dispatch",
          "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    h.auth_ok = false;
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=process")->status == 401);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=process")->status == 401);
    CHECK(h.calls.empty());
}

// ── Success shape ───────────────────────────────────────────────────────────

TEST_CASE("fragment purge: success dispatches tar/purge_source to the one device",
          "[pg][server][tar][purge][fragment]") {
    FragmentHarness h;
    auto res = h.post(kPurgePath, "device_id=dev-B&source=tcp");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "tar");
    CHECK(h.calls[0].action == "purge_source");
    CHECK(h.calls[0].scope_expr.empty()); // targeted, never a scope fan-out
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-B");
    REQUIRE(h.calls[0].params.count("source") == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
    CHECK(h.audit_detail("tar.source.purge", "success") == "device=dev-B source=tcp");
    CHECK(h.metric("yuzu_tar_source_purge_total", "success") == 1.0);
    // Purge leaves the source PAUSED, so the row stays and is annotated.
    CHECK(contains(res->body, "Purge dispatched"));
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("fragment reenable: success dispatches tar/configure with <source>_enabled=true",
          "[pg][server][tar][reenable][fragment]") {
    FragmentHarness h;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=service");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "tar");
    CHECK(h.calls[0].action == "configure");
    CHECK(h.calls[0].scope_expr.empty());
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    // Per-source independence (#539): ONLY the named source's key is set.
    REQUIRE(h.calls[0].params.size() == 1);
    REQUIRE(h.calls[0].params.count("service_enabled") == 1);
    CHECK(h.calls[0].params.at("service_enabled") == "true");
    CHECK(h.audit_detail("tar.source.reenable", "success") == "device=dev-A source=service");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "success") == 1.0);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("fragment purge: query-string params are honoured like form-body params",
          "[pg][server][tar][purge][fragment]") {
    // htmx posts a urlencoded body, but the handler also accepts req.params —
    // both paths must land on the same dispatch.
    FragmentHarness h;
    auto res = h.post(std::string{kPurgePath} + "?device_id=dev-A&source=process", "");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    CHECK(h.calls[0].params.at("source") == "process");
}

TEST_CASE("fragment purge: a query param wins over a body param of the same name",
          "[pg][server][tar][purge][fragment]") {
    // httplib parses the query string into req.params BEFORE the body, and
    // get_param_value returns the first match — so a query value shadows a body
    // value. Pinned because it is a request-smuggling shape: a proxy inspecting
    // only the body would see `user` while the server dispatches `process`.
    // This asserts the CURRENT, httplib-faithful precedence; if the handler ever
    // needs body-wins semantics that is a deliberate change, not a silent one.
    FragmentHarness h;
    auto res = h.post(std::string{kPurgePath} + "?source=process", "device_id=dev-A&source=user");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].params.at("source") == "process");
}

TEST_CASE("fragment purge: a non-form content-type falls back to raw-body parsing",
          "[pg][server][tar][purge][fragment]") {
    // With a non-urlencoded Content-Type the sink leaves req.params empty, as
    // httplib does, so the handler takes its extract_form_value(req.body, ...)
    // fallback. That fallback carries the unanchored-key defect filed as #2527
    // (`xsource=` matches the needle `source=`), so the SAME bytes that dispatch
    // source=tcp through the params branch are rejected 400 here. Pinning both
    // directions keeps #2527's blast radius visible: it fails CLOSED on this
    // route, and this test is what will flip when #2527 is fixed.
    FragmentHarness h;
    auto res = h.sink.dispatch("POST", kPurgePath, "xsource=evil&device_id=dev-A&source=tcp",
                               "text/plain", FragmentHarness::same_site_headers());
    REQUIRE(res != nullptr);
    CHECK(res->status == 400);
    CHECK(h.calls.empty());
}

TEST_CASE("fragment purge: form fields are read the way httplib would parse them",
          "[pg][server][tar][purge][fragment]") {
    // Guards the TestRouteSink fidelity fix (#1786): the sink must parse a
    // urlencoded BODY into req.params like httplib::Server does, so these
    // tests exercise the handler's `req.has_param` branch — the production
    // path — rather than its `extract_form_value(req.body, ...)` fallback.
    //
    // `xsource=` is the discriminator. httplib's parser splits on `&`/`=` and
    // yields source="tcp"; the fallback's unanchored `body.find("source=")`
    // matches INSIDE `xsource=` and yields "evil", which the allowlist would
    // reject with a 400. So a 200 carrying source=tcp proves the params branch
    // ran. (If the fallback's key matching is ever anchored the two branches
    // agree and this stops discriminating — it still passes, it just stops
    // adding information.)
    FragmentHarness h;
    auto res = h.post(kPurgePath, "xsource=evil&device_id=dev-A&source=tcp");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
}

// ═══════════════════════════════════════════════════════════════════════════
// CDX-R7-02 — dashboard execute dispatch confinement handoff
//
// The dashboard execute surface now routes through the shared
// `dispatch_confined` seam (server.cpp), narrowing every arm to the operator's
// Execution:Execute visible set. As with the MCP handoff test
// (test_mcp_server.cpp CDX-R5-02), the route-level harness wires a MOCK
// DispatchFn, so it asserts the HANDOFF — the handler derived the caller's
// visible set and threaded it into dispatch — while the per-arm narrowing
// itself (filter_to_scope / in_scope) is pinned by the authz_model unit tests
// and the single shared dispatch_confined seam.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("dashboard execute threads the caller's exec_visible into dispatch (CDX-R7-02)",
          "[server][dashboard][execute][scope]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0; // stop before the result-render path (registry_ is null here)
    // Service-scoped confinement: the caller can see only dev-A.
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{
            .exec_visible = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"dev-A"}}};
    };
    // Target dev-B (an id-list arm), which is OUTSIDE the caller's visible set.
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-B");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"dev-B"});
    // The handoff: a PRESENT (confined) set, dev-A in / dev-B out. The
    // production dispatch_confined then drops dev-B via filter_to_scope.
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("dev-A") == 1);
    CHECK(h.calls[0].exec_visible->count("dev-B") == 0);
}

TEST_CASE("dashboard execute broadcast still carries the caller's exec_visible (CDX-R7-02)",
          "[server][dashboard][execute][scope]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{
            .exec_visible = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"dev-A"}}};
    };
    // CDX-R8-01: `__all__` is now passed THROUGH by name (the Broadcast arm),
    // not stripped to empty+empty (the None arm). Broadcast is named, never
    // inferred from emptiness — dispatch_target_shape.hpp:14-16. This assertion
    // deliberately inverts the previous one, which pinned the empty-fallthrough
    // shape the contract forbids.
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=__all__");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids.empty());
    CHECK(h.calls[0].scope_expr == "__all__"); // kBroadcastScope, by name
    // Even the deliberate fleet broadcast composes with the visible set.
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("dev-A") == 1);
}

TEST_CASE("dashboard execute REFUSES a supplied-but-empty scope (CDX-R8-01)",
          "[server][dashboard][execute][scope][security]") {
    // The defect: `extract_form_value` returns "" for an absent `scope` AND for
    // a supplied `scope=`, so a crafted or malformed submission that names
    // NOBODY previously fell through to the broadest action the caller was
    // allowed to take. An omitted target still means the fleet; a supplied one
    // resolving to nothing is an error.
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=");
    REQUIRE(res->status == 200); // HTMX fragment, not a status-code surface
    CHECK(h.calls.empty());      // the security property: nothing was dispatched
    CHECK(res->body.find("No target selected") != std::string::npos);
}

TEST_CASE("dashboard execute still broadcasts when scope is OMITTED entirely (CDX-R8-01)",
          "[server][dashboard][execute][scope]") {
    // The other half of the contract, and the reason this cannot simply reject
    // every empty value: an OMITTED targeting argument means the whole fleet.
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    auto res = h.post("/api/dashboard/execute", "instruction=run");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids.empty());
    CHECK(h.calls[0].scope_expr.empty()); // None arm + broadcast_on_none
}

TEST_CASE("dashboard execute FAILS CLOSED when the exec-visible derivation is unwired (CDX-R7-02)",
          "[server][dashboard][execute][scope]") {
    // Genuinely UNWIRED CallerFn: the production handler must hand dispatch
    // a PRESENT EMPTY visible set (deny all), never nullopt (unfiltered).
    FragmentHarness h(/*with_dispatch=*/true, /*wire_exec_visible=*/false);
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-A");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].exec_visible.has_value()); // PRESENT (deny), not nullopt
    CHECK(h.calls[0].exec_visible->empty());       // EMPTY → production sink reaches no one
}

// PLAN-006: the identity sibling of the fail-closed test above — an unwired
// CallerFn must hand dispatch an EMPTY principal too, not merely a deny-all
// exec_visible.
TEST_CASE("dashboard execute hands dispatch an EMPTY principal when the CallerFn is unwired "
          "(PLAN-006)",
          "[server][dashboard][execute][scope]") {
    FragmentHarness h(/*with_dispatch=*/true, /*wire_exec_visible=*/false);
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-A");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].caller.principal.empty());
}

// PLAN-006: the sibling of the confinement handoff test above, asserting the
// IDENTITY half of DispatchCaller — a wired CallerFn's principal must reach
// the dispatch seam, not just its exec_visible.
TEST_CASE("dashboard execute threads the caller's principal into dispatch (PLAN-006)",
          "[server][dashboard][execute][scope]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{.principal = "dash-operator",
                                            .principal_role = "admin"};
    };
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-A");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].caller.principal == "dash-operator");
    CHECK(h.calls[0].caller.principal_role == "admin");
    CHECK_FALSE(h.calls[0].caller.system);
}

TEST_CASE("dashboard execute REFUSES a PERCENT-ENCODED supplied-but-empty scope "
          "(CDX-P1-01)",
          "[server][dashboard][execute][scope][security]") {
    // The defect: the prior refusal checked ONLY the raw-body helper
    // (form_value_supplied), a literal byte-scan for the needle `scope=` that
    // cannot recognize a percent-encoded KEY spelling. httplib DECODES both
    // keys and values when it parses an application/x-www-form-urlencoded
    // body into req.params, so `sc%6fpe=` (percent-encoded `o`) decodes to the
    // key `scope` there even though the raw-body scan never matches it —
    // reopening the exact supplied-vs-omitted collapse CDX-R8-01 closed, just
    // spelled differently. The fix checks req.has_param() FIRST.
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    auto res = h.post("/api/dashboard/execute", "instruction=run&sc%6fpe=");
    REQUIRE(res->status == 200); // HTMX fragment, not a status-code surface
    CHECK(h.calls.empty());      // the security property: nothing was dispatched
    CHECK(res->body.find("No target selected") != std::string::npos);
}

TEST_CASE("dashboard execute REFUSES a BARE supplied-but-empty scope (no '=') "
          "(CDX-P1-01)",
          "[server][dashboard][execute][scope][security]") {
    // A second spelling form_value_supplied's `key + "="` needle also misses:
    // a bare `scope` field with no `=` at all. httplib's form parser still
    // recognizes it as a present key with an empty value.
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope");
    REQUIRE(res->status == 200);
    CHECK(h.calls.empty());
    CHECK(res->body.find("No target selected") != std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// QE-4 / UP-10 — /api/dashboard/tar-execute (the TAR-SQL sibling of
// /api/dashboard/execute above) had NO test at all for the CDX-R8-01
// supplied-but-empty-scope refusal. The last case below is the UP-10 bind:
// the TAR route used req.has_param()/get_param_value() ALONE, which only see
// the query string or a body httplib parsed into req.params — form-encoded
// Content-Type only — so a non-form POST left a body-supplied `scope=`
// invisible to the refusal and it was silently skippable.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("tar-execute REFUSES a supplied-but-empty scope (CDX-R8-01)",
          "[server][dashboard][tar-execute][scope][security]") {
    FragmentHarness h;
    auto res = h.post("/api/dashboard/tar-execute", "sql=SELECT+1&scope=");
    REQUIRE(res->status == 200); // HTMX fragment, not a status-code surface
    CHECK(h.calls.empty());      // the security property: nothing was dispatched
    CHECK(res->body.find("No target selected") != std::string::npos);
}

TEST_CASE("tar-execute still broadcasts when scope is OMITTED entirely (CDX-R8-01)",
          "[server][dashboard][tar-execute][scope]") {
    FragmentHarness h;
    auto res = h.post("/api/dashboard/tar-execute", "sql=SELECT+1");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids.empty());
    CHECK(h.calls[0].scope_expr.empty());
}

TEST_CASE("tar-execute REFUSES a supplied-but-empty scope even under a non-form "
          "Content-Type (UP-10)",
          "[server][dashboard][tar-execute][scope][security]") {
    // `sql` rides the QUERY string — parsed into req.params regardless of
    // Content-Type — purely so the handler's earlier "Missing SQL query" 400
    // doesn't short-circuit before the scope logic under test is reached.
    // `scope=` rides the BODY under a non-form Content-Type: req.has_param()
    // and get_param_value() cannot see it (httplib parses a body into
    // req.params only for application/x-www-form-urlencoded), so this proves
    // the refusal via the raw-body fallback, not the params branch.
    FragmentHarness h;
    auto res = h.sink.dispatch("POST", "/api/dashboard/tar-execute?sql=SELECT+1", "scope=",
                               "text/plain", FragmentHarness::same_site_headers());
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    CHECK(h.calls.empty());
    CHECK(res->body.find("No target selected") != std::string::npos);
}
