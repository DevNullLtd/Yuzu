/**
 * test_dashboard_echo_fragments.cpp — route-handler coverage for the Echo
 * retention-paused DASHBOARD FRAGMENT POSTs (issue #1786):
 *   - POST /fragments/echo/retention-paused/purge   (destructive)
 *   - POST /fragments/echo/retention-paused/reenable
 *
 * Until #1786 these two handlers were registered directly on a raw
 * httplib::Server, so the in-process route harness could not reach them and
 * their security gates were untested — a refactor that dropped one would not
 * fail any test. `DashboardRoutes::register_routes` now has an HttpRouteSink
 * overload (the httplib::Server& overload wraps + delegates to it), so the
 * handlers are drivable here with no acceptor thread (#438 TSan trap).
 *
 * Pinned per handler:
 *   - the permission tier, asked of the per-device scoped gate (#2540, the REST
 *     twin's chokepoint) on the posted device — Infrastructure:Delete for purge,
 *     Execution:Execute for reenable (a tier downgrade must fail here); a denial
 *     collapses to the offline 404, an authorization that could not be evaluated
 *     (the gate's own refusal class: it answered 503, or a read it depends on
 *     failed) answers 503 with a toast, an unwired gate fails closed, and the gate
 *     is asked again after the attempted row; a service-scoped token is refused
 *     403 before the gate,
 *   - the CSRF same-site gate — cross-origin AND header-less POSTs are 403'd
 *     BEFORE dispatch (these fragments are stricter than the shared
 *     `origin_is_same_site` helper, which permits header-less non-browser
 *     clients). For PURGE that strictness is free: a programmatic caller has
 *     the REST twin POST /api/v1/echo/retention-paused/purge. REENABLE HAS NO
 *     REST OR MCP TWIN, so pinning its header-less 403 also pins it as
 *     unreachable by any non-browser principal — a pre-existing gap in a
 *     grandfathered fragment, recorded here so the test is not mistaken for
 *     an endorsement of it,
 *   - the {process,tcp,service,user} source allowlist and the
 *     required-field check → 400, no dispatch,
 *   - the per-device scoped denial → 404 collapsed with the offline
 *     case (no existence oracle) + a `scope_violation` audit recording the
 *     real reason server-side,
 *   - the offline (0 agents reached) path → 404 + `agent_not_connected`,
 *   - the success dispatch shape — echo/purge_source {source} and
 *     echo/configure {<source>_enabled=true}, targeting the one device only.
 *
 * The REST twin (POST /api/v1/echo/retention-paused/purge) is covered by
 * test_rest_echo_purge.cpp; the render-time button gating by
 * test_dashboard_echo_retention.cpp.
 */

#include "agent_registry.hpp" // detail::classify_and_authorize_dispatch (#7114)
#include "dashboard_routes.hpp"
#include "echo_source_action_rules.hpp" // the shared metric vocabulary, refusal mapping, cooldown
#include "management_group_store.hpp"
#include "rest_api_v1.hpp" // the REST purge twin (#2540 parity case)
#include "test_mgmt_group_pg_helper.hpp"
#include "test_real_capability_registry.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kUser = "frag-op";
constexpr const char* kHost = "yuzu.example:8080";
constexpr const char* kPurgePath = "/fragments/echo/retention-paused/purge";
constexpr const char* kReenablePath = "/fragments/echo/retention-paused/reenable";
/// The 404 body for "not yours" and "not connected" alike (#2540: byte-identical).
constexpr const char* kEchoAgentNotReachableBody =
    "<span class=\"echo-row-error\">Agent not reachable.</span>";

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
/// One probe of the per-device scoped gate (#2540).
struct ScopedCall {
    std::string securable_type, op, agent_id;
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
    ra.role_name = "Operator";
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
    yuzu::test::TempDbFile mg_db{"yuzu_test_echo_frag_mg_"};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    std::vector<PermCall> perms;
    std::vector<ScopedCall> scoped_calls;
    /// #3619: "audit:<action>/<result>" and "dispatch", in call order — proves an `attempted`
    /// row precedes the dispatch it covers.
    std::vector<std::string> order;
    /// #3619: whether the audit store persists a given row (read live per row). Default: all do.
    std::function<bool(const AuditRow&)> audit_persists{[](const AuditRow&) { return true; }};
    bool perm_allow{true}; ///< perm_fn verdict (false → handler's 403 path)
    /// #2540: devices the scoped gate admits (read live per probe; clear() == grant withdrawn).
    std::unordered_set<std::string> scoped_allowed{"dev-A", "dev-B"};
    /// What the scoped gate answers for a device it does not admit: the refusal class the real
    /// gate returns (a plain denial, a session that ended, an authorization it could not evaluate,
    /// or a degraded authorization read).
    ScopedGateOutcome scoped_deny_outcome{ScopedGateOutcome::Denied};
    bool auth_ok{true};    ///< auth_fn verdict (false → handler returns early)
    /// Opt-in: when set, a session that ended (`auth_ok` false) also refuses at the two gates the
    /// way production does: perm_fn answers 401, and the scoped gate answers Unauthenticated.
    bool gates_follow_session{false};
    /// Runs inside every dispatch call, before it answers (a grant withdrawn during the dispatch).
    std::function<void()> on_dispatch;
    std::string auth_source{"local"}; ///< resolved session source; "local" = a cookie session
    /// Non-empty models a service-scoped API token (both POSTs refuse it 403 before any gate).
    std::string token_scope_service;
    int dispatch_sent{1};  ///< agents reached per dispatch (0 → offline 404)
    /// #5294: ConfinedDispatchOutcome fields the zero-reach messages key on.
    bool dispatch_os_gate_unreadable{false};
    /// #7114: when set, decides each dispatch the way the chokepoint does; a returned denial makes
    /// the outcome a refusal (`denied` set, nothing sent), exactly what `ServerImpl::
    /// dispatch_confined` returns when `build_classified_command` refuses.
    std::function<std::optional<yuzu::server::detail::DispatchDenial>(
        const std::string&, const std::string&, const yuzu::server::DispatchCaller&)>
        dispatch_decide;
    std::size_t dispatch_kill_switched_os_count{0};

    /// CDX-R7-02 / PLAN-006: the per-request DispatchCaller derivation the
    /// handlers consult for /api/dashboard/execute + echo-execute. Default
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
    /// @param wire_scoped false → leave the #2540 scoped gate unwired (fail closed, 503).
    explicit FragmentHarness(bool with_dispatch = true, bool wire_exec_visible = true,
                             bool wire_scoped = true) {
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
            s.auth_source = auth_source;
            s.token_scope_service = token_scope_service;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            perms.push_back({type, op});
            if (gates_follow_session && !auth_ok) {
                res.status = 401;
                return false;
            }
            if (!perm_allow)
                res.status = 403;
            return perm_allow;
        };
        // ONE recording sink behind both callbacks, as production wires ONE `audit_log` behind
        // `audit_fn` and `set_persist_audit_fn` (server.cpp); each returns the store's verdict.
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& tid, const std::string& d) {
            order.push_back("audit:" + a + "/" + r);
            AuditRow row{a, r, tt, tid, d};
            const bool ok = audit_persists(row);
            audits.push_back(std::move(row));
            return ok;
        };
        routes.set_persist_audit_fn(audit_fn);
        if (wire_scoped) {
            routes.set_scoped_perm_fn([this](const httplib::Request&, httplib::Response& res,
                                             const std::string& type, const std::string& op,
                                             const std::string& agent) -> ScopedGateOutcome {
                scoped_calls.push_back({type, op, agent});
                const auto outcome = gates_follow_session && !auth_ok
                                         ? ScopedGateOutcome::Unauthenticated
                                     : scoped_allowed.count(agent) != 0 ? ScopedGateOutcome::Admitted
                                                                         : scoped_deny_outcome;
                // The status the real gate writes with each class; the routes read the class, not this.
                switch (outcome) {
                    case ScopedGateOutcome::Admitted: break;
                    case ScopedGateOutcome::Unauthenticated: res.status = 401; break;
                    case ScopedGateOutcome::Unavailable: res.status = 503; break;
                    case ScopedGateOutcome::Denied:
                    case ScopedGateOutcome::MgmtGroupReadDegraded:
                    case ScopedGateOutcome::RbacReadDegraded: res.status = 403; break;
                }
                return outcome;
            });
        }
        DashboardRoutes::DispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string& scope,
                   const std::unordered_map<std::string, std::string>& params,
                   const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            order.push_back("dispatch");
            calls.push_back({plugin, action, scope, ids, params, caller.exec_visible, caller});
            if (on_dispatch)
                on_dispatch();
            if (dispatch_decide) {
                if (auto denial = dispatch_decide(plugin, action, caller)) {
                    yuzu::server::ConfinedDispatchOutcome refused;
                    refused.command_id = "cmd-" + std::to_string(calls.size());
                    refused.denied = std::move(denial);
                    return refused;
                }
            }
            return {.sent = dispatch_sent,
                    .command_id = "cmd-" + std::to_string(calls.size()),
                    .kill_switched_os_count = dispatch_kill_switched_os_count,
                    .os_gate_unreadable = dispatch_os_gate_unreadable};
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
        // #4027: +1 for GET /api/v1/echo/retention-paused.
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
    /// Every row of `action`, in write order.
    std::vector<AuditRow> rows_for(const std::string& action) const {
        std::vector<AuditRow> out;
        for (const auto& a : audits)
            if (a.action == action)
                out.push_back(a);
        return out;
    }
    /// The detail of the LAST row matching (action, result); "" if none.
    std::string last_detail(const std::string& action, const std::string& result) const {
        std::string out;
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                out = a.detail;
        return out;
    }
    /// The detail of the first row matching (action, result) without its trailing `cid=` token:
    /// the shape the route wrote before the correlation id was added.
    std::string audit_detail_no_cid(const std::string& action, const std::string& result) const;
    /// One series of a counter family. The two Echo source families carry {result, surface} with
    /// surface=dashboard on this harness; every other family here carries only {result}.
    double metric(const std::string& name, const std::string& result) {
        const bool echo_source_family =
            name == echo_source::kPurgeTotal || name == echo_source::kReenableTotal;
        return metrics
            .counter(name, echo_source_family
                               ? yuzu::Labels{{"result", result}, {"surface", "dashboard"}}
                               : yuzu::Labels{{"result", result}})
            .value();
    }
    /// The label-less `{result}` series of an Echo source family: it stopped moving, so it is 0.
    double metric_without_surface(const std::string& name, const std::string& result) {
        return metrics.counter(name, {{"result", result}}).value();
    }
};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

/// The last space-separated token of an audit detail.
std::string last_token(const std::string& detail) {
    const auto at = detail.rfind(' ');
    return at == std::string::npos ? detail : detail.substr(at + 1);
}
/// The id in a trailing `<key>=<id>` token of an audit detail ("" when the last token is not one).
std::string trailing_id(const std::string& detail, std::string_view key = "cid=") {
    const auto token = last_token(detail);
    return token.rfind(key, 0) == 0 ? token.substr(key.size()) : std::string{};
}
/// The detail without its trailing `<key>=<id>` token.
std::string without_trailing_id(const std::string& detail, std::string_view key = "cid=") {
    const auto token = last_token(detail);
    if (token.rfind(key, 0) != 0)
        return detail;
    return detail.substr(0, detail.size() - token.size() - 1);
}

std::string FragmentHarness::audit_detail_no_cid(const std::string& action,
                                                 const std::string& result) const {
    return without_trailing_id(audit_detail(action, result));
}

} // namespace

// ── Permission tier ─────────────────────────────────────────────────────────

TEST_CASE("fragment purge: the scoped gate is asked for Infrastructure:Delete on the posted device "
          "and a denial collapses to the offline 404 body",
          "[pg][server][echo][purge][fragment][2540]") {
    FragmentHarness h;
    auto allowed = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(allowed->status == 200);
    // Asked once at admission and once more after the attempted row, for the posted device.
    REQUIRE(h.scoped_calls.size() == 2);
    for (const auto& c : h.scoped_calls) {
        CHECK(c.securable_type == "Infrastructure");
        CHECK(c.op == "Delete");
        CHECK(c.agent_id == "dev-A");
    }
    CHECK(h.perms.empty()); // the global gate is no longer consulted
    h.scoped_allowed.clear();
    h.calls.clear();
    auto denied = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(denied->status == 404);
    h.dispatch_sent = 0;
    h.scoped_allowed = {"dev-A"};
    // source=tcp: the first post's dispatch started the repeat window for dev-A / process.
    auto offline = h.post(kPurgePath, "device_id=dev-A&source=tcp");
    CHECK(denied->status == offline->status);
    CHECK(denied->body == offline->body); // no distinguishing marker
    CHECK(h.audit_detail("echo.source.purge", "failure") == "scope_violation source=process");
    CHECK(h.metric("yuzu_echo_source_purge_total", "scope_violation") == 1.0);
}

TEST_CASE("fragment reenable: the scoped gate is asked for Execution:Execute on the posted device "
          "and a denial collapses to the offline 404 body",
          "[pg][server][echo][reenable][fragment][2540]") {
    FragmentHarness h;
    auto allowed = h.post(kReenablePath, "device_id=dev-A&source=process");
    CHECK(allowed->status == 200);
    REQUIRE(h.scoped_calls.size() == 2);
    for (const auto& c : h.scoped_calls) {
        CHECK(c.securable_type == "Execution");
        CHECK(c.op == "Execute");
        CHECK(c.agent_id == "dev-A");
    }
    CHECK(h.perms.empty());
    h.scoped_allowed.clear();
    h.calls.clear();
    auto denied = h.post(kReenablePath, "device_id=dev-A&source=process");
    CHECK(denied->status == 404);
    h.dispatch_sent = 0;
    h.scoped_allowed = {"dev-A"};
    // source=tcp: the first post's dispatch started the repeat window for dev-A / process.
    auto offline = h.post(kReenablePath, "device_id=dev-A&source=tcp");
    CHECK(denied->status == offline->status);
    CHECK(denied->body == offline->body);
    CHECK(h.audit_detail("echo.source.reenable", "failure") == "scope_violation source=process");
    CHECK(h.metric("yuzu_echo_source_reenable_total", "scope_violation") == 1.0);
}

TEST_CASE("fragment purge and reenable: an unwired scoped gate refuses with 503 and dispatches "
          "nothing",
          "[pg][server][echo][purge][reenable][fragment][security][2540]") {
    FragmentHarness h{/*with_dispatch=*/true, /*wire_exec_visible=*/true, /*wire_scoped=*/false};
    for (const auto& [path, action] : {std::pair{kPurgePath, "echo.source.purge"},
                                       std::pair{kReenablePath, "echo.source.reenable"}}) {
        DYNAMIC_SECTION(action) {
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 503);
            CHECK(res->body != kEchoAgentNotReachableBody); // not the 404 collapse
            CHECK(h.audits_for(action, "attempted") == 0);
        }
    }
    CHECK(h.calls.empty());
}

TEST_CASE("fragment purge and reenable: a scoped gate that answers 503 refuses with 503 at "
          "admission and at the recheck",
          "[pg][server][echo][purge][reenable][fragment][audit][security][2540]") {
    // The gate's own refusal class Unavailable is it saying it could not evaluate authority; it
    // must not collapse into the 404 a denial gets, and (htmx does not swap a 5xx body) it rides
    // the toast channel. It counts infra_unavailable, an outage, never a refusal. A degraded
    // authorization READ is a different class (2532 cases below).
    for (const auto& [path, action, family] :
         {std::tuple{kPurgePath, "echo.source.purge", "yuzu_echo_source_purge_total"},
          std::tuple{kReenablePath, "echo.source.reenable", "yuzu_echo_source_reenable_total"}}) {
        DYNAMIC_SECTION(action) {
            const std::string act = action;
            FragmentHarness h;
            h.scoped_allowed.clear();
            h.scoped_deny_outcome = ScopedGateOutcome::Unavailable;
            auto at_admission = h.post(path, "device_id=dev-A&source=process");
            CHECK(at_admission->status == 503);
            CHECK(at_admission->body != kEchoAgentNotReachableBody);
            CHECK_FALSE(at_admission->get_header_value("HX-Trigger").empty()); // the toast
            CHECK(h.audits_for(act, "attempted") == 0);
            CHECK(h.audits_for(act, "failure") == 0); // not a scope violation
            CHECK(h.audit_detail(act, "denied") == "scoped_gate_unavailable source=process");
            CHECK(h.metric(family, "infra_unavailable") == 1.0);
            CHECK(h.metric(family, "denied") == 0.0);

            // Admitted, then unavailable once the attempted row is stored.
            h.scoped_allowed = {"dev-A"};
            h.scoped_deny_outcome = ScopedGateOutcome::Denied;
            h.scoped_calls.clear();
            h.audit_persists = [&h, act](const AuditRow& r) {
                if (r.action == act && r.result == "attempted") {
                    h.scoped_allowed.clear();
                    h.scoped_deny_outcome = ScopedGateOutcome::Unavailable;
                }
                return true;
            };
            auto at_recheck = h.post(path, "device_id=dev-A&source=process");
            CHECK(at_recheck->status == 503);
            CHECK(at_recheck->body != kEchoAgentNotReachableBody);
            CHECK_FALSE(at_recheck->get_header_value("HX-Trigger").empty()); // the toast
            REQUIRE(h.scoped_calls.size() == 2);
            CHECK(h.audits_for(act, "attempted") == 1);
            const auto failure = h.audit_detail(act, "failure");
            CHECK(without_trailing_id(failure) ==
                  "scoped_gate_unavailable device=dev-A source=process");
            CHECK(trailing_id(failure) == trailing_id(h.audit_detail(act, "attempted")));
            CHECK(h.audits_for(act, "success") == 0);
            CHECK(h.metric(family, "infra_unavailable") == 2.0);
            CHECK(h.calls.empty());
        }
    }
}

TEST_CASE("fragment purge and reenable: a service-scoped token is refused 403 before the scoped "
          "gate and dispatches nothing",
          "[pg][server][echo][purge][reenable][fragment][security][2540]") {
    // The global gate these routes asked before #2540 refused every service-scoped token. The
    // scoped gate's service branch would admit a confined one, so the handlers refuse it first.
    for (const auto& [path, action, family] :
         {std::tuple{kPurgePath, "echo.source.purge", "yuzu_echo_source_purge_total"},
          std::tuple{kReenablePath, "echo.source.reenable", "yuzu_echo_source_reenable_total"}}) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            h.token_scope_service = "svc-example";
            auto res = h.post(path, "device_id=dev-A&source=process"); // a device the gate admits
            CHECK(res->status == 403);
            CHECK(contains(res->body, "Permission denied"));
            // The same answer whatever the device: the refusal is no existence oracle.
            auto other = h.post(path, "device_id=dev-OTHER&source=process");
            CHECK(other->status == res->status);
            CHECK(other->body == res->body);
            CHECK(h.scoped_calls.empty());
            CHECK(h.perms.empty());
            CHECK(h.calls.empty());
            CHECK(h.audits_for(action, "attempted") == 0);
            CHECK(h.audit_detail(action, "denied") == "service_scoped_token_denied");
            CHECK(h.metric(family, "denied") == 2.0);
        }
    }
}

TEST_CASE("fragment purge and reenable: the scoped gate admits a device outside the caller's "
          "group membership",
          "[pg][server][echo][purge][reenable][fragment][2540]") {
    // dev-OTHER is in no group kUser holds a role on (grant_visibility covers dev-A and dev-B), so
    // the get_visible_agents loop these handlers used to run refused it. The scoped gate is the
    // SOLE gate: when it admits (a global grant holder), the dispatch goes out. Reintroducing the
    // membership loop fails here.
    FragmentHarness h;
    h.scoped_allowed.insert("dev-OTHER");
    CHECK(h.post(kPurgePath, "device_id=dev-OTHER&source=process")->status == 200);
    CHECK(h.post(kReenablePath, "device_id=dev-OTHER&source=process")->status == 200);
    REQUIRE(h.calls.size() == 2);
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"dev-OTHER"});
    CHECK(h.calls[1].agent_ids == std::vector<std::string>{"dev-OTHER"});
}

TEST_CASE("fragment purge: a grant withdrawn after the attempted row dispatches nothing and audits "
          "permission_revoked",
          "[pg][server][echo][purge][fragment][audit][security][2540]") {
    FragmentHarness h;
    h.audit_persists = [&h](const AuditRow& r) {
        if (r.action == "echo.source.purge" && r.result == "attempted")
            h.scoped_allowed.clear(); // revoked mid-write
        return true;
    };
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 404);
    CHECK(res->body == kEchoAgentNotReachableBody);
    CHECK(h.calls.empty());
    REQUIRE(h.scoped_calls.size() == 2); // admission, then the recheck of the SAME pair
    CHECK(h.scoped_calls[1].securable_type == "Infrastructure");
    CHECK(h.scoped_calls[1].op == "Delete");
    CHECK(h.scoped_calls[1].agent_id == "dev-A");
    CHECK(h.audits_for("echo.source.purge", "attempted") == 1);
    CHECK(h.audit_detail_no_cid("echo.source.purge", "failure") ==
          "permission_revoked device=dev-A source=process");
    CHECK(h.audits_for("echo.source.purge", "success") == 0);
    CHECK(h.metric("yuzu_echo_source_purge_total", "denied") == 1.0);
}

TEST_CASE("fragment reenable: a grant withdrawn after the attempted row dispatches nothing and "
          "audits permission_revoked",
          "[pg][server][echo][reenable][fragment][audit][security][2540]") {
    FragmentHarness h;
    h.audit_persists = [&h](const AuditRow& r) {
        if (r.action == "echo.source.reenable" && r.result == "attempted")
            h.scoped_allowed.clear(); // revoked mid-write
        return true;
    };
    auto res = h.post(kReenablePath, "device_id=dev-A&source=process");
    CHECK(res->status == 404);
    CHECK(res->body == kEchoAgentNotReachableBody);
    CHECK(h.calls.empty());
    REQUIRE(h.scoped_calls.size() == 2);
    CHECK(h.scoped_calls[1].securable_type == "Execution");
    CHECK(h.scoped_calls[1].op == "Execute");
    CHECK(h.scoped_calls[1].agent_id == "dev-A");
    CHECK(h.audits_for("echo.source.reenable", "attempted") == 1);
    CHECK(h.audit_detail_no_cid("echo.source.reenable", "failure") ==
          "permission_revoked device=dev-A source=process");
    CHECK(h.audits_for("echo.source.reenable", "success") == 0);
    CHECK(h.metric("yuzu_echo_source_reenable_total", "denied") == 1.0);
}

TEST_CASE("fragment and REST purge: a confined operator is denied for the same out-of-scope device "
          "on both surfaces",
          "[pg][server][echo][purge][fragment][security][2540]") {
    // ONE scope policy behind both chokepoints, as server.cpp wires ONE scoped_perm_fn into both.
    const std::unordered_set<std::string> confined{"dev-A"};

    FragmentHarness h;
    h.scoped_allowed = confined;

    yuzu::MetricsRegistry rest_metrics;
    RestApiV1 api;
    std::vector<std::string> rest_dispatched;
    auto rest_auth = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session sess;
        sess.username = kUser;
        sess.role = auth::Role::admin;
        return sess;
    };
    auto rest_perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                        const std::string&) { return true; };
    auto rest_audit = [](const httplib::Request&, const std::string&, const std::string&,
                         const std::string&, const std::string&, const std::string&) { return true; };
    RestApiV1::ScopedPermFn rest_scoped = [&confined](const httplib::Request&, httplib::Response& res,
                                                      const std::string&, const std::string&,
                                                      const std::string& agent) -> bool {
        if (confined.count(agent) != 0)
            return true;
        res.status = 403;
        return false;
    };
    // The purge route authorizes through the typed gate: the SAME policy as the fragment's.
    api.set_scoped_gate_fn([&confined](const httplib::Request&, httplib::Response& res,
                                       const std::string&, const std::string&,
                                       const std::string& agent) -> ScopedGateOutcome {
        if (confined.count(agent) != 0)
            return ScopedGateOutcome::Admitted;
        res.status = 403;
        return ScopedGateOutcome::Denied;
    });
    RestApiV1::CommandDispatchFn rest_dispatch =
        [&rest_dispatched](const std::string&, const std::string&, const std::vector<std::string>& ids,
                           const std::string&,
                           const std::unordered_map<std::string, std::string>&, const std::string&,
                           const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
        rest_dispatched.insert(rest_dispatched.end(), ids.begin(), ids.end());
        return {.sent = 1, .command_id = "cmd-rest"};
    };
    yuzu::server::test::TestRouteSink rest_sink; // declared after `api`: destroyed first
    api.register_routes(
        rest_sink, rest_auth, rest_perm, rest_audit,
        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
        /*quarantine_store=*/nullptr, /*response_store=*/nullptr, /*instruction_store=*/nullptr,
        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
        /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
        /*tag_push_fn=*/{}, /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
        /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr, /*license_store=*/nullptr,
        /*guaranteed_state_store=*/nullptr, &rest_metrics, /*session_revoke_fn=*/{},
        /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr, rest_dispatch,
        /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{}, /*network_api=*/{},
        /*lockout_clear_fn=*/{}, /*baseline_store=*/nullptr, rest_scoped,
        /*software_inventory_store=*/nullptr,
        /*response_scope_fn=*/{},
        /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
        /*auth_db=*/nullptr, /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
        RestApiV1::ExecVisibleFn{[](const auth::Session&) -> yuzu::server::authz::VisibleSet {
            return yuzu::server::authz::VisibleSet{};
        }});

    const auto rest_post = [&](const std::string& device) {
        auto res = rest_sink.dispatch(
            "POST", "/api/v1/echo/retention-paused/purge",
            "{\"device_id\":\"" + device + "\",\"source\":\"process\"}");
        REQUIRE(res != nullptr);
        return res->status;
    };

    // dev-B is a real, connected device the operator holds in the fixture's visibility group, but
    // the shared scoped policy excludes it: BOTH surfaces refuse and dispatch nothing for it.
    CHECK(rest_post("dev-B") == 403);
    CHECK(h.post(kPurgePath, "device_id=dev-B&source=process")->status == 404);
    CHECK(rest_dispatched.empty());
    CHECK(h.calls.empty());
    // ...and both admit the device the policy admits.
    CHECK(rest_post("dev-A") == 202); // REST: accepted, poll the command
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=process")->status == 200);
    CHECK(rest_dispatched == std::vector<std::string>{"dev-A"});
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"dev-A"});
}

// ── CSRF same-site gate ─────────────────────────────────────────────────────

TEST_CASE("fragment purge: cross-origin and header-less POSTs are refused before dispatch",
          "[pg][server][echo][purge][fragment][csrf]") {
    SECTION("cross-origin Origin") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(contains(res->body, "Cross-origin request refused"));
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("echo.source.purge", "denied") == "csrf_cross_origin");
        CHECK(h.metric("yuzu_echo_source_purge_total", "denied") == 1.0);
        CHECK(h.scoped_calls.empty()); // refused before the scoped gate is asked
    }
    SECTION("cross-origin Referer (no Origin)") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Referer", "https://evil.example/echo"}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
    }
    SECTION("neither Origin nor Referer — stricter than origin_is_same_site's default") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process", {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("echo.source.purge", "denied") == "csrf_cross_origin");
    }
    SECTION("same-site Referer is accepted") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Referer", std::string{"https://"} + kHost + "/echo"}});
        CHECK(res->status == 200);
        CHECK(h.calls.size() == 1);
    }
}

TEST_CASE("fragment reenable: cross-origin and header-less POSTs are refused before dispatch",
          "[pg][server][echo][reenable][fragment][csrf]") {
    SECTION("cross-origin") {
        FragmentHarness h;
        auto res = h.post(kReenablePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("echo.source.reenable", "denied") == "csrf_cross_origin");
        CHECK(h.metric("yuzu_echo_source_reenable_total", "denied") == 1.0);
        CHECK(h.scoped_calls.empty()); // refused before the scoped gate is asked
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
          "[pg][server][echo][purge][fragment]") {
    FragmentHarness h;
    CHECK(h.post(kPurgePath, "source=process")->status == 400);          // no device_id
    CHECK(h.post(kPurgePath, "device_id=dev-A")->status == 400);         // no source
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=")->status == 400); // empty source
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=evil")->status == 400);
    // A real Echo source deliberately outside the four-source frame scope.
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=software")->status == 400);
    CHECK(h.calls.empty());
    CHECK(h.scoped_calls.empty()); // validation precedes the scoped gate (no gate audit row)
    CHECK(h.metric("yuzu_echo_source_purge_total", "invalid_input") == 5.0);
}

TEST_CASE("fragment reenable: missing fields and forged sources are rejected 400, no dispatch",
          "[pg][server][echo][reenable][fragment]") {
    FragmentHarness h;
    CHECK(h.post(kReenablePath, "source=process")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=")->status == 400); // empty source
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=evil")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=software")->status == 400);
    CHECK(h.calls.empty());
    CHECK(h.scoped_calls.empty()); // validation precedes the scoped gate (no gate audit row)
    CHECK(h.metric("yuzu_echo_source_reenable_total", "invalid_input") == 5.0);
}

TEST_CASE("fragment reenable: every allowlisted source dispatches",
          "[pg][server][echo][reenable][fragment]") {
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
    CHECK(h.metric("yuzu_echo_source_reenable_total", "success") == 4.0);
}

TEST_CASE("fragment purge: every allowlisted source dispatches", "[pg][server][echo][purge][fragment]") {
    FragmentHarness h;
    for (const char* src : {"process", "tcp", "service", "user"})
        CHECK(h.post(kPurgePath, std::string{"device_id=dev-A&source="} + src)->status == 200);
    CHECK(h.calls.size() == 4);
    CHECK(h.metric("yuzu_echo_source_purge_total", "success") == 4.0);
}

// ── RBAC device scope ───────────────────────────────────────────────────────

TEST_CASE("fragment purge: out-of-scope device 404s (no existence oracle) and audits the reason",
          "[pg][server][echo][purge][fragment]") {
    FragmentHarness h;
    auto res = h.post(kPurgePath, "device_id=dev-OTHER&source=process");
    CHECK(res->status == 404);
    // Same body as the offline case — the response must not distinguish
    // "not yours" from "not connected".
    CHECK(contains(res->body, "Agent not reachable"));
    CHECK(h.calls.empty());
    CHECK(h.audit_detail("echo.source.purge", "failure") == "scope_violation source=process");
    CHECK(h.metric("yuzu_echo_source_purge_total", "scope_violation") == 1.0);
}

TEST_CASE("fragment reenable: out-of-scope device 404s and audits the reason",
          "[pg][server][echo][reenable][fragment]") {
    FragmentHarness h;
    auto res = h.post(kReenablePath, "device_id=dev-OTHER&source=tcp");
    CHECK(res->status == 404);
    CHECK(contains(res->body, "Agent not reachable"));
    CHECK(h.calls.empty());
    CHECK(h.audit_detail("echo.source.reenable", "failure") == "scope_violation source=tcp");
    CHECK(h.metric("yuzu_echo_source_reenable_total", "scope_violation") == 1.0);
}

// ── Offline / unavailable ───────────────────────────────────────────────────

TEST_CASE("fragment purge: offline agent (0 reached) → 404 + agent_not_connected",
          "[pg][server][echo][purge][fragment]") {
    FragmentHarness h;
    h.dispatch_sent = 0;
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 404);
    CHECK(contains(res->body, "Agent not reachable"));
    REQUIRE(h.calls.size() == 1); // dispatch was attempted, reached nobody
    CHECK(h.audit_detail_no_cid("echo.source.purge", "failure") ==
          "agent_not_connected source=process");
    CHECK(h.metric("yuzu_echo_source_purge_total", "agent_not_connected") == 1.0);
}

TEST_CASE("fragment reenable: offline agent (0 reached) → 404 + agent_not_connected",
          "[pg][server][echo][reenable][fragment]") {
    FragmentHarness h;
    h.dispatch_sent = 0;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=user");
    CHECK(res->status == 404);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.audit_detail_no_cid("echo.source.reenable", "failure") ==
          "agent_not_connected source=user");
    CHECK(h.metric("yuzu_echo_source_reenable_total", "agent_not_connected") == 1.0);
}

TEST_CASE("fragment purge: the out-of-scope and offline 404s are byte-identical",
          "[pg][server][echo][purge][fragment]") {
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
    CHECK(h.audits_for("echo.source.purge", "failure") == 2);
    CHECK(contains(h.audit_detail("echo.source.purge", "failure"), "scope_violation"));
}

TEST_CASE("fragment purge/reenable: no dispatch wiring → 503",
          "[pg][server][echo][purge][fragment]") {
    // No `calls.empty()` assertion here: with an empty DispatchFn nothing can
    // ever be recorded, so it would be a tautology rather than evidence.
    FragmentHarness h{/*with_dispatch=*/false};
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=process")->status == 503);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=process")->status == 503);
    CHECK(h.scoped_calls.empty()); // dispatch wiring is checked before the scoped gate
    // An outage, counted as one: neither a refusal nor an RBAC denial.
    CHECK(h.metric("yuzu_echo_source_purge_total", "infra_unavailable") == 1.0);
    CHECK(h.metric("yuzu_echo_source_reenable_total", "infra_unavailable") == 1.0);
}

TEST_CASE("fragment purge/reenable: an unauthenticated session stops before dispatch",
          "[pg][server][echo][purge][fragment]") {
    FragmentHarness h;
    h.auth_ok = false;
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=process")->status == 401);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=process")->status == 401);
    CHECK(h.calls.empty());
    CHECK(h.scoped_calls.empty());
}

// ── Success shape ───────────────────────────────────────────────────────────

TEST_CASE("fragment purge: success dispatches echo/purge_source to the one device",
          "[pg][server][echo][purge][fragment]") {
    FragmentHarness h;
    auto res = h.post(kPurgePath, "device_id=dev-B&source=tcp");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "echo");
    CHECK(h.calls[0].action == "purge_source");
    CHECK(h.calls[0].scope_expr.empty()); // targeted, never a scope fan-out
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-B");
    REQUIRE(h.calls[0].params.count("source") == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
    CHECK(h.audit_detail_no_cid("echo.source.purge", "success") == "device=dev-B source=tcp");
    CHECK(h.metric("yuzu_echo_source_purge_total", "success") == 1.0);
    // Purge leaves the source PAUSED, so the row stays and is annotated.
    CHECK(contains(res->body, "Purge dispatched"));
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("fragment reenable: success dispatches echo/configure with <source>_enabled=true",
          "[pg][server][echo][reenable][fragment]") {
    FragmentHarness h;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=service");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "echo");
    CHECK(h.calls[0].action == "configure");
    CHECK(h.calls[0].scope_expr.empty());
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    // Per-source independence (#539): ONLY the named source's key is set.
    REQUIRE(h.calls[0].params.size() == 1);
    REQUIRE(h.calls[0].params.count("service_enabled") == 1);
    CHECK(h.calls[0].params.at("service_enabled") == "true");
    CHECK(h.audit_detail_no_cid("echo.source.reenable", "success") ==
          "device=dev-A source=service");
    CHECK(h.metric("yuzu_echo_source_reenable_total", "success") == 1.0);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("fragment purge: query-string params are honoured like form-body params",
          "[pg][server][echo][purge][fragment]") {
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
          "[pg][server][echo][purge][fragment]") {
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
          "[pg][server][echo][purge][fragment]") {
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
          "[pg][server][echo][purge][fragment]") {
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

// #5294: a zero-reach caused by the per-OS kill switch must not be reported as
// "No agents connected" -- the operator would chase connectivity, not policy.
TEST_CASE("dashboard execute: a per-OS kill-switch zero-reach names the switch, not connectivity",
          "[server][dashboard][execute][5294]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    h.dispatch_kill_switched_os_count = 2;
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-A");
    REQUIRE(res->status == 200);
    CHECK(contains(res->body, "switched off"));
    CHECK_FALSE(contains(res->body, "No agents connected"));
}

TEST_CASE("dashboard execute: an unreadable-presence zero-reach fails closed with its own message",
          "[server][dashboard][execute][5294]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0;
    h.dispatch_os_gate_unreadable = true;
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-A");
    REQUIRE(res->status == 200);
    CHECK(contains(res->body, "presence could not be read"));
    CHECK_FALSE(contains(res->body, "No agents connected"));
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
          "[pg][server][dashboard][execute][scope]") {
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
          "[pg][server][dashboard][execute][scope]") {
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
// QE-4 / UP-10 — /api/dashboard/echo-execute (the Echo-SQL sibling of
// /api/dashboard/execute above) had NO test at all for the CDX-R8-01
// supplied-but-empty-scope refusal. The last case below is the UP-10 bind:
// the Echo route used req.has_param()/get_param_value() ALONE, which only see
// the query string or a body httplib parsed into req.params — form-encoded
// Content-Type only — so a non-form POST left a body-supplied `scope=`
// invisible to the refusal and it was silently skippable.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("echo-execute REFUSES a supplied-but-empty scope (CDX-R8-01)",
          "[pg][server][dashboard][echo-execute][scope][security]") {
    FragmentHarness h;
    auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1&scope=");
    REQUIRE(res->status == 200); // HTMX fragment, not a status-code surface
    CHECK(h.calls.empty());      // the security property: nothing was dispatched
    CHECK(res->body.find("No target selected") != std::string::npos);
}

// Same-site gate (browser_write_is_cross_site) on the "Run on Echo history" form post.
TEST_CASE("echo-execute: a cookie-session write without a same-site Origin is refused",
          "[pg][server][dashboard][echo-execute][csrf][security]") {
    FragmentHarness h;
    SECTION("no Origin and no Referer") {
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1", {{"Host", kHost}});
        CHECK(res->status == 403);
    }
    SECTION("a foreign Origin") {
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
    }
    CHECK(h.calls.empty());
    CHECK(h.audits_for("csrf.denied", "denied") == 1);
}

TEST_CASE("echo-execute: a token session is not gated by Origin",
          "[pg][server][dashboard][echo-execute][csrf]") {
    FragmentHarness h;
    h.auth_source = "mcp_token";
    auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1", {{"Host", kHost}});
    CHECK(res->status == 200);
    CHECK(h.calls.size() == 1);
    CHECK(h.audits_for("csrf.denied", "denied") == 0);
}

TEST_CASE("echo-execute still broadcasts when scope is OMITTED entirely (CDX-R8-01)",
          "[pg][server][dashboard][echo-execute][scope]") {
    FragmentHarness h;
    auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1");
    REQUIRE(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids.empty());
    CHECK(h.calls[0].scope_expr.empty());
}

TEST_CASE("echo-execute REFUSES a supplied-but-empty scope even under a non-form "
          "Content-Type (UP-10)",
          "[pg][server][dashboard][echo-execute][scope][security]") {
    // `sql` rides the QUERY string — parsed into req.params regardless of
    // Content-Type — purely so the handler's earlier "Missing SQL query" 400
    // doesn't short-circuit before the scope logic under test is reached.
    // `scope=` rides the BODY under a non-form Content-Type: req.has_param()
    // and get_param_value() cannot see it (httplib parses a body into
    // req.params only for application/x-www-form-urlencoded), so this proves
    // the refusal via the raw-body fallback, not the params branch.
    FragmentHarness h;
    auto res = h.sink.dispatch("POST", "/api/dashboard/echo-execute?sql=SELECT+1", "scope=",
                               "text/plain", FragmentHarness::same_site_headers());
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    CHECK(h.calls.empty());
    CHECK(res->body.find("No target selected") != std::string::npos);
}

// The Echo page shell is a raw-string constant in its own TU, at global scope.
extern const char* const kEchoPageHtml;

TEST_CASE("echo page shell: capture-sources frame and hourly process record text",
          "[server][echo][shell]") {
    const std::string page = kEchoPageHtml;
    CHECK(page.find("id=\"frame-capture-sources\"") != std::string::npos);
    CHECK(page.find("id=\"capture-sources\"") != std::string::npos);
    CHECK(page.find("Built from the hourly process record") != std::string::npos);
    CHECK(page.find("Reconstructed from") == std::string::npos);
    CHECK(page.find("#capCards .card.pending") != std::string::npos);
    CHECK(page.find("cb.closest('.card')") != std::string::npos);
    CHECK(page.find("capTable") == std::string::npos);
    CHECK(page.find("echoTreeState") == std::string::npos);
    CHECK(page.find("badge-pii") == std::string::npos);
    // #7075: the push's toast is server-authored (HX-Trigger on every answer, a refusal
    // included); the push function must raise no toast itself, whatever its wording.
    const auto push_fn = page.find("function pushCapChanges");
    REQUIRE(push_fn != std::string::npos);
    const auto push_end = page.find("function filterCap", push_fn);
    REQUIRE(push_end != std::string::npos);
    CHECK(page.substr(push_fn, push_end - push_fn).find("showToast") == std::string::npos);
}

// ── (#1162) Every echo.sql pre-dispatch rejection leaves a `denied` audit row ──
//
// The detail is a fixed reason token plus, where useful, a byte count or a matched blocklist
// entry: never the SQL text or any other caller string. Response bodies and statuses are unchanged.

TEST_CASE("echo-execute: each pre-dispatch SQL rejection writes one echo.sql denied row",
          "[pg][server][dashboard][echo-execute][audit]") {
    FragmentHarness h;

    SECTION("no sql") {
        auto res = h.post("/api/dashboard/echo-execute", "scope=__all__");
        REQUIRE(res->status == 200);
        CHECK(res->body.find("Missing SQL query") != std::string::npos);
        CHECK(h.audit_detail("echo.sql", "denied") == "reason=sql_missing");
    }
    SECTION("sql over 4096 bytes: the byte count is audited, the text is not") {
        const std::string filler(4100, 'q');
        const std::size_t decoded_bytes = std::string("SELECT ").size() + filler.size();
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+" + filler);
        REQUIRE(res->status == 200);
        CHECK(res->body.find("exceeds 4KB") != std::string::npos);
        const auto detail = h.audit_detail("echo.sql", "denied");
        CHECK(detail == "reason=sql_too_large sql_bytes=" + std::to_string(decoded_bytes));
        CHECK(detail.find("qqqq") == std::string::npos);
    }
    SECTION("not a SELECT") {
        auto res = h.post("/api/dashboard/echo-execute", "sql=UPDATE+echo_config+SET+x%3D1");
        REQUIRE(res->status == 200);
        CHECK(res->body.find("Only SELECT") != std::string::npos);
        CHECK(h.audit_detail("echo.sql", "denied") == "reason=not_select");
    }
    SECTION("a SELECT with a blocked keyword names the entry that matched") {
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+drop+FROM+t");
        REQUIRE(res->status == 200);
        CHECK(res->body.find("forbidden keyword") != std::string::npos);
        CHECK(h.audit_detail("echo.sql", "denied") == "reason=forbidden_keyword keyword=DROP");
    }
    SECTION("a supplied-but-empty scope") {
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1&scope=");
        REQUIRE(res->status == 200);
        CHECK(res->body.find("No target selected") != std::string::npos);
        CHECK(h.audit_detail("echo.sql", "denied") == "reason=no_target");
    }
    CHECK(h.audits_for("echo.sql", "denied") == 1);
    CHECK(h.calls.empty()); // nothing dispatched on any refusal
    CHECK(h.audits_for("echo.sql", "success") == 0);
}

TEST_CASE("echo-execute: a denied row the store does not persist keeps the refusal and flags it",
          "[pg][server][dashboard][echo-execute][audit]") {
    FragmentHarness h;
    h.audit_persists = [](const AuditRow&) { return false; };
    auto res = h.post("/api/dashboard/echo-execute", "sql=DELETE+FROM+t");
    REQUIRE(res->status == 200);
    CHECK(res->body.find("Only SELECT") != std::string::npos); // same refusal body
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.calls.empty());
}

TEST_CASE("echo-execute: an accepted query writes its success row and no denied row; gate refusals write none",
          "[pg][server][dashboard][echo-execute][audit]") {
    SECTION("accepted") {
        FragmentHarness h;
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1");
        REQUIRE(res->status == 200);
        CHECK(h.audits_for("echo.sql", "success") == 1);
        CHECK(h.audits_for("echo.sql", "denied") == 0);
    }
    SECTION("permission gate") {
        FragmentHarness h;
        h.perm_allow = false;
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1");
        CHECK(res->status == 403);
        CHECK(h.audits_for("echo.sql", "denied") == 0);
    }
    SECTION("cross-site write") {
        FragmentHarness h;
        auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1", {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.audits_for("echo.sql", "denied") == 0);
    }
}

// ── (#3619) Audit-failure posture (ADR-0033 §9: no audit row, no mutation) ──
//
// Re-enable and purge change a device's capture state (purge is Destructive), so each writes an
// `attempted` row BEFORE the dispatch and refuses with nothing sent when that row is not
// persisted. Their outcome and refusal rows, and the read-class Echo SQL send, proceed and mark
// the response `Sec-Audit-Failed: true` instead.

namespace {
/// The two Echo mutations, each with its fragment path and audit verb.
constexpr std::pair<const char*, const char*> kEchoMutations[] = {
    {kPurgePath, "echo.source.purge"}, {kReenablePath, "echo.source.reenable"}};

std::function<bool(const AuditRow&)> fail_only(std::string action, std::string result) {
    return [action = std::move(action), result = std::move(result)](const AuditRow& r) {
        return !(r.action == action && r.result == result);
    };
}
} // namespace

TEST_CASE("fragment purge/reenable audit: the attempted row is stored BEFORE the dispatch",
          "[pg][server][echo][purge][reenable][fragment][audit][3619]") {
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 200);
            const std::vector<std::string> expected{std::string("audit:") + action + "/attempted",
                                                    "dispatch",
                                                    std::string("audit:") + action + "/success"};
            CHECK(h.order == expected);
            CHECK(contains(h.audit_detail(action, "attempted"), "source=process"));
            CHECK(contains(h.audit_detail(action, "attempted"), "device=dev-A"));
            CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
        }
    }
}

TEST_CASE("fragment purge/reenable audit: an attempted row the store does not persist sends "
          "NOTHING",
          "[pg][server][echo][purge][reenable][fragment][audit][security][3619]") {
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            h.audit_persists = fail_only(action, "attempted");
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 503);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(contains(res->body, "audit_unavailable"));
            CHECK(h.calls.empty()); // the security property
            CHECK(h.audits_for(action, "success") == 0);
        }
    }
}

TEST_CASE("fragment purge/reenable audit: a refused request writes no attempted row",
          "[pg][server][echo][purge][reenable][fragment][audit][3619]") {
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            CHECK(h.post(path, "device_id=dev-A&source=not-a-source")->status == 400);
            CHECK(h.post(path, "device_id=dev-Z&source=process")->status == 404); // out of scope
            h.scoped_allowed.clear();
            CHECK(h.post(path, "device_id=dev-A&source=process")->status == 404);
            CHECK(h.audits_for(action, "attempted") == 0);
            CHECK(h.calls.empty());
        }
    }
}

TEST_CASE("fragment purge/reenable audit: a success row that is not persisted keeps the 200 and "
          "is flagged on the response",
          "[pg][server][echo][purge][reenable][fragment][audit][3619]") {
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            h.audit_persists = fail_only(action, "success");
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 200);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(h.calls.size() == 1);
            CHECK(h.audits_for(action, "attempted") == 1);
        }
    }
}

TEST_CASE("fragment purge/reenable audit: refusal rows that are not persisted keep the refusal "
          "and are flagged on the response",
          "[pg][server][echo][purge][reenable][fragment][audit][3619]") {
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            h.audit_persists = [](const AuditRow&) { return false; };
            h.scoped_allowed.clear();
            auto denied = h.post(path, "device_id=dev-A&source=process");
            CHECK(denied->status == 404);
            CHECK(denied->get_header_value("Sec-Audit-Failed") == "true");

            h.scoped_allowed = {"dev-A", "dev-B"};
            auto out_of_scope = h.post(path, "device_id=dev-Z&source=process");
            CHECK(out_of_scope->status == 404);
            CHECK(out_of_scope->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(h.calls.empty());
        }
    }
}

TEST_CASE("echo-execute audit: a success row that is not persisted keeps the 200 and is flagged",
          "[pg][server][dashboard][echo-execute][audit][3619]") {
    FragmentHarness h;
    h.audit_persists = fail_only("echo.sql", "success");
    auto res = h.post("/api/dashboard/echo-execute", "sql=SELECT+1");
    CHECK(res->status == 200);
    CHECK(h.calls.size() == 1);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

namespace {
/// The Echo fragments' audit refusal, verbatim (body span text and toast message).
constexpr const char* kEchoAuditRefusalText =
    "The audit record could not be stored, so nothing was sent. Retry once the audit store "
    "recovers.";
} // namespace

TEST_CASE("fragment purge/reenable audit: a refusal is visible and counted, and the body is exact",
          "[pg][server][echo][purge][reenable][fragment][audit][3619]") {
    // arch-4 / sre-1: htmx does not swap a 5xx body on the Echo page, so the refusal also rides
    // the page's toast channel, and the exit is counted under its own bounded result value.
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action) {
            FragmentHarness h;
            h.audit_persists = fail_only(action, "attempted");
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 503);
            CHECK(res->body == std::string("<span class=\"echo-row-error\" "
                                           "data-reason=\"audit_unavailable\">") +
                                   kEchoAuditRefusalText + "</span>");
            // Guarded parse: a regression that drops `showToast` fails a CHECK, never aborts.
            const auto trigger = nlohmann::json::parse(res->get_header_value("HX-Trigger"),
                                                       nullptr, /*allow_exceptions=*/false);
            REQUIRE_FALSE(trigger.is_discarded());
            REQUIRE(trigger.is_object());
            REQUIRE(trigger.contains("showToast"));
            REQUIRE(trigger["showToast"].is_object());
            CHECK(trigger["showToast"].value("message", std::string{}) == kEchoAuditRefusalText);
            CHECK(trigger["showToast"].value("level", std::string{}) == "error");
            const std::string metric = std::string(action) == "echo.source.purge"
                                           ? "yuzu_echo_source_purge_total"
                                           : "yuzu_echo_source_reenable_total";
            CHECK(h.metric(metric, "audit_unavailable") == 1.0);
            CHECK(h.metric(metric, "denied") == 0.0); // not an RBAC refusal
        }
    }
}

TEST_CASE("fragment purge audit: a flapping audit store dispatches exactly once per stored "
          "attempted row",
          "[pg][server][echo][purge][fragment][audit][security][3619]") {
    // CH-3: four clicks against a store that refuses every other attempted row.
    // Declared before the harness so it outlives the predicate that captures it.
    int attempted_calls = 0;
    FragmentHarness h;
    h.audit_persists = [&attempted_calls](const AuditRow& r) {
        if (r.action == "echo.source.purge" && r.result == "attempted")
            return (++attempted_calls % 2) == 0; // fail, ok, fail, ok
        return true;
    };
    int refused = 0;
    // Four different sources: a dispatched one starts its own 30 s window, and a repeat of the same
    // pair would answer 429 before it ever reached the audit store.
    const char* const sources[] = {"process", "tcp", "service", "user"};
    for (const char* src : sources) {
        auto res = h.post(kPurgePath, std::string{"device_id=dev-A&source="} + src);
        if (res->status == 503) {
            ++refused;
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        } else {
            CHECK(res->status == 200);
            CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
        }
    }
    CHECK(refused == 2);
    CHECK(h.calls.size() == 2);
    CHECK(h.audits_for("echo.source.purge", "success") == 2);
    CHECK(h.metric("yuzu_echo_source_purge_total", "audit_unavailable") == 2.0);
}

TEST_CASE("fragment purge/reenable audit: an unwired or throwing persist sink refuses, never "
          "dispatches",
          "[pg][server][echo][purge][reenable][fragment][audit][security][3619]") {
    // CH-4.
    for (const auto& [path, action] : kEchoMutations) {
        DYNAMIC_SECTION(action << " unwired") {
            FragmentHarness h;
            h.routes.set_persist_audit_fn({});
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 503);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(h.calls.empty());
        }
        DYNAMIC_SECTION(action << " throwing") {
            FragmentHarness h;
            h.routes.set_persist_audit_fn(
                [](const httplib::Request&, const std::string&, const std::string&,
                   const std::string&, const std::string&, const std::string&) -> bool {
                    throw std::runtime_error("test: audit sink threw");
                });
            auto res = h.post(path, "device_id=dev-A&source=process");
            CHECK(res->status == 503);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(h.calls.empty());
        }
    }
}

TEST_CASE("dashboard execute audit (#3619 UP-5): authority revoked while the attempted row is "
          "written narrows the send",
          "[pg][server][dashboard][execute][audit][security][3619]") {
    // The attempted row can wait on the audit pool (up to AuditStore's write timeout); the
    // dispatch must use the caller's authority as it stands AFTER that wait, not before it.
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0; // stop before the result-render path (registry_ is null here)
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{.exec_visible = yuzu::server::authz::VisibleSet{
                                                std::unordered_set<std::string>{"dev-A", "dev-B"}}};
    };
    h.audit_persists = [&h](const AuditRow& r) {
        if (r.action == "command.dispatch" && r.result == "attempted") // revoked mid-write
            h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
                return yuzu::server::DispatchCaller{.exec_visible = yuzu::server::authz::VisibleSet{
                                                        std::unordered_set<std::string>{"dev-A"}}};
            };
        return true;
    };
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-B");
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("dev-A") == 1);
    CHECK(h.calls[0].exec_visible->count("dev-B") == 0); // the revocation reached the send
}

TEST_CASE("dashboard execute audit (#3619 UP-5): Execution:Execute revoked while the attempted "
          "row is written sends nothing and records the outcome",
          "[pg][server][dashboard][execute][audit][security][3619]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.dispatch_sent = 0; // a regression reaches dispatch, never the result-render path
    h.audit_persists = [&h](const AuditRow& r) {
        if (r.action == "command.dispatch" && r.result == "attempted")
            h.perm_allow = false; // revoked mid-write
        return true;
    };
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-B");
    CHECK(res->status == 403);
    CHECK(h.calls.empty());
    // The last gate call is the recheck after the attempted row, of the route's own permission
    // (the route makes other gate calls before the row, so the count is not pinned here). This
    // tells the recheck from admission only because the InstructionDefinition:Read lookup sits
    // between them; calls.empty() and the failure detail below are the independent guards.
    REQUIRE(h.perms.size() >= 2);
    CHECK(h.perms.back().securable_type == "Execution");
    CHECK(h.perms.back().op == "Execute");
    CHECK(h.audits_for("command.dispatch", "attempted") == 1);
    REQUIRE(h.audits_for("command.dispatch", "failure") == 1);
    CHECK(without_trailing_id(h.audit_detail("command.dispatch", "failure"), "correlation_id=") ==
          "reason=permission_revoked os_info:version");
    CHECK(h.audits_for("command.dispatch", "success") == 0);
}

TEST_CASE("fragment purge audit (#3619 UP-5, Gate 5 CH-1): a recheck refusal whose failure row is "
          "not stored still purges nothing and flags the response",
          "[pg][server][echo][purge][fragment][audit][security][3619]") {
    // Compound fault: the attempted row is stored, the grant is withdrawn during that write, and
    // every later row fails to persist. Only the attempted row survives; nothing is dispatched;
    // the route's own (unstored) failure row marks the response.
    FragmentHarness h;
    bool attempted_seen = false;
    h.audit_persists = [&h, &attempted_seen](const AuditRow& r) {
        if (attempted_seen)
            return false; // the audit store fails after the attempted row
        if (r.action == "echo.source.purge" && r.result == "attempted") {
            attempted_seen = true;
            h.scoped_allowed.clear(); // revoked mid-write
        }
        return true;
    };
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 404);
    CHECK(h.calls.empty());
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.audits_for("echo.source.purge", "attempted") == 1);
    CHECK(h.audit_detail_no_cid("echo.source.purge", "failure") ==
          "permission_revoked device=dev-A source=process"); // attempted, not stored
    CHECK(h.audits_for("echo.source.purge", "failure") == 1);
    CHECK(h.audits_for("echo.source.purge", "success") == 0);
    CHECK(h.metric("yuzu_echo_source_purge_total", "denied") == 1.0);
}

// ── #7114: a chokepoint refusal is reported as such, not as an unreachable agent ──────────────

TEST_CASE("fragment re-enable: a non-admin Execution:Execute holder under RBAC on is refused "
          "approval_required by the real classifier (#7114)",
          "[pg][server][echo][reenable][fragment][audit][security][7114]") {
    FragmentHarness h;
    // A non-admin operator who HOLDS the securable: the pair's AdminOrApproval gate (echo.configure)
    // is what refuses it, with no approval provenance on a REST-shaped caller.
    h.caller_fn = [](const httplib::Request&) {
        return yuzu::server::DispatchCaller{.principal = kUser,
                                            .principal_role = "user",
                                            .exec_visible = yuzu::server::authz::VisibleSet{},
                                            .principal_is_admin = false};
    };
    h.dispatch_decide = [](const std::string& plugin, const std::string& action,
                           const yuzu::server::DispatchCaller& caller)
        -> std::optional<yuzu::server::detail::DispatchDenial> {
        auto decision = yuzu::server::detail::classify_and_authorize_dispatch(
            yuzu::test::real_capability_registry(), caller, plugin, action,
            [](std::string_view, std::string_view, yuzu::server::authz::Operation) { return true; });
        if (decision)
            return std::nullopt;
        return decision.error();
    };
    auto res = h.post(kReenablePath, "device_id=dev-A&source=process");
    CHECK(res->status == 403);
    CHECK(contains(res->body, "Not permitted: approval_required"));
    CHECK(h.audits_for("echo.source.reenable", "attempted") == 1);
    REQUIRE(h.audits_for("echo.source.reenable", "failure") == 1);
    CHECK(h.audit_detail_no_cid("echo.source.reenable", "failure") ==
          "dispatch_denied reason=approval_required device=dev-A source=process");
    CHECK(h.audits_for("echo.source.reenable", "success") == 0);
    CHECK(h.metric("yuzu_echo_source_reenable_total", "approval_required") == 1.0);
    CHECK(h.metric("yuzu_echo_source_reenable_total", "agent_not_connected") == 0.0);
}

TEST_CASE("fragment re-enable/purge: a denial on the outcome is reported as dispatch_denied reason=<token>, "
          "never agent_not_connected (#7114)",
          "[pg][server][echo][reenable][purge][fragment][audit][security][7114]") {
    namespace detail = yuzu::server::detail;
    struct Denial {
        const char* name;
        detail::DispatchDenial denial;
        int status;
        const char* token;
    };
    const std::vector<Denial> denials = {
        {"Forbidden answers 403",
         {detail::DispatchDenialReason::Forbidden, "Infrastructure",
          yuzu::server::authz::Operation::Delete},
         403, "forbidden"},
        // The other permission-class tokens: describe_dispatch_denial maps both to kPermissionDenied.
        {"AnonymousOperator answers 403",
         {detail::DispatchDenialReason::AnonymousOperator, "Infrastructure",
          yuzu::server::authz::Operation::Write},
         403, "anonymous_operator"},
        {"KillSwitched answers 403",
         {detail::DispatchDenialReason::KillSwitched, "Infrastructure",
          yuzu::server::authz::Operation::Write},
         403, "kill_switched"},
        // 500, unlike the 400 describe_dispatch_denial gives a caller-named pair: both pairs here
        // are server literals, so an Unclassified one is a server catalogue fault.
        {"Unclassified answers 500 (server-literal pair)",
         {detail::DispatchDenialReason::Unclassified, {}, yuzu::server::authz::Operation::Read},
         500, "unclassified"},
    };
    struct Arm {
        const char* path;
        const char* action;
        const char* metric;
    };
    const Arm arms[] = {{kReenablePath, "echo.source.reenable", "yuzu_echo_source_reenable_total"},
                        {kPurgePath, "echo.source.purge", "yuzu_echo_source_purge_total"}};
    for (const auto& d : denials) {
        for (const auto& arm : arms) {
            DYNAMIC_SECTION(arm.action << ": " << d.name) {
                FragmentHarness h;
                h.dispatch_decide = [denial = d.denial](const std::string&, const std::string&,
                                                        const yuzu::server::DispatchCaller&) {
                    return std::optional<detail::DispatchDenial>{denial};
                };
                const std::string token = d.token;
                auto res = h.post(arm.path, "device_id=dev-A&source=process");
                CHECK(res->status == d.status);
                REQUIRE(h.audits_for(arm.action, "failure") == 1);
                CHECK(h.audit_detail_no_cid(arm.action, "failure") ==
                      "dispatch_denied reason=" + token + " device=dev-A source=process");
                CHECK(h.metric(arm.metric, token) == 1.0);
                CHECK(h.metric(arm.metric, "agent_not_connected") == 0.0);
            }
        }
    }
}

TEST_CASE("echo-execute and the echo.status scan: a denial on the outcome is reported as not permitted "
          "and audited as a failure, never as no agents connected (#7114)",
          "[pg][server][dashboard][echo-execute][echo][scan][fragment][audit][security][7114]") {
    // Both routes gate on Execution:Execute but dispatch a pair classified Infrastructure:Read
    // (echo.sql, echo.status), so a holder of only the first is refused on EVERY call.
    struct Arm {
        const char* path;
        const char* body;
        const char* action;
        const char* no_agents_text; // what the pre-#7114 fold-in said
        const char* metric;         // the counter the denied head bumps; null: it counts nothing
    };
    const Arm arms[] = {
        {"/api/dashboard/echo-execute", "sql=SELECT+1", "echo.sql", "No agents connected", nullptr},
        {"/fragments/echo/retention-paused/scan", "", "echo.status.scan",
         "None of the agents in your scope are currently connected",
         "yuzu_echo_scan_dispatched_total"},
    };
    for (const auto& arm : arms) {
        DYNAMIC_SECTION(arm.action) {
            FragmentHarness h;
            h.dispatch_decide = [](const std::string&, const std::string&,
                                   const yuzu::server::DispatchCaller&) {
                return std::optional<yuzu::server::detail::DispatchDenial>{
                    yuzu::server::detail::DispatchDenial{
                        yuzu::server::detail::DispatchDenialReason::Forbidden, "Infrastructure",
                        yuzu::server::authz::Operation::Read}};
            };
            auto res = h.post(arm.path, arm.body);
            CHECK(res->status == 200);
            CHECK(contains(res->body, "Not permitted: forbidden"));
            CHECK_FALSE(contains(res->body, arm.no_agents_text));
            REQUIRE(h.audits_for(arm.action, "failure") == 1);
            CHECK(h.audit_detail(arm.action, "failure") ==
                  "reason=dispatch_denied dispatch_reason=forbidden");
            CHECK(h.audits_for(arm.action, "success") == 0);
            if (arm.metric)
                CHECK(h.metric(arm.metric, "forbidden") == 1.0);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Typed scoped-gate refusal class, correlation ids, repeat bound, one metric vocabulary
// ═══════════════════════════════════════════════════════════════════════════

namespace {
/// The counter family of an Echo mutation's audit verb.
std::string family_for(const std::string& action) {
    return action == "echo.source.purge" ? std::string(echo_source::kPurgeTotal)
                                         : std::string(echo_source::kReenableTotal);
}
/// {message, level} of a response's HX-Trigger showToast ({"", ""} when absent or malformed).
std::pair<std::string, std::string> toast_of(const httplib::Response& res) {
    const auto trigger = nlohmann::json::parse(res.get_header_value("HX-Trigger"), nullptr,
                                               /*allow_exceptions=*/false);
    if (trigger.is_discarded() || !trigger.is_object() || !trigger.contains("showToast") ||
        !trigger["showToast"].is_object())
        return {};
    return {trigger["showToast"].value("message", std::string{}),
            trigger["showToast"].value("level", std::string{})};
}
/// A persist predicate that runs @p on_attempted when the attempted row of @p action is written.
std::function<bool(const AuditRow&)> on_attempted_row(std::string action,
                                                      std::function<void()> on_attempted) {
    return [action = std::move(action),
            on_attempted = std::move(on_attempted)](const AuditRow& r) {
        if (r.action == action && r.result == "attempted")
            on_attempted();
        return true;
    };
}
std::function<bool(const AuditRow&)> persist_everything() {
    return [](const AuditRow&) { return true; };
}
} // namespace

TEST_CASE("fragment purge/reenable audit (#7076): one trailing cid ties the attempted row to every "
          "row written after it",
          "[pg][server][echo][purge][reenable][fragment][audit][7076]") {
    FragmentHarness h;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        CAPTURE(act);
        // One request, and the rows it wrote. Each (device, source) pair is used once per action,
        // so no request meets another's repeat window.
        const auto run = [&](const std::string& device, const std::string& source) {
            h.audits.clear();
            h.post(request_path, "device_id=" + device + "&source=" + source);
            return h.rows_for(act);
        };

        // Success: attempted then success, the same cid last in both.
        const auto ok = run("dev-A", "process");
        REQUIRE(ok.size() == 2);
        CHECK(ok[0].result == "attempted");
        CHECK(ok[1].result == "success");
        const auto cid = trailing_id(ok[0].detail);
        CHECK(cid.rfind("req-", 0) == 0);
        CHECK(trailing_id(ok[1].detail) == cid);

        // agent_not_connected.
        h.dispatch_sent = 0;
        const auto offline = run("dev-A", "tcp");
        h.dispatch_sent = 1;
        REQUIRE(offline.size() == 2);
        CHECK(without_trailing_id(offline[1].detail) == "agent_not_connected source=tcp");
        CHECK(trailing_id(offline[1].detail) == trailing_id(offline[0].detail));
        CHECK(trailing_id(offline[0].detail) != cid); // a second request, a second id

        // dispatch_denied.
        h.dispatch_decide = [](const std::string&, const std::string&,
                               const yuzu::server::DispatchCaller&) {
            return std::optional<yuzu::server::detail::DispatchDenial>{
                yuzu::server::detail::DispatchDenial{
                    yuzu::server::detail::DispatchDenialReason::Forbidden, "Infrastructure",
                    yuzu::server::authz::Operation::Delete}};
        };
        const auto denied = run("dev-A", "service");
        h.dispatch_decide = nullptr;
        REQUIRE(denied.size() == 2);
        CHECK(without_trailing_id(denied[1].detail) ==
              "dispatch_denied reason=forbidden device=dev-A source=service");
        CHECK(trailing_id(denied[1].detail) == trailing_id(denied[0].detail));

        // permission_revoked at the recheck.
        h.audit_persists = on_attempted_row(act, [&h] { h.scoped_allowed.clear(); });
        const auto revoked = run("dev-A", "user");
        h.audit_persists = persist_everything();
        h.scoped_allowed = {"dev-A", "dev-B"};
        REQUIRE(revoked.size() == 2);
        CHECK(without_trailing_id(revoked[1].detail) ==
              "permission_revoked device=dev-A source=user");
        CHECK(trailing_id(revoked[1].detail) == trailing_id(revoked[0].detail));

        // scoped_gate_unavailable at the recheck.
        h.audit_persists = on_attempted_row(act, [&h] {
            h.scoped_allowed.clear();
            h.scoped_deny_outcome = ScopedGateOutcome::Unavailable;
        });
        const auto unavailable = run("dev-B", "process");
        h.audit_persists = persist_everything();
        h.scoped_allowed = {"dev-A", "dev-B"};
        h.scoped_deny_outcome = ScopedGateOutcome::Denied;
        REQUIRE(unavailable.size() == 2);
        CHECK(without_trailing_id(unavailable[1].detail) ==
              "scoped_gate_unavailable device=dev-B source=process");
        CHECK(trailing_id(unavailable[1].detail) == trailing_id(unavailable[0].detail));

        // A refusal before the attempted row carries none.
        h.scoped_allowed.clear();
        const auto before_row = run("dev-A", "process");
        h.scoped_allowed = {"dev-A", "dev-B"};
        REQUIRE(before_row.size() == 1);
        CHECK(before_row[0].result == "failure");
        CHECK(before_row[0].detail == "scope_violation source=process");
        CHECK_FALSE(contains(before_row[0].detail, "cid="));
    }
}

TEST_CASE("dashboard execute audit (#7076): one trailing correlation_id ties the attempted row to "
          "every command.dispatch row written after it",
          "[pg][server][dashboard][execute][audit][7076]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    std::unordered_set<std::string> ids;
    // One request, and the command.dispatch rows it wrote.
    const auto run = [&](const char* what) {
        CAPTURE(what);
        h.audits.clear();
        h.post("/api/dashboard/execute", "instruction=run&scope=dev-B");
        const auto rows = h.rows_for("command.dispatch");
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].result == "attempted");
        const auto id = trailing_id(rows[0].detail, "correlation_id=");
        CHECK(id.rfind("req-", 0) == 0);
        CHECK(trailing_id(rows[1].detail, "correlation_id=") == id);
        ids.insert(id);
        return rows;
    };

    const auto sent = run("success");
    CHECK(sent[1].result == "success");

    h.dispatch_sent = 0;
    const auto none = run("no_agents_reached");
    CHECK(none[1].result == "failure");
    CHECK(without_trailing_id(none[1].detail, "correlation_id=") == "reason=no_agents_reached");
    h.dispatch_sent = 1;

    h.dispatch_decide = [](const std::string&, const std::string&,
                           const yuzu::server::DispatchCaller&) {
        return std::optional<yuzu::server::detail::DispatchDenial>{
            yuzu::server::detail::DispatchDenial{
                yuzu::server::detail::DispatchDenialReason::Forbidden, "Execution",
                yuzu::server::authz::Operation::Execute}};
    };
    const auto denied = run("dispatch_denied");
    h.dispatch_decide = nullptr;
    CHECK(contains(denied[1].detail, "reason=dispatch_denied dispatch_reason=forbidden"));

    h.audit_persists = on_attempted_row("command.dispatch", [&h] { h.perm_allow = false; });
    const auto revoked = run("permission_revoked");
    CHECK(without_trailing_id(revoked[1].detail, "correlation_id=") ==
          "reason=permission_revoked os_info:version");

    CHECK(ids.size() == 4); // four requests, four different ids
}

TEST_CASE("dashboard execute audit (#7116 CH-3): a session that ends while the attempted row is "
          "written sends nothing and records permission_revoked",
          "[pg][server][dashboard][execute][audit][security][3619][7116]") {
    FragmentHarness h;
    h.resolve_to = {"os_info", "version"};
    h.gates_follow_session = true;
    h.audit_persists = on_attempted_row("command.dispatch", [&h] { h.auth_ok = false; });
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-B");
    CHECK(res->status == 401);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("command.dispatch", "attempted") == 1);
    REQUIRE(h.audits_for("command.dispatch", "failure") == 1);
    CHECK(h.audit_detail("command.dispatch", "failure")
              .rfind("reason=permission_revoked os_info:version", 0) == 0);
    CHECK(h.audits_for("command.dispatch", "success") == 0);
}

TEST_CASE("fragment purge/reenable audit (#7116 CH-3): a session that ends while the attempted row "
          "is written sends nothing and is counted denied",
          "[pg][server][echo][purge][reenable][fragment][audit][security][3619][7116]") {
    FragmentHarness h;
    h.gates_follow_session = true;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        CAPTURE(act);
        h.auth_ok = true;
        h.audit_persists = on_attempted_row(act, [&h] { h.auth_ok = false; });
        auto res = h.post(request_path, "device_id=dev-A&source=process");
        // The gate answers Unauthenticated at the recheck; the route collapses it like a denial.
        CHECK(res->status == 404);
        CHECK(res->body == kEchoAgentNotReachableBody);
        CHECK(h.calls.empty());
        CHECK(h.audits_for(act, "attempted") == 1);
        REQUIRE(h.audits_for(act, "failure") == 1);
        CHECK(h.audit_detail_no_cid(act, "failure") ==
              "permission_revoked device=dev-A source=process");
        CHECK(h.audits_for(act, "success") == 0);
        CHECK(h.metric(family_for(act), "denied") == 1.0);
    }
}

TEST_CASE("fragment purge/reenable and the console send audit (#7116 CH-7): a grant withdrawn "
          "inside the dispatch call still ends in success, with no failure row",
          "[pg][server][echo][purge][reenable][fragment][audit][security][3619][7116]") {
    // The recheck ran BEFORE the dispatch, so a grant that goes during it cannot un-send what is
    // sent: the honest outcome is success, never a failure row beside a dispatched command.
    FragmentHarness h;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        CAPTURE(act);
        h.order.clear();
        h.audits.clear();
        h.on_dispatch = [&h] { h.scoped_allowed.clear(); };
        auto res = h.post(request_path, "device_id=dev-A&source=process");
        h.on_dispatch = nullptr;
        h.scoped_allowed = {"dev-A", "dev-B"};
        CHECK(res->status == 200);
        const std::vector<std::string> expected{"audit:" + act + "/attempted", "dispatch",
                                                "audit:" + act + "/success"};
        CHECK(h.order == expected);
        CHECK(h.audits_for(act, "failure") == 0);
    }

    h.resolve_to = {"os_info", "version"};
    h.audits.clear();
    h.on_dispatch = [&h] { h.perm_allow = false; };
    auto res = h.post("/api/dashboard/execute", "instruction=run&scope=dev-B");
    h.on_dispatch = nullptr;
    CHECK(res->status == 200);
    CHECK(h.audits_for("command.dispatch", "attempted") == 1);
    CHECK(h.audits_for("command.dispatch", "success") == 1);
    CHECK(h.audits_for("command.dispatch", "failure") == 0);
}

TEST_CASE("fragment purge/reenable (#7116 CH-8, #2536): every refusal and outage counts under its "
          "own result on surface=dashboard",
          "[pg][server][echo][purge][reenable][fragment][audit][security][3619][7116][2536]") {
    // Sequential posts on ONE harness per wiring variant (no section per row, no second harness
    // per row). No step here dispatches, so none starts a repeat window for the next.
    {
        FragmentHarness h;
        for (const auto& [path, action] : kEchoMutations) {
            const std::string act = action;
            const std::string request_path = path; // a plain copy: lambdas below use it
            const std::string family = family_for(act);
            // Posts one request and requires that `result` moved by exactly one.
            const auto expect = [&](const char* step, const char* result,
                                    const std::unordered_map<std::string, std::string>& headers =
                                        FragmentHarness::same_site_headers()) {
                CAPTURE(act, step, result);
                const double before = h.metric(family, result);
                h.post(request_path, "device_id=dev-A&source=process", headers);
                CHECK(h.metric(family, result) == before + 1.0);
            };
            const auto reset = [&h] {
                h.scoped_allowed = {"dev-A", "dev-B"};
                h.scoped_deny_outcome = ScopedGateOutcome::Denied;
                h.token_scope_service.clear();
                h.audit_persists = persist_everything();
            };
            // The gate refuses (with `outcome`) once the attempted row is written.
            const auto refuse_at_recheck = [&](ScopedGateOutcome outcome) {
                h.audit_persists = on_attempted_row(act, [&h, outcome] {
                    h.scoped_allowed.clear();
                    h.scoped_deny_outcome = outcome;
                });
            };

            h.token_scope_service = "svc-example";
            expect("service-scoped token", "denied");
            reset();

            expect("cross-site", "denied", {{"Host", kHost}, {"Origin", "https://evil.example"}});

            h.scoped_allowed.clear();
            expect("denied at admission", "scope_violation");
            reset();

            h.scoped_allowed.clear();
            h.scoped_deny_outcome = ScopedGateOutcome::Unauthenticated;
            const int failure_rows = h.audits_for(act, "failure");
            expect("unauthenticated at admission", "denied");
            CHECK(h.last_detail(act, "denied") == "session_revoked source=process");
            CHECK(h.audits_for(act, "failure") == failure_rows); // no scope_violation row
            reset();

            h.scoped_allowed.clear();
            h.scoped_deny_outcome = ScopedGateOutcome::Unavailable;
            expect("unavailable at admission", "infra_unavailable");
            reset();

            refuse_at_recheck(ScopedGateOutcome::Denied);
            expect("denied at the recheck", "denied");
            reset();

            refuse_at_recheck(ScopedGateOutcome::Unauthenticated);
            expect("unauthenticated at the recheck", "denied");
            reset();

            refuse_at_recheck(ScopedGateOutcome::Unavailable);
            expect("unavailable at the recheck", "infra_unavailable");
            reset();

            // The five `denied` steps above, read through the literal label set.
            CHECK(h.metrics
                      .counter(family, {{"result", "denied"}, {"surface", "dashboard"}})
                      .value() == 5.0);
            // The label-less series the surface label replaced no longer moves.
            for (const char* result : {"denied", "scope_violation", "infra_unavailable"})
                CHECK(h.metric_without_surface(family, result) == 0.0);
            CHECK(h.calls.empty());
        }
    }
    {
        // The scoped gate was never wired.
        FragmentHarness h{/*with_dispatch=*/true, /*wire_exec_visible=*/true, /*wire_scoped=*/false};
        for (const auto& [path, action] : kEchoMutations) {
            CAPTURE(action);
            CHECK(h.post(path, "device_id=dev-A&source=process")->status == 503);
            CHECK(h.metric(family_for(action), "infra_unavailable") == 1.0);
            CHECK(h.metric(family_for(action), "denied") == 0.0);
        }
    }
    {
        // The dispatch function was never wired (checked before the gate is asked).
        FragmentHarness h{/*with_dispatch=*/false};
        for (const auto& [path, action] : kEchoMutations) {
            CAPTURE(action);
            CHECK(h.post(path, "device_id=dev-A&source=process")->status == 503);
            CHECK(h.metric(family_for(action), "infra_unavailable") == 1.0);
            CHECK(h.metric(family_for(action), "denied") == 0.0);
        }
    }
}

TEST_CASE("fragment purge/reenable (#2532): a degraded authorization read at admission answers 503 "
          "and is recorded store_unavailable, not the 404 collapse and not scope_violation",
          "[pg][server][echo][purge][reenable][fragment][audit][security][2532]") {
    FragmentHarness h;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        const std::string family = family_for(act);
        CAPTURE(act);
        const std::pair<ScopedGateOutcome, const char*> classes[] = {
            {ScopedGateOutcome::MgmtGroupReadDegraded, "mgmt_group_store"},
            {ScopedGateOutcome::RbacReadDegraded, "rbac_store"}};
        double expected_unavailable = 0.0;
        for (const auto& [outcome, store] : classes) {
            CAPTURE(store);
            h.scoped_allowed.clear();
            h.scoped_deny_outcome = outcome;
            auto res = h.post(request_path, "device_id=dev-A&source=process");
            CHECK(res->status == 503);
            CHECK(res->body != kEchoAgentNotReachableBody);
            const auto toast = toast_of(*res);
            CHECK(contains(toast.first, "Authorization could not be checked"));
            CHECK(toast.second == "error");
            CHECK(h.last_detail(act, "denied") ==
                  std::string("store_unavailable store=") + store + " source=process");
            expected_unavailable += 1.0;
            CHECK(h.metric(family, "store_unavailable") == expected_unavailable);
        }
        CHECK(h.audits_for(act, "failure") == 0);   // no scope_violation row
        CHECK(h.audits_for(act, "attempted") == 0); // refused before the row
        CHECK(h.metric(family, "scope_violation") == 0.0);
        CHECK(h.calls.empty());

        // A plain denial is unchanged: the 404 collapse, a failure row, scope_violation.
        h.scoped_deny_outcome = ScopedGateOutcome::Denied;
        auto plain = h.post(request_path, "device_id=dev-A&source=process");
        CHECK(plain->status == 404);
        CHECK(plain->body == kEchoAgentNotReachableBody);
        CHECK(h.last_detail(act, "failure") == "scope_violation source=process");
        CHECK(h.metric(family, "scope_violation") == 1.0);
        h.scoped_allowed = {"dev-A", "dev-B"};
    }
}

TEST_CASE("fragment purge/reenable (#2532): a degraded authorization read at the recheck answers "
          "503 and records a store_unavailable failure",
          "[pg][server][echo][purge][reenable][fragment][audit][security][2532]") {
    FragmentHarness h;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        const std::string family = family_for(act);
        CAPTURE(act);
        const std::pair<ScopedGateOutcome, const char*> classes[] = {
            {ScopedGateOutcome::MgmtGroupReadDegraded, "mgmt_group_store"},
            {ScopedGateOutcome::RbacReadDegraded, "rbac_store"}};
        const char* const sources[] = {"process", "tcp"};
        for (std::size_t i = 0; i < 2; ++i) {
            const auto [outcome, store] = classes[i];
            CAPTURE(store);
            h.audit_persists = on_attempted_row(act, [&h, outcome = outcome] {
                h.scoped_allowed.clear();
                h.scoped_deny_outcome = outcome;
            });
            auto res = h.post(request_path, std::string{"device_id=dev-A&source="} + sources[i]);
            h.audit_persists = persist_everything();
            h.scoped_allowed = {"dev-A", "dev-B"};
            h.scoped_deny_outcome = ScopedGateOutcome::Denied;
            CHECK(res->status == 503);
            CHECK(res->body != kEchoAgentNotReachableBody);
            CHECK(toast_of(*res).second == "error");
            const auto failure = h.last_detail(act, "failure");
            CHECK(without_trailing_id(failure) == std::string("store_unavailable store=") + store +
                                                     " device=dev-A source=" + sources[i]);
            CHECK(trailing_id(failure) == trailing_id(h.last_detail(act, "attempted")));
        }
        CHECK(h.metric(family, "store_unavailable") == 2.0);
        CHECK(h.metric(family, "denied") == 0.0);
        CHECK(h.calls.empty());
    }
}

TEST_CASE("fragment purge/reenable (#2532): a repeat inside the 30 s window answers 429 and "
          "dispatches nothing",
          "[pg][server][echo][purge][reenable][fragment][audit][security][2532]") {
    FragmentHarness h;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        const std::string family = family_for(act);
        CAPTURE(act);
        // The other action on the same device and source was just dispatched by the previous
        // iteration (and is its own window), so this first post also proves the keys are per action.
        const auto calls_before = h.calls.size();
        CHECK(h.post(request_path, "device_id=dev-A&source=process")->status == 200);
        CHECK(h.calls.size() == calls_before + 1);

        auto repeat = h.post(request_path, "device_id=dev-A&source=process");
        CHECK(repeat->status == 429);
        const auto wait = repeat->get_header_value("Retry-After");
        REQUIRE_FALSE(wait.empty());
        CHECK(std::stoi(wait) >= 1);
        CHECK(std::stoi(wait) <= 30);
        CHECK(contains(repeat->body, "echo-row-error"));
        const auto toast = toast_of(*repeat);
        CHECK(toast.second == "error");
        CHECK(contains(toast.first, "second"));
        const auto row = h.audit_detail(act, "denied");
        CHECK(row.rfind("rate_limited cooldown=", 0) == 0);
        CHECK(row.ends_with(" device=dev-A source=process"));
        CHECK(h.metric(family, "rate_limited") == 1.0);
        CHECK(h.audits_for(act, "attempted") == 1); // the repeat wrote none
        CHECK(h.calls.size() == calls_before + 1);  // and dispatched nothing

        // Another source is its own window.
        CHECK(h.post(request_path, "device_id=dev-A&source=tcp")->status == 200);
        CHECK(h.calls.size() == calls_before + 2);

        // A repeat that arrives while a request is still in flight is refused too: the key is
        // held from the gate's admission. The dispatch hook posts the same pair from inside the
        // first request.
        const auto calls_in_flight = h.calls.size();
        bool nested = false;
        std::unique_ptr<httplib::Response> during;
        h.on_dispatch = [&] {
            if (nested)
                return;
            nested = true;
            during = h.post(request_path, "device_id=dev-A&source=service");
        };
        CHECK(h.post(request_path, "device_id=dev-A&source=service")->status == 200);
        h.on_dispatch = nullptr; // after the post: clearing it inside the running hook frees it
        REQUIRE(during != nullptr);
        CHECK(during->status == 429);
        CHECK(during->get_header_value("Retry-After") ==
              std::to_string(echo_source::EchoActionCooldown::kWindowSec));
        CHECK(h.calls.size() == calls_in_flight + 1); // only the first request dispatched
    }
}

TEST_CASE("fragment purge/reenable (#2532): an attempt that dispatched nothing frees its key",
          "[pg][server][echo][purge][reenable][fragment][audit][security][2532]") {
    FragmentHarness h;
    for (const auto& [path, action] : kEchoMutations) {
        const std::string act = action;
        const std::string request_path = path; // a plain copy: lambdas below use it
        CAPTURE(act);
        // The immediate retry of the same device and source is admitted (200), not throttled.
        const auto retry = [&](const std::string& source) {
            CAPTURE(source);
            CHECK(h.post(request_path, "device_id=dev-A&source=" + source)->status == 200);
        };

        h.audit_persists = fail_only(act, "attempted"); // audit_unavailable
        CHECK(h.post(request_path, "device_id=dev-A&source=process")->status == 503);
        h.audit_persists = persist_everything();
        retry("process");

        h.audit_persists = on_attempted_row(act, [&h] { h.scoped_allowed.clear(); }); // recheck
        CHECK(h.post(request_path, "device_id=dev-A&source=tcp")->status == 404);
        h.audit_persists = persist_everything();
        h.scoped_allowed = {"dev-A", "dev-B"};
        retry("tcp");

        h.dispatch_decide = [](const std::string&, const std::string&,
                               const yuzu::server::DispatchCaller&) { // dispatch denial
            return std::optional<yuzu::server::detail::DispatchDenial>{
                yuzu::server::detail::DispatchDenial{
                    yuzu::server::detail::DispatchDenialReason::Forbidden, "Infrastructure",
                    yuzu::server::authz::Operation::Delete}};
        };
        CHECK(h.post(request_path, "device_id=dev-A&source=service")->status == 403);
        h.dispatch_decide = nullptr;
        retry("service");

        h.dispatch_sent = 0; // agent_not_connected
        CHECK(h.post(request_path, "device_id=dev-A&source=user")->status == 404);
        h.dispatch_sent = 1;
        retry("user");
    }
}

TEST_CASE("echo action cooldown (#2532): a request holds its key, a dispatch starts the window, "
          "and the map is bounded",
          "[server][echo][cooldown][2532]") {
    using echo_source::EchoActionCooldown;
    constexpr auto kWindow = EchoActionCooldown::kWindowSec;

    SECTION("a held key is refused with the full window however late") {
        EchoActionCooldown c;
        CHECK_FALSE(c.try_acquire("k", 100).has_value());
        CHECK(c.try_acquire("k", 100) == kWindow);
        CHECK(c.try_acquire("k", 100 + 31) == kWindow); // a held key never expires
    }
    SECTION("release frees the key") {
        EchoActionCooldown c;
        CHECK_FALSE(c.try_acquire("k", 0).has_value());
        c.release("k");
        CHECK_FALSE(c.try_acquire("k", 0).has_value());
    }
    SECTION("commit starts the window from the dispatch time") {
        EchoActionCooldown c;
        CHECK_FALSE(c.try_acquire("k", 30).has_value());
        c.commit("k", 40);
        CHECK(c.try_acquire("k", 60) == 10);
        CHECK(c.try_acquire("k", 69) == 1);
        CHECK_FALSE(c.try_acquire("k", 70).has_value()); // the window ended: held again
    }
    SECTION("keys are independent") {
        EchoActionCooldown c;
        CHECK_FALSE(c.try_acquire("a", 0).has_value());
        CHECK_FALSE(c.try_acquire("b", 0).has_value());
    }
    SECTION("a Slot releases with no dispatch time and commits with one") {
        EchoActionCooldown c;
        REQUIRE_FALSE(c.try_acquire("idle", 0).has_value());
        { EchoActionCooldown::Slot s{c, "idle"}; }
        CHECK_FALSE(c.try_acquire("idle", 0).has_value()); // released

        REQUIRE_FALSE(c.try_acquire("sent", 0).has_value());
        {
            EchoActionCooldown::Slot s{c, "sent"};
            s.dispatching(100);
        }
        CHECK(c.try_acquire("sent", 110) == kWindow - 10); // committed from 100

        REQUIRE_FALSE(c.try_acquire("undone", 0).has_value());
        {
            EchoActionCooldown::Slot s{c, "undone"};
            s.dispatching(5);
            s.nothing_sent();
        }
        CHECK_FALSE(c.try_acquire("undone", 0).has_value()); // nothing_sent cleared the time
    }
    SECTION("at the cap, expired entries are pruned, a held entry never, a live window is kept") {
        EchoActionCooldown c;
        for (std::size_t i = 0; i < EchoActionCooldown::kCap; ++i)
            REQUIRE_FALSE(c.try_acquire("held-" + std::to_string(i), 0).has_value());
        // Every key is held: a new key is refused however late it is.
        CHECK(c.try_acquire("new", 100000) == kWindow);
        // One request ends: its window runs 0..30. Still live at 29, pruned from 30.
        c.commit("held-0", 0);
        CHECK(c.try_acquire("new", 29) == kWindow);
        CHECK_FALSE(c.try_acquire("new", 30).has_value());
        // The held keys survived the prune.
        CHECK(c.try_acquire("held-1", 100000) == kWindow);
    }
    SECTION("a full map of live windows refuses until they end") {
        EchoActionCooldown c;
        for (std::size_t i = 0; i < EchoActionCooldown::kCap; ++i) {
            const auto key = "live-" + std::to_string(i);
            REQUIRE_FALSE(c.try_acquire(key, 0).has_value());
            c.commit(key, 100);
        }
        CHECK(c.try_acquire("new", 110) == kWindow);
        CHECK_FALSE(c.try_acquire("new", 130).has_value());
    }
    SECTION("a deadline more than one window ahead of now was stamped before the clock stepped "
            "back and counts as ended") {
        EchoActionCooldown c;
        REQUIRE_FALSE(c.try_acquire("k", 0).has_value());
        c.commit("k", 100000);
        CHECK(c.try_acquire("k", 100000) == kWindow); // exactly one window ahead is live
        CHECK_FALSE(c.try_acquire("k", 96400).has_value());
    }
    SECTION("a full map of deadlines stamped before a clock step back admits a new key") {
        EchoActionCooldown c;
        for (std::size_t i = 0; i < EchoActionCooldown::kCap; ++i) {
            const auto key = "ahead-" + std::to_string(i);
            REQUIRE_FALSE(c.try_acquire(key, 0).has_value());
            c.commit(key, 100000);
        }
        CHECK_FALSE(c.try_acquire("new", 0).has_value());
    }
}

TEST_CASE("echo source rules (#2536): the scoped gate's class maps to one result, one detail and "
          "one audit result",
          "[server][echo][metrics][2536]") {
    struct Row {
        ScopedGateOutcome outcome;
        std::string_view result_at_admission, result_at_recheck;
        std::string_view detail_at_admission, detail_at_recheck;
        std::string_view admission_result;
        bool could_not_evaluate;
    };
    const Row table[] = {
        {ScopedGateOutcome::Denied, "scope_violation", "denied", "scope_violation",
         "permission_revoked", "failure", false},
        {ScopedGateOutcome::Unauthenticated, "denied", "denied", "session_revoked",
         "permission_revoked", "denied", false},
        {ScopedGateOutcome::Unavailable, "infra_unavailable", "infra_unavailable",
         "scoped_gate_unavailable", "scoped_gate_unavailable", "denied", true},
        {ScopedGateOutcome::MgmtGroupReadDegraded, "store_unavailable", "store_unavailable",
         "store_unavailable store=mgmt_group_store", "store_unavailable store=mgmt_group_store",
         "denied", true},
        {ScopedGateOutcome::RbacReadDegraded, "store_unavailable", "store_unavailable",
         "store_unavailable store=rbac_store", "store_unavailable store=rbac_store", "denied",
         true},
        // Never passed in production; answered as the plain denial so the switch is total.
        {ScopedGateOutcome::Admitted, "scope_violation", "denied", "scope_violation",
         "permission_revoked", "failure", false},
    };
    for (const auto& r : table) {
        CAPTURE(static_cast<int>(r.outcome));
        CHECK(echo_source::refusal_result(r.outcome, false) == r.result_at_admission);
        CHECK(echo_source::refusal_result(r.outcome, true) == r.result_at_recheck);
        CHECK(echo_source::refusal_detail(r.outcome, false) == r.detail_at_admission);
        CHECK(echo_source::refusal_detail(r.outcome, true) == r.detail_at_recheck);
        CHECK(echo_source::admission_audit_result(r.outcome) == r.admission_result);
        CHECK(echo_source::could_not_evaluate(r.outcome) == r.could_not_evaluate);
    }
    // Only the two degraded classes name a store, and the detail ends with it.
    CHECK(degraded_store(ScopedGateOutcome::MgmtGroupReadDegraded) == "mgmt_group_store");
    CHECK(degraded_store(ScopedGateOutcome::RbacReadDegraded) == "rbac_store");
    for (const auto o : {ScopedGateOutcome::Denied, ScopedGateOutcome::Unauthenticated,
                         ScopedGateOutcome::Unavailable, ScopedGateOutcome::Admitted})
        CHECK(degraded_store(o).empty());
    // An out-of-range value is a plain denial: never admitted, never a 503.
    const auto stray = static_cast<ScopedGateOutcome>(99);
    CHECK(echo_source::refusal_result(stray, false) == "scope_violation");
    CHECK(echo_source::refusal_detail(stray, true) == "permission_revoked");
    CHECK(echo_source::admission_audit_result(stray) == "failure");
    CHECK_FALSE(echo_source::could_not_evaluate(stray));
    CHECK(degraded_store(stray).empty());
    // A value-initialised outcome refuses.
    CHECK(ScopedGateOutcome{} != ScopedGateOutcome::Admitted);
}

TEST_CASE("echo source rules (#2536): labels are result then surface, and every series exists at 0",
          "[server][echo][metrics][2536]") {
    CHECK(echo_source::labels("denied", "dashboard") ==
          yuzu::Labels{{"result", "denied"}, {"surface", "dashboard"}});

    yuzu::MetricsRegistry m;
    echo_source::describe_and_seed(m);
    const std::string text = m.serialize();
    const auto lines_starting = [&text](std::string_view prefix) {
        std::size_t n = 0;
        for (std::size_t at = text.find(prefix); at != std::string::npos;
             at = text.find(prefix, at + 1))
            if (at == 0 || text[at - 1] == '\n')
                ++n;
        return n;
    };
    std::vector<std::string> results(echo_source::kFixedResults.begin(),
                                     echo_source::kFixedResults.end());
    for (const auto reason : yuzu::server::detail::kAllDispatchDenialReasons)
        results.emplace_back(yuzu::server::detail::to_string(reason));
    CHECK(results.size() == 15);
    for (const auto& result : results) {
        CAPTURE(result);
        for (const char* surface : {"dashboard", "rest"})
            CHECK(contains(text, std::string(echo_source::kPurgeTotal) + "{result=\"" + result +
                                     "\",surface=\"" + surface + "\"} 0\n"));
        CHECK(contains(text, std::string(echo_source::kReenableTotal) + "{result=\"" + result +
                                 "\",surface=\"dashboard\"} 0\n"));
        // The re-enable action has no REST surface.
        CHECK_FALSE(contains(text, std::string(echo_source::kReenableTotal) + "{result=\"" +
                                       result + "\",surface=\"rest\"}"));
    }
    CHECK(lines_starting(echo_source::kPurgeTotal) == 30);
    CHECK(lines_starting(echo_source::kReenableTotal) == 15);
    CHECK(contains(text, "# HELP yuzu_echo_source_purge_total"));
    CHECK(contains(text, "# HELP yuzu_echo_source_reenable_total"));
}
