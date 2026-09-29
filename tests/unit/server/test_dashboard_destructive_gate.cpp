/**
 * test_dashboard_destructive_gate.cpp — PR6.0b: the Destructive-class
 * TARGETING gate on `POST /api/dashboard/execute`.
 *
 * WHY THIS FILE EXISTS. #3685 wired `dispatch_destructive_gate.hpp` into the
 * two operator-facing dispatch surfaces it knew about — REST `/api/command`
 * and MCP `execute_instruction`. The dashboard exec console is a THIRD: it
 * resolves a free-form instruction to a `plugin.action`, lets the operator
 * pick `__all__`, `group:<id>`, a single agent, or nothing at all (which its
 * legacy UI contract reads as the whole fleet), and reaches agents through
 * `ServerImpl::dispatch_confined` rather than `/api/command`. Every
 * Destructive row that does not additionally carry
 * `ExecuteGate::AdminOrApproval` — `tar.purge_source`, `registry.delete_key`,
 * `filesystem.delete_lines`, `tags.clear`, `storage.clear`, … — was
 * fleet-targetable from it by any holder of the declared securable.
 *
 * WHAT IS BOUND HERE (each case fails if the corresponding guard is deleted):
 *   - a `__all__` broadcast of a Destructive action is refused, counted on
 *     `yuzu_server_dispatch_target_rejected_total{route="dashboard"}`, and
 *     audited — with NO dispatch,
 *   - a `group:<id>` scope fan-out of a Destructive action is refused the
 *     same way (a different arm, not the same assertion twice),
 *   - an OMITTED scope — the fleet-by-omission case, the one an operator
 *     reaches by just typing a command — is refused too,
 *   - a `ReadOnly` and a `Mutating` action are COMPLETELY unaffected on all
 *     three of those shapes: the gate must not silently widen,
 *   - an explicit, in-scope single agent DOES dispatch (the `[pg]` case —
 *     confinement needs a real `ManagementGroupStore`), and an explicit
 *     OUT-of-scope agent is dropped to the no-visible-agent refusal,
 *   - an unwired `ClassifyFn` refuses EVERY dispatch rather than silently
 *     reverting the gate (the `ContainmentGate{}` class of regression).
 *
 * Classifications come from the REAL catalogue (the same six spans the
 * production registry composes), not a local fixture, so a case cannot
 * silently become a test about a pair that is no longer Destructive.
 *
 * `TestRouteSink` trap (CLAUDE.md → Test conventions): `Post(path, body)`
 * defaults to `application/json` and does NOT populate `req.params`, which
 * silently exercises the handler's raw-body fallback instead of its
 * production branch. Every POST here goes through `post()`, which sets
 * `application/x-www-form-urlencoded` explicitly — and
 * `handler_read_the_scope_param` pins that the production `req.params` branch
 * is the one actually being driven.
 */

#include "dashboard_routes.hpp"
#include "management_group_store.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "command_capability.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_target_shape.hpp"
#include "test_real_capability_registry.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kUser = "exec-op";
constexpr const char* kHost = "yuzu.example:8080";
constexpr const char* kPath = "/api/dashboard/execute";

/// The REAL registry, composed exactly as the production site composes it —
/// shared with the other route fixtures that must wire a `ClassifyFn` (see
/// `test_real_capability_registry.hpp` for why it is not a per-file copy).
const CommandCapabilityRegistry& real_registry() {
    return yuzu::test::real_capability_registry();
}

/// The three pairs every case below is written against. Asserted to still
/// hold their expected class in `catalogue anchors` — if the catalogue ever
/// reclassifies one, that case fails loudly instead of these tests quietly
/// becoming about nothing.
constexpr std::pair<const char*, const char*> kDestructive{"tar", "purge_source"};
constexpr std::pair<const char*, const char*> kReadOnly{"os_info", "os_version"};
constexpr std::pair<const char*, const char*> kMutating{"tags", "set"};

struct DispatchCall {
    std::string plugin, action, scope_expr;
    std::vector<std::string> agent_ids;
};
struct AuditRow {
    std::string action, result, detail;
};

/// Make `agents` visible to kUser via a group on which kUser holds a role —
/// `get_visible_agents` is that role-scoped join. Copied in shape from
/// `test_dashboard_tar_fragments.cpp`'s helper of the same name.
void grant_visibility(ManagementGroupStore& mg, std::initializer_list<std::string> agents) {
    ManagementGroup g;
    g.name = "All Devices";
    g.membership_type = "static";
    auto gid = mg.create_group(g);
    REQUIRE(gid.has_value());
    for (const auto& a : agents)
        REQUIRE(mg.add_member(*gid, a).has_value());
    GroupRoleAssignment ra;
    ra.group_id = *gid;
    ra.principal_type = "user";
    ra.principal_id = kUser;
    ra.role_name = "ITServiceOwner";
    REQUIRE(mg.assign_role(ra).has_value());
}

/// MEMBER ORDER IS LOAD-BEARING (CLAUDE.md → Test conventions): `sink` is
/// declared LAST so it is destroyed FIRST, while the `DashboardRoutes` whose
/// `this` its handlers captured is still alive. `metrics` precedes `routes`
/// because `routes` borrows it.
struct ExecHarness {
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;

    /// What `resolve_fn` maps the typed instruction to. Set per test.
    std::pair<std::string, std::string> resolve_to{};

    /// @param mg  the visible-agent store; nullptr exercises the fail-closed
    ///            arm (an absent store reads as "nobody visible", never
    ///            "everybody" — `DestructiveVisibleAgents`' inverted nullopt).
    /// @param wire_classifier false → register with NO ClassifyFn, so the
    ///            production handler's own fail-closed branch is driven.
    explicit ExecHarness(ManagementGroupStore* mg = nullptr, bool wire_classifier = true) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = kUser;
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string&, const std::string&,
                               const std::string& d) { audits.push_back({a, r, d}); };
        DashboardRoutes::DispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string& scope,
                   const std::unordered_map<std::string, std::string>&,
                   const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
            calls.push_back({plugin, action, scope, ids});
            return {.sent = 1, .command_id = "cmd-" + std::to_string(calls.size())};
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn,
                               /*response_store=*/nullptr, mg, /*registry=*/nullptr,
                               /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                               /*agents_json_fn=*/[] { return std::string{"[]"}; }, dispatch,
                               /*caller_fn=*/
                               [](const httplib::Request&) -> yuzu::server::DispatchCaller {
                                   // A real operator identity: `principal` is
                                   // what the gate reads for the visible-agent
                                   // lookup, and an unfiltered exec_visible
                                   // keeps this file's subject the DESTRUCTIVE
                                   // gate rather than the #1788 intersection
                                   // (bound separately in
                                   // test_dispatch_confined_arms.cpp).
                                   return yuzu::server::DispatchCaller{
                                       .principal = kUser, .exec_visible = std::nullopt};
                               },
                               /*resolve_fn=*/
                               [this](const std::string&) { return resolve_to; }, &metrics,
                               /*instruction_store=*/nullptr);
        // One registration pass only — two would register every route twice
        // and first-match-wins would serve handlers bound to the first call.
        // #4027: +1 for GET /api/v1/tar/retention-paused.
        REQUIRE(sink.route_count() == 13);

        if (wire_classifier)
            routes.set_capability_classify_fn(yuzu::test::real_classify_fn());
    }

    std::unique_ptr<httplib::Response> post(const std::string& body) {
        std::unordered_map<std::string, std::string> headers{
            {"Host", kHost}, {"Origin", std::string{"https://"} + kHost}};
        // Content-type set EXPLICITLY: the TestRouteSink default of
        // application/json would leave req.params empty and silently drive the
        // handler's raw-body fallback instead of the production branch (#1786).
        auto res = sink.dispatch("POST", kPath, body, "application/x-www-form-urlencoded", headers);
        REQUIRE(res != nullptr);
        return res;
    }

    double rejected_metric() {
        return metrics
            .counter("yuzu_server_dispatch_target_rejected_total",
                     {{"route", "dashboard"},
                      {"reason", std::string(yuzu::server::kReasonDestructiveUntargeted)}})
            .value();
    }
    int audits_with(const std::string& needle) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.detail.find(needle) != std::string::npos)
                ++n;
        return n;
    }
};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

// ── The pairs these tests are written against still mean what they claim ────

TEST_CASE("catalogue anchors: the three pairs under test hold their expected dispatch class",
          "[server][dashboard][execute][destructive]") {
    auto d = real_registry().classify(kDestructive.first, kDestructive.second);
    REQUIRE(d.has_value());
    CHECK(d->dispatch_class == DispatchClass::Destructive);

    auto r = real_registry().classify(kReadOnly.first, kReadOnly.second);
    REQUIRE(r.has_value());
    CHECK(r->dispatch_class == DispatchClass::ReadOnly);

    auto m = real_registry().classify(kMutating.first, kMutating.second);
    REQUIRE(m.has_value());
    CHECK(m->dispatch_class == DispatchClass::Mutating);
}

// ── Refusals: the three fan-out shapes ──────────────────────────────────────

TEST_CASE("dashboard execute: __all__ broadcast of a Destructive action is refused, counted, "
          "audited, and never dispatched",
          "[server][dashboard][execute][destructive][security]") {
    ExecHarness h;
    h.resolve_to = {kDestructive.first, kDestructive.second};

    auto res = h.post("instruction=purge&scope=__all__");

    CHECK(h.calls.empty()); // the security property, stated first
    CHECK(contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
    CHECK(h.rejected_metric() == 1.0);
    CHECK(h.audits_with(std::string(yuzu::server::kReasonDestructiveUntargeted)) == 1);
}

TEST_CASE("dashboard execute: group: scope fan-out of a Destructive action is refused",
          "[server][dashboard][execute][destructive][security]") {
    ExecHarness h;
    h.resolve_to = {kDestructive.first, kDestructive.second};

    auto res = h.post("instruction=purge&scope=group:eng");

    CHECK(h.calls.empty());
    CHECK(contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
    CHECK(h.rejected_metric() == 1.0);
}

TEST_CASE("dashboard execute: an OMITTED scope (fleet-by-omission) of a Destructive action is "
          "refused",
          "[server][dashboard][execute][destructive][security]") {
    // The shape an operator reaches by simply typing a command with no target
    // selected at all — the handler's own comment calls it "the legacy UI
    // contract: the whole fleet". Before PR6.0b this dispatched fleet-wide
    // with `broadcast_on_none=true` and no Destructive check anywhere.
    ExecHarness h;
    h.resolve_to = {kDestructive.first, kDestructive.second};

    auto res = h.post("instruction=purge");

    CHECK(h.calls.empty());
    CHECK(contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
    CHECK(h.rejected_metric() == 1.0);
}

// ── The gate must not widen: ReadOnly / Mutating are untouched ──────────────

TEST_CASE("dashboard execute: a ReadOnly action is unaffected on every fan-out shape",
          "[server][dashboard][execute][destructive][regression]") {
    SECTION("__all__ broadcast") {
        ExecHarness h;
        h.resolve_to = {kReadOnly.first, kReadOnly.second};
        h.post("instruction=version&scope=__all__");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].scope_expr == "__all__");
        CHECK(h.calls[0].agent_ids.empty());
        CHECK(h.rejected_metric() == 0.0);
    }
    SECTION("group: scope") {
        ExecHarness h;
        h.resolve_to = {kReadOnly.first, kReadOnly.second};
        h.post("instruction=version&scope=group:eng");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].scope_expr == "group:eng");
        CHECK(h.rejected_metric() == 0.0);
    }
    SECTION("omitted scope") {
        ExecHarness h;
        h.resolve_to = {kReadOnly.first, kReadOnly.second};
        h.post("instruction=version");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].scope_expr.empty());
        CHECK(h.calls[0].agent_ids.empty());
        CHECK(h.rejected_metric() == 0.0);
    }
}

TEST_CASE("dashboard execute: a Mutating action is unaffected on every fan-out shape",
          "[server][dashboard][execute][destructive][regression]") {
    SECTION("__all__ broadcast") {
        ExecHarness h;
        h.resolve_to = {kMutating.first, kMutating.second};
        h.post("instruction=settag&scope=__all__");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].scope_expr == "__all__");
        CHECK(h.rejected_metric() == 0.0);
    }
    SECTION("omitted scope") {
        ExecHarness h;
        h.resolve_to = {kMutating.first, kMutating.second};
        h.post("instruction=settag");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].agent_ids.empty());
        CHECK(h.rejected_metric() == 0.0);
    }
}

TEST_CASE("dashboard execute: a ReadOnly action with an explicit agent needs NO visible-agent "
          "store — the gate does not confine a non-Destructive dispatch",
          "[server][dashboard][execute][destructive][regression]") {
    // Sharpens the case above: with `mg == nullptr` a DESTRUCTIVE explicit-id
    // dispatch fails closed (next case), so if the gate ever applied its
    // confinement to ReadOnly rows this would break instead of dispatching.
    ExecHarness h{/*mg=*/nullptr};
    h.resolve_to = {kReadOnly.first, kReadOnly.second};
    h.post("instruction=version&scope=dev-A");
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"dev-A"});
}

// ── Confinement: fail-closed without a store, in-scope succeeds with one ────

TEST_CASE("dashboard execute: a Destructive action with an explicit agent FAILS CLOSED when no "
          "visible-agent store is wired",
          "[server][dashboard][execute][destructive][security]") {
    // `DestructiveVisibleAgents`' nullopt means DENY-ALL — the deliberate
    // opposite of `authz::VisibleSet`'s nullopt. An absent (or ADR-0042
    // degraded) read must empty the target list, never pass it through.
    ExecHarness h{/*mg=*/nullptr};
    h.resolve_to = {kDestructive.first, kDestructive.second};

    auto res = h.post("instruction=purge&scope=dev-A");

    CHECK(h.calls.empty());
    CHECK(contains(res->body, std::string(yuzu::server::kDestructiveNoVisibleAgentMessage)));
    // This is a confinement drop, not an untargeted refusal — the two arms
    // must stay distinguishable in the evidence they leave.
    CHECK(h.rejected_metric() == 0.0);
    CHECK(h.audits_with("scope_violation") == 1);
}

TEST_CASE("dashboard execute: a Destructive action DOES dispatch to an explicit, in-scope agent, "
          "and an out-of-scope one is dropped",
          "[pg][server][dashboard][execute][destructive][security]") {
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    REQUIRE(mg.is_open());
    grant_visibility(mg, {"dev-A", "dev-B"});

    SECTION("in-scope agent dispatches") {
        ExecHarness h{&mg};
        h.resolve_to = {kDestructive.first, kDestructive.second};
        auto res = h.post("instruction=purge&scope=dev-A");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].plugin == kDestructive.first);
        CHECK(h.calls[0].action == kDestructive.second);
        CHECK(h.calls[0].agent_ids == std::vector<std::string>{"dev-A"});
        CHECK(h.calls[0].scope_expr.empty());
        CHECK(h.rejected_metric() == 0.0);
        CHECK(!contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
    }
    SECTION("out-of-scope agent is confined out, not dispatched") {
        ExecHarness h{&mg};
        h.resolve_to = {kDestructive.first, kDestructive.second};
        auto res = h.post("instruction=purge&scope=dev-Z");
        CHECK(h.calls.empty());
        CHECK(contains(res->body, std::string(yuzu::server::kDestructiveNoVisibleAgentMessage)));
    }
    SECTION("__all__ is STILL refused even with a store that would confine it") {
        // Confinement is not a substitute for the targeting rule: broadcast is
        // refused outright, never narrowed to "the visible fleet".
        ExecHarness h{&mg};
        h.resolve_to = {kDestructive.first, kDestructive.second};
        auto res = h.post("instruction=purge&scope=__all__");
        CHECK(h.calls.empty());
        CHECK(contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
    }
}

// ── Fail-closed when the classifier itself is unwired ───────────────────────

TEST_CASE("dashboard execute: an UNWIRED classifier refuses every dispatch, not just Destructive "
          "ones",
          "[server][dashboard][execute][destructive][security]") {
    // The `ContainmentGate{}` lesson: if an unwired seam were permissive, a
    // dropped `set_capability_classify_fn` line in server.cpp would silently
    // revert this whole gate with every other test still green.
    SECTION("a Destructive action is refused") {
        ExecHarness h{/*mg=*/nullptr, /*wire_classifier=*/false};
        h.resolve_to = {kDestructive.first, kDestructive.second};
        auto res = h.post("instruction=purge&scope=dev-A");
        CHECK(h.calls.empty());
        CHECK(contains(res->body, "classification is unavailable"));
        CHECK(h.audits_with("classifier_unavailable") == 1);
    }
    SECTION("a ReadOnly action is refused too — the refusal is not class-dependent") {
        ExecHarness h{/*mg=*/nullptr, /*wire_classifier=*/false};
        h.resolve_to = {kReadOnly.first, kReadOnly.second};
        auto res = h.post("instruction=version&scope=__all__");
        CHECK(h.calls.empty());
        CHECK(contains(res->body, "classification is unavailable"));
    }
}

// ── The production branch is the one being driven ───────────────────────────

TEST_CASE("dashboard execute: the gate reads the DECODED scope param, not the raw-body fallback",
          "[server][dashboard][execute][destructive][security]") {
    // CDX-P1-01 / #1786: the handler reads `req.get_param_value("scope")`
    // first and only falls back to a raw-body scan. A percent-encoded field
    // NAME decodes into req.params but never matches the literal `scope=`
    // needle `extract_form_value` scans for, so the two branches see DIFFERENT
    // targeting for this request — which is what makes this case
    // discriminating rather than decorative:
    //   * production branch  → scope="dev-A" → an explicit id → `Targeted`,
    //                          then confinement fails closed (no store wired)
    //                          → "no reachable in-scope agent";
    //   * raw-body fallback  → scope=""      → no target at all →
    //                          `RefuseUntargeted` → the OTHER message.
    // A test asserting only "refused" would pass on either branch and prove
    // nothing about which one ran. `sc%6fpe` decodes to `scope`.
    ExecHarness h{/*mg=*/nullptr};
    h.resolve_to = {kDestructive.first, kDestructive.second};

    auto res = h.post("instruction=purge&sc%6fpe=dev-A");

    CHECK(h.calls.empty());
    CHECK(contains(res->body, std::string(yuzu::server::kDestructiveNoVisibleAgentMessage)));
    CHECK(!contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
    CHECK(h.rejected_metric() == 0.0);
}
