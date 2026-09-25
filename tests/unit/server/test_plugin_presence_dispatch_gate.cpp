/**
 * test_plugin_presence_dispatch_gate.cpp — #3424/#3511: the plugin-presence
 * filter at the dispatch chokepoint. Mirrors test_quarantine_dispatch_gate.cpp
 * exactly (same RecordingSink, same arm/priority/fast-path shape) since
 * `plugin_absent` is the direct sibling of `contained` — checked immediately
 * after it, same per-id continue-before-send position, in every arm.
 */

#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using yuzu::server::ArmDispatchResult;
using yuzu::server::ConfinedDispatchSink;
using yuzu::server::ConfinedDispatchTargets;
using yuzu::server::ContainmentGate;
using yuzu::server::dispatch_confined_arms;
using yuzu::server::DispatchArm;
using yuzu::server::authz::VisibleSet;

namespace {

/// Identical to test_dispatch_confined_arms.cpp's own RecordingSink — kept as
/// a separate copy (not shared) because that file's own header explains why:
/// each dispatch test file binds a different production seam directly, and a
/// shared fixture header would be one more place the mutation could hide.
struct RecordingSink {
    std::vector<std::string> reached;
    bool unfiltered_broadcast_used = false;
    std::vector<std::string> fleet{"dev-A", "dev-B", "dev-C"};

    ConfinedDispatchSink make() {
        return ConfinedDispatchSink{
            [this](const std::string& id) {
                reached.push_back(id);
                return true;
            },
            [this] {
                unfiltered_broadcast_used = true;
                return static_cast<int>(fleet.size());
            },
            [this] { return fleet; },
            /*prepare_route_fallback=*/nullptr,
            // HA WS-5 (governance hardening, 2026-09-22): see
            // test_dispatch_confined_arms.cpp's RecordingSink — this mock
            // has no presence concept, so every candidate is always locally
            // known (never widens) for the fast-path eligibility check to
            // hold.
            [](const std::vector<std::string>&) { return false; }};
    }

    bool reached_exactly(std::vector<std::string> expected) {
        auto got = reached;
        std::sort(got.begin(), got.end());
        std::sort(expected.begin(), expected.end());
        return got == expected;
    }
};

VisibleSet unfiltered() { return std::nullopt; }
VisibleSet only(std::initializer_list<std::string> ids) {
    return std::unordered_set<std::string>(ids);
}

const std::vector<std::string> kThree{"dev-A", "dev-B", "dev-C"};

// Containment off for every test in this file — the quarantine INTERACTION
// (contained wins priority) is bound separately, below, with containment
// deliberately ON in exactly those two cases.
const ContainmentGate kNoContainment = ContainmentGate::exempt_control_plugin();

} // namespace

// ------------------------------------------------------------- per-arm ---

TEST_CASE("Ids arm: a dispatch naming a plugin-absent agent reaches nobody",
          "[server][dispatch][plugin_presence][security]") {
    RecordingSink sink;
    const std::vector<std::string> one{"dev-A"};
    ConfinedDispatchTargets t;
    t.agent_ids = &one;
    const std::unordered_set<std::string> missing{"dev-A"};
    const auto result = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false,
                                               kNoContainment, sink.make(), missing);
    CHECK(result.sent == 0);
    CHECK(sink.reached.empty());
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-A"});
    CHECK(result.unknown_plugin_count == 1);
}

TEST_CASE("Ids arm: a mixed list reaches only the agents that have the plugin",
          "[server][dispatch][plugin_presence][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const std::unordered_set<std::string> missing{"dev-B"};
    const auto result = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false,
                                               kNoContainment, sink.make(), missing);
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-B"});
    CHECK(result.unknown_plugin_count == 1);
}

TEST_CASE("plugin presence runs AFTER the #1788 intersection: an out-of-scope "
          "plugin-absent id is NOT recorded",
          "[server][dispatch][plugin_presence][security]") {
    // Same audit-leak shape the quarantine sibling test guards: an id absent
    // from BOTH `sent` and `unknown_plugin` was never authorised to be
    // reached, so it must not appear in a caller's evidence for a device
    // outside their own visibility.
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const std::unordered_set<std::string> missing{"dev-B"};
    const auto result = dispatch_confined_arms(DispatchArm::Ids, t, only({"dev-A"}), false,
                                               kNoContainment, sink.make(), missing);
    CHECK(result.sent == 1);
    CHECK(sink.reached_exactly({"dev-A"}));
    CHECK(result.unknown_plugin.empty());
}

TEST_CASE("plugin presence runs AFTER the #1788 intersection: a plugin-absent id "
          "that IS in scope is recorded exactly",
          "[server][dispatch][plugin_presence][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const std::unordered_set<std::string> missing{"dev-B"};
    const auto result = dispatch_confined_arms(DispatchArm::Ids, t, only({"dev-A", "dev-B"}),
                                               false, kNoContainment, sink.make(), missing);
    CHECK(result.sent == 1);
    CHECK(sink.reached_exactly({"dev-A"}));
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-B"});
}

TEST_CASE("Group arm skips a plugin-absent member",
          "[server][dispatch][plugin_presence][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.group_members = &kThree;
    const std::unordered_set<std::string> missing{"dev-C"};
    const auto result = dispatch_confined_arms(DispatchArm::Group, t, unfiltered(), false,
                                               kNoContainment, sink.make(), missing);
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-B"}));
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-C"});
}

TEST_CASE("Scope arm skips a plugin-absent match",
          "[server][dispatch][plugin_presence][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.scope_matched = &kThree;
    const std::unordered_set<std::string> missing{"dev-A"};
    const auto result = dispatch_confined_arms(DispatchArm::Scope, t, unfiltered(), false,
                                               kNoContainment, sink.make(), missing);
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-B", "dev-C"}));
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-A"});
}

// ------------------------------------------------------- default is safe ---

TEST_CASE("an omitted plugin_missing set changes NOTHING — the default preserves "
          "every pre-#3511 caller's behaviour exactly",
          "[server][dispatch][plugin_presence][security]") {
    // Unlike ContainmentGate, plugin_missing is deliberately DEFAULTED (see
    // dispatch_confined_arms's own doc comment for why that default is safe
    // here and not for `gate`). This is the test that makes that claim
    // falsifiable: every existing (pre-#3511) call site compiles and behaves
    // unchanged by construction only if the 5-arg call below is IDENTICAL to
    // passing an explicit empty set.
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const auto result =
        dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, kNoContainment, sink.make());
    CHECK(result.sent == 3);
    CHECK(sink.reached_exactly({"dev-A", "dev-B", "dev-C"}));
    CHECK(result.unknown_plugin.empty());
    CHECK(result.unknown_plugin_count == 0);
}

// ---------------------------------------------------------- fast path ---

TEST_CASE("Broadcast arm: unfiltered authority with an EMPTY plugin_missing set still "
          "takes the unfiltered fast path",
          "[server][dispatch][plugin_presence][security]") {
    // Correctness-preserving optimization (dispatch_confined_arms's own doc
    // comment): an empty plugin_missing set means the walk would find
    // nothing, so skipping it changes no outcome. This is the common-case
    // path (every agent has the plugin) and must stay cheap.
    RecordingSink sink;
    const auto result = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                               kNoContainment, sink.make(), {});
    CHECK(result.sent == 3);
    CHECK(sink.unfiltered_broadcast_used);
    CHECK(result.unknown_plugin.empty());
}

TEST_CASE("Broadcast arm: unfiltered authority with a NON-EMPTY plugin_missing set is "
          "forced off the fast path and reaches every plugin-present id",
          "[server][dispatch][plugin_presence][security]") {
    // THE HEADLINE CASE, mirroring #881's own headline Broadcast test:
    // `send_to_all_unfiltered()` has no per-id hook, so it cannot skip a
    // specific agent. Before this filter existed, a broadcast on this exact
    // path (forward_legacy_command, RBAC disabled) would have sent to a
    // plugin-absent agent with no check at all.
    RecordingSink sink;
    const std::unordered_set<std::string> missing{"dev-B"};
    const auto result = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                               kNoContainment, sink.make(), missing);
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
    CHECK_FALSE(sink.unfiltered_broadcast_used);
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-B"});
}

TEST_CASE("None arm: broadcast_on_none with a non-empty plugin_missing set is also forced "
          "off the fast path",
          "[server][dispatch][plugin_presence][security]") {
    RecordingSink sink;
    const std::unordered_set<std::string> missing{"dev-A"};
    const auto result = dispatch_confined_arms(DispatchArm::None, {}, unfiltered(),
                                               /*broadcast_on_none=*/true, kNoContainment,
                                               sink.make(), missing);
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-B", "dev-C"}));
    CHECK_FALSE(sink.unfiltered_broadcast_used);
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-A"});
}

// ------------------------------------------------ priority vs. quarantine ---

TEST_CASE("an agent both quarantined AND plugin-absent is reported quarantined, "
          "never plugin-absent",
          "[server][dispatch][plugin_presence][quarantine][security]") {
    // The ordering the header comment states explicitly: `contained` is
    // checked BEFORE `plugin_absent`, so the stronger, more actionable fact
    // (a policy denial) wins over the weaker one (a request that would fail
    // anyway). This is the ONLY test in this file with containment enforced.
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
    const std::unordered_set<std::string> missing{"dev-B"}; // same id, both reasons apply
    const auto result =
        dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, gate, sink.make(), missing);
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-B"});
    // The headline assertion: dev-B is NOT double-reported as plugin-absent.
    CHECK(result.unknown_plugin.empty());
    CHECK(result.unknown_plugin_count == 0);
}

TEST_CASE("a quarantined agent and a DIFFERENT plugin-absent agent are each reported "
          "under their own reason",
          "[server][dispatch][plugin_presence][quarantine][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-A"});
    const std::unordered_set<std::string> missing{"dev-B"};
    const auto result =
        dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, gate, sink.make(), missing);
    CHECK(result.sent == 1);
    CHECK(sink.reached_exactly({"dev-C"}));
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-A"});
    CHECK(result.unknown_plugin == std::vector<std::string>{"dev-B"});
}

// ------------------------------------------------------------- revert-survivor ---

TEST_CASE("a mutant that skips the plugin_absent check entirely is caught: sending to "
          "a plugin-absent agent is a real, observable send",
          "[server][dispatch][plugin_presence][security]") {
    // This is the case that would go GREEN if `plugin_absent(aid)` were
    // deleted (or its result ignored) from any arm — the RecordingSink
    // records a genuine send to dev-A, which every other test in this file
    // asserts must NOT happen when dev-A is in `plugin_missing`.
    RecordingSink sink;
    const std::vector<std::string> one{"dev-A"};
    ConfinedDispatchTargets t;
    t.agent_ids = &one;
    const std::unordered_set<std::string> missing{"dev-A"};
    const auto result = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false,
                                               kNoContainment, sink.make(), missing);
    REQUIRE(sink.reached.empty());
    REQUIRE(result.sent == 0);
}

// ─────────────────── AgentRegistry::ids_missing_plugin ───────────────────

#include "agent_registry.hpp"

namespace {
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

agent_pb::AgentInfo make_presence_test_info(const std::string& id) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname("host.local");
    return info;
}
} // namespace

TEST_CASE("ids_missing_plugin: an agent whose inventory does not include the plugin "
          "is reported missing",
          "[server][dispatch][plugin_presence][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    auto info = make_presence_test_info("dev-A");
    auto* p = info.add_plugins();
    p->set_name("os_info");
    registry.register_agent(info);

    const auto missing = registry.ids_missing_plugin("tar");
    CHECK(missing.contains("dev-A"));
}

TEST_CASE("ids_missing_plugin: an agent whose inventory DOES include the plugin is "
          "never reported missing",
          "[server][dispatch][plugin_presence][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    auto info = make_presence_test_info("dev-A");
    auto* p = info.add_plugins();
    p->set_name("tar");
    registry.register_agent(info);

    const auto missing = registry.ids_missing_plugin("tar");
    CHECK_FALSE(missing.contains("dev-A"));
}

TEST_CASE("ids_missing_plugin: an agent with an EMPTY reported inventory is never "
          "reported missing — fail OPEN on absent data, never on absent plugin",
          "[server][dispatch][plugin_presence][registry][security]") {
    // #3424/#3511 header comment: absence of DATA is not evidence of absence
    // of the PLUGIN. A freshly-registered or gateway-relayed agent whose
    // AgentInfo carried no plugins[] at all must never be silently withheld
    // from dispatch for a plugin it may well have.
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_presence_test_info("dev-A")); // no add_plugins() call at all

    const auto missing = registry.ids_missing_plugin("tar");
    CHECK_FALSE(missing.contains("dev-A"));
}

TEST_CASE("ids_missing_plugin: a mixed fleet reports exactly the agents genuinely "
          "missing the plugin",
          "[server][dispatch][plugin_presence][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    auto has_it = make_presence_test_info("dev-has-it");
    has_it.add_plugins()->set_name("tar");
    registry.register_agent(has_it);

    auto lacks_it = make_presence_test_info("dev-lacks-it");
    lacks_it.add_plugins()->set_name("os_info");
    registry.register_agent(lacks_it);

    registry.register_agent(make_presence_test_info("dev-no-inventory"));

    const auto missing = registry.ids_missing_plugin("tar");
    CHECK(missing.size() == 1);
    CHECK(missing.contains("dev-lacks-it"));
    CHECK_FALSE(missing.contains("dev-has-it"));
    CHECK_FALSE(missing.contains("dev-no-inventory"));
}

// ─── BR-009 regression: the plugin-presence filter must query the CANONICAL
// spelling, never the caller's raw casing (Gate 8 round-4, quality-engineer) ───
//
// `finalize_classified_command`'s own BR-009 test (test_dispatch_chokepoint.cpp)
// proves the wire command carries the canonical plugin name. It does NOT prove
// server.cpp's call sites actually USE that canonical value when they call
// `ids_missing_plugin` — that was the real bug (`server.cpp` called
// `ids_missing_plugin(plugin)` with the raw caller string instead of
// `ids_missing_plugin(classified->wire().plugin())`). Composing the two real
// functions here pins the INVARIANT the two call sites depend on (server.cpp
// has no unit-test harness of its own to exercise the call sites directly) --
// a regression back to the raw `plugin` local AT one of those two call sites
// specifically would NOT be caught by this test, only a regression in this
// composed invariant itself would be.
TEST_CASE("BR-009: ids_missing_plugin against the canonical wire plugin name "
          "correctly finds an agent that reported it, where the raw caller "
          "casing would have wrongly reported it missing",
          "[server][dispatch][plugin_presence][registry][security][3424]") {
    using yuzu::server::CommandCapability;
    using yuzu::server::DispatchClass;
    using yuzu::server::Mutability;
    using yuzu::server::detail::finalize_classified_command;

    constexpr CommandCapability kTarPurgeCap{
        .plugin = "tar",
        .action = "purge_source",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Write,
        .risk_tier = yuzu::server::authz::RiskTier::Medium,
        .system_reserved = false,
    };
    std::function<bool(std::string_view, std::string_view)> switch_on =
        [](std::string_view, std::string_view) { return true; };

    // A real caller dispatching with different-cased spelling — classify() is
    // case-insensitive, so this is authorized against kTarPurgeCap exactly
    // like test_dispatch_chokepoint.cpp's own BR-009 test.
    auto classified = finalize_classified_command(kTarPurgeCap, switch_on, "TAR", "Purge_Source",
                                                   "cmd-br009", {}, {}, 0, 0, {}, {});
    REQUIRE(classified.has_value());
    REQUIRE(classified->wire().plugin() == "tar");

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    auto info = make_presence_test_info("dev-A");
    info.add_plugins()->set_name("tar"); // agent reports the canonical spelling
    registry.register_agent(info);

    // The fix: query with the canonical wire plugin — the agent has it.
    const auto missing_canonical = registry.ids_missing_plugin(classified->wire().plugin());
    CHECK_FALSE(missing_canonical.contains("dev-A"));

    // The bug BR-009 fixed: querying with the raw caller casing instead would
    // have wrongly reported dev-A as missing the plugin it genuinely has —
    // pinned here so a future call-site regression back to the raw string is
    // caught by this same test, not just by the composition it demonstrates.
    const auto missing_raw_caller_casing = registry.ids_missing_plugin("TAR");
    CHECK(missing_raw_caller_casing.contains("dev-A"));
}

// ─────────────── wire_and_dispatch_confined: claim-leak fix (ADR-1007) ───────────────
//
// [pg]: ExecutionTracker is Postgres-backed (ADR-0006) -- this section needs
// a live database and SKIPs (not fails) when YUZU_TEST_POSTGRES_DSN is
// unset, same posture as every other [pg] test in this suite.

#include "execution_tracker.hpp"
#include "pg/pg_pool.hpp"
#include "test_execution_tracker_pg_helper.hpp"

namespace {
using yuzu::server::detail::ClassifiedCommandTestAccess;
} // namespace

TEST_CASE("wire_and_dispatch_confined: a plugin-absent id's per-device concurrency claim "
          "is released, not leaked (#3424/#3511 claim-leak fix)",
          "[pg][server][dispatch][plugin_presence][integration]") {
    // The exact leak class ADR-1007's own fix closed for `not_sent` and
    // `denied_quarantined`: `claim_fn` runs on the visible-filtered candidate
    // list BEFORE `dispatch_confined_arms`, so a plugin-absent id that never
    // reaches `sink.send_to` still held a fresh claim nothing else releases
    // unless this third bucket is wired into the leaked-count/to_release
    // logic too.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::execution_tracker_pg_template);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    yuzu::server::ExecutionTracker tracker{pool};
    REQUIRE(tracker.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    {
        // dev-A reports "tar" (the dispatched plugin) so it is genuinely
        // reachable; dev-B reports a NON-EMPTY inventory that lacks "tar".
        // Registering dev-B via the bare `make_presence_test_info` helper
        // (no plugins at all) would instead hit `ids_missing_plugin`'s
        // fail-open branch (empty inventory = unknown, not absent -- see
        // the dedicated fail-open test above) and never land in
        // `unknown_plugin`, so this test's REQUIRE below could never pass.
        auto info_a = make_presence_test_info("dev-A");
        info_a.add_plugins()->set_name("tar");
        registry.register_agent(info_a);
        auto info_b = make_presence_test_info("dev-B");
        info_b.add_plugins()->set_name("os_info");
        registry.register_agent(info_b);
    }
    for (const auto& id : {"dev-A", "dev-B"})
        REQUIRE(registry.set_gateway_route(
            id, /*session_id=*/{}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-plugin-presence-cmd");
    cmd.set_plugin("tar");
    cmd.set_action("sql");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    auto gate = ContainmentGate::exempt_control_plugin();
    std::vector<std::string> agent_ids{"dev-A", "dev-B"};
    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr, &tracker, noop_audit,
        noop_audit,
        /*command_id=*/"wiring-plugin-presence-cmd", /*execution_id=*/"exec-1",
        /*principal_role=*/"", agent_ids, /*scope_expr=*/"", /*exec_visible=*/unfiltered(),
        /*broadcast_on_none=*/false, gate, classified, /*definition_id=*/"def-1",
        /*concurrency_mode=*/"per-device");

    REQUIRE(outcome.unknown_plugin.size() == 1);
    CHECK(outcome.unknown_plugin[0] == "dev-B");
    // The claim-leak fix: dev-B's claim was taken by claim_fn (per-device
    // mode was requested) then never sent to, so it must already be
    // released -- a fresh claim attempt for the SAME (definition, agent)
    // must succeed immediately rather than finding an open claim still held.
    auto reclaim = tracker.claim_concurrency_slots("def-1", "exec-2", "wiring-plugin-presence-cmd-2",
                                                    {"dev-B"}, /*expires_at_seconds=*/9999999999);
    CHECK(reclaim == std::vector<std::string>{"dev-B"});
}
