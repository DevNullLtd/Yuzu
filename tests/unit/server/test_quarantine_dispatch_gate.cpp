/**
 * test_quarantine_dispatch_gate.cpp — the #881 quarantine dispatch gate:
 * `ContainmentGate`, the plugin-name exemption predicate, the bounded-
 * staleness degradation policy, and the per-arm containment check itself.
 *
 * WHY THIS FILE EXISTS, SEPARATELY FROM test_dispatch_confined_arms.cpp.
 * That file binds the #1788 visible-set intersection — every case in it runs
 * with containment OFF (`kNoContainment`), so it stays a clean regression
 * suite for the pre-existing authz property and is not the place to grow the
 * #881 matrix. This file binds the SECOND, orthogonal filter
 * `dispatch_confined_arms` now applies after that intersection and before
 * the send: containment. Every case here sets `ContainmentGate::enforced =
 * true` (or drives the pure predicate/policy functions directly), so a
 * mutation that deletes the containment check — but leaves #1788's
 * `filter_to_scope`/`in_scope` calls intact — cannot hide behind either
 * file's suite.
 *
 * Three things are bound, matching the #881 spec's own layering:
 *   1. `is_quarantine_control_plugin` — the pure, case-insensitive
 *      whole-plugin exemption predicate. No store, no ServerImpl.
 *   2. `evaluate_quarantine_degradation` — the pure bounded-staleness
 *      degradation policy, driven with a fake reader. No store, no
 *      ServerImpl, no Postgres — the VERIFICATION VERDICT for this spec
 *      calls this fully provable on any host for exactly that reason.
 *   3. `dispatch_confined_arms`'s per-arm containment check itself, and
 *      `wire_and_dispatch_confined`'s threading of `denied_quarantined` all
 *      the way out through `ConfinedDispatchOutcome` — against a REAL
 *      `AgentRegistry` for the wiring test, mirroring K-1 in
 *      test_dispatch_confined_arms.cpp.
 *
 * `ServerImpl::make_containment_gate` itself — the glue that calls a real
 * `QuarantineStore::list_quarantined()` and holds `quarantine_snapshot_`
 * under its own mutex — is NOT exercised here: it needs a live Postgres pool
 * and is code-review-verified only, per this spec's own VERIFICATION
 * VERDICT. What IS provable without one, and is bound below, is that its
 * call PATTERN (one read, once per dispatch, feeding one gate that
 * `dispatch_confined_arms` never re-reads) is correct — a fake reader that
 * counts its own invocations makes a regression that moved the read inside
 * a per-agent loop fail loudly rather than merely being slow.
 */

#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
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
using yuzu::server::evaluate_quarantine_degradation;
using yuzu::server::is_quarantine_control_plugin;
using yuzu::server::kQuarantineGateOutcomeFailClosed;
using yuzu::server::kQuarantineGateOutcomeFresh;
using yuzu::server::kQuarantineGateOutcomeStale;
using yuzu::server::QuarantineSnapshot;
using yuzu::server::authz::VisibleSet;

namespace {

/// Records exactly who was reached — same shape as test_dispatch_confined_arms.cpp's
/// fixture; duplicated rather than shared because the two files are
/// independent translation units and this one's `fleet` needs to grow to 50
/// for the read-count test below.
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

} // namespace

// ============================================================ predicate ===

TEST_CASE("is_quarantine_control_plugin: exempts the quarantine plugin case-insensitively, "
          "without a store",
          "[server][dispatch][quarantine]") {
    CHECK(is_quarantine_control_plugin("quarantine", "unquarantine"));
    CHECK(is_quarantine_control_plugin("Quarantine", "unquarantine"));
    CHECK(is_quarantine_control_plugin("QUARANTINE", "UnQuarantine"));
    CHECK_FALSE(is_quarantine_control_plugin("quarantined", "unquarantine"));
    CHECK_FALSE(is_quarantine_control_plugin("quarantin", "unquarantine"));
    CHECK_FALSE(is_quarantine_control_plugin("", "unquarantine"));
    CHECK_FALSE(is_quarantine_control_plugin("firewall", "unquarantine"));
}

TEST_CASE("is_quarantine_control_plugin: the exemption is keyed on the ACTION too",
          "[server][dispatch][quarantine]") {
    // The four the plugin declares are exempt: release, the read, the
    // whitelist repair path, and the re-dispatch #3127 relies on.
    for (const auto* action : {"quarantine", "unquarantine", "status", "whitelist"}) {
        INFO("action=" << action);
        CHECK(is_quarantine_control_plugin("quarantine", action));
    }
    // A FIFTH action must NOT inherit the exemption by belonging to the same
    // plugin — that is the whole reason this is keyed on the pair. If someone
    // adds an action to the plugin, it arrives gated until it is named here
    // deliberately.
    for (const auto* action : {"exec", "run", "collect", "reset", ""}) {
        INFO("action=" << action);
        CHECK_FALSE(is_quarantine_control_plugin("quarantine", action));
    }
}

// =================================================== degradation policy ===

TEST_CASE("evaluate_quarantine_degradation: a successful read is fresh, no snapshot needed",
          "[server][dispatch][quarantine]") {
    const std::unordered_set<std::string> read{"dev-Q"};
    const auto result = evaluate_quarantine_degradation(read, /*fail_closed_regardless=*/false,
                                                         QuarantineSnapshot{},
                                                         std::chrono::steady_clock::now());
    CHECK(result.gate.enforced);
    CHECK_FALSE(result.gate.fail_closed);
    CHECK(result.gate.quarantined == read);
    CHECK(result.outcome == kQuarantineGateOutcomeFresh);
    REQUIRE(result.refreshed_snapshot.has_value());
    CHECK(result.refreshed_snapshot->ids == read);
    CHECK(result.refreshed_snapshot->valid);
}

TEST_CASE("evaluate_quarantine_degradation: nullopt with a 5s-old snapshot serves stale, "
          "fail_closed = false",
          "[server][dispatch][quarantine]") {
    const auto now = std::chrono::steady_clock::now();
    QuarantineSnapshot snapshot;
    snapshot.ids = {"dev-Q"};
    snapshot.at = now - std::chrono::seconds{5};
    snapshot.valid = true;

    const auto result = evaluate_quarantine_degradation(
        /*fresh_read=*/std::nullopt, /*fail_closed_regardless=*/false, snapshot, now);
    CHECK(result.gate.enforced);
    CHECK_FALSE(result.gate.fail_closed);
    CHECK(result.gate.quarantined == snapshot.ids);
    CHECK(result.outcome == kQuarantineGateOutcomeStale);
    CHECK_FALSE(result.refreshed_snapshot.has_value());
}

TEST_CASE("evaluate_quarantine_degradation: a read that was NEVER ATTEMPTED fails closed even "
          "with a perfectly fresh snapshot",
          "[server][dispatch][quarantine][security]") {
    // The distinction this whole parameter exists to draw, and the one an
    // earlier version of the read-concurrency bound got wrong.
    //
    // A `nullopt` fresh_read means the store was ASKED and could not answer —
    // riding that out on a recent snapshot is the bounded-staleness design, and
    // the case above covers it. `fail_closed_regardless` means nobody asked:
    // the store is not open, or the dispatch could not get a containment-read
    // slot within its budget. Serving stale there under-enforces against a
    // HEALTHY store — the read would have succeeded, and a device quarantined
    // since the snapshot gets dispatched to.
    //
    // The snapshot here is one second old, i.e. as good as a snapshot ever
    // gets. It must still fail closed, or the bound added to protect the
    // connection pool becomes a containment bypass.
    const auto now = std::chrono::steady_clock::now();
    QuarantineSnapshot snapshot{{"dev-A"}, now - std::chrono::seconds(1), true};

    const auto result = evaluate_quarantine_degradation(
        /*fresh_read=*/std::nullopt, /*fail_closed_regardless=*/true, snapshot, now);

    CHECK(result.gate.enforced);
    CHECK(result.gate.fail_closed);
    CHECK(result.outcome == yuzu::server::kQuarantineGateOutcomeFailClosed);
    // It must NOT be reported as `stale` — the two are different operator
    // conditions and the metric is what tells them apart.
    CHECK(result.outcome != yuzu::server::kQuarantineGateOutcomeStale);
    // And it must not adopt the snapshot's contents: under fail-closed the
    // gate reaches nobody, so a quarantined set would be meaningless here.
    CHECK(result.gate.quarantined.empty());
    CHECK_FALSE(result.refreshed_snapshot.has_value());
}

TEST_CASE("evaluate_quarantine_degradation: nullopt with a 120s-old snapshot fails closed",
          "[server][dispatch][quarantine]") {
    const auto now = std::chrono::steady_clock::now();
    QuarantineSnapshot snapshot;
    snapshot.ids = {"dev-Q"};
    snapshot.at = now - std::chrono::seconds{120};
    snapshot.valid = true;

    const auto result = evaluate_quarantine_degradation(
        /*fresh_read=*/std::nullopt, /*fail_closed_regardless=*/false, snapshot, now);
    CHECK(result.gate.enforced);
    CHECK(result.gate.fail_closed);
    CHECK(result.outcome == kQuarantineGateOutcomeFailClosed);
}

TEST_CASE("evaluate_quarantine_degradation: nullopt with no snapshot fails closed",
          "[server][dispatch][quarantine]") {
    const auto now = std::chrono::steady_clock::now();
    const auto result = evaluate_quarantine_degradation(
        /*fresh_read=*/std::nullopt, /*fail_closed_regardless=*/false, QuarantineSnapshot{},
        now);
    CHECK(result.gate.enforced);
    CHECK(result.gate.fail_closed);
    CHECK(result.outcome == kQuarantineGateOutcomeFailClosed);
}

TEST_CASE("evaluate_quarantine_degradation: a durably unavailable store fails closed regardless "
          "of a fresh, valid snapshot",
          "[server][dispatch][quarantine]") {
    // store_permanently_unavailable is checked BEFORE the snapshot-age
    // branch: it is a permanent condition (server.cpp refuses to start
    // without an open quarantine store), never worth riding out on a
    // snapshot no matter how fresh.
    const auto now = std::chrono::steady_clock::now();
    QuarantineSnapshot snapshot;
    snapshot.ids = {"dev-Q"};
    snapshot.at = now; // as fresh as a snapshot can be
    snapshot.valid = true;

    const auto result = evaluate_quarantine_degradation(
        /*fresh_read=*/std::nullopt, /*fail_closed_regardless=*/true, snapshot, now);
    CHECK(result.gate.enforced);
    CHECK(result.gate.fail_closed);
    CHECK(result.outcome == kQuarantineGateOutcomeFailClosed);
}

// ================================================= dispatch_confined_arms ===
// Quarantine containment (#881) — the SECOND filter `dispatch_confined_arms`
// now applies, after the #1788 visible-set intersection and before the
// send. Every case below sets `ContainmentGate::enforced = true`.

TEST_CASE("Broadcast arm: enforced containment with unfiltered authority reaches every "
          "non-quarantined id and none quarantined, and NEVER takes the unfiltered fast path",
          "[server][dispatch][quarantine][security]") {
    // THE HEADLINE CASE (#881): exec_visible == nullopt (genuinely unfiltered
    // system authority, e.g. command_dispatch_fn's DispatchCaller{.system =
    // true}) combined with enforced containment. Before #881 this combination
    // took send_to_all_unfiltered() with no per-id check at all — the exact
    // hole a quarantined agent walked through on the fast path.
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
    const auto result =
        dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false, gate, sink.make());
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
    CHECK_FALSE(sink.unfiltered_broadcast_used);
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-B"});
}

TEST_CASE("Broadcast arm: enforced = false preserves the unfiltered fast path exactly",
          "[server][dispatch][quarantine][security]") {
    // The exemption case (#881): with containment OFF (the quarantine
    // plugin's own control channel, or containment simply not enforced for
    // this dispatch), unfiltered authority still takes the fast path exactly
    // as it did before #881 — pre-existing behaviour is unchanged.
    RecordingSink sink;
    auto gate = ContainmentGate::exempt_control_plugin(); // containment off
    const auto result =
        dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false, gate, sink.make());
    CHECK(result.sent == 3);
    CHECK(sink.unfiltered_broadcast_used);
    CHECK(result.denied_quarantined.empty());
}

TEST_CASE("Ids arm: a dispatch to a quarantined agent reaches nobody",
          "[server][dispatch][quarantine][security]") {
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-A"});
    const std::vector<std::string> one{"dev-A"};
    ConfinedDispatchTargets t;
    t.agent_ids = &one;
    const auto result =
        dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, gate, sink.make());
    CHECK(result.sent == 0);
    CHECK(sink.reached.empty());
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-A"});
}

TEST_CASE("Ids arm: a mixed list reaches only the non-quarantined ids",
          "[server][dispatch][quarantine][security]") {
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const auto result =
        dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, gate, sink.make());
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-B"});
}

TEST_CASE("containment runs AFTER the #1788 intersection: an out-of-scope quarantined id is "
          "NOT recorded as a containment denial",
          "[server][dispatch][quarantine][security]") {
    // The header's own audit contract (dispatch_confined_arms.hpp): an id
    // absent from both `sent` and `denied_quarantined` was never AUTHORISED
    // to be reached in the first place; only an id the caller could actually
    // have reached is a containment denial. A reorder that moved the gate
    // ABOVE the visible-set intersection would leave send behaviour
    // identical (dev-B is unreachable either way) but would leak an id the
    // operator cannot see into their own audit rows — a cross-tenant
    // disclosure through the audit trail this test exists to catch.
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const auto result =
        dispatch_confined_arms(DispatchArm::Ids, t, only({"dev-A"}), false, gate, sink.make());
    CHECK(result.sent == 1);
    CHECK(sink.reached_exactly({"dev-A"}));
    CHECK(result.denied_quarantined.empty());
}

TEST_CASE("containment runs AFTER the #1788 intersection: a quarantined id that IS in scope "
          "is recorded exactly",
          "[server][dispatch][quarantine][security]") {
    // The companion case to the one above: when the quarantined id survives
    // the visible-set intersection, it MUST appear in `denied_quarantined` —
    // this pins the positive half so the negative-case test above cannot be
    // satisfied by a gate that never records anything.
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const auto result = dispatch_confined_arms(DispatchArm::Ids, t, only({"dev-A", "dev-B"}),
                                               false, gate, sink.make());
    CHECK(result.sent == 1);
    CHECK(sink.reached_exactly({"dev-A"}));
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-B"});
}

TEST_CASE("Group arm skips a quarantined member", "[server][dispatch][quarantine][security]") {
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-C"});
    ConfinedDispatchTargets t;
    t.group_members = &kThree;
    const auto result =
        dispatch_confined_arms(DispatchArm::Group, t, unfiltered(), false, gate, sink.make());
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-B"}));
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-C"});
}

TEST_CASE("Scope arm skips a quarantined match", "[server][dispatch][quarantine][security]") {
    RecordingSink sink;
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-A"});
    ConfinedDispatchTargets t;
    t.scope_matched = &kThree;
    const auto result =
        dispatch_confined_arms(DispatchArm::Scope, t, unfiltered(), false, gate, sink.make());
    CHECK(result.sent == 2);
    CHECK(sink.reached_exactly({"dev-B", "dev-C"}));
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-A"});
}

TEST_CASE("fail_closed reaches NOBODY on every arm, including Broadcast",
          "[server][dispatch][quarantine][security]") {
    auto gate = ContainmentGate::enforcing(/*fail_closed=*/true, {});
    // No entries in `quarantined` at all — fail_closed alone must withhold
    // everything, proving the two conditions are independently sufficient.
    //
    // On the reporting contract these assertions pin: a fail-closed denial
    // reports a COUNT and deliberately does NOT collect the ids. It denies
    // every target, so collecting them builds a fleet-sized vector<string> on
    // the dispatch thread, per refused dispatch, during the store degradation
    // that caused the refusal — purely so callers can take .size(), which is
    // all any of them do (the audit path emits ONE aggregate row for a
    // fail-closed denial, never one per device). The identities carry no
    // information the gate state does not already imply. So the assertion here
    // is `denied_quarantined_count == 3` AND `denied_quarantined.empty()` —
    // both halves, so a future change that starts collecting again is caught
    // rather than quietly reintroducing the allocation.

    {
        RecordingSink sink;
        ConfinedDispatchTargets t;
        t.agent_ids = &kThree;
        const auto result =
            dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, gate, sink.make());
        CHECK(result.sent == 0);
        CHECK(sink.reached.empty());
        CHECK(result.denied_quarantined_count == kThree.size());
        CHECK(result.denied_quarantined.empty());
    }
    {
        RecordingSink sink;
        ConfinedDispatchTargets t;
        t.group_members = &kThree;
        const auto result =
            dispatch_confined_arms(DispatchArm::Group, t, unfiltered(), false, gate, sink.make());
        CHECK(result.sent == 0);
        CHECK(sink.reached.empty());
        CHECK(result.denied_quarantined_count == kThree.size());
        CHECK(result.denied_quarantined.empty());
    }
    {
        RecordingSink sink;
        ConfinedDispatchTargets t;
        t.scope_matched = &kThree;
        const auto result =
            dispatch_confined_arms(DispatchArm::Scope, t, unfiltered(), false, gate, sink.make());
        CHECK(result.sent == 0);
        CHECK(sink.reached.empty());
        CHECK(result.denied_quarantined_count == kThree.size());
        CHECK(result.denied_quarantined.empty());
    }
    {
        RecordingSink sink;
        const auto result = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                                    gate, sink.make());
        CHECK(result.sent == 0);
        CHECK(sink.reached.empty());
        CHECK_FALSE(sink.unfiltered_broadcast_used);
        // The count is exact even on Broadcast, where the target set is the
        // whole known fleet — that exactness is what lets the audit row and
        // the response body report a true number while collecting nothing.
        CHECK(result.denied_quarantined_count == kThree.size());
        CHECK(result.denied_quarantined.empty());
    }
}

TEST_CASE("the quarantine read happens exactly once per dispatch, never per agent, for a "
          "50-agent broadcast",
          "[server][dispatch][quarantine]") {
    // WHAT THIS ACTUALLY BINDS: `dispatch_confined_arms` takes a
    // `ContainmentGate` BY VALUE and has no reference to any reader at all —
    // so a regression that moved a store read inside its per-id `contained()`
    // check would be a COMPILE ERROR, not a count that climbs to 50. That
    // stronger, type-level guarantee is what this test demonstrates: the
    // fake reader is invoked to build ONE gate (via
    // `evaluate_quarantine_degradation`, mirroring
    // `ServerImpl::make_containment_gate`'s own call pattern), and the
    // assertion that `read_count` is still 1 after walking a 50-id broadcast
    // is a sanity check on the harness, not a property that could fail from
    // a mutation inside `dispatch_confined_arms` itself. The property THIS
    // test does not and cannot bind is `ServerImpl::make_containment_gate`
    // being called once per dispatch rather than once per arm branch or once
    // per agent inside `ServerImpl` — that call site has no fake reader
    // seam today and is code-review-verified only.
    int read_count = 0;
    const auto counting_read = [&]() -> std::optional<std::unordered_set<std::string>> {
        ++read_count;
        return std::unordered_set<std::string>{"dev-0"};
    };

    const auto decision = evaluate_quarantine_degradation(
        counting_read(), /*fail_closed_regardless=*/false, QuarantineSnapshot{},
        std::chrono::steady_clock::now());
    CHECK(read_count == 1);
    CHECK(decision.gate.enforced);
    CHECK_FALSE(decision.gate.fail_closed);

    RecordingSink sink;
    std::vector<std::string> fleet;
    fleet.reserve(50);
    for (int i = 0; i < 50; ++i)
        fleet.push_back("dev-" + std::to_string(i));
    sink.fleet = fleet;

    const auto result = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                               decision.gate, sink.make());
    CHECK(read_count == 1); // still exactly one read after walking all 50 ids
    CHECK(result.sent == 49);
    CHECK(result.denied_quarantined == std::vector<std::string>{"dev-0"});
}

// ============================================= wire_and_dispatch_confined ===
// K-1-style wiring test (mirrors test_dispatch_confined_arms.cpp's own): a
// REAL `AgentRegistry`, proving `denied_quarantined` survives the
// resolve_and_dispatch_confined -> wire_and_dispatch_confined boundary intact,
// with exact contents. `wire_and_dispatch_confined` has no audit hook of its
// own — audit is a caller responsibility (`ServerImpl::dispatch_confined`'s
// own post-call loop, code-review-verified only) — so that half is out of
// scope for this seam; see the note on the test case itself.

#include "agent_registry.hpp"

namespace {
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::ClassifiedCommandTestAccess;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

agent_pb::AgentInfo make_wiring_test_info(const std::string& id) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname("host.local");
    return info;
}
} // namespace

TEST_CASE("wire_and_dispatch_confined: denied_quarantined survives out through "
          "ConfinedDispatchOutcome with exact contents (#881)",
          "[server][dispatch][quarantine][integration]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    for (const auto& id : {"dev-A", "dev-B", "dev-C"}) {
        registry.register_agent(make_wiring_test_info(id));
        REQUIRE(registry.set_gateway_route(
            id, /*session_id=*/{}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
    }

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-quarantine-cmd");
    cmd.set_plugin("os_info");
    cmd.set_action("version");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
    std::vector<std::string> agent_ids{"dev-A", "dev-B", "dev-C"};

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"wiring-quarantine-cmd", /*execution_id=*/"", /*principal_role=*/"",
        agent_ids, /*scope_expr=*/"", /*exec_visible=*/unfiltered(), /*broadcast_on_none=*/false,
        gate, classified);

    CHECK(outcome.sent == 2);
    CHECK(outcome.command_id == "wiring-quarantine-cmd");
    REQUIRE(outcome.denied_quarantined.size() == 1);
    CHECK(outcome.denied_quarantined[0] == "dev-B");

    // NOTE ON SCOPE: this proves `denied_quarantined` threads intact across
    // the resolve_and_dispatch_confined -> wire_and_dispatch_confined
    // boundary — the half of AC 12 this seam can actually bind, since
    // `wire_and_dispatch_confined` has no audit hook of its own (audit is a
    // caller responsibility, wired by `ServerImpl::dispatch_confined`'s own
    // loop over `outcome.denied_quarantined`). It does NOT exercise
    // `ServerImpl::audit_quarantine_dispatch_denied` or the counter/audit
    // fan-out `ServerImpl::dispatch_confined` performs with this list —
    // those are code-review-verified only, same as this spec's own
    // VERIFICATION VERDICT states for the rest of the ServerImpl wiring.
}

// ── CDX-P1-06: bind the PRODUCTION composition, not just the pure helpers ──
//
// The degradation policy and the arm intersection were each well covered, but
// the composition between them — the plugin exemption, and the decision to
// build an ENFORCED gate at all — lived only inside
// ServerImpl::make_containment_gate where no test could reach it. Making the
// exemption unconditional there disabled containment for EVERY plugin and this
// entire suite still passed. These cases fail if that happens again.

TEST_CASE("compose_containment_gate: a non-control plugin gets an ENFORCED gate",
          "[dispatch][quarantine][server]") {
    using namespace yuzu::server;
    QuarantineSnapshot snap;
    const auto now = std::chrono::steady_clock::now();
    std::unordered_set<std::string> quarantined{"dev-A"};

    const auto d = compose_containment_gate("firewall", "exec", /*store_unavailable=*/false,
                                            std::optional{quarantined}, snap, now);
    // THE mutation guard: if the exemption is ever made unconditional, or the
    // gate stops being enforced for ordinary plugins, this fails.
    CHECK(d.gate.enforced);
    CHECK_FALSE(d.gate.fail_closed);
    CHECK(d.gate.quarantined.contains("dev-A"));
}

TEST_CASE("compose_containment_gate: ONLY the quarantine control plugin is exempt",
          "[dispatch][quarantine][server]") {
    using namespace yuzu::server;
    const auto now = std::chrono::steady_clock::now();
    std::unordered_set<std::string> quarantined{"dev-A"};

    for (const auto* plugin : {"firewall", "services", "tar", "quarantine_helper", ""}) {
        QuarantineSnapshot snap;
        const auto d = compose_containment_gate(plugin, "exec", false, std::optional{quarantined}, snap, now);
        INFO("plugin=" << plugin);
        CHECK(d.gate.enforced);
    }
    QuarantineSnapshot snap;
    const auto exempt = compose_containment_gate("quarantine", "unquarantine", false, std::optional{quarantined},
                                                 snap, now);
    CHECK_FALSE(exempt.gate.enforced);
    CHECK(exempt.outcome == "exempt_control_plugin");
}

TEST_CASE("compose_containment_gate: the exemption does not consult the store",
          "[dispatch][quarantine][server]") {
    using namespace yuzu::server;
    QuarantineSnapshot snap;
    const auto now = std::chrono::steady_clock::now();
    // Store durably unavailable AND no read available: release must still be
    // exempt, because a store outage must never block the path that lifts a
    // quarantine.
    const auto d = compose_containment_gate("quarantine", "unquarantine", /*store_unavailable=*/true,
                                            std::nullopt, snap, now);
    CHECK_FALSE(d.gate.enforced);
    CHECK_FALSE(d.gate.fail_closed);
}

TEST_CASE("compose_containment_gate: a slower concurrent read cannot rewind the snapshot",
          "[dispatch][quarantine][server]") {
    using namespace yuzu::server;
    const auto t0 = std::chrono::steady_clock::now();
    const auto t1 = t0 + std::chrono::seconds(5);
    QuarantineSnapshot snap;

    // The newer read lands first and advances the snapshot...
    compose_containment_gate("firewall", "exec", false, std::optional{std::unordered_set<std::string>{"new"}},
                             snap, t1);
    REQUIRE(snap.valid);
    REQUIRE(snap.at == t1);

    // ...then an older, slower read completes. It must NOT overwrite it.
    compose_containment_gate("firewall", "exec", false, std::optional{std::unordered_set<std::string>{"old"}},
                             snap, t0);
    CHECK(snap.at == t1);
    CHECK(snap.ids.contains("new"));
}
