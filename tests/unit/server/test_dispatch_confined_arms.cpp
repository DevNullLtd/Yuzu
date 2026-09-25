/**
 * test_dispatch_confined_arms.cpp — the PRODUCTION per-arm visible-set
 * intersection (#1788), bound by exact-send-set assertions.
 *
 * WHY THIS FILE EXISTS. The confinement work was previously "proven" by route
 * mocks that recorded the VisibleSet handed to a permissive dispatch stub and
 * asserted nothing about delivery. Those tests stayed GREEN with the
 * intersection deleted from production — a false-green offered as closure
 * evidence for a blocking finding (CDX-R8-02/CDX-FV-01, confirmed
 * independently by both external reviewers: removing `filter_to_scope` from
 * the seam left all six of them passing).
 *
 * These tests bind the real thing. `dispatch_confined_arms` is the ONE
 * implementation both `ServerImpl::dispatch_confined` and the `/api/command`
 * handler call, and here it runs against a recording sink that captures the
 * EXACT set of agents reached. Delete any single `in_scope`/`filter_to_scope`
 * call in it and cases below fail, because they assert who was reached — not
 * that a set was passed along.
 *
 * The matrix is every arm x each of the three VisibleSet states ADR-0033 §1
 * defines: nullopt = unfiltered, present-subset = narrowed, present-EMPTY =
 * deny-all (NOT "no filter"). The present-empty column is the fail-closed
 * contract every unwired-derivation path depends on.
 */

#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

using yuzu::server::ArmDispatchResult;
using yuzu::server::ConfinedDispatchOutcome;
using yuzu::server::ConfinedDispatchSink;
using yuzu::server::ConfinedDispatchTargets;
using yuzu::server::ContainmentGate;
using yuzu::server::dispatch_confined_arms;
using yuzu::server::DispatchArm;
using yuzu::server::DispatchResolvers;
using yuzu::server::resolve_and_dispatch_confined;
using yuzu::server::resolve_scope_targets;
using yuzu::server::ScopeLadderAudit;
using yuzu::server::ScopeLadderResult;
using yuzu::server::authz::VisibleSet;

namespace {

/// Records exactly who was reached. `send_to_all_unfiltered` is deliberately
/// distinguishable from a per-agent walk: the unfiltered fast path is only
/// legitimate when the caller's authority is genuinely unfiltered (nullopt),
/// and a present-empty set reaching it would be the fail-open we are guarding.
struct RecordingSink {
    std::vector<std::string> reached;
    bool unfiltered_broadcast_used = false;
    std::vector<std::string> fleet{"dev-A", "dev-B", "dev-C"};
    // HA WS-5 (governance hardening, 2026-09-22): override point for a test
    // that simulates presence widening known_agent_ids() beyond the local
    // registry — nullopt (the default) means "no presence", i.e. every id in
    // `fleet` is locally known, exactly as it was before this field existed.
    // When set, names the LOCAL-ONLY subset of `fleet`; any candidate not in
    // it is treated as presence-only (mirrors AgentRegistry::
    // has_remote_presence's direct-membership-check semantics, not a size
    // comparison — a size-based mock would reintroduce the exact race class
    // that method was written to close).
    std::optional<std::vector<std::string>> local_only_override;
    std::optional<std::vector<std::string>> route_fallback_candidates;

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
            [this](const std::vector<std::string>& candidates) {
                route_fallback_candidates = candidates;
                return false; // never degraded, in this mock
            },
            [this](const std::vector<std::string>& candidates) {
                const auto& local = local_only_override ? *local_only_override : fleet;
                return std::any_of(candidates.begin(), candidates.end(), [&](const auto& id) {
                    return std::find(local.begin(), local.end(), id) == local.end();
                });
            }};
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
VisibleSet deny_all() { return std::unordered_set<std::string>{}; }

const std::vector<std::string> kThree{"dev-A", "dev-B", "dev-C"};

/// #881: containment disabled — every test in this file exercises
/// `dispatch_confined_arms` with quarantine enforcement OFF, so a mutation
/// that deletes the containment check entirely cannot hide behind these
/// cases; that mutation is bound separately in
/// test_quarantine_dispatch_gate.cpp, which sets `enforced = true`.
// Containment off. Named rather than default-constructed: ContainmentGate
// has no default state, precisely so a production call site cannot reach the
// permissive one by omission.
const ContainmentGate kNoContainment = ContainmentGate::exempt_control_plugin();

} // namespace

// ---------------------------------------------------------------- Ids arm ---

TEST_CASE("Ids arm: unfiltered authority reaches every named agent",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const int sent =
        dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, kNoContainment, sink.make())
            .sent;
    CHECK(sent == 3);
    CHECK(sink.reached_exactly({"dev-A", "dev-B", "dev-C"}));
}

TEST_CASE("Ids arm: an out-of-scope id is DROPPED, not reached",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Ids, t, only({"dev-B"}), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    // The security property, stated positively: the hidden agents were never sent to.
    CHECK(std::find(sink.reached.begin(), sink.reached.end(), "dev-A") == sink.reached.end());
    CHECK(std::find(sink.reached.begin(), sink.reached.end(), "dev-C") == sink.reached.end());
}

TEST_CASE("Ids arm: a present-EMPTY visible set reaches NOBODY (fail-closed)",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const int sent =
        dispatch_confined_arms(DispatchArm::Ids, t, deny_all(), false, kNoContainment, sink.make())
            .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// -------------------------------------------------------------- Group arm ---

TEST_CASE("Group arm: members outside the visible set are dropped",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.group_members = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Group, t, only({"dev-A", "dev-C"}), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
}

TEST_CASE("Group arm: a management group is targeting, never an authz exemption",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.group_members = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Group, t, deny_all(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
}

TEST_CASE("Group arm: an unavailable management-group store reaches nobody",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t; // group_members left null == store unavailable
    const int sent = dispatch_confined_arms(DispatchArm::Group, t, unfiltered(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
}

// -------------------------------------------------------------- Scope arm ---

TEST_CASE("Scope arm: the matched set is intersected before dispatch",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.scope_matched = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Scope, t, only({"dev-C"}), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-C"}));
}

TEST_CASE("Scope arm: aborted resolution (null) reaches nobody — ADR-0036 fail-closed",
          "[server][dispatch][scope][security]") {
    // A parse failure / degraded DB / failed owner check leaves scope_matched
    // null. Reaching nobody is load-bearing: under a NOT combinator an
    // unresolved atom would otherwise invert to match-the-entire-fleet.
    RecordingSink sink;
    ConfinedDispatchTargets t; // scope_matched null
    const int sent = dispatch_confined_arms(DispatchArm::Scope, t, unfiltered(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// ---------------------------------------------------------- Broadcast arm ---

TEST_CASE("Broadcast arm: unfiltered authority uses the fast send-to-all path",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 3);
    CHECK(sink.unfiltered_broadcast_used);
}

TEST_CASE("Broadcast arm: a named __all__ is still narrowed to the visible set",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, only({"dev-B"}), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    // Naming the broadcast must NOT buy the unfiltered path.
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("Broadcast arm: present-EMPTY reaches nobody and never falls back to send-to-all",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, deny_all(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// HA WS-5 (ADR-2002 §7a): once known_agent_ids() can include presence-only
// (remote) ids, an unfiltered Broadcast is no longer safe to answer with the
// local-only fast path — it must fall through to the per-id walk so a
// remote id gets a directory-fallback consult via prepare_route_fallback
// before send_to. This is the exact bug class WS-4 hit twice (a
// wired-but-behaviorally-dead reader) — see ConfinedDispatchSink::
// presence_widens's doc comment.
TEST_CASE("Broadcast arm: presence widening known_agent_ids skips the unfiltered fast path "
          "and consults the route fallback",
          "[server][dispatch][scope][security][ha]") {
    RecordingSink sink;
    sink.fleet = {"dev-A", "dev-B", "dev-C", "remote-only"}; // presence added "remote-only"
    sink.local_only_override = {"dev-A", "dev-B", "dev-C"};  // local registry still has 3
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK_FALSE(sink.unfiltered_broadcast_used); // fast path correctly skipped
    REQUIRE(sink.route_fallback_candidates.has_value());
    CHECK(sink.reached_exactly(*sink.route_fallback_candidates));
    CHECK(sent == 4);
    CHECK(sink.reached_exactly({"dev-A", "dev-B", "dev-C", "remote-only"}));
}

TEST_CASE("Broadcast arm: presence adding nothing beyond local keeps the unfiltered fast path",
          "[server][dispatch][scope][security][ha]") {
    RecordingSink sink;
    sink.local_only_override = sink.fleet; // presence configured, adds nothing this call
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK(sink.unfiltered_broadcast_used);
    CHECK_FALSE(sink.route_fallback_candidates.has_value()); // fast path never calls it
    CHECK(sent == 3);
}

// HA WS-5 governance hardening (Gate 4 unhappy-path finding, 2026-09-22):
// regression test for the race the size-comparison design had — a
// COINCIDENTAL size match between known_agent_ids() and a separately-queried
// local count must NOT fool the gate when the SETS genuinely differ. This
// mock can't reproduce the original two-call race directly (RecordingSink's
// presence_widens closure and known_agent_ids share one `fleet`/
// `local_only_override` snapshot with no window between them), but it does
// assert the CURRENT single-call membership-check semantics hold even when
// sizes happen to be equal by construction: replacing one local id with a
// same-count remote-only id must still force the slow path.
TEST_CASE("Broadcast arm: a same-size but different-membership candidate set still "
          "skips the fast path (regression: size comparison is not membership)",
          "[server][dispatch][scope][security][ha]") {
    RecordingSink sink;
    sink.fleet = {"dev-A", "dev-B", "remote-only"}; // 3 candidates
    sink.local_only_override = {"dev-A", "dev-B", "dev-C"}; // ALSO 3 — sizes match, sets don't
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                            kNoContainment, sink.make())
                         .sent;
    CHECK_FALSE(sink.unfiltered_broadcast_used);
    REQUIRE(sink.route_fallback_candidates.has_value());
    CHECK(sent == 3);
}

// --------------------------------------------------------------- None arm ---

TEST_CASE("None arm: the shared closure reaches NOBODY, not everybody (#2500)",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::None, {}, unfiltered(),
                                            /*broadcast_on_none=*/false, kNoContainment,
                                            sink.make())
                         .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("None arm: broadcast_on_none honours a deliberate fleet selection, still narrowed",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::None, {}, only({"dev-A"}),
                                            /*broadcast_on_none=*/true, kNoContainment,
                                            sink.make())
                         .sent;
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-A"}));
}

TEST_CASE("None arm: broadcast_on_none with a present-EMPTY set still reaches nobody",
          "[server][dispatch][scope][security]") {
    // The unwired-ExecVisibleFn path: dashboard/MCP substitute a present-empty
    // set rather than nullopt, so failing closed must survive broadcast_on_none.
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::None, {}, deny_all(),
                                            /*broadcast_on_none=*/true, kNoContainment,
                                            sink.make())
                         .sent;
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// ===================================================================================
// resolve_and_dispatch_confined — the "middle link" (QE-2).
//
// Every test above feeds dispatch_confined_arms a HAND-BUILT DispatchArm and
// ConfinedDispatchTargets — it never exercises the classification
// (classify_dispatch_arm) or the arm-specific target resolution (group store /
// scope ladder) that `ServerImpl::dispatch_confined` and `/api/command` do
// BEFORE calling it. Nothing bound that: replacing the call in
// `ServerImpl::dispatch_confined` with a bare `for (id : agent_ids)
// send_to(id)` left all 12 tests above green (QE-2).
//
// These tests call `resolve_and_dispatch_confined` — the actual shared
// implementation `ServerImpl::dispatch_confined` now delegates to entirely —
// with the SAME (agent_ids, scope_expr) inputs a real caller supplies, so a
// regression collapsing the classification/resolution to a naive loop over
// `agent_ids` fails every case here that is not coincidentally an Ids arm
// under an unfiltered visible set.
// ===================================================================================

namespace {

DispatchResolvers no_group_no_scope_resolvers() { return DispatchResolvers{}; }

} // namespace

TEST_CASE("resolve_and_dispatch_confined: Ids arm is classified and intersected end-to-end",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const std::vector<std::string> ids{"dev-A", "dev-B", "dev-C"};
    const auto outcome = resolve_and_dispatch_confined(
        ids, /*scope_expr=*/"", only({"dev-B"}), /*broadcast_on_none=*/false, kNoContainment,
        no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    // The security property, stated positively: dev-A/dev-C were never sent to
    // despite being named — a naive unfiltered loop would have reached them.
    CHECK(std::find(sink.reached.begin(), sink.reached.end(), "dev-A") == sink.reached.end());
}

TEST_CASE("resolve_and_dispatch_confined: a fail-closed containment gate sets "
          "containment_unreadable through the REAL derivation, not a hand-built struct "
          "(CH-3, Gate 5)",
          "[server][dispatch][scope][security][3424]") {
    // `outcome.containment_unreadable = gate.enforced && gate.fail_closed` lives in
    // resolve_and_dispatch_confined (dispatch_scope_ladder.hpp), NOT in
    // dispatch_confined_arms — the inner function the sibling fail-closed test above
    // calls directly. Every other `containment_unreadable` test in this codebase (MCP,
    // REST, dashboard) constructs a `ConfinedDispatchOutcome` by hand and sets the field
    // itself, so none of them exercises this line. This test calls the same
    // classify-then-dispatch entry point `ServerImpl::dispatch_confined` delegates to,
    // with the same (agent_ids, scope_expr) shape a real caller supplies — a regression
    // that stopped deriving the field here (e.g. reverted to always-false, or read the
    // wrong gate field) fails this test while every fake-struct test stays green.
    RecordingSink sink;
    const std::vector<std::string> ids{"dev-A", "dev-B"};
    const auto gate = ContainmentGate::enforcing(/*fail_closed=*/true, {});
    const auto outcome = resolve_and_dispatch_confined(
        ids, /*scope_expr=*/"", unfiltered(), /*broadcast_on_none=*/false, gate,
        no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.containment_unreadable);
    CHECK(outcome.sent == 0);
    CHECK(sink.reached.empty());
}

TEST_CASE("resolve_and_dispatch_confined: Group arm resolves via the injected group store, "
          "then intersects",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    std::string requested_group;
    resolvers.group_members_fn = [&](const std::string& group_id) {
        requested_group = group_id;
        return std::vector<std::string>{"dev-A", "dev-B", "dev-C"};
    };
    const auto outcome =
        resolve_and_dispatch_confined({}, "group:eng", only({"dev-A", "dev-C"}),
                                      /*broadcast_on_none=*/false, kNoContainment, resolvers,
                                      sink.make());
    CHECK(requested_group == "eng"); // the "group:" prefix is stripped before lookup
    CHECK(outcome.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
}

TEST_CASE("resolve_and_dispatch_confined: Broadcast arm (__all__) still narrows to the "
          "visible set",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const auto outcome =
        resolve_and_dispatch_confined({}, "__all__", only({"dev-B"}), /*broadcast_on_none=*/true,
                                      kNoContainment, no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("resolve_and_dispatch_confined: None arm reaches nobody when broadcast_on_none is "
          "false (#2500)",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const auto outcome =
        resolve_and_dispatch_confined({}, "", unfiltered(), /*broadcast_on_none=*/false,
                                      kNoContainment, no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.sent == 0);
    CHECK(sink.reached.empty());
}

TEST_CASE("resolve_and_dispatch_confined: Scope arm dispatches exactly the ladder's matched set",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    std::string requested_expr;
    resolvers.scope_ladder_fn = [&](std::string_view expr) {
        requested_expr = std::string(expr);
        ScopeLadderResult r;
        r.matched = std::vector<std::string>{"dev-A", "dev-B", "dev-C"};
        return r;
    };
    const auto outcome = resolve_and_dispatch_confined(
        {}, "tag:role == \"web\"", only({"dev-C"}), /*broadcast_on_none=*/false, kNoContainment,
        resolvers, sink.make());
    CHECK(requested_expr == "tag:role == \"web\"");
    CHECK(outcome.sent == 1);
    CHECK(sink.reached_exactly({"dev-C"}));
}

TEST_CASE("resolve_and_dispatch_confined: Scope arm aborted resolution reaches nobody — "
          "ADR-0036 fail-closed",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    resolvers.scope_ladder_fn = [](std::string_view) {
        return ScopeLadderResult{}; // matched stays nullopt — an aborted ladder
    };
    const auto outcome = resolve_and_dispatch_confined(
        {}, "tag:role == \"web\"", unfiltered(), /*broadcast_on_none=*/false, kNoContainment,
        resolvers, sink.make());
    CHECK(outcome.sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("resolve_and_dispatch_confined: a Scope arm parse error is surfaced, not swallowed",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    resolvers.scope_ladder_fn = [](std::string_view) {
        ScopeLadderResult r;
        r.parse_error = "unexpected token";
        return r;
    };
    const auto outcome = resolve_and_dispatch_confined(
        {}, "tag:role == \"web\"", unfiltered(), /*broadcast_on_none=*/false, kNoContainment,
        resolvers, sink.make());
    CHECK(outcome.sent == 0);
    REQUIRE(outcome.scope_parse_error.has_value());
    CHECK(*outcome.scope_parse_error == "unexpected token");
    CHECK(sink.reached.empty());
}

// ===================================================================================
// resolve_scope_targets — the ADR-0036 ladder itself (A-3).
//
// `resolve_scope_aliases`/`gate_scope_dispatch`'s OWN correctness on a real
// from_result_set: atom is already pinned against a live ResultSetStore in
// test_scope_walking_authz.cpp; both no-op/Proceed when the expression has NO
// from_result_set: atom, regardless of the store pointer, so a plain
// attribute condition below exercises this ladder's OWN new orchestration
// (which audit hook fires, whether evaluate_scope_fn is even reached) without
// needing a live store. The AbortDbDegraded/AbortOwnerCheck branches (which
// DO require a real from_result_set: atom + a degraded/live store) are
// UNBOUND here for that reason — see the notes in the accompanying patch
// summary.
// ===================================================================================

TEST_CASE("resolve_scope_targets: a matching expression with no from_result_set atom returns "
          "the evaluator's set untouched",
          "[server][dispatch][scope]") {
    bool audit_fired = false;
    ScopeLadderAudit audit;
    audit.evaluation_aborted = [&](const std::string&) { audit_fired = true; };
    audit.resolution_failed = [&](const std::string&) { audit_fired = true; };
    const auto result = resolve_scope_targets(
        "ostype == \"Windows\"", "alice", /*result_set_store=*/nullptr,
        [](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            return std::vector<std::string>{"dev-A", "dev-B"};
        },
        audit);
    REQUIRE(result.matched.has_value());
    CHECK(*result.matched == std::vector<std::string>{"dev-A", "dev-B"});
    CHECK_FALSE(result.parse_error.has_value());
    CHECK_FALSE(audit_fired);
}

TEST_CASE("resolve_scope_targets: invalid scope syntax surfaces a parse_error and never "
          "reaches evaluate_scope_fn",
          "[server][dispatch][scope]") {
    bool evaluate_called = false;
    ScopeLadderAudit audit;
    const auto result = resolve_scope_targets(
        "(ostype == \"Windows\"", "alice", nullptr,
        [&](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            evaluate_called = true;
            return std::vector<std::string>{};
        },
        audit);
    CHECK_FALSE(result.matched.has_value());
    REQUIRE(result.parse_error.has_value());
    CHECK_FALSE(evaluate_called);
}

TEST_CASE("resolve_scope_targets: a degraded registry evaluation aborts as db_degraded when "
          "a principal is known",
          "[server][dispatch][scope]") {
    std::string aborted_reason;
    ScopeLadderAudit audit;
    audit.evaluation_aborted = [&](const std::string& reason) { aborted_reason = reason; };
    const auto result = resolve_scope_targets(
        "ostype == \"Windows\"", "alice", nullptr,
        [](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            return std::nullopt; // registry membership preload failed
        },
        audit);
    CHECK_FALSE(result.matched.has_value());
    CHECK(aborted_reason == "db_degraded");
}

TEST_CASE("resolve_scope_targets: a degraded registry evaluation with no principal aborts as "
          "principal_unresolved",
          "[server][dispatch][scope]") {
    std::string aborted_reason;
    ScopeLadderAudit audit;
    audit.evaluation_aborted = [&](const std::string& reason) { aborted_reason = reason; };
    const auto result = resolve_scope_targets(
        "ostype == \"Windows\"", /*principal=*/"", nullptr,
        [](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            return std::nullopt;
        },
        audit);
    CHECK_FALSE(result.matched.has_value());
    CHECK(aborted_reason == "principal_unresolved");
}

// ═══════════════════════════════════════════════════════════════════════════
// K-1 (QE-2 residual): every case above binds `resolve_and_dispatch_confined`
// and `dispatch_confined_arms` by calling them DIRECTLY with a fake sink — but
// none of them exercises `wire_and_dispatch_confined`, the glue that builds
// their inputs from a real `AgentRegistry` + stores (extracted verbatim from
// `ServerImpl::dispatch_confined`). A mutation probe proved that glue was
// UNBOUND: replacing the whole `ServerImpl::dispatch_confined` body with a
// naive unfiltered `send_to` loop left every existing test green, because
// none of them called through it. This test does, against a REAL
// `AgentRegistry` (not a fake — `AgentRegistry` has zero virtuals and cannot
// be faked polymorphically), using the registry's gateway-pending path
// (`set_gateway_route` + `drain_gateway_pending()`) to observe exactly which
// agent_ids a dispatch reached without needing a live gRPC stream.
// ═══════════════════════════════════════════════════════════════════════════

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

TEST_CASE("wire_and_dispatch_confined: the Ids arm intersects exec_visible against a REAL "
          "AgentRegistry (K-1)",
          "[server][dispatch][scope][integration]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    for (const auto& id : {"dev-A", "dev-B", "dev-C"}) {
        (void)registry.register_agent(make_wiring_test_info(id));
        // Gateway-pending path: send_to() queues onto drain_gateway_pending()
        // and returns true with NO live gRPC stream needed — the observable
        // hook this test uses to see exactly who was targeted.
        // p8/PR1.9c CC-03: send_to()'s routed-path check now refuses a
        // dispatch-tagged command to a gateway session that hasn't advertised
        // command_dispatch_tag_v1 — irrelevant to what THIS test binds (the
        // exec_visible intersection), so advertise it for every fixture agent
        // exactly as a real gateway's CONNECTED notification would.
        REQUIRE(registry.set_gateway_route(
            id, /*session_id=*/{}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
    }

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-test-cmd");
    cmd.set_plugin("os_info");
    cmd.set_action("version");
    // p8/PR1.9c PLAN-011: send_to()'s defensive belt-and-braces check now
    // refuses a command whose dispatch_tag doesn't decode — irrelevant to
    // what THIS test binds, so stamp a well-formed one. Wrapped via the
    // test-only door (`ClassifiedCommandTestAccess`) mirroring
    // `EngineLivenessTestAccess`: `send_to`/`send_to_all` accept only a
    // `ClassifiedCommand`, mintable in production ONLY by
    // `ServerImpl::build_classified_command`.
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    // Confined to dev-A only; agent_ids names all three. If the intersection
    // is deleted (the exact K-1 mutation), all three get queued instead of
    // just dev-A.
    yuzu::server::authz::VisibleSet exec_visible{std::unordered_set<std::string>{"dev-A"}};
    std::vector<std::string> agent_ids{"dev-A", "dev-B", "dev-C"};

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"wiring-test-cmd", /*execution_id=*/"", /*principal_role=*/"",
        agent_ids, /*scope_expr=*/"", exec_visible, /*broadcast_on_none=*/false, kNoContainment,
        classified);

    CHECK(outcome.sent == 1);
    CHECK(outcome.command_id == "wiring-test-cmd");
    CHECK(outcome.denied_quarantined.empty());
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-A");
}

// ═══════════════════════════════════════════════════════════════════════════
// ADR-1007 — the per-device concurrency GATE ACTIVATION itself (Gate 3
// quality-engineer SHOULD): every existing test above passes
// execution_tracker=nullptr with definition_id/concurrency_mode defaulted
// empty, so none of them ever reaches the claim_fn construction branch in
// wire_and_dispatch_confined. A swapped/wrong definition_id or
// concurrency_mode argument at a real call site (workflow_routes.cpp,
// schedule_runner.cpp) would compile clean and silently never activate the
// gate — this is the exact "marked Done, never wired" failure mode this
// whole PR exists to close, and it deserves its own regression proof against
// a REAL ExecutionTracker, not just ExecutionTracker's own unit tests.
// ═══════════════════════════════════════════════════════════════════════════

#include "test_execution_tracker_pg_helper.hpp"

TEST_CASE("wire_and_dispatch_confined: concurrency_mode=\"per-device\" with a live "
          "ExecutionTracker excludes an already-claimed agent",
          "[server][dispatch][scope][integration][pg][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    yuzu::server::ExecutionTracker& tracker = *tracker_bundle;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_wiring_test_info("dev-A"));
    REQUIRE(registry.set_gateway_route(
        "dev-A", /*session_id=*/{}, "test-gateway",
        {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-concurrency-cmd");
    cmd.set_plugin("os_info");
    cmd.set_action("version");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    std::vector<std::string> agent_ids{"dev-A"};

    // First dispatch: claims the slot, reaches the agent.
    const auto first = yuzu::server::wire_and_dispatch_confined(
        registry, nullptr, nullptr, nullptr, nullptr, &tracker, noop_audit, noop_audit,
        /*command_id=*/"wiring-concurrency-cmd-1", /*execution_id=*/"exec-1",
        /*principal_role=*/"", agent_ids, /*scope_expr=*/"",
        yuzu::server::authz::VisibleSet{std::nullopt}, /*broadcast_on_none=*/false, kNoContainment,
        classified, /*definition_id=*/"def-wiring-test", /*concurrency_mode=*/"per-device");
    CHECK(first.sent == 1);

    // Second dispatch of the SAME definition to the SAME agent, still
    // claimed (no terminal response recorded) — must be excluded.
    const auto second = yuzu::server::wire_and_dispatch_confined(
        registry, nullptr, nullptr, nullptr, nullptr, &tracker, noop_audit, noop_audit,
        /*command_id=*/"wiring-concurrency-cmd-2", /*execution_id=*/"exec-2",
        /*principal_role=*/"", agent_ids, /*scope_expr=*/"",
        yuzu::server::authz::VisibleSet{std::nullopt}, /*broadcast_on_none=*/false, kNoContainment,
        classified, /*definition_id=*/"def-wiring-test", /*concurrency_mode=*/"per-device");
    CHECK(second.sent == 0);
}

TEST_CASE("wire_and_dispatch_confined: a non-\"per-device\" concurrency_mode leaves the gate "
          "inert even with a live ExecutionTracker",
          "[server][dispatch][scope][integration][pg][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    yuzu::server::ExecutionTracker& tracker = *tracker_bundle;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_wiring_test_info("dev-A"));
    REQUIRE(registry.set_gateway_route(
        "dev-A", /*session_id=*/{}, "test-gateway",
        {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-unlimited-cmd");
    cmd.set_plugin("os_info");
    cmd.set_action("version");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    std::vector<std::string> agent_ids{"dev-A"};

    // Both dispatches use concurrency_mode="unlimited" — neither should ever
    // be excluded, proving the gate genuinely no-ops for a non-per-device
    // mode rather than merely "not yet tested to exclude."
    for (int i = 0; i < 2; ++i) {
        const auto outcome = yuzu::server::wire_and_dispatch_confined(
            registry, nullptr, nullptr, nullptr, nullptr, &tracker, noop_audit, noop_audit,
            "wiring-unlimited-cmd-" + std::to_string(i), "exec-unlimited-" + std::to_string(i),
            /*principal_role=*/"", agent_ids, /*scope_expr=*/"",
            yuzu::server::authz::VisibleSet{std::nullopt}, /*broadcast_on_none=*/false,
            kNoContainment, classified, /*definition_id=*/"def-wiring-test",
            /*concurrency_mode=*/"unlimited");
        CHECK(outcome.sent == 1);
    }
}

// ADR-1007 fix round (PR #3784 external review, important-finding-#1, converged on
// independently by security-guardian/cpp-expert/architect/quality-engineer in the
// governance re-review of the fix itself): a per-device claim is taken in
// resolve_and_dispatch_confined BEFORE dispatch_confined_arms attempts the send —
// if the send then fails, the claim previously leaked (stayed open) with nothing
// to release it until the reconciler's expires_at. This is the BEHAVIORAL proof
// the fix actually releases the claim, not just that a mock observed a call: no
// registered gateway route on dev-A makes AgentRegistry::send_to fail
// deterministically (agent_registry.cpp: gateway_node empty AND no live stream ->
// false), so the first dispatch's claim, once taken, is guaranteed to hit the
// not_sent path. The second dispatch — same definition, same agent, gateway route
// now wired so the send can succeed — proves the release actually happened: if it
// hadn't, this dispatch would ALSO be excluded by the still-open first claim.
TEST_CASE("wire_and_dispatch_confined: a per-device claim is released when the send itself "
          "fails, not left open until the reconciler",
          "[server][dispatch][scope][integration][pg][concurrency][adr1007]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    yuzu::server::ExecutionTracker& tracker = *tracker_bundle;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_wiring_test_info("dev-A"));
    // Deliberately NOT calling set_gateway_route — dev-A has no gateway_node and
    // no live Subscribe stream, so send_to() returns false deterministically.

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-leak-cmd");
    cmd.set_plugin("os_info");
    cmd.set_action("version");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    std::vector<std::string> agent_ids{"dev-A"};

    // First dispatch: claims the slot, but the send itself fails (no route).
    const auto first = yuzu::server::wire_and_dispatch_confined(
        registry, nullptr, nullptr, nullptr, nullptr, &tracker, noop_audit, noop_audit,
        /*command_id=*/"wiring-leak-cmd-1", /*execution_id=*/"exec-leak-1",
        /*principal_role=*/"", agent_ids, /*scope_expr=*/"",
        yuzu::server::authz::VisibleSet{std::nullopt}, /*broadcast_on_none=*/false, kNoContainment,
        classified, /*definition_id=*/"def-leak-test", /*concurrency_mode=*/"per-device");
    CHECK(first.sent == 0);
    REQUIRE(first.not_sent.size() == 1);
    CHECK(first.not_sent[0] == "dev-A");

    // Fix the transport and dispatch again. If the fix works, the released claim
    // lets this second dispatch through; if the claim had leaked, this would also
    // report sent == 0, indistinguishable from a stale open claim.
    REQUIRE(registry.set_gateway_route(
        "dev-A", /*session_id=*/{}, "test-gateway",
        {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
    const auto second = yuzu::server::wire_and_dispatch_confined(
        registry, nullptr, nullptr, nullptr, nullptr, &tracker, noop_audit, noop_audit,
        /*command_id=*/"wiring-leak-cmd-2", /*execution_id=*/"exec-leak-2",
        /*principal_role=*/"", agent_ids, /*scope_expr=*/"",
        yuzu::server::authz::VisibleSet{std::nullopt}, /*broadcast_on_none=*/false, kNoContainment,
        classified, /*definition_id=*/"def-leak-test", /*concurrency_mode=*/"per-device");
    CHECK(second.sent == 1);
    CHECK(second.not_sent.empty());
}

// ===================================================================================
// PR6.0b — the D3 DECISION PIN: the shared confined-dispatch seam must NOT
// refuse a Destructive-class fan-out.
//
// `dispatch_destructive_gate.hpp` deliberately gates Destructive TARGETING in
// route/handler code (`/api/command`, MCP `execute_instruction`, and — since
// PR6.0b — `POST /api/dashboard/execute`) and NOT here. That decision looks
// like an oversight from `server.cpp`: `ServerImpl::dispatch_confined` has no
// dispatch-class check at all, so "finish the job at the chokepoint" is the
// obvious next move. It is the wrong move, and until this case existed the
// only thing standing between the next person and shipping it was a paragraph
// of prose.
//
// WHAT WOULD BREAK: `ScheduleRunner::dispatch_tracked` (schedule_runner.cpp)
// dispatches EVERY scheduled fire with `agent_ids={}` plus a scope expression
// — an empty stored `scope_expression` is mapped to `kBroadcastScope` right at
// the call site — and `schedule_arming_permitted`
// (schedule_arming_check.hpp) refuses only `system_reserved` and unclassified
// rows, never Destructive ones. A Destructive-refusing gate at this seam
// therefore turns every scheduled Destructive instruction into a permanent,
// silent zero-reach fire, INCLUDING the approval-gated ones the four-eyes
// ticket flow exists to make safe. `rest_api_v1.cpp`'s async result-set
// producers dispatch `{}` + `__all__` by construction too.
//
// HONEST LIMIT OF THIS PIN: this seam receives a `ClassifiedCommand` (a wire
// `CommandRequest`), never a `CommandCapability`, so it structurally CANNOT
// consult the dispatch class without a signature widening. This case fails on
// any gate added inside `wire_and_dispatch_confined` /
// `resolve_and_dispatch_confined` / `dispatch_confined_arms`. It does NOT
// reach a gate added directly in `ServerImpl::dispatch_confined`'s own body,
// which no test seam exposes — that path is still guarded by prose alone.
// ===================================================================================

TEST_CASE("the shared confined-dispatch seam does not refuse a Destructive fan-out "
          "(dispatch_destructive_gate.hpp D3)",
          "[server][dispatch][scope][security][destructive]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    for (const auto& id : {"dev-A", "dev-B", "dev-C"}) {
        (void)registry.register_agent(make_wiring_test_info(id));
        REQUIRE(registry.set_gateway_route(
            id, /*session_id=*/{}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
    }

    // A REAL Destructive row (tar.purge_source, DispatchClass::Destructive in
    // capability_decls/plugin_action_catalogue_a.hpp) — named explicitly so
    // this case cannot quietly become a test about a harmless pair.
    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("d3-pin-cmd");
    cmd.set_plugin("tar");
    cmd.set_action("purge_source");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};

    // EXACTLY the shape ScheduleRunner produces: no agent_ids, `__all__`
    // scope, and the unfiltered visible set a system/background caller has.
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"d3-pin-cmd", /*execution_id=*/"", /*principal_role=*/"",
        /*agent_ids=*/{}, /*scope_expr=*/std::string(yuzu::server::kBroadcastScope),
        /*exec_visible=*/unfiltered(), /*broadcast_on_none=*/false, kNoContainment, classified);

    // The scheduled purge REACHES the fleet. If this ever reads 0, read this
    // case's header before "fixing" it — the fix is almost certainly a gate
    // that belongs in a route handler instead.
    CHECK(outcome.sent == 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// WS-4 4.2b Task C — GatewayRouteStore reader wiring (fallback-only). These
// bind `wire_and_dispatch_confined`'s new `gateway_route_store` parameter
// against a REAL `GatewayRouteStore` + REAL `AgentRegistry`, mirroring the
// K-1 section above. See dispatch_route_fallback.hpp's file header for the
// fallback-only contract this pins: a candidate WITH a local `AgentRegistry`
// session is NEVER routed via the directory, regardless of what row (if any)
// the directory holds for it — the acceptance property is that this changes
// ZERO monolith routing outcomes.
// ═══════════════════════════════════════════════════════════════════════════

#include "gateway_route_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

namespace {
using yuzu::server::GatewayRouteStore;
namespace pg = yuzu::server::pg;

// Separate template key ("dispatchroutefallback") so this file's clone
// lineage never shares with test_gateway_route_store.cpp's "gatewayroute" or
// test_gateway_route_wiring.cpp's "gwroutewiring" fixtures.
yuzu::test::PgTestTemplate dispatch_route_fallback_tpl{
    "dispatchroutefallback", [](const std::string& dsn) {
        pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        GatewayRouteStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("dispatchroutefallback template: store failed to migrate");
    }};

agent_pb::CommandRequest make_route_fallback_cmd(const std::string& command_id) {
    agent_pb::CommandRequest cmd;
    cmd.set_command_id(command_id);
    cmd.set_plugin("os_info");
    cmd.set_action("version");
    cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
    return cmd;
}
} // namespace

TEST_CASE("wire_and_dispatch_confined: a locally-known agent routes via the EXISTING path "
          "and the directory store is never queried, even with a routable row present for "
          "the same id (WS-4 4.2b Task C — fallback-only)",
          "[pg][server][dispatch][scope][gateway_route_dispatch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_route_fallback_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_wiring_test_info("dev-local"));
    REQUIRE(registry.set_gateway_route(
        "dev-local", /*session_id=*/{}, "test-gateway",
        {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    // A directory row for the SAME agent id — deliberately present AND
    // routable even though the agent has a local session. If the local path
    // were bypassed, this dispatch would come out carrying "cluster-decoy"'s
    // cluster_id via the directory fallback instead of the existing local
    // gateway_node queue.
    auto fresh = store.register_fresh("dev-local", "sess-local-1");
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->won);
    auto announced = store.announce_connected("dev-local", "sess-local-1", "cluster-decoy",
                                              "node-decoy", /*lease_ttl_secs=*/90);
    REQUIRE(announced.has_value());
    REQUIRE(announced->matched);

    auto classified = ClassifiedCommandTestAccess::make(make_route_fallback_cmd("route-fb-local"));
    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"route-fb-local", /*execution_id=*/"", /*principal_role=*/"",
        /*agent_ids=*/{"dev-local"}, /*scope_expr=*/"", /*exec_visible=*/unfiltered(),
        /*broadcast_on_none=*/false, kNoContainment, classified, /*definition_id=*/{},
        /*concurrency_mode=*/{}, &store);

    CHECK(outcome.sent == 1);
    CHECK_FALSE(outcome.route_unreadable);
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-local");
    // Routed via the EXISTING local gateway_node path: no cluster_id carried
    // on the pending entry — `send_via_directory` (the only path that ever
    // sets it) was never called, proving the directory row was ignored.
    CHECK_FALSE(pending[0].cluster_id.has_value());
}

TEST_CASE("wire_and_dispatch_confined: a local-miss agent with a ROUTABLE directory row is "
          "queued via the directory fallback, carrying its cluster_id (WS-4 4.2b Task C)",
          "[pg][server][dispatch][scope][gateway_route_dispatch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_route_fallback_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    // Deliberately NEVER registered locally — this replica has no session
    // for "dev-remote" at all, the precondition for the fallback to fire.

    auto fresh = store.register_fresh("dev-remote", "sess-remote-1");
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->won);
    auto announced =
        store.announce_connected("dev-remote", "sess-remote-1", "cluster-b", "node-b", 90);
    REQUIRE(announced.has_value());
    REQUIRE(announced->matched);

    auto classified = ClassifiedCommandTestAccess::make(make_route_fallback_cmd("route-fb-remote"));
    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"route-fb-remote", /*execution_id=*/"", /*principal_role=*/"",
        /*agent_ids=*/{"dev-remote"}, /*scope_expr=*/"", /*exec_visible=*/unfiltered(),
        /*broadcast_on_none=*/false, kNoContainment, classified, /*definition_id=*/{},
        /*concurrency_mode=*/{}, &store);

    CHECK(outcome.sent == 1);
    CHECK_FALSE(outcome.route_unreadable);
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-remote");
    REQUIRE(pending[0].cluster_id.has_value());
    CHECK(*pending[0].cluster_id == "cluster-b");
}

TEST_CASE("wire_and_dispatch_confined: a local-miss agent ABSENT from the directory is a "
          "definite no-route — not queued via the directory, not sent (WS-4 4.2b Task C)",
          "[pg][server][dispatch][scope][gateway_route_dispatch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_route_fallback_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    // Never registered locally AND no directory row at all for this id.

    auto classified = ClassifiedCommandTestAccess::make(make_route_fallback_cmd("route-fb-absent"));
    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"route-fb-absent", /*execution_id=*/"", /*principal_role=*/"",
        /*agent_ids=*/{"dev-ghost"}, /*scope_expr=*/"", /*exec_visible=*/unfiltered(),
        /*broadcast_on_none=*/false, kNoContainment, classified, /*definition_id=*/{},
        /*concurrency_mode=*/{}, &store);

    CHECK(outcome.sent == 0);
    CHECK_FALSE(outcome.route_unreadable);
    CHECK(outcome.not_sent == std::vector<std::string>{"dev-ghost"});
    CHECK(registry.drain_gateway_pending().empty());
}

TEST_CASE("wire_and_dispatch_confined: a DEGRADED directory read on a local-miss candidate "
          "surfaces route_unreadable (WS-4 4.2b Task C)",
          "[server][dispatch][scope][gateway_route_dispatch]") {
    // Mirrors test_gateway_route_wiring.cpp's fail-open/fail-closed cases: a
    // deliberately unparseable conninfo makes PgPool::valid() false, so the
    // store's construction-time acquire() fails fast and `open_` stays
    // false — no real Postgres instance needed, this case runs even when
    // YUZU_TEST_POSTGRES_DSN is unset.
    pg::PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    // Never registered locally — a local miss, so the batched read fires
    // (and immediately degrades, since the store never opened).

    auto classified =
        ClassifiedCommandTestAccess::make(make_route_fallback_cmd("route-fb-degraded"));
    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"route-fb-degraded", /*execution_id=*/"", /*principal_role=*/"",
        /*agent_ids=*/{"dev-degraded"}, /*scope_expr=*/"", /*exec_visible=*/unfiltered(),
        /*broadcast_on_none=*/false, kNoContainment, classified, /*definition_id=*/{},
        /*concurrency_mode=*/{}, &broken_store);

    CHECK(outcome.sent == 0);
    CHECK(outcome.route_unreadable);
    CHECK(registry.drain_gateway_pending().empty());
}

TEST_CASE("wire_and_dispatch_confined: a narrowed exec_visible excludes a local-miss agent "
          "with a ROUTABLE directory row -- #1788 confinement runs BEFORE the directory "
          "fallback, so the excluded agent is neither sent to nor queued via the directory "
          "(security-guardian: the new fallback path must not resurrect a "
          "confinement-excluded agent)",
          "[pg][server][dispatch][scope][gateway_route_dispatch][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_route_fallback_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    // "dev-in-scope" has a real local session -- the caller's OWN visible set
    // admits it, so it is reached via the existing local path.
    (void)registry.register_agent(make_wiring_test_info("dev-in-scope"));
    REQUIRE(registry.set_gateway_route(
        "dev-in-scope", /*session_id=*/{}, "test-gateway",
        {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    // "dev-excluded" is a local MISS (no session on this replica) but DOES
    // have a routable directory row -- the exact precondition for
    // `send_via_directory` to fire, mirroring the "ROUTABLE directory row"
    // case above. The only difference from that case: the caller's
    // exec_visible does NOT include it, so it must never reach the directory
    // send at all, regardless of what the directory knows about it.
    auto fresh = store.register_fresh("dev-excluded", "sess-excluded-1");
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->won);
    auto announced = store.announce_connected("dev-excluded", "sess-excluded-1", "cluster-x",
                                              "node-x", /*lease_ttl_secs=*/90);
    REQUIRE(announced.has_value());
    REQUIRE(announced->matched);

    auto classified =
        ClassifiedCommandTestAccess::make(make_route_fallback_cmd("route-fb-confinement"));
    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto outcome = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"route-fb-confinement", /*execution_id=*/"", /*principal_role=*/"",
        /*agent_ids=*/{"dev-in-scope", "dev-excluded"}, /*scope_expr=*/"",
        /*exec_visible=*/only({"dev-in-scope"}), /*broadcast_on_none=*/false, kNoContainment,
        classified, /*definition_id=*/{}, /*concurrency_mode=*/{}, &store);

    // Only the in-scope agent was reached -- the excluded one is dropped by
    // the #1788 `filter_to_scope` intersection before the arm walk ever calls
    // `send_to` on it, so it lands in NEITHER `sent` NOR `not_sent`: it never
    // entered the per-id loop at all, exactly like an ordinary out-of-scope
    // id on the local-only path (see the Ids-arm "an out-of-scope id is
    // DROPPED" case near the top of this file).
    CHECK(outcome.sent == 1);
    CHECK(outcome.not_sent.empty());
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-in-scope");
    // The directory fallback never resurrects the excluded agent: no pending
    // entry names it, and in particular none carries "cluster-x" -- the
    // cluster_id `send_via_directory` would have stamped had "dev-excluded"
    // ever reached the send step.
    for (const auto& p : pending)
        CHECK(p.agent_id != "dev-excluded");
}
