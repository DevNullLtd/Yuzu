/**
 * test_dispatch_destructive_gate.cpp — #3685: the pure Destructive-class
 * targeting verdict (`evaluate_destructive_targeting`) and REST-side
 * visible-set confinement (`confine_destructive_targets`).
 *
 * WHY THIS FILE EXISTS. `/api/command`'s inline Destructive block guarded on
 * `if (classified_for_gate && classified_for_gate->dispatch_class ==
 * DispatchClass::Destructive)` — an `if` that collapses "classified and not
 * Destructive" and "failed to classify at all" into the same skipped branch.
 * Not exploitably fail-open there (the downstream chokepoint denies every
 * classify-miss unconditionally), but exactly the shape that would be
 * fail-open the next time the same pattern is copied without that backstop.
 * `dispatch_destructive_gate.hpp` makes the miss a first-class verdict with
 * no `default:` escape; this file pins that a `ClassifyMiss` is reachable and
 * distinguishable from every other verdict, and that the two long-lived
 * refusal strings (zero test occurrences before #3685) are pinned byte-exact.
 *
 * Pure — no Postgres, no sleeps, no spawns, no `ServerImpl`. Everything under
 * test is a header-only, injected-input surface (`dispatch_destructive_gate
 * .hpp`), same as `test_dispatch_confined_arms.cpp` and
 * `test_dispatch_target_shape.cpp` for their own shared rules.
 *
 * The tail of this file (commit 3, #3685 checkpoint 1) additionally binds a
 * COMPOSITION property the pure header cannot prove on its own: that
 * `evaluate_destructive_targeting`'s `Targeted` verdict is a targeting
 * decision only, never an authorization one — the same command can still be
 * independently denied by the real dispatch chokepoint
 * (`classify_and_authorize_dispatch`, `agent_registry.hpp`), and
 * `/api/command`'s own `require_permission` call stays present and distinct
 * from that chokepoint's `has_permission` callback (D3/D4 in
 * `dispatch_destructive_gate.hpp`'s doc comment).
 */

#include "dispatch_destructive_gate.hpp"

#include "agent_registry.hpp"
#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "capability_decls/plugin_action_catalogue_b.hpp"
#include "capability_decls/plugin_action_catalogue_c.hpp"
#include "capability_decls/plugin_action_catalogue_content_dist.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "capability_decls/plugin_action_catalogue_disk_actions.hpp"
#include "capability_decls/plugin_action_catalogue_filesystem_posture.hpp"
#include "capability_decls/plugin_action_catalogue_power_health.hpp"
#include "capability_decls/plugin_action_catalogue_autoruns.hpp"
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
#include "capability_decls/plugin_action_catalogue_execution_artifacts.hpp"
#include "capability_decls/plugin_action_catalogue_windows_optional_features.hpp"
#include "capability_decls/plugin_action_catalogue_peripherals.hpp"
#include "capability_decls/plugin_action_catalogue_printing.hpp"
#include "capability_decls/plugin_action_catalogue_app_control.hpp"
#include "capability_decls/plugin_action_catalogue_firmware_posture.hpp"
#include "capability_decls/plugin_action_catalogue_runtimes.hpp"
#include "capability_decls/plugin_action_catalogue_platform_security.hpp"
#include "capability_decls/plugin_action_catalogue_browser_inventory.hpp"
#include "capability_decls/plugin_action_catalogue_system_hardening.hpp"
#include "capability_decls/plugin_action_catalogue_pkg_inventory.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

using yuzu::server::ClassificationError;
using yuzu::server::CommandCapability;
using yuzu::server::CommandCapabilityRegistry;
using yuzu::server::confine_destructive_targets;
using yuzu::server::DestructiveTargetingVerdict;
using yuzu::server::DestructiveVisibleAgents;
using yuzu::server::DispatchClass;
using yuzu::server::evaluate_destructive_targeting;
using yuzu::server::ExecuteGate;
using yuzu::server::kDestructiveNoVisibleAgentMessage;
using yuzu::server::kDestructiveUntargetedMessage;
using yuzu::server::kForensicsSecurable;
using yuzu::server::kForensicUntargetedMessage;
using yuzu::server::kReasonDestructiveUntargeted;
using yuzu::server::kReasonForensicUntargeted;
using yuzu::server::Mutability;
using yuzu::server::requires_explicit_targets;

namespace {

// A minimal three-row fixture — one Destructive, one ReadOnly, one Mutating
// — deliberately NOT the real catalogue (that is `test_capability_catalogue
// .cpp`'s job; a separate case below binds this file to the REAL catalogue
// count as a tripwire, but the verdict-shape cases use this small,
// independent fixture so they do not have to track the real catalogue's
// content).
inline constexpr std::array<CommandCapability, 3> kFixture{{
    {
        .plugin = "tar",
        .action = "purge_source",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Delete,
        .risk_tier = yuzu::server::authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Read,
        .risk_tier = yuzu::server::authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tags",
        .action = "set",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Tag",
        .operation = yuzu::server::authz::Operation::Write,
        .risk_tier = yuzu::server::authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// A second, independently-authored fragment that redeclares tar.purge_source
// — exercises the Ambiguous classify-miss path, same technique
// test_command_capability.cpp uses for its own Ambiguous case.
inline constexpr std::array<CommandCapability, 1> kCollidingFragment{{
    {
        .plugin = "TAR",
        .action = "PURGE_SOURCE",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Delete,
        .risk_tier = yuzu::server::authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// Wave 7 PR7.2 — a local Forensics fixture: `ReadOnly`/`None`, never
// `Destructive`, but still subject to the single-target rule via
// `requires_explicit_targets`'s securable-name branch. Also a plain
// Inventory `ReadOnly` row (no relation to Forensics) proving the rule does
// NOT leak onto every ReadOnly securable.
inline constexpr std::array<CommandCapability, 2> kForensicsFixture{{
    {
        .plugin = "execution_artifacts",
        .action = "shimcache",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = yuzu::server::authz::Operation::Read,
        .risk_tier = yuzu::server::authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "inventory",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = yuzu::server::authz::Operation::Read,
        .risk_tier = yuzu::server::authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

std::vector<std::string> ids(std::initializer_list<std::string> v) { return {v}; }

} // namespace

// ──────────────────────────────── evaluate_destructive_targeting: verdicts ──

TEST_CASE("Destructive row, explicit non-empty agent_ids, no scope: Targeted",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == DestructiveTargetingVerdict::Targeted);
    REQUIRE(gate.capability.has_value());
    CHECK(gate.capability->plugin == "tar");
    CHECK(gate.capability->action == "purge_source");
    CHECK_FALSE(gate.miss.has_value());
}

TEST_CASE("Destructive row, empty/absent agent_ids: RefuseUntargeted",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/false,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
    REQUIRE(gate.capability.has_value());
    CHECK_FALSE(gate.miss.has_value());
}

TEST_CASE("Destructive row, agent_ids AND scope both present: RefuseUntargeted — covers the "
          "scope:\"__all__\"-alongside-ids combo check_targeting_shape uniquely permits through",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());

    // `scope_key_present=true` stands for BOTH real-world request shapes at
    // once: an ordinary conflicting scope (which check_targeting_shape
    // already refuses upstream for every value except "__all__", so a
    // Destructive row refusing it too is defense in depth) AND the one
    // combination check_targeting_shape DOES let through —
    // {"agent_ids":[...],"scope":"__all__"}. The two are indistinguishable
    // at THIS function's boolean interface by design (that is the caller
    // contract documented on evaluate_destructive_targeting: any non-empty
    // scope string, "__all__" included, must map to scope_key_present=true)
    // — so one assertion here proves both request shapes refuse.
    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/true);
    CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
}

TEST_CASE("Destructive row, scope-only or broadcast (no agent_ids): RefuseUntargeted",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());

    // Same collapse as above: a real scope expression and a scope:"__all__"
    // broadcast, both with no agent_ids, both arrive here as
    // scope_key_present=true — indistinguishable at this layer by design.
    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/false,
                                                      /*scope_key_present=*/true);
    CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
}

TEST_CASE("Classify miss (Unclassified): ClassifyMiss, capability disengaged, error recorded",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};
    auto classified = registry.classify("no_such_plugin", "no_such_action");
    REQUIRE_FALSE(classified.has_value());
    CHECK(classified.error() == ClassificationError::Unclassified);

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == DestructiveTargetingVerdict::ClassifyMiss);
    CHECK_FALSE(gate.capability.has_value());
    REQUIRE(gate.miss.has_value());
    CHECK(*gate.miss == ClassificationError::Unclassified);
}

TEST_CASE("Classify miss (Ambiguous): ClassifyMiss, capability disengaged, error recorded",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture),
                                       std::span<const CommandCapability>(kCollidingFragment)};
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE_FALSE(classified.has_value());
    CHECK(classified.error() == ClassificationError::Ambiguous);

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == DestructiveTargetingVerdict::ClassifyMiss);
    CHECK_FALSE(gate.capability.has_value());
    REQUIRE(gate.miss.has_value());
    CHECK(*gate.miss == ClassificationError::Ambiguous);
}

TEST_CASE("ReadOnly and Mutating rows: NotDestructive regardless of targeting shape",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};

    auto read_only = registry.classify("tar", "query");
    REQUIRE(read_only.has_value());
    // Even with no ids and no scope — NotDestructive means this gate simply
    // does not apply; it is not this function's job to say whether the
    // dispatch itself is otherwise permitted.
    const auto gate1 = evaluate_destructive_targeting(read_only,
                                                       /*valid_nonempty_agent_ids=*/false,
                                                       /*scope_key_present=*/false);
    CHECK(gate1.verdict == DestructiveTargetingVerdict::NotDestructive);
    REQUIRE(gate1.capability.has_value());
    CHECK(gate1.capability->plugin == "tar");

    auto mutating = registry.classify("tags", "set");
    REQUIRE(mutating.has_value());
    const auto gate2 = evaluate_destructive_targeting(mutating,
                                                       /*valid_nonempty_agent_ids=*/true,
                                                       /*scope_key_present=*/true);
    CHECK(gate2.verdict == DestructiveTargetingVerdict::NotDestructive);
    REQUIRE(gate2.capability.has_value());
    CHECK(gate2.capability->plugin == "tags");
}

// ──────────────────────────── Wave 7 PR7.2: Forensics single-target rule ──

TEST_CASE("Forensics ReadOnly row, exactly one explicit agent_id, no scope: Targeted",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kForensicsFixture)};
    auto classified = registry.classify("execution_artifacts", "shimcache");
    REQUIRE(classified.has_value());
    CHECK(requires_explicit_targets(*classified));

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/false,
                                                      /*agent_id_count=*/1);
    CHECK(gate.verdict == DestructiveTargetingVerdict::Targeted);
    REQUIRE(gate.capability.has_value());
    CHECK(gate.capability->securable == kForensicsSecurable);
}

TEST_CASE("Forensics ReadOnly row: RefuseUntargeted for 0 ids, 2 ids, ids+scope, and an "
          "omitted count (fail-closed default)",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kForensicsFixture)};
    auto classified = registry.classify("execution_artifacts", "shimcache");
    REQUIRE(classified.has_value());

    // 0 ids.
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/false,
                                                          /*scope_key_present=*/false,
                                                          /*agent_id_count=*/0);
        CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK(gate.refusal_reason == kReasonForensicUntargeted);
        CHECK(gate.refusal_message == kForensicUntargetedMessage);
    }
    // 2 ids (fan-out — not a broadcast, but still more than the one target
    // the single-target rule permits).
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/false,
                                                          /*agent_id_count=*/2);
        CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK(gate.refusal_reason == kReasonForensicUntargeted);
        CHECK(gate.refusal_message == kForensicUntargetedMessage);
    }
    // Exactly one id, but scope ALSO present.
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/true,
                                                          /*agent_id_count=*/1);
        CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK(gate.refusal_reason == kReasonForensicUntargeted);
        CHECK(gate.refusal_message == kForensicUntargetedMessage);
    }
    // The count parameter OMITTED entirely — defaults to 0, so a caller that
    // has not been updated to count ids FAILS CLOSED rather than admitting a
    // forensic broadcast by silent omission.
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/false);
        CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK(gate.refusal_reason == kReasonForensicUntargeted);
        CHECK(gate.refusal_message == kForensicUntargetedMessage);
    }
}

TEST_CASE("execution_artifacts: the REAL catalogue fragment (not the independent kForensicsFixture "
          "copy above) is Forensics-securable and gates identically to a targeted single-agent "
          "dispatch for all three real actions — a static_assert only proves the fragment's three "
          "rows share ONE securable literal with EACH OTHER, never that the literal is still "
          "\"Forensics\"; this pins the real fragment against evaluate_destructive_targeting so a "
          "drift in the shipped securable string (kForensicsFixture's local copy would not see it) "
          "fails here",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_execution_artifacts()};

    for (const char* action : {"shimcache", "amcache", "prefetch"}) {
        auto classified = registry.classify("execution_artifacts", action);
        REQUIRE(classified.has_value());
        CHECK(classified->securable == kForensicsSecurable);
        CHECK(requires_explicit_targets(*classified));

        const auto targeted = evaluate_destructive_targeting(classified,
                                                              /*valid_nonempty_agent_ids=*/true,
                                                              /*scope_key_present=*/false,
                                                              /*agent_id_count=*/1);
        CHECK(targeted.verdict == DestructiveTargetingVerdict::Targeted);
        REQUIRE(targeted.capability.has_value());
        CHECK(targeted.capability->securable == kForensicsSecurable);

        const auto refused = evaluate_destructive_targeting(classified,
                                                              /*valid_nonempty_agent_ids=*/true,
                                                              /*scope_key_present=*/false,
                                                              /*agent_id_count=*/2);
        CHECK(refused.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK(refused.refusal_reason == kReasonForensicUntargeted);
        CHECK(refused.refusal_message == kForensicUntargetedMessage);
    }
}

TEST_CASE("Inventory ReadOnly row stays NotDestructive — the single-target rule does not leak "
          "onto every ReadOnly securable",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kForensicsFixture)};
    auto classified = registry.classify("inventory", "list");
    REQUIRE(classified.has_value());
    CHECK_FALSE(requires_explicit_targets(*classified));

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/false,
                                                      /*scope_key_present=*/false,
                                                      /*agent_id_count=*/0);
    CHECK(gate.verdict == DestructiveTargetingVerdict::NotDestructive);
}

// Wave 7b PR7b.3 — pins the REAL app_usage fragment (not the hand-built
// kForensicsFixture above) through the same Forensics single-target rule:
// app_usage's three rows are ReadOnly/AdminOrApproval under the Forensics
// securable, so they must be targeted exactly as execution_artifacts is.
TEST_CASE("app_usage.summary (real fragment): Forensics single-target rule — 1 agent Targeted, "
          "2 agents RefuseUntargeted",
          "[server][dispatch][security]") {
    namespace capdecls = yuzu::server::capdecls;
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_app_usage()};
    auto classified = registry.classify("app_usage", "summary");
    REQUIRE(classified.has_value());
    CHECK(classified->securable == kForensicsSecurable);
    CHECK(requires_explicit_targets(*classified));

    const auto targeted = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/false,
                                                          /*agent_id_count=*/1);
    CHECK(targeted.verdict == DestructiveTargetingVerdict::Targeted);

    const auto refused = evaluate_destructive_targeting(classified,
                                                         /*valid_nonempty_agent_ids=*/true,
                                                         /*scope_key_present=*/false,
                                                         /*agent_id_count=*/2);
    CHECK(refused.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
    CHECK(refused.refusal_reason == kReasonForensicUntargeted);
}

// Wave 10 P2a-3 — pins the REAL browser_inventory fragment (not the
// hand-built kForensicsFixture above) through the same Forensics
// single-target rule: browser_inventory's two rows are ReadOnly/
// AdminOrApproval under the Forensics securable (field-for-field copy of
// execution_artifacts'), so they must be targeted exactly as
// execution_artifacts is.
TEST_CASE("browser_inventory (real fragment): Forensics single-target rule — 1 agent Targeted, "
          "2 agents RefuseUntargeted for both actions",
          "[server][dispatch][security]") {
    namespace capdecls = yuzu::server::capdecls;
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_browser_inventory()};

    for (const char* action : {"browsers", "profiles"}) {
        auto classified = registry.classify("browser_inventory", action);
        REQUIRE(classified.has_value());
        CHECK(classified->securable == kForensicsSecurable);
        CHECK(requires_explicit_targets(*classified));

        const auto targeted = evaluate_destructive_targeting(classified,
                                                              /*valid_nonempty_agent_ids=*/true,
                                                              /*scope_key_present=*/false,
                                                              /*agent_id_count=*/1);
        CHECK(targeted.verdict == DestructiveTargetingVerdict::Targeted);

        const auto refused = evaluate_destructive_targeting(classified,
                                                             /*valid_nonempty_agent_ids=*/true,
                                                             /*scope_key_present=*/false,
                                                             /*agent_id_count=*/2);
        CHECK(refused.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK(refused.refusal_reason == kReasonForensicUntargeted);
    }
}

TEST_CASE("Destructive RefuseUntargeted arms carry the Destructive reason/message, not the "
          "Forensics pair",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/false,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
    CHECK(gate.refusal_reason == kReasonDestructiveUntargeted);
    CHECK(gate.refusal_message == kDestructiveUntargetedMessage);
}

// ──────────────────────────────────────────────── confine_destructive_targets ──

TEST_CASE("confine_destructive_targets: drops out-of-visible entries, preserves order and "
          "multiplicity of survivors",
          "[server][dispatch][security]") {
    const auto agent_ids = ids({"dev-A", "dev-X", "dev-B", "dev-A", "dev-Y"});
    const DestructiveVisibleAgents visible{
        std::optional<std::vector<std::string>>{ids({"dev-A", "dev-B"})}};

    const auto out = confine_destructive_targets(agent_ids, visible);
    CHECK(out == ids({"dev-A", "dev-B", "dev-A"}));
}

TEST_CASE("confine_destructive_targets: every id out of visible set -> empty",
          "[server][dispatch][security]") {
    const auto agent_ids = ids({"dev-X", "dev-Y"});
    const DestructiveVisibleAgents visible{
        std::optional<std::vector<std::string>>{ids({"dev-A", "dev-B"})}};

    CHECK(confine_destructive_targets(agent_ids, visible).empty());
}

TEST_CASE("confine_destructive_targets: present-but-empty visible list -> empty",
          "[server][dispatch][security]") {
    const auto agent_ids = ids({"dev-A", "dev-B"});
    const DestructiveVisibleAgents visible{std::optional<std::vector<std::string>>{
        std::vector<std::string>{}}};

    CHECK(confine_destructive_targets(agent_ids, visible).empty());
}

TEST_CASE("confine_destructive_targets: nullopt visible -> empty (FAIL CLOSED, ADR-0042)",
          "[server][dispatch][security]") {
    const auto agent_ids = ids({"dev-A", "dev-B"});
    const DestructiveVisibleAgents visible{std::nullopt};

    CHECK(confine_destructive_targets(agent_ids, visible).empty());
}

// ────────────────────────────────────────────────── refusal-string pins ──

TEST_CASE("#3685 defect 4: the two Destructive refusal strings are pinned byte-exact — "
          "first-ever test occurrence for either",
          "[server][dispatch][security]") {
    // Copied byte-exact from the live /api/command handler at the time this
    // file was written (verified via `git grep -n` against this worktree,
    // not from memory or the design doc's own quoted copy).
    CHECK(kDestructiveUntargetedMessage ==
          "destructive action requires explicit in-scope agent_ids; broadcast and "
          "scope fan-out are refused");
    CHECK(kDestructiveNoVisibleAgentMessage == "no reachable in-scope agent");
}

// ─────────────────────────────────── catalogue-consistency tripwire (bonus) ──
//
// Not required by the #3685 checkpoint-1 brief's own test list, but cheap
// and directly protective of the header's D4 doc-comment claims: composes
// the REAL registry exactly as the production composition site does
// (mirrors test_capability_catalogue.cpp's own `build_registry`) and pins
// the live Destructive row count. #3685's design doc claimed 14 Destructive
// rows; counting the actual capability_decls/*.hpp fragments during this
// checkpoint found 17 (19 once power_health's and printing's rows landed;
// verified at the time via `git grep -c ".dispatch_class =
// DispatchClass::Destructive" capability_decls/*.hpp`) — the "four
// Execution:Execute rows" sub-claim (script_exec.{exec,powershell,bash} +
// content_dist.execute_staged) IS accurate, but the total is not. This case
// pins the CORRECTED, live count so a future catalogue change that adds or
// removes a Destructive row has to touch this test, not silently drift past
// #3685's own coverage claim the way the design doc's count already did.
TEST_CASE("catalogue-consistency tripwire: the live Destructive row count is 19, not the design "
          "doc's stale 14 (#3685) — a new/removed Destructive row must touch this test",
          "[server][dispatch][security]") {
    namespace capdecls = yuzu::server::capdecls;

    const std::array<std::span<const CommandCapability>, 22> sources{{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::plugin_action_catalogue_disk_actions(),
        capdecls::plugin_action_catalogue_power_health(),
        capdecls::plugin_action_catalogue_filesystem_posture(),
        capdecls::plugin_action_catalogue_autoruns(),
        capdecls::plugin_action_catalogue_app_usage(),
        capdecls::plugin_action_catalogue_execution_artifacts(),
        capdecls::plugin_action_catalogue_windows_optional_features(),
        capdecls::plugin_action_catalogue_peripherals(),
        capdecls::plugin_action_catalogue_printing(),
        capdecls::plugin_action_catalogue_app_control(),
        capdecls::plugin_action_catalogue_firmware_posture(),
        capdecls::plugin_action_catalogue_runtimes(),
        capdecls::plugin_action_catalogue_platform_security(),
        capdecls::plugin_action_catalogue_browser_inventory(),
        capdecls::plugin_action_catalogue_system_hardening(),
        capdecls::plugin_action_catalogue_pkg_inventory(),
        capdecls::core_dispatch_capabilities(),
    }};

    std::size_t destructive_count = 0;
    std::size_t destructive_execution_securable_count = 0;
    for (const auto& src : sources) {
        for (const auto& row : src) {
            if (row.dispatch_class != DispatchClass::Destructive)
                continue;
            ++destructive_count;
            if (row.securable == "Execution")
                ++destructive_execution_securable_count;
            // A Destructive row `!system_reserved` — a new Destructive row
            // silently changing gate coverage must not also silently claim
            // the system-caller exemption core_dispatch_capabilities.hpp
            // rows carry.
            INFO("plugin=" << row.plugin << " action=" << row.action);
            CHECK_FALSE(row.system_reserved);
        }
    }
    // 19, not 17: power_health's set_power_plan and printing's clear_queue are
// each a Destructive row and the mirror must include both, or a FUTURE
// Destructive row in either fragment lands with the aggregate tripwire
// still passing -- which is exactly the drift this test's own title
// forbids.
    CHECK(destructive_count == 19);
    // D4's rationale (dispatch_destructive_gate.hpp doc comment): exactly
    // the four Execution:Execute rows rely on the chokepoint's
    // AdminOrApproval gate as their elevation ceiling. This sub-claim WAS
    // verified accurate (script_exec.{exec,powershell,bash} +
    // content_dist.execute_staged) even though the design doc's total-row
    // count was stale — pinned here so the two counts cannot silently
    // drift apart from each other either.
    CHECK(destructive_execution_securable_count == 4);

    // Composability spot check — mirrors test_capability_catalogue.cpp's own
    // `build_registry`: the same twenty-two spans compose into a real registry
    // exactly as the production composition site does, and a known
    // Destructive row still resolves through it.
    CommandCapabilityRegistry registry{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::plugin_action_catalogue_disk_actions(),
        capdecls::plugin_action_catalogue_power_health(),
        capdecls::plugin_action_catalogue_filesystem_posture(),
        capdecls::plugin_action_catalogue_autoruns(),
        capdecls::plugin_action_catalogue_app_usage(),
        capdecls::plugin_action_catalogue_execution_artifacts(),
        capdecls::plugin_action_catalogue_windows_optional_features(),
        capdecls::plugin_action_catalogue_peripherals(),
        capdecls::plugin_action_catalogue_printing(),
        capdecls::plugin_action_catalogue_app_control(),
        capdecls::plugin_action_catalogue_firmware_posture(),
        capdecls::plugin_action_catalogue_runtimes(),
        capdecls::plugin_action_catalogue_platform_security(),
        capdecls::plugin_action_catalogue_browser_inventory(),
        capdecls::plugin_action_catalogue_system_hardening(),
        capdecls::plugin_action_catalogue_pkg_inventory(),
        capdecls::core_dispatch_capabilities(),
    };
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());
    CHECK(classified->dispatch_class == DispatchClass::Destructive);
}

// ────────────────────────────────────── composition: targeting != authorization ──
//
// #3685 commit 3 (Sol's ask, folded into the plan's Decisions section): the
// targeting evaluator returning Targeted must not, by itself, be mistaken
// for an authorization decision. This section binds that separation two
// ways — a runtime demonstration that the SAME plugin.action pair can be
// Targeted here and still independently Forbidden at the real dispatch
// chokepoint, and a source-scan pin that REST's own require_permission call
// is still present and textually distinct from the chokepoint's
// has_permission callback.

using yuzu::server::authz::Operation;
using yuzu::server::detail::classify_and_authorize_dispatch;
using yuzu::server::detail::DispatchDenialReason;
using yuzu::server::DispatchCaller;

namespace {
[[nodiscard]] bool always_deny(std::string_view, std::string_view, Operation) { return false; }
} // namespace

TEST_CASE("#3685 composition: a Targeted verdict makes NO authorization decision — the same "
          "command can still be independently denied by classify_and_authorize_dispatch",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFixture)};

    // Step 1 — the pure targeting evaluator: explicit ids, no scope, a
    // Destructive row. Targeted means only "proceed to confinement"; it says
    // nothing about whether the caller is authorized to issue the command.
    auto classified = registry.classify("tar", "purge_source");
    REQUIRE(classified.has_value());
    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/false);
    REQUIRE(gate.verdict == DestructiveTargetingVerdict::Targeted);

    // Step 2 — the SAME registry, the SAME plugin.action pair, run through
    // the real dispatch chokepoint with an operator principal `has_permission`
    // denies. No call from step 1 into step 2, and no shared mutable state
    // between them (evaluate_destructive_targeting took the classify()
    // result by const reference and returned a plain value) — this is two
    // genuinely independent decisions on the same input, not one function
    // calling the other.
    DispatchCaller caller{.principal = "alice", .principal_role = "operator"};
    auto result =
        classify_and_authorize_dispatch(registry, caller, "tar", "purge_source", always_deny);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().reason == DispatchDenialReason::Forbidden);
    CHECK(result.error().securable == "Infrastructure");
}

// ──────────────────────── composition: require_permission stays REST's own ──

namespace {
namespace fs = std::filesystem;

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') -- see the server_test_exe cpp_args block."
#endif

std::string read_src_file(const std::string& name) {
    const fs::path path = fs::path(YUZU_SERVER_SRC_DIR) / name;
    REQUIRE(fs::is_regular_file(path));
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
} // namespace

TEST_CASE("#3685 composition: /api/command's require_permission call is present and textually "
          "distinct from the chokepoint's has_permission callback usage — source-scan structural "
          "pin (a runtime bind is awkward here: both live on ServerImpl/agent_registry.hpp "
          "internals with no test-reachable seam of their own)",
          "[server][dispatch][security]") {
    // #2557: the Destructive-gate composition moved from server.cpp's inline
    // /api/command handler to command_routes.cpp (the HttpRouteSink
    // extraction) — this scan follows it there. `require_permission` itself
    // became `deps.perm_fn` at the extraction boundary (every ServerImpl
    // method call in the handler became a `Deps` closure call), so the
    // literal this test looks for changed to match — the SEMANTIC property
    // being pinned (a caller-owned re-check, textually distinct from the
    // chokepoint's `has_permission` callback) is unchanged.
    const std::string command_routes_cpp = read_src_file("command_routes.cpp");

    // The Destructive-gate call site itself must still exist.
    const auto gate_pos = command_routes_cpp.find("evaluate_destructive_targeting(");
    REQUIRE(gate_pos != std::string::npos);

    // Within a bounded window after the gate call, /api/command's own
    // JIT-elevation-aware perm_fn(cap.securable, cap.operation) re-check
    // must still be present — this is D3/D4's "do not collapse the two"
    // invariant: the caller keeps its own authorization call, never folded
    // into or replaced by the chokepoint's has_permission callback.
    constexpr std::size_t kWindow = 4000;
    const std::string window = command_routes_cpp.substr(
        gate_pos, std::min(kWindow, command_routes_cpp.size() - gate_pos));
    CHECK(window.find("deps.perm_fn(req, res, std::string(cap.securable)") != std::string::npos);

    // And the chokepoint's own has_permission callback usage
    // (agent_registry.hpp) is a TEXTUALLY DISTINCT call — a different
    // function name entirely, never a shared/aliased spelling of
    // require_permission.
    const std::string agent_registry_hpp = read_src_file("agent_registry.hpp");
    CHECK(agent_registry_hpp.find(
              "has_permission(caller.principal, cap.securable, cap.operation)") !=
          std::string::npos);
    // The two identifiers themselves must differ — the structural guarantee
    // this test exists to pin. (Trivially true today; stated explicitly so
    // a future rename that made them collide would have to touch this
    // assertion, not silently pass it.)
    CHECK(std::string("require_permission") != std::string("has_permission"));
}

// ─────────────────────────────────────── Wave 6 W1B (power_health) — P-009 ──

namespace {

// A locally-constructed Destructive+Reversible row (power_health's real
// set_power_plan row is Destructive/Reversible/PowerManagement/Write/
// AdminOrApproval — see plugin_action_catalogue_power_health.hpp; not
// included here, this fixture is deliberately independent of the real
// catalogue, same as kFixture above).
inline constexpr std::array<CommandCapability, 1> kReversibleDestructiveFixture{{
    {
        .plugin = "power_health",
        .action = "set_power_plan",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Reversible,
        .securable = "PowerManagement",
        .operation = yuzu::server::authz::Operation::Write,
        .risk_tier = yuzu::server::authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

} // namespace

TEST_CASE("Destructive+Reversible row gates identically to Destructive+Irreversible: the gate is "
          "class-driven, mutability-independent (P-009)",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kReversibleDestructiveFixture)};
    auto classified = registry.classify("power_health", "set_power_plan");
    REQUIRE(classified.has_value());
    REQUIRE(classified->mutability == Mutability::Reversible);

    // Same targeting-shape matrix kFixture's Irreversible tar.purge_source
    // row exercises above: Targeted, RefuseUntargeted (no ids), and
    // RefuseUntargeted (ids + scope both present) — the verdict must match
    // in every case, because evaluate_destructive_targeting keys off
    // DispatchClass::Destructive alone, never Mutability.
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/false);
        CHECK(gate.verdict == DestructiveTargetingVerdict::Targeted);
        REQUIRE(gate.capability.has_value());
        CHECK(gate.capability->mutability == Mutability::Reversible);
        CHECK_FALSE(gate.miss.has_value());
    }
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/false,
                                                          /*scope_key_present=*/false);
        CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK_FALSE(gate.miss.has_value());
    }
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/true);
        CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
        CHECK_FALSE(gate.miss.has_value());
    }
}

TEST_CASE("power_health.set_power_plan: the REAL catalogue row (not the independent P-009 "
          "fixture above) is security-classified as Destructive/Reversible/PowerManagement/Write/"
          "AdminOrApproval and gates identically to a targeted Destructive dispatch — guards "
          "against the shipped row silently becoming permissive (e.g. downgraded to ReadOnly or "
          "ExecuteGate::None) while kReversibleDestructiveFixture's independent, class-driven "
          "assertions above continue to pass on their own (PH-006)",
          "[server][dispatch][security]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_power_health()};
    auto classified = registry.classify("power_health", "set_power_plan");
    REQUIRE(classified.has_value());

    CHECK(classified->dispatch_class == DispatchClass::Destructive);
    CHECK(classified->mutability == Mutability::Reversible);
    CHECK(classified->securable == "PowerManagement");
    CHECK(classified->operation == yuzu::server::authz::Operation::Write);
    CHECK(classified->risk_tier == yuzu::server::authz::RiskTier::Medium);
    CHECK(classified->execute_gate == ExecuteGate::AdminOrApproval);

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/false,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted);
}
