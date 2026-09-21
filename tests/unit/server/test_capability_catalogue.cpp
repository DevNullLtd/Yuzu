/**
 * test_capability_catalogue.cpp — PR1.9's cross-cutting invariant gate over
 * the WHOLE capability catalogue: the eight independently-authored sources
 * (the seven per-plugin-group `capability_decls/plugin_action_catalogue_*.hpp`
 * fragments plus the core-owned `capability_decls/core_dispatch_capabilities
 * .hpp`) composed into one `CommandCapabilityRegistry`, exactly as a real
 * dispatch chokepoint eventually will.
 *
 * Nobody who authors a single fragment can see the other seven, so nobody is
 * positioned to catch a row that under-declares risk for its operation, uses
 * a securable or operation that was never seeded, calls itself Destructive
 * without being Irreversible, or falsely claims `system_reserved`. This file
 * is where those checks live.
 *
 * Pure — no Postgres, no sleeps, no spawns, no clock. Every fragment is a
 * `constexpr` array over static storage; `CommandCapabilityRegistry` is a
 * plain composing view.
 */

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
#include "capability_decls/plugin_action_catalogue_update_source_trust.hpp"
#include "command_capability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <utility> // std::pair in kReversibleDestructive
#include <vector>

using namespace yuzu::server;

namespace {

// Mirrors rbac_store.cpp's `seed_defaults()` `types[]` (the securable types
// actually seeded into `rbac.db`) — this test file may not include or edit
// rbac_store.cpp (it is a .cpp with a live SQLite dependency, not a header,
// and this package's boundaries forbid editing it regardless), so the list
// is reproduced read-only here. If `types[]` ever changes, this mirror needs
// updating too — that is the intended failure mode: a securable this
// catalogue references but rbac_store.cpp stops seeding should fail loudly,
// not silently pass.
constexpr std::array<std::string_view, 30> kSeededSecurableTypes{{
    "Infrastructure",
    "UserManagement",
    "InstructionDefinition",
    "InstructionSet",
    "Execution",
    "Schedule",
    "Approval",
    "Tag",
    "AuditLog",
    "Response",
    "ManagementGroup",
    "ApiToken",
    "Security",
    "Policy",
    "DeviceToken",
    "SoftwareDeployment",
    "License",
    "FileRetrieval",
    "GuaranteedState",
    "Inventory",
    "AccessReview",
    "SoftwareLicensing",
    "EnginePrincipal", // #4030 Gate 8 fix: was missing (pre-existing gap,
                       // predates #4030 -- already flagged by #4029's own
                       // Gate 8 pass on its own worktree; closed here since
                       // this file is already being touched for "Workflow"
                       // below).
    "PluginConfig",
    "PluginSecret",
    "UploadGrant",
    "PowerManagement",
    "Workflow", // #4030: this PR's own new securable (rbac_store.cpp) --
                // this mirror was the third of three hand-maintained
                // copies (rbac_store.cpp's types[], mcp_server.cpp's
                // kRbacSecurables[], and this one) and was the one left
                // stale (cpp-expert, Gate 3).
    "Forensics",
    "Decommission",
}};

// Mirrors rbac_store.cpp's `seed_defaults()` `ops[]` — the full seven-value
// `authz::Operation` vocabulary that store seeds grants over.
constexpr std::array<std::string_view, 7> kSeededOperations{{
    "Read", "Write", "Execute", "Delete", "Approve", "Push", "Attest",
}};

[[nodiscard]] bool is_seeded_securable(std::string_view securable) noexcept {
    return std::find(kSeededSecurableTypes.begin(), kSeededSecurableTypes.end(), securable) !=
           kSeededSecurableTypes.end();
}

[[nodiscard]] bool is_seeded_operation(authz::Operation op) noexcept {
    const auto name = authz::to_string(op);
    return std::find(kSeededOperations.begin(), kSeededOperations.end(), name) !=
           kSeededOperations.end();
}

/// One entry per span this test composes, paired with a human label for
/// failure messages and whether the span is the core (system-reserved)
/// source — everything else is the two-way `system_reserved` boundary this
/// file enforces.
struct LabeledSpan {
    std::string_view label;
    std::span<const CommandCapability> rows;
    bool is_core;
};

[[nodiscard]] std::vector<LabeledSpan> all_labeled_sources() {
    return {
        {"content_dist", capdecls::plugin_action_catalogue_content_dist(), false},
        {"a", capdecls::plugin_action_catalogue_a(), false},
        {"b", capdecls::plugin_action_catalogue_b(), false},
        {"c", capdecls::plugin_action_catalogue_c(), false},
        {"d", capdecls::plugin_action_catalogue_d(), false},
        {"disk_actions", capdecls::plugin_action_catalogue_disk_actions(), false},
        {"filesystem_posture", capdecls::plugin_action_catalogue_filesystem_posture(), false},
        {"power_health", capdecls::plugin_action_catalogue_power_health(), false},
        {"autoruns", capdecls::plugin_action_catalogue_autoruns(), false},
        {"app_usage", capdecls::plugin_action_catalogue_app_usage(), false},
        {"execution_artifacts", capdecls::plugin_action_catalogue_execution_artifacts(), false},
        {"windows_optional_features", capdecls::plugin_action_catalogue_windows_optional_features(), false},
        {"peripherals", capdecls::plugin_action_catalogue_peripherals(), false},
        {"printing", capdecls::plugin_action_catalogue_printing(), false},
        {"update_source_trust", capdecls::plugin_action_catalogue_update_source_trust(), false},
        {"core", capdecls::core_dispatch_capabilities(), true},
    };
}

[[nodiscard]] CommandCapabilityRegistry build_registry(const std::vector<LabeledSpan>& sources) {
    // CommandCapabilityRegistry's constructor only accepts a brace-enclosed
    // std::initializer_list (see command_capability.hpp), so this can't be
    // built from the vector programmatically — it mirrors all_labeled_sources()
    // literally, sixteen sources exactly as a live composition site would use.
    return CommandCapabilityRegistry{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::plugin_action_catalogue_disk_actions(),
        capdecls::plugin_action_catalogue_filesystem_posture(),
        capdecls::plugin_action_catalogue_power_health(),
        capdecls::plugin_action_catalogue_autoruns(),
        capdecls::plugin_action_catalogue_app_usage(),
        capdecls::plugin_action_catalogue_execution_artifacts(),
        capdecls::plugin_action_catalogue_windows_optional_features(),
        capdecls::plugin_action_catalogue_peripherals(),
        capdecls::plugin_action_catalogue_printing(),
        capdecls::plugin_action_catalogue_update_source_trust(),
        capdecls::core_dispatch_capabilities(),
    };
}

} // namespace

TEST_CASE("capability catalogue: every row's risk_tier is at or above its operation's floor",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            CHECK(static_cast<uint8_t>(row.risk_tier) >=
                  static_cast<uint8_t>(authz::min_risk_tier_for(row.operation)));
        }
    }
}

TEST_CASE("capability catalogue: every securable and operation is one rbac_store.cpp actually "
          "seeds",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action << " securable=" << row.securable);
            CHECK(is_seeded_securable(row.securable));
            CHECK(is_seeded_operation(row.operation));
        }
    }
}

/// Destructive rows that are deliberately `Reversible`, with the reason. Every
/// other Destructive row must be `Irreversible`.
///
/// `command_capability.hpp:42-46` is explicit that mutability reflects "the
/// actual device-side effect, never inferred from `DispatchClass` alone", so
/// Destructive+Reversible is a legal combination rather than a contradiction —
/// but until Wave 6 every shipped Destructive row happened to be Irreversible,
/// and this case asserted that coincidence as a universal. It is kept as an
/// explicit allowlist so a NEW Destructive+Reversible row still fails loudly
/// and has to be justified here, which is the property the original assertion
/// was really providing.
constexpr std::array<std::pair<std::string_view, std::string_view>, 1> kReversibleDestructive{{
    {"power_health.set_power_plan",
     "switching the active Windows power scheme is undone by setting the previous scheme back; "
     "the action captures and emits previous_guid precisely so the operator can. It is "
     "Destructive (not Mutating) because it must inherit the destructive-targeting gate — "
     "explicit device IDs, no unapproved broadcast — not because the effect is unrecoverable."},
}};

TEST_CASE("capability catalogue: every Destructive row is Irreversible unless explicitly "
          "allowlisted",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            if (row.dispatch_class != DispatchClass::Destructive)
                continue;
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            const std::string pair = std::string{row.plugin} + "." + std::string{row.action};
            const bool allowlisted =
                std::find_if(kReversibleDestructive.begin(), kReversibleDestructive.end(),
                             [&](const auto& e) { return e.first == pair; }) !=
                kReversibleDestructive.end();
            if (allowlisted) {
                // The allowlist exists for Reversible rows; an allowlisted row that
                // is Irreversible means the entry is stale and should be removed.
                CHECK(row.mutability == Mutability::Reversible);
                continue;
            }
            CHECK(row.mutability == Mutability::Irreversible);
        }
    }
}

/// Exact-row pin for `autoruns` (P15 Arbiter action). Both its actions are
/// ReadOnly/None with no Destructive row to protect via the allowlist above,
/// so this pins their classification directly, the same way
/// `kReversibleDestructive` protects `power_health.set_power_plan`'s fields
/// from a silent future change.
TEST_CASE("capability catalogue: autoruns.list and autoruns.catalog pin their exact "
          "classification",
          "[server][dispatch][capability]") {
    const auto rows = capdecls::plugin_action_catalogue_autoruns();
    for (const auto action : {"list", "catalog"}) {
        const auto it =
            std::find_if(rows.begin(), rows.end(), [&](const auto& r) { return r.action == action; });
        REQUIRE(it != rows.end());
        CHECK(it->dispatch_class == DispatchClass::ReadOnly);
        CHECK(it->mutability == Mutability::None);
        CHECK(it->securable == "Security");
        CHECK(it->operation == authz::Operation::Read);
        CHECK(it->execute_gate == ExecuteGate::None);
    }
}

TEST_CASE("capability catalogue: system_reserved is true only for core_dispatch_capabilities.hpp "
          "rows",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            CHECK(row.system_reserved == source.is_core);
        }
    }
}

/// Exact-row pin for `update_source_trust.sources` (Wave 10 PR10.1-d). The
/// action is a read-only supply-chain-POSTURE fact under `Security`:Read with
/// no execute gate. Pinning it directly means a silent drift to a mutating
/// class, a different securable, or a gate on a facts-only read fails here.
TEST_CASE("capability catalogue: update_source_trust.sources pins its exact classification",
          "[server][dispatch][capability]") {
    const auto rows = capdecls::plugin_action_catalogue_update_source_trust();
    REQUIRE(rows.size() == 1);
    const auto& row = rows.front();
    CHECK(row.plugin == "update_source_trust");
    CHECK(row.action == "sources");
    CHECK(row.dispatch_class == DispatchClass::ReadOnly);
    CHECK(row.mutability == Mutability::None);
    CHECK(row.securable == "Security");
    CHECK(row.operation == authz::Operation::Read);
    CHECK(row.risk_tier == authz::RiskTier::Low);
    CHECK(row.system_reserved == false);
    CHECK(row.execute_gate == ExecuteGate::None);
}

TEST_CASE("capability catalogue: classify() resolves every declared plugin.action across all eight "
          "sources",
          "[server][dispatch][capability]") {
    auto registry = build_registry(all_labeled_sources());
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            auto result = registry.classify(row.plugin, row.action);
            REQUIRE(result.has_value());
            CHECK(result->plugin == row.plugin);
            CHECK(result->action == row.action);
        }
    }
}

TEST_CASE("capability catalogue: a locally-constructed duplicate span makes the registry report "
          "Ambiguous, never first-wins",
          "[server][dispatch][capability]") {
    // Deliberately collides with content_dist's real `content_dist.stage` row
    // — a locally-constructed fixture, never an edit to the fragment itself
    // (this package may not touch capability_decls/*.hpp).
    static constexpr std::array<CommandCapability, 1> kDuplicateStageSpan{{
        {
            .plugin = "content_dist",
            .action = "stage",
            .dispatch_class = DispatchClass::ReadOnly,
            .mutability = Mutability::None,
            .securable = "Response",
            .operation = authz::Operation::Read,
            .risk_tier = authz::RiskTier::Low,
            .system_reserved = false,
        },
    }};

    CommandCapabilityRegistry registry{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::plugin_action_catalogue_disk_actions(),
        capdecls::plugin_action_catalogue_filesystem_posture(),
        capdecls::core_dispatch_capabilities(),
        std::span<const CommandCapability>(kDuplicateStageSpan),
    };

    auto result = registry.classify("content_dist", "stage");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == ClassificationError::Ambiguous);

    // A different content_dist action, untouched by the duplicate, still
    // resolves normally — ambiguity is per plugin.action, not registry-wide.
    auto other = registry.classify("content_dist", "list_staged");
    REQUIRE(other.has_value());
    CHECK(other->dispatch_class == DispatchClass::ReadOnly);
}
