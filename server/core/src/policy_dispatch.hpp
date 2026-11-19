#pragma once

// policy_dispatch.hpp: the one refusal seam for policy evaluation's dispatch.
//
// Policy evaluation applies the action approval requirement before dispatch. This
// header holds that decision, applied before anything is sent: a pair is dispatched
// only when it is classified, is not reserved for the server's own use, has no
// execute gate and is not Destructive.
//
// Pure and header-only: no store, no I/O, no allocation, so it is `noexcept`
// and can be unit tested against any registry. The evaluator calls it in
// `PolicyEvaluator::dispatch_instruction`, the only place that reaches
// `dispatch_fn`.
//
// Precedence, fixed so tests and the write-on-change `blocked` row are
// deterministic (the evaluator's own `Unwired` arm comes first and does not call
// the seam):
//   1. a non-empty plugin or action that is not a well-formed dispatch
//      identifier: DispatchIdentifierInvalid
//   2. classification fails: Ambiguous or Unclassified
//   3. the row's execute gate is Unspecified: Unclassified (as the interactive
//      chokepoint does)
//   4. system_reserved: Reserved
//   5. any execute gate other than None: Gated
//   6. Destructive class: Destructive
//   otherwise the row is returned and the pair may be dispatched.

#include "command_capability.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace yuzu::server {

/// The limit instruction authoring applies to each of plugin and action
/// (`kMaxDefinitionDispatchIdentifierLen`, instruction_definition_model.hpp).
/// Mirrored here so this header stays light; a test pins the two together.
inline constexpr std::size_t kMaxPolicyDispatchIdentifierLen = 128;

/// Why policy evaluation refused to dispatch a pair. The lowercase tokens are the
/// `blocked` row's reason, the `yuzu_server_policy_dispatch_denied_total` label, the
/// audit reason and the log field: one string everywhere.
enum class PolicyDispatchDenialReason : uint8_t {
    Unclassified,              ///< no capability row, or an unspecified execute gate
    Ambiguous,                 ///< two or more rows for the same pair
    Gated,                     ///< the row has an execute gate
    Destructive,               ///< the row is Destructive
    Reserved,                  ///< the row is reserved for the server's own dispatch
    Unwired,                   ///< the evaluator holds no registry (fails closed)
    DispatchIdentifierInvalid, ///< plugin or action over 128 bytes or off the authoring charset
};

/// The reason only: keeps the seam `noexcept` and allocation free. The caller holds
/// the plugin and action and records them itself.
struct PolicyDispatchDenial {
    PolicyDispatchDenialReason reason;
};

/// Who asked for the dispatch. Decides whether a refusal always writes an audit row
/// (an operator-triggered evaluate or remediate) or only when the `blocked` write
/// changed something (the scheduler tick and the verify phase).
enum class DispatchOrigin : uint8_t {
    Tick,
    Operator,
};

/// No `default:` so `-Werror=switch` catches a new enumerator without a token.
[[nodiscard]] constexpr std::string_view to_string(PolicyDispatchDenialReason reason) noexcept {
    switch (reason) {
        case PolicyDispatchDenialReason::Unclassified: return "unclassified";
        case PolicyDispatchDenialReason::Ambiguous: return "ambiguous";
        case PolicyDispatchDenialReason::Gated: return "gated";
        case PolicyDispatchDenialReason::Destructive: return "destructive";
        case PolicyDispatchDenialReason::Reserved: return "reserved";
        case PolicyDispatchDenialReason::Unwired: return "unwired";
        case PolicyDispatchDenialReason::DispatchIdentifierInvalid:
            return "dispatch_identifier_invalid";
    }
    return "";
}

/// One part of a dispatch pair: 1 to 128 bytes of letters, digits, '_', '.' and '-'. The
/// same rule as `check_dispatch_identifier` (instruction_definition_model.cpp), without
/// its allocation; a test checks the two agree on every byte and at the length limits.
[[nodiscard]] constexpr bool dispatch_identifier_part_ok(std::string_view part) noexcept {
    if (part.empty() || part.size() > kMaxPolicyDispatchIdentifierLen)
        return false;
    for (const char ch : part) {
        const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                        (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
        if (!ok)
            return false;
    }
    return true;
}

/// A pair is well formed when each NON-EMPTY part is a valid identifier. An empty part is
/// not an identifier failure: authoring allows an empty action, and an empty part falls
/// through to classification, which refuses it as Unclassified.
[[nodiscard]] constexpr bool dispatch_pair_well_formed(std::string_view plugin,
                                                       std::string_view action) noexcept {
    return (plugin.empty() || dispatch_identifier_part_ok(plugin)) &&
           (action.empty() || dispatch_identifier_part_ok(action));
}

/// The refusal decision. Returns the classified row when the pair may be dispatched.
[[nodiscard]] inline std::expected<CommandCapability, PolicyDispatchDenial>
authorize_policy_dispatch(const CommandCapabilityRegistry& registry, std::string_view plugin,
                          std::string_view action) noexcept {
    if (!dispatch_pair_well_formed(plugin, action))
        return std::unexpected(
            PolicyDispatchDenial{PolicyDispatchDenialReason::DispatchIdentifierInvalid});

    const auto classified = registry.classify(plugin, action);
    if (!classified)
        return std::unexpected(PolicyDispatchDenial{
            classified.error() == ClassificationError::Ambiguous
                ? PolicyDispatchDenialReason::Ambiguous
                : PolicyDispatchDenialReason::Unclassified});

    const CommandCapability& cap = *classified;
    // An unspecified gate is a classification failure, as at the interactive chokepoint
    // (`classify_and_authorize_dispatch`); every fragment's compile-time sweep should make it
    // unreachable, so reaching it means that sweep is broken. Checked before the others so
    // an unspecified row is never reported as allowed or as gated.
    if (cap.execute_gate == ExecuteGate::Unspecified)
        return std::unexpected(PolicyDispatchDenial{PolicyDispatchDenialReason::Unclassified});
    if (cap.system_reserved)
        return std::unexpected(PolicyDispatchDenial{PolicyDispatchDenialReason::Reserved});
    if (cap.execute_gate != ExecuteGate::None)
        return std::unexpected(PolicyDispatchDenial{PolicyDispatchDenialReason::Gated});
    // A switch with no `default:`, like the gate switch at the interactive chokepoint: a new
    // `DispatchClass` enumerator is a `-Werror=switch` build failure here, never a silent
    // admit. A value no branch names (an out-of-range cast) is refused as unclassified.
    switch (cap.dispatch_class) {
        case DispatchClass::ReadOnly:
        case DispatchClass::Mutating:
            return cap;
        case DispatchClass::Destructive:
            return std::unexpected(PolicyDispatchDenial{PolicyDispatchDenialReason::Destructive});
    }
    return std::unexpected(PolicyDispatchDenial{PolicyDispatchDenialReason::Unclassified});
}

} // namespace yuzu::server
