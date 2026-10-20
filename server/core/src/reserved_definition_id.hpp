#pragma once

#include <string>
#include <string_view>

// The reserved `mcp.` and `guardian.` definition-id namespaces (#2442, #6062).
//
// `guardian.` (#6062, four-eyes MVP PR2) is reserved by the SAME mechanism, for the
// same reason: Guardian rule-deploy approvals (ApprovalOrigin::kGuardianDeploy) are
// minted under `guardian.<...>`, and an authored instruction definition under that
// prefix would be a ticket namespace an operator can populate from the instruction
// editor. The recorded origin, not the prefix, is what redemption trusts; the prefix
// is the authoring-side half, so the two namespaces stay separable on screen and in
// audit as well as in the store.
//
// MCP approval tickets are minted under `mcp.<tool>`, and the MCP recall matched
// a ticket on (definition_id, scope_expression) alone, without binding the
// minting surface or the submitter. So a definition id under that prefix,
// reachable from any other surface, was a ticket the MCP gate would accept.
// Both gaps are closed at REDEMPTION now, not here: `consume_ticket` refuses a
// ticket whose recorded origin isn't MCP, and separately refuses one whose
// `submitted_by` doesn't match the recalling principal (see
// `ApprovalManager::consume_ticket`'s doc comment). This header is about the
// definition-id NAMESPACE, a narrower, mint-time-adjacent concern: it stops a
// definition from being authored under `mcp.` in the first place. The rule
// lives here, once, because it has to hold at two unrelated places that would
// otherwise each carry a copy:
//
//   * InstructionStore::validate_and_prepare — authoring (create + import)
//   * instruction_yaml::validate_definition_yaml — the YAML validator, which MUST agree
//     with the store or the "YAML that validates always saves" contract breaks
//     (#1993, re-broken by #2010 and again by the first cut of #2442 — three
//     times, which is why the predicate is no longer copied)
//
// (`ApprovalManager::submit` was a third site and enforced this at MINT time.
// That refusal was removed deliberately — it permanently stopped schedules on
// pre-existing `mcp.`-prefixed definitions — and #2442 is now defended at
// redemption instead. The store RECORDS the minting surface; it does not police
// the namespace.)
//
// A further site would be another chance to diverge: call `is_reserved_definition_id`
// and report `kReservedDefinitionIdError` rather than re-implementing either.
// mcp_server.cpp is the fourth call site of `kMcpDefinitionPrefix` (it builds
// the definition id at the MCP mint) but not of the predicate above — it has
// no authoring decision to gate, only a literal to share.
namespace yuzu::server {

/// Definition-id prefix reserved for MCP-minted approval tickets.
inline constexpr std::string_view kMcpDefinitionPrefix = "mcp.";

/// Definition-id prefix reserved for Guardian rule-deploy approval tickets (#6062).
inline constexpr std::string_view kGuardianDefinitionPrefix = "guardian.";

/// True iff `id` is under the MCP prefix specifically. The Approvals page keys its
/// "MCP" tag, its tool-name display and its "re-call the tool" note off this, NOT off
/// `is_reserved_definition_id`: a `guardian.` ticket is reserved but is not an MCP
/// tool call.
[[nodiscard]] inline bool is_mcp_definition_id(std::string_view id) {
    return id.starts_with(kMcpDefinitionPrefix);
}

/// True iff `id` lands in ANY reserved namespace. Case-sensitive on purpose:
/// ids are compared byte-for-byte everywhere else, so `MCP.` is a different id,
/// and treating it as reserved here would refuse an id nothing else conflates.
[[nodiscard]] inline bool is_reserved_definition_id(std::string_view id) {
    return is_mcp_definition_id(id) || id.starts_with(kGuardianDefinitionPrefix);
}

/// THE denial messages, shared by both authoring sites. One rule reads as one denial
/// to an operator and keys as one stable token in a SIEM rule
/// (docs/user-manual/audit-log.md enumerates them) - two hand-written variants of
/// the same refusal is how that contract silently drifts. The `mcp.` text is the
/// #2442 token and is deliberately UNCHANGED; `guardian.` has its own so a rule keyed
/// on the first keeps matching exactly what it matched before.
inline constexpr std::string_view kReservedDefinitionIdError =
    "definition id may not use the reserved 'mcp.' prefix (reserved for MCP approvals)";
inline constexpr std::string_view kReservedGuardianDefinitionIdError =
    "definition id may not use the reserved 'guardian.' prefix (reserved for Guardian "
    "deploy approvals)";

/// The denial message for `id`, or an empty view when `id` is not reserved. Both
/// authoring sites call THIS (not the constants), so which prefix fired can never
/// disagree with which message is reported.
[[nodiscard]] inline std::string_view reserved_definition_id_error(std::string_view id) {
    if (is_mcp_definition_id(id))
        return kReservedDefinitionIdError;
    if (id.starts_with(kGuardianDefinitionPrefix))
        return kReservedGuardianDefinitionIdError;
    return {};
}

} // namespace yuzu::server
