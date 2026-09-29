#pragma once

#include <string>
#include <string_view>

// The reserved `mcp.` definition-id namespace (#2442).
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
//   * InstructionStore::create_definition_impl — authoring (create + import)
//   * validate_instruction_yaml        — the YAML validator, which MUST agree
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
// A third site would be a third chance to diverge: call `is_reserved_definition_id`
// and report `kReservedDefinitionIdError` rather than re-implementing either.
// mcp_server.cpp is the fourth call site of `kMcpDefinitionPrefix` (it builds
// the definition id at the MCP mint) but not of the predicate above — it has
// no authoring decision to gate, only a literal to share.
namespace yuzu::server {

/// Definition-id prefix reserved for MCP-minted approval tickets.
inline constexpr std::string_view kMcpDefinitionPrefix = "mcp.";

/// True iff `id` lands in the reserved namespace. Case-sensitive on purpose:
/// SQLite's default BINARY collation makes `MCP.` a different id everywhere
/// else, so treating it as reserved here would refuse an id nothing else
/// conflates.
[[nodiscard]] inline bool is_reserved_definition_id(std::string_view id) {
    return id.starts_with(kMcpDefinitionPrefix);
}

/// THE denial message, shared by all three sites. One rule reads as one denial
/// to an operator and keys as one stable token in a SIEM rule
/// (docs/user-manual/audit-log.md enumerates it) — two hand-written variants of
/// the same refusal is how that contract silently drifts.
inline constexpr std::string_view kReservedDefinitionIdError =
    "definition id may not use the reserved 'mcp.' prefix (reserved for MCP approvals)";

} // namespace yuzu::server
