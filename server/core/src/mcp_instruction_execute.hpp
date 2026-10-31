#pragma once

/// @file mcp_instruction_execute.hpp
/// MCP twin of `POST /api/instructions/{id}/execute`: the `execute_instruction_definition` tool
/// (ledger row `post.api-instructions-param-execute`, #2146, ADR-1005 Decision 4). Owner ruling
/// 2026-10-30: the existing `execute_instruction` is a RAW plugin/action call (no definition, no
/// `approval_mode`, no parameter schema) and is NOT this row's twin; this is a NEW tool that
/// takes a definition id plus params.
///
/// The pipeline is instruction_execute.hpp's, shared with the REST route. This file owns only
/// what is MCP-specific: the input bounds, the mapping of an `Outcome` to a JSON-RPC response,
/// and the composition rule below.
///
/// THE COMPOSITION OF TWO APPROVAL MECHANISMS (binding security rule, owner ruling 2026-10-30).
///   (1) THE TIER LADDER (mcp_policy.hpp, enforced by the generic C8 gate in mcp_server.cpp
///       BEFORE any handler): readonly refuses `Execution:Execute`; OPERATOR tier admits it with
///       no ticket ("auto-approved"); SUPERVISED tier admits it only through a ticket
///       (ticket-then-recall). This is a fact about the TOKEN, and it is NEVER translated into
///       `approval_provenance == Ticket` for this tool (see "NO TICKET PROVENANCE" below).
///   (2) THE DEFINITION'S OWN `approval_mode` (`auto` / `role-gated` / `always` / unknown =
///       approval): a fact about the DEFINITION.
/// (1) NEVER satisfies (2). An operator-tier auto-approval and a supervised ticket that C8
/// consumed are not inputs to the definition gate (`instruction_execute::Request` has no field
/// for either), so a non-auto definition answers `pending_approval` and dispatches nothing for
/// every tier. Conversely (2) never replaces (1): a supervised call on an `auto` definition
/// still needs its C8 ticket. The cost of putting the definition gate FIRST is that a
/// supervised caller on a non-auto definition is answered `pending_approval` by the pre-mint
/// probe (mcp_server.cpp C8 block) and never mints or burns a tier ticket for a call whose
/// answer is already "needs approval". The probe tolerates nothing: a caller whose (plugin,
/// action) pair is gated by the ExecuteGate and who is not an administrator is refused there
/// (`approval_required`, permanent, no retry hint), before any tier ticket exists.
///
/// NO TICKET PROVENANCE (sec-F1, architect ruling). The C8 tier ticket binds the call's
/// ARGUMENTS (definition_id, params, targets). The (plugin, action) pair it would run comes from
/// the STORED definition, which `update_definition` edits in place, so between approval and
/// recall an editor can repoint the definition at a pair carrying `AdminOrApproval` /
/// `AlwaysApproval`. Stamping `Ticket` would then lift that gate on an approval that was granted
/// for a different action. This tool therefore never stamps it: the pair's own ExecuteGate
/// decides, evaluated at the recall against the pair that will actually dispatch. Cost, accepted
/// by the owner: a supervised token cannot use a ticket to run a definition whose pair is gated;
/// it gets an `approval_required` refusal (permission denied, no retry hint), and only an
/// administrator caller (a ROLE fact, `principal_is_admin`: the token carries its creator's
/// role) still reaches a gated pair or a `role-gated` definition.
///
/// `pending_approval` is a SUCCESS result, not `-32006`: that code's contract is a ticket the
/// caller may redeem by re-calling with `approval_id`, and this ticket is minted with
/// `ApprovalOrigin::kInstruction`, which the MCP recall refuses (`origin_redeemable_as`). There
/// is no redemption path through this tool, and the description says so.
///
/// DispatchCaller: this file constructs none. The caller comes from `McpServer::CallerFn`; the
/// handler forces `approval_provenance = None` (dispatch_caller.hpp: this tool is NOT a stamping
/// site).

#include "instruction_execute.hpp"
#include "mcp_input_bounds.hpp" // BoundViolation

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace yuzu::server::mcp::instruction_definition {

inline constexpr const char* kToolName = "execute_instruction_definition";

/// One principal's share of the global pending-approval queue (the C8 mint uses the same 25).
inline constexpr int kSubmitterPendingCap = 25;

/// `definition_id` bound (bytes). Stored ids are short slugs; the schema literal repeats it.
inline constexpr std::size_t kDefinitionIdMaxLen = kExecInstrIdentMaxLen;

/// The bounds the CLOSED input-schema subset cannot express, plus the shared targeting shape.
/// Pure and total. Runs pre-mint (C8) and in the handler, so a supervised call that violates
/// one never mints or burns a ticket.
[[nodiscard]] std::optional<BoundViolation> check_args(const nlohmann::json& args);

/// The request body the core reads: `args` without the control-plane keys (`definition_id`,
/// `approval_id`).
[[nodiscard]] nlohmann::json core_body(const nlohmann::json& args);

/// One JSON-RPC response, ready for `res.set_content`. `is_error` selects `error_response` (with
/// `data_json` as `error.data`) or `success_response(tool_result(payload, kObjectOutputSchema))`.
struct Rendered {
    bool is_error{false};
    int code{0};
    std::string message;
    std::string data_json;     ///< error.data (always carries correlation_id, retry_after_ms, reason)
    std::string payload_json;  ///< the tool result object when !is_error
};

[[nodiscard]] Rendered render_refusal(const instruction_execute::Refusal& r, bool audit_dropped,
                                      const std::string& correlation_id);
[[nodiscard]] Rendered render_pending(const instruction_execute::PendingApproval& p,
                                      bool audit_dropped);
[[nodiscard]] Rendered render_outcome(const instruction_execute::Outcome& o,
                                      const std::string& correlation_id);
/// The pre-mint probe's answer: engaged for a refusal or a pending approval (respond with it,
/// mint nothing), empty for a Plan (fall through to the C8 ticket flow).
[[nodiscard]] std::optional<Rendered>
render_unless_plan(const instruction_execute::PrepareOutcome& p, const std::string& correlation_id);

} // namespace yuzu::server::mcp::instruction_definition
