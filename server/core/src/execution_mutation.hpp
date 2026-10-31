#pragma once

#include "authz_model.hpp"
#include "execution_tracker.hpp"

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

/// @file execution_mutation.hpp
/// ONE copy of the admit -> audit -> effect -> audit sequence behind the two execution
/// mutations that exist on both REST v1 and MCP (docs/api-twin-recipe.md Rule 1):
///
///   - cancel: `POST /api/v1/executions/{id}/cancel` and MCP `cancel_execution`
///   - rerun:  `POST /api/v1/executions/{id}/rerun` and MCP `record_execution_rerun`
///
/// Both surfaces build an `ExecutionMutationRequest` from their own gate results and map the
/// returned status onto their own envelope; neither re-derives the decision. The legacy
/// `/api/executions/{id}/{cancel,rerun}` handlers (`execution_routes.cpp`) predate this and are
/// DELIBERATELY left untouched (the source tripwires in test_legacy_executions_scope_authz.cpp
/// pin their text); they call the same primitives (`admit_confined_mutation`,
/// `mark_cancelled_checked`, `create_rerun`).
///
/// WHAT NEITHER MUTATION DOES. Cancel only marks the tracker row cancelled; it sends nothing to
/// any device. Rerun only creates a PENDING tracker record linked to the original; it sends
/// nothing to any device either, and no agent runs anything because of it. Every surface's
/// name and description must keep saying so.
///
/// SEQUENCE (the order is the contract; a test pins each step):
///   1. an empty `username` is refused outright. The legacy handlers fall back to the string
///      "unknown" for an unconfined caller; that fallback is NOT copied. Nothing is audited
///      (there is no principal to attribute the row to) and nothing is read or written.
///   2. the execution and, for a CONFINED caller, its agent-status rows are read
///      UNCONDITIONALLY, so a nonexistent id and an existing-but-hidden id cost the same number
///      of store round trips. A degraded read is `kStoreDegraded`, never a not-found.
///   3. admission: a confined caller needs `admit_confined_mutation` (the dispatcher alone
///      before any agent has reported; otherwise COMPLETE cohort visibility, so a partially
///      visible or incomplete cohort denies). Not admitted -> `kNotFound` with the SAME
///      response and the SAME `denied` audit detail whether the id is hidden or does not exist.
///      An unconfined caller who names an unknown id also gets `kNotFound`, with no audit row
///      (not a confinement decision; matches the read twins).
///   4. the `attempted` audit row is written BEFORE the effect. If it is not durable the effect
///      is NOT performed (`kAuditFailed`, the surface answers 503 / `Sec-Audit-Failed`).
///   5. the effect, then the outcome row (`success` / `failure` / `denied` for the cancel
///      state-guard refusal). The effect has already happened by then, so a failed outcome row
///      does not undo it: it is reported as `audit_persisted=false` on an otherwise successful
///      outcome.
///
/// The ports below exist so this sequence is testable without Postgres; production binds them
/// to the `ExecutionTracker` with `make_tracker_mutation_ports`.

namespace yuzu::server {

enum class ExecutionMutation { kCancel, kRerun };

struct ExecutionMutationPorts {
    /// `unexpected` = the read DEGRADED; an empty inner optional = no such execution.
    std::function<std::expected<std::optional<Execution>, std::string>(const std::string&)>
        get_execution;
    /// `nullopt` = the read DEGRADED. Always the COMPLETE, unfiltered cohort (admission needs it).
    std::function<std::optional<std::vector<AgentExecStatus>>(const std::string&)> get_statuses;
    std::function<ExecutionTracker::MarkCancelledOutcome(const std::string&, const std::string&)>
        mark_cancelled;
    std::function<std::expected<std::string, std::string>(const std::string&, const std::string&,
                                                          bool)>
        create_rerun;

    [[nodiscard]] bool wired() const {
        return get_execution && get_statuses && mark_cancelled && create_rerun;
    }
};

/// Ports bound to a live tracker. A null tracker yields unwired ports (`wired() == false`).
[[nodiscard]] ExecutionMutationPorts make_tracker_mutation_ports(ExecutionTracker* tracker);

struct ExecutionMutationRequest {
    ExecutionMutation what{ExecutionMutation::kCancel};
    std::string execution_id;
    /// The resolved principal. Empty is refused (`kNoPrincipal`); there is no "unknown" default.
    std::string username;
    /// The fleet-read scope: `nullopt` = unconfined, present-empty = deny-all.
    authz::VisibleSet scope;
    /// Rerun only: target just the agents that failed.
    bool failed_only{false};
    /// Appended to every audit detail (e.g. "surface=rest-v1 cid=..."). Same shape for the
    /// hidden and the nonexistent case, so it cannot tell them apart.
    std::string audit_context;
};

enum class ExecutionMutationStatus {
    kDone,            ///< cancel: the row is now cancelled. rerun: a pending record exists.
    kNoPrincipal,     ///< empty username; nothing read, written or audited.
    kStoreDegraded,   ///< an admission read failed; retryable; nothing written.
    kNotFound,        ///< nonexistent OR hidden from this caller (indistinguishable).
    kAuditFailed,     ///< the attempted row was not durable; the effect was NOT performed.
    kAlreadyFinished, ///< cancel only: unknown-by-now or already terminal; no state change.
    kStoreFailed,     ///< the effect itself failed; nothing changed.
};

struct ExecutionMutationOutcome {
    ExecutionMutationStatus status{ExecutionMutationStatus::kStoreDegraded};
    /// Rerun + kDone: the id of the new pending record.
    std::string new_execution_id;
    /// False when the OUTCOME audit row failed to persist after the effect had happened.
    bool audit_persisted{true};
};

/// The audit verb every row of one mutation carries: `execution.cancel` / `execution.rerun`
/// (the legacy routes' verbs, so a SIEM filter on either keeps working across surfaces).
[[nodiscard]] const char* execution_mutation_audit_action(ExecutionMutation what);

/// Writes one audit row (target type "execution"). Returns true iff it persisted (or audit is
/// off). The sequence wraps a throwing sink as a failed write regardless.
using ExecutionMutationAuditFn = std::function<bool(const std::string& action,
                                                    const std::string& result,
                                                    const std::string& target_id,
                                                    const std::string& detail)>;

[[nodiscard]] ExecutionMutationOutcome
apply_execution_mutation(const ExecutionMutationPorts& ports, const ExecutionMutationRequest& req,
                         const ExecutionMutationAuditFn& audit);

/// The characters an execution id may contain on every surface (the REST route regex and the
/// MCP schema both use this set), bounded at 128. Single definition so the two cannot drift.
[[nodiscard]] bool is_valid_execution_id(const std::string& id);

} // namespace yuzu::server
