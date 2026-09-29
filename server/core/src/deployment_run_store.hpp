#pragma once

/// @file deployment_run_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `deployment_run_store`) for the `/auto`
/// DEPLOY stage — the persistence behind a deployment run and its per-device
/// stage→execute state machine. Twin of PreflightRunStore, but the device step is
/// STATEFUL (mutating), so this store does NOT recompute a grid: it exposes
/// GUARDED ONE-WAY TRANSITIONS (each UPDATE keys on the expected source step), and
/// the execute step is CLAIMED before dispatch (`claim_for_exec`: staged→executing
/// RETURNING) so an installer runs AT MOST ONCE per device even under concurrent
/// advances / a server restart (the claim commits before the execute leaves the
/// server).
///
/// Posture (ADR-0012): CONSTRUCTION is fail-CLOSED (a reachable DB whose schema
/// can't migrate sets startup_failed_ in server.cpp — same as PreflightRunStore).
/// RUNTIME is durability-on-top — a transient lease/query error degrades the page
/// to an honest note, never blocks the gRPC hot path. Owner scoping: `created_by`
/// is frozen at creation; reads pass the viewer so a not-yours deployment is
/// indistinguishable from not-found. RETURNING is the mutate-and-return idiom; a
/// lease is NEVER held across a dispatch (the engine owns that ordering).
///
/// Two tables:
///   * deployments       — artifact spec + source pre-flight run + lifecycle + counts.
///   * deployment_device — PK(deployment_id, agent_id); hostname/os FROZEN at create
///                         (the cohort = denominator + owner-scoped read surface);
///                         step/exit_code/error advanced by the guarded transitions.

#include "preflight_parse.hpp" // preflight::PreflightTarget (frozen cohort identity)

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One persisted deployment run (artifact + source run + lifecycle + summary).
struct DeploymentRow {
    std::string deployment_id;
    std::string source_run_id; ///< the /auto pre-flight run whose go-cohort this targets
    std::string created_by;    ///< frozen creator username (owner-scope key)
    std::string name;
    std::string artifact_url;
    std::string artifact_filename;
    std::string artifact_sha256;
    std::string exec_args;
    std::string status = "running"; ///< "running" | "complete"
    std::int64_t created_at_ms = 0;
    std::int64_t completed_at_ms = 0;
    int total = 0;
    int succeeded = 0;
    int failed = 0;
    int skipped = 0;
    int active = 0; ///< pending+staging+staged+executing (in-flight)
};

/// One device row of a deployment (frozen identity + the current step cell).
struct DeploymentDeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string step = "pending"; ///< deployment::step_token
    std::int64_t exit_code = 0;
    std::string error;
    std::int64_t updated_at_ms = 0;
};

/// One guarded transition for apply_results: move `agent_id` from `from_step` to
/// `to_step` ONLY if it is currently in `from_step` (a concurrent advance that
/// already moved it makes this a no-op — the keystone of correctness).
struct DeviceTransition {
    std::string agent_id;
    std::string from_step;
    std::string to_step;
    std::int64_t exit_code = 0;
    std::string error;
};

class DeploymentRunStore {
public:
    explicit DeploymentRunStore(pg::PgPool& pool);

    DeploymentRunStore(const DeploymentRunStore&) = delete;
    DeploymentRunStore& operator=(const DeploymentRunStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Create a deployment + its frozen cohort (device rows seeded step='pending')
    /// in ONE transaction. Returns false on error.
    bool create_deployment(const DeploymentRow& dep,
                           const std::vector<preflight::PreflightTarget>& targets);

    /// Metadata by id; nullopt if absent/error. Non-empty `created_by` = OWNER-
    /// SCOPED at the seam (not-yours reads as not-found). Empty = unscoped (engine).
    [[nodiscard]] std::optional<DeploymentRow> get_deployment(const std::string& deployment_id,
                                                              const std::string& created_by = "");

    /// A viewer's recent deployments (created_by = viewer, or all when is_admin),
    /// newest first, capped at `limit`.
    [[nodiscard]] std::vector<DeploymentRow> list_deployments(const std::string& viewer,
                                                              bool is_admin, int limit);

    /// The owner's RUNNING deployment for a source pre-flight run, if any — the
    /// create-time guard against a duplicate run that would re-install the cohort
    /// (#governance security HIGH-1). Owner-scoped at the seam.
    [[nodiscard]] std::optional<std::string> find_running_for_run(const std::string& source_run_id,
                                                                  const std::string& created_by);

    /// Agents that already SUCCEEDED in ANY prior deployment of a source run,
    /// owner-scoped. The create handler excludes these so a re-deploy (after an
    /// earlier mid-run deploy completes) covers only NEW / FAILED / not-yet-deployed
    /// devices and never re-runs the installer on a device a prior deployment already
    /// installed — cross-deployment execute-once (#governance HIGH: mid-run deploy
    /// double-install).
    [[nodiscard]] std::vector<std::string>
    succeeded_agents_for_run(const std::string& source_run_id, const std::string& created_by);

    /// The device grid (frozen identity + current step), ordered by hostname.
    [[nodiscard]] std::vector<DeploymentDeviceRow> get_devices(const std::string& deployment_id);

    /// Apply response-derived transitions in ONE batched, source-step-GUARDED
    /// UPDATE (a row already moved by a concurrent advance is skipped). Returns
    /// false only on a query error (zero matched rows is success).
    bool apply_results(const std::string& deployment_id,
                       const std::vector<DeviceTransition>& transitions);

    /// CAS: claim `candidates` currently in 'pending' → 'staging', RETURNING the
    /// claimed ids. The caller dispatches `stage` to exactly the returned set.
    [[nodiscard]] std::vector<std::string> claim_for_stage(const std::string& deployment_id,
                                                           const std::vector<std::string>& candidates);

    /// CAS — THE execute-once guard: claim `candidates` currently in 'staged' →
    /// 'executing', RETURNING the claimed ids. The caller dispatches
    /// `execute_staged` to exactly the returned set. A concurrent advance (or a
    /// re-advance after restart) matches zero rows for an already-claimed device,
    /// so the installer is dispatched at most once.
    [[nodiscard]] std::vector<std::string> claim_for_exec(const std::string& deployment_id,
                                                          const std::vector<std::string>& candidates);

    /// Mark out-of-scope `agent_ids` (still in 'pending'/'staged', never executed)
    /// as 'skipped'. Returns the count moved.
    int mark_skipped(const std::string& deployment_id, const std::vector<std::string>& agent_ids);

    /// Recompute the deployments summary counts from the device grid.
    bool refresh_counts(const std::string& deployment_id);

    /// Flip to 'complete' ONLY if running AND no device is still non-terminal
    /// (the settled check is in SQL, so completion is correct regardless of the
    /// caller's read). Returns true iff a row was flipped.
    bool complete_deployment(const std::string& deployment_id, std::int64_t completed_at_ms);

    /// WS-10 (#2508): clock-guarded, single-writer, capped retention prune
    /// (deployment_device cascades). Deletes deployments older than
    /// now - `retention_window_ms`, now read from Postgres itself. Returns rows
    /// deleted this pass, or -1 on error.
    int run_retention_prune(std::int64_t retention_window_ms);

    /// Delete one deployment, OWNER-SCOPED at the seam (`created_by` must match;
    /// device rows cascade). Returns true if a row was deleted.
    bool delete_deployment(const std::string& deployment_id, const std::string& created_by);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
