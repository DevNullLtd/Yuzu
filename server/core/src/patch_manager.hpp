#pragma once

/// @file patch_manager.hpp
/// Postgres-backed OS-patch inventory + deployment-orchestration store
/// (ADR-0006/0009/0062). Schema `patch_manager`, three tables
/// (`patch_inventory`, `patch_deployments`, `patch_deployment_targets` —
/// the last FK-cascaded on `patch_deployments`).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE/fail-hard construction — a
/// reachable database whose schema can't migrate/open is a fatal startup
/// error (`startup_failed_`), a posture UPGRADE from the SQLite era (where
/// construction was unconditional/best-effort and `is_open()` was never
/// even checked by any caller). Runtime reads/writes keep their
/// pre-migration plain-container/`std::expected<std::string,std::string>`
/// shapes — this store has exactly one external consumer surface
/// (`DiscoveryRoutes`' `/api/patches/*`, no MCP), and its call sites are
/// unaffected by this migration by design.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of any Yuzu
/// store). The legacy `patches.db` is never read for data; construction
/// logs a one-time "fresh start, no legacy backfill" line, and the caller
/// (`server.cpp`) runs `legacy_sqlite_probe::warn_if_legacy_rows()` over
/// the legacy file so an environment where "no production fleet" turns out
/// to be locally wrong gets a loud signal instead of silent loss.
///
/// `execute_deployment()` (+ its `PatchDispatchFn`/`AgentOsLookupFn`
/// callback types) is REMOVED in this migration — it had zero production
/// callers on `dev` (nothing wires a dispatch/os-lookup callback to it),
/// see ADR-0062 "Deleted: execute_deployment" for the rationale and the
/// tracking issue for its tested-but-unwired reboot-orchestration
/// behaviour.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu {
class MetricsRegistry;
} // namespace yuzu

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct PatchInfo {
    std::string kb_id;      // KB identifier (e.g., "KB5034441") or package name
    std::string title;      // Human-readable title
    std::string severity;   // "Critical", "Important", "Moderate", "Low", "Unspecified"
    std::string status;     // "missing", "installed", "pending", "failed"
    std::string agent_id;   // Agent that reported this patch
    int64_t released_at{0}; // Release timestamp (epoch seconds)
    int64_t scanned_at{0};  // When the agent last scanned
};

enum class DeploymentStatus {
    kPending,    // Deployment created, not yet started
    kScanning,   // Checking if patch is missing on targets
    kDownloading,// Downloading patch content
    kInstalling, // Installing patch on targets
    kVerifying,  // Verifying successful installation
    kCompleted,  // All targets patched successfully
    kFailed,     // One or more targets failed
    kCancelled   // Deployment cancelled by operator
};

struct PatchDeploymentTarget {
    std::string agent_id;
    std::string status;    // "pending", "scanning", "downloading", "installing",
                           // "verifying", "rebooting", "completed", "failed", "skipped"
    std::string error;     // Error message if failed
    int64_t started_at{0};
    int64_t completed_at{0};
};

struct PatchDeployment {
    std::string id;
    std::string kb_id;
    std::string title;
    std::string status;     // Overall status
    std::string created_by; // Principal who initiated the deployment
    bool reboot_if_needed{false};
    int reboot_delay_seconds{300};  // Countdown before reboot (default 5 min)
    int64_t reboot_at{0};           // Optional epoch timestamp for scheduled reboot (0 = use delay)
    int64_t created_at{0};
    int64_t completed_at{0};
    int total_targets{0};
    int completed_targets{0};
    int failed_targets{0};

    // Populated by get_deployment()
    std::vector<PatchDeploymentTarget> targets;
};

struct PatchQuery {
    std::string agent_id;    // Filter by agent
    std::string severity;    // Filter by severity
    std::string status;      // Filter by status ("missing", "installed")
    int limit{100};
};

/// Request struct for creating a patch deployment.
struct DeploymentRequest {
    std::string kb_id;                      // KB identifier (e.g., "KB5034441")
    std::vector<std::string> agent_ids;     // Target agent IDs
    bool reboot_if_needed{false};           // Reboot agents after patching
    std::string created_by;                 // Principal who initiated
    int reboot_delay_seconds{300};          // Countdown before reboot (clamped to 60-86400)
    int64_t reboot_at{0};                   // Optional epoch timestamp for scheduled reboot (0 = use delay)
};

// ── PatchManager ─────────────────────────────────────────────────────────────

class PatchManager {
public:
    explicit PatchManager(pg::PgPool& pool);

    PatchManager(const PatchManager&) = delete;
    PatchManager& operator=(const PatchManager&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for write-outcome counters
    /// (`yuzu_server_patch_manager_writes_total{op,result}` — `op` one of
    /// `record_patches`/`deploy_patch`/`cancel_deployment`, `result` one of
    /// `success`/`failed`; pre-seeded at boot so a rate can be computed
    /// from the first request, not just from the first failure). Set-
    /// before-traffic contract, same as every other metrics-emitting store.
    void set_metrics(yuzu::MetricsRegistry* metrics) noexcept { metrics_ = metrics; }

    // ── Patch inventory ─────────────────────────────────────────────────

    /// Record patches reported by an agent (called when scan results come in).
    /// One transaction for the whole batch (translated 1:1 from the
    /// SQLite-era explicit BEGIN/COMMIT around this same loop).
    void record_patches(const std::string& agent_id,
                        const std::vector<PatchInfo>& patches);

    /// Query missing patches, optionally filtered by agent/severity.
    std::vector<PatchInfo> get_missing_patches(const PatchQuery& query = {}) const;

    /// Query installed patches, optionally filtered.
    std::vector<PatchInfo> get_installed_patches(const PatchQuery& query = {}) const;

    /// Get a fleet-wide summary: how many agents are missing each patch.
    std::vector<std::pair<std::string, int>> get_fleet_patch_summary(int limit = 50) const;

    // ── Deployment ──────────────────────────────────────────────────────

    /// Create a new patch deployment targeting specific agents. The
    /// deployment row + its per-target rows are inserted in ONE
    /// transaction — new atomicity added by this migration; the SQLite era
    /// inserted the deployment row and target rows unprotected (see
    /// ADR-0062 for why, and for the caller-supplied-duplicate-agent-id
    /// de-dup this atomicity required).
    std::expected<std::string, std::string>
    deploy_patch(const DeploymentRequest& req);

    // Overload preserved for backward compatibility — delegates to struct form.
    std::expected<std::string, std::string>
    deploy_patch(const std::string& kb_id,
                 const std::vector<std::string>& agent_ids,
                 bool reboot_if_needed,
                 const std::string& created_by,
                 int reboot_delay_seconds = 300,
                 int64_t reboot_at = 0);

    /// Get deployment details including per-target status.
    std::optional<PatchDeployment> get_deployment(const std::string& id) const;

    /// List recent deployments.
    std::vector<PatchDeployment> list_deployments(int limit = 50) const;

    /// Cancel a pending/running deployment.
    std::expected<void, std::string> cancel_deployment(const std::string& id);

    /// Update a target's status within a deployment (called as results come in).
    void update_target_status(const std::string& deployment_id,
                              const std::string& agent_id,
                              const std::string& status,
                              const std::string& error = {});

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    std::string generate_id() const;

    std::vector<PatchInfo> query_patches(const PatchQuery& query,
                                          const std::string& status_filter) const;
};

} // namespace yuzu::server
