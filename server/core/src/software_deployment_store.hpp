#pragma once

/// @file software_deployment_store.hpp
/// Migrated Postgres store (ADR-0006, schema `software_deployment_store`,
/// ADR-0051) for capability 7.6 — a lightweight software packaging + fleet
/// deployment catalog: `SoftwarePackage` installers, `SoftwareDeployment`
/// lifecycle jobs against a scope expression, and per-agent
/// `AgentDeploymentStatus` install outcomes.
///
/// **DORMANT** (verified 2026-08-14 against origin/dev): nothing in
/// production constructs this store — `rest_api_v1.hpp`'s `sw_deploy_store`
/// parameter defaults to `nullptr` and no call site passes a non-null one
/// (`acc6c481a` wired construction, `2fcfb95b5`'s server.cpp decomposition
/// removed it — an operator decision to shelve the capability, not an
/// accidental regression; same family as `LicenseStore`, ADR-0048). The
/// `/api/v1/software-packages*` / `/api/v1/software-deployments*` routes in
/// `rest_api_v1.cpp` are compiled and register whenever a non-null pointer
/// IS passed, so this header's contract is real even though nothing
/// exercises it in production today. See ADR-0051 for the full
/// posture/backfill/dormancy record; its Update records `migrate_from_sqlite()`'s
/// retirement (chore/retire-migrate-from-sqlite-batch-b, #3623) — this store's
/// zero production callers meant its schema migration v1 never ran against
/// any real database either.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and
/// runtime — same reasoning as `DeploymentStore` (ADR-0043): no in-memory
/// authoritative layer sits above this data, so every reader/mutator returns
/// `std::expected<..., std::string>` and a genuine DB/lease failure is never
/// papered over as an empty/false/not-found result. Every such failure is
/// prefixed `kSwDeployDbErrorPrefix` ("db_error: "), mirroring
/// `DeploymentStore`/`AccessReviewStore` — a machine-checkable idiom so a
/// route handler can classify 503 (store outage) vs 400/404
/// (validation/business rule) without pattern-matching message text.
///
/// Three tables with INTERNAL foreign keys (no external coupling):
/// `software_packages` (parent) -> `software_deployments` (`package_id` FK)
/// -> `agent_software_status` (`deployment_id` FK, PK
/// `(deployment_id, agent_id)`). **Postgres ENFORCES these FKs** — the
/// pre-migration SQLite store never ran `PRAGMA foreign_keys=ON`, so an
/// orphan row (a deployment referencing a deleted package, e.g.) was
/// possible there and is not here. See `delete_package`'s doc comment for
/// the enforced-FK behavior change on the live path.
///
/// `id` (packages, deployments) stays a client-generated 32-hex-char TEXT
/// surrogate key — the pre-migration `generate_id()` format (two
/// `mt19937_64` 64-bit draws formatted as 16 hex chars each), unchanged
/// (playbook: keep pre-migration ID contracts). `agent_software_status` has
/// no surrogate id — its PK is the natural `(deployment_id, agent_id)` pair,
/// also unchanged.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `SoftwareDeploymentStore`
/// `unexpected()` that represents a genuine DB/lease failure rather than
/// caller-input validation or a not-found/wrong-state business rule (mirrors
/// `DeploymentStore::kDeploymentDbErrorPrefix`). Exported here so a route
/// classifier can depend on it without duplicating the literal.
inline constexpr const char* kSwDeployDbErrorPrefix = "db_error: ";

struct SoftwarePackage {
    std::string id;
    std::string name;
    std::string version;
    std::string platform;         // "windows", "linux", "darwin"
    std::string installer_type;   // "msi", "deb", "rpm", "pkg", "script"
    std::string content_hash;     // SHA-256 of installer
    std::string content_url;      // content_dist URL or local path
    std::string silent_args;      // e.g. "/qn /norestart"
    std::string verify_command;   // post-install verification command
    std::string rollback_command; // rollback command
    std::int64_t size_bytes{0};
    std::int64_t created_at{0};
    std::string created_by;
};

struct SoftwareDeployment {
    std::string id;
    std::string package_id;
    std::string scope_expression;
    // "staged" -> "deploying" -> "verifying" -> "completed", with
    // "cancelled"/"rolled_back"/"failed" reachable as terminal exits from
    // various points. Only staged/deploying/cancelled/rolled_back have a
    // store writer today (start_deployment/cancel_deployment/
    // rollback_deployment) — verifying/completed/failed are part of the
    // documented contract for a future orchestration engine.
    std::string status;
    std::string created_by;
    std::int64_t created_at{0};
    std::int64_t started_at{0};
    std::int64_t completed_at{0};
    int agents_targeted{0};
    int agents_success{0};
    int agents_failure{0};
};

struct AgentDeploymentStatus {
    std::string deployment_id;
    std::string agent_id;
    // "pending" -> "downloading" -> "installing" -> "verifying" ->
    // {"success","failed","rolled_back"} (terminal). `update_agent_status`
    // is an unguarded upsert (any transition is possible on the live path)
    // — this order is documented, not enforced by a transition guard like
    // the deployment table's.
    std::string status;
    std::int64_t started_at{0};
    std::int64_t completed_at{0};
    std::string error;
};

class SoftwareDeploymentStore {
public:
    /// Borrows the shared pool and runs the `software_deployment_store`
    /// schema migration on a pinned lease. `is_open()` is false if the
    /// lease was empty or the migration failed.
    explicit SoftwareDeploymentStore(pg::PgPool& pool);

    SoftwareDeploymentStore(const SoftwareDeploymentStore&) = delete;
    SoftwareDeploymentStore& operator=(const SoftwareDeploymentStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Packages ─────────────────────────────────────────────────────────

    /// Mints a 32-hex-char id and inserts the package. `unexpected(msg)` on
    /// a validation failure (empty `name`) or a write error — a genuine
    /// DB/lease failure carries `kSwDeployDbErrorPrefix`.
    [[nodiscard]] std::expected<std::string, std::string>
    create_package(const SoftwarePackage& pkg);

    /// Every package, newest first, capped at 10,000 rows (bounded
    /// materialization regardless of table growth). `unexpected(msg)` is a
    /// genuine read failure; a package-free store still returns success
    /// with an empty vector.
    [[nodiscard]] std::expected<std::vector<SoftwarePackage>, std::string> list_packages();

    /// `nullopt` = no package with this id (a successful read of zero
    /// rows); `unexpected(msg)` = a genuine read failure.
    [[nodiscard]] std::expected<std::optional<SoftwarePackage>, std::string>
    get_package(const std::string& id);

    /// Postgres enforces the `software_deployments.package_id` FK — a
    /// package referenced by an existing deployment cannot be deleted; that
    /// case returns a validation-shaped `unexpected` (not
    /// `kSwDeployDbErrorPrefix`), distinguishable from a genuine DB
    /// failure. `unexpected("package not found")` when `id` doesn't exist.
    [[nodiscard]] std::expected<void, std::string> delete_package(const std::string& id);

    // ── Deployments ──────────────────────────────────────────────────────

    /// Mints a 32-hex-char id and inserts the deployment as 'staged'.
    /// `unexpected(msg)` on a validation failure (empty `package_id`), an
    /// FK violation (`package_id` does not exist — validation-shaped, not
    /// `kSwDeployDbErrorPrefix`), or a genuine write failure.
    [[nodiscard]] std::expected<std::string, std::string>
    create_deployment(const SoftwareDeployment& dep);

    /// Every deployment (optionally filtered by `status`), newest first,
    /// capped at 10,000 rows. `unexpected(msg)` is a genuine read failure.
    [[nodiscard]] std::expected<std::vector<SoftwareDeployment>, std::string>
    list_deployments(const std::string& status = {});

    /// `nullopt` = no deployment with this id; `unexpected(msg)` = a
    /// genuine read failure.
    [[nodiscard]] std::expected<std::optional<SoftwareDeployment>, std::string>
    get_deployment(const std::string& id);

    /// Single guarded `UPDATE ... WHERE status = 'staged'` (race-safe, no
    /// mutex). `unexpected("deployment not found")` or
    /// `unexpected("deployment is not staged")` on the two rejection cases
    /// (best-effort disambiguation under concurrency — see the .cpp); any
    /// other `unexpected(msg)` carries `kSwDeployDbErrorPrefix`.
    [[nodiscard]] std::expected<void, std::string> start_deployment(const std::string& id);

    /// Single guarded `UPDATE ... WHERE status IN ('staged','deploying')`.
    /// Same not-found/wrong-state/db-error error shape as `start_deployment`.
    [[nodiscard]] std::expected<void, std::string> cancel_deployment(const std::string& id);

    /// Single guarded
    /// `UPDATE ... WHERE status IN ('deploying','verifying','completed')`.
    /// Same not-found/wrong-state/db-error error shape as `start_deployment`.
    [[nodiscard]] std::expected<void, std::string> rollback_deployment(const std::string& id);

    /// Upsert one agent's status for a deployment
    /// (`ON CONFLICT (deployment_id, agent_id) DO UPDATE`). `unexpected(msg)`
    /// on an unrecognised `status`, an FK violation (`deployment_id` does
    /// not exist — validation-shaped), or a genuine write failure.
    [[nodiscard]] std::expected<void, std::string>
    update_agent_status(const std::string& deployment_id, const AgentDeploymentStatus& status);

    /// Recomputes `agents_success`/`agents_failure` from
    /// `agent_software_status`. `unexpected("deployment not found")` when
    /// `deployment_id` doesn't exist; any other `unexpected(msg)` carries
    /// `kSwDeployDbErrorPrefix`.
    [[nodiscard]] std::expected<void, std::string> refresh_counts(const std::string& deployment_id);

    /// Every agent status row for `deployment_id`, capped at 10,000 rows.
    /// `unexpected(msg)` is a genuine read failure; a deployment with no
    /// reported agents still returns success with an empty vector.
    [[nodiscard]] std::expected<std::vector<AgentDeploymentStatus>, std::string>
    get_agent_statuses(const std::string& deployment_id);

    /// Count of deployments currently `deploying` or `verifying`.
    /// `unexpected(msg)` is a genuine read failure.
    [[nodiscard]] std::expected<int, std::string> active_count();

private:
    pg::PgPool& pool_;
    bool open_{false};

    static std::string generate_id();
};

} // namespace yuzu::server
