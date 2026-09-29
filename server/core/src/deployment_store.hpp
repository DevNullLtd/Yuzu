#pragma once

/// @file deployment_store.hpp
/// Migrated Postgres store (ADR-0006, schema `deployment_store`) for
/// operator-initiated ad-hoc deployment jobs — SSH / group-policy / manual
/// agent installs (Issue 7.7). This is the OLDER, simpler `deployment_jobs`
/// concept. It is NOT `DeploymentRunStore` (schema `deployment_run_store`,
/// the `/auto` Deploy feature's stage->execute state machine) — same
/// English word, unrelated stores; do not conflate the two.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and
/// runtime. A deployment job is operator-initiated state with no in-memory
/// authoritative layer behind it (unlike e.g. `OfflineEndpointStore`'s
/// durability-on-top relationship to `FleetTopologyStore`), so a runtime DB
/// error is surfaced to the caller, never papered over with an empty/false
/// result — a silently-empty `list_jobs` would read as "no deployments ever
/// ran", and a silently-`false` `update_status` would let an operator
/// believe a state change landed when it didn't. Construction is
/// fail-CLOSED (ADR-0007): a reachable database whose schema can't migrate
/// leaves the store `!is_open()`, which `server.cpp` wires to
/// `startup_failed_`. Every reader returns `std::expected<..., std::string>`
/// so a DB error is type-distinguishable from a genuine empty/not-found
/// result (playbook "Authoritative reads must be type-distinguishable").
/// Every genuine DB/lease failure (as opposed to caller-input validation or
/// a not-found/wrong-state business rule) is prefixed `"db_error: "` in the
/// `.cpp` — a machine-checkable idiom mirroring `AccessReviewStore`'s
/// `"not_found: "` prefix — so `discovery_routes.cpp` can map it to 503
/// without string-matching ad hoc message text.
///
/// `id` is a client-generated TEXT primary key (`generate_id()`, mirrors
/// `AccessReviewStore::generate_campaign_id` — a 64-bit RNG value formatted
/// as 16 lowercase hex chars; not cryptographic — uniqueness, not
/// unguessability, is what matters here). Deliberately NOT a
/// Postgres-generated identity column: switching would change the ID
/// format/contract for any existing caller.
///
/// One table, no foreign keys: `deployment_jobs`.
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b,
/// #3623): no production fleet ever ran a pre-Postgres build of this store —
/// see ADR-0043's Update. `server.cpp` now runs a detect-and-warn probe over
/// the legacy file instead.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `DeploymentStore` `unexpected()` that
/// represents a genuine DB/lease failure rather than caller-input validation
/// or a not-found/wrong-state business rule (mirrors `AccessReviewStore`'s
/// `"not_found: "` idiom). Exported here — not left as a private literal
/// duplicated in `discovery_routes.cpp`'s classifier — so the two can never
/// silently drift apart (gov F3, adversarial-review hardening round).
inline constexpr const char* kDeploymentDbErrorPrefix = "db_error: ";

/// One persisted deployment job.
struct DeploymentJob {
    std::string id;
    std::string target_host;
    std::string os;     ///< "windows" | "linux" | "darwin"
    std::string method; ///< "ssh" | "group_policy" | "manual"
    std::string status; ///< "pending" | "running" | "completed" | "failed" | "cancelled"
    std::int64_t created_at{0};   ///< epoch seconds
    std::int64_t started_at{0};   ///< epoch seconds, 0 = not started
    std::int64_t completed_at{0}; ///< epoch seconds, 0 = not completed
    std::string error;            ///< error message if failed
};

class DeploymentStore {
public:
    /// Borrows the shared pool and runs the `deployment_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit DeploymentStore(pg::PgPool& pool);

    DeploymentStore(const DeploymentStore&) = delete;
    DeploymentStore& operator=(const DeploymentStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Validates target_host (DNS-safe chars only, <=253 chars — defense in
    /// depth against a future caller templating a shell/SSH command from
    /// this field; the current REST layer's install command does not), os,
    /// and method, mints an id, and inserts the job as 'pending'. Returns
    /// the minted id, or `unexpected(msg)` on a validation failure or a
    /// write error.
    [[nodiscard]] std::expected<std::string, std::string>
    create_job(const std::string& target_host, const std::string& os, const std::string& method);

    /// Every job, newest first, capped at 10,000 rows (gov UP-5: bounded
    /// materialization regardless of table growth — this is an operator
    /// convenience list, not a paged feed). `unexpected(msg)` is a genuine
    /// read failure (surface as 503); a job-free store still returns success
    /// with an empty vector.
    [[nodiscard]] std::expected<std::vector<DeploymentJob>, std::string> list_jobs();

    /// `nullopt` = no job with this id (a successful read of zero rows);
    /// `unexpected(msg)` = a genuine read failure (surface as 503, never
    /// treat as not-found).
    [[nodiscard]] std::expected<std::optional<DeploymentJob>, std::string>
    get_job(const std::string& id);

    /// `status` must be one of pending/running/completed/failed/cancelled.
    /// Stamps `started_at` on a transition to 'running', `completed_at` on a
    /// transition to 'completed'/'failed'; otherwise touches only
    /// status+error. `unexpected("job not found")` when `id` doesn't exist;
    /// any other `unexpected(msg)` is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string>
    update_status(const std::string& id, const std::string& status,
                  const std::string& error = {});

    /// Cancels a job via one guarded UPDATE (`WHERE status IN
    /// ('pending','running')`) — race-safe against a concurrent second
    /// cancel or status update without a separate check-then-write round
    /// trip. `unexpected("job not found")` or
    /// `unexpected("only pending or running jobs can be cancelled")` on the
    /// two rejection cases (best-effort distinction — see .cpp); any other
    /// `unexpected(msg)` is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string> cancel_job(const std::string& id);

private:
    pg::PgPool& pool_;
    bool open_{false};

    static std::string generate_id();
};

} // namespace yuzu::server
