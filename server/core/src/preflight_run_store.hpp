#pragma once

/// @file preflight_run_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `preflight_run_store`) for `/auto`
/// pre-flight RUNS — the persistence behind the saved-runs rail and the
/// re-dispatch-on-reconnect runner. The store is the ONLY home for run state (no
/// in-memory duplicate). Posture per ADR-0012: CONSTRUCTION is fail-CLOSED — a
/// reachable database whose schema can't migrate/open sets `startup_failed_` in
/// server.cpp (same as OfflineEndpointStore; a broken substrate is a deploy
/// error, not a serve-degraded state). RUNTIME is durability-on-top / fail-soft —
/// once open, a transient lease timeout or query error degrades /auto to an
/// honest note rather than failing the request, never blocking the gRPC hot path.
///
/// Two tables:
///   * runs       — metadata + frozen config + window + status + summary counts.
///   * run_device — PK(run_id, agent_id); hostname/os FROZEN at creation (the
///                  cohort denominator + the owner-scoped read surface), bucket +
///                  checks_json COMPUTED/upserted by the runner.
///
/// Owner scoping: `created_by` is captured at creation; the rail lists a viewer's
/// own runs and the result route reads via get_run(run_id, viewer), so another
/// operator's run is indistinguishable from not-found (no existence oracle).
/// Admin-sees-all (the `is_admin` list_runs path) is a tracked follow-up — not
/// wired; callers pass is_admin=false today.
///
/// Durability rationale: the computed grid is persisted (not recomputed from the
/// ResponseStore at render) so a run revisited days later survives ResponseStore
/// pruning. A *running* run is still rendered live (handler computes from
/// query_by_execution); the stored grid is the source for *complete* runs.
///
/// Substrate contract (ADR-0008/0012): holds a `PgPool&`, runs its migration at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// RETURNING is the mutate-and-return idiom. Bounded acquires everywhere; a
/// lease is NEVER held across a dispatch or a ResponseStore read (the runner
/// owns that ordering).

#include "preflight_parse.hpp" // preflight::PreflightTarget

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One persisted run (metadata + frozen config + lifecycle + summary).
struct PreflightRunRow {
    std::string run_id;
    std::string execution_id; ///< "preflight-<run_id>" (per-check ids derive from it)
    std::string created_by;   ///< frozen creator username (owner-scope key)
    std::string name;
    std::string scope_label;
    std::string group_id;
    std::string os_filter;
    std::string config_json; ///< serialized PreflightConfig + applicable check keys
    int window_seconds = 0;
    std::int64_t created_at_ms = 0;
    std::int64_t deadline_at_ms = 0;
    std::string status = "running"; ///< "running" | "complete"
    std::int64_t completed_at_ms = 0;
    int total = 0;
    int go = 0;
    int warn = 0;
    int nogo = 0;
    int incomplete = 0;
};

/// One device row of a run (frozen identity + the latest computed grid cell).
struct PreflightRunDeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string bucket = "inc"; ///< preflight::bucket_token (go|nogo|warn|inc)
    std::string checks_json;    ///< serialized vector<PreflightDeviceCheck>
    std::int64_t updated_at_ms = 0;
};

class PreflightRunStore {
public:
    explicit PreflightRunStore(pg::PgPool& pool);

    PreflightRunStore(const PreflightRunStore&) = delete;
    PreflightRunStore& operator=(const PreflightRunStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Create a run + its frozen target rows in ONE transaction (run_device seeded
    /// bucket='inc'). Returns false on error.
    bool create_run(const PreflightRunRow& run, const std::vector<preflight::PreflightTarget>& targets);

    /// Run metadata by id; nullopt if absent/error. When `created_by` is non-empty
    /// the read is OWNER-SCOPED at the seam: a not-yours run reads as nullopt, same
    /// as not-found — closes the existence oracle on the result route. Empty
    /// `created_by` = unscoped (internal callers).
    ///
    /// Thin wrapper over `get_run_checked` that DISCARDS the store-error channel —
    /// preserves the original fail-soft contract (a transient lease timeout or
    /// query error reads the same as absent) for the pre-existing HTML-fragment
    /// callers (`/fragments/auto/deploy` et al.), which render an "honest note"
    /// either way and were never meant to distinguish the two (see the file
    /// header). New callers that need to tell "genuinely absent" apart from "the
    /// store faulted" (e.g. an API twin that should 503 rather than silently claim
    /// not-found) MUST use `get_run_checked` instead (#4036 hardening round).
    [[nodiscard]] std::optional<PreflightRunRow> get_run(const std::string& run_id,
                                                         const std::string& created_by = "");

    /// Authoritative variant of `get_run` — distinguishes a genuine miss
    /// (`std::optional` engaged, `nullopt` inside) from a store-level failure
    /// (`std::unexpected`, store not open / pool acquire timeout / query error).
    /// Same posture as `RbacStore`'s `_checked` accessors. An empty `run_id` is
    /// treated as a genuine miss, not a store error — callers are expected to
    /// validate presence themselves (both #4036 REST/MCP twins already 400 on an
    /// empty run_id before reaching the store).
    [[nodiscard]] std::expected<std::optional<PreflightRunRow>, std::string>
    get_run_checked(const std::string& run_id, const std::string& created_by = "");

    /// A viewer's recent runs (created_by = viewer, or all when `is_admin`),
    /// newest first, capped at `limit`.
    ///
    /// Thin wrapper over `list_runs_checked` that DISCARDS the store-error
    /// channel — same rationale as `get_run` above: preserves the pre-existing
    /// fail-soft rail-rendering contract for `/fragments/auto`. New callers that
    /// need to 503 rather than silently claim "zero runs" on a store fault MUST
    /// use `list_runs_checked` instead (#4036 hardening round).
    [[nodiscard]] std::vector<PreflightRunRow> list_runs(const std::string& viewer, bool is_admin,
                                                         int limit);

    /// Authoritative variant of `list_runs` — `std::unexpected` on a store-level
    /// failure (not open / pool acquire timeout / query error) rather than a
    /// silently-empty vector indistinguishable from "genuinely zero runs".
    [[nodiscard]] std::expected<std::vector<PreflightRunRow>, std::string>
    list_runs_checked(const std::string& viewer, bool is_admin, int limit);

    /// Every `running` run — the runner's per-tick worklist.
    [[nodiscard]] std::vector<PreflightRunRow> list_running();

    /// Frozen target cohort for a run (the denominator).
    [[nodiscard]] std::vector<preflight::PreflightTarget> get_targets(const std::string& run_id);

    /// Stored device grid for a run (complete-run revisit).
    [[nodiscard]] std::vector<PreflightRunDeviceRow> get_devices(const std::string& run_id);

    /// Runner: upsert the whole computed device grid + the summary counts in ONE
    /// transaction (kinder to the pool than per-device leases; atomic snapshot).
    /// Called BEFORE complete_run (compute → persist grid → THEN flip complete).
    bool persist_grid(const std::string& run_id, const std::vector<PreflightRunDeviceRow>& devices,
                      int total, int go, int warn, int nogo, int inc);

    /// Runner: flip a run to complete (compute → persist_grid → THEN this).
    bool complete_run(const std::string& run_id, std::int64_t completed_at_ms);

    /// Runner: clock-guarded, single-writer, capped retention prune (WS-10 #2508;
    /// run_device cascades). Deletes runs older than now - `retention_window_ms`,
    /// where now is read from Postgres itself (shared clock). Returns rows deleted
    /// this pass, or -1 on error.
    int run_retention_prune(std::int64_t retention_window_ms);

    /// Delete one run, OWNER-SCOPED at the seam (`created_by` must match;
    /// run_device cascades). Returns true if a row was deleted.
    bool delete_run(const std::string& run_id, const std::string& created_by);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
