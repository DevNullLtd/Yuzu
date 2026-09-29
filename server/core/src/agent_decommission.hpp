#pragma once

/// @file agent_decommission.hpp
/// The agent-decommission cascade (ADR-0024 Decision 11 / roadmap D-3): a single
/// entry point that fans `delete_agent(agent_id)` across EVERY per-agent store,
/// so that an operator decommission CAN durably erase a machine's stored rows.
/// This is the GDPR-erasure MECHANISM half; the per-store `delete_agent` methods
/// exist on each store but had ZERO production callers before this seam (they
/// were invoked only from unit tests). The PRODUCTION TRIGGER is now LIVE:
/// `DELETE /api/v1/sle/agents/{id}` — see `sle_routes.cpp`. It is gated on ONE
/// SCOPED securable, `Decommission:Delete` (ADR-0024 Decision 9, amended Wave 7
/// PR7.2), that authorizes for the cascade's WHOLE blast radius rather than the
/// per-store securables each store's READ routes gate on, plus audit-before-erase
/// fail-closed. It calls `ServerImpl::decommission_agent`, which builds this
/// cascade. §27 builds the fan-out AND wires its first production caller.
///
/// STANDING RULE — the gate is the single `Decommission:Delete` securable, so
/// adding a store no longer changes WHO can decommission — but it DOES widen WHAT
/// the securable destroys, so when you add a store to `AgentDecommissionStores`
/// you MUST: (a) append the store here, (b) register it in
/// `agent_decommission.cpp`'s registration list, (c) bump `kCascadeStoreCount` in
/// `test_agent_decommission.cpp`, (d) add the store to the blast-radius lists in
/// `sle_routes.hpp`/`.cpp`, `rest_api_v1.cpp`'s delete block, ADR-0024 Decisions
/// 9/11, and `rest-api.md`. The drift guard in `test_agent_decommission.cpp` fails
/// until (c) is done, so the store list and the documented radius cannot silently
/// diverge.
///
/// ACCOUNTABLE, aggregated. Each per-store `delete_agent` now RETURNS a bool
/// status: true iff the delete actually committed, false on a transient failure
/// (a PG lease it cannot acquire in time, a rolled-back transaction, a SQL
/// error). This cascade attempts EVERY registered store even when an earlier one
/// throws or reports failure, aggregates the outcomes, and returns a structured
/// result the caller can audit (which stores were deleted / skipped / failed).
/// A store that returns false — a delete that did NOT happen — is recorded
/// `Failed`, never `Deleted`, so a `DecommissionResult` can never claim erasure
/// that a silently-rolled-back DELETE did not achieve (the ADR-0024 Decision 11
/// Art.17 evidence must be truthful).
///
/// LEASE DISCIPLINE (ADR-0012). Each `delete_agent` acquires and releases its
/// OWN lease/lock inside the call and returns before the cascade moves on, so
/// the cascade never holds one store's lease across another store's call — the
/// "never holding a lease across another store call" rule.
///
/// NULL-TOLERANT, like the sibling ingest seams. A store that is not configured
/// on this deployment (a null pointer) is recorded as `Skipped`, never a crash.

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

// Non-owning forward declarations — the .cpp includes the store headers so it
// can call each `delete_agent`.
class InventoryStore;
class SoftwareInventoryStore;
class AppPerfDailyStore;
class DeviceInventoryStore;
class SoftwareLicensingStore;
class AppUsageStore;

/// Per-store outcome of one decommission fan-out.
enum class DecommissionOutcome {
    Deleted, ///< delete_agent was invoked and reported success (returned true):
             ///< the delete committed. This is confirmed erasure, not merely
             ///< "invoked".
    Skipped, ///< the store was not configured on this deployment (null pointer).
    Failed,  ///< delete_agent reported failure (returned false — e.g. a transient
             ///< PG outage rolled the DELETE back) OR threw. Either way the delete
             ///< did NOT commit; every OTHER store was still attempted.
};

/// Human-readable outcome tag for logs/audit ("deleted"|"skipped"|"failed").
[[nodiscard]] const char* to_string(DecommissionOutcome o) noexcept;

/// One store's line in the aggregated result.
struct DecommissionStoreResult {
    std::string store; ///< store name, for the audit trail / logs
    DecommissionOutcome outcome{DecommissionOutcome::Skipped};
    std::string error; ///< populated iff outcome == Failed
};

/// Aggregate result of a single `decommission(agent_id)` call — one entry per
/// registered store, plus rolled-up counts so a caller can audit at a glance.
struct DecommissionResult {
    std::string agent_id;
    std::vector<DecommissionStoreResult> stores;
    std::size_t deleted{0};
    std::size_t skipped{0};
    std::size_t failed{0};

    /// True iff no registered store's delete FAILED. Now that each `delete_agent`
    /// reports its commit status, a configured store whose delete did not commit
    /// (a transient PG failure that rolls the DELETE back, or a throw) counts as
    /// `failed` and flips `ok()` to false — so for a decommission that did real
    /// work (`deleted > 0`), `ok()` means "erasure confirmed across every
    /// configured store", not merely "no exception".
    ///
    /// CAVEAT — `ok()` is NOT by itself proof that anything was erased. An
    /// all-`Skipped` result is also `ok()`: an empty `agent_id` short-circuits
    /// to every-store-`Skipped` (see `decommission`), and a
    /// deployment that configured no stores skips them all. A caller using this
    /// as Art.17 erasure evidence must therefore confirm the `agent_id` was a
    /// real, non-empty id AND check `deleted` (or the per-store outcomes), not
    /// `ok()` alone.
    [[nodiscard]] bool ok() const noexcept { return failed == 0; }
};

/// The per-agent stores the cascade fans `delete_agent` across. NON-OWNING: the
/// caller (server.cpp) owns every store for the process lifetime and outlives
/// the cascade. Any pointer may be null — a null store is skipped, not a crash.
/// Extend this struct (and the constructor's registration list) when a new
/// per-agent store with a `delete_agent` joins the ladder.
struct AgentDecommissionStores {
    InventoryStore* inventory{nullptr};                  ///< PG generic per-source inventory
    SoftwareInventoryStore* software_inventory{nullptr}; ///< PG installed_software
    AppPerfDailyStore* app_perf_daily{nullptr};          ///< PG per-device app-perf
    DeviceInventoryStore* device_inventory{nullptr};     ///< PG device_ci
    SoftwareLicensingStore* software_licensing{nullptr}; ///< PG detected licences (SLE)
    AppUsageStore* app_usage{nullptr};                    ///< PG per-agent last-used app usage
};

/// A single decommission entry point that fans `delete_agent` across a fixed set
/// of per-agent stores. Construct it with the stores this deployment owns; call
/// `decommission(agent_id)` on an operator decommission.
class AgentDecommission {
public:
    /// Register the fixed set of per-agent stores. Null pointers are registered
    /// too so the structured result still reports them as `Skipped` (auditable:
    /// "this deployment has no such store" is distinct from "the store had
    /// nothing to delete"). The SoftwareLicensingStore is included — it carries
    /// the Decision 11 per-user `user_ref` rows, the whole reason this cascade
    /// exists.
    explicit AgentDecommission(const AgentDecommissionStores& stores);

    /// Empty cascade — register targets with `add_store`.
    AgentDecommission() = default;

    /// Register an additional decommission target by name. Used by tests (to
    /// inject a store that throws, or returns false, or a null/unconfigured
    /// target) and as the forward-compat seam for a per-agent store not yet
    /// modelled by AgentDecommissionStores. The `deleter` returns true iff the
    /// delete committed; a false return is recorded `Failed`. A null `deleter`
    /// is registered as an always-Skipped target.
    void add_store(std::string name, std::function<bool(std::string_view)> deleter);

    /// Fan `delete_agent(agent_id)` across every registered store. Best-effort:
    /// attempts every store even if one throws OR reports failure (a delete that
    /// did not commit). Returns the per-store outcomes.
    /// An empty `agent_id` is a no-op that logs and reports every target Skipped
    /// (mirrors each store's own empty-id guard; a `WHERE agent_id = ''` DELETE
    /// would be a footgun, never a fleet wipe).
    [[nodiscard]] DecommissionResult decommission(std::string_view agent_id);

    /// Number of registered targets (incl. skipped/null ones).
    [[nodiscard]] std::size_t target_count() const noexcept { return targets_.size(); }

private:
    struct Target {
        std::string name;
        std::function<bool(std::string_view)> deleter; ///< null ⇒ always Skipped;
                                                       ///< returns true iff committed
    };
    std::vector<Target> targets_;
};

} // namespace yuzu::server
