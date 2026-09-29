#pragma once

/// @file baseline_store.hpp
/// Server-side storage for Guardian **Baselines** — the named, deployable
/// collection of Guards. See docs/guardian-baseline-model.md (resolved model)
/// and docs/guardian-mvp-contract.md §6/§7 (frozen contract; G10's single-scope
/// targeting is superseded by the baseline-model doc — assignment is now
/// included − excluded management groups).
///
/// Migrated to PostgreSQL (ADR-0006/0008/0009/0055, schema `baseline_store`);
/// was `guardian-baselines.db` (SQLite). See
/// docs/adr/0055-baseline-store-postgres-migration.md for the migration's
/// posture decisions (this header follows that ADR verbatim) and
/// docs/yuzu-guardian-design-v1.1.md §9.1/§24 for the schema + standing
/// invariants. `migrate_from_sqlite()` retired
/// (chore/retire-migrate-from-sqlite-batch-b, #3623) — see ADR-0055's Update;
/// server.cpp now runs a detect-and-warn probe over the legacy file instead.
///
/// Model recap (what this store persists):
///   - A Baseline groups one or more Guards (M:N, via `baseline_rules`) and
///     carries an ASSIGNMENT: a set of *included* minus *excluded* management
///     groups (`baseline_groups`; exclude wins, whole-Baseline grain).
///   - The Baseline is the ONLY deployable unit — individual Guards are never
///     deployed on their own (same shape as a GPO / Intune baseline / Jamf
///     Configuration Profile). Deploy is a separate, later slice; this store is
///     pure control-plane config with no engine dependency.
///   - Lifecycle is draft ↔ deployed (MVP). `deployed_snapshot` holds the member
///     set captured at the last deploy and is the ENFORCED set — the push/reconcile
///     gate reads it via deployed_member_rule_ids(), and the detail renderer diffs
///     it against live members for the "re-deploy to apply" flag.
///
/// Cross-store references (deliberate, no in-DB foreign key):
///   - A member row's `rule_id` points at a Guard in `GuaranteedStateStore`
///     (a DIFFERENT Postgres schema), and an assignment row's `group_id` points
///     at a management group in `ManagementGroupStore` (also a different
///     schema) — a cross-schema `REFERENCES` foreign key is possible in
///     Postgres but deliberately NOT used here, matching the pre-migration
///     SQLite store's cross-*file* reasoning: a membership/assignment row
///     whose target Guard or group has since been deleted is HARMLESS at
///     deploy time (the push builder resolves member Guards from the Guard
///     store and simply skips one that no longer exists). For config
///     integrity we still expose application-level cleanup hooks —
///     remove_rule_everywhere() / remove_group_everywhere() — for the
///     Guard-delete and group-delete paths to call in a later slice.
///   - The join tables DO carry an in-schema foreign key to `baselines` (same
///     schema) with ON DELETE CASCADE, so delete_baseline() tears down its own
///     members + assignment atomically, and inserting a join row for a
///     non-existent baseline is rejected by the FK.
///
/// Unlike the Guard EVENT store this is bounded operator-authored config (not a
/// multi-GB/day stream), so there is deliberately NO retention reaper / cleanup
/// thread here.
///
/// ── Posture (ADR-0012 §1 / ADR-0055) ─────────────────────────────────────────
/// Every table is operator-authored Guardian enforcement config — uniformly
/// AUTHORITATIVE (unlike ADR-0038's split-by-table-family, there is no
/// bounded/re-derivable telemetry table here to carve out a fail-soft tier).
///  - **Baseline CRUD writes — fail-hard** (unchanged from pre-migration):
///    `create_baseline`/`update_baseline`/`delete_baseline`/`set_members`/
///    `set_assignment` stay `std::expected<..., std::string>`, a
///    `kConflictPrefix`-tagged error mapping to HTTP 409.
///  - **The catastrophic-read set (CLAUDE.md Guardian invariant)** —
///    `deployed_member_rule_ids()` (both overloads) feed the push fan-out /
///    heartbeat reconcile gate and the per-device compliance REST view, so
///    BOTH are now `std::expected<..., std::string>`: a degraded read
///    (store-not-open / lease-timeout / query-error) is `std::unexpected`,
///    NEVER a silent empty container indistinguishable from "nothing
///    deployed" — every push/reconcile/REST consumer MUST abort (503 / no-op
///    push) on `!result`. A malformed OR genuinely-empty stored
///    `deployed_snapshot` is **not** a degrade — it is a successful read that
///    contributes nothing to the union (unchanged, fail-closed-by-construction
///    behavior pinned by the pre-migration store's own doc comment).
///  - **`get_members_checked()`** is a degrade-distinguishable twin of the
///    plain `get_members()` for the ONE call site that writes a live-member
///    read into a DURABLE enforced snapshot (the deploy handler,
///    `guardian_routes.cpp`) — a lease timeout there must abort the deploy,
///    never persist `deployed_snapshot = "[]"` (a durable disarm). Every other
///    `get_members()` caller is render-only / deny-or-benign (dashboard
///    fragments, the "drifted from deployed" diff) and keeps the plain
///    empty-on-degrade container (ADR-0038 "deferred widening" class).
///  - Every other read (`list_baselines`/`get_assignment`/`baselines_containing_rule`/
///    counts) stays plain container/size_t, empty-on-degrade — dashboard
///    display only, never an enforce/target decision.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

// Lifecycle states for a Baseline.
inline constexpr const char* kBaselineDraft = "draft";
inline constexpr const char* kBaselineDeployed = "deployed";

// Disposition of a management group within a Baseline's assignment.
inline constexpr const char* kAssignInclude = "include";
inline constexpr const char* kAssignExclude = "exclude";

struct Baseline {
    std::string baseline_id;       // 12-hex, generated by the store when empty on create
    std::string name;              // unique, human-authored
    std::string description;
    std::string lifecycle{kBaselineDraft}; // "draft" | "deployed"
    // JSON array of member rule_ids captured at the last deploy — the set the
    // fleet ACTUALLY enforces (see deployed_member_rule_ids()), distinct from the
    // live member set which may have been edited since (those draft edits enforce
    // only after a Push-gated re-deploy rewrites this). Written by deploy_baseline
    // (guardian_routes.cpp) as nlohmann::json(get_members_checked()).dump(); the
    // detail renderer diffs it against live members to flag "members changed —
    // re-deploy to apply" (baseline_members_drifted). Empty until first deploy.
    std::string deployed_snapshot;
    std::string created_by;
    std::string updated_by;
    std::string deployed_by;       // principal of the last deploy; empty if never deployed
    int64_t created_at{0};         // epoch seconds
    int64_t updated_at{0};         // epoch seconds
    int64_t deployed_at{0};        // epoch seconds of last deploy; 0 if never deployed
};

// A management-group reference in a Baseline's assignment.
struct BaselineGroupAssignment {
    std::string group_id;
    std::string disposition;       // "include" | "exclude"
};

class BaselineStore {
public:
    /// Borrows the shared pool and runs the `baseline_store` schema migration
    /// on a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed.
    explicit BaselineStore(pg::PgPool& pool);

    BaselineStore(const BaselineStore&) = delete;
    BaselineStore& operator=(const BaselineStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Baseline CRUD ──────────────────────────────────────────────────────
    // create_baseline generates a 12-hex baseline_id when `b.baseline_id` is
    // empty and returns the id that was used. A duplicate name (or a caller-
    // supplied duplicate id) is reported with `kConflictPrefix` so REST handlers
    // map it to HTTP 409 via is_conflict_error() — see store_errors.hpp.
    std::expected<std::string, std::string> create_baseline(const Baseline& b);
    // `store_ok` (optional out-param, same contract as get_baseline_by_name below)
    // disambiguates a transient STORE FAULT (pool/lease/query error — set false)
    // from a genuine NOT-FOUND (set true), so a caller gating a Guardian deploy/
    // delete/edit action can 503-and-retry instead of misreporting "Baseline not
    // found" for a baseline that still exists (governance UP-3 finding — the fix
    // this pattern already applied to get_baseline_by_name, extended here).
    std::optional<Baseline> get_baseline(const std::string& baseline_id,
                                         bool* store_ok = nullptr) const;
    // Look up a Baseline by its unique human-authored name (names are unique —
    // create_baseline reports a dup with kConflictPrefix). Backs the name-keyed
    // per-device compliance REST view so an integration (ServiceNow) can reference
    // a stable constant ("ServiceNow Compliance") instead of a churning baseline_id.
    // `store_ok` (optional out-param) disambiguates the two nullopt causes so a
    // caller can distinguish a transient STORE FAULT (pool/lease/query error —
    // set false) from a genuine NOT-FOUND (set true): the device-compliance route
    // maps the former to a retryable 503 and the latter to 404, so a CMDB poller
    // does not auto-delete the CI record on a transient fault (UP-13/sre-2).
    std::optional<Baseline> get_baseline_by_name(const std::string& name,
                                                 bool* store_ok = nullptr) const;
    std::vector<Baseline> list_baselines() const;
    // Updates the mutable scalar fields (name, description, lifecycle,
    // deployed_snapshot, deployed_by/at, updated_by) of an existing Baseline.
    // Members + assignment are managed by their own methods. Unknown id is a
    // non-conflict error; a name collision is a kConflictPrefix error.
    std::expected<void, std::string> update_baseline(const Baseline& b);
    // Deletes the Baseline and (via ON DELETE CASCADE) its member + assignment
    // rows. Unknown id is a non-conflict error.
    std::expected<void, std::string> delete_baseline(const std::string& baseline_id);

    // ── Member Guards (M:N) ────────────────────────────────────────────────
    // Replace the ENTIRE member set in one transaction (the create/edit form
    // posts the whole list). Duplicate rule_ids in `rule_ids` are de-duplicated.
    // The baseline must exist (enforced by the join table's FK).
    std::expected<void, std::string> set_members(const std::string& baseline_id,
                                                  const std::vector<std::string>& rule_ids);
    // Member rule_ids for a Baseline, sorted for a stable UI order.
    // Empty-on-degrade (render-only / deny-or-benign consumers — dashboard
    // fragments, the "drifted from deployed" diff). See get_members_checked()
    // for the degrade-distinguishable twin the deploy path must use instead.
    std::vector<std::string> get_members(const std::string& baseline_id) const;
    // Degrade-distinguishable twin of get_members(): std::unexpected on a
    // store-not-open / lease-timeout / query-error degrade, never a silent
    // empty vector. The ONLY caller that may write this read's result into a
    // DURABLE enforced state (deploy_baseline's deployed_snapshot write,
    // guardian_routes.cpp) MUST use this, not get_members() — a degrade
    // there must abort the deploy, never persist an empty snapshot (a
    // durable fleet-wide disarm of that Baseline).
    std::expected<std::vector<std::string>, std::string>
    get_members_checked(const std::string& baseline_id) const;
    // Which Baselines list this Guard as a member? (Reverse lookup the deploy /
    // reconciliation slice needs to recompute affected agents when a Guard
    // changes.) Returns baseline_ids.
    std::vector<std::string> baselines_containing_rule(const std::string& rule_id) const;
    // Cross-store cleanup hook: drop `rule_id` from EVERY Baseline's membership.
    // For the Guard-delete path to call (Guards live in a different schema, so
    // no in-DB cascade is possible). Returns the number of membership rows removed.
    std::size_t remove_rule_everywhere(const std::string& rule_id);

    // ── Assignment (included − excluded management groups) ──────────────────
    // Replace the ENTIRE assignment in one transaction. Each entry's disposition
    // must be "include" or "exclude" (validated; an invalid value aborts without
    // writing). Duplicate group_ids collapse to the LAST disposition seen. The
    // baseline must exist (enforced by the FK).
    std::expected<void, std::string>
    set_assignment(const std::string& baseline_id,
                   const std::vector<BaselineGroupAssignment>& groups);
    // The Baseline's assignment, sorted (include before exclude, then group_id).
    std::vector<BaselineGroupAssignment> get_assignment(const std::string& baseline_id) const;
    // Cross-store cleanup hook for management-group deletion (different schema).
    // Returns the number of assignment rows removed.
    std::size_t remove_group_everywhere(const std::string& group_id);

    // ── Reverse lookups for the deploy slice ────────────────────────────────
    // All Baselines currently in "deployed" lifecycle — the set the per-device
    // reconciliation deploy unions over.
    std::vector<Baseline> list_deployed_baselines() const;

    // The Baseline gate's input: the union of member rule_ids across every
    // *deployed* Baseline, sourced from each one's deployed_snapshot — i.e. the
    // set that was deployed, NOT the live member set. Editing a deployed
    // Baseline's members is a draft change that reaches agents only after a
    // Push-gated re-deploy rewrites the snapshot; sourcing live members here would
    // let a Write-without-Push principal change fleet enforcement and would
    // diverge from the dashboard's "re-deploy to apply" flag. A malformed or
    // empty snapshot contributes nothing (successful read, fail-closed by
    // construction — NOT a degrade). Computed under one bounded pool lease (no
    // per-Baseline round-trip). CATASTROPHIC-READ SET (CLAUDE.md Guardian
    // invariant): `std::unexpected` on a store-not-open / lease-timeout /
    // query-error degrade — the push fan-out / heartbeat reconcile caller MUST
    // abort on `!result`, never fan out an empty set it cannot distinguish from
    // "nothing deployed" (a fleet-wide silent disarm).
    std::expected<std::unordered_set<std::string>, std::string> deployed_member_rule_ids() const;

    // The deployed member rule_ids of ONE Baseline (its `deployed_snapshot` — the
    // enforced set captured at last deploy), sorted + de-duplicated. Per-Baseline
    // analog of the fleet-union overload above; same fail-closed parse (a draft /
    // never-deployed / empty / malformed snapshot yields {}, a successful read —
    // not a degrade). Backs the baseline-anchored per-device Guardian status REST
    // view. Same catastrophic-read posture as the fleet-union overload:
    // `std::unexpected` on degrade, never a silent empty vector that would
    // render a device falsely "compliant" (0 guards reported).
    std::expected<std::vector<std::string>, std::string>
    deployed_member_rule_ids(const std::string& baseline_id) const;

    // ── Counting (metrics / UI) ─────────────────────────────────────────────
    std::size_t baseline_count() const;
    std::size_t member_count(const std::string& baseline_id) const;

private:
    pg::PgPool& pool_;
    bool open_{false};

    std::string generate_id() const;
};

} // namespace yuzu::server
