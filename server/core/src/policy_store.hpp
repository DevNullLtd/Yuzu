#pragma once

/// @file policy_store.hpp
/// Compliance definition + status store (ADR-0056, schema `policy_store`) —
/// six operator-authored tables (`policy_fragments`/`policies`/
/// `policy_inputs`/`policy_triggers`/`policy_groups`/`policy_status`) plus one
/// new, purely operational table (`policy_dispatch_state`) that exists only
/// to make `PolicyEvaluator`'s dispatch decision safe across replicas.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`policy_store.policies`) —
/// pooled connections carry no per-store search_path. Mutate-and-return uses
/// `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.
///
/// Posture (ADR-0012 §1, split by table class — see ADR-0056 "Posture"):
/// operator-authored intent (fragments/policies/inputs/triggers/groups) is
/// AUTHORITATIVE/fail-hard; reads that feed `PolicyEvaluator`'s dispatch
/// claim, a compliance percentage, or a remediation target list are
/// degrade-distinguishable (`PolicyReadError::kDegraded`, never a silent
/// empty) per ADR-0036 — collapsing "the DB could not answer" into "there is
/// nothing to do" on any of those paths reads as false fleet compliance or a
/// remediation that silently fixes nobody. `policy_dispatch_state` is
/// internal-only, never read outside `claim_due_policies`.
///
/// `create_fragment`/`create_policy` write once — there is no update path for
/// a fragment or a policy's own detail rows (only `enable_policy`/
/// `disable_policy` and the entire `policy_status` table mutate after
/// creation). This is why the backfill IDENTITY/LIFECYCLE partition in
/// ADR-0056 is unusually clean: five tables are pure write-once IDENTITY, one
/// column pair (`policies.enabled`/`updated_at`) is LIFECYCLE, and
/// `policy_status` is fully LIFECYCLE.

#include "compliance_types.hpp"
#include "pg/pg_pool.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

// ── Data types (moved verbatim to compliance_types.hpp, ADR-0031 WS-A4 —
// PolicyTrigger/PolicyInput/PolicyGroupBinding/PolicyFragment/Policy/
// PolicyQuery/FragmentQuery/PolicyAgentStatus/ComplianceSummary/
// FleetCompliance/PolicyReadError; re-exposed here via the include above so
// every existing includer keeps seeing them transitively) ──────────────────

/// Prefix for a genuine DB/lease failure on a mutator, so callers (route
/// handlers) can classify 503 (this prefix) vs 400/404/409 (a validation or
/// not-found message, or `kConflictPrefix` from store_errors.hpp) without
/// string-matching arbitrary text. Mirrors `kSwDeployDbErrorPrefix`.
inline constexpr std::string_view kPolicyDbErrorPrefix = "db_error: ";

/// Governance (2026-08-24): originally defined above but never checked
/// anywhere — every mutator route mapped a degraded-store error the same as a
/// validation error (400), leaking the raw internal string into the
/// response body. Mirrors `is_conflict_error`/`strip_conflict_prefix` in
/// store_errors.hpp.
inline bool is_db_error(std::string_view msg) {
    return msg.rfind(kPolicyDbErrorPrefix, 0) == 0;
}

inline std::string_view strip_db_error_prefix(std::string_view msg) {
    if (!is_db_error(msg))
        return msg;
    return msg.substr(kPolicyDbErrorPrefix.size());
}

// ── PolicyStore ──────────────────────────────────────────────────────────────

class PolicyStore {
public:
    explicit PolicyStore(pg::PgPool& pool);

    PolicyStore(const PolicyStore&) = delete;
    PolicyStore& operator=(const PolicyStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Fragments ────────────────────────────────────────────────────────
    [[nodiscard]] std::expected<std::string, std::string>
    create_fragment(const std::string& yaml_source);
    [[nodiscard]] std::expected<std::vector<PolicyFragment>, PolicyReadError>
    query_fragments(const FragmentQuery& q = {}) const;
    [[nodiscard]] std::expected<std::optional<PolicyFragment>, PolicyReadError>
    get_fragment(const std::string& id) const;
    [[nodiscard]] bool delete_fragment(const std::string& id);

    /// Extract the operator-facing fragment name from a YAML source string
    /// without parsing the entire fragment. Used by route handlers that
    /// need to attribute denial audits before calling create_fragment().
    /// Returns the displayName, falling back to name, falling back to id,
    /// finally falling back to "" if none are present. Defined as a static
    /// helper because route layers should not own YAML parsing themselves.
    static std::string peek_fragment_name(const std::string& yaml_source);

    // ── Policies ─────────────────────────────────────────────────────────
    [[nodiscard]] std::expected<std::string, std::string>
    create_policy(const std::string& yaml_source);
    [[nodiscard]] std::expected<std::vector<Policy>, PolicyReadError>
    query_policies(const PolicyQuery& q = {}) const;
    [[nodiscard]] std::expected<std::optional<Policy>, PolicyReadError>
    get_policy(const std::string& id) const;
    [[nodiscard]] std::expected<void, std::string> enable_policy(const std::string& id);
    [[nodiscard]] std::expected<void, std::string> disable_policy(const std::string& id);
    [[nodiscard]] bool delete_policy(const std::string& id);

    // ── Compliance tracking ──────────────────────────────────────────────
    /// `expected_gen` (HA WS-3 3.4): when set, this write is FENCED on the
    /// caller's remediation claim generation — a plain UPDATE guarded by
    /// `remediation_claim_gen = expected_gen`, so a stale claim-holder whose
    /// row a sibling has already reclaimed (bumping the gen) writes NOTHING
    /// instead of stomping the reclaimer's live status. A zero-row fenced
    /// write is a benign no-op (logged + counted via yuzu_server_policy_
    /// remediation_fence_skip_total), NOT an error. When unset (the ordinary
    /// detection path, which may be the FIRST-ever write for a pair) it is the
    /// unconditional UPSERT. `expected_gen` MUST NEVER be 0 — 0 is the DEFAULT
    /// no-claim / pre-v3 sentinel `nextval` never mints, so a fenced write with
    /// 0 would match every unclaimed row; the evaluator passes a real gen or
    /// `nullopt`, gating on `claim_gen != 0`, never 0. Both paths author
    /// last_check_at/last_fix_at from Postgres NOW() so the stranded-fixing
    /// sweep never compares a replica clock against a DB clock (review B2).
    ///
    /// Returns TRUE iff a row was written. For the unfenced path that is
    /// always true (the UPSERT always writes). For the fenced path FALSE is
    /// the benign zero-row no-op — the caller's claim generation no longer
    /// owns the row — and the remediation-path caller counts it
    /// (yuzu_server_policy_remediation_fence_skip_total). `unexpected` is
    /// reserved for a genuine store failure, never a fence miss.
    [[nodiscard]] std::expected<bool, std::string>
    update_agent_status(const std::string& policy_id, const std::string& agent_id,
                        const std::string& status, const std::string& check_result = "",
                        std::optional<int64_t> expected_gen = std::nullopt);
    [[nodiscard]] std::expected<std::optional<PolicyAgentStatus>, PolicyReadError>
    get_agent_status(const std::string& policy_id, const std::string& agent_id) const;
    [[nodiscard]] std::expected<std::vector<PolicyAgentStatus>, PolicyReadError>
    get_policy_agent_statuses(const std::string& policy_id) const;
    [[nodiscard]] std::expected<ComplianceSummary, PolicyReadError>
    get_compliance_summary(const std::string& policy_id) const;
    [[nodiscard]] std::expected<FleetCompliance, PolicyReadError> get_fleet_compliance() const;

    // ── Cache invalidation ───────────────────────────────────────────────
    /// Reset all agent statuses to 'unknown' for a specific policy, forcing
    /// re-check. Returns the number of agent statuses invalidated.
    [[nodiscard]] std::expected<int64_t, std::string>
    invalidate_policy(const std::string& policy_id);

    /// Reset all agent statuses to 'unknown' across ALL policies. Returns the
    /// total number of agent statuses invalidated.
    [[nodiscard]] std::expected<int64_t, std::string> invalidate_all_policies();

    // ── Multi-replica dispatch claim (ADR-0056 "headline decision") ────────
    /// Single-sweeper CLAIM: under `pg_try_advisory_xact_lock('policy_store:
    /// dispatch')`, sweeps stranded `fixing` rows (`last_fix_at` older than
    /// `fixing_stale_seconds`) back to `unknown`, then claims every enabled
    /// policy whose interval has elapsed (durable in `policy_dispatch_state`,
    /// replacing the evaluator's old in-memory `last_eval_`) and returns the
    /// claimed policies fully loaded. Lock not acquired -> `{}` (empty, Ok —
    /// another replica is claiming this tick, the normal skip). A genuine DB
    /// error -> `unexpected` — the caller (`PolicyEvaluator::dispatch_due`)
    /// MUST skip the tick on this, never treat it as "nothing due".
    [[nodiscard]] std::expected<std::vector<Policy>, std::string>
    claim_due_policies(int64_t now, int64_t default_interval_seconds,
                       int64_t fixing_stale_seconds);

    /// Unconditionally stamps `policy_dispatch_state.last_dispatched_at` for
    /// a manual, operator-triggered dispatch (`PolicyEvaluator::evaluate_now`)
    /// — no advisory lock, no WHERE-guard, no interval check (evaluate_now
    /// deliberately bypasses the interval). Without this, a manual dispatch
    /// leaves no durable record, so the very next automatic tick's
    /// claim_due_policies sees an unclaimed policy (no row = the fresh-INSERT
    /// branch, which always succeeds regardless of the WHERE guard) and
    /// re-dispatches immediately — a duplicate check within seconds of the
    /// manual one, found in testing (the interval-throttle regression
    /// ADR-0056's removal of the in-memory last_eval_ would otherwise cause).
    [[nodiscard]] std::expected<void, std::string> record_dispatch(const std::string& policy_id,
                                                                    int64_t now);

    // ── Durable per-(policy,agent) remediation claim (HA WS-3 3.4) ──────────
    /// The ids a claim actually won, plus the per-CALL generation token minted
    /// for them (one value shared by every id in that claim). `generation` is
    /// meaningless when `ids` is empty.
    struct RemediationClaim {
        std::vector<std::string> ids;
        int64_t generation{0};
    };

    /// UPSERT CAS: claims the subset of `agent_ids` whose `policy_status` row
    /// is either absent (fresh-INSERT branch — `resolve_targets()`'s scope
    /// list can name an agent never checked before), unclaimed
    /// (`remediation_claim_at == 0`), or claimed stale (older than
    /// `NOW() - stale_seconds`, authored from POSTGRES NOW() — mirrors
    /// `claim_due_policies`'s own fixing_stale_seconds window; callers MUST
    /// pass the SAME value so the two never fight over the same row), AND
    /// whose `fix_attempt_count` has not already hit the cap. Returns exactly
    /// the ids actually claimed — NEVER the full `agent_ids` echoed back
    /// unconditionally, or two concurrent callers (same process or a sibling
    /// replica) would both believe they own the same agent. An UPDATE-only
    /// claim would silently never remediate an agent with no existing row —
    /// this is why the claim is an UPSERT, not a plain UPDATE. Deliberately
    /// does NOT check `open_`/acquire failure any differently from every other
    /// mutator here — `try_acquire_for` returning no lease or the UPSERT
    /// itself erroring both surface as `unexpected`, never collapsed into
    /// "claimed nothing" (PolicyEvaluator::remediate must not read a degraded
    /// claim read as "already in flight").
    ///
    /// The returned `generation` MUST be threaded back into
    /// `release_remediation_claim` and every remediation-owned
    /// `update_agent_status` (mark 'fixing', the verify verdict, the
    /// fix/verify 'error' writes) so a stale holder cannot release or overwrite
    /// a row a sibling has already reclaimed (review B3 / ABA). Staleness is
    /// authored AND adjudicated entirely from Postgres NOW() (review B2) — a
    /// replica clock can no longer steal a live claim, which is why this takes
    /// NO `now`.
    ///
    /// RESIDUAL (ADR-2002 effectively-once, review Q5 + UP-2): the generation
    /// fences every DB write, but a DISPATCH — the fix send AND the later
    /// post-fix VERIFY send (both gRPC, in `collect_ready`) — is not a fenced
    /// write. A holder paused longer than `stale_seconds` between winning here
    /// and sending can still emit that one fix (or verify) to a target a
    /// sibling has since reclaimed (its later fenced DB writes correctly
    /// no-op). Closing it would require routing operator remediation through
    /// the leader outbox, which the fenced-leader concern forbids for an
    /// operator-synchronous path.
    [[nodiscard]] std::expected<RemediationClaim, std::string>
    claim_remediation(const std::string& policy_id, const std::vector<std::string>& agent_ids,
                      int64_t stale_seconds);

    /// Releases a durable claim WITHOUT touching `fix_attempt_count` or
    /// `status` — the caller (PolicyEvaluator::remediate) uses this for a
    /// claimed-but-not-DELIVERED target (offline / quarantined / plugin
    /// absent / a systemic containment-gate failure), which must never burn
    /// a capped retry attempt (ADR-2002 §6 finding 6a(ii)). Also called by
    /// `collect_ready()` when a dispatched FixWait entry matures — the
    /// dispatching replica is the only holder of that in-memory entry, so
    /// this release is itself replica-local with nothing to coordinate,
    /// exactly like `update_agent_status`'s own per-replica FixWait writes.
    /// FENCED on `generation` (review B3): only zeroes `remediation_claim_at`
    /// for rows still carrying the caller's claim generation, so a stale
    /// holder resuming after a sibling reclaim (which bumped the gen) releases
    /// NOTHING instead of erasing the sibling's live claim. A no-op (row
    /// already released, never existed, or reclaimed by another gen) is benign,
    /// not an error.
    ///
    /// LOAD-BEARING (review UP-5): this clears ONLY `remediation_claim_at`,
    /// NEVER `remediation_claim_gen`. `collect_ready` releases the FixWait claim
    /// here and only THEN dispatches the post-fix verify, whose verdict write is
    /// fenced on the SAME generation — so zeroing the gen on release would
    /// silently no-op every post-fix verify verdict fleet-wide. Do not "tidy" it.
    [[nodiscard]] std::expected<void, std::string>
    release_remediation_claim(const std::string& policy_id,
                              const std::vector<std::string>& agent_ids, int64_t generation);

private:
    pg::PgPool& pool_;
    bool open_{false};

    // Fleet compliance cache (recomputed at most every 60s). A plain mutex
    // (not the SQLite-era shared_mutex) since the pool itself provides real
    // concurrency — this only protects the two cache fields.
    mutable std::mutex cache_mtx_;
    mutable FleetCompliance cached_fleet_compliance_;
    mutable std::chrono::steady_clock::time_point fleet_compliance_last_computed_{};
    static constexpr auto kFleetComplianceCacheTtl = std::chrono::seconds(60);

    // ADR-0012 §4 rule 2: invalidate synchronously on the store's OWN writes,
    // after the write lands. Called by every mutator of policy_status
    // (update_agent_status, invalidate_policy, invalidate_all_policies) on
    // success. Cheap: this only resets the TTL clock, not the DB.
    void invalidate_fleet_compliance_cache() const;

    static std::string generate_id();

    // Compute fleet compliance fresh from the DB. Returns kDegraded on a
    // read failure — the cache is never populated from a degraded read.
    std::expected<FleetCompliance, PolicyReadError> compute_fleet_compliance() const;
};

} // namespace yuzu::server
