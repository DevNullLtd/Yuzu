#pragma once

/// @file access_review_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `access_review_store`) for
/// Periodic Access Review CAMPAIGNS (SOC 2 CC6.2) — the persistence behind
/// "freeze the current grant population, have reviewers attest or flag each
/// grant, keep the evidence forever". This store does NOT compute the grant
/// population itself (that is `access_review_model.hpp`'s
/// `build_access_review`) — it only persists a campaign's FROZEN snapshot
/// and the per-grant decisions recorded against it.
///
/// Posture per ADR-0012 §1: **authoritative / fail-hard**, both at
/// construction AND at runtime — mirrors `EnginePrincipalStore`, not
/// `PreflightRunStore`'s durability-on-top posture. This is SOC 2 evidence:
/// a write that silently degraded to a no-op, or a read that silently
/// returned an empty result on a query error, would corrupt the audit trail
/// this feature exists to produce. Every mutator and every "must be
/// complete" reader returns a typed `std::expected<T, std::string>`.
/// Construction is fail-CLOSED — a reachable database whose schema can't
/// migrate leaves the store `!is_open()`, which server.cpp wires to
/// `startup_failed_` (server.cpp wiring is out of this file's scope — a
/// later task).
///
/// R3 (codex BLOCK) — freeze at open: `open_campaign` inserts the campaign
/// row AND one `decision='pending'` attestation row per entry in the
/// caller-supplied `frozen_population` — the COMPLETE current grant set,
/// captured by the caller via `access_review_model::build_access_review`
/// immediately before calling this — in ONE transaction. This is what makes
/// "every grant that existed when the campaign opened has a reviewable row"
/// a provable invariant rather than a hope: a grant created after
/// `open_campaign` returns is simply not part of this campaign (review it in
/// the next one), and a grant revoked after `open_campaign` returns is STILL
/// reviewable here (the row is frozen, not re-derived from live state) —
/// exactly the "who had access, on this date, and did a reviewer sign off on
/// it" question SOC 2 CC6.2 evidence must answer.
///
/// Deliberately NO prune method — unlike the `/auto` pre-flight/deployment
/// runs (which are operational scratch state, 14-day-pruned), a closed
/// access-review campaign IS the compliance evidence. It persists
/// indefinitely; any future retention policy is an explicit, separately-
/// reviewed decision, not a default cadence inherited from an unrelated
/// store.
///
/// Two tables (schema-qualified at runtime, unqualified in the migration —
/// the runner sets `search_path` for the migration transaction):
///   * access_review_campaign    — one row per opened review campaign.
///   * access_review_attestation — one row per (campaign, principal, role)
///     grant frozen at open; PK is the full 4-tuple so a decision can only
///     ever be recorded against a grant that was actually in the frozen
///     population (an unknown/foreign key never matches — see
///     `record_attestation`).

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One grant to freeze into a campaign at `open_campaign` time — the shape
/// `access_review_model::AccessReviewRow` is expanded into (one `GrantRef`
/// per (principal, role) pair, not per principal — a principal holding N
/// roles yields N frozen rows, each independently reviewable/attestable).
struct GrantRef {
    std::string principal_type; ///< "user" | "group" | "engine"
    std::string principal_id;
    std::string role_name;
    /// Caller-serialized snapshot of the grant as observed at freeze time
    /// (e.g. principal display_name/source/classification/lifecycle_state at
    /// that instant) — opaque to this store, stored and returned verbatim.
    /// Free-form (typically JSON), never parsed here.
    std::string grant_snapshot;
};

/// One persisted campaign metadata row.
struct AccessReviewCampaignRow {
    std::string campaign_id;
    std::string title;
    std::string status; ///< "open" | "closed"
    std::string created_by;
    std::int64_t created_at_ms{0};
    std::string closed_by;   ///< "" while open
    std::int64_t closed_at_ms{0}; ///< 0 while open
    /// "enabled" | "disabled" | "degraded" (A3, RBAC delivery plan) — the
    /// fleet's RBAC enforcement state AT OPEN, per
    /// `access_review_model::access_review_rbac_enforcement` /
    /// `rbac_enforcement_label` (`rbac_store.hpp`). Stamped once, at freeze
    /// time, alongside the grant population itself — NOT re-derived on a
    /// later read, matching every other frozen field on this row. Empty
    /// (`""`) is the honest-empty value for a campaign frozen BEFORE this
    /// column existed (schema migration 2) — never re-backfilled, and never
    /// confused with `"degraded"`: the store genuinely didn't degrade, the
    /// field simply didn't exist yet.
    std::string rbac_enforcement;
};

/// One persisted (campaign, principal, role) attestation row.
struct AccessReviewAttestationRow {
    std::string campaign_id;
    std::string principal_type; ///< "user" | "group" | "engine"
    std::string principal_id;
    std::string role_name;
    std::string decision; ///< "pending" | "attested" | "flagged_revoke"
    std::string reviewer; ///< "" until decided
    std::int64_t decided_at_ms{0}; ///< 0 until decided
    std::string justification;    ///< "" until decided (or never required)
    std::string grant_snapshot;   ///< verbatim from the freezing `GrantRef`
};

/// A campaign's full evidentiary state: metadata + every frozen attestation
/// row + a pending-count convenience field (the "review completeness"
/// number a dashboard/REST caller needs without re-counting the vector).
struct CampaignView {
    AccessReviewCampaignRow campaign;
    std::vector<AccessReviewAttestationRow> attestations;
    int pending_count{0};
};

class AccessReviewStore {
public:
    explicit AccessReviewStore(pg::PgPool& pool);

    AccessReviewStore(const AccessReviewStore&) = delete;
    AccessReviewStore& operator=(const AccessReviewStore&) = delete;
    AccessReviewStore(AccessReviewStore&&) = delete;
    AccessReviewStore& operator=(AccessReviewStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// R3 — freeze at open (see file header). Mints a fresh `campaign_id`,
    /// inserts the campaign row (`status='open'`), and inserts one
    /// `decision='pending'` attestation row per entry in
    /// `frozen_population` — ALL in one transaction. `title`/`created_by`
    /// must be non-empty. `rbac_enforcement` must be exactly one of
    /// `"enabled"`/`"disabled"`/`"degraded"` (A3 — the caller computes this
    /// via `access_review_model::access_review_rbac_enforcement` on the same
    /// `RbacStore` INSTANCE used to build `frozen_population`, read
    /// immediately afterward — a separate, later call, not the same read —
    /// and passes it in; this store has no `RbacStore*` of its own and never
    /// derives authorization state itself) — an empty or unrecognised value is
    /// rejected, mirroring `record_attestation`'s `decision` validation; the
    /// column's own `""` default exists ONLY for rows frozen before this
    /// field existed (schema migration 2), never as a value a live caller
    /// may supply. Returns the minted `campaign_id` on success;
    /// `unexpected(msg)` if the transaction did not commit (nothing is
    /// left half-open — the whole freeze is atomic).
    [[nodiscard]] std::expected<std::string, std::string>
    open_campaign(std::string title, std::string created_by,
                 const std::vector<GrantRef>& frozen_population,
                 std::string rbac_enforcement);

    /// Record (or overwrite, on a later re-attest) a reviewer's decision for
    /// one frozen grant. `decision` must be `"attested"` or
    /// `"flagged_revoke"` — NEVER `"pending"` (that is the frozen-at-open
    /// default only; there is no route back to pending once a reviewer has
    /// spoken, matching how `record_failed_login`-style stores never allow a
    /// terminal-shaped write to un-terminal itself). Stamps
    /// `decided_at_ms = now` (caller-independent — this store reads the wall
    /// clock, matching `EnginePrincipalStore`'s `now_epoch` idiom) and the
    /// given `reviewer`/`justification`. `unexpected("not_found: ...")` —
    /// note the machine-checkable `not_found:` prefix, so a REST caller can
    /// map it to 404 rather than 503 — when the (campaign_id, principal_type,
    /// principal_id, role_name) tuple is not in the frozen population, OR
    /// the campaign is not open (closed campaigns are immutable evidence —
    /// see `close_campaign`). Any other `unexpected(msg)` is a genuine
    /// write failure (503/retry).
    [[nodiscard]] std::expected<void, std::string>
    record_attestation(const std::string& campaign_id, const std::string& principal_type,
                       const std::string& principal_id, const std::string& role_name,
                       std::string decision, std::string reviewer, std::string justification);

    /// Full evidentiary state for one campaign: metadata + every frozen
    /// attestation row + `pending_count`. `unexpected("not_found: ...")`
    /// (machine-checkable prefix, as `record_attestation` above) when no
    /// campaign with this id exists; any other `unexpected(msg)` is a
    /// genuine read failure (503/retry).
    [[nodiscard]] std::expected<CampaignView, std::string>
    get_campaign(const std::string& campaign_id);

    /// Close an open campaign (`status='open' -> 'closed'`, stamps
    /// `closed_by`/`closed_at_ms`). Does NOT touch attestation rows — a
    /// campaign may be closed with pending rows still outstanding (an
    /// incomplete review is itself a fact the evidence should show, not one
    /// this store silently launders by forcing completion). Idempotent-
    /// rejecting: closing an already-closed or unknown campaign returns
    /// `unexpected("not_found: ...")` (machine-checkable prefix, as above);
    /// any other `unexpected(msg)` is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string>
    close_campaign(const std::string& campaign_id, const std::string& closed_by);

    /// Every campaign's metadata row (NOT its attestations — call
    /// `get_campaign` for those), newest-first by `created_at_ms`. This is
    /// the surface an auditor needs to prove reviews ran on cadence — "list
    /// every campaign that ever ran" — so unlike the operational `/auto`
    /// pre-flight/deployment run stores, nothing here is pruned. Bounded to
    /// the most recent 500 campaigns (a monthly-cadence program takes ~40
    /// years to reach that; a higher-frequency one is exactly the case an
    /// auditor would want capped rather than an unbounded read). Same
    /// posture as every other reader on this store: `unexpected(msg)` is a
    /// genuine read failure (503/retry), never a silently-partial result.
    [[nodiscard]] std::expected<std::vector<AccessReviewCampaignRow>, std::string>
    list_campaigns();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
