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
/// Three tables (schema-qualified at runtime, unqualified in the migration —
/// the runner sets `search_path` for the migration transaction):
///   * access_review_campaign    — one row per opened review campaign.
///   * access_review_attestation — one row per (campaign, principal, role)
///     grant frozen at open; PK is the full 4-tuple so a decision can only
///     ever be recorded against a grant that was actually in the frozen
///     population (an unknown/foreign key never matches — see
///     `record_attestation`). Holds the CURRENT decision and `decision_seq`,
///     the count of decisions recorded for the grant (0 while pending).
///   * access_review_attestation_history: one row per recorded decision,
///     keyed by the 4-tuple and `seq` (schema v3, #4752). Every decision is
///     kept: a later decision for the same grant appends at seq+1 and never
///     replaces the earlier one, and a reviewer cannot decide a `user` grant
///     that names them. Ordering is by `seq`, never by time.
///
/// Append-only history, honestly bounded. The STORE writes the history row
/// inside the same transaction as the state change (`record_attestation`);
/// the database GUARDS (schema v3): triggers refuse a state change that is
/// not exactly one appended, matching history row, refuse any update or
/// delete of a history row and any delete of an attestation row (so of a
/// campaign that has one: the v1 cascade reaches the same trigger), and a
/// deferred constraint trigger refuses a commit in which the history and the
/// state did not advance together. That holds against the application path
/// and ordinary SQL, including an older binary's bare UPDATE during a mixed-
/// version window (it fails, SQLSTATE class 23, it does not bypass the
/// reviewer rule). It does NOT hold against the application credential: the
/// migration runner creates the schema under that role, so the owner can
/// DISABLE TRIGGER USER (DISABLE TRIGGER ALL is refused to a non-superuser,
/// because of the foreign keys' system triggers), forge a matching history
/// row, TRUNCATE or DROP TABLE, and a role granted TRUNCATE can truncate. A
/// data-only restore into a migrated schema is refused by the guard, so restore
/// schema and data together. A future migration that touches attestation rows
/// must DISABLE TRIGGER USER inside its own transaction. The audit store is
/// evidence independent of these tables but not of the database credential: it
/// is in the same database with no guard triggers, so it is independent only to
/// the extent audit rows are exported.
///
/// A decision event is ONE COMMITTED decision transaction. When the
/// connection drops after COMMIT was sent, the caller cannot tell whether the
/// decision was recorded (`PgPool`'s lost-COMMIT ambiguity) and is answered
/// with a write failure. GET the campaign and compare `decision_seq` before
/// retrying: a retry after an unacknowledged commit appends an identical
/// decision at seq+1, which is kept and visible (an earlier entry shows at most
/// its first 64 characters, so match on the rest), not an error, until the
/// grant's 100th decision.
///
/// Close starvation: a queued `close_campaign` does not block a NEW
/// attestation's `FOR SHARE` on the campaign row, so under a continuous
/// stream of attestations a close can wait for the pool's 10 s
/// `lock_timeout` and answer a write failure (503). Retry it.
///
/// Schema v3 REFUSES a database that holds a decision recorded by the
/// subject of the grant (an earlier build allowed it): the store is
/// `!is_open()`, naming the cause and the number of rows, and the version stays 2. Fresh-database
/// only (docs/user-manual/upgrading.md, "Deployment contract").

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Longest `justification` `record_attestation` accepts, in bytes; a longer one is refused with
/// `bad_request:` so no stored decision row is unbounded.
inline constexpr std::size_t kMaxJustificationBytes = 4096;

/// Most characters (not bytes) of a SUPERSEDED history entry's justification that
/// `get_campaign(id, true)` returns; the grant's latest entry is always returned in full. The
/// full text stays in the database. Together with `kMaxDecisionsPerGrant` this bounds what one
/// grant adds to a response, so a campaign with many grants cannot make it grow by
/// 4 KiB x 100 x grants.
inline constexpr std::int32_t kHistoryJustificationPreviewChars = 64;

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

/// One recorded decision for a grant: a row of `access_review_attestation_history`.
struct AttestationHistoryRow {
    std::int32_t seq{0};           ///< 1 for the first decision; ordering is by this, never time
    std::string decision;          ///< "attested" | "flagged_revoke"
    std::string previous_decision; ///< "pending" | "attested" | "flagged_revoke"; "" for a row
                                   ///< backfilled by schema v3 (not recorded, NOT pending)
    std::string reviewer;
    /// The grant's latest entry in full; a superseded entry carries at most its first
    /// `kHistoryJustificationPreviewChars` characters (the full text stays in the database).
    std::string justification;
    /// True only for a superseded entry whose stored text was longer than the preview.
    bool justification_truncated{false};
    std::int64_t decided_at_ms{0}; ///< the recording replica's wall clock
};

/// What `record_attestation` appended: the decision it superseded and the new `seq`.
struct AttestationOutcome {
    std::string previous_decision; ///< "pending" for a grant's first decision
    std::int32_t seq{0};           ///< 1 for the first decision, then 2, 3, ...
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
    /// Decisions recorded for this grant; 0 exactly while `decision == "pending"`.
    std::int32_t decision_seq{0};
    /// The latest (at most `kMaxDecisionsPerGrant`) decisions for this grant in `seq` order, every
    /// entry but the latest with its justification cut to a preview. Filled only by
    /// `get_campaign(id, include_history=true)`; empty otherwise (not a claim that none exist).
    std::vector<AttestationHistoryRow> history;
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
    /// left half-open — the whole freeze is atomic). An embedded NUL in
    /// `title` or `created_by` (libpq binds `c_str()`, so it would truncate
    /// the stored value) returns `unexpected("bad_request: ...")` before the
    /// pool is touched and no campaign is created.
    [[nodiscard]] std::expected<std::string, std::string>
    open_campaign(std::string title, std::string created_by,
                 const std::vector<GrantRef>& frozen_population,
                 std::string rbac_enforcement);

    /// Record a reviewer's decision for one frozen grant. A later decision for
    /// the same grant is APPENDED to the grant's history (seq+1, with the
    /// decision it superseded), never an overwrite; an identical repeat appends
    /// too. `decision` must be `"attested"` or `"flagged_revoke"`, NEVER
    /// `"pending"` (that is the frozen-at-open default only; there is no route
    /// back to pending once a reviewer has spoken). Stamps `decided_at_ms = now`
    /// (caller-independent, this store reads the wall clock, matching
    /// `EnginePrincipalStore`'s `now_epoch` idiom) and the given
    /// `reviewer`/`justification`. Returns the superseded decision and the new
    /// `seq`. The history row and the state change commit together or not at all.
    /// Errors carry a machine-checkable prefix so a REST caller can map them
    /// without parsing prose, in this precedence:
    /// `unexpected("bad_request: ...")` (400) when `campaign_id` fails
    /// `valid_campaign_id` (`access_review_model.hpp`; an empty id included),
    /// when `principal_type`/`principal_id`/`role_name`/`justification`/
    /// `reviewer` holds an embedded NUL (libpq binds `c_str()`, so a NUL would
    /// silently truncate the value), when `reviewer` is empty, when
    /// `principal_type`/`principal_id`/`role_name` exceeds its cap
    /// (`kPrincipalIdMaxLen`/`kRoleNameMaxLen`), or when `justification` exceeds
    /// `kMaxJustificationBytes`, all checked before the pool is touched;
    /// `unexpected("forbidden: ...")` (403) when `principal_type == "user"` and
    /// `principal_id == reviewer` (byte-exact), also decided before the pool is
    /// touched, so it precedes `not_found`; `unexpected("not_found: ...")` (404)
    /// when the (campaign_id, principal_type, principal_id, role_name) tuple is
    /// not in the frozen population, OR the campaign is not open (the
    /// application refuses further decisions on a closed campaign, see
    /// `close_campaign`; the campaign row itself has no database guard);
    /// `unexpected("bad_request: " + kDecisionCapMessage)` (400) when the grant
    /// already holds `kMaxDecisionsPerGrant` decisions, decided inside the
    /// transaction under the row lock (nothing is written). Any other
    /// `unexpected(msg)` is a genuine write failure (503/retry). The engine-owner
    /// and group-member rules are NOT enforced here (they need other stores); the
    /// route layer's gate owns them.
    [[nodiscard]] std::expected<AttestationOutcome, std::string>
    record_attestation(const std::string& campaign_id, const std::string& principal_type,
                       const std::string& principal_id, const std::string& role_name,
                       std::string decision, std::string reviewer, std::string justification);

    /// Full evidentiary state for one campaign: metadata + every frozen
    /// attestation row + `pending_count`. With `include_history` each row also
    /// carries its `history` (the recorded decisions in `seq` order), read in
    /// the same REPEATABLE READ snapshot, capped at the latest
    /// `kMaxDecisionsPerGrant` entries per grant (a backstop: the write cap keeps
    /// a grant at or under it, so `decision_seq > history.size()` means rows were
    /// added by other means). The cap holds for rows written through the application path;
    /// rows added by other means (owner-level SQL with the guard triggers disabled, which can
    /// forge a state row) are outside the guarantee. Every entry except the grant's latest (`seq ==
    /// decision_seq`) carries at most its first `kHistoryJustificationPreviewChars` characters of
    /// justification, cut in SQL on a character boundary, with `justification_truncated` set when
    /// the stored text was longer; the latest entry is whole. The two bounds together cap what one
    /// grant adds to a response; a superseded entry's full text is in the database only. It
    /// defaults to false so a caller that shows only the latest decision stays one cheap read.
    /// `unexpected("bad_request: ...")`
    /// when `campaign_id` fails `valid_campaign_id` (empty included), checked
    /// before the pool is touched. `unexpected("not_found: ...")`
    /// (machine-checkable prefix, as `record_attestation` above) when no
    /// campaign with this id exists; any other `unexpected(msg)` is a
    /// genuine read failure (503/retry).
    [[nodiscard]] std::expected<CampaignView, std::string>
    get_campaign(const std::string& campaign_id, bool include_history = false);

    /// Close an open campaign (`status='open' -> 'closed'`, stamps
    /// `closed_by`/`closed_at_ms`). Does NOT touch attestation rows — a
    /// campaign may be closed with pending rows still outstanding (an
    /// incomplete review is itself a fact the evidence should show, not one
    /// this store silently launders by forcing completion). Idempotent-
    /// rejecting: closing an already-closed or unknown campaign returns
    /// `unexpected("not_found: ...")` (machine-checkable prefix, as above);
    /// a `campaign_id` that fails `valid_campaign_id` (empty included)
    /// returns `unexpected("bad_request: ...")` before the pool is touched, as
    /// does a `closed_by` holding an embedded NUL; any other `unexpected(msg)`
    /// is a genuine write failure.
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
