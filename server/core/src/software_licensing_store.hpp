#pragma once

/// @file software_licensing_store.hpp
/// Born-on-Postgres detected-licence store (ADR-0024 Decision 4, schema
/// `software_licensing_store`): per-agent detected licence rows for the
/// `software_licensing` daily-sync source, the compliance evaluator's posture
/// rollup, and the alert-dedup state behind the `software_license.expiring` /
/// `software_license.expired` events.
///
/// COEXISTS with `ProductRegistryStore` (canonical identities + match links)
/// — one-store-per-typed-domain is the established precedent; NO cross-schema
/// SQL or FKs (ADR-0024 Decision 4): cross-store joins happen in C++ in the
/// evaluator, never holding a lease across another store call.
///
/// HASH-SKIP DIVERGENCE (ADR-0024 Decision 3, roadmap D-2): unlike the three
/// legacy sources, this source's `content_hash` is the SHA-256 of the RAW
/// received blob bytes, recomputed by the ingest seam
/// (`software_licensing_ingestion`) — never re-derived from parsed rows and
/// never trusted from the agent's claim. The store therefore has NO
/// canonical_hash of its own: it persists the seam's hash verbatim and offers
/// the trichotomy primitives (`stored_hash` / `touch` /
/// `replace_agent_licenses`) the seam drives — stored (full payload
/// replaced), touched (hash matched, freshness bumped), need-full (no state
/// row or drifted hash → the framework's `need_full` lever, which is also the
/// forced-reprojection path per roadmap G-8).
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// uses `RETURNING`, bounded leases. Failure posture (ADR-0012 §1 / ADR-0024
/// Decision 4):
///   - **Ingest:** fail-soft — a transient PG outage returns false; the seam
///     nacks and the agent re-sends next cycle.
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns
///     `std::nullopt` / `kDegraded` (logged at warn), NEVER a silent empty. A
///     silent-empty read on a compliance surface reads as "nothing detected /
///     nothing expired" — the fail-open lie ADR-0024 Decision 4 forbids. An
///     empty *value* = a genuine zero-row result.
///   - `first_seen`/`last_seen` on the state row are the **SERVER receipt
///     time**, never the agent-supplied `collected_at` (the #1685 lesson /
///     ADR-0016 clock-skew rule); the roadmap C-10 staleness read
///     (`count_stale_agents`) keys off them.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One detected licence row (roadmap §7.2 `agent_licenses`). String fields
/// carry the seam-scrubbed wire values; `state`/`license_type` etc. are the
/// closed §3.2 vocabularies (whitelisted at projection by the seam, C-7 —
/// the store persists what it is given). `expiry_at` is the agent-observed
/// expiry epoch (0 = none); `collected_at` is the agent-supplied collection
/// time (proto-carried; drives NO persisted freshness — see the state row).
/// `confidence` and `exe_hints` persist from migration v1: hash-skip
/// suppresses re-sync exactly when nothing changes, so a column added later
/// would stay empty forever on stable estates. Operators weight `heuristic`
/// rows via `confidence` (ADR-0024 Decisions 1/2/7); `exe_hints` (roadmap R6)
/// is the authoritative product↔exe bridge for the PR3 usage join.
/// `first_seen`/`last_seen` are store-stamped
/// (server receipt time of the storing replace); values supplied on write are
/// ignored.
struct AgentLicenseRow {
    std::string product;
    std::string vendor;
    std::string version;
    std::string license_type;
    std::string state;
    std::int64_t expiry_at{0}; ///< agent-observed epoch seconds; 0 = none
    std::string channel;       ///< e.g. KMS/MAK/OEM/retail
    std::string key_hint;      ///< OS-provided partial key — never full key material
    std::string detector;      ///< which probe produced the row
    std::string confidence;    ///< closed §3.2 set: authoritative|probable|heuristic|unknown
    std::string exe_hints;     ///< product↔exe bridge (roadmap R6)
    std::string user_scope;    ///< "machine" | "user"
    std::string user_ref;      ///< per ADR-0024 Decision 11 (pseudonym/raw/empty)
    std::int64_t collected_at{0};
    std::int64_t first_seen{0}; ///< store-stamped; ignored on write
    std::int64_t last_seen{0};  ///< store-stamped; ignored on write
};

/// One distinct detected (product, vendor) pair — the matcher-pass input
/// (evaluator joins these against the registry candidates in C++).
struct DetectedProduct {
    std::string product;
    std::string vendor;
};

// NB: the posture-rollup (`LicensePostureRow`) and alert-dedup
// (`LicenseAlertState`) types the compliance evaluator produced are NOT defined
// here — per ADR-0024 "Placement under ADR-1005" the evaluator and its
// posture/alert state are the SAM use-case-engine module's, stored in the
// module's own database, not created in-server.

/// Error type for the authoritative single-row reads (mirrors `CiReadError` /
/// `RegistryReadError`): the success type's `std::nullopt` == absent (read
/// succeeded, no row); `std::unexpected(kDegraded)` == store/pool/query
/// failure.
enum class LicensingReadError { kDegraded };

class SoftwareLicensingStore {
public:
    /// Borrows the shared pool and runs the `software_licensing_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before reaching
    /// here).
    explicit SoftwareLicensingStore(pg::PgPool& pool);

    SoftwareLicensingStore(const SoftwareLicensingStore&) = delete;
    SoftwareLicensingStore& operator=(const SoftwareLicensingStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter (the shared
    /// `yuzu_inventory_read_degrade_total{reason, source="software_licensing"}`
    /// family, #1675 — the SLE-specific `yuzu_server_sle_*` families land with
    /// the evaluator per roadmap R12). Set ONCE during single-threaded
    /// startup; null (the default) disables emission — every site is
    /// null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// The stored raw-blob content hash for one agent — the seam's hash-skip
    /// comparison input (trichotomy leg 1). `std::unexpected(kDegraded)` on a
    /// store/pool/query failure (the seam maps it to kError → nack); a value
    /// holding `std::nullopt` when no state row exists (cold cache → the seam
    /// answers need_full); a value holding the hash otherwise. The hash is
    /// returned VERBATIM as stored — the store never recomputes or normalises
    /// it (raw-blob contract, ADR-0024 Decision 3).
    [[nodiscard]] std::expected<std::optional<std::string>, LicensingReadError>
    stored_hash(std::string_view agent_id);

    /// Bump the state row's `last_seen` to the server receipt time after a
    /// matching hash-only report (trichotomy leg 2 — "touched": nothing
    /// changed, the agent is alive). Returns false when the row is missing or
    /// on a store/pool/query failure (the seam maps it to kError). Child rows
    /// are untouched — the state row is the freshness authority (C-10).
    [[nodiscard]] bool touch(std::string_view agent_id);

    /// Full replace for one agent (trichotomy leg 3 — "stored"), in ONE
    /// transaction: upsert the `agent_license_state` parent (persisting the
    /// seam-recomputed raw-blob `content_hash` VERBATIM + the blob's
    /// `cfg|user_ref` effective mode per roadmap D-10; `first_seen` preserved,
    /// `last_seen` = server receipt time), delete the agent's old
    /// `agent_licenses` rows, batch-insert the new ones. An empty `rows` is a
    /// legitimate replace-to-empty (zero detected licences is a valid state —
    /// ADR-0024 Decision 3's empty-vs-error rule is enforced upstream at the
    /// agent). Concurrent replaces for ONE agent serialise on a per-agent
    /// advisory lock (the software-inventory precedent). Fail-soft: false on
    /// any failure (the txn rolls back whole — old rows survive untouched;
    /// the seam nacks and the agent re-sends).
    [[nodiscard]] bool replace_agent_licenses(std::string_view agent_id,
                                              const std::vector<AgentLicenseRow>& rows,
                                              std::string_view content_hash,
                                              std::string_view effective_user_ref_mode);

    /// All detected licence rows for one agent (the `/sle/agents/{id}` drill),
    /// (product, vendor, version)-sorted, capped. AUTHORITATIVE read:
    /// `std::nullopt` on a store/pool/query degrade (NEVER a silent empty —
    /// callers surface a banner, not `.value_or({})`); an empty value = the
    /// agent genuinely reported no licences. An empty `agent_id` is a
    /// precondition miss → empty value.
    [[nodiscard]] std::optional<std::vector<AgentLicenseRow>>
    agent_licenses(std::string_view agent_id);

    /// Distinct detected (product, vendor) pairs across the fleet — the
    /// evaluator matcher pass's input (consumed in C++ alongside the
    /// installed-software catalog; no cross-schema SQL). Sorted, capped.
    /// AUTHORITATIVE read: `std::nullopt` on a degrade.
    [[nodiscard]] std::optional<std::vector<DetectedProduct>> distinct_products();

    // The posture-rollup and alert-dedup read/write methods (replace_posture_rollup,
    // posture_rollup, alert_state, upsert_alert_state) are removed — they are the
    // compliance evaluator's, and per ADR-0024 "Placement under ADR-1005" the
    // evaluator + its posture/alert state are the SAM UCE module's, not in-server.

    /// Drop an agent's detected rows AND its state row (the roadmap D-3
    /// agent-decommission cascade calls this per store). Both deletes run in one
    /// transaction so a removal can't leave a parent state row without children
    /// or vice versa. Returns true iff that transaction committed; false on a
    /// closed store, a lock/lease timeout, or a SQL failure. The failure is
    /// surfaced to the caller (the decommission cascade logs it and records the
    /// store Failed) rather than swallowed, so a silently-rolled-back erasure can
    /// never be reported as a completed Art.17 delete; the next decommission (or
    /// the FK cascade on a later parent delete) self-heals.
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

    /// Count agents whose licensing state has not been refreshed since
    /// `stale_before_secs` (epoch seconds), i.e. `last_seen <
    /// stale_before_secs` on `agent_license_state` — the roadmap C-10
    /// per-source staleness read the UCE module's evaluator consumes
    /// ("Unreported ≠ Unused" needs a checkable staleness signal). Mirrors
    /// the sibling's bounded posture: a SHORT lease acquire AND a per-
    /// statement `SET LOCAL statement_timeout` so a metrics-sweep caller can
    /// never stall behind a bloated-table scan. `std::nullopt` on a degrade
    /// (incl. the execution timeout) — callers hold the previous value, never
    /// publish a false zero.
    [[nodiscard]] std::optional<std::int64_t> count_stale_agents(std::int64_t stale_before_secs);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
