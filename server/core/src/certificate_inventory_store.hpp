#pragma once

/// @file certificate_inventory_store.hpp
/// Born-on-Postgres fleet certificate inventory store (slice-2 PR 2a-2a, schema
/// `cert_inventory`, ADR-0070 D12, ADR-0016 §5, ADR-0006/0012): the server half of the
/// `certificate_inventory` daily-sync source. Design:
/// `docs/crypto-slice2-certificate-design.md`, "Server: store, ingest and lifecycle".
///
/// SHAPE. Seven tables, every one leading its key with `agent_id` (decommission and
/// confinement): `agent_state` (hash-skip state), `store_state` (one row per store per
/// device: status, reason, `observed_at`, `status_at`), `cert_location` (where a
/// certificate was seen), `cert_fact` (one row per (device,
/// certificate): the X.509 facts), and the `cert_san` / `cert_eku` / `cert_cdp` children.
/// A `cert_fact` row exists while at least one `cert_location` row references it; the
/// ingest transaction deletes the orphans.
///
/// CLOCK. Every `*_at` / `*_seen` column is a TIMESTAMPTZ authored by the DATABASE clock
/// (never the replica's, never the agent's: #1685, ADR-0016 clock-skew rule). One value is
/// read per transaction, after the per-agent lock, and is forced strictly above the agent's
/// previous `last_full_at`, so a report that took the lock second never stamps an earlier
/// time than the one that took it first. Certificate validity columns come from the
/// certificate itself and are stored unclamped.
///
/// SCHEMA LINT. No column is named after a D13 rule id or window field, or
/// `days_remaining` (ADR-0070 D13 "Mechanical checks"). `certificate_inventory_migrations()`
/// is exported so `test_certificate_inventory_store.cpp` can walk the migration array.
///
/// PER-AGENT SERIALISATION. Ingest (full and hash-skip) and `delete_agent` take the SAME
/// `pg_advisory_xact_lock(hashtextextended('cert_inventory:' || agent_id, 0))` first, so a
/// decommission cannot interleave with an ingest's transaction. The retention
/// prune (PR 2a-2d) must take it too.
///
/// DECOMMISSION. `delete_agent` erases every table's rows for the agent in one transaction
/// under the per-agent lock. A still-running agent's next report re-creates its rows; keeping it
/// out is the decommission tombstone, which is a separate, later change.
///
/// FAILURE POSTURE (ADR-0012 §1). Ingest is fail-soft (a transient outage returns `kError`; the
/// seam nacks and the agent resends next cycle). `delete_agent` returns true only when the
/// transaction committed, so the decommission cascade records a rolled-back erasure as Failed.
/// This PR ships no read surface; a store that failed to open is visible on `/readyz`.
///
/// Registered in the agent-decommission cascade (`AgentDecommissionStores::certificate_inventory`,
/// the eighth store).

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
struct PgMigration;
} // namespace yuzu::server::pg

namespace yuzu::server {

/// The store's migration array (schema `cert_inventory`), for the D13 schema lint.
[[nodiscard]] const std::vector<pg::PgMigration>& certificate_inventory_migrations();

/// Closed store-status vocabulary (design "Store status"). `not_observed` is server-side only.
namespace cert_status {
inline constexpr std::string_view kOk = "ok";
inline constexpr std::string_view kAbsent = "absent";
inline constexpr std::string_view kUnreadable = "unreadable";
inline constexpr std::string_view kConstrained = "constrained";
inline constexpr std::string_view kNotObserved = "not_observed";
} // namespace cert_status

/// One SAN entry. `type` is one of dns, ip, rfc822, uri, upn, dirname, other.
struct CertSan {
    std::string type;
    std::string value;
};

/// The facts of one certificate. An unset optional is UNKNOWN (stored NULL); a set empty string
/// is a real empty value. `der_base64` is the optional whole-DER; this PR stores it and does not
/// parse it (`server_parsed` stays false).
struct CertFactRow {
    std::string sha256; ///< lowercase hex, the row identity
    std::optional<std::string> sha1, tbs_sha256;
    std::optional<int> version;
    std::optional<std::string> serial; ///< canonical uppercase hex
    std::optional<bool> serial_negative;
    std::optional<std::string> subject_dn, issuer_dn, subject_name_sha256, issuer_name_sha256;
    std::optional<std::string> not_before, not_after; ///< RFC 3339 UTC, whole seconds
    std::optional<std::string> key_alg_oid;
    std::optional<int> rsa_modulus_bits;
    std::optional<std::string> ec_curve_oid;
    std::optional<int> ec_order_bits;
    std::optional<std::string> sig_alg_oid, pss_hash_oid, pss_mgf1_hash_oid, spki_sha256, ski,
        aki_key_id;
    std::optional<bool> is_ca;
    std::optional<int> path_len;
    std::optional<std::string> key_usage;
    std::optional<bool> self_signed;
    std::optional<std::string> key_association, key_provider, key_exportable, der_omitted;
    std::optional<std::string> der_base64;
    std::string constrained_fields; ///< comma-joined tokens, '' when none
    std::vector<CertSan> sans;
    std::vector<std::string> ekus;
    std::vector<std::string> cdps;
};

/// One place a certificate was seen. `path` is '' for a store without file paths.
struct CertLocationRow {
    std::string store_id;
    std::string path;
    std::string sha256;
};

/// One `store|` record after parsing. `status` is never `not_observed` (agent never sends it).
struct CertStoreReport {
    std::string store_id;
    std::string scope; ///< 'machine' only in slice 2
    std::string status;
    std::string reason;
};

/// Everything one full report asks the store to apply. `facts` is keyed by `sha256`; a fact is
/// only written when one of its locations lands in an `ok` or `constrained` store.
struct CertReportData {
    std::string blob_version;
    std::vector<CertStoreReport> stores;
    std::vector<CertFactRow> facts;
    std::vector<CertLocationRow> locations;
};

/// What one ingest call did.
enum class CertIngestOutcome {
    kStored,         ///< full report applied
    kTouched,        ///< hash-skip matched; freshness advanced
    kNeedFull,       ///< cold cache or hash mismatch: the agent must resend in full
    kError,          ///< pool/SQL failure (transient)
};

/// Why a kNeedFull. Meaningful only for kNeedFull.
enum class CertNeedFullCause { kNone, kCold, kHashMismatch };

struct CertIngestResult {
    CertIngestOutcome outcome{CertIngestOutcome::kError};
    CertNeedFullCause need_full_cause{CertNeedFullCause::kNone};
};

class CertificateInventoryStore {
public:
    /// Borrows the shared pool and runs the `cert_inventory` migration on a pinned lease.
    /// `is_open()` is false if the lease was empty or the migration failed (the server fails
    /// closed before reaching here).
    explicit CertificateInventoryStore(pg::PgPool& pool);

    CertificateInventoryStore(const CertificateInventoryStore&) = delete;
    CertificateInventoryStore& operator=(const CertificateInventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Apply one full report for `agent_id` in ONE transaction under the per-agent lock.
    /// `content_hash` is the SHA-256 of the raw received bytes, recomputed by the seam. Per-store
    /// rules: ok replaces, absent removes, constrained upserts and keeps, unreadable is untouched,
    /// a stored store missing from the report becomes `not_observed`.
    [[nodiscard]] CertIngestResult ingest_full(std::string_view agent_id,
                                               const CertReportData& report,
                                               std::string_view content_hash);

    /// Hash-skip leg: compare `claimed_hash` to the stored hash under the lock. On a match,
    /// advance `agent_state.last_seen`, every carried store's `status_at`, `observed_at` for
    /// `ok`/`absent` stores only, and `cert_location.last_seen` only for the locations the last
    /// full report carried. A mismatch or a cold cache is kNeedFull.
    [[nodiscard]] CertIngestResult ingest_touch(std::string_view agent_id,
                                                std::string_view claimed_hash);

    /// Erase every table's rows for the agent in ONE transaction under the per-agent lock. Empty id -> false without touching PG. True iff committed.
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

    /// Row counts for one agent, for tests and diagnostics: {agent_state, store_state,
    /// cert_location, cert_fact, cert_san, cert_eku, cert_cdp}. nullopt on a failure.
    struct RowCounts {
        std::int64_t agent_state{0}, store_state{0}, cert_location{0}, cert_fact{0}, cert_san{0},
            cert_eku{0}, cert_cdp{0};
    };
    [[nodiscard]] std::optional<RowCounts> row_counts(std::string_view agent_id);

    /// TEST SEAMS. Run inside the transaction (null in production): `after_lock` right after an
    /// ingest has taken the per-agent lock, `after_erase` in `delete_agent` after the deletes and
    /// before the commit. They let a test start a racing call at exactly that point.
    void set_test_hook_after_lock(std::function<void()> hook) {
        test_hook_after_lock_ = std::move(hook);
    }
    void set_test_hook_after_erase(std::function<void()> hook) {
        test_hook_after_erase_ = std::move(hook);
    }

private:
    pg::PgPool& pool_;
    bool open_{false};
    std::function<void()> test_hook_after_lock_;
    std::function<void()> test_hook_after_erase_;
};

} // namespace yuzu::server
