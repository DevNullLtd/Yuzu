#pragma once

/// @file certificate_read_types.hpp
/// Plain DTOs of the fleet certificate READ surface (slice-2 PR 2a-2b, ADR-0070 D12): the filter
/// set, the per-certificate page and the raw-value summary. Std headers only - no store, wire or
/// transport types - so the store (which fills them), the pure model (which parses and shapes
/// them), the abstract `CryptoApi` seam and every transport (REST, MCP, the dashboard fragment)
/// share ONE set of structs.
///
/// Facts only (ADR-0070 D10): nothing here labels a certificate good, bad, weak or at risk.
/// Timestamps are RFC 3339 UTC strings to the second, authored by the store from the stored
/// TIMESTAMPTZ; an unset optional is UNKNOWN (JSON null), distinct from a real empty value.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

// ── Bounds ───────────────────────────────────────────────────────────────────

inline constexpr int kCertPageDefault = 100;
inline constexpr int kCertPageMax = 500;
/// Locations listed per certificate; a certificate seen in more places sets `locations_cap`.
inline constexpr std::size_t kCertReadMaxLocations = 32;
/// SANs listed per certificate (the ingest cap is the same 64: `sans_cap` is the honest flag if
/// the two ever diverge).
inline constexpr std::size_t kCertReadMaxSans = 64;
/// Byte budget of one serialised page: past it the page stops at a whole certificate, sets
/// `byte_budget` and carries a `next_cursor`.
inline constexpr std::size_t kCertPageByteBudget = 4u * 1024 * 1024;
/// Groups per summary dimension, and the issuer group's own cap (ADR-0070: issuer_dn top 50).
inline constexpr std::size_t kCertSummaryGroupMax = 500;
inline constexpr std::size_t kCertSummaryIssuerMax = 50;
inline constexpr std::size_t kCertEdgesMax = 32;
inline constexpr std::size_t kCertFilterContainsMin = 3;
inline constexpr std::size_t kCertFilterContainsMax = 256;
inline constexpr std::size_t kCertCursorMaxBytes = 2048;

// ── The filter set ───────────────────────────────────────────────────────────

/// Every filter of the per-certificate read and the summary. Values are already validated and
/// normalised by `cert_read::parse_*` (hex lower/upper-cased to the stored case, dates
/// normalised to `YYYY-MM-DDTHH:MM:SSZ`, bounds checked); the store binds them, never splices.
struct CertReadFilter {
    std::optional<std::string> store;      ///< a store_id: has a location in it
    std::optional<std::string> scope;      ///< closed: "machine"
    std::optional<std::string> key_alg_oid, sig_alg_oid, ec_curve_oid;
    std::optional<std::string> not_after_before, not_after_after, not_before_after;
    std::optional<int> rsa_modulus_bits_lt, ec_order_bits_lt;
    std::optional<bool> is_ca, self_signed;
    std::optional<std::string> agent_id;
    std::optional<std::string> issuer_dn;          ///< exact RFC 4514 string
    std::optional<std::string> issuer_dn_contains; ///< literal, case-insensitive substring
    std::optional<std::string> subject_dn_contains; ///< only ever with is_ca == true
    std::optional<std::string> sha256;      ///< lowercase hex
    std::optional<std::string> spki_sha256; ///< lowercase hex
    std::optional<std::string> aki_key_id;  ///< UPPERCASE hex (the stored case)
};

struct CertQuery {
    CertReadFilter filter;
    std::string cursor; ///< opaque; "" = first page
    int limit{kCertPageDefault};
    /// The calling principal (the session username), set by the transport AFTER parsing, never
    /// from a request parameter. Keys the one-in-flight caller-priced read cap (CertPrincipalReadCap,
    /// crypto_read_gate.hpp); "" shares one slot with every other unresolved caller.
    std::string principal;
};

struct CertSummaryQuery {
    CertReadFilter filter;
    /// The caller's `not_after` histogram edges, ascending RFC 3339 UTC; empty = no histogram.
    std::vector<std::string> not_after_edges;
    /// As CertQuery::principal.
    std::string principal;
};

/// The keyset position of the last row served (ordered by (agent_id, sha256)).
struct CertReadAfter {
    std::string agent_id;
    std::string sha256;
};

// ── The per-certificate page ─────────────────────────────────────────────────

struct CertLocationRead {
    std::string store_id;
    std::string path;
    std::string store_status;                 ///< ok|absent|unreadable|constrained|not_observed
    std::optional<std::string> observed_at;   ///< the store's last ok/absent report
    std::string last_seen;
};

struct CertSanRead {
    std::string type;
    std::string value;
};

/// One (device, certificate).
struct CertReadRow {
    std::string agent_id;
    std::string hostname; ///< "" = unknown to the registry
    std::string sha256;
    std::optional<std::string> sha1, tbs_sha256;
    std::optional<std::string> serial;
    std::optional<std::string> subject_dn, issuer_dn;
    std::optional<std::string> not_before, not_after;
    std::optional<std::string> key_alg_oid;
    std::optional<int> rsa_modulus_bits;
    std::optional<std::string> ec_curve_oid;
    std::optional<int> ec_order_bits;
    std::optional<std::string> sig_alg_oid, pss_hash_oid, spki_sha256, ski, aki_key_id;
    std::optional<bool> is_ca;
    std::optional<int> path_len;
    std::optional<bool> self_signed;
    std::optional<std::string> key_usage; ///< comma-joined names as the agent reported them
    std::vector<std::string> ekus;
    std::vector<CertSanRead> sans;
    bool sans_truncated{false};
    std::optional<std::string> key_association, key_provider, key_exportable;
    std::vector<CertLocationRead> locations;
    bool locations_truncated{false};
    std::string last_seen; ///< the newest location last_seen
    std::string constrained_fields; ///< comma-joined tokens, '' when none
};

/// A store's status on one device of the page (so a kept row is never shown without it).
struct CertStoreRead {
    std::string agent_id;
    std::string store_id;
    std::string status;
    std::string reason;
    std::optional<std::string> observed_at;
    std::string status_at;
};

struct CertCoverage {
    std::int64_t devices_reporting{0}; ///< in-scope devices with a certificate_inventory report
    std::int64_t devices_included{0};  ///< distinct devices among this page's rows
    bool confined{false};
};

struct CertPage {
    std::vector<CertReadRow> rows;
    std::vector<CertStoreRead> stores;
    CertCoverage coverage;
    std::vector<std::string> blob_versions;
    bool has_more{false};    ///< rows exist past this page (set by the store)
    std::string next_cursor; ///< "" = the last page (set by the model)
    /// The cuts the model recorded: page_limit, byte_budget, locations_cap, sans_cap,
    /// constrained_store, constrained_certificate (design "Truncation"). Filled by the model.
    std::vector<std::string> truncated_parts;
    bool result_truncated{false};
};

// ── The raw-value summary ────────────────────────────────────────────────────

struct CertCounts {
    std::int64_t device_count{0};      ///< DISTINCT devices
    std::int64_t certificate_count{0}; ///< DISTINCT certificates (sha256)
};

struct CertKeyAlgGroup {
    std::string key_alg_oid;
    std::optional<int> rsa_modulus_bits, ec_order_bits;
    CertCounts counts;
};
struct CertSigAlgGroup {
    std::string sig_alg_oid;
    std::optional<std::string> pss_hash_oid;
    CertCounts counts;
};
struct CertCurveGroup {
    std::string ec_curve_oid;
    CertCounts counts;
};
struct CertIssuerGroup {
    std::string issuer_dn;
    CertCounts counts;
};
struct CertStoreGroup {
    std::string store_id;
    CertCounts counts;
};
/// Stores (not certificates) per status, over the in-scope devices.
struct CertStatusGroup {
    std::string status;
    std::int64_t store_count{0};
    std::int64_t device_count{0};
};
/// One `not_after` bucket over the caller's edges: [from, to), `from` null = unbounded below,
/// `to` null = unbounded above. A certificate with no known `not_after` is in the `unknown`
/// bucket (both null, `unknown` true).
struct CertHistogramBucket {
    std::optional<std::string> from, to;
    bool unknown{false};
    CertCounts counts;
};

struct CertSummary {
    CertCounts totals;
    std::vector<CertKeyAlgGroup> key_algorithms;
    std::vector<CertSigAlgGroup> signature_algorithms;
    std::vector<CertCurveGroup> ec_curves;
    std::vector<CertIssuerGroup> issuers; ///< top kCertSummaryIssuerMax by device count
    std::vector<CertStoreGroup> stores;
    std::vector<CertStatusGroup> store_statuses;
    std::vector<CertHistogramBucket> not_after_histogram;
    CertCoverage coverage;
    std::vector<std::string> blob_versions;
    std::vector<std::string> truncated_parts; ///< row_ceiling when a group hit its cap
    bool result_truncated{false};
};

// ── Fleet gauge rollup (cert_inventory.fleet_store_status) ───────────────────

/// Stores per {OS bucket, status}, folded in SQL (CertificateInventoryStore::fleet_status_counts).
using CertFleetStatusCounts = std::map<std::pair<std::string, std::string>, std::int64_t>;

} // namespace yuzu::server
