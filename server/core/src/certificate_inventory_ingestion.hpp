#pragma once

/// @file certificate_inventory_ingestion.hpp
/// Shared `certificate_inventory` ingest seam (slice-2 PR 2a-2a, ADR-0016 §5, ADR-0070 D12;
/// design `docs/crypto-slice2-certificate-design.md`, "The daily-sync source" and "Ingest").
/// BOTH server entry points, the direct `AgentServiceImpl::ReportInventory` and the gateway
/// `GatewayUpstreamServiceImpl::ProxyInventory`, call `ingest_certificate_inventory_report`, so
/// the two paths persist identically. The gateway's generic-blob loop skips this source
/// (`typed_inventory_sources.hpp`), so nothing lands in the generic `InventoryStore`.
///
/// The report is untrusted external input. This seam applies the caps, validates UTF-8, parses
/// the blob with its own stateful escape-aware splitter, recomputes the raw-byte hash and only
/// then touches the store. A record over a cap is REFUSED, never truncated.
///
/// BLOB GRAMMAR (version 1). Records are LF-separated lines, fields `|`-separated. Every field is
/// framed the same way and fully reversibly: `\\` is a backslash, `\|` a pipe, `\n` and `\r` LF
/// and CR; any other escape, or a trailing unpaired `\`, is a parse error. The scanner walks
/// left to right consuming each `\` with the byte after it (it is NOT `find_unescaped_pipe`,
/// which misreads `\\|`). Records:
///
///   ver|<major>[.<minor>]
///   store|<store_id>|<scope>|<status>|<reason>|<cert_count or ?>
///   cert|<34 positional fields, below>
///   loc|<sha256>|<store_id>|<path>
///   san|<sha256>|<type>|<value>
///   eku|<sha256>|<oid>
///   cdp|<sha256>|<uri>
///   der|<sha256>|<base64>
///
/// A certificate GROUP is a `cert|` and the `loc|`/`san|`/`eku|`/`cdp|`/`der|` records after it.
/// The stores a group belongs to are the stores its `loc|` records name; a certificate in two
/// stores is emitted as two groups (the facts are identical and the first wins; the locations
/// add up). `cert|` positional fields, in order (the design leaves the tail as `...`, so this
/// list IS the contract the collector PR must write):
///
///   0 sha256, 1 sha1, 2 tbs_sha256, 3 version, 4 serial, 5 subject_dn, 6 issuer_dn,
///   7 subject_name_sha256, 8 issuer_name_sha256, 9 not_before, 10 not_after, 11 key_alg_oid,
///   12 rsa_modulus_bits, 13 ec_curve_oid, 14 ec_order_bits, 15 sig_alg_oid, 16 pss_hash_oid,
///   17 pss_mgf1_hash_oid, 18 spki_sha256, 19 ski, 20 aki_key_id, 21 is_ca, 22 path_len,
///   23 key_usage, 24 self_signed, 25 serial_negative, 26 key_association, 27 key_provider,
///   28 key_exportable, 29 der_omitted, 30 constrained_fields (comma-joined tokens),
///   31 sans=<n>, 32 ekus=<n>, 33 cdps=<n>
///
/// Fields 0-10 are mandatory; a record without the rest is an older agent's and the missing
/// fields read UNKNOWN. A field sent as `?` is UNKNOWN (NULL); an empty text field is a real empty
/// value; an empty integer, boolean or date field is not applicable and also stored NULL. The
/// three counts, when present, must equal the records that follow.
///
/// PARSE ERRORS. A record-level error (a bad field, a count mismatch, a wrong hash, an over-cap
/// record) refuses only that record; the stores the group's `loc|` records name read
/// `constrained`, reason `parse_error`, and keep their rows. A record that cannot be tied to a
/// store (no `loc|`, an unknown store id, a stray child) makes every `ok`/`absent`/`constrained`
/// store of the report read `constrained`/`parse_error`. Either way the blob is ACKED and stored,
/// so the agent neither resends it for ever nor hides the defect (every hash-skip replay of the
/// same bytes keeps it visibly constrained). An unparseable header (`ver|`, `store|`) or an
/// unknown major version, an over-cap blob, more than 64 stores or 10,000 distinct certificates
/// NACKs the blob (need_full) and writes nothing.
///
/// RAW-BYTE HASH. The stored hash is the SHA-256 of the received blob bytes, recomputed here;
/// the agent's claim is only compared on the hash-only leg.
///
/// DECOMMISSION. The store's per-agent lock and tombstone make a decommissioned agent's report
/// acknowledged, written nowhere, and counted (`reason=decommissioned`); this seam never nacks
/// a tombstoned agent (that would loop).
///
/// METRIC. `yuzu_server_cert_inventory_ingest_total{result,reason}`; the (result, reason) pairs
/// are the closed set in `cert_ingest_metric::kPairs`.

#include "certificate_inventory_store.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent::v1 {
class InventoryReport;
class InventoryAck;
} // namespace yuzu::agent::v1

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// The wire key of the source.
inline constexpr std::string_view kCertificateInventorySource = "certificate_inventory";

// Caps. MUST match the collector (comment-coordinated: the repo has no shared agent/server
// constants). A one-sided cap makes the agent send and the server drop in a tight loop.
inline constexpr std::size_t kCertMaxBlobBytes = 3u * 1024 * 1024;
inline constexpr std::size_t kCertMaxStores = 64;
inline constexpr std::size_t kCertMaxDistinctCerts = 10000;
inline constexpr std::size_t kCertMaxCertsPerStore = 2000;
inline constexpr std::size_t kCertMaxDerPerBlob = 1024u * 1024;
inline constexpr std::size_t kCertMaxDerBytes = 16u * 1024;
inline constexpr std::size_t kCertMaxSans = 64;
inline constexpr std::size_t kCertMaxSanBytes = 256;
inline constexpr std::size_t kCertMaxEkus = 32;
inline constexpr std::size_t kCertMaxCdps = 8;
inline constexpr std::size_t kCertMaxCdpBytes = 512;
inline constexpr std::size_t kCertMaxDnBytes = 1024;

/// Why a whole blob was nacked.
enum class CertBlobNack { kNone, kBlobTooLarge, kUnknownVersion, kBadHeader, kOverCap };

/// Parse output of one blob.
struct CertBlobParse {
    CertBlobNack nack{CertBlobNack::kNone};
    CertReportData data;
    bool any_parse_error{false}; ///< at least one record refused, or the report fell back
    bool any_over_cap{false};    ///< at least one refusal was a cap
    bool utf8_replaced{false};   ///< at least one field had invalid UTF-8 replaced
    std::size_t refused_records{0};
};

/// Parse the blob. Pure: no I/O. Exposed for tests.
[[nodiscard]] CertBlobParse parse_certificate_inventory_blob(std::string_view blob);

/// SHA-256 hex (lowercase) over the raw bytes. Empty only on digest failure.
[[nodiscard]] std::string certificate_inventory_raw_hash(std::string_view blob);

/// Ingest the source of `report` for `agent_id` into `store`; appends to `ack.need_full` when the
/// server needs a full resend. Does NOT set `ack.received`. No-op when `agent_id` is empty or the
/// source is absent from the report. `metrics` (nullable) receives the ingest counter.
void ingest_certificate_inventory_report(CertificateInventoryStore& store,
                                         const std::string& agent_id,
                                         const ::yuzu::agent::v1::InventoryReport& report,
                                         ::yuzu::agent::v1::InventoryAck& ack,
                                         ::yuzu::MetricsRegistry* metrics = nullptr);

namespace cert_ingest_metric {
inline constexpr std::string_view kName = "yuzu_server_cert_inventory_ingest_total";
/// The closed (result, reason) set. Every increment is one of these pairs.
inline constexpr std::array<std::pair<std::string_view, std::string_view>, 15> kPairs = {{
    {"stored", "none"},
    {"stored", "parse_error"},
    {"stored", "over_cap"},
    {"stored", "utf8_replaced"},
    {"touched", "none"},
    {"discarded", "decommissioned"},
    {"need_full", "cold"},
    {"need_full", "hash_mismatch"},
    {"nacked", "blob_too_large"},
    {"nacked", "unknown_version"},
    {"nacked", "bad_header"},
    {"nacked", "over_cap"},
    {"nacked", "too_many_sources"},
    {"error", "store_error"},
    {"error", "digest_error"},
}};
/// Register the HELP text and zero-seed every pair, so the series exist on an idle server.
void register_metrics(::yuzu::MetricsRegistry& metrics);
} // namespace cert_ingest_metric

} // namespace yuzu::server
