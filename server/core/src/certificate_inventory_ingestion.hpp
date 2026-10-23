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
/// BLOB GRAMMAR (version 1). THE WRITER IS THE CANONICAL CONTRACT: the agent's
/// `agents/plugins/certificates/src/certificates_inventory_blob.hpp` (`render_blob`, pinned
/// byte-for-byte by its golden test; this seam's `test_certificate_inventory.cpp` parses a
/// golden of the same shape). This parser follows it; change the writer first.
///
/// Records are LF-separated lines, fields `|`-separated. Every field is framed the same way and
/// fully reversibly: `\\` is a backslash, `\|` a pipe, `\n` and `\r` LF and CR; any other escape,
/// or a trailing unpaired `\`, is a parse error. The scanner walks left to right consuming each
/// `\` with the byte after it (it is NOT `find_unescaped_pipe`, which misreads `\\|`). Records:
///
///   ver|<major>[.<minor>]
///   store|<store_id>|<scope>|<status>|<reason>|<cert_count or ?>     all stores first, sorted
///   cert|<33 positional fields, below>                               then one group per store
///   loc|<sha256>|<store_id>|<path>
///   san|<sha256>|<type>|<value>
///   eku|<sha256>|<oid>
///   cdp|<sha256>|<uri>
///   der|<sha256>|<base64>                 once, in the first group that carries the certificate
///
/// A certificate GROUP is a `cert|` and the `loc|`/`san|`/`eku|`/`cdp|`/`der|` records after it.
/// The stores a group belongs to are the stores its `loc|` records name; a certificate in two
/// stores repeats its `cert|` in each group (the facts are identical and the first wins; the
/// locations add up). A self-signed certificate carries der_omitted=self_signed and no `der|`.
/// `cert|` positional fields, in order (the 33 after the kind):
///
///   0 sha256, 1 sha1, 2 tbs_sha256, 3 version, 4 serial, 5 subject_dn, 6 issuer_dn,
///   7 subject_name_sha256, 8 issuer_name_sha256, 9 not_before, 10 not_after, 11 key_alg_oid,
///   12 rsa_modulus_bits, 13 ec_curve_oid, 14 ec_order_bits, 15 sig_alg_oid, 16 pss_hash_oid,
///   17 pss_mgf1_hash_oid, 18 spki_sha256, 19 ski, 20 aki_key_id, 21 is_ca, 22 path_len,
///   23 key_usage, 24 self_signed, 25 key_association, 26 key_provider, 27 key_exportable,
///   28 sans=<n>, 29 ekus=<n>, 30 cdps=<n>, 31 der_omitted (empty|self_signed|oversize|budget|?),
///   32 flags (comma-joined: serial_negative, sans_truncated, ekus_truncated,
///   crl_dps_truncated, subject_dn_truncated, issuer_dn_truncated)
///
/// Fields 0-10 are mandatory; a record without the rest is an older agent's and the missing
/// fields read UNKNOWN. A field sent as `?` is UNKNOWN (NULL); an empty text field is a real empty
/// value; an empty integer, boolean or date field is not applicable and also stored NULL.
/// Booleans are `1`/`0`. The three counts, when present, must equal the records that follow.
/// `flags` is kept verbatim in `cert_fact.constrained_fields` (with any `utf8_replaced:<field>`
/// marks this seam adds); `serial_negative` is also its own column.
///
/// HEX CASE is normalised on ingest so filters compare case-insensitively: digests (sha256,
/// sha1, tbs_sha256, the two name digests, spki_sha256) are stored LOWERCASE; serial, ski and aki_key_id are
/// stored UPPERCASE.
///
/// STORE REASONS are stored verbatim (sanitised, 256 bytes), never used as a metric label, so
/// the tokens the writer emits (`not_collected`, `cert_malformed`, `mountinfo_unreadable`,
/// `permission_denied`, `deadline`, `row_cap`, `byte_cap`, `open_failed:<errno>`, ...) need no
/// server-side registry.
///
/// PARSE ERRORS. A record-level error (a bad field, a count mismatch, a wrong hash, an over-cap
/// record) refuses only that record; the stores the group's `loc|` records name read
/// `constrained`, reason `parse_error` (`row_cap` when the refusal was a size cap), and keep their
/// rows. A record that cannot be tied to a
/// store (no `loc|`, an unknown store id, a stray child) makes every `ok`/`absent`/`constrained`
/// store of the report read `constrained`/`parse_error`. Either way the blob is ACKED and stored,
/// so the agent neither resends it for ever nor hides the defect (every hash-skip replay of the
/// same bytes keeps it visibly constrained). An unparseable header (`ver|`, `store|`) or an
/// unknown major version, an over-cap blob, more than 64 stores or 10,000 distinct certificates
/// is REJECTED: acknowledged without need_full (the same bytes would be refused again, so
/// asking for them again would loop), counted result="rejected", and nothing is written.
///
/// BUSY. Ingest TRIES the per-agent advisory lock; if another report for the agent holds it, the
/// report is answered result="deferred" reason="agent_busy" and nothing is written. A full report
/// asks for need_full (resend); a hash-only report does not (it simply retries next cycle).
/// A store error on the hash-only leg likewise does not ask for a full resend.
///
/// RAW-BYTE HASH. The stored hash is the SHA-256 of the received blob bytes, recomputed here;
/// the agent's claim is only compared on the hash-only leg.
///
/// DECOMMISSION. The store's `delete_agent` erases the device's rows under the same per-agent
/// lock this seam's ingest takes, so a racing report and erase end as one whole state.
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
    bool der_hash_mismatch{false}; ///< at least one DER did not hash to its certificate; dropped
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
inline constexpr std::array<std::pair<std::string_view, std::string_view>, 17> kPairs = {{
    {"stored", "none"},
    {"stored", "parse_error"},
    {"stored", "over_cap"},
    {"stored", "der_hash_mismatch"},
    {"stored", "utf8_replaced"},
    {"touched", "none"},
    {"need_full", "cold"},
    {"need_full", "hash_mismatch"},
    {"need_full", "bad_claim"},
    {"rejected", "blob_too_large"},
    {"rejected", "unknown_version"},
    {"rejected", "bad_header"},
    {"rejected", "over_cap"},
    {"rejected", "too_many_sources"},
    {"deferred", "agent_busy"},
    {"error", "store_error"},
    {"error", "digest_error"},
}};
/// Register the HELP text and zero-seed every pair, so the series exist on an idle server.
void register_metrics(::yuzu::MetricsRegistry& metrics);
} // namespace cert_ingest_metric

} // namespace yuzu::server
