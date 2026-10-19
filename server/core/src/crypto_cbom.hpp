#pragma once

/// @file crypto_cbom.hpp
/// The CycloneDX 1.7 CBOM export of the `/crypto` crypto-library-presence data (slice 1's
/// summary, re-shaped; no new collection, store or agent change). One pure shaper shared by
/// REST (`GET /api/v1/crypto/cbom`) and MCP (`export_crypto_cbom`) so the two cannot drift.
///
/// MECHANISM, not interpretation (ADR-1005 D2, decision #6051): every component is a
/// `"type":"library"` - an installed package matched by NAME - never a `cryptographic-asset`,
/// and the document carries NO `cryptoProperties`, strength, quantum-security-level or
/// good/bad field. Classification is engine territory behind the ADR-0032 interlock.
///
/// Shape (CI validates real output against the vendored `bom-1.7.schema.json`):
///  - one component per (family, version, ecosystem) bucket of the summary; the `version` key
///    is omitted for a bucket with no version (never an empty string);
///  - `bom-ref` = `yuzu-crypto-lib/<family>/<version>/<ecosystem>`, each segment percent-
///    encoded outside [A-Za-z0-9._~+-]; a collision (cannot occur from the store, which groups
///    by that triple) gets a `#<n>` suffix so refs stay unique;
///  - everything Yuzu-specific rides in `properties` under the `yuzu:crypto:` namespace.
///
/// A cut is never silent (principle 2): every component carries `yuzu:crypto:versions_truncated`
/// (true/false) for its family and `yuzu:crypto:package_names_truncated` (true/false) for its
/// own bucket (more matching package names exist than the store returns per bucket), and
/// metadata lists `yuzu:crypto:truncated_families` (the ids of every family whose version list
/// was cut - including one whose buckets were ALL dropped and which therefore has no component
/// at all) next to `yuzu:crypto:result_truncated`.
///
/// Scope and completeness are machine-readable: `yuzu:crypto:scope` is `fleet` (the caller's
/// visibility was unfiltered) or `confined` (a management-group / service-scope confined
/// caller: the BOM covers only its visible devices), and the document always carries
/// `"compositions":[{"aggregate":"incomplete"}]` - a name match cannot see statically linked,
/// vendored or OS-bundled copies, so the inventory is incomplete by nature.
///
/// `serialNumber` is a random (version 4) UUID URN from the process CSPRNG, minted per export:
/// CycloneDX recommends one unique per BOM even when the content is unchanged. The identity
/// (serial, timestamp, tool version) is INJECTED into the pure shaper so tests and the golden
/// fixtures are deterministic.
///
/// Purl is deliberately NOT emitted: the inventory records a package name, version and an
/// ecosystem string (deb, rpm, brew, windows, ...) but not the distro/namespace a correct purl
/// needs, and a wrong purl is worse than none.

#include "crypto_types.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::crypto_cbom {

inline constexpr std::string_view kContentType = "application/vnd.cyclonedx+json; version=1.7";
inline constexpr std::string_view kSpecVersion = "1.7";

/// Per-export identity, injected into the shaper.
struct CbomIdentity {
    std::string serial_number; ///< `urn:uuid:<v4>`
    std::string timestamp;     ///< RFC 3339, UTC, `Z` suffix
    std::string tool_version;  ///< Yuzu's version string
};

/// The filters the export was produced under, echoed in metadata so a filtered BOM is never
/// mistaken for the whole inventory.
struct CbomOptions {
    CryptoSummaryQuery filters;
    /// The caller's visibility was filtered (management-group / service-scope confinement):
    /// emitted as `yuzu:crypto:scope` = `confined`, else `fleet`. The same truth the audit
    /// rows record as `scope=`.
    bool confined{false};
    /// false only when the access-audit row failed to persist: surfaced as
    /// `yuzu:crypto:audit_persisted` = false (the data is still served, set-and-proceed).
    bool audit_persisted{true};
};

/// `urn:uuid:` + the canonical lowercase form of 16 bytes with the version-4 / RFC 4122
/// variant bits forced.
[[nodiscard]] std::string uuid_urn_v4(std::array<std::uint8_t, 16> bytes);

/// RFC 3339 UTC (`2026-10-18T21:46:00Z`); an unrepresentable epoch yields the epoch itself.
[[nodiscard]] std::string rfc3339_utc(std::int64_t epoch_seconds);

/// A fresh identity (CSPRNG serial, current time); nullopt when the CSPRNG failed - the caller
/// answers a retryable 503, never a BOM without a serial.
[[nodiscard]] std::optional<CbomIdentity> make_identity(std::string_view tool_version);

/// The extra audit-detail keys of a successful export, appended to `crypto_library::audit_detail`
/// at the CBOM call sites only (the sibling verbs' detail is unchanged): ` serial=<urn:uuid:...>
/// [ecosystem=<filter>] components=<n>`, the `ecosystem` key present only when that filter was
/// given. Ties the audit row to the exact artefact handed out.
[[nodiscard]] std::string audit_evidence(const CbomIdentity& id, const CryptoSummaryQuery& filters,
                                         std::size_t components);

/// Flags an already-built document as served without a persisted audit row: appends
/// `yuzu:crypto:audit_persisted` = false to `metadata.properties`, giving the same document
/// `cbom_json` builds with `audit_persisted = false`, without building it twice. Call at most
/// once per document (a second call appends the property again).
void mark_audit_not_persisted(nlohmann::json& bom);

/// The CycloneDX 1.7 document. `summary` is the output of `CryptoApi::library_summary`
/// (already normalised by `finish_summary`).
[[nodiscard]] nlohmann::json cbom_json(const CryptoSummary& summary, const CbomIdentity& id,
                                       const CbomOptions& opts = {});

/// MCP's STRICT argument check: `arguments` must be a JSON object, keys limited to `family`
/// and `ecosystem`, each a string within the model's bounds, `family` a known id. nullopt =
/// acceptable; otherwise the kInvalidParams message.
[[nodiscard]] std::optional<std::string> strict_cbom_args_error(const nlohmann::json& args);

} // namespace yuzu::server::crypto_cbom
