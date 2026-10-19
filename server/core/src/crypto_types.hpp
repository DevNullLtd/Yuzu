#pragma once

/// @file crypto_types.hpp
/// Plain DTOs of the `/crypto` crypto-library-presence surface (slice 1). No store types, no
/// transport types - the pure model (`crypto_library_model.hpp`), the abstract seam
/// (`crypto_api.hpp`) and every transport (REST, MCP, the dashboard fragment) share these, so
/// the wire shapes are shaped from ONE set of structs.
///
/// Presence and versions only. Nothing here labels a library or version good, bad, current or
/// out of date: that is interpretation (ADR-1005 D2, engine territory behind the ADR-0032
/// interlock), not mechanism.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Filters of the family summary. Both optional; `family` is a curated-table id.
struct CryptoSummaryQuery {
    std::optional<std::string> family;
    std::optional<std::string> ecosystem;
};

/// Filters of one family's device drill. `family` is required (a curated-table id); `version`
/// nullopt = any version, present (including "") = that exact version. `cursor` is the opaque
/// token of the previous page, bound to the filter set.
struct CryptoDevicesQuery {
    std::string family;
    std::optional<std::string> version;
    std::optional<std::string> ecosystem;
    std::string cursor;
    int limit{100};
};

/// One (version, ecosystem) bucket of a family.
struct CryptoVersionRow {
    std::string version;
    std::string ecosystem;
    std::int64_t device_count{0};
    std::vector<std::string> package_names;
    /// More matching package names exist in this bucket than the store returns per bucket
    /// (kNamePatternNamesPerRow, 8): `package_names` is a cut list.
    bool package_names_truncated{false};
};

struct CryptoFamilyRow {
    std::string id;
    std::string display;
    std::int64_t device_count{0}; ///< DISTINCT devices carrying any package of the family
    std::vector<CryptoVersionRow> versions;
    bool versions_truncated{false};
};

struct CryptoCoverage {
    std::int64_t devices_reporting_inventory{0}; ///< in-scope devices with an installed_software report
    std::int64_t devices_with_crypto_library{0}; ///< DISTINCT in-scope devices matching any family
};

struct CryptoSummary {
    std::vector<CryptoFamilyRow> families; ///< zero-device families omitted
    CryptoCoverage coverage;
    bool result_truncated{false}; ///< the store row cap dropped version rows
    /// Where the package NAMES came from: true = the hourly catalogue rollup (fresh), then
    /// `names_as_of` is its refresh time (epoch seconds); false = read live from the inventory
    /// (catalogue never built or stale), `names_as_of` is 0 and the names are as of the read.
    /// Counts and versions for listed names are live either way.
    bool names_from_catalogue{false};
    std::int64_t names_as_of{0};
};

/// Why a degraded read could not be answered: a closed set so every transport words the 503
/// and the failure-audit row identically. kStoreDegraded = the inventory read failed (pool,
/// query, bound, store not open); kCapacity = the per-process admission bound refused it before
/// any store call. Meaningless (kNone) on a refused request. kAccessCheck = the access gate
/// itself degraded (it answered 503: the RBAC, management-group or tag store could not be
/// read); it is
/// rendered by the dashboard fragments only (review #6109) and no seam ever returns it - on REST
/// and MCP the gate writes its own envelope.
enum class CryptoReadCause { kNone, kStoreDegraded, kCapacity, kAccessCheck };

struct CryptoDeviceRow {
    std::string agent_id;
    std::string hostname; ///< "" = unknown to the registry
    std::string package_name;
    std::string version;
    std::string release;
    std::string ecosystem;
    std::string kind;
};

struct CryptoDevicesPage {
    std::string family;
    std::optional<std::string> version;
    std::optional<std::string> ecosystem; ///< the exact-ecosystem filter echoed (nullopt = any)
    bool names_from_catalogue{false};     ///< as CryptoSummary::names_from_catalogue
    std::int64_t names_as_of{0};          ///< as CryptoSummary::names_as_of
    std::vector<CryptoDeviceRow> devices;
    std::string next_cursor; ///< "" = last page
};


// ── Dashboard widgets: Yuzu-issued certificates (ADR-0070 D6/D13) ───────────
//
// Yuzu's OWN internal-CA certificates only (CaStore); fleet certificates are never read from
// there (D6). Every count is computed at read time against `as_of` - Postgres `now()` read in
// the same statement as the comparisons (ADR-0070 R4), or a caller-pinned instant - and carries
// the window it applies (D13 conditions 1-3): nothing here is a stored verdict, and nothing
// labels a certificate good, bad or at risk. Expiry follows RFC 5280 (valid THROUGH notAfter,
// inclusive): the one definition is crypto_widgets::unexpired_at / expiring_within /
// expired_within.

/// Which certificate set a Yuzu-issued list selects. `days` (kExpiring/kExpired/kRevoked/
/// kIssued) must be one of the closed window set in crypto_widget_catalogue.hpp; `week_start`
/// (kIssuedWeek/kRevokedWeek) is a Monday 00:00 UTC, epoch seconds.
///   kActive      status active AND issued_at <= as_of <= not_after
///   kExpiring    status active AND as_of <= not_after <= as_of + days
///   kExpired     status active AND as_of - days <= not_after < as_of (a revoked certificate
///                is counted in the revoked windows only)
///   kRevoked     as_of - days < revoked_at <= as_of
///   kIssued      as_of - days < issued_at <= as_of, unpublished revocations excluded
///   kIssuedWeek  week_start <= issued_at < week_start + 7 days, issued_at <= as_of,
///                unpublished revocations excluded
///   kRevokedWeek week_start <= revoked_at < week_start + 7 days, revoked_at <= as_of
enum class CaCertKind { kActive, kExpiring, kExpired, kRevoked, kIssued, kIssuedWeek, kRevokedWeek };

/// The three disjoint buckets every Yuzu-CA revocation falls in (ADR-0070 D13), decided by the
/// revocation reason exactly as recorded: `superseded` and `unpublished` are the CA's own
/// bookkeeping markers (never a compromise); `other` is any other reason, an operator reason
/// that collided with a marker included. Never labelled "security".
enum class RevokedBucket { kSuperseded, kUnpublished, kOther };

struct CaCertQuery {
    CaCertKind kind{CaCertKind::kActive};
    int days{0};
    std::int64_t week_start{0};
    /// kRevoked / kRevokedWeek only: one bucket (nullopt = all three).
    std::optional<RevokedBucket> bucket;
    /// The instant to compare against: nullopt = Postgres `now()` at read time; a value pins the
    /// read (a Load-more page passes back the as_of of the page before it, so a walk is one
    /// snapshot and its total equals the count that led to it).
    std::optional<std::int64_t> as_of;
    int limit{100};
    int offset{0};
};

/// One Yuzu-issued certificate as the list shows it: raw facts only (no PEM). The same field
/// set `GET /api/v1/ca/issued` serves per row.
struct CaCertRow {
    std::string serial_hex;
    std::string subject;
    std::string san;
    std::string purpose;
    std::int64_t issued_at{0};
    std::int64_t not_after{0};
    std::string status; ///< "active" | "revoked"
    std::int64_t revoked_at{0}; ///< 0 = not revoked
    std::string revocation_reason; ///< as recorded ("" when not revoked)
    std::string issued_by;
    std::string issuer_key_id;
};

struct CaCertPage {
    CaCertQuery query; ///< echoed, limit as applied, as_of = the instant actually used
    std::int64_t as_of{0};
    std::vector<CaCertRow> rows;
    std::int64_t total{0}; ///< every matching certificate, counted in the same statement
    bool truncated{false}; ///< more matching rows exist beyond this page (offset + rows < total)
};

/// One fixed window's count: `days` is the window, `count` the certificates inside it.
struct CaWindowCount {
    int days{0};
    std::int64_t count{0};
};

/// One revoked window, split into the three buckets (never summed into one figure).
struct CaRevokedWindow {
    int days{0};
    std::int64_t superseded{0};
    std::int64_t unpublished{0};
    std::int64_t other{0};
};

/// One ISO week (Monday 00:00 UTC start) of the per-week series, zero-filled.
struct CaWeekCount {
    std::int64_t week_start{0};
    std::string label; ///< ISO 8601 week, "2026-W40"
    std::int64_t issued{0}; ///< unpublished revocations excluded
    std::int64_t revoked_superseded{0};
    std::int64_t revoked_unpublished{0};
    std::int64_t revoked_other{0};
    bool partial{false}; ///< the week containing as_of: its counts stop at as_of
};

/// Every Yuzu-issued count of the dashboard, read in one statement against `as_of`.
struct CaCertStats {
    std::int64_t as_of{0};
    std::int64_t active{0};
    std::vector<CaWindowCount> expiring;  ///< one per kExpiringWindowDays entry, in order
    std::vector<CaWindowCount> expired;   ///< one per kExpiredWindowDays entry
    std::vector<CaRevokedWindow> revoked; ///< one per kRevokedWindowDays entry
    CaWindowCount issued;                 ///< days = kIssuedWindowDays, unpublished excluded
    std::vector<CaWeekCount> weeks;       ///< kWeeklyBuckets ISO weeks, oldest first, the last
                                          ///< one containing as_of (partial)
};

/// An operator's dashboard layout: catalogue widget ids in display order.
///   `is_default`        the drawn layout IS the catalogue default (nothing stored, or a stored
///                       layout equal to it with nothing preserved);
///   `version`           the stored row's version, 0 when nothing is stored - a save passes it
///                       back as `expected_version`, and a stale one is a conflict;
///   `preserved_unknown` stored ids this build does not know (a widget a newer build added):
///                       never drawn, but kept on every save (after the caller's ids).
struct CryptoDashboardLayout {
    std::vector<std::string> widgets;
    bool is_default{false};
    std::int64_t version{0};
    std::size_t preserved_unknown{0};
};

} // namespace yuzu::server
