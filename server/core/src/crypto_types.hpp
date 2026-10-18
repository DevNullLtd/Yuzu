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

} // namespace yuzu::server
