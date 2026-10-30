#pragma once

/// @file device_inventory_types.hpp
/// Plain value types for the device-CI record (`DeviceCiRecord`, `CiReadError`), split
/// out of `device_inventory_store.hpp` so the hardware read model and the MCP registry
/// lane can name a record without including a store header (ADR-0031 seam closure,
/// #6558).
/// `device_inventory_store.hpp` re-includes this header, so existing includers are unaffected. No
/// behaviour lives here — the store keeps its class and every query.

#include <cstdint>
#include <string>

namespace yuzu::server {

/// One device-CI record — the typed projection of the `device_ci` canonical wire
/// blob. All collected fields are carried as strings (the exact wire bytes, so
/// `canonical_hash` reproduces the agent's hash); the numeric fields are
/// ADDITIONALLY persisted to BIGINT columns (`apply` parses them). Field order here
/// IS the canonical-blob order (see the agent's `CiRecord` /
/// `device_ci_ingestion.cpp`) — adding/reordering is a coordinated cross-side change.
struct DeviceCiRecord {
    std::string agent_id; ///< not in the blob; set by the ingest seam / read
    std::string manufacturer;
    std::string model;
    std::string serial;
    std::string system_uuid;
    std::string hostname;
    std::string domain;
    std::string ou;
    std::string bios_vendor;
    std::string bios_version;
    std::string bios_date;
    std::string cpu_model;
    std::string cpu_cores;   ///< decimal string (also persisted to BIGINT)
    std::string cpu_threads; ///< decimal string (also persisted to BIGINT)
    std::string ram_bytes;   ///< decimal string (also persisted to BIGINT)
    std::string disks_summary;
    std::string primary_mac;
    std::string macs_summary;
    std::string nic_count; ///< decimal string (also persisted to BIGINT)
    std::string os_name;
    std::string os_version;
    std::string os_build;
    std::string arch;
    std::int64_t first_seen{0}; ///< server receipt time (epoch seconds)
    std::int64_t last_seen{0};  ///< server receipt time (epoch seconds)
};

/// Error type for the authoritative single-record read. The success type is
/// `std::optional<DeviceCiRecord>`: a value == found, `std::nullopt` == absent
/// (read succeeded, no CI record for this agent yet). `std::unexpected(kDegraded)`
/// == store/pool/query failure (the caller shows an error banner vs a "not yet
/// synced" note). Out-params are forbidden in new code (docs/cpp-conventions.md) —
/// hence `std::expected` rather than an enum + out-param.
enum class CiReadError { kDegraded };

} // namespace yuzu::server
