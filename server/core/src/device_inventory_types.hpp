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
#include <vector>

namespace yuzu::server {

/// One v2 section: the agent's status for a kind plus (for list kinds) its rows.
/// `rows[i]` holds the kind's declared column values in wire order. Status-only
/// sections (chassis, baseboard, machine_id) carry no rows.
struct DeviceCiSection {
    std::string kind;
    std::string level;  ///< agent-reported level, or "constrained" after a server cap
    std::string reason; ///< agent-reported reason; ";server_cap:<n>" appended on truncation
    std::vector<std::vector<std::string>> rows;
};

/// One device-CI record — the typed projection of the `device_ci` canonical wire
/// blob. All collected fields are carried as strings (the exact wire bytes, so
/// `canonical_hash` reproduces the agent's hash); the numeric fields are
/// ADDITIONALLY persisted to BIGINT columns (`apply` parses them). Field order here
/// IS the canonical-blob order (see the agent's `CiRecord` /
/// `device_ci_ingestion.cpp`) — adding/reordering is a coordinated cross-side change.
/// Wire positions 0-21 (manufacturer..arch) are frozen; v2 blobs append positions 22-32
/// (the chassis/board/machine-id scalars below); list-kind rows follow as separate
/// records (see `DeviceCiSection`, `device_ci_kinds.hpp`).
///
/// PERSONAL DATA: `chassis_serial`, `board_serial` and the DIMM `serial` column join
/// `serial`/`system_uuid`/MACs in the behavioural-PII tier covered by the audited read
/// `inventory.device.ci` (ADR-0016). Any read route over them must sit behind that
/// fail-closed audit.
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
    // ── v2 additions (appended AFTER last_seen so existing designated initialisers
    //    keep compiling). Blank on a v1 record. ──
    int blob_version{1};       ///< 1 = positional 22-field blob, 2 = versioned blob
    std::string content_hash;  ///< v2 only: sha256 of the received blob (set by the parser)
    std::string chassis_type;  ///< wire position 22
    std::string chassis_serial;
    std::string chassis_asset_tag;
    std::string chassis_source;
    std::string board_vendor;
    std::string board_product;
    std::string board_serial;
    std::string board_source;
    std::string machine_id_hash;
    std::string machine_id_algorithm;
    std::string machine_id_source; ///< wire position 32
    /// v2 only: per-section statuses + list rows, in `kDeviceCiSections` order (only
    /// sections the blob mentioned). Empty on v1. Not populated by `get_device_ci` —
    /// read via `get_device_ci_sections`.
    std::vector<DeviceCiSection> sections;
};

/// Error type for the authoritative single-record read. The success type is
/// `std::optional<DeviceCiRecord>`: a value == found, `std::nullopt` == absent
/// (read succeeded, no CI record for this agent yet). `std::unexpected(kDegraded)`
/// == store/pool/query failure (the caller shows an error banner vs a "not yet
/// synced" note). Out-params are forbidden in new code (docs/cpp-conventions.md) —
/// hence `std::expected` rather than an enum + out-param.
enum class CiReadError { kDegraded };

} // namespace yuzu::server
