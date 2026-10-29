#pragma once

/// @file device_ci_kinds.hpp
/// The single table-driven contract for the device-CI v2 blob (ADR-0016 update
/// "device_ci blob v2"). Shared by the ingest parser (status acceptance, field
/// counts, row caps) and the store (DDL names, insert/select/delete loops) so a
/// section is declared exactly once.
///
/// Wire layout (v2): `0x02 scalar_record list_record*`
///   scalar_record := f0 1F ... 1F f21 [1F f22 ... 1F f32] 1E
///   list_record   := "status" 1F section 1F level 1F reason 1E
///                  | kind 1F c1 1F ... 1F cn 1E
/// Positions 0-21 are the frozen v1 order; 22-32 are appended (chassis, board,
/// machine-id scalars, each with its `source` kept for provenance).
///
/// The section identifier on the wire is ALWAYS the row-kind token, never the
/// plugin action name (the one rename is `partitions` -> `partition`).

#include <cstddef>
#include <iterator>

namespace yuzu::server {

/// First byte of a v2 blob. A blob that does not start with it is v1.
inline constexpr char kDeviceCiVersionByte = '\x02';

/// Scalar positions in a v2 scalar record: 22 frozen v1 + 11 appended.
inline constexpr std::size_t kDeviceCiScalarFields = 33;

/// One registered section. `table == nullptr` marks a status-only section whose
/// values are the appended scalars (chassis, baseboard, machine_id): it carries a
/// level/reason but never rows.
struct DeviceCiSectionDef {
    const char* section;
    const char* table;   ///< unqualified child table, or nullptr (status-only)
    const char* columns; ///< comma-separated TEXT columns, in wire order
    int n_fields;        ///< number of columns / wire fields per row
    int row_cap;         ///< server-side row cap (agent applies the same cap)
};

inline constexpr DeviceCiSectionDef kDeviceCiSections[] = {
    {"chassis", nullptr, "", 0, 0},
    {"baseboard", nullptr, "", 0, 0},
    {"machine_id", nullptr, "", 0, 0},
    {"cpu", "device_ci_cpu", "idx,model,cores,threads,clock_mhz,socket_designation,stepping", 7,
     32},
    {"dimm", "device_ci_dimm", "slot,size_mb,type,speed_mhz,manufacturer,part_number,serial", 7,
     64},
    {"disk", "device_ci_disk", "idx,model,size_gb,media_type,interface", 5, 128},
    // used_mb is volatile telemetry and deliberately absent from the daily row
    // (ADR-0016 hash-stability rule); the on-demand action still reports it.
    {"swap", "device_ci_swap", "device,total_mb,source", 3, 16},
    {"volume", "device_ci_volume", "volume,mount_points,device,fstype,total_bytes,detail", 6, 256},
    {"partition", "device_ci_partition", "disk,partition,size_bytes,type,mount_points,detail", 6,
     512},
    {"topology", "device_ci_topology", "topo_kind,name,uuid,members,detail", 5, 512},
};

inline constexpr std::size_t kDeviceCiSectionCount = std::size(kDeviceCiSections);

} // namespace yuzu::server
