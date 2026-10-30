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
#include <optional>
#include <string_view>

namespace yuzu::server {

/// First byte of a v2 blob. A blob that does not start with it is v1.
inline constexpr char kDeviceCiVersionByte = '\x02';

/// Scalar positions in a v2 scalar record: 22 frozen v1 + 11 appended.
inline constexpr std::size_t kDeviceCiScalarFields = 33;

/// The blob ceiling: 96 KiB (98,304 bytes), on the server and, equal by contract, on the agent
/// (`yuzu::agent::kDeviceCiMaxBlobBytes`, agents/core/src/sync_source_device_ci.hpp). The two
/// binaries share no header, so each side's test pins its own constant to the literal 98304.
///
/// Derivation, not a transport figure. A p99 large host (every registered kind populated,
/// ordinary row widths) is about 25 KiB. Filling every kind to its row cap with a p99.9-wide row
/// is the registry-derived sum below, about 75 KiB; the 96 KiB ceiling leaves headroom over that
/// figure, and the `static_assert` after the table fails the build when a cap or a row budget
/// is changed without reconsidering the ceiling (the sum must stay within 80% of it).
///
/// A conforming sender never reaches the ceiling. It keeps the first N rows of each kind in a
/// fixed sorted order (so the blob and its hash are stable day to day), marks the section
/// `constrained` with kept-of-total counts, and, if the blob would still exceed the ceiling,
/// trims whole sections' tail rows in this order, least valuable first: topology, partition,
/// volume, dimm, disk, cpu. The scalar record and the per-section status records are never
/// trimmed, so a record always fits and the base fields always land. Trimmed rows are not
/// stored. The server drops and nacks a blob over the ceiling as a backstop for a non-conforming
/// sender only. Contract recorded in ADR-0016 (update "device_ci blob v2").
inline constexpr std::size_t kDeviceCiMaxBlobBytes = 96u * 1024;

/// Declared budget, in wire bytes, for the scalar record plus every per-section status record
/// (a p99.9 host with a long hostname, OU path and MAC list sits near 2 KiB; the status
/// records add about 1 KiB). Never trimmed by a sender.
inline constexpr std::size_t kDeviceCiScalarStatusBudget = 3u * 1024;

/// One registered section. `table == nullptr` marks a status-only section whose
/// values are the appended scalars (chassis, baseboard, machine_id): it carries a
/// level/reason but never rows.
struct DeviceCiSectionDef {
    const char* section;
    const char* table;   ///< unqualified child table, or nullptr (status-only)
    const char* columns; ///< comma-separated TEXT columns, in wire order
    int n_fields;        ///< number of columns / wire fields per row
    int row_cap;         ///< server-side row cap (the agent-side v2 writer MUST apply the same cap)
    int row_budget;      ///< declared p99.9 row width in wire bytes (kind token, separators and
                         ///< the record terminator included); 0 for a status-only section. A
                         ///< budget, not a bound: the 1,024-byte field clamp is the per-field
                         ///< hard bound, the blob ceiling the hard bound for a blob.
};

inline constexpr DeviceCiSectionDef kDeviceCiSections[] = {
    {"chassis", nullptr, "", 0, 0, 0},
    {"baseboard", nullptr, "", 0, 0, 0},
    {"machine_id", nullptr, "", 0, 0, 0},
    {"cpu", "device_ci_cpu", "idx,model,cores,threads,clock_mhz,socket_designation,stepping", 7, 32,
     96},
    {"dimm", "device_ci_dimm", "slot,size_mb,type,speed_mhz,manufacturer,part_number,serial", 7, 64,
     96},
    {"disk", "device_ci_disk", "idx,model,size_gb,media_type,interface", 5, 128, 64},
    // used_mb is volatile telemetry and deliberately absent from the daily row
    // (ADR-0016 hash-stability rule); the on-demand action still reports it.
    {"swap", "device_ci_swap", "device,total_mb,source", 3, 16, 56},
    {"volume", "device_ci_volume", "volume,mount_points,device,fstype,total_bytes,detail", 6, 128,
     144},
    {"partition", "device_ci_partition", "disk,partition,size_bytes,type,mount_points,detail", 6,
     192, 120},
    {"topology", "device_ci_topology", "topo_kind,name,uuid,members,detail", 5, 96, 144},
};

inline constexpr std::size_t kDeviceCiSectionCount = std::size(kDeviceCiSections);

/// The registry-derived worst plausible blob: the scalar/status budget plus, for every list
/// kind, row_cap x row_budget.
[[nodiscard]] constexpr std::size_t device_ci_registry_budget() {
    std::size_t sum = kDeviceCiScalarStatusBudget;
    for (const auto& d : kDeviceCiSections)
        sum += static_cast<std::size_t>(d.row_cap) * static_cast<std::size_t>(d.row_budget);
    return sum;
}

/// Every list kind's budget sits between the shortest possible row (all fields empty) and the
/// clamp-bound row (every field at the 1,024-byte field clamp); a status-only section declares
/// neither rows nor a budget.
[[nodiscard]] constexpr bool device_ci_row_budgets_sane() {
    constexpr std::size_t kFieldClamp = 1024; // MUST equal kMaxFieldLen in device_ci_ingestion.cpp
    for (const auto& d : kDeviceCiSections) {
        if (d.table == nullptr) {
            if (d.row_cap != 0 || d.row_budget != 0)
                return false;
            continue;
        }
        const std::size_t n = static_cast<std::size_t>(d.n_fields);
        const std::size_t kind_len = std::string_view(d.section).size();
        const std::size_t shortest = kind_len + n + 1;               // kind, n separators, 1E
        const std::size_t longest = kind_len + n * (kFieldClamp + 1) + 1;
        const auto budget = static_cast<std::size_t>(d.row_budget);
        if (d.row_cap <= 0 || budget < shortest || budget > longest)
            return false;
    }
    return true;
}

static_assert(device_ci_row_budgets_sane(),
              "device_ci_kinds.hpp: a row budget is outside [shortest row, clamp-bound row], or a "
              "status-only section declares rows");
// Changing a cap or a row budget fails the build here until the ceiling is reconsidered: the
// declared worst case must stay within 80% of kDeviceCiMaxBlobBytes (and the agent's equal
// constant, pinned by tests/unit/test_device_ci_sync.cpp).
static_assert(device_ci_registry_budget() * 5 <= kDeviceCiMaxBlobBytes * 4,
              "device_ci_kinds.hpp: sum(row_cap x row_budget) + scalar/status budget exceeds 80% of "
              "kDeviceCiMaxBlobBytes; lower a cap or budget, or reconsider the ceiling on BOTH the "
              "server and the agent (ADR-0016 update \"device_ci blob v2\")");

/// The one registry lookup: index of a section / row-kind token in `kDeviceCiSections`, or
/// nullopt when unregistered. Both the parser (status acceptance, row kinds) and the store
/// (write and read trust boundary: only registered kinds reach a table) go through it.
[[nodiscard]] constexpr std::optional<std::size_t> device_ci_section_index(std::string_view name) {
    for (std::size_t i = 0; i < kDeviceCiSectionCount; ++i)
        if (name == kDeviceCiSections[i].section)
            return i;
    return std::nullopt;
}

} // namespace yuzu::server
