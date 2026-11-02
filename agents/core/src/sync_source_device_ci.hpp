#pragma once

/// @file sync_source_device_ci.hpp
/// The `device_ci` daily-sync source (ADR-0016) — a further source of the agent
/// sync framework (after `installed_software` and `app_perf`). Collects the
/// machine's stable hardware / OS identity — a ServiceNow-CMDB-style configuration
/// item (CI) record — by invoking the existing `hardware`, `device_identity`,
/// `os_info`, and `network_config` plugins in-process (`LocalDispatcher`) and
/// rendering them into the canonical wire blob the server (`device_ci_ingestion`)
/// reconstructs byte-for-byte.
///
/// **Machine scope only** — no per-user data (ADR-0016 §8). **Deliberately excludes
/// volatile telemetry** (disk free space, uptime, IP addresses): those flap between
/// cycles, which would flip the content hash every sync and defeat the hash-skip
/// protocol (the network-kindness the framework exists for). Only stable identity /
/// firmware / fixed-hardware / OS-version facts are in the CI record.

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor (C ABI) — typedef, so include not fwd-decl

#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>

namespace yuzu::agent {

/// The device-CI blob ceiling: 96 KiB (98,304 bytes). MUST equal the server's
/// `yuzu::server::kDeviceCiMaxBlobBytes` (server/core/src/device_ci_kinds.hpp). The two binaries
/// share no header, so each side's test pins its own constant to the literal 98304
/// (tests/unit/test_device_ci_sync.cpp here). The derivation and the sender trim contract are
/// recorded at the server constant and in ADR-0016 update "device_ci blob v2".
inline constexpr std::size_t kDeviceCiMaxBlobBytes = 96u * 1024;

/// One device-CI record — the canonical, ordered field set. The canonical blob is
/// these fields in THIS exact order (positional), 0x1F-separated and 0x1E-terminated
/// (one record). Adding/reordering a field is a COORDINATED change: the server's
/// reconstruction (`device_ci_ingestion.cpp`) AND the cross-pin test must move in
/// lockstep, or the agent- and server-recomputed hashes diverge → permanent
/// `need_full`. Numbers are rendered as decimal strings (hashed as text; the server
/// parses them back to integers for typed columns).
struct CiRecord {
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
    std::string cpu_cores;   ///< decimal string (summed physical cores)
    std::string cpu_threads; ///< decimal string (summed logical processors)
    std::string ram_bytes;   ///< decimal string (summed DIMM capacity, bytes)
    std::string disks_summary;
    std::string primary_mac;
    std::string macs_summary; ///< all non-zero MACs, sorted, comma-joined
    std::string nic_count;    ///< decimal string
    std::string os_name;
    std::string os_version;
    std::string os_build;
    std::string arch;
};

/// The raw stdout of each plugin action the device_ci source invokes (pipe-delimited
/// `key|...` lines). Grouped so the parse/aggregate step (`build_device_ci_record`)
/// is a PURE function, testable without a live `LocalDispatcher` (gov L2).
struct CiPluginOutputs {
    std::string manufacturer; ///< hardware "manufacturer"
    std::string model;        ///< hardware "model"
    std::string system;       ///< hardware "system" (serial + system_uuid)
    std::string bios;         ///< hardware "bios"
    std::string processors;   ///< hardware "processors"
    std::string memory;       ///< hardware "memory"
    std::string disks;        ///< hardware "disks"
    std::string device_name;  ///< device_identity "device_name"
    std::string domain;       ///< device_identity "domain"
    std::string ou;           ///< device_identity "ou"
    std::string os_name;      ///< os_info "os_name"
    std::string os_version;   ///< os_info "os_version"
    std::string os_build;     ///< os_info "os_build"
    std::string os_arch;      ///< os_info "os_arch"
    std::string adapters;     ///< network_config "adapters"
};

/// Pure parse + aggregate: plugin action outputs → a `CiRecord` (cpu cores/threads
/// summed across sockets, RAM summed to bytes, disks summarised + sorted, MACs
/// deduped + sorted, primary = first sorted). No I/O — exercised directly by the unit
/// tests (the live `collect()` path is otherwise only reachable with a loaded plugin).
/// Numbers render as decimal strings. Does NOT apply the `core_identity_unavailable`
/// skip — that is the caller's cycle decision.
YUZU_EXPORT CiRecord build_device_ci_record(const CiPluginOutputs& out);

/// Canonical wire blob (see `CiRecord` for the field order). Each field is
/// UTF-8-scrubbed + length-clamped + separator-stripped identically to the server,
/// then positionally joined. MUST be byte-identical to the server's reconstruction
/// (`device_ci_ingestion.cpp`) so the server-recomputed hash equals this one.
YUZU_EXPORT std::string device_ci_canonical_blob(const CiRecord& rec);

// ── v2 wire layout (ADR-0016 update "device_ci blob v2") ─────────────────────
//
//   0x02  scalar_record  section*          (section := status_record row_record*)
//   scalar_record := 33 clamp-joined fields (the 22 frozen v1 positions, then 11 appended
//                    chassis / baseboard / machine-id scalars), 0x1F-separated, 0x1E-terminated
//   status_record := "status" 1F <section> 1F <level> 1F <reason> 1E
//   row_record    := <kind> 1F c1 1F ... 1F cn 1E
//
// Sections appear in the server's registry order (kCiV2Sections), each as its status record then
// its rows. The section id is the ROW-KIND token, never the plugin action name (the one rename is
// the `partitions` action -> `partition`).
//
// Level vocabulary: `ok` | `constrained` | `unavailable` | `permission_denied`.
// Reason tokens the agent authors: `agent:action_absent` (an older plugin answered `unknown
// action`), `agent:rc=<n>`, `agent:truncated`, `agent:plugin_not_loaded`,
// `agent:windows_volumes_unbounded` (the Windows `volumes` probe is not run on the sync thread),
// `agent:mount_points_redacted` (a mount point under a user profile or a /Volumes label was
// replaced), and the cap disclosure `agent_cap:<kept>/<total>`; otherwise the plugin's own typed
// provenance / status-row token passes through verbatim (e.g. `linux:planned`).
//
// PIPES IN A FIELD: the plugins write a literal `|` as `\|` (and fold a literal backslash to `/`),
// so the v2 row and scalar projections split on an UNESCAPED pipe and unescape before the clamp. The
// 22 v1 positions keep the raw split: their bytes are frozen.
//
// MOUNT POINTS: the `volume` and `partition` mount-point column can name an account (a volume
// folder-mounted under a user profile) or carry a personal label (/Volumes/<label>). Such an entry
// is replaced by `[redacted]` before the blob is built and the section is `constrained`; see
// redact_mount_points.
//
// FAILURE PROVENANCE: a section whose level is `unavailable` or `permission_denied` carries its
// status record and NO rows (and its scalar positions stay blank). Nothing from a failed,
// truncated, absent or refused capture is ever projected, and the cap token can never promote
// such a section to `constrained`.
//
// ROW PROJECTION: only real data rows become wire rows. Empty-result placeholders are dropped: the
// hardware disk sentinel (`unknown|0`), the dimm sentinel (`dimm|unknown|0|...`) and the
// disk_actions volume placeholder (volume `-`). The memory summary row (`dimm|total|<mb>|...`,
// slot `total`) is NOT a placeholder: it is the hardware plugin's documented memory row on macOS
// and its Linux /proc/meminfo fallback, carries the host's real capacity, and is kept as a dimm row.
//
// RESERVED REASON SLOT: the base reason is clamped to kMaxFieldLen - kCiAgentCapReserve bytes so
// the single `agent_cap:` token (appended after `;` when the base is non-empty) always fits in the
// field contract, and the server's clamp can never cut the disclosure. A later ceiling trim
// REPLACES the token; a record never carries two.

/// Reason-slot reserve: strlen(";agent_cap:") + 2 x 10 digits + strlen("/") = 32 bytes. Ten digits
/// hold any row count a capture can reach: LocalDispatcher bounds a capture to 2 MiB.
inline constexpr std::size_t kCiAgentCapReserve = 11 + 2 * 10 + 1;

/// One plugin action's outcome as the device_ci source saw it: the ABI4 typed result and the
/// dispatcher metadata the section status is mapped from, plus the captured stdout.
struct CiActionResult {
    int rc{0};
    bool truncated{false};
    YuzuResultStatus status{YUZU_RESULT_STATUS_UNDECLARED};
    std::string provenance; ///< typed provenance the plugin declared ("" when none)
    std::string captured;
};

/// Reason of the Windows `volumes` section while its probe is not run on the sync thread.
inline constexpr std::string_view kReasonWindowsVolumesUnbounded = "agent:windows_volumes_unbounded";
/// Reason of a `volume`/`partition` section in which at least one mount point was redacted.
inline constexpr std::string_view kReasonMountPointsRedacted = "agent:mount_points_redacted";

/// The `volumes` outcome on a Windows host: `unavailable` with kReasonWindowsVolumesUnbounded and
/// no capture. The Windows `volumes` leg issues synchronous `DeviceIoControl` calls with no
/// deadline (disk_actions_win.cpp, "BOUNDING"), and the sync thread is joined on reconnect and on
/// shutdown, so one wedged drive would stop the agent from reconnecting. Until those calls have a
/// bound the daily record reports the section instead of running it; the operator-triggered
/// `volumes` dispatch is unchanged.
YUZU_EXPORT CiActionResult windows_volumes_deferred_result();

/// Replace every entry of a comma-separated mount-point list that sits under a user profile
/// (`/Users`, `/home`, `\Users` and `\Documents and Settings` behind a drive letter) or under
/// `/Volumes` (the label is user-chosen) with `[redacted]`, and set `redacted` when any entry was.
/// A piece that is not a path (the tail of a label that contained a comma) is redacted too. `-` (no
/// mount) and drive roots, `/` and `/System/Volumes/*` pass through. Never clears `redacted`.
YUZU_EXPORT std::string redact_mount_points(std::string_view csv, bool& redacted);

/// The ten section-bearing actions' outcomes (the three pre-existing actions carry their typed
/// metadata too -- it is retained, never discarded).
struct CiSectionInputs {
    CiActionResult processors; ///< -> cpu
    CiActionResult memory;     ///< -> dimm
    CiActionResult disks;      ///< -> disk
    CiActionResult chassis;
    CiActionResult baseboard;
    CiActionResult machine_id;
    CiActionResult swap;
    CiActionResult volumes;    ///< disk_actions -> volume
    CiActionResult partitions; ///< disk_actions -> partition
    CiActionResult topology;   ///< disk_actions -> topology
    bool disk_actions_loaded{false};
};

/// One registered section: row-kind token, wire columns per row, row cap. MUST mirror the server's
/// kDeviceCiSections (server/core/src/device_ci_kinds.hpp) in token, order, n_fields and row_cap;
/// the agent test pins an independent literal of the same table.
struct CiV2Section {
    const char* token;
    int n_fields; ///< 0 for a status-only section (chassis, baseboard, machine_id)
    int row_cap;
};

inline constexpr CiV2Section kCiV2Sections[] = {
    {"chassis", 0, 0}, {"baseboard", 0, 0}, {"machine_id", 0, 0}, {"cpu", 7, 32},
    {"dimm", 7, 64},   {"disk", 5, 128},    {"swap", 3, 16},      {"volume", 6, 128},
    {"partition", 6, 192}, {"topology", 5, 96},
};
inline constexpr std::size_t kCiV2SectionCount = std::size(kCiV2Sections);

/// Ceiling-trim order, least valuable first. The server's recorded order omits swap; swap is
/// appended LAST here so the sender can prove termination at the clamp bound (16 swap rows at the
/// clamp are ~49 KB, which would not fit alongside the untrimmed records if swap were exempt).
inline constexpr const char* kCiV2TrimOrder[] = {"topology", "partition", "volume", "dimm",
                                                 "disk",     "cpu",       "swap"};

namespace detail {
inline constexpr std::size_t kCiClampField = 1024;
inline constexpr std::size_t kCiScalarFields = 33;

/// The part of a blob the sender never trims, at its clamp-bound worst case: version byte, a
/// scalar record with every field at the clamp, and one status record per section with level and
/// reason at the clamp. Mirrors device_ci_untrimmed_worst_case() on the server literally. Every
/// row-bearing kind is in kCiV2TrimOrder, so the untrimmed set is exactly this.
constexpr std::size_t ci_untrimmed_worst_case() {
    std::size_t sum = 1 + kCiScalarFields * kCiClampField + (kCiScalarFields - 1) + 1;
    for (const auto& d : kCiV2Sections)
        sum += std::string_view("status").size() + 1 + std::string_view(d.token).size() + 1 +
               kCiClampField + 1 + kCiClampField + 1;
    return sum;
}

/// Every row-bearing registry entry appears exactly once in kCiV2TrimOrder, and nothing else does.
constexpr bool ci_trim_order_covers_row_kinds() {
    std::size_t row_kinds = 0;
    for (const auto& d : kCiV2Sections) {
        if (d.row_cap <= 0)
            continue;
        ++row_kinds;
        int seen = 0;
        for (const char* t : kCiV2TrimOrder)
            if (std::string_view(t) == d.token)
                ++seen;
        if (seen != 1)
            return false;
    }
    return row_kinds == std::size(kCiV2TrimOrder);
}
} // namespace detail

static_assert(detail::ci_untrimmed_worst_case() < kDeviceCiMaxBlobBytes,
              "device_ci v2: the scalar record and status records, which are never trimmed, can "
              "exceed kDeviceCiMaxBlobBytes at the field clamp");
static_assert(detail::ci_trim_order_covers_row_kinds(),
              "device_ci v2: every row-bearing section must appear exactly once in kCiV2TrimOrder");

/// Canonical v2 blob (layout above). Pure: the same inputs in any plugin row order produce the same
/// bytes. Rows are projected only for sections whose mapped level is `ok`/`constrained`, sorted,
/// capped per kind (`agent_cap:<kept>/<total>`), then trimmed whole-kind-in-order to fit
/// kDeviceCiMaxBlobBytes. The scalar and status records are never trimmed. MUST be byte-identical
/// to the layout the server parses (`device_ci_ingestion.cpp`).
YUZU_EXPORT std::string device_ci_canonical_blob_v2(const CiRecord& rec,
                                                    const CiSectionInputs& in);

/// True when the platform's core-identity subsystem was unavailable for this
/// collection — Windows WMI down (every WMI-gated action returns the `"unknown"`
/// sentinel at rc=0, so the per-action rc check does NOT catch it) or the Linux
/// DMI tables unreadable. The tell is `manufacturer` AND `model` both `"unknown"`:
/// on Windows both come from one `Win32_ComputerSystem` query behind one
/// `wmi.valid()` gate (Linux reads two separate `/sys/class/dmi/id` files), so on a
/// functioning machine — physical OR virtual — both are always real (a VM reports e.g.
/// "VMware, Inc."/"VMware7,1"). Using AND (not OR) avoids skipping a healthy host
/// that reports a real manufacturer but an empty model forever. When true, the
/// collect skips the cycle rather than persist a degraded record whose
/// `serial`/`system_uuid` collapsed to `"unknown"` — which would overwrite the
/// last-good CI row and flap the content hash on every WMI blip (UP-1). A
/// genuinely serial-less host (a VM with real manufacturer/model) is NOT skipped;
/// its stable `"unknown"` serial persists. Pure/deterministic — unit-tested.
YUZU_EXPORT bool core_identity_unavailable(const CiRecord& rec);

/// Build the `device_ci` SyncSource. The first four arguments are loaded plugin descriptors; if
/// ANY is null (not built/loaded — e.g. `build_agent=false`) the source's collect returns
/// `std::nullopt` and the scheduler no-ops it (a partial CI record is never synced). The fifth,
/// `disk_actions`, is optional: null reports the volume / partition / topology sections as
/// `unavailable|agent:plugin_not_loaded` and the rest of the record is unaffected.
///
/// The agent always emits the v2 record: there is no capability negotiation or fallback flag. A
/// host that cannot produce a section reports a typed section status instead, so the 22 base
/// fields always land. The 15 original actions keep abort-on-failure; the seven section actions
/// added with v2 never abort the cycle.
YUZU_EXPORT SyncSource make_device_ci_source(const YuzuPluginDescriptor* hardware,
                                             const YuzuPluginDescriptor* device_identity,
                                             const YuzuPluginDescriptor* os_info,
                                             const YuzuPluginDescriptor* network_config,
                                             const YuzuPluginDescriptor* disk_actions);

} // namespace yuzu::agent
