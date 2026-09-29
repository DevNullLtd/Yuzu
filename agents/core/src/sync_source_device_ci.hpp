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

#include <string>

namespace yuzu::agent {

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

/// Build the `device_ci` SyncSource. Each argument is a loaded plugin descriptor;
/// if ANY required plugin is null (not built/loaded — e.g. `build_agent=false`)
/// the source's collect returns `std::nullopt` and the scheduler no-ops it (a
/// partial CI record is never synced).
YUZU_EXPORT SyncSource make_device_ci_source(const YuzuPluginDescriptor* hardware,
                                             const YuzuPluginDescriptor* device_identity,
                                             const YuzuPluginDescriptor* os_info,
                                             const YuzuPluginDescriptor* network_config);

} // namespace yuzu::agent
