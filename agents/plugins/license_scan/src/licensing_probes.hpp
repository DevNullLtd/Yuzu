/**
 * licensing_probes.hpp — the extensible ProbeSpec table + engine for the
 * license_scan plugin (SLE roadmap §5 PR1 detection-surface table; ADR-0024
 * Decision 2: "Adding a vendor later is one ProbeSpec row").
 *
 * A ProbeSpec row is {surface name, platform, scope, registry path / file
 * glob, interpreter fn, presence-row metadata}. The engine walks the rows for
 * the current platform+scope, drives all I/O through the ProbeHost interface
 * (per-OS TUs supply registry access; the filesystem defaults live in
 * licensing_probes.cpp), and aggregates one ProbeOutcome per unique surface
 * name. Rows without an interpreter are PRESENCE rows: key/file exists →
 * one record built from the row's metadata, status stays `unknown`
 * (unknown-preserving — presence alone never claims a licence state).
 *
 * Absence is ok|0, not an error: a probe that ran and found nothing is a
 * structural success (ADR-0024 D3 empty-vs-error rule). Real failures on the
 * PRIMARY surfaces (SLP WMI, rpm/dpkg enumeration, cert dirs) are reported by
 * the per-OS TUs, which own those surfaces directly.
 *
 * The engine and interpreters touch platform I/O only through ProbeHost, so
 * this pair of files compiles on every OS; the Windows-only registry methods
 * default to "absent" elsewhere.
 */

#ifndef YUZU_LICENSE_SCAN_LICENSING_PROBES_HPP
#define YUZU_LICENSE_SCAN_LICENSING_PROBES_HPP

#include "licensing_record.hpp"

#include <cstddef>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::license_scan {

enum class Platform { windows_os, linux_os, macos_os };
enum class Scope { machine, user };

/// I/O the engine and interpreters may perform. Filesystem operations have
/// working defaults (licensing_probes.cpp, std::filesystem — bounded);
/// registry operations default to "absent" and are overridden by the Windows
/// host (Reg*W + win_str.hpp per roadmap R17). Registry paths are relative to
/// the host's root (HKLM for machine scope; the mounted/loaded user hive for
/// user scope) — a ProbeSpec row never names a hive root, which is what lets
/// the same row probe both live HKU hives and RegLoadKey mounts.
class ProbeHost {
public:
    virtual ~ProbeHost() = default;

    // ── registry (Windows hosts override) ──────────────────────────────────
    virtual bool reg_key_exists(std::string_view key_path) {
        (void)key_path;
        return false;
    }
    virtual std::optional<std::string> reg_read_str(std::string_view key_path,
                                                    std::string_view value_name) {
        (void)key_path;
        (void)value_name;
        return std::nullopt;
    }
    virtual std::vector<std::string> reg_enum_subkeys(std::string_view key_path) {
        (void)key_path;
        return {};
    }
    /// (value name, string value) pairs for REG_SZ/REG_EXPAND_SZ values.
    virtual std::vector<std::pair<std::string, std::string>>
    reg_enum_str_values(std::string_view key_path) {
        (void)key_path;
        return {};
    }

    // ── filesystem (defaults in licensing_probes.cpp) ───────────────────────
    /// Expand a `*`-wildcard glob (per-segment, no `**`), bounded to
    /// kGlobMaxMatches results. UTF-8 in, UTF-8 out.
    virtual std::vector<std::string> glob(std::string_view pattern);
    virtual bool file_exists(std::string_view path);
    /// First max_bytes of a file, or nullopt when unreadable.
    virtual std::optional<std::string> read_file_prefix(std::string_view path,
                                                        std::size_t max_bytes);

    /// Collection time (UTC epoch seconds) — virtual so tests can pin it and
    /// countdown→absolute-date conversions stay deterministic per run.
    virtual long long now_epoch() { return static_cast<long long>(::time(nullptr)); }
};

inline constexpr std::size_t kGlobMaxMatches = 512;

// ── ProbeSpec rows ──────────────────────────────────────────────────────────

enum class ProbeKind { registry_key, file_glob };

struct ProbeSpec;

/// Custom interpreter: called once per existing registry key (matched ==
/// spec.path) or once per glob match (matched == file path). Appends records;
/// must emit only §3.2 closed-vocabulary values.
using InterpretFn = void (*)(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                             std::vector<LicRecord>& out);

struct ProbeSpec {
    const char* surface;      // probe_status surface token (rows may share one)
    Platform platform;
    Scope scope;
    ProbeKind kind;
    const char* path;         // registry key path (root-relative) or file glob
    InterpretFn interpret;    // nullptr → generic presence row
    // Presence-row metadata (used when interpret == nullptr):
    const char* product;
    const char* vendor;
    const char* license_type; // §3.2 license_type token
    const char* source;       // §3.2 source token
    const char* confidence;   // §3.2 confidence token
    const char* exe_hints;    // comma-separated bare exe names (R6)
};

/// The v1 table (roadmap §5 PR1 detection-surface table). Adding a vendor
/// later = one row (+ optional interpreter fn); no engine change.
const std::vector<ProbeSpec>& probe_spec_table();

/// Run every table row matching platform+scope. Appends records and one
/// aggregated ProbeOutcome per unique surface name (in first-appearance
/// order). User-scope callers stamp user_scope/user_ref on the records they
/// receive — the engine emits scope-neutral records.
void run_probe_specs(ProbeHost& host, Platform platform, Scope scope,
                     std::vector<LicRecord>& records, std::vector<ProbeOutcome>& outcomes);

/// The JetBrains per-user `.key` interpreter, exposed so licensing_win.cpp
/// can run the per-profile file scan through the same code path the table's
/// interpreter rows use (paths are per-profile, so they cannot be static
/// table rows).
InterpretFn jetbrains_key_interpreter();

// ── per-OS surface runners ──────────────────────────────────────────────────

/// Everything one `list` run produces: records first, then one outcome per
/// surface attempted (§3.1 emission order). Implemented per-OS in
/// licensing_win.cpp / licensing_linux.cpp / licensing_macos.cpp.
struct SurfaceRun {
    std::vector<LicRecord> records;
    std::vector<ProbeOutcome> outcomes;
};

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
SurfaceRun run_platform_surfaces();
#endif

} // namespace yuzu::license_scan

#endif // YUZU_LICENSE_SCAN_LICENSING_PROBES_HPP
