#pragma once

/**
 * echo_schema_registry.hpp -- Capture source definitions for the Echo data warehouse
 *
 * Defines every capture source, its roll-up tiers (Hourly, Daily, Monthly), typed column
 * schemas per tier, and the DDL for the tables the roll-up model does not own. The tiers'
 * columns are derived from fold_sources() (echo_fold_schema.hpp), never typed twice.
 *
 * ROLL-UP IS THE ONLY STORAGE MODEL: raw capture rows are not kept, and no setting, flag or
 * environment variable selects between the two. The retired raw names (`$Process_Live` and the
 * other 15) do not translate: a query that names one fails as an unknown table.
 *
 * The $-name convention ($Process_Hourly, $TCP_Daily, etc.) maps to snake_case SQLite
 * view names (process_hourly, tcp_daily) via a whitelist translation.
 */

#include <yuzu/plugin.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::echo {

// ── Column and table metadata ───────────────────────────────────────────────

/// What a column is in a roll-up tier table (echo_fold_schema.hpp). Only the
/// roll-up declarations set anything but the default; every `{name, type}`
/// initialiser in build_sources() keeps compiling untouched.
enum class ColumnRole {
    kBucket,    ///< the tier's time bucket (hour_ts / day_ts / month_ts)
    kKey,       ///< part of the (bucket, keys...) identity of a roll-up row
    kMeasure,   ///< a merged value (see MergeOp)
    kGenerated, ///< VIRTUAL generated column derived from measures; never written
};

/// How a measure merges when a fold lands on an existing (bucket, keys) row.
enum class MergeOp {
    kNone, ///< not a merged value (keys, generated columns, plain registry columns)
    kSum,  ///< m = m + incoming
    kMax,  ///< m = MAX(m, incoming)
    kMin,  ///< m = MIN(m, incoming)
    kLast, ///< m = incoming iff incoming `guard` >= stored `guard` (ties take the later arrival)
};

struct ColumnDef {
    std::string_view name;
    std::string_view sql_type; // INTEGER, TEXT, REAL
    ColumnRole role = ColumnRole::kMeasure;
    MergeOp merge = MergeOp::kNone;
    bool interned = false;            ///< TEXT key stored as an echo_dict id
    std::string_view generated_expr{}; ///< SQL of a kGenerated column
    std::string_view guard{};          ///< kLast only: the INTEGER column that orders it
};

enum class RetentionType { kRowCount, kTimeBased };

struct GranularityDef {
    std::string_view suffix;      // "hourly", "daily", "monthly"; "boot" (netqual) and "live" (usage) are plain tables
    RetentionType retention_type;
    int64_t retention_default;    // row count or seconds
    std::vector<ColumnDef> columns;
};

// ── Per-source OS support metadata (issue #59) ─────────────────────────────
//
// Each capture source declares, per supported operating system, how it
// gathers data and any known constraints. The metadata is read at runtime
// by the Echo `compatibility` action so operators can see exactly what is
// captured on each platform without reading the source.
//
// `kSupported`           -- fully wired and exercised in CI
// `kSupportedConstrained`-- works but with a known limitation (e.g., legacy
//                           Windows API that returns less detail; documented
//                           in `notes`)
// `kPlanned`             -- not yet implemented, but the `capture_method`
//                           field names the planned implementation so the
//                           configuration surface can validate against it
// `kUnsupported`         -- platform cannot supply the data at all (e.g.,
//                           `services` on a kernel that has no service
//                           manager)
//
// Unified with the ABI4 plugin descriptor's per-OS support enum (#2204):
// Echo is the first adopter, so these four values are pinned 1:1 to
// YuzuSupportLevel's four declared values (YUZU_SUPPORT_UNDECLARED is
// deliberately never used here — every registry row always declares one of
// the other four). This is the single source of truth both the `compatibility`
// action (echo_plugin.cpp's do_compatibility()) and any future capability-matrix
// consumer derive their output from, rather than each maintaining its own copy.
enum class OsSupportStatus {
    kSupported           = YUZU_SUPPORT_SUPPORTED,
    kSupportedConstrained = YUZU_SUPPORT_CONSTRAINED,
    kPlanned             = YUZU_SUPPORT_PLANNED,
    kUnsupported         = YUZU_SUPPORT_UNSUPPORTED,
};

/**
 * Convert an OsSupportStatus to the shared ABI4 descriptor enum. Since the
 * two are pinned 1:1 by value, this is a plain reinterpretation — but going
 * through a named function keeps the "single source of truth" claim
 * mechanically checkable rather than relying on every call site getting the
 * cast right.
 */
[[nodiscard]] constexpr YuzuSupportLevel to_yuzu_support_level(OsSupportStatus status) noexcept {
    return static_cast<YuzuSupportLevel>(status);
}

/**
 * Human-readable name for a support level, as surfaced by the `compatibility`
 * action. The one place that maps YuzuSupportLevel to the operator-facing
 * string — do_compatibility() derives its output from this rather than
 * keeping its own switch.
 */
[[nodiscard]] std::string_view support_level_name(OsSupportStatus status);

struct OsSupport {
    std::string_view os;             // "windows", "linux", "macos"
    OsSupportStatus status;
    std::string_view capture_method; // "polling", "etw", "systemctl", "wts",
                                      // "utmpx", "launchctl", "iphlpapi", ...
    std::string_view notes;           // free-form constraint description
};

struct CaptureSourceDef {
    std::string_view name;        // "process", "tcp", "service", "user"
    std::string_view dollar_name; // "Process", "TCP", "Service", "User"
    // Whether a fresh agent (no `<name>_enabled` config row yet) treats this
    // source as enabled. Every source ships `true` (a registry-wide test
    // forbids `false`); `echo.status`, retention, the collect gates and the
    // paused_at transition all read this one field. This is the single source
    // of truth — `source_default_enabled()` exposes it to the call sites that
    // only have the source name (issue #59 follow-up).
    // (Declared before os_support so the designated initialisers in
    // build_sources() stay in member-declaration order.)
    bool default_enabled = true;
    std::vector<OsSupport> os_support;
    std::vector<GranularityDef> granularities;
};

// ── Per-source capture-method validation (issue #59) ───────────────────────
//
// Returns the list of accepted `capture_method` values for a given source.
// Used by the plugin's `configure` action to reject mistyped or unsupported
// methods (e.g. `etw` for `tcp` on Linux) at write time, instead of
// silently storing a value that the collector ignores.
//
// The accept-list is the union over all OS rows in `os_support` whose
// `status != kUnsupported`. `kPlanned` methods are intentionally accepted
// so an operator can pre-stage configuration ahead of an implementation
// landing.
[[nodiscard]] std::vector<std::string> accepted_capture_methods(std::string_view source_name);

// The compile-time platform this agent was built for: "windows", "linux",
// "macos", or "" on an unrecognised platform.
[[nodiscard]] std::string_view current_platform_os();

// Like accepted_capture_methods, but restricted to the `os_support` rows for a
// single OS. This is what `configure` MUST validate against: the OS-blind union
// (accepted_capture_methods) lets a Linux agent accept a Windows-only method
// such as `iphlpapi`, which is then stored and surfaced even though the
// collector never honours it (#540). Pass `current_platform_os()` for the
// running host. `kPlanned` rows for that OS are still included (pre-staging).
[[nodiscard]] std::vector<std::string>
accepted_capture_methods_for_os(std::string_view source_name, std::string_view os);

// Support status of `source_name` on `os`, or nullopt for an unknown source or
// an OS with no row. When a source lists several rows for one OS the best
// (kSupported > kSupportedConstrained > kPlanned > kUnsupported) wins.
[[nodiscard]] std::optional<OsSupportStatus> os_support_status(std::string_view source_name,
                                                               std::string_view os);

// The registry's capture_method for the source's kSupported/kSupportedConstrained
// row on `os` (first such row); "none" when there is no supported row.
[[nodiscard]] std::string_view supported_capture_method(std::string_view source_name,
                                                        std::string_view os);

// ── Effective (actually-wired) network capture mechanism (issue #1528) ─────
//
// Returns the capture mechanism the Echo collector ACTUALLY uses, given the
// configured `network_capture_method`. Only polling is wired today: the
// per-OS platform APIs (procfs / iphlpapi / proc_pidfdinfo) ARE the polling
// implementation, and the kPlanned kernel-event methods (etw /
// endpoint_security) are accepted for pre-staging but not yet collected. So
// the effective mechanism is "polling" for every configured value until a
// kernel-event collector lands -- at which point this is where the runtime
// availability check goes (mirroring the process collector's `etw_active_`
// gate in echo_plugin.cpp's do_status). The `status` action reports this
// alongside the configured value so it can never misrepresent the active
// mechanism.
[[nodiscard]] std::string effective_network_capture_method(std::string_view configured);

// ── Per-source default-enabled lookup ──────────────────────────────────────
//
// Returns `CaptureSourceDef::default_enabled` for the named source — the value
// a fresh agent should assume when no `<source>_enabled` config row exists yet.
// `true` (the always-on default) when the source name is unknown. Used by the
// two default-enabled read sites that only have the bare source name (the
// plugin's `source_enabled()` and the aggregator's
// `apply_source_enabled_transition()`); call sites that already hold the
// `CaptureSourceDef` read the field directly.
[[nodiscard]] bool source_default_enabled(std::string_view source_name);

// ── Registry access ─────────────────────────────────────────────────────────

/** Get all registered capture source definitions. */
const std::vector<CaptureSourceDef>& capture_sources();

/**
 * The timestamp column for a granularity suffix: `ts` (usage_live, netqual_boot), `hour_ts`,
 * `day_ts`, `month_ts`. Unknown suffixes fall back to `ts`.
 *
 * This is the one mapping the warehouse DDL indexes, the fold's bucket columns use and the
 * #2361 retention clock guard counts against. Read it from here rather than re-deriving it --
 * a second copy would diverge silently, and the guard would then count a different column from
 * the one the delete acts on.
 */
[[nodiscard]] std::string_view ts_column_for_suffix(std::string_view suffix);

/**
 * Generate DDL for the typed warehouse tables the roll-up model does not own (netqual_boot and
 * the usage tables). Every roll-up tier name is a VIEW (generate_fold_ddl creates it) and is
 * skipped here. Returns a single SQL string of CREATE TABLE IF NOT EXISTS + indexes.
 */
std::string generate_warehouse_ddl();

/**
 * Translate a $-prefixed table name to its real SQLite table name.
 * e.g. "$Process_Hourly" -> "process_hourly", "$TCP_Hourly" -> "tcp_hourly".
 * Returns nullopt if the name is not in the whitelist.
 */
std::optional<std::string> translate_dollar_name(std::string_view dollar_name);

/**
 * Return true if `real_table_name` is a table that untrusted operator SQL
 * (the echo.sql action) is permitted to read: the typed warehouse tables from
 * the registry plus the base echo_state / echo_config tables (tar_events is NOT
 * included — schema v3 retired it and v5 drops it from the installed base). Used
 * by the read-only SQL sandbox's SQLite authorizer (#760). The set is computed
 * once from the registry, so it stays in sync as new capture sources land.
 */
[[nodiscard]] bool is_queryable_table(std::string_view real_table_name);

/**
 * Get all valid $-prefixed table names.
 * Used for schema browsing and documentation.
 */
std::vector<std::string> all_dollar_names();

/**
 * Get column names for a given real table name.
 * Returns empty vector if the table is unknown.
 */
std::vector<std::string> columns_for_table(const std::string& real_table_name);

} // namespace yuzu::echo
