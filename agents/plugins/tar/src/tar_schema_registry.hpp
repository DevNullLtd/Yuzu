#pragma once

/**
 * tar_schema_registry.hpp -- Capture source definitions for the TAR data warehouse
 *
 * Defines every capture source, its supported granularity tiers (Live, Hourly,
 * Daily, Monthly), typed column schemas per tier, and the DDL + rollup SQL
 * needed to create and maintain the warehouse tables.
 *
 * The $-name convention ($Process_Live, $TCP_Hourly, etc.) maps to snake_case
 * SQLite table names (process_live, tcp_hourly) via a whitelist translation.
 */

#include <yuzu/plugin.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

// ── Column and table metadata ───────────────────────────────────────────────

struct ColumnDef {
    std::string_view name;
    std::string_view sql_type; // INTEGER, TEXT, REAL
};

enum class RetentionType { kRowCount, kTimeBased };

struct GranularityDef {
    std::string_view suffix;      // "live", "hourly", "daily", "monthly"
    RetentionType retention_type;
    int64_t retention_default;    // row count or seconds
    std::vector<ColumnDef> columns;
};

// ── Per-source OS support metadata (issue #59) ─────────────────────────────
//
// Each capture source declares, per supported operating system, how it
// gathers data and any known constraints. The metadata is read at runtime
// by the TAR `compatibility` action so operators can see exactly what is
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
// TAR is the first adopter, so these four values are pinned 1:1 to
// YuzuSupportLevel's four declared values (YUZU_SUPPORT_UNDECLARED is
// deliberately never used here — every registry row always declares one of
// the other four). This is the single source of truth both the `compatibility`
// action (tar_plugin.cpp's do_compatibility()) and any future capability-matrix
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
    // source as enabled. Always-on sources keep the default `true`; high-volume
    // usage-class sources that are opt-in under the works-council posture
    // (module, procperf, netqual) set this `false` so `tar.status`, retention,
    // and the paused_at transition all agree the source starts disabled. This is
    // the single source of truth — `source_default_enabled()` exposes it to the
    // two call sites that only have the source name (issue #59 follow-up).
    // (Declared before os_support so the designated initialisers in
    // build_sources() stay in member-declaration order.)
    bool default_enabled = true;
    // Non-empty for a source whose LIVE tier enforces replay idempotence via a
    // UNIQUE index (tar_cursor.hpp rule 3 — the cursor-model seam). When set,
    // generate_warehouse_ddl() emits
    // `CREATE UNIQUE INDEX IF NOT EXISTS <table>_record_key_uq ON <table>(<this column>)`
    // for the live tier only. Empty ("") for every source that has no such
    // column (the default — a plain diff-driven source has no idempotence
    // requirement beyond its own diff logic).
    std::string_view unique_key_column;
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
// Returns the capture mechanism the TAR collector ACTUALLY uses, given the
// configured `network_capture_method`. Only polling is wired today: the
// per-OS platform APIs (procfs / iphlpapi / proc_pidfdinfo) ARE the polling
// implementation, and the kPlanned kernel-event methods (etw /
// endpoint_security) are accepted for pre-staging but not yet collected. So
// the effective mechanism is "polling" for every configured value until a
// kernel-event collector lands -- at which point this is where the runtime
// availability check goes (mirroring the process collector's `etw_active_`
// gate in tar_plugin.cpp's do_status). The `status` action reports this
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
 * The timestamp column for a granularity suffix: `ts` (live), `hour_ts`,
 * `day_ts`, `month_ts`. Unknown suffixes fall back to `ts`.
 *
 * This is the one mapping the warehouse DDL indexes, `retention_sql`'s
 * time-based branch filters on, and the #2361 retention clock guard counts
 * against. Read it from here rather than re-deriving it -- a second copy would
 * diverge silently, and the guard would then count a different column from the
 * one the delete acts on.
 */
[[nodiscard]] std::string_view ts_column_for_suffix(std::string_view suffix);

/**
 * Generate DDL for all typed warehouse tables.
 * Returns a single SQL string containing CREATE TABLE IF NOT EXISTS + indexes.
 */
std::string generate_warehouse_ddl();

/**
 * Translate a $-prefixed table name to its real SQLite table name.
 * e.g. "$Process_Live" -> "process_live", "$TCP_Hourly" -> "tcp_hourly".
 * Returns nullopt if the name is not in the whitelist.
 */
std::optional<std::string> translate_dollar_name(std::string_view dollar_name);

/**
 * Return true if `real_table_name` is a table that untrusted operator SQL
 * (the tar.sql action) is permitted to read: the typed warehouse tables from
 * the registry plus the base tar_state / tar_config tables (tar_events is NOT
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

/**
 * Generate rollup SQL for a specific source and target granularity.
 * The SQL is an INSERT INTO ... SELECT that aggregates from the source tier.
 * @param source_name  e.g. "process"
 * @param target_suffix e.g. "hourly"
 * @return SQL string, or empty if rollup is not defined for this combination.
 */
std::string rollup_sql(std::string_view source_name, std::string_view target_suffix);

/**
 * Generate retention SQL for a specific table.
 * Row-count retention: DELETE oldest rows exceeding the limit.
 * Time-based retention: DELETE rows older than the cutoff.
 * @param real_table_name  e.g. "process_live"
 * @param now_epoch        Current epoch seconds (for time-based retention).
 * @return SQL string to execute, or empty if no retention defined.
 */
std::string retention_sql(const std::string& real_table_name, int64_t now_epoch);

} // namespace yuzu::tar
