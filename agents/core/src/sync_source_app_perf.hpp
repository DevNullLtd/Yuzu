#pragma once

/// @file sync_source_app_perf.hpp
/// The `app_perf` daily-sync source (DEX app-perf-over-time, layer B1). Each daily
/// cycle it rolls the on-device `procperf_hourly` warehouse up to per-`(app,
/// version, day)` daily summaries for the last 2 completed UTC days and ships them
/// over the existing `ReportInventory` transport (a new `plugin_data` key — no
/// proto change, no gateway regen). The server persists them in AppPerfDailyStore.
///
/// It obtains the warehouse rows via `LocalDispatcher` → the Echo plugin's `sql`
/// action (the read-only, authorizer-sandboxed operator-SQL path) — no second
/// echo.db handle from agent-core. NAMES ONLY (procperf is names-only + operator
/// redaction applied at collection). Windows-fed today (procperf is Windows-only;
/// Linux/macOS report nothing until those collectors land).
///
/// Hash-skip is MOOT (the per-day window changes daily → the agent always sends
/// full); the source still computes a content hash for the scheduler's local
/// "did it change" check, but the SERVER ignores it (B1 is hash-less), so the
/// wire blob need only be parseable, not byte-reproducible.

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor, YUZU_EXPORT

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::agent {

/// One daily per-app-version summary (agent-local mirror of the server's
/// AppPerfDailyRow; kept agent-side so this module needs no server headers).
struct AppPerfRow {
    std::string name;
    std::string version;
    std::int64_t day{0}; ///< UTC midnight epoch seconds
    std::int64_t samples{0};
    std::int64_t instances_max{0};
    double cpu_avg{0.0};
    double cpu_max{0.0};
    std::int64_t ws_avg_bytes{0};
    std::int64_t ws_max_bytes{0};
};

/// Build the daily-rollup SELECT over `$ProcPerf_Hourly` for the half-open window
/// `[window_start, today_start)` (epoch seconds). Sample-weighted averages,
/// max-of-max peaks, summed counts; grouped by `(name, version, UTC day)`. Pure.
YUZU_EXPORT std::string build_app_perf_query(std::int64_t window_start, std::int64_t today_start);

/// Parse the Echo `sql` action's captured output (`__schema__|…` header, pipe-
/// delimited rows in the SELECT's column order, `__total__|N` footer; `error|…`
/// lines and the markers are skipped). Pure.
YUZU_EXPORT std::vector<AppPerfRow> parse_app_perf_sql_output(const std::string& captured);

/// Canonicalize each row's version (`yuzu::util::canon_version`) and MERGE rows
/// that collapse to the same `(name, version, day)` — sample-weighted averages,
/// max peaks — so the wire blob (and the server's batched upsert) is key-unique.
/// Numerics clamped finite + non-negative. Pure.
YUZU_EXPORT std::vector<AppPerfRow> canon_merge_app_perf(std::vector<AppPerfRow> rows);

/// Render canon-merged rows to the wire blob: records 0x1E-separated, fields
/// 0x1F-separated, 9 fields `name, version, day, samples, instances_max, cpu_avg,
/// cpu_max, ws_avg_bytes, ws_max_bytes`. Separators/NUL stripped from name/version.
/// Pure. (No byte-identical-with-server requirement — B1 is hash-less.)
YUZU_EXPORT std::string render_app_perf_blob(std::vector<AppPerfRow> rows);

/// Build the `app_perf` SyncSource. `echo_descriptor` is the loaded Echo plugin
/// descriptor; when null (Echo not built/loaded) the source's collect returns
/// std::nullopt and the scheduler no-ops it. An empty rollup (procperf disabled /
/// no activity) also skips the cycle (network-kind — never sends an empty blob).
YUZU_EXPORT SyncSource make_app_perf_source(const YuzuPluginDescriptor* echo_descriptor);

} // namespace yuzu::agent
