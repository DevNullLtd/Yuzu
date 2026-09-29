#pragma once

/// @file sync_source_app_usage.hpp
/// The `app_usage` daily-sync source (ADR-0016; wave 7 PR7.2). Collects
/// per-executable last-used state by invoking the `app_usage` plugin in-process
/// (`LocalDispatcher`, action `last_used`) — the plugin is a thin, Forensics-
/// gated read-only view over the TAR plugin's `usage_daily` sqlite fold
/// (agents/plugins/app_usage/src/app_usage_plugin.cpp). The server persists the
/// projection in `AppUsageStore` (server/core/src/app_usage_store.hpp).
///
/// HASH-SKIP over RAW bytes (mirrors `software_licensing`, ADR-0024 Decision 3 /
/// roadmap D-2): the server hash-skips on the SHA-256 of the RAW received blob
/// bytes, never re-derived from re-parsed rows. So this source needs only
/// STABLE bytes across collects of the same detected state (sort + dedup),
/// NOT a server-byte-identical canonicalisation. §3.3 field hygiene
/// (sync_canonical clamp_field) still applies as defence-in-depth.
///
/// CONSTRAINED OUTPUT (never an empty blob): the plugin reports
/// `constrained|...` (usage source disabled, older TAR schema, tar.db
/// unavailable) with rc==0 — a *legitimate* "nothing to say this cycle", not
/// "zero usage". Treating it as a valid empty replace would wipe stored
/// last-used state the next time the constraint lifts and a stale server view
/// would linger. So a constrained capture is parsed and SKIPPED (collect()
/// returns std::nullopt), exactly like a plugin-not-loaded / dispatch-failure
/// skip — never sent as an empty full payload.
///
/// ESCAPED exe_key (adjudication P5): the plugin escapes a literal '|' inside
/// exe_key as `\|` so the pipe-delimited line stays well-formed. Parsing
/// therefore splits only on UNESCAPED pipes and unescapes `\|` back to `|` in
/// the recovered exe_key — see the local mirror of
/// server/core/src/result_parsing.hpp:79-90's find_unescaped_pipe/
/// unescape_pipes in the .cpp (that header is not reachable from agent core).

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor, YUZU_EXPORT

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::agent {

/// One per-executable last-used summary (agent-local mirror of the server's
/// AppUsageStore row; kept agent-side so this module needs no server headers).
struct AppUsageRow {
    std::string exe_key;
    std::int64_t first_seen{0};       ///< first-seen epoch seconds, within TAR's retained usage
                                       ///< window (never all-time — see app_usage_parsers.hpp
                                       ///< RETENTION, adjudication P3)
    std::int64_t last_seen{0};        ///< last-seen epoch seconds, within TAR's retained usage
                                       ///< window (never all-time — see app_usage_parsers.hpp
                                       ///< RETENTION, adjudication P3)
    std::int64_t run_count_30d{0};    ///< trailing-30-day run count
    std::int64_t total_seconds_30d{0}; ///< trailing-30-day total run seconds
};

/// Result of parsing one `app_usage last_used` capture.
struct AppUsageParse {
    std::vector<AppUsageRow> rows; ///< `last_used|` rows only, fields clamped
    /// True iff the capture carried a `constrained|...` line (usage source
    /// disabled, older TAR schema, tar.db unavailable). When true the caller
    /// MUST skip the cycle — never send an empty blob for a constrained
    /// source (see the file header).
    bool constrained{false};
};

/// Parse the `app_usage` plugin's `last_used` action output
/// (agents/plugins/app_usage/src/app_usage_parsers.hpp `format_last_used_row`):
/// `last_used|<exe_key>|<last_seen>|<first_seen>|<run_count_30d>|<total_seconds_30d>`,
/// where a literal '|' inside `exe_key` arrives escaped as `\|` and is
/// unescaped back to `|` here (see the file header). `meta|` lines (not
/// emitted by `last_used`, but tolerated) are skipped; `constrained|...` sets
/// `constrained` and returns immediately (no rows are collected from a
/// constrained capture); any other/unknown line is skipped without error
/// (forward-compat). Fields are clamped via sync_canonical clamp_field;
/// numeric fields via a plain parse, clamped non-negative. Pure.
YUZU_EXPORT AppUsageParse parse_app_usage_last_used_output(const std::string& captured);

/// Render parsed rows to the wire blob: a leading `cfg|scope|machine` record
/// (fixed position — machine-scope only, this source carries no per-user
/// data), then `lu|<exe_key>|<first_seen>|<last_seen>|<run_count_30d>|
/// <total_seconds_30d>` records, 0x1F-field / 0x1E-record framed, sorted +
/// deduped for byte stability across collects of the same detected state (no
/// byte-identical-with-server requirement — the raw-byte hash removes that
/// burden). Pure.
YUZU_EXPORT std::string render_app_usage_blob(std::vector<AppUsageRow> rows);

/// Build the `app_usage` SyncSource. `descriptor` is the loaded `app_usage`
/// plugin descriptor; when null (plugin not built/loaded) the source's
/// collect returns std::nullopt and the scheduler no-ops it. 24 h interval.
YUZU_EXPORT SyncSource make_app_usage_source(const YuzuPluginDescriptor* descriptor);

} // namespace yuzu::agent
