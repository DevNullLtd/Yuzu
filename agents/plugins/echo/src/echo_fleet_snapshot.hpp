#pragma once

/**
 * echo_fleet_snapshot.hpp -- JSON builder for the echo.fleet_snapshot action
 *
 * Pure free function that takes already-collected process and connection
 * inventories plus the host's local IPs and emits a single JSON document
 * conforming to the fleet_snapshot.v1 schema. Factored out of echo_plugin.cpp
 * so it can be unit-tested without instantiating the plugin or stubbing
 * CommandContext.
 *
 * Schema (one JSON object):
 *   {
 *     "schema": "fleet_snapshot.v1",
 *     "schema_minor": 1,
 *     "ts": <int64_t epoch seconds>,
 *     "hostname": <string>,
 *     "local_ips": [<string>, ...],
 *     "processes": [
 *       {"pid":<u32>, "ppid":<u32>, "name":<string>,
 *        "cmdline":<string|"[REDACTED by Echo]">, "user":<string>}, ...
 *     ],
 *     "connections": [
 *       {"proto":<string>, "local_addr":<string>, "local_port":<int>,
 *        "remote_addr":<string>, "remote_host":<string>, "remote_port":<int>,
 *        "state":<string>, "pid":<u32>, "process_name":<string>}, ...
 *     ],
 *     "truncated_processes": <bool>,
 *     "truncated_connections": <bool>,
 *     "process_source_paused": <bool>,    // optional, only when true
 *     "tcp_source_paused":     <bool>     // optional, only when true
 *   }
 *
 * `schema_minor` allows additive evolution (e.g. PR 7 adding rss_kb) without
 * a breaking version bump. Consumers MUST ignore unknown keys.
 */

#include "echo_collectors.hpp"
#include "echo_db.hpp" // NetworkEvent (input shape from query_recent_tcp_connections)

#include <yuzu/agent/process_enum.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::echo {

/// Hard cap on each list to bound payload size on busy hosts. Empirically a
/// fully-populated snapshot at this cap (4096 procs + 4096 conns) is ~1.3 MB
/// of JSON; realistic hosts emit 50-500 KB. Truncation flags inform the
/// server when the cap is hit so the operator can investigate.
inline constexpr int kFleetSnapshotMaxRows = 4096;

/**
 * Build the fleet_snapshot.v1 JSON document.
 *
 * @param processes        Process inventory (cmdline will be redacted in-place
 *                         per redaction_patterns; original input is not modified).
 * @param connections      Network connection inventory.
 * @param local_ips        Host-bound non-loopback non-link-local IPs.
 * @param hostname         Reporting host's name.
 * @param ts               Epoch seconds at snapshot time.
 * @param redaction_patterns  Glob patterns for cmdline redaction (e.g. "*password*").
 * @param process_source_enabled  When false, emits process_source_paused=true
 *                                so the renderer can show "partial observation".
 * @param tcp_source_enabled      Same for the tcp source.
 * @param max_rows         Truncation cap per list (defaults to kFleetSnapshotMaxRows).
 *
 * @return Single-line JSON string (no trailing newline).
 */
std::string build_fleet_snapshot_json(
    const std::vector<yuzu::agent::ProcessInfo>& processes,
    const std::vector<NetConnection>& connections, const std::vector<std::string>& local_ips,
    const std::string& hostname, int64_t ts,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns,
    bool process_source_enabled = true, bool tcp_source_enabled = true,
    int max_rows = kFleetSnapshotMaxRows);

/**
 * Merge the live `/proc/net/tcp` snapshot with the Echo warehouse's recent
 * observations so the viz can render any connection that existed within
 * the recent window as a tube — not just those still ESTABLISHED at the
 * exact sample moment.
 *
 * Live rows are emitted first with `last_seen_seconds_ago = 0`. Recent
 * rows are appended only when their (proto, local_addr, local_port,
 * remote_addr, remote_port, pid) 5-tuple does NOT match any live row;
 * matched rows are dropped because /proc has the more authoritative
 * current state. For each surviving recent row, `last_seen_seconds_ago`
 * is computed as `max(0, now_ts - recent.ts)` so the renderer can fade
 * older tubes.
 *
 * Pure function — no I/O. The plugin orchestration produces `live` from
 * `enumerate_connections()` and `recent` from
 * `EchoDatabase::query_recent_tcp_connections(now - window)`.
 */
std::vector<NetConnection>
merge_live_and_recent_connections(const std::vector<NetConnection>& live,
                                  const std::vector<NetworkEvent>& recent, int64_t now_ts);

} // namespace yuzu::echo
