#pragma once

/// @file guardian_ingest.hpp
/// Shared ingest for Guardian "__guard__" side-channel CommandResponses.
///
/// Both the direct Subscribe read loop (AgentServiceImpl) and the
/// gateway-proxied path (GatewayUpstreamServiceImpl::ForwardGuardianMessage)
/// route unsolicited "__guard__" responses through this one function so the
/// two paths cannot diverge (the spec_json-style divergence bug class). The
/// `agent_id` is supplied by the caller — cert-bound on the direct path,
/// gateway-asserted on the gateway path — and is NEVER read from the frame.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/common.h> // spdlog::sink_ptr, spdlog::level::level_enum -- lightweight, no logger/thread_pool machinery

#include "agent.pb.h"

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class GuaranteedStateStore;
class BlastRadiusDetector;
class DexAlertRouter;
}

namespace spdlog {
class logger;
}

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

/// Ingest one Guardian side-channel CommandResponse. The caller must have
/// already verified `resp.plugin() == "__guard__"`. Dispatches by `action`:
///   "event" → parse the GuaranteedStateEvent from `payload`, enrich severity
///             from the rule store, insert into the events table.
///   other   → logged and dropped (the channel is generic; a future "status"
///             message must not crash this path).
/// Never touches the response store / executions drawer.
///
/// `blast_radius` (optional): fed each successfully-inserted RULELESS
/// observation so fleet-wide incident detection sees both the direct and the
/// gateway path through this one chokepoint (docs/dex-brd-coverage.md D3).
/// nullptr disables detection (tests / detector-less configs).
///
/// `alert_router` (optional, F1): fed the same ruleless observations so
/// operator-routed per-signal alerts also cover both wire paths. nullptr
/// disables routing.
///
/// `metrics` (optional): when non-null, times exactly the `insert_event_classified`
/// store call and observes it into `kGuardianEventStoreDurationMetric` under the
/// event's outcome `status` label (inserted|redelivered|conflict|error). Threaded
/// through this one chokepoint so the direct and gateway paths time identically.
/// nullptr disables timing (tests / metrics-less configs).
void ingest_guardian_response(GuaranteedStateStore& store, const std::string& agent_id,
                              const pb::CommandResponse& resp,
                              BlastRadiusDetector* blast_radius = nullptr,
                              DexAlertRouter* alert_router = nullptr,
                              yuzu::MetricsRegistry* metrics = nullptr);

/// Prometheus metric name for the store-operation latency histogram: server-side latency of
/// `insert_event_classified` (the classify+store SQLite txn) for one Guardian event, split by
/// outcome `status`. Shared by the observe site (guardian_ingest.cpp) and the describe +
/// warm-create site (server.cpp) so the name cannot drift between them.
inline constexpr char kGuardianEventStoreDurationMetric[] =
    "yuzu_server_guardian_event_store_duration_seconds";

/// The custom bucket ladder for that histogram - sub-millisecond (SQLite single-row insert)
/// through the seconds tail (Postgres / lock contention). Boundaries are fixed at first series
/// creation, so warm-create and any observe MUST agree; this is the single source.
[[nodiscard]] std::vector<double> guardian_event_store_buckets();

/// Birth all four `status` series (inserted|redelivered|conflict|error) with the custom ladder
/// so the boundaries are pinned before the first observe and the series appear on /metrics from
/// boot. Call once at startup (server.cpp) and in tests that assert the histogram.
void warm_create_guardian_event_store_metric(yuzu::MetricsRegistry& metrics);

// ── #4666 PR-4: dedicated bounded async logger for the T_server diagnostic line ─────────────
//
// The "Guardian T_server ..." line (ingest_guardian_response's Inserted/non-observation arm,
// guardian_ingest.cpp) runs on the server's gRPC Subscribe read thread, or on the gateway
// forwarding path's thread. Before this seam it went through spdlog's process default logger,
// which is synchronous on the server (unlike the agent, async since #4666 PR-1/PR-2) -- a
// stalled sink (an undrained pipe, a stuck network-mounted log path) blocked that thread. This
// seam mirrors agents/core/src/log_handoff.hpp's async_logger/thread_pool/overrun_oldest
// pattern, much more lightly: no teardown watchdog is built here -- ACCEPTED, not eliminated
// (adversarial-review finding, 2026-09-28, corrects an earlier draft of this comment). The
// server's hard-exit machinery (main.cpp's on_signal_hard_exit) is signal-DRIVEN, not
// self-armed: the FIRST SIGINT/SIGTERM takes the graceful Server::stop() path (main.cpp's
// g_signal_count check escalates only on a SECOND signal, already consumed by the first), so a
// sink that stalls mid-drain leaves this pool's exit-time worker join bounded only by a SECOND
// signal or the deployment's external stop deadline (systemd TimeoutStopSec=210s / Compose
// stop_grace_period: 210s), never by "a single SIGTERM" alone. That exit-time join is a
// genuinely new blocking point (the pre-existing synchronous default logger owns no worker to
// join at teardown) -- accepted because the 210s external bound already exists and T_server is
// a temporary #4606 benchmark diagnostic PR-7 retires; no heartbeat/metrics tags either
// (out of scope for this PR).
//
// create_t_server_logger() is best-effort BY CONSTRUCTION (never EXIT_FAILURE, never refuses to
// start): a thread-creation refusal is caught internally and logged via spdlog's default logger,
// returning nullptr. main.cpp additionally wraps its own spdlog::register_logger() call (a
// duplicate logger name throws) the same way -- either failure just leaves the T_server logger
// unset. The call site (guardian_ingest.cpp) is null-safe: with nothing installed it skips the
// T_server line and counts it via t_server_log_skipped_total_for_test() instead.
//
// LEVEL, NOT FORMAT, is why this is registered at all: the returned logger is built over COPIES
// of the caller's sink list (main.cpp passes spdlog::default_logger()->sinks() copies -- owned
// shared_ptrs, so this stays valid even if the default logger is later replaced), so its
// formatter/pattern already match the default logger's (sinks are literally shared) with no
// registration needed. spdlog::set_level()'s registry-wide reach (the --log-level/config-reload
// override) is the part that does NOT retroactively apply to an unregistered logger -- only
// spdlog::registry::initialize_logger() does that, and register_logger() alone does not call it
// -- so `level` is applied explicitly via logger->set_level() inside create_t_server_logger(),
// mirroring the existing default-logger level-setting line in main.cpp.
[[nodiscard]] std::shared_ptr<spdlog::logger>
create_t_server_logger(std::vector<spdlog::sink_ptr> sinks, spdlog::level::level_enum level);

/// Installs (or clears, with `nullptr`) the logger the T_server call site resolves through.
/// main.cpp calls this once at boot with create_t_server_logger()'s result (a no-op call with
/// nullptr if construction failed, matching the null-safe default). Tests use it to inject a
/// SYNCHRONOUS capture logger for the span of one TEST_CASE and MUST restore `nullptr` before
/// that capture's backing sink is destroyed (see tests/unit/server/test_guardian_ingest.cpp's
/// TServerLoggerCapture) -- a seam still pointing at a freed ostream is a use-after-free the
/// very next TEST_CASE's T_server line would hit.
void set_t_server_logger(std::shared_ptr<spdlog::logger> logger);

/// Count of T_server lines skipped because no logger was installed on this seam (construction
/// failed, registration failed, or nothing has called set_t_server_logger() yet). Zero in a
/// healthy running server; test-only accessor -- not surfaced on any production metric/heartbeat
/// (out of scope for this PR, see #5024's equivalent agent-side item).
[[nodiscard]] std::uint64_t t_server_log_skipped_total_for_test();

} // namespace yuzu::server::detail
