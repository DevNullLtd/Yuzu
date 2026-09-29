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

#include <string>
#include <string_view>
#include <vector>

#include "agent.pb.h"

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class GuaranteedStateStore;
class BlastRadiusDetector;
class DexAlertRouter;
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

} // namespace yuzu::server::detail
