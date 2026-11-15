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
#include <iterator>
#include <memory>
#include <optional>
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
struct GuaranteedStateEventRow;
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

/// The agent's wire timestamp as nanoseconds since the epoch, or nullopt when it cannot be used.
/// The wire field is untrusted protobuf input: it must be present, `nanos` must be in [0, 1e9)
/// and `seconds` must be in [0, INT64_MAX / 1e9 - 1] (9,223,372,035), so `seconds * 1e9 + nanos`
/// cannot overflow. An ABSENT timestamp reads as seconds()==0 and must not be taken for a real
/// epoch-0 instant, so it is nullopt too. This is the ONE validation of the stamp: the row's
/// `agent_ns` (the census ordering key input) and the T_server diagnostic line both use it.
[[nodiscard]] std::optional<std::int64_t> agent_stamp_ns(bool has_timestamp, std::int64_t seconds,
                                                         std::int32_t nanos) noexcept;

/// Counter of events the ingest boundary refuses before they reach the store, by `reason`
/// (today only `empty_rule_id`: an event with no rule id cannot be projected or matched and is
/// not stored). Warm-created at startup (server.cpp) so the series reads 0, not absent.
inline constexpr char kGuardianEventsRejectedMetric[] =
    "yuzu_server_guardian_events_rejected_total";

/// The limits on a wire pair, in ONE place (the store's `census_pair` and `pair_from_wire` both
/// read them). Each half of a pair is in [1, `kPairValueLimit`): below 2^62 the BIGINT sign bit is
/// unreachable. On top of that (UP-9) a pair must be PLAUSIBLE: `emit_seq` below `kEmitSeqCeiling`
/// (2^40, about 1.1e12 events in one boot) and `boot_epoch` (Unix seconds) at most
/// `kEpochSkewSeconds` (ten years of 365.25 days) past the server's receipt time. A pair that
/// passes the range check and fails this one is `Implausible`: one such pair accepted would pin an
/// agent's pair clock above every honest event for the life of the row, because only a higher pair
/// advances the clock. The bound is absolute and stateless; a pair inside it is still judged by the
/// pair clock (an agent whose clock was pinned by a value just inside it heals when the hold
/// expires, one hour after the last accepted event).
inline constexpr std::uint64_t kPairValueLimit = std::uint64_t{1} << 62;
inline constexpr std::uint64_t kEmitSeqCeiling = std::uint64_t{1} << 40;
inline constexpr std::int64_t kEpochSkewSeconds = 315'576'000;

/// Why a wire emit-order pair was not taken as a pair (D5). `None` covers both a valid pair and
/// the legitimate unpaired 0/0 (a journal replay, or an agent whose epoch claim failed); neither is
/// counted. `Implausible` (UP-9) is a structurally valid pair outside the absolute bound above. It
/// is handled exactly like the other two: the pair is dropped HERE, once, and the event is judged
/// as an unpaired one at first delivery (stored pair NULL, the normal unpaired census write). No
/// later stage knows the reason.
enum class PairReject { None, HalfSet, OutOfRange, Implausible };

/// The wire `(boot_epoch, emit_seq)` pair as validated at the ingest boundary: `paired` is true
/// only when BOTH are set and each is in [1, 2^62) (2^62 - 1 is accepted), so the values fit a
/// signed BIGINT with the sign bit unreachable. Both zero is unpaired and not a rejection.
/// Exactly one zero is `HalfSet` (checked first, so a lone value >= 2^62 beside a zero is still
/// half-set); either value >= 2^62 beside a set partner is `OutOfRange`. Either rejection is
/// unpaired too: the event is still stored, only the pair is withheld.
struct WirePair {
    bool paired{false};
    std::int64_t boot_epoch{0};
    std::int64_t emit_seq{0};
    PairReject reject{PairReject::None};
};
[[nodiscard]] WirePair pair_from_wire(std::uint64_t boot_epoch, std::uint64_t emit_seq) noexcept;

/// The production form (UP-9): the structural check above, then the absolute plausibility bound
/// (`kEmitSeqCeiling`, `kEpochSkewSeconds`) against `receipt_unix_s`, the server's receipt time in
/// whole Unix seconds. A pair that fails only the bound is `Implausible` (unpaired, `paired`
/// false). The two-argument form checks structure only and exists for callers with no receipt; the
/// ingest boundary never uses it (production ingest must use this overload, or the bound is not
/// applied).
[[nodiscard]] WirePair pair_from_wire(std::uint64_t boot_epoch, std::uint64_t emit_seq,
                                      std::int64_t receipt_unix_s) noexcept;

/// Counter of wire emit-order pairs the ingest boundary withheld, by `reason` (`half_set`,
/// `out_of_range`, `implausible`). Not a refusal: the event is stored. A withheld pair of any of
/// the three reasons is judged as an unpaired event (the census row's stored pair becomes
/// NULL/NULL only when that unpaired verdict is applied). This is separate from
/// `kGuardianEventsRejectedMetric`. Counted once per withheld pair: only when the store reports the
/// event `Inserted`, so a redelivery of the same event does not count again. Pre-seeded
/// (server.cpp) from `kGuardianPairRejectReasons` so each series reads 0, not absent. Never
/// labelled by agent.
inline constexpr char kGuardianPairRejectedMetric[] = "yuzu_server_guardian_pair_rejected_total";
inline constexpr const char* kGuardianPairRejectReasons[] = {"half_set", "out_of_range",
                                                             "implausible"};

/// Counter of census decisions by `decision` (the closed `CensusDecision` set,
/// `guardian_pair_mode.hpp`), one per census write whose upsert returned a labelled row and whose
/// savepoint released: a first delivery, a Repair and a batch row. A key-mode event the key rule
/// refuses has no label and counts nothing. Best-effort and counted
/// before the transaction commits, as the projection counter is. Pre-seeded (server.cpp) from
/// `kCensusDecisions` so each series reads 0, not absent. Never labelled by agent.
inline constexpr char kGuardianCensusPairDecisionsMetric[] =
    "yuzu_server_guardian_census_pair_decisions_total";

/// The ONE place a `PairReject` becomes its label, so the counter series, the pre-seed loop and the
/// log line cannot drift from `kGuardianPairRejectReasons`. `None` has no reason (empty).
[[nodiscard]] constexpr const char* pair_reject_reason(PairReject r) noexcept {
    switch (r) {
    case PairReject::HalfSet:
        return kGuardianPairRejectReasons[0];
    case PairReject::OutOfRange:
        return kGuardianPairRejectReasons[1];
    case PairReject::Implausible:
        return kGuardianPairRejectReasons[2];
    case PairReject::None:
        break;
    }
    return "";
}
static_assert(std::size(kGuardianPairRejectReasons) ==
                  static_cast<std::size_t>(PairReject::Implausible),
              "one reason label per PairReject value other than None");
static_assert(std::string_view(pair_reject_reason(PairReject::HalfSet)) == "half_set" &&
                  std::string_view(pair_reject_reason(PairReject::OutOfRange)) == "out_of_range" &&
                  std::string_view(pair_reject_reason(PairReject::Implausible)) == "implausible",
              "the reason labels are the documented series values");

/// Validate the wire pair and, when it is a pair, set `row.boot_epoch`/`row.emit_seq`; otherwise
/// leave both unset. Returns why the pair was withheld, or `nullopt` when it was taken or the sender
/// is unpaired (0/0). Pure: it neither logs nor counts, because the caller must do that only once
/// the store has accepted the event (`report_pair_reject`). Never refuses the event.
[[nodiscard]] std::optional<PairReject> apply_wire_pair(GuaranteedStateEventRow& row,
                                                        std::uint64_t boot_epoch,
                                                        std::uint64_t emit_seq);

/// The production form (UP-9): as above with the plausibility bound applied against
/// `receipt_unix_s`. An `Implausible` pair leaves `boot_epoch`/`emit_seq` unset and is returned as
/// the reason, like `HalfSet` and `OutOfRange`; it is decided once, here, and nothing downstream
/// distinguishes it (a Repair reads the stored unset pair).
[[nodiscard]] std::optional<PairReject> apply_wire_pair(GuaranteedStateEventRow& row,
                                                        std::uint64_t boot_epoch,
                                                        std::uint64_t emit_seq,
                                                        std::int64_t receipt_unix_s);

/// Warn (agent and event ids sanitised) and count one withheld pair on `kGuardianPairRejectedMetric`
/// (best-effort; `metrics` may be nullptr). Called once per pair, after the store reports the event
/// `Inserted`; never for a redelivery, so a durable agent journal replaying the event does not
/// inflate the series.
void report_pair_reject(PairReject reject, const GuaranteedStateEventRow& row,
                        yuzu::MetricsRegistry* metrics);

/// Gauge of agents "currently unordered": the latest accepted unpaired census-bearing event is
/// later than the agent's pair clock, or the pair clock is recorded more than 300 s in the
/// database's future (the sweep reads `GuaranteedStateStore::unordered_agent_count`, the count-only
/// twin of `unordered_agents`, and both use the one SQL predicate). The value depends on the
/// database clock, so it can change between two sweeps with no event. Fleet-wide, no
/// labels (never by agent: the per-agent view is the `ordering` field of the per-device read).
/// Described in server.cpp and deliberately NOT pre-seeded, like `..._census_pending_events`: a
/// zero before the first answered read would read as "no unordered agents".
inline constexpr char kGuardianCensusUnorderedAgentsMetric[] =
    "yuzu_server_guardian_census_unordered_agents";

/// Periodic-sweep body for `kGuardianCensusUnorderedAgentsMetric`: reads the fleet-wide count and
/// sets the gauge ONLY when the store answered. A store that cannot answer leaves the previous
/// sample in place (a failed read must not publish a fresh zero).
void publish_guardian_census_unordered_gauge(yuzu::MetricsRegistry& metrics,
                                             const GuaranteedStateStore& store);

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

/// Birth every `decision` series of `kGuardianCensusPairDecisionsMetric` (the closed
/// `kCensusDecisions` set) at 0, so each reads 0 rather than absent from boot. Call once at startup
/// (server.cpp) and in tests that assert the family.
void preseed_census_pair_decision_metric(yuzu::MetricsRegistry& metrics);

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

/// Test-only fault injection for create_t_server_logger()'s pool/logger construction step
/// (governance Gate 8 follow-up, closes a gap cpp-safety flagged: every throw site was traced by
/// hand and reasoned to unwind cleanly, but none was test-covered) -- mirrors
/// agents/core/src/log_handoff.hpp's LogHandoff::set_construction_fault_for_test() exactly,
/// including its consumption contract: the flag is consumed (reset to false) by the very next
/// create_t_server_logger() call, whether or not that call is the one the test intended, so it
/// never leaks into a later, unrelated test. Production callers never set this.
void set_t_server_construction_fault_for_test(bool fail) noexcept;

} // namespace yuzu::server::detail
