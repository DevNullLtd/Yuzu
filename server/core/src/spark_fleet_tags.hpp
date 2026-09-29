#pragma once

/// @file spark_fleet_tags.hpp
/// Single source of truth for the SparkEngine heartbeat status-tag keys and the
/// forged-value-safe parse of their agent-supplied values. Shared by the
/// Prometheus rollup (AgentHealthStore::recompute_metrics → yuzu_fleet_spark_*)
/// and pinned by tests/unit/server/test_spark_fleet_tags.cpp so the gauge reader
/// and the agent emit site (agents/core/src/agent.cpp, the spark heartbeat block)
/// can never silently disagree about a key.
///
/// THE EDGE SHIPS FACTS, NEVER A VERDICT — counts only, no threshold/classification.
/// The agent (ADR-0021 Stage-2 rung 1) exports these OBSERVE-ONLY: with no
/// consumer armed, every counter reads 0 and only the two always-present keys
/// (`spark_running`, `spark_mechs`) carry signal — the running denominator and the
/// per-agent mechanism capability. The counters become non-zero once rung 2 arms
/// rules against the engine; the plumbing ships now so that cutover reports for
/// free. Emission is SPARSE: a counter tag is omitted when 0 (be-kind-to-network,
/// fleet-scale heartbeat) — an absent counter is 0 at the reader (the server
/// pre-nothing: an absent {os,mechanism} series simply does not contribute).
/// A spark-capable agent reports exactly ONE of four postures, and each is
/// distinguishable on the wire — this is the contract the reader is built on:
///
///   RUNNING   spark_running=1, spark_mechs=<CSV>, sparse counters
///   FAILED    spark_running=0                       (enabled, but boot threw)
///   DISABLED  spark_running=0, spark_disabled=1       (--spark-disable)
///   ABSENT    no yuzu.spark_* key at all (a pre-rung-1 agent, a dead one, or the
///             final beats of a gracefully-stopping one — a clean restart must never
///             be bucketed as FAILED)
///
/// So `--spark-disable` does NOT omit all spark tags — an earlier version of this
/// comment said it did, and that WAS the behaviour, which is exactly why a fleet-wide
/// spark boot FAILURE used to be invisible: it emitted nothing, identical to a
/// deliberate opt-out and to an agent that never had spark. Only RUNNING feeds the
/// reporting denominator; FAILED and DISABLED are counted separately (alert on the
/// former, never the latter).
///
/// Values are agent-supplied strings: accept only a finite, non-negative, full-token
/// integer parse below an implausibility ceiling; empty / garbage / negative / overflow
/// / implausible → nullopt, which the caller MUST treat as "did not report", never 0.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::detail {

// ── Hostile-input bounds (every spark tag value is fully agent-controlled) ─────
/// Max accepted length of the `yuzu.spark_mechs` CSV. Honest max is 21 bytes
/// ("file,registry,service"); 64 leaves room for ~2 future tokens. See
/// spark_mechs_from_csv() for why an unbounded value is a fleet-read DoS.
inline constexpr std::size_t kMaxSparkMechsCsvBytes = 64;
/// Max accepted value of any spark COUNT tag. These count per-endpoint watch
/// rejections / quarantines / slow ops — a real agent cannot approach this. Above it,
/// the value is treated as "did not report". See parse_spark_count() for why clamping
/// matters more than it looks (double-precision annihilation of the fleet sum).
inline constexpr unsigned long long kMaxPlausibleSparkCount = 1'000'000'000ULL;

// ── Fixed engine-level keys (at most one of each per reporting agent) ──────────
/// "1" = engine constructed AND running. "0" = NOT running: either it was disabled
/// (kSparkTagDisabled also present) or boot-time instantiation threw (it is not).
/// ABSENT = the agent ships no spark telemetry at all (pre-rung-1, dead, or
/// mid-graceful-shutdown).
/// Those three states must stay distinguishable — see spark_heartbeat.hpp.
inline constexpr const char* kSparkTagRunning = "yuzu.spark_running";
/// Present + "1" ONLY under --spark-disable. Its absence alongside running=="0" is
/// what identifies a boot FAILURE rather than a deliberate opt-out.
inline constexpr const char* kSparkTagDisabled = "yuzu.spark_disabled";
inline constexpr const char* kSparkTagMechs = "yuzu.spark_mechs";
inline constexpr const char* kSparkTagArmedFaulted = "yuzu.spark_armed_faulted";
inline constexpr const char* kSparkTagWatchFaults = "yuzu.spark_watch_faults";
inline constexpr const char* kSparkTagQueuedDropped = "yuzu.spark_queued_dropped";
inline constexpr const char* kSparkTagConsumerErrors = "yuzu.spark_consumer_errors";
/// #2270. Mechanism unwatch() calls that THREW during arm_impl's consumer-race
/// teardown, where the throw is contained rather than propagated. Registered HERE
/// even though no `yuzu_fleet_*` rollup consumes it yet: key registration is what
/// binds the agent writer to the server reader, and omitting it is exactly what let
/// the writer-reader guard case in test_spark_fleet_tags.cpp pass green against a key
/// it could not see (governance round 4 Gate 8 — sec8-1, doc8-3, SRE8-1). The {os}
/// rollup, the metrics.md row and an alert rule are deferred to the prefer_spark flip.
/// SCOPE: teardown_arm_race ONLY — see the sibling below for disarm(). Note
/// unregister_consumer() still propagates and is counted by NEITHER, so a zero across
/// both is not a fleet-wide all-clear.
inline constexpr const char* kSparkTagArmRaceUnwatchFailures =
    "yuzu.spark_arm_race_unwatch_failures";

/// The same residual on the ordinary disarm() teardown (#2270). Registered here for the
/// same reason as its sibling — key registration is what binds the agent writer to the
/// server reader — and its {os} rollup, metrics.md row and alert rule are deferred to the
/// prefer_spark flip in the same way. SCOPE: disarm() ONLY.
inline constexpr const char* kSparkTagDisarmUnwatchFailures =
    "yuzu.spark_disarm_unwatch_failures";

// ── Per-mechanism-type key composition ────────────────────────────────────────
// A per-type key is `kSparkTagPrefix + <mechanism-token> + "_" + <metric-suffix>`,
// e.g. "yuzu.spark_file_watch_rejected". The mechanism tokens below MUST equal
// spark_type_token() in agents/core/include/yuzu/agent/spark.hpp — the agent
// composes the identical string from spark_type_token(SparkType) — so a drift here
// (or there) is silent zero-reporting. The pin test asserts the composed literals.
inline constexpr const char* kSparkTagPrefix = "yuzu.spark_";

// Closed set of mechanism tokens the fleet rollup buckets by (the `mechanism`
// gauge label). Windows: file + registry + service; Linux: service; macOS: none.
// INVARIANT: this set must list every SparkType that becomes a REGISTERED mechanism
// (spark_type_token() output). The agent emits per-type keys for every registered
// type; a new registered mechanism whose token is missing here is silently dropped
// server-side (never bucketed) — extend this set in lockstep. (gov ca-N1)
inline constexpr const char* kSparkMechFile = "file";
inline constexpr const char* kSparkMechRegistry = "registry";
inline constexpr const char* kSparkMechService = "service";
inline constexpr const char* kSparkMechTokens[] = {kSparkMechFile, kSparkMechRegistry,
                                                   kSparkMechService};

// Per-type metric suffixes. The first three are SparkMechanismStats health
// counters surfaced per type (the ones that back the fleet alerts). `retiring`/
// `retiring_cap` is a per-mechanism teardown-backpressure internal (File's IOCP
// retirements; Registry's detached callback drains since PR-B1; 0 without
// arming churn) - it is summed at engine level in SparkEngineStats but its
// per-{os,mechanism} fleet rollup is deferred to rung 2, when arming makes it
// non-zero.
inline constexpr const char* kSparkMetricWatchRejected = "watch_rejected";
inline constexpr const char* kSparkMetricQuarantined = "quarantined";
inline constexpr const char* kSparkMetricSlowOp = "slow_op";
/// F7 (#2298 rung 2): NOT a SparkMechanismStats counter like its three siblings above
/// - its data source is GuardianEngine::unsupported_counts_by_type(), a per-rule
/// classification outcome, not a SparkEngine mechanism-health stat. Composed into the
/// SAME per-{mechanism} key family regardless (design doc places it in the
/// yuzu_fleet_spark_* Prometheus family) - verified safe this session: every
/// consumer of kSparkMetricTokens (the array-size-driven key-composition loop in
/// agent_registry.cpp, and test_spark_fleet_tags.cpp's reader-keys bind, which only
/// asserts emitted-keys-are-recognised, never the reverse) is agnostic to which
/// stats struct backs a given token. A CURRENT gauge, not cumulative, unlike its
/// three siblings - see guardian_unsupported_heartbeat.hpp.
inline constexpr const char* kSparkMetricUnsupported = "unsupported";
inline constexpr const char* kSparkMetricTokens[] = {
    kSparkMetricWatchRejected, kSparkMetricQuarantined, kSparkMetricSlowOp,
    kSparkMetricUnsupported};

/// Named indices into kSparkMetricTokens (and therefore into agent_registry.cpp's
/// spark_mech_metric_keys[mechanism][metric], which is built in this exact order).
/// F7 governance finding (consistency-auditor C1 / architect): the reader loop used
/// to index kSparkMetricTokens by bare literal (0/1/2/3) bound to its order only by
/// a comment - a future reorder or mid-array insertion would still compile, the
/// name-keyed WRITER side would still succeed, and the reader would silently
/// misattribute one health signal's fleet sum into another gauge family (e.g.
/// quarantined counted as watch_rejected), corrupting the family backing the
/// CRITICAL YuzuSparkMechanismQuarantined alert. These constants + the static_asserts
/// below make that a compile error instead.
inline constexpr std::size_t kSparkMetricIdxWatchRejected = 0;
inline constexpr std::size_t kSparkMetricIdxQuarantined = 1;
inline constexpr std::size_t kSparkMetricIdxSlowOp = 2;
inline constexpr std::size_t kSparkMetricIdxUnsupported = 3;
static_assert(kSparkMetricTokens[kSparkMetricIdxWatchRejected] == kSparkMetricWatchRejected);
static_assert(kSparkMetricTokens[kSparkMetricIdxQuarantined] == kSparkMetricQuarantined);
static_assert(kSparkMetricTokens[kSparkMetricIdxSlowOp] == kSparkMetricSlowOp);
static_assert(kSparkMetricTokens[kSparkMetricIdxUnsupported] == kSparkMetricUnsupported);
static_assert(std::size(kSparkMetricTokens) == 4,
              "a 5th metric token needs its own named index + static_assert above, "
              "and a new read line in agent_registry.cpp's recompute_metrics loop");

/// Compose a per-mechanism-type heartbeat key. MUST match the agent's own
/// composition byte-for-byte (see the header note above).
inline std::string spark_type_metric_tag(std::string_view mech_token, std::string_view metric) {
    std::string key;
    key.reserve(std::string_view(kSparkTagPrefix).size() + mech_token.size() + 1 + metric.size());
    key += kSparkTagPrefix;
    key += mech_token;
    key += '_';
    key += metric;
    return key;
}

/// Parse a `spark_mechs` CSV (the agent's registered mechanism tokens) into the
/// RECOGNISED closed-set tokens, DEDUPED, in encounter order, silently dropping any
/// token not in kSparkMechTokens (forged / future-value safe). Empty input -> empty.
/// De-dup matters because the fleet capability gauge counts one agent once per
/// mechanism: a forged/buggy repeated CSV ("service,service,…") must not inflate it
/// (gov sec-L1 / UP-3). An honest agent never repeats — it composes from a map's
/// unique keys — so the dedup is defence-in-depth, bounded by heartbeat tag size.
inline std::vector<std::string> spark_mechs_from_csv(std::string_view csv) {
    std::vector<std::string> out;
    // LENGTH CAP. The value is fully agent-controlled and re-read on EVERY
    // recompute_metrics sweep (~15s) under AgentHealthStore::mu_ — the lock heartbeat
    // ingest AND every dashboard/REST fleet read also take. Without a cap, an agent that
    // parks a multi-MB value here (bounded only by the 4 MB gRPC frame) is O(n)-scanned
    // forever. The honest maximum is 21 bytes ("file,registry,service"); 64 leaves
    // headroom for ~2 future tokens. Over-cap → "reported nothing", never a partial parse.
    //
    // SCOPE, HONESTLY (governance Gate-2 security): this closes the SCAN, not the whole
    // DoS. Two things sit outside it and are NOT fixed by this cap:
    //   - the caller's tag lookup, which used to COPY the value before this cap could be
    //     tested (fixed separately — recompute_metrics' `get` now returns string_view);
    //   - AgentHealthStore::upsert, which still deep-copies the ENTIRE agent-controlled
    //     tag map on every heartbeat with no key-count or value-length bound. That is a
    //     cross-cutting fix benefiting every tag family (net / DEX / spark alike) and is
    //     tracked as the heartbeat-tag ingest-bound follow-up (drafted at governance) — do not read this cap as "the ingest DoS is closed".
    if (csv.size() > kMaxSparkMechsCsvBytes)
        return out;
    for (std::size_t start = 0; start <= csv.size();) {
        const std::size_t comma = csv.find(',', start);
        const std::string_view tok = csv.substr(
            start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        for (const char* known : kSparkMechTokens)
            if (tok == known) {
                bool already = false;
                for (const auto& seen : out)
                    if (seen == known) {
                        already = true;
                        break;
                    }
                if (!already)
                    out.emplace_back(known);
                break;
            }
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

/// The agent's spark posture, parsed STRICTLY from `yuzu.spark_running`.
enum class SparkRunState {
    NotReported, ///< tag absent, or an unrecognised value — contribute to NOTHING
    Running,     ///< exactly "1"
    NotRunning,  ///< exactly "0" — the caller then splits DISABLED vs FAILED
};

/// Every OTHER agent-supplied spark value goes through a strict validator whose contract is
/// "garbage → did not report, never a value" (see parse_spark_count). `spark_running` was
/// the exception: the rollup bucketed `== "1"` as running and ANY other non-empty string as
/// not-running — so `"true"`, `" 1"`, `"01"`, `"2"` or `"x"` from one buggy or forked agent
/// build all landed in `yuzu_fleet_spark_failed{os}`, the ONE gauge documented "alert on
/// it". A single misbehaving agent could page on-call.
///
/// It is also a FORWARD-COMPAT trap: if a later rung adds a third posture value, an OLD
/// server would read it as FAILED and alarm the fleet during a rolling upgrade.
///
/// Strict now: only the two exact tokens mean anything; everything else is NotReported.
/// (governance Gate-4 UP-6 / consistency C-2.)
inline SparkRunState parse_spark_running(std::string_view s) {
    if (s == "1")
        return SparkRunState::Running;
    if (s == "0")
        return SparkRunState::NotRunning;
    return SparkRunState::NotReported;
}

/// Once `spark_running` parsed as NotRunning, this splits the deliberate opt-out
/// (DISABLED) from a boot failure (FAILED). It is the SAME forged-value class
/// parse_spark_running was hardened against, one level down: the discriminator used to be
/// a bare `spark_disabled == "1" ? disabled : failed`, so a buggy/forked agent that emitted
/// `spark_disabled="01"`/`"true"`/`"2"` while genuinely opted-out landed in
/// `yuzu_fleet_spark_failed{os}` — the ONE gauge with an active alert. A single misbehaving
/// agent could page on-call. (governance Gate-4 UP-3.)
///
/// The writer contract (spark_heartbeat.hpp emit_spark_absent_tags): DISABLED emits
/// `spark_disabled="1"`; FAILED emits the key NOT AT ALL. So "1" is the only Disabled token,
/// and an ABSENT key (empty view) is the conforming FAILED posture. "0" is accepted as an
/// explicit not-disabled for symmetry with parse_spark_running's two-token strictness even
/// though the writer never emits it. Every OTHER value is Unknown → the caller counts it in
/// NEITHER bucket, so garbage never fabricates a FAILED alert (mirrors parse_spark_running's
/// "garbage → contribute to nothing").
enum class SparkDisabledState {
    Disabled,    ///< exactly "1" — the deliberate --spark-disable opt-out
    NotDisabled, ///< absent (conforming FAILED) or exactly "0"
    Unknown,     ///< any other value — count in neither bucket, never page
};

inline SparkDisabledState parse_spark_disabled(std::string_view s) {
    if (s == "1")
        return SparkDisabledState::Disabled;
    if (s.empty() || s == "0")
        return SparkDisabledState::NotDisabled;
    return SparkDisabledState::Unknown;
}

/// Forged-value-safe parse of an agent-supplied spark COUNT (a non-negative
/// integer tag). Full-token parse only; empty / garbage / negative / overflow →
/// nullopt (the caller treats nullopt as "did not report", never 0).
///
/// IMPLAUSIBILITY CLAMP: a value above kMaxPlausibleSparkCount is REJECTED (nullopt),
/// not clamped-and-counted. These gauges are a fleet SUM accumulated into a `double`,
/// so a single agent reporting near-UINT64_MAX (~1.8e19) does not merely dominate the
/// sum — it makes every honest agent's +1 a NO-OP, because 1.8e19 + 1 == 1.8e19 in
/// IEEE-754 double. One compromised endpoint could permanently destroy the fleet
/// signal for every other agent, and at rung 2 (alerts enabled) page on a single
/// forged tag. No honest agent can reach this: these count watch rejections /
/// quarantines / slow ops on one endpoint. (governance Gate-4 UP-7.)
inline std::optional<double> parse_spark_count(std::string_view s) {
    // LENGTH CAP BEFORE PARSE. kMaxPlausibleSparkCount (1e9) is 10 digits, so any
    // longer token is implausible by construction — reject it in O(1) WITHOUT letting
    // from_chars scan it. Without this, a hostile agent parking a multi-megabyte
    // all-digit value in each of the 13 count tags gets them O(n)-scanned on every
    // 15 s sweep UNDER AgentHealthStore::mu_ — the same unbounded-scan class the
    // 64-byte CSV cap exists for (governance Gate-3 performance S1). The value bytes
    // still sit in the tag map until the store-level ingest bound lands (tracked:
    // heartbeat-tag ingest-bound follow-up); this cap only keeps the scan out of the
    // sweep's critical section.
    if (s.empty() || s.size() > 10)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleSparkCount)
        return std::nullopt; // implausible → "did not report", never poison the sum
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
