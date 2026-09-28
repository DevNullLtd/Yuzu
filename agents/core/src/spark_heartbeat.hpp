#pragma once

/// @file spark_heartbeat.hpp
/// Pure composition of the SparkEngine fleet-telemetry heartbeat tags (ADR-0021
/// Stage-2 rung 1). Extracted from the agent heartbeat lambda so the exact emitted
/// keys + the sparse-emit rule are unit-testable without standing up a heartbeat
/// thread. The keys are pinned to server/core/src/spark_fleet_tags.hpp by
/// tests/unit/server/test_spark_fleet_tags.cpp (the reader side); this header is the
/// writer side.
///
/// ── THE FOUR POSTURES ────────────────────────────────────────────────────────────
/// A spark-capable agent is always in exactly one of these, and each is DISTINGUISHABLE
/// on the wire. That distinguishability is the point of rung 1 — an engine that failed
/// to boot must not look like one that was never asked to (governance Gate-4
/// consistency + UP-10):
///
///   RUNNING   yuzu.spark_running=1, yuzu.spark_mechs=<CSV>, sparse counters
///   FAILED    yuzu.spark_running=0                       (enabled, but boot threw)
///   DISABLED  yuzu.spark_running=0, yuzu.spark_disabled=1  (--spark-disable)
///   ABSENT    no yuzu.spark_* key at all (a pre-rung-1 agent, a dead one, or the
///             final beats of a gracefully-stopping one — see the stop_requested_
///             guard in agent.cpp's heartbeat block)
///
/// Before this, FAILED emitted nothing — byte-identical to DISABLED and to ABSENT. A
/// fleet where spark failed to boot on 30% of endpoints was therefore *unobservable*,
/// which defeats rung 1's stated purpose ("prove the engine runs and reports at rest").
/// The DEX sibling already got this right: it emits `yuzu.dex_observer_armed = "0"`
/// when enabled-but-deaf rather than going quiet.

#include <map>
#include <string>
#include <utility>

#include <yuzu/agent/spark.hpp> // spark_type_token

#include "spark_engine.hpp"    // SparkEngineStats, SparkType
#include "spark_mechanism.hpp" // SparkMechanismStats

namespace yuzu::agent {

/// FAILED / DISABLED: the engine is not running, so there is nothing to report but the
/// fact itself. `disabled` distinguishes the deliberate opt-out from a boot failure.
template <typename TagMap>
void emit_spark_absent_tags(TagMap& tags, bool disabled) {
    tags["yuzu.spark_running"] = "0";
    if (disabled)
        tags["yuzu.spark_disabled"] = "1";
}

/// RUNNING: populate `tags` with the spark fleet telemetry. `TagMap` is any map with a
/// string `operator[]` (the protobuf status_tags map in production, std::map in tests).
///
/// `running` MUST come from `SparkEngine::is_running()` — never from "the pointer is
/// non-null". After Agent::stop() calls spark_engine_->stop() the pointer is still
/// non-null, so a hardcoded "1" would ship a healthy-looking capability report from a
/// STOPPED engine (governance Gate-4 UP-4).
///
/// SPARSE: a counter tag is omitted when 0 (fleet-scale, and every counter is 0 at
/// rung 1), so a quiescent agent ships only the two always-present capability keys.
///
/// #2833 — WHAT THIS FUNCTION CANNOT REPORT, AND WHY THE FIX IS NOT HERE. The !running
/// early-return below is not the only gate, and it is not the binding one. The agent's
/// heartbeat composer emits NOTHING AT ALL once stop_requested_ is set
/// (agent.cpp:2582 / :3311). The two shutdown paths' spark-stop and heartbeat-join calls
/// (agent.cpp:1086 / :3345 vs :3125 / :3774) run on different threads and are not
/// ordered relative to each other, but that ordering isn't what makes this
/// unreachable — the stop_requested_ gate above and emit_spark_heartbeat_tags()'s own
/// !running early-return each independently suppress it regardless of interleaving. So
/// every counter that can ONLY increment during teardown — the two unwatch-failure
/// counters' shutdown-window
/// increments, and teardown_join_timeouts_total in its entirety — is structurally
/// unreachable from here no matter what this function does. Adding a tag for one of them
/// would be inert on the wire.
///
/// Consequence for whoever comes looking: a zero reading for `yuzu.spark_*_unwatch_failures`
/// during a shutdown is NOT evidence that nothing was orphaned; the journal
/// (spdlog::error at each increment site in spark_engine.cpp) is the only egress in that
/// window. If a future change genuinely needs teardown telemetry off the box, the gate to
/// move is the AGENT's, and it is there on purpose — STOPPED is not FAILED, and bucketing
/// a cleanly-stopping agent into yuzu_fleet_spark_failed{os} would page on-call on every
/// restart. Pinned by "#2833 — a shutdown-window unwatch failure is counted but has NO
/// heartbeat egress" in test_spark_mechanism.cpp.
///
/// The `yuzu.spark_mechs` CSV lists only mechanisms that are registered AND FUNCTIONAL.
/// An inert mechanism, one that started but could not bind its OS facility (no systemd
/// system bus in a container, OpenSCManager denied, IOCP creation failed), or one whose
/// worker is in persistent pass failure (Registry and File; three consecutive failed passes,
/// cleared on the next success), is EXCLUDED, because it is not currently serviceable:
/// the first kind refuses every watch(), the second accepts it but cannot serve it until a
/// pass succeeds. Listing it would advertise a capability the agent cannot honour:
/// "looks healthy, can detect nothing" (governance Gate-3 cross-platform + Gate-6 sre,
/// reached independently).
///
/// HOW AN INERT MECHANISM IS OBSERVED, precisely. Inertness suppresses the CAPABILITY CLAIM
/// (the CSV above), not the telemetry: the per-type counter loop below does NOT skip inert
/// mechanisms, so a non-zero counter on one IS reported. The Service mechanism tracks none
/// of those counters, so its stats are all-zero and the sparse rule drops every tag. File
/// and Registry do track them (slow_op, watch_rejected, quarantined), so a File or Registry
/// runtime-inert episode can carry non-zero cumulative counters. That is a property of which
/// counters exist, NOT a rule the code enforces: do not rely on an inert mechanism emitting
/// nothing.
///
/// An inert mechanism is therefore visible as a CAPABILITY GAP on the server, per mechanism:
/// the agents reporting for an OS minus the agents listing that mechanism. That comparison is
/// only valid where the mechanism is expected on every agent of that OS, and an OS reports
/// several mechanism series per agent, so comparing `reporting` with their SUM never fires.
/// The absent-safe query form (a bare subtraction returns nothing when the mechanism series
/// is missing on every agent) is documented in `docs/user-manual/metrics.md`.
///
/// (Two earlier versions of this comment contradicted each other here — one claimed inert
/// mechanisms "still report their counters", the next that they "emit NOTHING of their own"
/// as an invariant. The reconciled statement above is what the code actually does.
/// governance Gate-8 round 7 consistency N-3.)
template <typename TagMap>
void emit_spark_heartbeat_tags(TagMap& tags, bool running, const SparkEngineStats& ss,
                               const std::map<SparkType, SparkMechanismStats>& by_type) {
    if (!running) {
        // CONSTRUCTED BUT NOT RUNNING → emit NOTHING (the ABSENT posture). Do NOT fall
        // through to FAILED.
        //
        // The overwhelmingly common way to reach this is a GRACEFUL SHUTDOWN: Agent::stop()
        // and run()'s ScopeExit both call spark_engine_->stop(), and the heartbeat thread
        // can compose one more beat before it is joined. Reporting FAILED there would have
        // the server count a cleanly-stopping agent into yuzu_fleet_spark_failed{os} — the
        // ONE gauge documented "alert on it" — so every `systemctl restart`, every reboot
        // and every OTA cycle would page on-call with a fault that never happened.
        // STOPPED is not FAILED (governance Gate-2 security + Gate-3 cross-platform, found
        // independently).
        //
        // FAILED is therefore reserved for exactly one condition, decided by the CALLER:
        // spark was ENABLED but the engine is NULL because boot-time instantiation threw.
        return;
    }
    tags["yuzu.spark_running"] = "1";
    // Capability: the registered AND functional mechanism types, as a CSV.
    std::string mechs;
    for (const auto& [type, ms] : by_type) {
        // `.inert` here is deliberately the UNION of boot-inert and runtime-degraded
        // (both reasons this CSV should stop advertising the type as a capability) -
        // NOT the narrower boot-inert-only signal Guardian's capability filter reads
        // (guardian_engine.cpp's reconcile_rule_locked, #4685): a transient
        // runtime-degraded mechanism stays armable there, but has nothing to serve
        // right now, so it correctly drops out of THIS CSV for that same window.
        if (ms.inert)
            continue; // registered but not currently serviceable: not a capability
        if (!mechs.empty())
            mechs += ',';
        mechs += spark_type_token(type);
    }
    tags["yuzu.spark_mechs"] = std::move(mechs); // last use
    // Engine-level counters (sparse).
    if (ss.armed_faulted > 0)
        tags["yuzu.spark_armed_faulted"] = std::to_string(ss.armed_faulted);
    if (ss.watch_faults_total > 0)
        tags["yuzu.spark_watch_faults"] = std::to_string(ss.watch_faults_total);
    // #2270: a throwing unwatch during the arm-race teardown orphans an OS watch, and
    // the fallback log line is inside a catch-all so it is dropped under the very OOM
    // that triggers the path. Without this tag the residual has NO egress at all — the
    // agent has no /metrics, so heartbeat tags are the only route off the box. Covers
    // teardown_arm_race ONLY; see the field doc. The fleet rollup is deferred to the
    // prefer_spark flip, as retiring/retiring_cap already is.
    if (ss.arm_race_unwatch_failures_total > 0)
        tags["yuzu.spark_arm_race_unwatch_failures"] =
            std::to_string(ss.arm_race_unwatch_failures_total);
    // The same residual on the ordinary disarm() teardown, counted separately because the
    // scope is in each name on purpose. Neither covers unregister_consumer(), which still
    // propagates — so a zero across both is not a fleet-wide all-clear.
    if (ss.disarm_unwatch_failures_total > 0)
        tags["yuzu.spark_disarm_unwatch_failures"] =
            std::to_string(ss.disarm_unwatch_failures_total);
    if (ss.queued_dropped_total > 0)
        tags["yuzu.spark_queued_dropped"] = std::to_string(ss.queued_dropped_total);
    if (ss.consumer_errors_total > 0)
        tags["yuzu.spark_consumer_errors"] = std::to_string(ss.consumer_errors_total);
    // Per-mechanism-type health counters (sparse). Key = "yuzu.spark_<type>_<metric>",
    // composed identically to spark_type_metric_tag() in spark_fleet_tags.hpp.
    // Deliberately NOT skipped for inert mechanisms; inertness suppresses the capability
    // claim (the CSV above), not the telemetry. See the header note: Service tracks none of
    // these counters, but File and Registry do, so a File or Registry runtime-inert episode
    // can report non-zero cumulative values here.
    for (const auto& [type, ms] : by_type) {
        if (ms.watch_rejected_total == 0 && ms.quarantined_total == 0 && ms.slow_op_total == 0)
            continue; // nothing to say — don't build the key prefix (all-zero at rung 1)
        const std::string p = std::string("yuzu.spark_") + spark_type_token(type) + "_";
        if (ms.watch_rejected_total > 0)
            tags[p + "watch_rejected"] = std::to_string(ms.watch_rejected_total);
        if (ms.quarantined_total > 0)
            tags[p + "quarantined"] = std::to_string(ms.quarantined_total);
        if (ms.slow_op_total > 0)
            tags[p + "slow_op"] = std::to_string(ms.slow_op_total);
    }
}

} // namespace yuzu::agent
