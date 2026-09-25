#pragma once

/**
 * guard.hpp — common Guardian guard abstraction shared by every Spark type.
 *
 * A guard is a live, kernel-notified watch on one piece of endpoint state that
 * reports drift to a sink. RegistryGuard (`registry-change`) and FileGuard
 * (`file-change`) implement IGuard; the GuardianEngine owns them polymorphically
 * (`unordered_map<rule_id, unique_ptr<IGuard>>`) and turns each GuardDrift into a
 * GuaranteedStateEvent.
 *
 * Proto-free and windows.h-free by design — keeps protobuf's headers and
 * windows.h's ERROR/min/max macros out of the same translation unit as the
 * guards. Header-only: no exported symbols (pure interface + a POD drift struct).
 */

#include <cstdint>
#include <functional>
#include <string>

namespace yuzu::agent {

/// What a guard observed when watched state drifted from its expected state.
/// Shared across Spark types; `guard_type` tells the engine which Spark produced
/// it (it becomes GuaranteedStateEvent.guard_type). The remediation fields apply
/// only to enforce-capable guards (registry write-back); a detection-only guard
/// (file) leaves them at their defaults.
struct GuardDrift {
    std::string guard_type{"registry"}; ///< "registry" | "file" | "service" — the Spark that produced this
    std::string rule_id;
    std::string rule_name;
    std::string detected_value; ///< string-encoded live value / state, or "<absent>"
    std::string expected_value; ///< string-encoded expected value / state
    std::uint64_t detection_latency_us{0};

    // Remediation (enforce-capable guards only). Default = not attempted.
    bool remediation_attempted{false};
    bool remediation_success{false};
    std::uint64_t remediation_latency_us{0};
    std::string remediation_action;

    /// ADDITIONAL drift detections collapsed into this report by the sink debounce
    /// window (H3 / #1209). 0 = sole detection in its window; >0 means a churning
    /// writer's burst was folded into one event. Surfaced as drift_rate on the wire.
    std::uint64_t collapsed_count{0};

    /// True = this report is a COMPLIANT transition (watched state is at / returned
    /// to expected), NOT a drift. The engine maps it to event_type "guard.compliant"
    /// so the server can derive a true per-(agent,rule) compliance census instead of
    /// only "last drift". Emitted on the compliant↔drift EDGE only — steady compliant
    /// state stays silent (network-kindness / NFR). Remediation fields stay default
    /// (a compliant edge is never a remediation). Slice B.
    bool compliant{false};

    /// Health report (NOT a compliance verdict). Unhealthy = the guard is still
    /// running but one detection channel has permanently failed, so it can no
    /// longer vouch for the watched state end to end. The engine maps it to
    /// event_type "guard.unhealthy" (server census: errored) and IGNORES every
    /// compliance field on the same report — a health report never mints
    /// drift.detected or guard.compliant. health_detail travels as detail_json
    /// {"detail": ...}, byte-identical to the Spark health stream
    /// (guardian_spark_send.cpp). No Healthy enumerator yet: no legacy producer
    /// emits a recovery today — a fresh guard instance's first verdict clears the
    /// census (see docs/spark-legacy-delta-registry.md D11 for why a bare
    /// guard.healthy alone could not).
    enum class Health : std::uint8_t { None, Unhealthy };
    Health health{Health::None};
    std::string health_detail;
};

/// Sink a guard calls on each (debounced) drift detection.
using GuardSink = std::function<void(const GuardDrift&)>;

/// One live watch on a dedicated thread. start() arms the watch and starts the
/// thread; stop() signals and joins it. Implementations are single-owner
/// (non-copyable); the engine owns each via unique_ptr<IGuard>. The virtual
/// destructor makes that deletion correct.
class IGuard {
public:
    virtual ~IGuard() = default;
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual const std::string& rule_id() const = 0;
};

} // namespace yuzu::agent
