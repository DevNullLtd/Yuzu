#include "guardian_drift_event.hpp"

#include <cstdint>

namespace yuzu::agent {

namespace gpb = ::yuzu::guardian::v1;

void apply_drift_to_event(const GuardDrift& d, gpb::GuaranteedStateEvent& ev) {
    ev.set_rule_name(d.rule_name);
    ev.set_guard_type(d.guard_type); // "registry" | "file" | "service"
    ev.set_detected_value(d.detected_value);
    ev.set_expected_value(d.expected_value);
    ev.set_detection_latency_us(d.detection_latency_us);

    if (d.compliant) {
        // A compliant transition is never a write-back: no remediation fields. The
        // server buckets guard.compliant + drift.remediated -> compliant; the guard
        // only emits this on the edge, so steady state adds zero traffic.
        ev.set_event_type("guard.compliant");
    } else if (d.remediation_attempted) {
        ev.set_remediation_action(d.remediation_action);
        ev.set_remediation_success(d.remediation_success);
        ev.set_remediation_latency_us(d.remediation_latency_us);
        // drift.remediated = the write-back restored the value; remediation.failed =
        // enforce attempted but the write did not succeed. Both are in the frozen
        // taxonomy; remediation.failed keeps a failed enforce visibly distinct from a
        // passive detection so the operator sees enforcement is not working.
        ev.set_event_type(d.remediation_success ? "drift.remediated" : "remediation.failed");
    } else {
        ev.set_event_type("drift.detected");
    }

    // drift_rate carries the count of ADDITIONAL drift detections the agent-side sink
    // debounce collapsed into this single event (H3 / #1209): 0 = sole detection in
    // its window; a high value means a churning writer's burst was folded to keep the
    // event store bounded.
    if (d.collapsed_count > 0)
        ev.set_drift_rate(static_cast<double>(d.collapsed_count));
}

} // namespace yuzu::agent
