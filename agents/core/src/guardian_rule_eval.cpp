#include "guardian_rule_eval.hpp"

#include <yuzu/agent/guard_service.hpp> // service_is_compliant, service_state_token, ServiceState, ServiceGuard::Desired

#include <string>
#include <utility>

namespace yuzu::agent {

namespace {

/// The Unknown outcome: arm the recovery-force bit and hand back the read-error
/// detail. EmitDeciderState is left UNTOUCHED - a read failure must never move
/// last_compliant/last_emit (that would turn "can't tell" into a committed
/// verdict). Marks the EDGE (the first Unknown of an errored episode); the runtime
/// emits guard.unhealthy only on that edge and suppresses+counts a repeat Unknown,
/// so a rule stuck errored does not flood the health stream every convergence tick.
EvalOutcome unhealthy(RuleEvalState& state, std::string detail) {
    const bool edge = !state.in_unknown; // first transition into the errored episode
    state.in_unknown = true;
    EvalOutcome out{EvalStatus::Unhealthy, GuardDrift{}, std::move(detail)};
    out.unhealthy_edge = edge;
    return out;
}

/// Run the shared decide_emit tail and pack its result + the guard's
/// detected/expected tokens into an Emit outcome, or a Silent outcome if it said
/// stay silent. On recovery from an Unknown gap, reset the decider's edge/debounce
/// so the verdict is FORCED to emit even if the value equals its pre-error value.
EvalOutcome pack(const RuleAssertion& a, const char* guard_type, bool compliant,
                 std::string detected, std::string expected, RuleEvalState& state,
                 std::chrono::steady_clock::time_point now, bool emit_compliant_edge,
                 std::uint64_t detection_latency_us) {
    bool recovered = false;
    if (state.in_unknown) {
        // Recovery: force a fresh verdict. Clearing last_compliant makes a compliant
        // read an edge again; clearing last_emit/suppressed lets a drift re-emit
        // rather than debounce-fold against a pre-error drift. `recovered` tells the
        // runtime to ALSO emit guard.healthy - so a systemd rule recovering to steady
        // compliant (a Silent verdict with emit_compliant_edge=false) still leaves the
        // health stream's errored state instead of staying unhealthy forever.
        state.emit.last_compliant.reset();
        state.emit.last_emit.reset();
        state.emit.suppressed = 0;
        state.in_unknown = false;
        recovered = true;
    }
    const EmitResult r = decide_emit(compliant, state.emit, a.debounce_ms, now, emit_compliant_edge);
    if (r.kind == EmitKind::Silent)
        return EvalOutcome{EvalStatus::Silent, GuardDrift{}, {}, recovered};
    GuardDrift d;
    d.guard_type = guard_type;
    d.rule_id = a.rule_id;
    d.rule_name = a.rule_name;
    d.detected_value = std::move(detected);
    d.expected_value = std::move(expected);
    d.detection_latency_us = detection_latency_us;
    d.collapsed_count = r.collapsed_count;
    d.compliant = (r.kind == EmitKind::CompliantEdge);
    return EvalOutcome{EvalStatus::Emit, std::move(d), {}, recovered};
}

} // namespace

EvalOutcome eval_file(const RuleAssertion& a, const ReadResult<FileSnapshot>& read,
                      RuleEvalState& state, std::chrono::steady_clock::time_point now,
                      bool emit_compliant_edge) {
    if (!read.known)
        return unhealthy(state, read.error);
    const FileSnapshot& snap = read.snapshot;

    bool compliant = false;
    std::string detected;
    std::string expected;

    if (a.kind == AssertionKind::FileExists) {
        compliant = (snap.exists == a.expect_present);
        detected = snap.exists ? "<present>" : "<absent>";
        expected = a.expect_present ? "<present>" : "<absent>";
    } else { // FileHashEquals - token precedence matches legacy: absent, unreadable, oversize, compare.
        const bool oversize = snap.size > a.max_bytes; // per-rule projection off the shared snapshot
        if (!snap.exists) {
            detected = "<absent>";
        } else if (!snap.readable) {
            detected = "<unreadable>";
        } else if (oversize) {
            detected = "<oversize>";
        } else if (snap.hash.empty()) {
            // Admitting size + readable + present but no digest: the reader should
            // have hashed it. Fail loud ("can't verify") rather than treat an empty
            // digest as a match; a genuine transient failure would be Unknown, not here.
            detected = "<unreadable>";
        } else {
            // baseline-on-arm: an empty expected_hash captures the first good read as
            // the baseline and reads compliant (a guard.compliant edge).
            if (a.expected_hash.empty() && !state.baseline_set) {
                state.baseline_hash = snap.hash;
                state.baseline_set = true;
            }
            const std::string& effective =
                a.expected_hash.empty() ? state.baseline_hash : a.expected_hash;
            compliant = (snap.hash == effective);
            detected = snap.hash;
            expected = effective;
        }
        if (expected.empty()) // absent/unreadable/oversize drift: report the target hash
            expected = a.expected_hash.empty() ? state.baseline_hash : a.expected_hash;
    }
    // guard_type via the shared guard_type_for(kind) so Compliance and Health/Lifecycle
    // (which derive it the same way) can never report a different guard_type for one rule.
    return pack(a, guard_type_for(a.kind), compliant, std::move(detected), std::move(expected),
                state, now,
                emit_compliant_edge, /*detection_latency_us=*/0);
}

EvalOutcome eval_registry(const RuleAssertion& a, const ReadResult<RegistrySnapshot>& read,
                          RuleEvalState& state, std::uint64_t detection_latency_us,
                          std::chrono::steady_clock::time_point now, bool emit_compliant_edge) {
    if (!read.known)
        return unhealthy(state, read.error);
    const RegistrySnapshot& snap = read.snapshot;

    bool compliant = false;
    std::string detected;
    if (!snap.present) {
        detected = "<absent>";
    } else if (!snap.supported) {
        detected = "<unsupported-type>";
    } else {
        compliant = (snap.value == a.expected_value);
        detected = snap.value;
    }
    return pack(a, guard_type_for(a.kind), compliant, std::move(detected), a.expected_value, state,
                now,
                emit_compliant_edge, detection_latency_us);
}

EvalOutcome eval_service(const RuleAssertion& a, const ReadResult<ServiceRunState>& read,
                         RuleEvalState& state, std::chrono::steady_clock::time_point now,
                         bool emit_compliant_edge) {
    if (!read.known)
        return unhealthy(state, read.error);

    // ServiceRunState (reader) -> ServiceState (guard vocabulary). There is no
    // Absent: a deleted service folds into Stopped at the reader (R5, accepted -
    // the compliance verdict is identical, only detected_value differs from legacy).
    ServiceState st = ServiceState::Stopped;
    switch (read.snapshot) {
    case ServiceRunState::Running:
        st = ServiceState::Running;
        break;
    case ServiceRunState::Stopped:
        st = ServiceState::Stopped;
        break;
    case ServiceRunState::Paused:
        st = ServiceState::Paused;
        break;
    }
    const ServiceGuard::Desired want = (a.kind == AssertionKind::ServiceRunning)
                                           ? ServiceGuard::Desired::Running
                                           : ServiceGuard::Desired::Stopped;
    const bool compliant = service_is_compliant(want, st);
    std::string detected{service_state_token(st)};
    std::string expected = (want == ServiceGuard::Desired::Running) ? "running" : "stopped";
    // emit_compliant_edge default true UNIFIES the compliant-census signal across
    // platforms: legacy Windows-Service emitted it, legacy systemd did not. The caller
    // can pass false to preserve exact legacy-systemd silence (pinned in parity tests).
    return pack(a, guard_type_for(a.kind), compliant, std::move(detected), std::move(expected),
                state, now,
                emit_compliant_edge, /*detection_latency_us=*/0);
}

} // namespace yuzu::agent
