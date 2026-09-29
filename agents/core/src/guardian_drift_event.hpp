#pragma once

// Shared drift -> event field mapping (ADR-0021 rung 7.7b, PR-1 item 1 / #2237).
//
// The single source of truth for turning a GuardDrift into the compliance-family
// fields of a GuaranteedStateEvent: rule_name, guard_type, detected/expected value,
// detection latency, the 4-way event_type cascade (guard.compliant / drift.remediated
// / remediation.failed / drift.detected) with its remediation fields, and drift_rate.
//
// Both producers call this so they cannot drift apart:
//   - the legacy enforcing path, GuardianEngine::emit_guard_event, and
//   - the spark consumer, guardian_outbox_entry_to_event's Compliance branch.
// Before this extraction the mapping was two hand-maintained copies (#2237 item 1).
//
// It sets ONLY the drift-derived fields. Each caller stamps the idempotency- and
// host-specific parts itself: event_id, rule_id, guard_category, timestamp, platform.
// Pure and I/O-free.

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/guard.hpp> // GuardDrift

#include "guaranteed_state.pb.h" // ::yuzu::guardian::v1::GuaranteedStateEvent

namespace yuzu::agent {

/// Populate the compliance-family drift fields of `ev` from `d`. Leaves event_id,
/// rule_id, guard_category, timestamp and platform untouched (caller-owned).
/// YUZU_EXPORT: default-hidden visibility would otherwise keep it out of the agent
/// core .so's dynamic symbol table, so the test binary could not link it.
YUZU_EXPORT void apply_drift_to_event(const GuardDrift& d,
                                      ::yuzu::guardian::v1::GuaranteedStateEvent& ev);

} // namespace yuzu::agent
