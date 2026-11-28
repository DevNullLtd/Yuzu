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
//
// Also home to guardian_event_refused_by_server, the one agent-side mirror of a server ingest
// refusal (an empty rule_id). It is not a drift mapping; it lives here because this is the agent's
// pure event-helper header, and agent.cpp, which holds both Guardian wire senders, includes it for this call.
// The server is the authority for the rule (guardian_ingest.cpp); change the two together.

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

/// True when the server will refuse `ev` at ingest for want of a rule id (guardian_ingest.cpp
/// drops an event whose rule_id is empty; ruleless observations carry the reserved
/// `__observation__` id, never an empty one). Both Guardian wire senders in agent.cpp call this
/// so the agent never writes an event it knows will be dropped, and logs the drop locally: the
/// server answers an ingest refusal with nothing, so this is the only place the agent can see it.
YUZU_EXPORT bool guardian_event_refused_by_server(
    const ::yuzu::guardian::v1::GuaranteedStateEvent& ev);

} // namespace yuzu::agent
