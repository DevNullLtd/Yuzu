#pragma once

// Guardian spark-consumer send mapping (ADR-0021 rung 7.7a).
//
// The pure half of the outbox drain worker's send path: one buffered OutboxEntry
// -> the wire GuaranteedStateEvent. It is deliberately I/O-free and host-independent
// so it can be unit-tested directly (via the drain seams) even though production
// only ever invokes it once rule placement is enabled (rung 7.7b) - at 7.7a
// prefer_spark is false, no rule attaches, and the outbox stays empty.
//
// event_id and enqueued_ns are taken VERBATIM from the entry: both are fixed at
// enqueue for wire idempotency, and the runtime already folds agent_id + a per-boot
// nonce into event_id (the #1307 global-primary-key collision fix). The mapping must
// not rebuild either.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "guardian_outbox.hpp" // OutboxEntry, OutboxDomain

#include "guaranteed_state.pb.h" // ::yuzu::guardian::v1::GuaranteedStateEvent

#include <string_view>

namespace yuzu::agent {

/// Map one buffered outbox entry to the wire event. `platform` is injected (rather
/// than read from a compiled-in #if) so the mapping is host-independent and testable;
/// production passes the host platform token ("windows" | "linux" | "macos").
/// YUZU_EXPORT: the default-hidden visibility would otherwise keep it out of the
/// agent core .so's dynamic symbol table, so the test binary could not link it.
YUZU_EXPORT ::yuzu::guardian::v1::GuaranteedStateEvent
guardian_outbox_entry_to_event(const OutboxEntry& e, std::string_view platform);

} // namespace yuzu::agent
