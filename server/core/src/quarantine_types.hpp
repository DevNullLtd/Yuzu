#pragma once

/// @file quarantine_types.hpp
/// Plain value type for a device-quarantine record, split out of
/// `quarantine_store.hpp` so the presentation-side read models
/// (`quarantine_read_model.hpp`, `quarantine_visible.hpp`,
/// `device_containment_render.hpp`) and the MCP registry lane can name a row
/// without including a store header (ADR-0031 seam closure, #6558).
/// `quarantine_store.hpp` re-includes this header, so existing includers are
/// unaffected. No behaviour lives here — the store keeps the class, the
/// `kQuarantineDbErrorPrefix` constant and every query.

#include <cstdint>
#include <string>

namespace yuzu::server {

struct QuarantineRecord {
    // #3425 governance Gate 4 (unhappy-path, Finding A): the row's own
    // primary key — NOT exposed on REST/MCP (wire surfaces stay unchanged),
    // used ONLY to scope `mark_endpoint_applied`/`mark_endpoint_confirmed`'s
    // guarded UPDATE to the SPECIFIC record a dispatch/status-read was
    // actually about. `agent_id`+`status='active'` alone is not a stable
    // identity: a release-then-requarantine sequence lands a NEW active row
    // for the same `agent_id` while a reconcile cycle for the OLD row is
    // still in flight, and without `id` scoping the stamp write silently
    // lands on the NEW row (whose whitelist was never actually dispatched).
    std::int64_t id{0};
    std::string agent_id;
    std::string status; // "active" or "released"
    std::string quarantined_by;
    std::int64_t quarantined_at{0};
    std::int64_t released_at{0};
    std::string whitelist; // comma-separated IPs
    std::string reason;
    // Schema v2 (#3425): 0 = never, matching `released_at`'s existing
    // never-happened sentinel on this same table — no optional plumbing.
    // Written ONLY by QuarantineContainmentReconciler. `last_applied_at` is
    // set when a system re-dispatch of the STORED whitelist is accepted by
    // the plugin registry (agents_reached > 0); `last_confirmed_at` is set
    // only after a FOLLOW-UP `quarantine.status` read reports `state|active`
    // — dispatch acceptance is not proof of endpoint containment (the same
    // distinction `quarantine_dispatch_decision.hpp` draws for the MCP path).
    std::int64_t last_applied_at{0};
    std::int64_t last_confirmed_at{0};
};

} // namespace yuzu::server
