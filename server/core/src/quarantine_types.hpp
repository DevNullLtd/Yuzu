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
    // "active", "releasing" or "released". The store keeps only active|released in the
    // column; a row with `release_requested_at != 0` reads "releasing" through a CASE in
    // the select list, so it stays listed and keeps the dispatch refusal.
    std::string status;
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
    // only after a FOLLOW-UP `firewall.quarantine_status` read reports
    // `status|active` (or `status|active_unproven` with no probe target) —
    // dispatch acceptance is not proof of endpoint containment (the same
    // distinction `quarantine_dispatch_decision.hpp` draws for the MCP path).
    std::int64_t last_applied_at{0};
    std::int64_t last_confirmed_at{0};
    // Schema v4 (PRQ.2), same 0 = never sentinel. `release_requested_at`: a release was
    // asked for (the record reads "releasing" until the device confirms it).
    // `device_release_owed_at`: the record was ended by an operator's forced DELETE before
    // the device confirmed, and the device still owes a release (set back to 0 when it
    // confirms).
    std::int64_t release_requested_at{0};
    std::int64_t device_release_owed_at{0};
};

/// How a record-scoped guarded write ended, as the pure decision code (`quarantine_release_decision.hpp`)
/// reads it. The store maps its `std::expected<void, std::string>` onto this with
/// `classify_quarantine_write` (`quarantine_store.hpp`), so the error literals are compared in one place.
/// `not_quarantined`: the guarded UPDATE touched no row (the record ended, was superseded, or its release
/// was already cleared). `apply_in_flight`: an apply's claim is live, or an apply was claimed after the
/// observation this write rests on (#7613). `store_error`: any other failure, nothing decided.
enum class QuarantineWrite { ok, not_quarantined, apply_in_flight, store_error };

} // namespace yuzu::server
