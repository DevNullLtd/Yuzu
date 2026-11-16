#pragma once

/// @file dex_app_usage_owner.hpp
/// Cross-store query owner (ADR-0012 §3) for the fleet application usage read:
/// the per-executable usage rows (`app_usage_store.agent_last_used`), the usage
/// freshness rows (`app_usage_store.usage_state`) and the crash and hang
/// observations (`guaranteed_state_store.guardian_observations`) are read in ONE
/// statement on ONE lease. A per-store class must never reach into another
/// store's schema, and the join cannot be split without losing its point: usage
/// collection can be off per device, so crashes and hangs counted on every
/// online device over usage from only the reporting devices would overstate the
/// exposure rate. The numerator (events on devices that freshly report usage for
/// the application) and the denominator (their run time) must come from one
/// population, one window and one snapshot.
///
/// Freshness: a device counts only while the server received its usage state at
/// or after `DexUsageQuery::fresh_since_epoch` (`usage_state.last_seen`, server
/// receipt time, never the agent's collected_at). A stale device contributes no
/// usage, no events and no reporting count; it is counted in `stale_devices`.
/// Events are cut at BOTH ends (`since_iso` inclusive, `until_iso` exclusive), so
/// a future-dated observation never enters a numerator.
///
/// No authorization and no disclosure floor are applied here. The device list,
/// cells, keys and time cuts are taken as given from the caller, and agent ids
/// must be unique (a repeated id repeats its rows in every sum and in the
/// coverage counts). Admitting the caller and the device list is the surface's
/// duty before it builds the query.
///
/// The owner returns aggregates per (application, cell) and per application,
/// never an agent id. Typed failure: `read` returns `std::nullopt` when no
/// connection is available within the bounded acquire, an index in the query is
/// out of range, or the statement times out or errors. That is the authoritative
/// degrade, never an empty result. An engaged EMPTY result means no devices were
/// asked about (no query is run) or the statement found nothing.
///
/// Read-only, no state written, idempotent per request.

#include "dex_usage_model.hpp" // DexUsageQuery, DexUsageRead (pure; names no store)

#include <optional>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class DexAppUsageOwner {
public:
    /// `pool` is borrowed and must outlive this owner.
    explicit DexAppUsageOwner(pg::PgPool& pool);

    DexAppUsageOwner(const DexAppUsageOwner&) = delete;
    DexAppUsageOwner& operator=(const DexAppUsageOwner&) = delete;

    /// nullopt = authoritative degrade (see above).
    [[nodiscard]] std::optional<DexUsageRead> read(const DexUsageQuery& q) const;

private:
    pg::PgPool& pool_;
};

} // namespace yuzu::server
