#pragma once

/// @file offline_endpoint_types.hpp
/// Plain value types for the persisted offline-roster read (`OfflineEndpoint`,
/// `PresenceReadError`, `OfflineRosterRead`), split out of `offline_endpoint_store.hpp` so
/// the hardware read model and the MCP registry lane can name a row without including a
/// store header (ADR-0031 seam closure, #6558).
/// `offline_endpoint_store.hpp` re-includes this header, so existing includers are unaffected. No
/// behaviour lives here — the store keeps its class and every query.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server {

/// One persisted endpoint row — the last-known identity for an agent the
/// server has seen. Deliberately thin: enough to render a stale placeholder
/// cube, nothing that belongs to the live in-memory topology.
struct OfflineEndpoint {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::int64_t last_heartbeat_ms{0}; ///< Server wall-clock epoch ms at last ingest.
    std::int64_t agent_ts{0};          ///< Agent-emitted snapshot epoch seconds (0 if none).
    /// Round-3 v2 columns (Devices-page merge, item 1): last-known agent
    /// version/arch, so an OFFLINE row still shows a version/arch on the
    /// Hardware list instead of blanking the moment the agent drops off the
    /// live registry. Empty when never observed (pre-migration rows, or a
    /// heartbeat that raced session lookup — see the blank-preserve note on
    /// `OfflineEndpointStore::upsert()` in offline_endpoint_store.hpp).
    std::string agent_version;
    std::string arch;
};

/// `query_live_ids`'s and `query_stale_within`'s typed failure surface (#4981 PR-1, Finding B;
/// #5531). `query_stale_within` never produces `Truncated`.
/// `StoreUnavailable`/`DbError` mirror `record_presence_store_failure`'s
/// existing `reason` label vocabulary (`store_unavailable`/`db_error`,
/// offline_endpoint_store.cpp) exactly — do not introduce a third spelling.
/// `Truncated` is new: the query result exceeded `kQueryRowCap` rows, so the
/// caller cannot trust it as the COMPLETE live set (silently dropping rows
/// past the cap would under-count presence, the same fail-open class a
/// genuine DB error guards against).
enum class PresenceReadError { StoreUnavailable, DbError, Truncated };

/// One offline-roster read, as `OfflineEndpointStore::query_stale_within` returns it (#5531).
using OfflineRosterRead = std::expected<std::vector<OfflineEndpoint>, PresenceReadError>;

} // namespace yuzu::server
