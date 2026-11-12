#pragma once

/// @file offline_endpoint_types.hpp
/// Plain value types for the persisted offline-roster read (`OfflineEndpoint`,
/// `PresenceReadError`, `OfflineRoster`, `OfflineRosterRead`, `OfflineEndpointRead`), split out of `offline_endpoint_store.hpp` so
/// the hardware read model and the MCP registry lane can name a row without including a
/// store header (ADR-0031 seam closure, #6558).
/// `offline_endpoint_store.hpp` re-includes this header, so existing includers are unaffected. No
/// behaviour lives here — the store keeps its class and every query.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// The row cap of the persisted offline-roster read (`OfflineEndpointStore::kQueryRowCap` is this
/// value). It lives here, in the store-free value-type header, so the read model and the
/// consumers that word the cap in a notice name the SAME constant the store enforces — a second
/// literal would let a notice quote a cap the store no longer applies (#5712).
inline constexpr int kOfflineRosterRowCap = 100000;

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
/// #5531). Only `query_live_ids` produces `Truncated`: `query_stale_within` serves a capped roster
/// as a typed PARTIAL success (`OfflineRoster::truncated`, #5712), never as this error.
/// `StoreUnavailable`/`DbError` mirror `record_presence_store_failure`'s
/// existing `reason` label vocabulary (`store_unavailable`/`db_error`,
/// offline_endpoint_store.cpp) exactly — do not introduce a third spelling.
/// `Truncated` is new: the query result exceeded `kQueryRowCap` rows, so the
/// caller cannot trust it as the COMPLETE live set (silently dropping rows
/// past the cap would under-count presence, the same fail-open class a
/// genuine DB error guards against). It is a FAIL-CLOSED signal for the
/// dispatch-safety presence read; a display read must not reuse it as a refusal
/// (a refusal that never clears once the fleet passes the cap, #5371).
enum class PresenceReadError { StoreUnavailable, DbError, Truncated };

/// One offline-roster read's payload (#5712): the newest `OfflineEndpointStore::kQueryRowCap`
/// endpoints inside the window, plus whether MORE existed than were returned. `truncated` is derived
/// afresh on every read (the store fetches one row past the cap), so it clears itself the moment
/// the fleet is back under the cap — there is no latch. A truncated roster is a LOWER BOUND: an
/// endpoint absent from `rows` may still exist, so a miss in it is never proof of absence.
/// A plain aggregate on purpose: nothing converts a bare `std::vector<OfflineEndpoint>` into one, so
/// a consumer that ignores `truncated` cannot be written by accident.
struct OfflineRoster {
    std::vector<OfflineEndpoint> rows;
    bool truncated = false;
};

/// One offline-roster read, as `OfflineEndpointStore::query_stale_within` returns it (#5531, #5712).
using OfflineRosterRead = std::expected<OfflineRoster, PresenceReadError>;

/// One endpoint point read, as `OfflineEndpointStore::find_within` returns it (#5712): an
/// engaged optional is the row, an empty one is a CONFIRMED absence from the window (the read is a
/// primary-key lookup, so unlike a roster scan a miss is exact), and an error is an unread answer.
using OfflineEndpointRead = std::expected<std::optional<OfflineEndpoint>, PresenceReadError>;

} // namespace yuzu::server
