#pragma once

/// @file inventory_ingest_outcome.hpp
/// Shared outcome vocabulary for the daily-sync hash-skip ingest (ADR-0016 §4),
/// common to every typed inventory store (`SoftwareInventoryStore`,
/// `DeviceInventoryStore`, …). Extracted to a leaf header so a store needs only
/// this enum, not a sibling store's full interface (interface segregation).

namespace yuzu::server {

/// Outcome of a hash-skip ingest for one source (ADR-0016 §4).
enum class InventoryIngestOutcome {
    kStored,   ///< full payload accepted; the agent's rows were replaced
    kTouched,  ///< claimed hash matched the stored hash; last_seen bumped only
    kNeedFull, ///< cold cache / mismatch with no rows — server asks for a resend
    kError,    ///< pool/SQL failure (transient). The seams ack it as need_full, so the agent resends
               ///< the full blob with backoff (it does not wait for the next scheduled cycle).
    kDeferred, ///< a write pause is standing (device_ci only, today: a PostgreSQL collation
               ///< mismatch); nothing was read or written. Acked as need_full so the agent resends
               ///< later. Sibling seams never produce it.
};

} // namespace yuzu::server
