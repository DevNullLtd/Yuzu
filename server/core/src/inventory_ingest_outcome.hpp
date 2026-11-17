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
               ///< later. Sibling stores never produce it, but their seams map it anyway
               ///< (`ingest_outcome_label` / `ingest_outcome_needs_full`).
};

/// The `outcome` label of `yuzu_inventory_ingest_total` for each outcome: the ONE mapping, shared
/// by every seam, so a new enumerator is a -Wswitch warning here instead of a silent `error` in a
/// seam's hand-written chain. An out-of-range value reads "error".
[[nodiscard]] constexpr const char* ingest_outcome_label(InventoryIngestOutcome o) noexcept {
    switch (o) {
    case InventoryIngestOutcome::kStored:
        return "stored";
    case InventoryIngestOutcome::kTouched:
        return "touched";
    case InventoryIngestOutcome::kNeedFull:
        return "need_full";
    case InventoryIngestOutcome::kError:
        return "error";
    case InventoryIngestOutcome::kDeferred:
        return "deferred";
    }
    return "error";
}

/// True when the seam must ack the source as need_full: every outcome where the agent must resend
/// a full payload rather than believe its data was stored (kNeedFull, kError, kDeferred). Stored
/// and touched are the only ones that are not. An out-of-range value nacks (the safe direction).
[[nodiscard]] constexpr bool ingest_outcome_needs_full(InventoryIngestOutcome o) noexcept {
    switch (o) {
    case InventoryIngestOutcome::kStored:
    case InventoryIngestOutcome::kTouched:
        return false;
    case InventoryIngestOutcome::kNeedFull:
    case InventoryIngestOutcome::kError:
    case InventoryIngestOutcome::kDeferred:
        return true;
    }
    return true;
}

} // namespace yuzu::server
