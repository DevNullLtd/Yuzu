#pragma once

/// @file app_usage_ingestion.hpp
/// Shared app_usage ingest seam (wave 7 PR7.2, mirrors
/// software_licensing_ingestion.hpp / ADR-0024 Decisions 3/5). BOTH server
/// entry points — the direct `AgentServiceImpl::ReportInventory` and the
/// gateway `GatewayUpstreamServiceImpl::ProxyInventory` — call this one
/// function so the two paths persist identically.
///
/// The report is **untrusted external input**: this seam applies caps (blob
/// bytes / record count / per-field scrub+clamp) before touching the store.
///
/// RAW-BYTE HASH: like `software_licensing`, this source's content hash is
/// the SHA-256 of the RAW received blob bytes, recomputed HERE — the agent's
/// claimed hash is never stored (it is only compared on the hash-only leg).
/// Because the hash is taken before (and independently of) parsing, skipping
/// unknown record kinds cannot diverge the stored hash from the agent's.

#include "app_usage_store.hpp" // AgentLastUsedRow

#include <string>
#include <vector>

namespace yuzu::agent::v1 {
class InventoryReport;
class InventoryAck;
} // namespace yuzu::agent::v1

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Parse output of one `app_usage` wire blob: the projected `lu|` rows.
/// `over_record_cap` reports a record-count breach — the caller must drop +
/// nack, NEVER store a truncated projection (under the raw-byte hash a
/// truncated row set would be frozen by hash-skip: every later identical
/// blob would be "touched" with rows missing forever).
struct AppUsageParse {
    std::vector<AgentLastUsedRow> rows;
    bool over_record_cap{false};
};

/// Parse the `app_usage` canonical wire blob: records 0x1E-joined, fields
/// 0x1F-joined, record kind in field 0. `lu|` records project positionally
/// (5 fields after the kind: exe_key, first_seen, last_seen, run_count_30d,
/// total_seconds_30d); missing trailing fields stay 0/empty, extra fields are
/// dropped, empty-exe_key rows are dropped. Unknown record kinds (`cfg|`,
/// anything newer) are SKIPPED without error — forward-compat. Every text
/// field is UTF-8-scrubbed/clamped; numerics are parsed via std::from_chars
/// and clamped non-negative. `collected_at` on the rows is left 0 (the
/// ingest entry point stamps it). Exposed for tests.
AppUsageParse parse_app_usage_blob(const std::string& blob);

/// SHA-256 hex over the raw received blob bytes — THE content hash this
/// source stores. Exposed so tests can pin "stored hash == sha256(raw
/// bytes), never the claim". Empty string only on digest failure (treated as
/// a transient error by the ingest entry point).
std::string app_usage_raw_hash(const std::string& blob);

/// Ingest the `app_usage` source of `report` for `agent_id` into `store`;
/// appends to `ack.need_full` when the server needs a full resend (cold
/// cache / drift / over-cap payload / store error). Does NOT set
/// `ack.received`. No-op when `agent_id` is empty or the source is not
/// present. Drives the store's trichotomy primitives: hash-only reports run
/// `stored_hash` (compare) + `touch`; full payloads run
/// `replace_agent_last_used` with the seam-recomputed raw-byte hash.
/// `metrics` (nullable) receives
/// `yuzu_inventory_ingest_total{source="app_usage",outcome}` per call.
void ingest_app_usage_report(AppUsageStore& store, const std::string& agent_id,
                             const ::yuzu::agent::v1::InventoryReport& report,
                             ::yuzu::agent::v1::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server
