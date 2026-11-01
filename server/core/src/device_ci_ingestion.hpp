#pragma once

/// @file device_ci_ingestion.hpp
/// Shared device-CI ingest seam (ADR-0016 §5). BOTH server entry points — the
/// direct `AgentServiceImpl::ReportInventory` and the gateway
/// `GatewayUpstreamServiceImpl::ProxyInventory` — call this one function so the two
/// paths persist identically (mirrors `ingest_app_perf_report` / the
/// HeartbeatIngestion pattern), right after the software + app_perf seams.
///
/// The report is **untrusted external input**: this seam applies a blob-size cap +
/// per-field UTF-8 scrub + length clamp before touching the store. It drives the
/// store's hash-skip path (hash-only → compare; full → recompute + upsert) and
/// fills `ack.need_full` for a source the server could not materialise. The store
/// stays proto-free (PG-unit-testable without protobuf).

#include "device_inventory_store.hpp" // DeviceCiRecord

#include <string>

namespace yuzu::agent::v1 {
class InventoryReport;
class InventoryAck;
} // namespace yuzu::agent::v1

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Parse the `device_ci` canonical wire blob into a record: one 0x1E-terminated
/// record of 0x1F-separated fields, each UTF-8-scrubbed + clamped IDENTICALLY to the
/// agent (sync_source_device_ci.cpp) so the store's recomputed hash equals the
/// agent's. Exposed for the cross-pin test. `agent_id` is left empty (the caller
/// sets it). A blob over the cap yields an empty (default) record — the caller checks
/// the cap and nacks before calling, so this is defence-in-depth.
///
/// **v2 blobs** (first byte 0x02, `device_ci_kinds.hpp`): `0x02`, a scalar record of
/// 33 positional fields (the 22 frozen v1 positions plus 11 appended chassis/board/
/// machine-id scalars), then kind-tagged list records and per-section `status`
/// records. Every field is scrubbed + clamped like v1; an unregistered status section
/// or unknown kind is ignored; list rows past a kind's cap are dropped and the section
/// is marked `constrained` / `server_cap:<n>`; a `machine_id_hash` that is not hex (or
/// "-") is blanked and the `machine_id` section marked `constrained` /
/// `server:machine_id_shape`. `blob_version` is 2 and `content_hash`
/// is the sha256 of the received bytes (empty if the digest failed — the store then
/// nacks). Any other first byte parses exactly as v1 (`blob_version` 1, no sections).
DeviceCiRecord parse_device_ci_blob(const std::string& blob);

/// Ingest the `device_ci` source of `report` for `agent_id` into `store`; appends to
/// `ack.need_full` when the server needs a full resend (cold cache / drift / store
/// error). Does NOT set `ack.received`. No-op when `agent_id` is empty or the source
/// is not present. `metrics` (nullable) receives
/// `yuzu_inventory_ingest_total{source="device_ci",outcome}` per call.
void ingest_device_ci_report(DeviceInventoryStore& store, const std::string& agent_id,
                             const ::yuzu::agent::v1::InventoryReport& report,
                             ::yuzu::agent::v1::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server
