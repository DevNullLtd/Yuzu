#pragma once

/// @file inventory_ingestion.hpp
/// Shared inventory ingest seam (ADR-0016 §5). BOTH server entry points —
/// the direct `AgentServiceImpl::ReportInventory` and the gateway
/// `GatewayUpstreamServiceImpl::ProxyInventory` — call this one function so the
/// two paths persist identically (mirrors the HeartbeatIngestion pattern).
///
/// The report is **untrusted external input**: this seam applies size/entry/
/// field caps before touching the store. It parses each due source's hash +
/// optional full blob, drives the store's hash-skip path, and fills
/// `ack.need_full` for any source the server could not materialise from a
/// hash-only report (cold cache / drift). The store itself stays proto-free
/// (and therefore PG-unit-testable without protobuf).

#include <string>

namespace yuzu::agent::v1 {
class InventoryReport;
class InventoryAck;
} // namespace yuzu::agent::v1

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class SoftwareInventoryStore;

/// Validate the untrusted report's map cardinality before any generic or
/// typed store write. Returns false after logging/counting a whole-report
/// rejection; callers acknowledge without requesting a resend.
[[nodiscard]] bool validate_inventory_report_source_count(
    const std::string& agent_id, const ::yuzu::agent::v1::InventoryReport& report,
    ::yuzu::MetricsRegistry* metrics = nullptr);

/// Ingest the normalized sources of `report` for `agent_id` into `store`
/// (slice 1: `installed_software`); appends any source needing a full resend to
/// `ack.need_full`. Does NOT set `ack.received` and does NOT touch generic
/// (blob) sources — the caller owns `received` and the generic-`InventoryStore`
/// upsert for non-normalized keys (coexistence, ADR-0016). No-op when `agent_id`
/// is empty or no normalized source is present.
/// `metrics` (nullable) receives a `yuzu_inventory_ingest_total{source,outcome}`
/// counter per source — the observability the silent-degradation findings need.
void ingest_inventory_report(SoftwareInventoryStore& store, const std::string& agent_id,
                             const ::yuzu::agent::v1::InventoryReport& report,
                             ::yuzu::agent::v1::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server
