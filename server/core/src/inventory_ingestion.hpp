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

/// Describe `yuzu_inventory_section_ingest_total{facet,outcome}` and create every closed-set
/// series at 0 (facets: each collector source, `component_inventory`, `unknown`; outcomes: the six
/// `V3SectionOutcome` names), and the same for `yuzu_software_changes_total{kind}` (its three
/// `SoftwareChangeKind` names), per docs/observability-conventions.md: a series that first appears
/// already at 1 contributes no increase, so the first refused section would never alert.
/// ServerImpl calls this once at construction; the unit test calls the same function.
void seed_section_ingest_series(::yuzu::MetricsRegistry& metrics);

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
///
/// Blob v2 vs v3 (ADR-0016 Update 2026-11-04): a blob that starts with the v3 header bytes
/// takes the sectioned path (`inventory_blob_v3.hpp`, `apply_installed_software_v3`); every
/// other blob is v2 and is handled exactly as before. A v3 report is nacked PER SECTION:
/// `ack.need_full` carries `installed_software:<facet>` for each section the server could not
/// apply (refused, a delta on a base it does not hold, a delta or component section that did not
/// verify, or a failed transaction), and the whole-source
/// `installed_software` only for a v3 blob that cannot be attributed to sections at all.
/// Each section also bumps `yuzu_inventory_section_ingest_total{facet,outcome}`
/// (outcome: stored | status_only | need_full | mismatch | rejected | error), and the
/// apply is timed under `yuzu_inventory_ingest_duration_seconds{phase="v3"}`.
void ingest_inventory_report(SoftwareInventoryStore& store, const std::string& agent_id,
                             const ::yuzu::agent::v1::InventoryReport& report,
                             ::yuzu::agent::v1::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server
