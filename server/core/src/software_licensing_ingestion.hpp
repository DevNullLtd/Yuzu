#pragma once

/// @file software_licensing_ingestion.hpp
/// Shared software_licensing ingest seam (ADR-0024 Decisions 3/5, ADR-0016 §5).
/// BOTH server entry points — the direct `AgentServiceImpl::ReportInventory` and
/// the gateway `GatewayUpstreamServiceImpl::ProxyInventory` — call this one
/// function so the two paths persist identically (mirrors
/// `ingest_device_ci_report` / `ingest_inventory_report`), right after the
/// device_ci seam.
///
/// The report is **untrusted external input**: this seam applies the roadmap R5
/// caps (blob bytes / record count / per-field scrub+clamp) before touching the
/// store, whitelists the closed §3.2 vocabularies at projection (C-7), and
/// plausibility-clamps `expires_at`.
///
/// RAW-BYTE HASH (ADR-0024 Decision 3 / roadmap D-2): unlike the three legacy
/// sources, this source's content hash is the SHA-256 of the RAW received blob
/// bytes, recomputed HERE — the agent's claimed hash is never stored (it is only
/// compared on the hash-only leg, like every sibling seam). Because the hash is
/// taken before (and independently of) parsing, skipping unknown record kinds
/// and normalising enums cannot diverge the stored hash from the agent's — the
/// mixed-version full-resend loop the parse-then-recompute sources document is
/// impossible by construction. The accepted consequence: a server-side
/// projection fix does not re-project a stable estate by itself — the
/// framework's `need_full` path (reachable through this seam's cold-cache/drift
/// leg) is the recorded forced-reprojection lever (roadmap G-8).

#include "software_licensing_store.hpp" // AgentLicenseRow

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

/// Parse output of one `software_licensing` wire blob (§3.1): the projected
/// `lic|` rows plus the blob-level `cfg|user_ref` effective mode (roadmap
/// D-10). `effective_user_ref_mode` is the whitelisted value
/// (collect|hash|omit, anything else → "unknown"), or "" when the blob carries
/// no cfg record (old agent). `over_record_cap` reports an R5 record-count
/// breach — the caller must drop + nack, NEVER store a truncated projection
/// (under the raw-byte hash a truncated row set would be frozen by hash-skip:
/// every later identical blob would be "touched" with rows missing forever).
struct SoftwareLicensingParse {
    std::vector<AgentLicenseRow> rows;
    std::string effective_user_ref_mode;
    bool over_record_cap{false};
};

/// Parse the `software_licensing` canonical wire blob: records 0x1E-joined,
/// fields 0x1F-joined, record kind in field 0 (§3.1). `lic|` records project
/// positionally (13 fields after the kind: product, vendor, version,
/// license_type, channel, status, expires_at, source, confidence, key_hint,
/// exe_hints, user_scope, user_ref); missing trailing fields stay empty, extra
/// fields are dropped, empty-product rows are dropped. Unknown record kinds
/// (`ent|` until PR2, the live-only `probe_status|`, anything newer) are
/// SKIPPED without error — forward-compat both directions (ADR-0024
/// Decision 3). Every field is UTF-8-scrubbed, §3.3-stripped and clamped;
/// enums are whitelisted to the closed §3.2 vocabularies (C-7 — at projection,
/// after the raw-byte hash by construction); `expires_at` is
/// plausibility-clamped. `collected_at`/`first_seen`/`last_seen` on the rows
/// are left 0 (the ingest entry point stamps `collected_at`; the store stamps
/// the rest). Exposed for tests.
SoftwareLicensingParse parse_software_licensing_blob(const std::string& blob);

/// SHA-256 hex over the raw received blob bytes — THE content hash this source
/// stores (ADR-0024 Decision 3 / roadmap D-2). Exposed so tests can pin
/// "stored hash == sha256(raw bytes), never the claim". Empty string only on
/// digest failure (treated as a transient error by the ingest entry point).
std::string software_licensing_raw_hash(const std::string& blob);

/// Ingest the `software_licensing` source of `report` for `agent_id` into
/// `store`; appends to `ack.need_full` when the server needs a full resend
/// (cold cache / drift / over-cap payload / store error). Does NOT set
/// `ack.received`. No-op when `agent_id` is empty or the source is not
/// present. Drives the store's trichotomy primitives: hash-only reports run
/// `stored_hash` (compare) + `touch`; full payloads run
/// `replace_agent_licenses` with the seam-recomputed raw-byte hash. `metrics`
/// (nullable) receives `yuzu_inventory_ingest_total{source="software_licensing",outcome}`
/// per call.
void ingest_software_licensing_report(SoftwareLicensingStore& store, const std::string& agent_id,
                                      const ::yuzu::agent::v1::InventoryReport& report,
                                      ::yuzu::agent::v1::InventoryAck& ack,
                                      ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server
