#pragma once

/// @file guardian_types.hpp
/// Pure, store-free value types for the Guardian / Guaranteed State surface
/// (ADR-0031 WS-A4, ninth family). Two families of type live here:
///
///   1. `GuaranteedStateRuleRow` / `GuaranteedStateEventRow` /
///      `GuaranteedStateEventQuery` / `GuaranteedStateReadError` — relocated
///      VERBATIM out of `guaranteed_state_store.hpp` (which `#include`s this
///      header back, ODR-safe, so every existing includer keeps seeing them
///      transitively — the same relocation shape `dex_types.hpp` /
///      `schedule_types.hpp` / `workflow_types.hpp` already established).
///   2. The six pure result structs (`GuardianStatusRollup` through
///      `GuardianDeviceComplianceRollup`, plus its nested member type
///      `GuardianDeviceComplianceGuardRow`) — relocated out of
///      `guardian_model.hpp`, whose function DECLARATIONS stay put (they
///      forward-declare `GuaranteedStateStore`/`BaselineStore` and take them
///      by reference, so `guardian_model.hpp` itself cannot sit behind the
///      abstract `guardian_api.hpp` seam — see that header's own comment).
///
/// This header names NO store type at all — no `GuaranteedStateStore`, no
/// `BaselineStore`, not even by forward declaration — so it is safe for the
/// abstract `guardian_api.hpp` to include (the seam-closure abstract-header
/// probe, `scripts/ci/check-seam-closure.py`, text-scans a header's whole
/// transitive closure for a bare `*Store` token; a forward declaration would
/// still match).

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Relocated from guaranteed_state_store.hpp (verbatim) ────────────────────

struct GuaranteedStateRuleRow {
    std::string rule_id;           // UUID
    std::string name;              // unique, human-authored
    std::string yaml_source;       // human-readable rendering (generated; see spec_json)
    // Canonical structured JSON of the Guard (spark/assertion/remediation) —
    // the AUTHORITATIVE form the agent enforces from and that the push proto is
    // built from. yaml_source is rendered one-way from this.
    std::string spec_json;
    // RESERVED (stored, not yet evaluated): the Guard's Prerequisites — a Scope
    // expression over device facts that must hold for the Guard to apply on a
    // device, finer than a Baseline's management-group assignment.
    std::string prerequisites;
    int64_t version{1};
    bool enabled{true};
    std::string enforcement_mode;  // "enforce" | "audit" (validated at the REST boundary; `enabled` controls disable)
    std::string severity;          // "critical" | "high" | "medium" | "low"
    std::string os_target;         // "windows" | "linux" | "macos" | ""=all
    std::string scope_expr;        // server-side scope expression
    std::vector<uint8_t> signature;// HMAC-SHA256 over yaml_source
    std::string created_at;        // ISO-8601
    std::string updated_at;        // ISO-8601
    // Principal who authored the rule (created_by) and who last modified it
    // (updated_by). Required for SOC 2 audit-chain reconstruction alongside
    // audit_events — the REST handler populates both from the session
    // principal; the store is a plain passthrough.
    std::string created_by;
    std::string updated_by;
};

/// Largest accepted Guard rule `version`. An update bumps the stored version by one and
/// the agent push casts it to uint64, so a caller-chosen value near INT64_MAX would
/// overflow the signed increment (UB) and wrap on the wire. Enforced at every writer:
/// `GuaranteedStateStore::create_rule` / `update_rule` (the latter on a version CHANGE only, so a
/// legacy out-of-range row can still be disabled), the REST create + update handlers
/// and the MCP create + update tools, all against these two helpers.
inline constexpr int64_t kMaxRuleVersion = std::numeric_limits<int>::max();
inline constexpr bool rule_version_in_range(int64_t v) noexcept {
    return v >= 1 && v <= kMaxRuleVersion;
}
/// True when the next update bump (`version + 1`) would leave the accepted range. Reachable
/// only for a row stored before the bound existed (or written out of band): refuse the
/// update instead of overflowing.
inline constexpr bool rule_version_exhausted(int64_t v) noexcept {
    return v >= kMaxRuleVersion;
}

struct GuaranteedStateEventRow {
    std::string event_id;          // UUID
    std::string rule_id;
    std::string agent_id;
    std::string event_type;        // "drift.detected" | "drift.remediated" | ...
    std::string severity;
    std::string guard_type;        // "registry" | "etw" | ...
    std::string guard_category;    // "event" | "condition"
    std::string detected_value;
    std::string expected_value;
    // Structured, machine-readable detail (JSON, keyed by event_type). Companion
    // to the human `detected_value`, not a replacement. For DEX observations
    // (process.crashed) it carries the projectable crash facts; "" for plain
    // drift. The DEX read model projects this into indexed columns.
    std::string detail_json;
    std::string remediation_action;
    bool remediation_success{false};
    int64_t detection_latency_us{0};
    int64_t remediation_latency_us{0};
    std::string timestamp;         // ISO-8601
    // Census ordering inputs (schema v4, set by the ingest boundary; a direct store caller may
    // leave both 0). `agent_ns` is the validated agent stamp in nanoseconds, 0 when absent or
    // unusable; `received_ns` is the server receipt in nanoseconds, 0 = the store substitutes its
    // own clock. They feed the store's derived key `min(agent_ns, received_ns + 300 s)` and stay
    // OUT of the duplicate identity. `query_events` does not populate them.
    std::int64_t agent_ns{0};
    std::int64_t received_ns{0};
};

struct GuaranteedStateEventQuery {
    std::string rule_id;           // filter by rule, optional
    std::string agent_id;          // filter by agent, optional
    std::string severity;          // "critical" ... optional
    int limit{100};                // clamped to [1, kMaxEventsLimit] by the store
    int offset{0};
};

// Error surface for the type-distinguishable single-object read (`get_rule`).
// The success type is `std::optional<GuaranteedStateRuleRow>`: a value ==
// found, `std::nullopt` == genuinely no row for this rule_id.
// `std::unexpected(kDegraded)` == store/pool/query failure — the caller shows
// a degrade banner/503, never treats it as absent (mirrors
// `CiReadError` (device_inventory_types.hpp) / `InventoryReadError` exactly).
enum class GuaranteedStateReadError { kDegraded };

// ── Relocated from guardian_model.hpp (verbatim) ─────────────────────────────
// See guardian_model.hpp for the pure functions that build these from a
// GuaranteedStateStore/BaselineStore, and guardian_api.hpp for the seam
// wrapping those same functions behind one method per public REST/MCP
// resource.

/// Fleet Guardian status rollup — shared by `GET /api/v1/guaranteed-state/status`
/// and MCP `get_guardian_status`. `compliant_rules`/`drifted_rules` stay 0
/// until full status ingest lands (unchanged from today) — this struct does
/// not widen the capability, only shares it.
struct GuardianStatusRollup {
    std::int64_t total_rules{0};
    std::int64_t compliant_rules{0};
    std::int64_t drifted_rules{0};
    std::int64_t errored_rules{0};
    std::int64_t uncertain_rules{0}; // rules with an order-uncertain or pending represented pair
};

/// Per-agent Guaranteed State status rollup — shared by
/// `GET /api/v1/guaranteed-state/status/{agent_id}` and MCP
/// `get_guardian_agent_status`. A DIFFERENT algorithm from
/// `GuardianStatusRollup` above: `total_rules` here is "rules with ANY
/// census entry for THIS agent, intersected against the live rule
/// catalogue", never the global catalogue size the fleet rollup uses.
struct GuardianAgentStatusRollup {
    std::int64_t total_rules{0};
    std::int64_t compliant_rules{0};
    std::int64_t drifted_rules{0};
    std::int64_t errored_rules{0};
    std::int64_t uncertain_rules{0}; // rules with an order-uncertain or pending represented pair
};

/// Per-guard fleet-wide agent-status drilldown row — one row per agent that
/// has reported THIS rule's state — shared by
/// `GET /api/v1/guaranteed-state/rules/{rule_id}/status` and MCP
/// `get_guardian_rule_status`.
struct GuardianRuleAgentStatusRow {
    std::string agent_id;
    std::string state;      // "compliant" | "drifted" | "errored"
    std::string updated_at; // ISO-8601 of the event that set it
    bool order_uncertain{false};
    bool projection_pending{false};
};

/// Per-device all-guards view row — one row per guard this device has
/// reported ANY status for, unscoped to any one Baseline — shared by
/// `GET /api/v1/guaranteed-state/agents/{agent_id}/rules` and MCP
/// `get_guardian_device_guards`.
struct GuardianDeviceGuardRow {
    std::string rule_id;
    std::string name;       // resolved rule name; falls back to rule_id if the
                             // rule has since been deleted from the catalogue
    std::string state;      // "compliant" | "drifted" | "errored"
    std::string updated_at; // ISO-8601 of the event that set it
    bool order_uncertain{false};
    bool projection_pending{false};
};

/// Per-baseline device-compliance rollup — shared by
/// `GET /api/v1/guaranteed-state/device-compliance` and MCP
/// `get_guardian_device_compliance`.
struct GuardianDeviceComplianceGuardRow {
    std::string rule_id;
    std::string name;       // resolved rule name; falls back to rule_id if the
                             // rule has since been deleted from the catalogue
    std::string status;     // "compliant" | "drifted" | "errored" | "pending"
    std::string updated_at; // ISO-8601 of the last reported verdict; empty if none
    /// Sticky: the ordering of the persisted verdict for this (device, guard) pair cannot be
    /// proven. false does not prove the verdict is fresh.
    bool order_uncertain{false};
    /// A retained event for this pair is not yet reflected in the census row. false does not
    /// prove the row is complete.
    bool projection_pending{false};
};

struct GuardianDeviceComplianceRollup {
    std::string baseline_id;
    std::string baseline_name;
    std::string baseline_lifecycle;
    bool deployed{false};
    std::int64_t snapshot_total{0}; // deployed_member_rule_ids().size()
    std::int64_t total_guards{0};   // snapshot members this device has reported ANY verdict for
    std::int64_t compliant{0};
    std::int64_t drifted{0};
    std::int64_t errored{0};
    std::int64_t pending{0};
    std::string last_updated; // max reported updated_at across guards; empty if none
                              // (census-only: never advanced by an unrepresented pending event)
    std::vector<GuardianDeviceComplianceGuardRow> guards;
    /// Emitted guards whose row has order_uncertain OR projection_pending, counted once per
    /// guard. Overlaps the verdict counts (compliant/drifted/errored/pending): a drifted guard
    /// with order_uncertain is counted in both. 0 does not establish freshness.
    std::int64_t uncertain_guards{0};
    /// Distinct rule_ids (deployed-snapshot members only) that have retained pending events for
    /// this device and NO census row. Excluded from guards[], total_guards and every verdict
    /// count. The count is exact; the id list is capped by the store. The ids may name a rule no
    /// longer in the catalogue. 0 does not establish completeness.
    std::int64_t unrepresented_pending_guards{0};
    std::vector<std::string> unrepresented_pending_rule_ids;
};

/// Why a per-device Guardian read could not answer (#7217). Reported through the `fault` out-parameter
/// of `GuardianApi::device_guards` / `device_compliance` alongside the existing degrade signal (a
/// `nullopt` result, and `*store_degraded` on compliance). `kTransient` means a retry can succeed
/// (store not open, pool timeout, a failed statement). `kStatementTimeout` means the unrepresented
/// pending read exceeded its time budget (SQLSTATE 57014): the cause is the size of the retained
/// pending backlog, so retrying the same request fails identically until the backlog shrinks and
/// the transports must NOT advertise a retry interval. `kNone` is the value when the read answered.
enum class GuardianReadFault : std::uint8_t { kNone = 0, kTransient, kStatementTimeout };

/// Per-device all-guards report - the rows of `GuardianDeviceGuardRow` plus the unrepresented
/// pending summary. Shared by `GET /api/v1/guaranteed-state/agents/{agent_id}/rules` and MCP
/// `get_guardian_device_guards`.
struct GuardianDeviceGuardsReport {
    /// One row per guard this device has a census row for; each row carries its own
    /// order_uncertain / projection_pending flags.
    std::vector<GuardianDeviceGuardRow> guards;
    /// Distinct rule_ids (ANY rule, not limited to a Baseline) with retained pending events for
    /// this device and NO census row. Excluded from guards[]. The count is exact; the id list is
    /// capped by the store and may name a rule no longer in the catalogue. 0 does not establish
    /// completeness.
    std::int64_t unrepresented_pending_guards{0};
    std::vector<std::string> unrepresented_pending_rule_ids;
};

} // namespace yuzu::server
