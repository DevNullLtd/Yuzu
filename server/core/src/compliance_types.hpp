#pragma once

/// @file compliance_types.hpp
/// Pure data types for the compliance/policy read surface (ADR-0031 WS-A4,
/// the THIRD per-family in-process API seam — `compliance_api.hpp`). Relocated
/// verbatim OUT of `policy_store.hpp` (which stays the store layer, holding
/// `pg::PgPool&` and every mutator) so the seam's abstract header
/// (`compliance_api.hpp`) and the pure model header (`compliance_model.hpp`)
/// can depend on the data shapes WITHOUT dragging in `pg/pg_pool.hpp` or the
/// `PolicyStore` class — mirrors `network_perf_model.hpp`/`app_perf_compare.hpp`
/// for the two merged families. std-only: no pg/store include, no I/O.
///
/// `policy_store.hpp` re-exposes these via `#include "compliance_types.hpp"`
/// so every existing includer keeps seeing them transitively (ODR-safe pure
/// relocation, not a duplication) — `class PolicyStore` and its mutator-only
/// `kPolicyDbErrorPrefix`/`is_db_error`/`strip_db_error_prefix` helpers stay
/// there. `policy_evaluator.hpp`'s `struct Policy; struct PolicyFragment;`
/// forward declarations remain valid — the types still live in
/// `namespace yuzu::server`, just in a different header.

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types (unchanged shape from the SQLite store) ──────────────────────

struct PolicyFragment {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::string check_instruction;
    std::string check_compliance;     // CEL expression (stored, evaluated later)
    std::string check_parameters;     // JSON of parameter bindings
    std::string fix_instruction;
    std::string fix_parameters;       // JSON of parameter bindings
    std::string post_check_instruction;
    std::string post_check_compliance;
    std::string post_check_parameters;
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct PolicyTrigger {
    int64_t id{0};
    std::string policy_id;
    std::string trigger_type;  // "interval", "file_change", "event_log", etc.
    std::string config_json;   // type-specific config (e.g. {"interval_seconds": 300})
};

struct PolicyInput {
    std::string policy_id;
    std::string key;
    std::string value;
};

struct PolicyGroupBinding {
    std::string policy_id;
    std::string group_id;
};

struct Policy {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::string fragment_id;
    std::string scope_expression;
    bool enabled{true};
    int64_t created_at{0};
    int64_t updated_at{0};

    // Populated by query methods (not stored in the policies table directly)
    std::vector<PolicyInput> inputs;
    std::vector<PolicyTrigger> triggers;
    std::vector<std::string> management_groups;
};

struct PolicyAgentStatus {
    std::string policy_id;
    std::string agent_id;
    std::string status;        // "compliant", "non_compliant", "unknown", "fixing", "error"
    int64_t last_check_at{0};
    int64_t last_fix_at{0};
    std::string check_result;  // JSON of last check output
};

struct ComplianceSummary {
    std::string policy_id;
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    int64_t total{0};
};

struct FleetCompliance {
    int64_t total_checks{0};     // total (policy, agent) pairs
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    double compliance_pct{0.0};  // compliant / total * 100
};

struct PolicyQuery {
    std::string name_filter;
    std::string fragment_filter;
    bool enabled_only{false};
    int limit{100};
};

struct FragmentQuery {
    std::string name_filter;
    int limit{100};
};

/// ADR-0036 degrade marker: a read on a dispatch/compliance-feeding path
/// could not be answered (store not open / pool-acquire timeout / query
/// error) — distinct from a genuinely empty result. Callers must never
/// collapse this into "nothing due" / "nothing non-compliant" / "0% fleet
/// compliance".
enum class PolicyReadError { kDegraded };

/// The `compliance_api.hpp` seam's composite `get_policy` result — assembled
/// by `LocalComplianceApi::get_policy` (compliance_api.cpp) from THREE
/// PolicyStore reads (get_policy, get_compliance_summary, and a fail-soft
/// get_fragment lookup for `remediation_available`), mirroring
/// `single_policy_detail_json`'s shape (`compliance_model.hpp`). There is no
/// public `GET /policy-fragments/{id}` resource, so the fragment lookup for
/// `remediation_available` stays an internal assembly step inside the impl,
/// never its own seam method (INV-31-4 — no private core API).
struct PolicyDetail {
    Policy policy;
    ComplianceSummary summary;
    bool remediation_available{false};
};

} // namespace yuzu::server
