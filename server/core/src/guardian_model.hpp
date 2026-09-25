#pragma once

/// @file guardian_model.hpp
/// Pure, no-httplib READ models shared by REST and MCP for the Guardian /
/// Guaranteed State surface (#4037, api-parity programme #2146 Batch A).
///
/// Follows the SAME real precedent as `access_review_model.hpp` /
/// `dex_app_perf_model.hpp` / `network_perf_model.hpp` — every function here
/// returns a plain value type (struct / vector / optional), never a JSON
/// string. `docs/api-twin-recipe.md` §1's own worked example (§8) shows a
/// JSON-string-returning shared builder, but that section is explicitly
/// illustrative-only ("no source files change as part of #3993, which is
/// docs-only") — no shipped model file in this tree actually does that,
/// because `JObj`/`JArr` are each defined LOCALLY inside `rest_api_v1.cpp`
/// and `mcp_server.cpp` (there is no header-exposed shared JSON builder to
/// return a string built from). What actually cannot drift between REST and
/// MCP by construction is the DATA — which store method gets called, with
/// what filter, and what it means — so that is what lives here. Each
/// transport still writes its own few lines of `JObj`/`JArr` field
/// enumeration over the struct returned below; that enumeration is
/// mechanical (list the struct's own fields) and low-risk compared to the
/// query/computation logic these functions centralise.
///
/// All four functions return `std::optional`/`nullopt` on a degraded store
/// read (ADR-0038 catastrophic-read set) — the caller MUST 503 (REST) or
/// otherwise refuse to render, never render an empty/zero result that would
/// misreport the fleet as compliant or a rule as having no reporting agents.
///
/// The six result structs these functions return (`GuardianStatusRollup`
/// through `GuardianDeviceComplianceRollup`, plus its nested
/// `GuardianDeviceComplianceGuardRow`) live in the pure
/// `guardian_types.hpp` (included below), NOT here — this header
/// forward-declares `GuaranteedStateStore`/`BaselineStore` and its functions
/// take them by reference, so it cannot itself sit behind the ADR-0031 WS-A4
/// abstract `guardian_api.hpp` seam (whose closure must name no store type at
/// all, not even by forward declaration — see that header's comment). The
/// seam wraps these SAME functions one-for-one; `guardian_api.cpp`'s
/// `LocalGuardianApi` is the one place that still includes this header.

#include "guardian_types.hpp"

#include <optional>
#include <vector>

namespace yuzu::server {

class GuaranteedStateStore;
class BaselineStore;

/// `agent_scope`: nullopt = whole fleet; engaged (including empty, ADR-0017
/// INV-2) = confine `errored_rules` to exactly these agents, applied in SQL
/// by `errored_rule_count` (INV-3) — never a C++ post-filter. `total_rules`
/// is the global rule-catalogue size and is NEVER confined (a rule has no
/// agent/management-group dimension of its own). Returns `nullopt` on a
/// degraded `rule_names()`/`errored_rule_count()` read.
std::optional<GuardianStatusRollup>
guardian_status_rollup(GuaranteedStateStore& store,
                       const std::optional<std::vector<std::string>>& agent_scope);

/// Per-agent Guaranteed State status rollup — shared by
/// `GET /api/v1/guaranteed-state/status/{agent_id}` and MCP
/// `get_guardian_agent_status` (#2146 Batch B1). A DIFFERENT algorithm from
/// `guardian_status_rollup` above, not a scoped call to it: `total_rules`
/// here is "rules with ANY census entry for THIS agent, intersected against
/// the live rule catalogue" (derived from `agent_rule_statuses_for_agent` +
/// `rule_names_for`), never the global catalogue size the fleet rollup uses.
/// `compliant_rules`/`drifted_rules` stay 0 for the same reason as the fleet
/// rollup — full status ingest lands in a later rung.
///
/// Returns `nullopt` on a degraded `agent_rule_statuses_for_agent()`/
/// `rule_names_for()` read (ADR-0038 catastrophic-read set) — caller MUST
/// refuse to render (503 on REST), never render a silent 0 that would
/// misreport this device as compliant. An agent_id with no census rows is a
/// legitimate empty result (all-zero rollup), not an error.
std::optional<GuardianAgentStatusRollup>
guardian_agent_status_rollup(GuaranteedStateStore& store, const std::string& agent_id);

/// Per-guard fleet-wide agent-status drilldown row — one row per agent that
/// has reported THIS rule's state — shared by the new
/// `GET /api/v1/guaranteed-state/rules/{rule_id}/status` and MCP
/// `get_guardian_rule_status`. This is the data behind
/// `/fragments/guardian/guard/{id}/page`'s fleet-wide agent census
/// (`guardian_routes.cpp::render_guard_page_fragment`), factored out to a
/// pure function so the fragment, REST and MCP compute the SAME census.
///
/// Deliberately does NOT apply the dashboard fragment's own
/// online-folds-to-unknown rollup (an offline agent's LAST reported state
/// forced to "unknown") or its not-implemented-platform augmentation — same
/// "raw census, not the dashboard's offline-agent-folds-to-unknown rollup"
/// posture `GET /guaranteed-state/status` already established
/// (rest_api_v1.cpp) for the identical class of data. A caller wanting
/// online/offline or hostname context correlates `agent_id` against
/// `list_agents`/`GET /api/v1/agents` separately.
///
/// Returns `nullopt` on a degraded `agent_rule_statuses()` read — caller MUST
/// refuse to render (503 on REST), never render an empty list as "no device
/// reports this guard". Does NOT distinguish "rule not found" from "rule
/// exists, no agent has reported yet" (both return an empty, non-nullopt
/// vector) — callers needing that distinction check `get_rule(rule_id)`
/// first (three-state: found / genuinely absent / degraded).
std::optional<std::vector<GuardianRuleAgentStatusRow>>
guardian_rule_agent_status_rows(GuaranteedStateStore& store, const std::string& rule_id);

/// Per-device all-guards view row — one row per guard this device has
/// reported ANY status for, unscoped to any one Baseline — shared by the new
/// `GET /api/v1/guaranteed-state/agents/{agent_id}/rules` and MCP
/// `get_guardian_device_guards`. This is the data behind
/// `/fragments/device/guardian`'s per-device Guardian lens
/// (`device_routes.cpp`), which answers "what is every guard's state for
/// this device" — a genuinely different shape from
/// `GET /guaranteed-state/device-compliance`, which answers "is this device
/// compliant with this ONE Baseline" (requires both `agent_id` AND
/// `baseline`). See the route header comment in rest_api_v1.cpp for why this
/// is a distinct route rather than an optional-`baseline` extension of
/// `device-compliance` (that route's response is baseline-shaped —
/// `baseline{}`/`deployed`/`assessable`/`snapshot_total` — and making
/// `baseline` optional would produce a union-shaped response with no single
/// OpenAPI/output-schema honest description).
///
/// Uses `agent_rule_statuses_for_agent` (a bounded, server-side-filtered
/// query), not the fragment's own `agent_rule_statuses()` unfiltered fleet
/// scan post-filtered in C++ — same modernisation `device-compliance`
/// already made for this identical class of read.
///
/// Returns `nullopt` on a degraded `agent_rule_statuses_for_agent()`/
/// `rule_names_for()` read — caller MUST refuse to render (503 on REST),
/// never render an empty list as "this device has no guards".
std::optional<std::vector<GuardianDeviceGuardRow>>
guardian_device_all_guards(GuaranteedStateStore& store, const std::string& agent_id);

/// Per-baseline device-compliance rollup — shared by
/// `GET /api/v1/guaranteed-state/device-compliance` and MCP
/// `get_guardian_device_compliance` (#2146 Batch B1, extracted post-review).
/// Both twins previously ran this same four-read sequence (baseline lookup,
/// deployed_member_rule_ids, rule_names_for, agent_rule_statuses_for_agent)
/// inline, and both audited "success"/"not_found" right after the FIRST read
/// only — a degrade in any of the other three then produced a 503 the audit
/// row had already called "success". Aggregating all four reads here, behind
/// one nullopt/`store_degraded` contract, means a caller can only audit once
/// every read has actually completed.
///
/// `store_degraded` is a REQUIRED out-param, same contract as
/// `BaselineStore::get_baseline_by_name`'s own `store_ok`: set true the
/// moment ANY of the four underlying reads degrades, at which point the
/// return is always `nullopt` and the caller MUST refuse to render (503),
/// never treat it as "baseline not found". `nullopt` with `*store_degraded
/// == false` means the named baseline genuinely does not exist (400/404) -
/// a real miss, not a fault. A degraded read must never render as a silent
/// 0/compliant result (ADR-0038/ADR-0055 catastrophic-read set) - this
/// function's whole job is making that the only way to call these four
/// reads.
///
/// `pii_access_began` is a SECOND required out-param distinguishing WHICH
/// read degraded, because the audit obligation differs: the baseline lookup
/// (read 1) is genuinely pre-audit (no per-agent PII has been touched yet,
/// same "no PII was looked up yet" posture this route has always had), but
/// the remaining three reads only run once a real baseline was found - the
/// baseline itself being found already counts as having begun accessing
/// this agent's per-baseline standing (`deployed_member_rule_ids`, read 2,
/// derives the enforced set for it), and by the time reads 3/4 run,
/// `agent_rule_statuses_for_agent` (the behavioral-PII read proper) has
/// already executed too - so a degrade in ANY of reads 2/3/4 MUST still be
/// audited as "failure" (matching `guardian_agent_status_rollup`'s sibling
/// posture - over-audit rather than silently drop evidence of a completed
/// PII access). Set false only when `*store_degraded` is also false, or when
/// the degrade was the baseline lookup itself; true for any degrade in the
/// remaining three reads. The caller must audit "failure" when
/// `*store_degraded && *pii_access_began`, and skip the audit entirely only
/// when `*store_degraded && !*pii_access_began`.
std::optional<GuardianDeviceComplianceRollup>
guardian_device_compliance_rollup(BaselineStore& baseline_store, GuaranteedStateStore& store,
                                  const std::string& baseline_name, const std::string& agent_id,
                                  bool* store_degraded, bool* pii_access_began);

} // namespace yuzu::server
