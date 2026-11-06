#pragma once

/// @file workflow_model.hpp
/// Shared, pure JSON row builders for the WorkflowEngine read surface
/// (workflow list/detail, workflow-execution detail) — REST v1
/// (`workflow_routes.cpp`) and MCP (`mcp_server.cpp`) call these SAME
/// functions so their JSON shapes cannot drift from each other by
/// construction (`docs/api-twin-recipe.md` Rule 1).
///
/// No `httplib.h`, no MCP-specific include, no store include. ADR-0031
/// WS-A4's eighth family (`WorkflowApi`, `workflow_api.hpp`) relocated the
/// pure `Workflow`/`WorkflowExecution`/`WorkflowStepResult` types this file
/// needs out of the store-coupled `workflow_engine.hpp` into `workflow_
/// types.hpp` — this file now includes only that pure header, so it is
/// genuinely I/O-free AND store-free, unlike its earlier state. (An earlier
/// version of this file claimed "pure, I/O-free" while also holding the
/// schedule-family builder and `#include`ing both `schedule_engine.hpp` and
/// `workflow_engine.hpp` — that claim was false by the WS-A4 seam's own bar;
/// the seventh family split the schedule builder out into `schedule_model.
/// hpp` first, and this eighth family finishes the job for `workflow`
/// itself.)
///
/// #4030: executions/workflows/schedules read-twin programme.

#include "authz_model.hpp" // authz::VisibleSet / authz::in_scope
#include "workflow_types.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// The most agent ids a run row stores in `agent_ids_json`. The run itself always targets the FULL
/// list the caller named; only the stored copy is bounded, so a looped run over a huge list cannot
/// grow `workflow_executions` by ~1.3 MB a row. 1000 ids of up to 128 bytes is 131,001 bytes of
/// JSON text.
inline constexpr std::size_t kStoredAgentIdsMax = 1000;

/// The most bytes of JSON text a run row stores in `agent_ids_json`, the marker included: 1000 ids
/// of the 128 bytes the v1 and MCP routes allow, quoted and comma-separated, is 131,001 bytes. The
/// legacy execute route checks no id length, so the count alone does not bound the column.
inline constexpr std::size_t kStoredAgentIdsColumnMaxBytes = 131072;

/// An id longer than this, or containing a NUL byte, is never stored (it is counted in the marker's
/// total and digest). This is `auth::kMaxAgentIdLength`, the longest id any agent can have, and
/// registration refuses a NUL, so no real device is dropped.
inline constexpr std::size_t kStoredAgentIdSkipBytes = 256;

/// Bytes held back from the budget for the truncation marker (about 125 with a 20 digit total).
inline constexpr std::size_t kStoredAgentIdsMarkerReserve = 160;

/// The `agent_ids_json` text a run row stores for `agent_ids`.
///
/// The ids are first reduced to the DISTINCT ids in first-seen order (duplicates are dropped before
/// any bound, so padding a list with copies of one id cannot push a real id out). If every distinct
/// id is at most `kStoredAgentIdSkipBytes` long and holds no NUL byte, there are at most `max` of
/// them and their JSON text is at most `max_bytes`, the column is that JSON array of strings, and a
/// list with no duplicates is stored unchanged. Otherwise it holds the ids admitted in this order:
/// those for which `first` answers true (the caller's own visible devices, so a confined caller can
/// still see the run it started), then the rest, each group in first-seen order. Admission stops at `max` ids or when
/// the next id would take the text past `max_bytes` less `kStoredAgentIdsMarkerReserve`; an id over
/// `kStoredAgentIdSkipBytes`, or holding a NUL byte, is skipped (so a copy that skipped one carries
/// the marker even for a short list). The array is then followed by ONE non-string element, the
/// marker `{"truncated":true,"total":<DISTINCT ids named>,"sha256":"<hex>"}`. `total` counts every
/// distinct id including the skipped ones; `sha256` is the digest of the JSON text of the distinct
/// list in first-seen order (the order the dispatcher received it, not the stored order), and is
/// null if the digest provider failed. The marker is an object so every reader that takes only
/// string elements (`workflow_execution_visible`, `confined_workflow_agent_ids_json`, the list SQL)
/// skips it with no change, and the column stays a valid JSON array. `max` and `max_bytes` are
/// seams for tests. The run is dispatched with the list as the caller sent it, never this one.
[[nodiscard]] std::string stored_agent_ids_json(
    const std::vector<std::string>& agent_ids,
    const std::function<bool(const std::string&)>& first = {},
    std::size_t max = kStoredAgentIdsMax, std::size_t max_bytes = kStoredAgentIdsColumnMaxBytes);

/// The number of distinct agent ids the run named when `agent_ids_json` holds a truncated copy (the
/// `stored_agent_ids_json` marker), or `nullopt` for a complete copy, a malformed column or a
/// marker without a usable count.
[[nodiscard]] std::optional<std::int64_t> stored_agent_ids_total(const std::string& agent_ids_json);

/// Adds `agent_ids_truncated: true` to a run detail object when `agent_ids_json` holds a truncated
/// copy, and, for an UNCONFINED reader only, `agent_ids_total` (the count the run named). Nothing
/// is added for a complete copy. The total is withheld from a confined reader on the same ground
/// as a step's `agents_reached`: it would disclose how many agents the run named beyond the
/// reader's scope. One function for the v1 twin, MCP and the legacy route so they cannot drift.
void add_agent_ids_bound(nlohmann::json& detail, const std::string& agent_ids_json,
                         bool confined);

/// List-row shape for `GET /api/workflows` / `GET /api/v1/workflows` / MCP
/// `list_workflows` — per-step summary (no `yaml_source`). Unlike the
/// pre-existing legacy `/api/workflows` list handler, this always includes
/// `retry_delay_seconds` per step (the legacy list omits it while the legacy
/// single-item route includes it — a pre-existing field drift within that
/// one file, not something #4030's new v1/MCP twin should carry forward).
nlohmann::json workflow_row_json(const Workflow& w);

/// Single-item detail shape for `GET /api/workflows/{id}` /
/// `GET /api/v1/workflows/{id}` / MCP `get_workflow` — full step list plus
/// `yaml_source`.
nlohmann::json workflow_detail_json(const Workflow& w);

/// Detail shape for `GET /api/workflow-executions/{id}` /
/// `GET /api/v1/workflow-executions/{id}` / MCP `get_workflow_execution` —
/// per-step results. `agent_ids_json`/`WorkflowStepResult::result_json` are
/// stored as JSON-text columns; this builder parses them permissively
/// (`nlohmann::json::parse(..., nullptr, false)`, matching the legacy
/// route's own tolerance for malformed/legacy rows) rather than failing the
/// whole response over one bad column.
///
/// `scope`, when engaged (non-nullopt), restricts the emitted `agent_ids`
/// array to `authz::in_scope(scope, id)` members (workflow-execution
/// confinement decision, #4030 — a caller confined by `fleet_read_fn` sees
/// only in-scope agent ids). `std::nullopt` is unrestricted, matching every
/// other `VisibleSet` consumer in the tree.
///
/// CALLERS MUST GATE THE RECORD FIRST via `workflow_execution_visible()`
/// below -- this builder only ever field-filters `agent_ids`; it has no way
/// to withhold `status`/`current_step`/`steps[]` for a caller with zero
/// visibility into the execution (#4030 Gate 8 fix, security-guardian Gate
/// 2 finding: the original cut called this builder unconditionally for any
/// id the caller supplied).
nlohmann::json workflow_execution_detail_json(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope);

/// Is `we` visible at all to a caller confined to `scope`? `WorkflowExecution`
/// carries no `dispatched_by` field (unlike `Execution`) — there is
/// deliberately NO ownership fallback here: visibility is
/// `has_visible_agent`-only. A caller who dispatched a workflow but has
/// since been re-scoped out of every one of its target agents loses
/// visibility to it — a consequence of the data model the fix accepts
/// rather than papers over (#4030 Gate 8 fix). `std::nullopt` scope is
/// always visible (unconfined/fleet-wide caller). A malformed/absent
/// `agent_ids_json` fails CLOSED (not visible) for a confined caller rather
/// than silently admitting.
///
/// Full scan, no early exit — mirrors `execution_scope_rules.hpp`'s
/// `execution_visible()` anti-timing-oracle rationale: an early `return
/// true` on the first in-scope id makes wall-clock time a function of WHERE
/// in `agent_ids` the first visible entry falls, a scan-length existence
/// oracle on the admit path.
[[nodiscard]] bool workflow_execution_visible(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope);

/// Confined `agent_ids` array for a workflow execution — parses
/// `agent_ids_json` permissively and narrows to `authz::in_scope(scope,
/// id)` members. Factored out so `workflow_execution_detail_json` and the
/// legacy `GET /api/workflow-executions/:id` route (which keeps its own,
/// differently-shaped response envelope and is therefore not migrated onto
/// the builder above) compute the SAME confined array rather than risking
/// two hand-copied loops drifting apart (#4030 Gate 8 fix).
nlohmann::json confined_workflow_agent_ids_json(const std::string& agent_ids_json,
                                                const authz::VisibleSet& scope);

/// Confined per-step `result` value — parses `result_json` permissively (a
/// parse failure embeds as JSON `null`, never the literal nlohmann
/// `<discarded>` sentinel text that an un-guarded embed produces, #4030
/// Gate 8 fix / Gate 4 unhappy-path finding UP-2) and, when `confined` is
/// true, strips the `agents_reached` key from the result (handles both the
/// single-object and the foreach-expanded array shape
/// `WorkflowEngine::execute` can produce, `workflow_engine.cpp`). That key
/// is the raw fleet-wide dispatch count for the step's FULL target-agent
/// list (`workflow_routes.cpp`'s `dispatch_fn`, `{"agents_reached", sent}`)
/// — not the confined caller's visible subset — so emitting it verbatim to
/// a confined caller discloses the true out-of-scope agent count by simple
/// arithmetic, the same disclosure class this file's sibling KPI strip
/// guards against for `Execution` (`workflow_routes.cpp`, the "#1712"
/// comment on `render_results`'s `total_agent_count`). Shared by
/// `workflow_execution_detail_json` and the legacy route for the same
/// no-drift reason as `confined_workflow_agent_ids_json` above.
nlohmann::json confined_workflow_step_result_json(const std::string& result_json, bool confined);

} // namespace yuzu::server
