#pragma once

/// @file preflight_eval.hpp
/// Shared (non-pure) glue between the pure verdict layer (preflight_parse.hpp)
/// and the server's ResponseStore + run-store, used IDENTICALLY by the routes
/// (live render of a running run) and the background runner (persist). Keeps the
/// dispatch + correlation + (de)serialization in ONE place so the two paths can
/// never compute a grid differently.
///
/// Correlation: each check in a run gets its own execution_id
/// `preflight-<run_id>-<check_key>`. Every (re-)dispatch of that check reuses it,
/// so ResponseStore::query_by_execution unions all command_ids per agent and
/// latest_per_agent picks the best — the re-dispatch-on-reconnect aggregation
/// falls out for free (the PolicyEvaluator pattern). The `preflight-` prefix is
/// skipped by AgentServiceImpl::notify_exec_tracker (like `polchk-`) so these
/// never reach the executions drawer.

#include "preflight_parse.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class ResponseStore;
class PreflightRunStore;

namespace preflight {

/// Per-check execution_id for a run.
std::string check_execution_id(const std::string& run_id, std::string_view check_key);

/// A check runs only when configured: `app` needs a target name; the rest always.
bool check_applicable(std::string_view key, const PreflightConfig& cfg);

/// The applicable (key, label) checks for a config, in catalogue order.
std::vector<std::pair<std::string, std::string>> applicable_checks(const PreflightConfig& cfg);

/// The plugin/action parameters for a check dispatch (app → {name}, disk → {path}).
std::unordered_map<std::string, std::string> dispatch_params(std::string_view key,
                                                             const PreflightConfig& cfg);

/// Collect each applicable check's per-agent best response via the ResponseStore
/// (query_by_execution on the per-check execution_id + latest_per_agent). MUST
/// NOT be called while holding a PreflightRunStore lease (ADR-0012). Feeds
/// compute_device_results.
std::vector<PreflightCheckResponses>
collect_check_responses(ResponseStore& store, const std::string& run_id,
                        const std::vector<std::pair<std::string, std::string>>& applicable);

/// True iff any check's read degraded (#2691 finding 10). Every caller that
/// would build a grid from `checks` and persist it (the runner tick, the live
/// result poll) MUST check this FIRST and skip persisting/completing when
/// true — retry next tick/poll instead. `compute_device_results` itself stays
/// unaware of degrade (it is the pure verdict layer); this is the gate in
/// front of it.
bool any_check_degraded(const std::vector<PreflightCheckResponses>& checks);

/// (De)serialize a device's checks for run_device.checks_json. Agent-derived
/// values → dump uses the replace error-handler (never throws on odd bytes).
std::string checks_to_json(const std::vector<PreflightDeviceCheck>& checks);
std::vector<PreflightDeviceCheck> checks_from_json(const std::string& json);

/// (De)serialize the thresholds for run.config_json so the runner reconstructs
/// them without re-parsing the request.
std::string config_to_json(const PreflightConfig& cfg);
PreflightConfig config_from_json(const std::string& json);

/// Persist a run's computed grid + summary counts, then complete the run IFF the
/// grid persisted AND it is settled (`!any_pending`) or `past_deadline`. Shared by
/// the background runner (called every tick) and the live result route (called on
/// the settling poll) so a run completes the MOMENT its cohort settles — no
/// up-to-60s runner lag before the result page reads "Complete" and stops polling —
/// and both paths build/persist the grid identically. MUST NOT be
/// called while holding a PreflightRunStore lease (it takes its own). Returns true
/// iff the run was completed by this call.
bool persist_and_maybe_complete(PreflightRunStore& store, const std::string& run_id,
                                const std::vector<PreflightDeviceResult>& grid,
                                std::int64_t now_ms, bool past_deadline, bool any_pending);

} // namespace preflight
} // namespace yuzu::server
