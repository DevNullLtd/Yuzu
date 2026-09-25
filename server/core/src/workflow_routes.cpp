#include "workflow_routes.hpp"

#include "command_capability.hpp"        // CommandCapability / ClassificationError / CommandCapabilityRegistry
#include "compliance_eval.hpp"
#include "dispatch_destructive_gate.hpp" // BR-001: evaluate_destructive_targeting / requires_explicit_targets
#include "dispatch_target_shape.hpp" // check_targeting_shape — the omitted-vs-supplied rule (#2500)
#include "event_bus.hpp"
#include "execution_event_bus.hpp"
#include "execution_event_scope.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "principal_quota_gate.hpp" // detail::adopt_quota_slot_into_stream (UP-1)
#include "product_pack_model.hpp" // #4029: shared row/detail builders + error classifiers
#include "rest_a4_envelope.hpp"     // detail::error_json_a4, make_correlation_id
#include "rest_a4_envelope_http.hpp" // detail::a4_denial (deny_service_scoped_scope_estimate) —
                                     // mints/reuses X-Correlation-Id so header and body agree
#include "scope_engine.hpp"
#include "sensitive_instruction_params.hpp" // redact_sensitive_instruction_params (#3136 blocker)
#include "web_utils.hpp"
#include "schedule_model.hpp" // ADR-0031 WS-A4 (seventh family): schedule_row_json, split out of workflow_model.hpp
#include "workflow_model.hpp" // #4030: shared workflow/workflow-execution row builders

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <expected>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

// #4029: `product_pack_error_status`/`product_pack_client_message` moved to
// product_pack_model.hpp — the new GET /api/v1/product-packs* routes and the
// MCP list_product_packs/get_product_pack tools need the same classifiers,
// and a second file-local copy is exactly the duplication
// docs/api-twin-recipe.md's Rule 1 exists to prevent. See that header for the
// (unchanged) behavior/rationale.

// F031/#3481: the same per-kind delete dispatch is needed in two places now — DELETE
// /api/product-packs/:id's uninstall_fn, and POST /api/product-packs's new compensate_fn
// (best-effort undo of items install_fn already committed, on a late persist failure).
// Factored out so the two call sites can't drift.
//
// ADR-0058/ADR-0064: InstructionDefinition and Workflow pass through their store's real
// db_error/not_found split (kProductPackDbErrorPrefix) — a null/unopen store is a genuine
// unavailability, not "this item doesn't exist"; using the tolerated not_found prefix here
// would let the caller (ProductPackStore::uninstall()/install()'s compensation path) proceed
// as if the item were already gone while it's still live underneath. PolicyFragment/Policy's
// origin stores are still bool-only — `false` there maps to a tolerated not_found, matching
// pre-ADR-0058 behaviour for those kinds.
static ItemUninstallFn make_item_delete_fn(InstructionStore* instruction_store,
                                           PolicyStore* policy_store,
                                           WorkflowEngine* workflow_engine) {
    return [instruction_store, policy_store, workflow_engine](
               const std::string& kind,
               const std::string& item_id) -> std::expected<void, std::string> {
        if (kind == "InstructionDefinition") {
            if (!instruction_store)
                return std::unexpected(std::string(kProductPackDbErrorPrefix) +
                                       "instruction store unavailable");
            return instruction_store->delete_definition(item_id);
        } else if (kind == "PolicyFragment") {
            if (policy_store && policy_store->delete_fragment(item_id))
                return {};
            return std::unexpected("not_found: policy fragment '" + item_id + "'");
        } else if (kind == "Policy") {
            if (policy_store && policy_store->delete_policy(item_id))
                return {};
            return std::unexpected("not_found: policy '" + item_id + "'");
        } else if (kind == "Workflow") {
            if (!workflow_engine)
                return std::unexpected(std::string(kProductPackDbErrorPrefix) +
                                       "workflow engine unavailable");
            return workflow_engine->delete_workflow(item_id);
        }
        return std::unexpected("not_found: unsupported item kind '" + kind + "'");
    };
}

// Production overload — wraps the Server in an HttplibRouteSink and forwards
// to the sink-based body. Defined first so callers see a familiar signature.
void WorkflowRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

// Sink-based body — every route registration goes through `sink`, not `svr`,
// so the in-process TestRouteSink can capture handlers and dispatch synthesised
// requests against them without standing up an httplib::Server (#438).
//
// PR 2.5 (#670): the parameter list was 14 deps; PR 2 added a 15th
// (`execution_id` 6th-param to CommandDispatchFn doesn't count toward
// register_routes arity but the count sat at 16 args incl. callbacks);
// PR 3 needs the SSE event-bus pointer. The Deps struct collapses the
// signature to one parameter and keeps the body's local-variable shape
// unchanged via the rebinding step below — every callsite inside the
// function still reads `auth_fn`, `perm_fn`, etc. as before.
void WorkflowRoutes::register_routes(HttpRouteSink& sink, Deps deps) {

    // Rebind to local variables so the rest of the function body reads
    // unchanged. The captures inside route lambdas pick these up by
    // copy (functions) or by raw pointer (stores) — exactly as before
    // the deps refactor. Move-from `deps` happens for the function-typed
    // fields; pointers are trivially copied.
    auto auth_fn = std::move(deps.auth_fn);
    auto perm_fn = std::move(deps.perm_fn);
    // #1712 / #3290 Phase 2 — see WorkflowRoutes::FleetReadFn's doc comment.
    auto fleet_read_fn = std::move(deps.fleet_read_fn);
    auto audit_fn = std::move(deps.audit_fn);
    auto emit_fn = std::move(deps.emit_fn);
    auto scope_fn = std::move(deps.scope_fn);
    auto* workflow_engine = deps.workflow_engine;
    auto* execution_tracker = deps.execution_tracker;
    auto schedule_api = deps.schedule_api; // ADR-0031 WS-A4 (seventh family)
    auto workflow_api = deps.workflow_api; // ADR-0031 WS-A4 (eighth family)
    auto* product_pack_store = deps.product_pack_store;
    auto* instruction_store = deps.instruction_store;
    auto* policy_store = deps.policy_store;
    auto* approval_manager = deps.approval_manager;
    auto* response_store = deps.response_store;
    auto* execution_event_bus = deps.execution_event_bus;
    auto* metrics = deps.metrics;
    auto* capability_registry = deps.capability_registry; // BR-001
    auto cmd_dispatch = std::move(deps.command_dispatch_fn);
    auto cmd_dispatch_concurrency = std::move(deps.command_dispatch_fn_concurrency);
    // K-R7-02 / PLAN-006: per-request DispatchCaller derivation. A missing
    // callback fails CLOSED on visibility at each dispatch site (empty
    // principal, present-empty set, deny all).
    auto caller_fn = std::move(deps.caller_fn);

    // -- HTMX fragments --------------------------------------------------------

    // GET /fragments/executions -- execution history HTMX fragment.
    //
    // Information design:
    //   - Status icon + .exec-row--{class} carries the headline pre-attentively;
    //     failed rows get a red left-border stripe so the eye finds them without
    //     re-sorting.
    //   - Fan-out is encoded as a 4-segment SVG sparkbar (succeeded / failed /
    //     pending / running). Length = count, hue = status. See
    //     `render_status_sparkbar` for the rounding-safe renderer.
    //   - Time renders as a coarse "3m ago" string; ISO-8601 UTC lives in the
    //     cell title= for forensic copy/paste. Mixed-timezone display is a
    //     known failure mode.
    //   - For failed rows we show a 1-line truncation (UTF-8-safe, 80 chars)
    //     of the most recent agent error_detail, populated via correlated
    //     subquery in `query_executions` so there is no N×M lookup.
    //   - Each row carries `hx-trigger="click once"` so the detail fragment is
    //     fetched at most once per row; subsequent clicks toggle visibility.
    //
    // The optional `definition_id` query param filters the list to one
    // definition. Click-handling on the trend sparkline (PR 4) and the
    // dashboard's per-instruction detail page (future) pass it through.
    sink.Get("/fragments/executions", [auth_fn, perm_fn, execution_tracker, instruction_store](
                                          const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        // sec-M1: Execution:Read gate. The LIST exposes definition_name
        // and last_error_detail (per-agent error preview) — same data
        // class as the DETAIL handler, so it earns the same RBAC gate.
        // Mirrors MCP list_executions and REST /api/v1/execution-statistics.
        if (!perm_fn(req, res, "Execution", "Read"))
            return;
        if (!execution_tracker) {
            res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
            return;
        }

        ExecutionQuery q;
        q.limit = 50;
        // Only the LIST fragment renders last_error_detail inline; opt
        // into the correlated subquery here. Other consumers (health
        // probes, metrics ticks at server.cpp:1727) leave the default
        // false and pay zero subquery cost (arch-B2 / perf-B1).
        q.include_error_detail = true;
        if (req.has_param("definition_id")) {
            q.definition_id = req.get_param_value("definition_id");
        }
        auto execs = execution_tracker->query_executions(q);
        std::string html;
        if (execs.empty()) {
            html = "<div class=\"empty-state\">No executions yet.</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        html = "<table class=\"exec-table\"><thead><tr>"
               "<th>Status</th>"
               "<th>Definition</th>"
               "<th>Fan-out</th>"
               "<th>Agents</th>"
               "<th>Result preview</th>"
               "<th>Dispatched by</th>"
               "<th>Time</th>"
               "</tr></thead><tbody>";

        for (const auto& e : execs) {
            // Status hue + row stripe.
            std::string row_class = "exec-row exec-row--" + e.status;
            std::string status_cls = "status-" + e.status;

            // Fan-out counts. The list-view bar shows succeeded / failed /
            // pending — running is folded into pending here because
            // agents_responded only counts terminal statuses; PR 1.4's
            // detail drawer queries per-agent statuses and shows the full
            // 4-bucket breakdown.
            int succeeded = e.agents_success;
            int failed = e.agents_failure;
            int responded = e.agents_responded;
            int targeted = e.agents_targeted;
            int pending = targeted > responded ? (targeted - responded) : 0;
            int running = 0; // distinguishable only in the detail drawer

            // Definition name (or fallback to truncated id).
            std::string def_label;
            std::string def_title;
            if (instruction_store && instruction_store->is_open() && !e.definition_id.empty()) {
                // ADR-0058: a DB-error outer result falls through to the id-truncated
                // fallback below, same as a not-found inner optional did pre-migration
                // — this is a best-effort display label, not a security/dispatch path.
                auto def_result = instruction_store->get_definition(e.definition_id);
                if (def_result && *def_result && !(*def_result)->name.empty()) {
                    def_label = (*def_result)->name;
                    def_title = e.definition_id;
                }
            }
            if (def_label.empty()) {
                def_label = e.definition_id.empty() ? std::string{"<unknown>"}
                                                    : e.definition_id.substr(0, 12);
                def_title = e.definition_id;
            }

            std::string first_error;
            if (failed > 0 && !e.last_error_detail.empty()) {
                first_error = truncate_utf8(e.last_error_detail, 80);
            }

            // The exec-time cell carries `data-epoch-ms` and the JS in
            // instruction_ui.cpp's `renderLocalTimes()` formats it as
            // `HH:MM:SS.mmm <TZ>` in the operator's local timezone (UAT
            // 2026-05-06 #9). The server-rendered text inside the cell
            // is the UTC fallback for no-JS environments; the title
            // attribute keeps the full ISO timestamp with date for
            // cross-day hover correlation.
            std::string time_iso = format_iso_utc(e.dispatched_at);
            int64_t time_ms = e.dispatched_at * 1000;

            // PR 3: data-execution-id / data-execution-status drive the
            // SSE EventSource bootstrap on drawer expand. Status is the
            // execution-row status at LIST-render time; the SSE handler
            // re-validates terminality server-side and returns 410 Gone
            // if the execution finished between LIST render and click,
            // so the client doesn't need to over-think the staleness
            // window.
            html += "<tr class=\"" + row_class +
                    "\" tabindex=\"0\" "
                    "data-execution-id=\"" +
                    html_escape(e.id) +
                    "\" "
                    "data-execution-status=\"" +
                    html_escape(e.status) +
                    "\" "
                    "onclick=\"toggleExecDetail(this)\" "
                    "onkeydown=\"if(event.key==='Enter'||event.key===' ')"
                    "{event.preventDefault();toggleExecDetail(this);}\" "
                    "hx-get=\"/fragments/executions/" +
                    html_escape(e.id) +
                    "/detail\" "
                    "hx-target=\"next .exec-detail-content\" "
                    "hx-trigger=\"click once\" "
                    "hx-swap=\"innerHTML\">";
            html += "<td><span class=\"status-badge " + status_cls + "\">" + html_escape(e.status) +
                    "</span></td>";
            html += "<td><span class=\"exec-def-name\" title=\"" + html_escape(def_title) + "\">" +
                    html_escape(def_label) + "</span></td>";
            html += "<td>" + render_status_sparkbar(succeeded, failed, running, pending) + "</td>";
            html += "<td class=\"exec-agent-count\">" + std::to_string(succeeded) + "/" +
                    std::to_string(failed) + " of " + std::to_string(targeted) + "</td>";
            html += "<td class=\"exec-error-preview\" title=\"" + html_escape(e.last_error_detail) +
                    "\">" + html_escape(first_error) + "</td>";
            html += "<td>" + html_escape(e.dispatched_by) + "</td>";
            html += "<td class=\"exec-time\" data-epoch-ms=\"" + std::to_string(time_ms) +
                    "\" title=\"" + html_escape(time_iso) + "\">" + html_escape(time_iso) + "</td>";
            html += "</tr>";

            // Empty drawer placeholder; HTMX targets the inner div on first
            // click. CSS hides this row until JS toggles `.exec-detail.open`.
            html += "<tr class=\"exec-detail\"><td colspan=\"7\">"
                    "<div class=\"exec-detail-content\">"
                    "<div class=\"empty-state\">Loading…</div>"
                    "</div></td></tr>";
        }
        html += "</tbody></table>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // GET /fragments/executions/{id}/detail -- per-execution detail drawer.
    //
    // Information design:
    //   - KPI strip (top): Total, Succeeded, Failed, p50, p95 — primary scan
    //     target. p50/p95 fall back to "—" if any agent is still running.
    //   - Agent grid: one CSS-grid cell per agent, colored by status. Small
    //     multiples for fan-out — discloses cluster-of-failures patterns that
    //     a 200-row table never could. Bucketed into deciles when fan-out
    //     exceeds 1024 to keep the DOM tractable.
    //   - Per-agent table: failed-first, then duration DESC. Inline
    //     server-rendered horizontal duration bars scaled to the slowest
    //     agent in this run so tail-latency outliers pop visually.
    //   - Responses: collapsed by default (<details>) so opening a drawer
    //     doesn't dump 500 rows. Long output rows collapse individually.
    //   - Sidebar: definition + scope + parameters + dispatched_by/at —
    //     reference data, not scan data.
    //
    // RBAC: Read on Execution. Same securable as MCP `get_execution_status`.
    // Correlation with responses uses the timestamp+agent join (PR 2 swaps
    // to exact `execution_id` correlation transparently).
    sink.Get(
        R"(/fragments/executions/([A-Za-z0-9_-]{1,128})/detail)",
        [auth_fn, fleet_read_fn, audit_fn, execution_tracker, instruction_store,
         response_store](const httplib::Request& req, httplib::Response& res) {
            // #1712 / #3290 Phase 2 — migrated onto require_fleet_read
            // (fleet_read_fn), mirroring query_installed_software / the REST
            // /api/v1/inventory/software twin exactly: the gate is now the
            // SOLE auth+authz check for this route (it calls require_auth
            // internally). It is never stacked with perm_fn (the BLOCKING defect
            // require_fleet_read's own doc comment warns against). auth_fn is
            // re-read only to obtain the admitted principal for the dispatcher
            // ownership rule below. Scopes the "Responses" section below
            // (#1712); the per-agent status grid above it reads from
            // ExecutionTracker, a distinct store from ResponseStore -- it is
            // filtered too, once, immediately after fetch (see the grid
            // fetch below), a same-PR adversarial-review finding: the gate
            // migration itself admits a confined caller class the old flat
            // gate denied outright, so the grid needed the same filter as
            // the responses section, not just the table.
            if (!fleet_read_fn) {
                spdlog::error("/fragments/executions/.../detail: fleet_read_fn unwired — "
                              "misconfigured call site; failing closed");
                res.status = 503;
                res.set_content("<div class=\"empty-state\">Service unavailable</div>",
                                "text/html; charset=utf-8");
                return;
            }
            auto gate = fleet_read_fn(req, res, "Execution", "Read");
            if (!gate.admitted)
                return; // gate already wrote the A4 error body + status.
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!execution_tracker) {
                res.status = 503;
                res.set_content("<div class=\"empty-state\">Tracker not available</div>",
                                "text/html; charset=utf-8");
                return;
            }
            auto exec_id = req.matches[1].str();
            // Governance fix (#2146 A2-R1 Gate 8 re-review): was the plain
            // get_execution(), which collapses "row genuinely absent" and
            // "read degraded" (pool/query failure) to the same nullopt -- a
            // transient degrade here fell through to the not-found +
            // denial-audit branch below, producing a FALSE 404 for a
            // legitimate owner and a permanently wrong CC7.2 audit trail for
            // a non-owner. get_execution_checked's outer std::expected
            // distinguishes the two; the degrade branch below matches this
            // same route's own agents_opt degrade handling just underneath.
            auto exec_r = execution_tracker->get_execution_checked(exec_id);
            if (!exec_r) {
                res.status = 503;
                res.set_content(
                    "<div class=\"empty-state\">Execution tracker degraded, retry "
                    "shortly.</div>",
                    "text/html; charset=utf-8");
                return;
            }
            const auto& exec_opt = *exec_r;
            // #1634 (Doomgoose review finding, important): fail closed on a
            // transient tracker degrade rather than silently treat it as
            // "zero agents" — see get_agent_statuses_checked's doc comment.
            // Fetched unconditionally (not gated on gate.scope): every
            // downstream consumer of `agents` below (KPI counts, decile
            // bucketing, the per-agent table, the legacy-fallback in_set
            // join) needs the real set for BOTH restricted and unrestricted
            // callers — only the visibility/audit decision below is
            // scope-conditional.
            auto agents_opt = execution_tracker->get_agent_statuses_checked(exec_id);
            if (!agents_opt) {
                res.status = 503;
                res.set_content(
                    "<div class=\"empty-state\">Execution tracker degraded — retry "
                    "shortly.</div>",
                    "text/html; charset=utf-8");
                return;
            }
            auto agents = std::move(*agents_opt);
            bool has_visible_agent = false;
            if (gate.scope) {
                for (const auto& a : agents)
                    has_visible_agent = authz::in_scope(gate.scope, a.agent_id) || has_visible_agent;
            }
            const bool owns_execution =
                exec_opt && exec_opt->dispatched_by == session->username;
            if (!exec_opt || (gate.scope && !owns_execution && !has_visible_agent)) {
                // #1634 (governance Gate 6 compliance-officer finding): a
                // suppressed cross-operator read attempt is CC7.2-evidence-worthy
                // the same way the REST twin (GET /api/v1/executions/{id},
                // action execution.detail.fetch) and MCP get_execution_status
                // already audit their own denials — this route keeps its own
                // pre-existing action name (execution.detail.view, matching
                // its success row below) rather than adopting the REST twin's,
                // but uses the SAME non-distinguishing detail text so no
                // enumeration oracle is reopened via query_audit_log.
                (void)audit_fn(req, "execution.detail.view", "denied", "Execution", exec_id,
                               "not found or outside caller's fleet-read scope");
                res.status = 404;
                res.set_content("<div class=\"empty-state\">Execution not found</div>",
                                "text/html; charset=utf-8");
                return;
            }
            const auto& exec = *exec_opt;
            // #1634 residual: status rows are response-arrival seeded. A confined
            // non-dispatcher sees a teammate's in-scope execution only after the
            // first visible response lands; this fails safe and avoids metadata leaks.
            // #1712 adversarial-review finding (blocker): migrating this route's
            // gate onto require_fleet_read admits a caller class (confined-only
            // via the #1715(a) additive grant) the OLD flat perm_fn gate denied
            // outright -- that caller previously got a 403 for this whole route,
            // never partial data. Filtering ONLY the "Responses" section (below)
            // and not this status grid would mean the gate migration itself
            // WIDENS what a newly-admitted confined caller sees, not narrows it.
            // Filtered here, once, so every downstream consumer (KPI counts,
            // decile bucketing, the per-agent table, and the legacy-fallback
            // in_set join) sees only in-scope agents -- same pattern as the
            // Responses section's authz::in_scope filter below.
            if (gate.scope) {
                std::vector<AgentExecStatus> visible;
                visible.reserve(agents.size());
                for (auto& a : agents) {
                    if (authz::in_scope(gate.scope, a.agent_id))
                        visible.push_back(std::move(a));
                }
                agents.swap(visible);
            }

            // -- Definition lookup -------------------------------------------
            std::string def_name = exec.definition_id;
            if (instruction_store && instruction_store->is_open() && !exec.definition_id.empty()) {
                // ADR-0058: a DB-error outer result falls through to the id fallback
                // above, same as a not-found inner optional did pre-migration.
                if (auto def_result = instruction_store->get_definition(exec.definition_id);
                    def_result && *def_result && !(*def_result)->name.empty()) {
                    def_name = (*def_result)->name;
                }
            }

            // -- Per-agent metrics: bucket counts + duration vector ----------
            int succeeded = 0, failed = 0, running = 0, pending = 0;
            int64_t max_dur_ms = 0;
            std::vector<int64_t> durations_ms;
            durations_ms.reserve(agents.size());
            bool any_running = false;
            for (const auto& a : agents) {
                if (a.status == "success")
                    ++succeeded;
                else if (a.status == "failure" || a.status == "timeout" || a.status == "rejected")
                    ++failed;
                else if (a.status == "running") {
                    ++running;
                    any_running = true;
                } else
                    ++pending;

                int64_t dispatched = a.dispatched_at;
                int64_t completed = a.completed_at;
                if (dispatched > 0 && completed > dispatched) {
                    int64_t dur = (completed - dispatched) * 1000; // → ms
                    durations_ms.push_back(dur);
                    if (dur > max_dur_ms)
                        max_dur_ms = dur;
                }
            }

            // -- KPI strip ---------------------------------------------------
            // Sort once; both p50 and p95 index into the same sorted vector
            // (perf-B2 / cpp-S3). Empty when any agent is still running, the
            // sentinel branch in fmt_pct returns "—" without a sort.
            std::vector<int64_t> sorted_durations;
            if (!any_running && !durations_ms.empty()) {
                sorted_durations = durations_ms;
                std::sort(sorted_durations.begin(), sorted_durations.end());
            }
            auto fmt_pct = [&](double p) -> std::string {
                if (sorted_durations.empty())
                    return std::string{"—"};
                std::size_t idx = static_cast<std::size_t>(p * (sorted_durations.size() - 1));
                if (idx >= sorted_durations.size())
                    idx = sorted_durations.size() - 1;
                int64_t v = sorted_durations[idx];
                if (v < 1000)
                    return std::format("{} ms", v);
                if (v < 60000)
                    return std::format("{:.1f} s", v / 1000.0);
                return std::format("{}m {}s", v / 60000, (v % 60000) / 1000);
            };

            std::string html;
            html.reserve(8192);
            html += "<div class=\"exec-detail-grid\">";

            // KPI strip — id-tagged for the SSE drawer (#exec-kpi-{id}). PR 3
            // listeners locate this strip via id and swap individual cell
            // values rather than re-rendering the whole strip.
            html += "<div class=\"exec-kpi-strip\" id=\"exec-kpi-" + html_escape(exec.id) + "\">";
            // #1712 adversarial-review + Gate 4 unhappy-path finding UP-1: for
            // an unscoped caller this must stay exec.agents_targeted (the
            // legitimate mid-dispatch total, byte-identical to pre-migration
            // -- see the SSE live-update path in instruction_ui.cpp's
            // execApplyProgress, which pushes this same field and must not
            // regress for that caller class). For a scoped caller, using the
            // unfiltered dispatch total here -- while Succeeded/Failed/the
            // grid are all correctly filtered -- discloses how many
            // out-of-scope agents exist by simple subtraction, the same
            // disclosure class dashboard_routes.cpp's render_results()
            // guards against by recomputing total_agent_count post-filter.
            html += std::format("<div class=\"exec-kpi\"><div class=\"exec-kpi-value\">{}</div>"
                                "<div class=\"exec-kpi-label\">Total</div></div>",
                                gate.scope ? agents.size() : static_cast<std::size_t>(exec.agents_targeted));
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value exec-kpi-value--ok\">{}</div>"
                "<div class=\"exec-kpi-label\">Succeeded</div></div>",
                succeeded);
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value exec-kpi-value--err\">{}</div>"
                "<div class=\"exec-kpi-label\">Failed</div></div>",
                failed);
            html += std::format("<div class=\"exec-kpi\"><div class=\"exec-kpi-value\">{}</div>"
                                "<div class=\"exec-kpi-label\">p50 duration</div></div>",
                                fmt_pct(0.5));
            html += std::format("<div class=\"exec-kpi\"><div class=\"exec-kpi-value\">{}</div>"
                                "<div class=\"exec-kpi-label\">p95 duration</div></div>",
                                fmt_pct(0.95));
            html += "</div>";

            // -- Agent grid (small multiples) -------------------------------
            html += "<div class=\"agent-grid-wrap\">";
            html += "<h4>Agent fan-out</h4>";
            html += "<div class=\"agent-grid\" id=\"agent-grid-" + html_escape(exec.id) + "\">";

            constexpr std::size_t kBucketThreshold = 1024;
            if (agents.size() > kBucketThreshold) {
                // Decile bucketing — render 10 buckets per status.
                // Keeps DOM bounded for huge fan-outs while preserving the
                // proportional-area read.
                struct Bucket {
                    int succeeded{0}, failed{0}, running{0}, pending{0};
                };
                Bucket buckets[10] = {};
                for (std::size_t i = 0; i < agents.size(); ++i) {
                    std::size_t b = i * 10 / agents.size();
                    if (b >= 10)
                        b = 9;
                    const auto& a = agents[i];
                    if (a.status == "success")
                        ++buckets[b].succeeded;
                    else if (a.status == "failure" || a.status == "timeout" ||
                             a.status == "rejected")
                        ++buckets[b].failed;
                    else if (a.status == "running")
                        ++buckets[b].running;
                    else
                        ++buckets[b].pending;
                }
                for (int i = 0; i < 10; ++i) {
                    const auto& b = buckets[i];
                    int total = b.succeeded + b.failed + b.running + b.pending;
                    const char* dom_status = b.failed > 0              ? "failed"
                                             : b.running > 0           ? "running"
                                             : b.pending > b.succeeded ? "pending"
                                                                       : "succeeded";
                    auto label =
                        std::format("Decile {}: {} succeeded / {} failed / {} running / {} pending",
                                    i + 1, b.succeeded, b.failed, b.running, b.pending);
                    html +=
                        std::format("<div class=\"agent-cell agent-cell--bucket agent-cell--{}\" "
                                    "title=\"{}\" aria-label=\"{}\">{}</div>",
                                    dom_status, html_escape(label), html_escape(label), total);
                }
            } else {
                for (const auto& a : agents) {
                    std::string dom_status;
                    if (a.status == "success")
                        dom_status = "succeeded";
                    else if (a.status == "failure" || a.status == "timeout" ||
                             a.status == "rejected")
                        dom_status = "failed";
                    else if (a.status == "running")
                        dom_status = "running";
                    else
                        dom_status = "pending";

                    int64_t dur_ms = 0;
                    if (a.dispatched_at > 0 && a.completed_at > a.dispatched_at) {
                        dur_ms = (a.completed_at - a.dispatched_at) * 1000;
                    }
                    auto title = std::format("{} · {} · {} ms", a.agent_id, a.status, dur_ms);
                    // Bind agent_id and exec_id via data-* attributes rather
                    // than interpolating into a JS string literal in an
                    // onclick handler. html_escape converts ' to &#39; which
                    // the HTML parser un-escapes BEFORE the JS lexer sees the
                    // attribute value, so a single quote in agent_id would
                    // terminate the JS literal and inject (UP-1). agent_id is
                    // wire-provided by the agent on Register and is not yet
                    // schema-validated. data-attribute + delegated listener
                    // in instruction_ui.cpp keeps the user-controlled bytes
                    // out of any JS-string context.
                    html += std::format("<div class=\"agent-cell agent-cell--{}\" "
                                        "title=\"{}\" aria-label=\"{}\" "
                                        "data-agent-id=\"{}\" data-exec-id=\"{}\"></div>",
                                        dom_status, html_escape(title), html_escape(title),
                                        html_escape(a.agent_id), html_escape(exec.id));
                }
            }
            html += "</div></div>"; // agent-grid + agent-grid-wrap

            // -- Per-agent table (failed first, then duration DESC) ----------
            html += "<div class=\"per-agent-table-wrap\">";
            html += "<h4>Agent results</h4>";
            html += "<table class=\"per-agent-table\"><thead><tr>"
                    "<th>Agent</th><th>Status</th><th>Exit</th><th>Duration</th>"
                    "<th>Error</th></tr></thead><tbody>";

            std::vector<AgentExecStatus> sorted_agents = agents;
            std::sort(sorted_agents.begin(), sorted_agents.end(),
                      [](const AgentExecStatus& l, const AgentExecStatus& r) {
                          auto rank = [](const std::string& s) {
                              if (s == "failure" || s == "timeout" || s == "rejected")
                                  return 0;
                              if (s == "running")
                                  return 1;
                              if (s == "pending")
                                  return 2;
                              return 3; // success last
                          };
                          int rl = rank(l.status), rr = rank(r.status);
                          if (rl != rr)
                              return rl < rr;
                          int64_t dl = (l.dispatched_at > 0 && l.completed_at > l.dispatched_at)
                                           ? (l.completed_at - l.dispatched_at)
                                           : -1;
                          int64_t dr = (r.dispatched_at > 0 && r.completed_at > r.dispatched_at)
                                           ? (r.completed_at - r.dispatched_at)
                                           : -1;
                          return dl > dr;
                      });

            for (const auto& a : sorted_agents) {
                // Wire vocabulary for `a.status`: success / failure /
                // timeout / rejected / running / pending. DOM/CSS
                // vocabulary is a separate set: succeeded / failed /
                // running / pending. Previous code emitted
                // `"status-" + a.status` — producing `.status-success` /
                // `.status-failure` / `.status-timeout` which had NO
                // matching CSS rule, so failed/timed-out agents
                // rendered with no colour. SSE swap then emitted yet a
                // third spelling (`.status-error`). Three vocabularies
                // for one concept (governance round ca-PR3-7).
                // Canonicalise here on the DOM vocabulary; the SSE swap
                // in instruction_ui.cpp does the same translation, so
                // initial render and live update produce identical
                // class strings. CSS gains `.status-succeeded` to
                // cover the new value alongside the existing
                // `.status-failed` / `.status-running` / `.status-pending`.
                std::string dom_status;
                if (a.status == "success")
                    dom_status = "succeeded";
                else if (a.status == "failure" || a.status == "timeout" || a.status == "rejected")
                    dom_status = "failed";
                else if (a.status == "running")
                    dom_status = "running";
                else
                    dom_status = "pending";
                std::string status_cls = "status-" + dom_status;

                int64_t dur_ms = 0;
                if (a.dispatched_at > 0 && a.completed_at > a.dispatched_at) {
                    dur_ms = (a.completed_at - a.dispatched_at) * 1000;
                }
                auto err_short = truncate_utf8(a.error_detail, 120);

                // data-* attributes (not id=) are the binding contract for
                // the agent-grid → row scroll. The legacy id is kept for any
                // future deep-link case but the click handler in
                // instruction_ui.cpp matches via getAttribute('data-agent-id')
                // so dash-in-id collisions (UP-19) cannot occur.
                html +=
                    std::format("<tr id=\"per-agent-row-{}-{}\" "
                                "data-exec-id=\"{}\" data-agent-id=\"{}\">"
                                "<td><code>{}</code></td>",
                                html_escape(exec.id), html_escape(a.agent_id), html_escape(exec.id),
                                html_escape(a.agent_id), html_escape(a.agent_id));
                // PR 3: `.per-agent-status` is the live-update binding.
                // The SSE `agent-transition` listener swaps innerHTML +
                // status-class on this span without re-rendering the row.
                html += "<td><span class=\"status-badge per-agent-status " + status_cls + "\">" +
                        html_escape(a.status) + "</span></td>";
                html +=
                    "<td class=\"per-agent-exit-code\">" + std::to_string(a.exit_code) + "</td>";
                html += "<td>" + render_duration_bar_html(dur_ms, max_dur_ms, dom_status) +
                        std::format(" <span class=\"duration-text\">{} ms</span>", dur_ms) +
                        "</td>";
                html += "<td title=\"" + html_escape(a.error_detail) + "\">" +
                        html_escape(err_short) + "</td></tr>";
            }
            html += "</tbody></table></div>";

            // -- Responses (collapsed) ---------------------------------------
            html += "<div class=\"per-agent-responses-wrap\">";
            if (response_store && response_store->is_open()) {
                ResponseQuery rq;
                rq.since = exec.dispatched_at;
                rq.until = exec.completed_at > 0 ? exec.completed_at : now_epoch_seconds();
                rq.limit = 500;
                // PR 2: prefer exact correlation via the new execution_id
                // column. Falls back to the legacy timestamp-window-+-agent
                // join on stores that haven't been backfilled to v2 yet
                // (response rows with execution_id='' from a pre-PR-2
                // server upgrade). Once an admin runs the backfill CLI
                // (PR 2.1 follow-up) and audits show 100% coverage, the
                // fallback can be removed.
                // #2691 (Doomgoose finding #7): still falls through to the
                // legacy-window attempt on empty exactly as an engaged-empty
                // result would (ADR-0039 deny-or-benign — this is an
                // informational drawer, not a gate), but `store_degraded`
                // stays distinguishable through to the render below so a
                // failed read doesn't print "No responses recorded."
                auto primary_opt = response_store->query_by_execution(exec.id, rq);
                bool store_degraded = !primary_opt.has_value();
                auto responses = primary_opt.value_or(std::vector<StoredResponse>{});
                if (responses.empty()) {
                    auto legacy_opt = response_store->query(exec.definition_id, rq);
                    store_degraded = store_degraded || !legacy_opt.has_value();
                    auto legacy = legacy_opt.value_or(std::vector<StoredResponse>{});
                    // Filter to agents that appear in this execution's
                    // status set, mirroring the pre-PR-2 best-effort join.
                    std::unordered_map<std::string, bool> in_set;
                    in_set.reserve(agents.size());
                    for (const auto& a : agents)
                        in_set[a.agent_id] = true;
                    for (auto& r : legacy) {
                        // Only fall back for legacy rows (empty
                        // execution_id). PR-2-tagged rows with a different
                        // execution_id are NOT this run's responses; the
                        // empty `responses` vector is the correct answer.
                        if (r.execution_id.empty() && in_set.count(r.agent_id))
                            responses.push_back(std::move(r));
                    }
                }
                std::vector<StoredResponse> filtered = std::move(responses);

                // #1712 / #3290 Phase 2 — scope filter (the gate's composed
                // meet(management-group, service-scope) VisibleSet). Applied
                // once, after the primary + legacy-window fallback have
                // already been merged into `filtered` above, so this single
                // filter covers both fetch paths. nullopt (TOP) ⇒ unfiltered
                // — byte-identical to the pre-#1712 path for that caller
                // class.
                if (gate.scope) {
                    std::vector<StoredResponse> visible;
                    visible.reserve(filtered.size());
                    for (auto& r : filtered) {
                        if (authz::in_scope(gate.scope, r.agent_id))
                            visible.push_back(std::move(r));
                    }
                    filtered.swap(visible);
                }

                html += std::format("<details class=\"per-agent-responses\">"
                                    "<summary>Show responses ({})</summary>",
                                    filtered.size());
                if (store_degraded) {
                    html += "<div class=\"empty-state result-degrade-banner\">"
                            "<b>Responses unavailable.</b> The response store could "
                            "not be read (Postgres pool/query degraded). This is "
                            "<b>not</b> \"no responses\" — retry shortly.</div>";
                } else if (filtered.empty()) {
                    html += "<div class=\"empty-state\">No responses recorded.</div>";
                } else {
                    html += "<table class=\"per-agent-responses-table\"><thead><tr>"
                            "<th>Agent</th><th>Time</th><th>Status</th><th>Output</th>"
                            "<th>Error</th></tr></thead><tbody>";
                    for (const auto& r : filtered) {
                        // UAT 2026-05-06 #10: server-side ingest wall-clock,
                        // millisecond precision. Falls back to `timestamp * 1000`
                        // for legacy rows (received_at_ms == 0). The
                        // instruction_ui.cpp `renderLocalTimes` JS formats this
                        // as `HH:MM:SS.mmm <TZ>` in the operator's local
                        // timezone; the cell text + title attribute keep the
                        // UTC ISO timestamp as a fallback for no-JS contexts.
                        int64_t arrived_ms =
                            r.received_at_ms > 0 ? r.received_at_ms : r.timestamp * 1000;
                        html += "<tr><td><code>" + html_escape(r.agent_id) + "</code></td>";
                        html += "<td class=\"resp-arrived\" data-epoch-ms=\"" +
                                std::to_string(arrived_ms) + "\" title=\"" +
                                format_iso_utc(r.timestamp) + "\">" + format_iso_utc(r.timestamp) +
                                "</td>";
                        html += "<td>" + std::to_string(r.status) + "</td>";
                        html += "<td><details class=\"resp-output\"><summary>output</summary>"
                                "<pre>" +
                                html_escape(r.output) + "</pre></details></td>";
                        html += "<td>" + html_escape(r.error_detail) + "</td></tr>";
                    }
                    html += "</tbody></table>";
                }
                html += "</details>";
            } else {
                html += "<div class=\"empty-state\">Response store not available.</div>";
            }
            html += "</div>";

            // -- Sidebar metadata --------------------------------------------
            html += "<aside class=\"exec-detail-sidebar\">";
            html += "<h4>Definition</h4><div>" + html_escape(def_name) +
                    "</div>"
                    "<div class=\"exec-detail-meta-id\"><code>" +
                    html_escape(exec.definition_id) + "</code></div>";
            html += "<h4>Dispatched by</h4><div>" + html_escape(exec.dispatched_by) + "</div>";
            html += "<h4>Dispatched at</h4><div>" +
                    html_escape(format_iso_utc(exec.dispatched_at)) + "</div>";
            html += "<h4>Completed at</h4><div>" + html_escape(format_iso_utc(exec.completed_at)) +
                    "</div>";
            // #1634 (Doomgoose review finding, blocking): this sidebar must
            // apply the same confined projection as the REST twin
            // (rest_api_v1.cpp GET /api/v1/executions/{id}) — ownership
            // admits VISIBILITY only, never a bypass of this redaction,
            // dispatcher included (mirrors that route's own comment).
            const std::string scope_display =
                gate.scope ? "(redacted - confined view)" : exec.scope_expression;
            const std::string params_display =
                gate.scope ? "(redacted - confined view)" : exec.parameter_values;
            if (!scope_display.empty()) {
                html += "<h4>Scope</h4><code class=\"exec-detail-scope\">" +
                        html_escape(scope_display) + "</code>";
            }
            if (!params_display.empty()) {
                html += "<h4>Parameters</h4><pre class=\"exec-detail-params\">" +
                        html_escape(params_display) + "</pre>";
            }
            html += "</aside>";

            html += "</div>"; // exec-detail-grid
            res.set_content(html, "text/html; charset=utf-8");

            // sec-M2: emit audit on the forensic-data read so SOC 2 can
            // answer "who viewed execution X's per-agent error data and
            // parameters between dates A and B?". Mirrors MCP
            // get_execution_status's audit pattern. The LIST handler
            // intentionally does not audit per the documented fragment-route
            // policy (only routes returning forensic-grade content audit).
            audit_fn(req, "execution.detail.view", "success", "Execution", exec.id, "");
        });

    // -------------------------------------------------------------------------
    // GET /sse/executions/{id} -- live drawer updates (PR 3).
    //
    // SSE channel that fans out per-execution transitions to subscribed
    // browser EventSources. The handler:
    //   1. Applies the fleet-read gate for `Read` on `Execution` (same
    //      securable as detail). Denials short-circuit before the chunked
    //      provider is attached so RBAC matches the rest of the surface.
    //   2. Resolves the execution via `execution_tracker->get_execution`;
    //      404 for unknown id, 410 (Gone) when the execution is already
    //      terminal so the client closes its EventSource without spinning
    //      a reconnect loop on the auto-reconnect path.
    //   3. On HTTP `Last-Event-ID` request header, atomically subscribes and
    //      replays ring-buffer events with id > Last-Event-ID, bounded by
    //      `kBufferCap` (1000 events, ~30 s window).
    //   4. Subscribes to the per-execution channel; the listener
    //      queues events onto the per-connection `SseSinkState`. Heartbeat
    //      every 3 s comes from the existing `sse_content_provider`.
    //   5. Cleanup: `sse_resource_release` runs when httplib closes the
    //      connection (operator nav-away, terminal-status close, browser
    //      EventSource error). Unsubscribes from the channel; the channel
    //      itself is GC'd by `gc_terminal_channels` when retention expires.
    //
    // Audit policy: emit `execution.live_subscribe` on every successful
    // Subscribe. The handler does NOT dedup per session-per-execution
    // currently — dedup is deferred (governance Deferred-5 / #700) because
    // a correct implementation needs lock-protected seen-set state, and a
    // naive dedup has a TOCTOU window where a concurrent reconnect can
    // both observe "not seen" and both emit. Operators on the SOC 2 evidence
    // chain currently get a row per reconnect; the forensic-grade audit on
    // first-load remains on /fragments/executions/{id}/detail's
    // `execution.detail.view`.
    auto* stream_budget = deps.stream_budget;
    sink.Get(R"(/sse/executions/([A-Za-z0-9_-]{1,128}))",
             [auth_fn, fleet_read_fn, audit_fn, execution_tracker, execution_event_bus,
              stream_budget](const httplib::Request& req, httplib::Response& res) {
                 if (!fleet_read_fn) {
                     spdlog::error("/sse/executions/{{id}}: fleet_read_fn unwired");
                     res.status = 503;
                     res.set_content("live updates not available", "text/plain; charset=utf-8");
                     return;
                 }
                 auto gate = fleet_read_fn(req, res, "Execution", "Read");
                 if (!gate.admitted)
                     return;
                 auto session = auth_fn(req, res);
                 if (!session)
                     return;
                 if (!execution_tracker) {
                     res.status = 503;
                     res.set_content("tracker not available", "text/plain; charset=utf-8");
                     return;
                 }
                 if (!execution_event_bus) {
                     // Bus disabled (test harness opted out, or a configuration
                     // path that didn't construct one). 503 is the right code:
                     // the route exists but the underlying event source is
                     // intentionally not wired.
                     res.status = 503;
                     res.set_content("live updates not available", "text/plain; charset=utf-8");
                     return;
                 }
                 auto exec_id = req.matches[1].str();
                 // Governance fix (#2146 A2-R1 Gate 8 re-review): was the
                 // plain get_execution(), which collapses "row genuinely
                 // absent" and "read degraded" (pool/query failure) to the
                 // same nullopt -- a transient degrade here fell through to
                 // the not-found + denial-audit branch below, producing a
                 // FALSE 404 for a legitimate owner and a permanently wrong
                 // CC7.2 audit trail for a non-owner. get_execution_checked's
                 // outer std::expected distinguishes the two; the degrade
                 // branch below matches this same route's own agents_opt
                 // degrade handling a few lines down.
                 auto exec_r = execution_tracker->get_execution_checked(exec_id);
                 if (!exec_r) {
                     res.status = 503;
                     res.set_content("live updates unavailable, tracker degraded, retry "
                                    "shortly",
                                    "text/plain; charset=utf-8");
                     return;
                 }
                 const auto& exec_opt = *exec_r;
                 // #1634 perf (governance Gate 3 finding): only fetch/scan agent
                 // statuses when confined — an unrestricted subscriber is always
                 // visible regardless, so this indexed lookup would be pure
                 // waste on every SSE subscribe.
                 bool has_visible_agent = false;
                 if (gate.scope) {
                     // #1634 (Doomgoose review finding, important): fail
                     // closed on a transient tracker degrade rather than
                     // silently treat it as "zero agents" — see
                     // get_agent_statuses_checked's doc comment.
                     auto agents_opt = execution_tracker->get_agent_statuses_checked(exec_id);
                     if (!agents_opt) {
                         res.status = 503;
                         res.set_content("live updates unavailable — tracker degraded, retry "
                                        "shortly",
                                        "text/plain; charset=utf-8");
                         return;
                     }
                     for (const auto& a : *agents_opt)
                         has_visible_agent =
                             authz::in_scope(gate.scope, a.agent_id) || has_visible_agent;
                 }
                 const bool owns_execution =
                     exec_opt && exec_opt->dispatched_by == session->username;
                 if (!exec_opt || (gate.scope && !owns_execution && !has_visible_agent)) {
                     // #1634 (governance Gate 6 compliance-officer finding): a
                     // suppressed cross-operator subscribe attempt is
                     // CC7.2-evidence-worthy the same way the REST twin
                     // (GET /api/v1/events, action api.v1.events.subscribe)
                     // already audits its own denials — this route keeps its
                     // own pre-existing action name (execution.live_subscribe,
                     // matching its success row below), but uses the SAME
                     // non-distinguishing detail text so no enumeration oracle
                     // is reopened via query_audit_log.
                     (void)audit_fn(req, "execution.live_subscribe", "denied", "Execution",
                                    exec_id, "not found or outside caller's fleet-read scope");
                     res.status = 404;
                     res.set_content("execution not found", "text/plain; charset=utf-8");
                     return;
                 }
                 // Don't open SSE for already-terminal executions — the drawer
                 // should fall back to the static detail fragment. 410 Gone tells
                 // the EventSource to stop reconnecting.
                 const auto& exec = *exec_opt;
                 if (exec.status != "running" && exec.status != "pending") {
                     res.status = 410;
                     res.set_content("execution complete", "text/plain; charset=utf-8");
                     return;
                 }

                 // Audit every successful subscribe. Dedup is deferred per
                 // governance Deferred-5 / #700; the comment block above this
                 // route registration explains the contract.
                 audit_fn(req, "execution.live_subscribe", "success", "Execution", exec_id, "");

                 res.set_header("Cache-Control", "no-cache");
                 res.set_header("X-Accel-Buffering", "no");

                 // Admission control. This response is about to hold an httplib worker thread
                 // for as long as the operator leaves the drawer open, so it takes a lease from
                 // the ONE budget every streaming surface shares (ADR-0034). Held in a
                 // shared_ptr so it dies with the release lambda — the worker goes back on any
                 // teardown path, including a throw.
                 //
                 // Taken BEFORE the bus subscription below, matching the /api/v1/events
                 // sibling. Subscribing first and rejecting afterwards leaked the listener:
                 // the 429 path returns without unsubscribing, and gc_terminal_channels only
                 // reaps channels whose listener set is empty, so each rejection pinned a
                 // channel and its event buffer for the life of the process — an unbounded
                 // memory leak introduced BY the control that exists to bound resources.
                 auto lease = std::make_shared<detail::StreamBudget::Lease>();
                 if (stream_budget != nullptr) {
                     auto admitted = stream_budget->try_acquire(detail::SseSurface::kDashboardExec,
                                                                session->username,
                                                                detail::kPerPrincipalDashboard);
                     if (!admitted.lease) {
                         res.status = 429;
                         res.set_header("Retry-After", "5");
                         res.set_content("too many live streams open — close a tab and retry",
                                         "text/plain; charset=utf-8");
                         return;
                     }
                     *lease = std::move(admitted.lease);
                 }

                 auto sink_state = std::make_shared<detail::SseSinkState>();
                 // Replay ring-buffer events newer than the client's
                 // Last-Event-ID header (browser EventSource sets this on
                 // auto-reconnect). 0 = no header / first connect → no replay.
                 std::uint64_t since_id = 0;
                 if (req.has_header("Last-Event-ID")) {
                     try {
                         since_id = std::stoull(req.get_header_value("Last-Event-ID"));
                     } catch (...) {
                         since_id = 0;
                     }
                 }
                 auto* bus = execution_event_bus;
                 // Install the listener and replay atomically, using one scope
                 // projection for both buffered and live events.
                 sink_state->sub_id = bus->subscribe_and_replay(
                     exec_id, since_id,
                     [sink_state, scope = gate.scope](const ExecutionEvent& ev) noexcept {
                         try {
                             const auto verdict = classify_execution_event_for_scope(ev, scope);
                             if (verdict == ExecutionEventVerdict::kDrop)
                                 return;
                             ExecutionEvent sanitized;
                             const ExecutionEvent* served = &ev;
                             if (verdict == ExecutionEventVerdict::kSanitize) {
                                 sanitized = sanitize_execution_event_for_scope(ev);
                                 served = &sanitized;
                             }
                             detail::SseEvent sse;
                             sse.event_type = served->event_type;
                             sse.data = std::to_string(served->id) + "\n" + served->data;
                             {
                                 std::lock_guard<std::mutex> lk(sink_state->mu);
                                 sink_state->queue.push_back(std::move(sse));
                             }
                             sink_state->cv.notify_one();
                         } catch (...) {
                             // A projection failure drops the event for this stream.
                         }
                     });
                 std::string captured_exec_id = exec_id;

                 // UP-1: adopt any pending engine QuotaSlot into this
                 // stream's resource-releaser so the concurrency reservation
                 // survives for the stream's actual lifetime instead of
                 // releasing early at post-routing (see is_streaming_path /
                 // adopt_quota_slot_into_stream in principal_quota_gate.hpp).
                 res.set_chunked_content_provider(
                     "text/event-stream",
                     [sink_state, stream_budget](size_t offset, httplib::DataSink& s) -> bool {
                         // Re-implement the existing sse_content_provider in-line
                         // with id-aware framing. We can't reuse `format_sse`
                         // verbatim because it doesn't emit `id:`; the prefixed
                         // `<id>\n<data>` payload we queued above carries the id
                         // we need to peel off here.
                         std::unique_lock<std::mutex> lk(sink_state->mu);
                         // #2703 Gate 7 item 2: shutdown close-signal, same
                         // predicate shape as the /events and /api/v1/events
                         // siblings — see StreamBudget::closing()'s doc comment.
                         sink_state->cv.wait_for(lk, std::chrono::seconds(3), [&] {
                             return !sink_state->queue.empty() || sink_state->closed.load() ||
                                    (stream_budget && stream_budget->closing());
                         });
                         if (sink_state->closed.load() ||
                             (stream_budget && stream_budget->closing()))
                             return false;
                         while (!sink_state->queue.empty()) {
                             auto ev = std::move(sink_state->queue.front());
                             sink_state->queue.pop_front();

                             // Split <id>\n<data>
                             std::string id_part, data_part;
                             if (auto nl = ev.data.find('\n'); nl != std::string::npos) {
                                 id_part = ev.data.substr(0, nl);
                                 data_part = ev.data.substr(nl + 1);
                             } else {
                                 data_part = std::move(ev.data);
                             }
                             std::string out = "id: " + id_part + "\n" + "event: " + ev.event_type +
                                               "\n" + "data: " + data_part + "\n\n";
                             const char* p = out.data();
                             std::size_t rem = out.size();
                             constexpr std::size_t kMaxSlice = 8192;
                             while (rem > 0) {
                                 auto n = std::min(rem, kMaxSlice);
                                 if (!s.write(p, n))
                                     return false;
                                 p += n;
                                 rem -= n;
                             }
                         }
                         static const char* keepalive = "event: heartbeat\ndata: \n\n";
                         if (!s.write(keepalive, std::strlen(keepalive)))
                             return false;
                         (void)offset;
                         return true;
                     },
                     detail::adopt_quota_slot_into_stream(
                         [sink_state, bus, captured_exec_id,
                          lease](bool /*success*/) noexcept {
                             // noexcept + catch-all: runs from ~Response, a DESTRUCTOR,
                             // so an escaping exception is std::terminate whatever
                             // httplib does (#2037's class). The lock_guard below is
                             // the throw site that made the guard necessary. Matches
                             // the MCP sibling.
                             try {
                             {
                                 // Under the sink mutex — `closed` is the provider's wait
                                 // predicate, and a store between its check and its atomic
                                 // release-and-block is a lost wakeup. Matches the shared
                                 // sse_resource_release in event_bus.hpp.
                                 std::lock_guard<std::mutex> lk(sink_state->mu);
                                 sink_state->closed.store(true);
                             }
                             sink_state->cv.notify_all();
                             // unsubscribe stays OUTSIDE the sink lock (publishers take the bus mutex
                             // then the sink mutex, so unsubscribing under `mu` inverts that order) and
                             // in its OWN try so that unsubscribe's OWN throw cannot skip the steps
                             // after it (the metrics decrement / lease return). A leaked subscription
                             // pins the sink for the life of the process; contain it, do not propagate
                             // it out of this ~Response-invoked releaser.
                             try {
                                 bus->unsubscribe(captured_exec_id, sink_state->sub_id);
                             } catch (...) {
                             }
                             // The lease dies with this lambda, returning the worker to the
                             // one budget every streaming surface shares (ADR-0034).
                             } catch (...) {
                                 // Contained — see the note above.
                             }
                         }));
             });

    // guardian-confinement-2298: fleet-wide schedule list has no single
    // schedule/agent to confine per-target, mirrors GuardianRoutes'/
    // RestApiV1's blanket service-scoped deny for the identical reason —
    // ITServiceOwner grants full CRUD on Schedule, so a bare Schedule:Read
    // gate alone would still let a service-scoped token enumerate every
    // schedule from every other service. Runs BEFORE this route's own
    // `perm_fn(Schedule,Read)` call below (independent of RBAC on/off branch
    // ordering) — matches the GuardianRoutes/DexRoutes/NetworkRoutes family
    // of fragment/REST denies with no single per-target to scope against.
    // Security-guardian correction (governance run 2026-08-21): an earlier
    // draft of this comment claimed this fragment "has no permission gate of
    // its own to run after" — false, `perm_fn` runs right below. The correct
    // classification is LIVE-but-redundant (fires BEFORE its gate, the same
    // bucket-1b class as the routed-concern row's other still-listed
    // helpers), not gate-less/§3e — this deny stays for that reason, not
    // because the route lacks a gate. Contrast the now-retired REST
    // `/api/schedules` family's interim deny (#3290 Phase 2 bucket 1a — that
    // one ran AFTER its route's permission gate(s) and was made provably
    // dead by the flip).
    auto deny_service_scoped_schedule_list = [auth_fn, audit_fn](const httplib::Request& req,
                                                                  httplib::Response& res) -> bool {
        auto session = auth_fn(req, res);
        if (!session)
            return true; // auth_fn already wrote 401/redirect; caller returns.
        if (session->token_scope_service.empty())
            return false;
        // Write the 403 FIRST, audit after (mirrors GuardianRoutes'
        // deny_service_scoped_): a throwing audit_fn must not suppress the 403.
        res.status = 403;
        // No `.permission`: `kServiceScopeGlobalSafe` is compile-time-empty,
        // so no grant admits a service-scoped caller here (gov-fix, Gate 8,
        // #2298 PR 3 hardening round — routed-concern MUST clause).
        // `a4_denial` also fixes a second bug found in the same pass: the
        // hand-built cid never reached the X-Correlation-Id header.
        res.set_content(
            detail::a4_denial(res, 403,
                              "service-scoped tokens may not read the fleet-wide schedule list"),
            "application/json");
        if (audit_fn) {
            try {
                audit_fn(req, "schedule.list.access_denied", "denied", "schedule", "",
                         "fleet-wide schedule list denied to a service-scoped token");
            } catch (const std::exception& e) {
                spdlog::warn("schedule.list.access_denied: audit_fn threw: {}", e.what());
            } catch (...) {
                spdlog::warn("schedule.list.access_denied: audit_fn threw (non-std)");
            }
        }
        return true;
    };

    // GET /fragments/schedules -- schedule list HTMX fragment
    sink.Get("/fragments/schedules", [perm_fn, schedule_api,
                                      deny_service_scoped_schedule_list](
                                         const httplib::Request& req, httplib::Response& res) {
        // deny_service_scoped_schedule_list already resolved (and validated)
        // the session via auth_fn — a second auth_fn call here would be
        // redundant, matching the original handler's only use of `session`
        // (the existence check; the body never read the session itself).
        if (deny_service_scoped_schedule_list(req, res))
            return;
        // sec-M1-style gate (mirrors /fragments/executions immediately above):
        // the LIST exposes every schedule's name/frequency/enabled state/
        // execution count fleet-wide — previously reachable by ANY
        // authenticated session with no RBAC check at all (guardian-
        // confinement-2298 hardening sweep).
        if (!perm_fn(req, res, "Schedule", "Read"))
            return;
        if (!schedule_api) {
            res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
            return;
        }

        // ADR-0031 WS-A4 (seventh family): routed through the SAME
        // `ScheduleApi::list_schedules` seam call the REST v1/MCP twins use
        // — the pre-seam unchecked `ScheduleEngine::query_schedules()` read
        // could not tell "the store failed" from "there are no schedules"
        // (see `schedule_types.hpp`'s `ScheduleListResult` doc comment); this
        // is a deliberate, disclosed behaviour delta, not a silent
        // byte-identical rewire. `result.error()` is an internal store
        // diagnostic and is NEVER rendered — a distinct degraded state
        // instead.
        auto result = schedule_api->list_schedules(ScheduleQuery{});
        if (!result) {
            // sre Gate 6 hardening (governance, feat/split-a4-schedule-seam):
            // REST v1/MCP both route their equivalent failure through
            // genericize_db_error(), which spdlog::errors the raw diagnostic
            // before returning a sanitized message -- this fragment used to
            // discard result.error() with no log call at all, leaving zero
            // server-side signal correlating the degraded banner with
            // backend health for an operator watching only the dashboard.
            // Called here PURELY for its logging side effect -- the return
            // value is intentionally discarded, never rendered (the fixed
            // banner text below is the only thing sent to the client).
            (void)yuzu::server::genericize_db_error("list_schedules", result.error());
            res.set_content(
                "<div class=\"empty-state\">Schedule list temporarily unavailable &mdash; "
                "retry shortly.</div>",
                "text/html");
            return;
        }
        const auto& scheds = result->schedules;
        std::string html;
        // adversarial-review-kimi round (Codex C1 / Kimi K1, both independently):
        // schedule_api.hpp's own contract says "every caller (REST, MCP, and the
        // fragment) must surface this, never present the capped count as the
        // fleet's true total" — REST v1/MCP already did; this fragment did not
        // until this fix, silently rendering a capped list as complete for an
        // operator with more schedules than the store's hard cap.
        if (result->truncated) {
            html += "<div class=\"empty-state\" style=\"color:var(--warn-color,#c9a227)\">"
                   "Showing a partial list &mdash; more schedules exist than can be "
                   "displayed.</div>";
        }
        if (scheds.empty()) {
            html += "<div class=\"empty-state\">No schedules configured.</div>";
        } else {
            html += "<table><thead><tr><th>Name</th><th>Frequency</th><th>Enabled</th><th>Next "
                   "Run</th><th>Count</th><th></th></tr></thead><tbody>";
            for (const auto& s : scheds) {
                html += "<tr><td>" + html_escape(s.name) +
                        "</td>"
                        "<td><code>" +
                        html_escape(s.frequency_type) +
                        "</code></td>"
                        "<td>" +
                        std::string(s.enabled ? "Yes" : "No") +
                        "</td>"
                        "<td style=\"font-size:0.7rem\">" +
                        (s.next_execution_at > 0 ? std::to_string(s.next_execution_at) : "-") +
                        "</td>"
                        "<td>" +
                        std::to_string(s.execution_count) +
                        "</td>"
                        "<td><button class=\"btn btn-danger\" "
                        "style=\"font-size:0.65rem;padding:0.15rem 0.5rem\" "
                        "hx-delete=\"/api/schedules/" +
                        s.id +
                        "\" hx-target=\"#tab-schedules\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Delete schedule?\">Delete</button></td></tr>";
            }
            html += "</tbody></table>";
        }
        res.set_content(html, "text/html; charset=utf-8");
    });

    // -- Scope estimate API ----------------------------------------------------

    // guardian-confinement-2298 PR3 §3e: /api/scope/estimate is auth_fn-only
    // (no perm_fn at all) and probes an arbitrary caller-supplied scope
    // expression against `scope_fn(expression, session->username)` — the
    // minter's OWN visible fleet, which for a service-scoped token is still
    // ITServiceOwner's full-CRUD-visible set (the route never consults
    // token_scope_service). No per-target parameter to scope against, same
    // gap class as deny_service_scoped_schedule_list above.
    auto deny_service_scoped_scope_estimate = [auth_fn, audit_fn](const httplib::Request& req,
                                                                   httplib::Response& res) -> bool {
        auto session = auth_fn(req, res);
        if (!session)
            return true; // auth_fn already wrote 401/redirect; caller returns.
        if (session->token_scope_service.empty())
            return false;
        res.status = 403;
        // No `.permission` label: this route has no perm_fn gate at all — a
        // blanket deny with no grant that would admit a service-scoped
        // token, so naming one would be a false self-remediation claim.
        //
        // `a4_denial` (not a hand-built `error_json_a4` + bare correlation
        // id): it mints/reuses the id via `ensure_correlation_id`, which
        // ALSO sets the X-Correlation-Id response header — a hand-built id
        // embeds a correlation_id in the body the header never carries,
        // breaking the header/body-must-agree contract (consistency-auditor,
        // Gate 4).
        res.set_content(
            detail::a4_denial(
                res, 403,
                "service-scoped tokens may not estimate scope expressions against the fleet"),
            "application/json");
        if (audit_fn) {
            try {
                audit_fn(req, "scope.estimate.access_denied", "denied", "ScopeExpression", "",
                         "fleet-wide scope estimate denied to a service-scoped token");
            } catch (const std::exception& e) {
                spdlog::warn("scope.estimate.access_denied: audit_fn threw: {}", e.what());
            } catch (...) {
                spdlog::warn("scope.estimate.access_denied: audit_fn threw (non-std)");
            }
        }
        return true;
    };

    // POST /api/scope/estimate -- scope expression target count
    sink.Post("/api/scope/estimate", [auth_fn, scope_fn, deny_service_scoped_scope_estimate](
                                          const httplib::Request& req, httplib::Response& res) {
        if (deny_service_scoped_scope_estimate(req, res))
            return;
        auto session = auth_fn(req, res);
        if (!session)
            return;

        // Extract expression from body
        std::string expression;
        try {
            auto j = nlohmann::json::parse(req.body);
            if (j.contains("expression") && j["expression"].is_string())
                expression = j["expression"].get<std::string>();
        } catch (...) {}

        if (expression.empty()) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "expression required"), "application/json");
            return;
        }

        auto parsed = yuzu::scope::parse(expression);
        if (!parsed) {
            res.status = 400;
            res.set_content(detail::a4_error(res, parsed.error()), "application/json");
            return;
        }

        auto [matched, total] = scope_fn(expression, session->username);
        res.set_content(nlohmann::json({{"matched", matched}, {"total", total}}).dump(),
                        "application/json");
    });

    // -- Workflow Engine API (Phase 7) -----------------------------------------

    // GET /api/workflows -- list all workflows
    sink.Get("/api/workflows", [perm_fn, workflow_engine](const httplib::Request& req,
                                                          httplib::Response& res) {
        if (!perm_fn(req, res, "Workflow", "Read"))
            return;
        if (!workflow_engine || !workflow_engine->is_open()) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "workflow engine not available"),
                            "application/json");
            return;
        }

        WorkflowQuery q;
        if (req.has_param("name"))
            q.name_filter = req.get_param_value("name");
        try {
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid numeric query parameter"),
                            "application/json");
            return;
        }
        if (q.limit <= 0) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "limit must be a positive integer"),
                            "application/json");
            return;
        }

        auto workflows_result = workflow_engine->list_workflows(q);
        if (!workflows_result) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, yuzu::server::genericize_db_error(
                                          "list_workflows", workflows_result.error())),
                "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& w : *workflows_result) {
            nlohmann::json steps_arr = nlohmann::json::array();
            for (const auto& s : w.steps) {
                steps_arr.push_back({{"index", s.index},
                                     {"instruction_id", s.instruction_id},
                                     {"label", s.label},
                                     {"condition", s.condition},
                                     {"retry_count", s.retry_count},
                                     {"foreach", s.foreach_source},
                                     {"on_failure", s.on_failure}});
            }
            arr.push_back({{"id", w.id},
                           {"name", w.name},
                           {"description", w.description},
                           {"steps", steps_arr},
                           {"step_count", w.steps.size()},
                           {"created_at", w.created_at},
                           {"updated_at", w.updated_at}});
        }
        res.set_content(nlohmann::json({{"workflows", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });

    // POST /api/workflows -- create workflow from YAML
    sink.Post("/api/workflows", [perm_fn, audit_fn, emit_fn, workflow_engine](
                                    const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Workflow", "Write"))
            return;
        if (!workflow_engine || !workflow_engine->is_open()) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "workflow engine not available"),
                            "application/json");
            return;
        }

        std::string yaml_source;
        if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
            try {
                auto j = nlohmann::json::parse(req.body);
                yaml_source = j.value("yaml_source", "");
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "invalid request body"), "application/json");
                return;
            }
        } else {
            yaml_source = req.body;
        }

        auto result = workflow_engine->create_workflow(yaml_source);
        if (!result) {
            if (yuzu::server::is_generic_db_error(result.error())) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res, yuzu::server::genericize_db_error(
                                              "create_workflow", result.error())),
                    "application/json");
                return;
            }
            res.status = 400;
            res.set_content(detail::a4_error(res, result.error()), "application/json");
            return;
        }
        audit_fn(req, "workflow.create", "success", "workflow", *result, "");
        emit_fn("workflow.created", req);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Workflow created","level":"success"}})");
        res.status = 201;
        res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                        "application/json");
    });

    // GET /api/workflows/:id -- get workflow detail
    sink.Get(R"(/api/workflows/([^/]+))", [perm_fn, workflow_engine](const httplib::Request& req,
                                                                     httplib::Response& res) {
        if (!perm_fn(req, res, "Workflow", "Read"))
            return;
        if (!workflow_engine) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto workflow_result = workflow_engine->get_workflow(id);
        if (!workflow_result) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, yuzu::server::genericize_db_error(
                                          "get_workflow", workflow_result.error())),
                "application/json");
            return;
        }
        if (!*workflow_result) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "workflow not found"), "application/json");
            return;
        }
        const auto& workflow = **workflow_result;

        nlohmann::json steps_arr = nlohmann::json::array();
        for (const auto& s : workflow.steps) {
            steps_arr.push_back({{"index", s.index},
                                 {"instruction_id", s.instruction_id},
                                 {"label", s.label},
                                 {"condition", s.condition},
                                 {"retry_count", s.retry_count},
                                 {"retry_delay_seconds", s.retry_delay_seconds},
                                 {"foreach", s.foreach_source},
                                 {"on_failure", s.on_failure}});
        }

        res.set_content(nlohmann::json({{"id", workflow.id},
                                        {"name", workflow.name},
                                        {"description", workflow.description},
                                        {"yaml_source", workflow.yaml_source},
                                        {"steps", steps_arr},
                                        {"created_at", workflow.created_at},
                                        {"updated_at", workflow.updated_at}})
                            .dump(),
                        "application/json");
    });

    // DELETE /api/workflows/:id -- delete workflow
    sink.Delete(R"(/api/workflows/([^/]+))", [perm_fn, audit_fn, emit_fn,
                                              workflow_engine](const httplib::Request& req,
                                                               httplib::Response& res) {
        if (!perm_fn(req, res, "Workflow", "Delete"))
            return;
        if (!workflow_engine) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto del = workflow_engine->delete_workflow(id);
        // ADR-0064: delete_workflow() now returns std::expected — a genuine store-unavailable
        // condition (kDbErrorPrefix) 503s instead of silently reporting {"deleted": false} as if
        // the workflow simply didn't exist; "not_found:" (missing OR already soft-deleted) keeps
        // the pre-migration {"deleted": false}/200 contract byte-identical.
        if (!del && yuzu::server::is_generic_db_error(del.error())) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, yuzu::server::genericize_db_error(
                                          "delete_workflow", del.error())),
                "application/json");
            return;
        }
        bool deleted = del.has_value();
        if (deleted) {
            audit_fn(req, "workflow.delete", "success", "workflow", id, "");
            emit_fn("workflow.deleted", req);
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Workflow deleted","level":"success"}})");
        }
        res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
    });

    // POST /api/workflows/:id/execute -- execute workflow against agents
    sink.Post(R"(/api/workflows/([^/]+)/execute)", [auth_fn, perm_fn, audit_fn, emit_fn,
                                                    workflow_engine, instruction_store,
                                                    cmd_dispatch, cmd_dispatch_concurrency,
                                                    caller_fn, approval_manager,
                                                    capability_registry, metrics](  // BR2-001/BR3-001
                                                        const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!perm_fn(req, res, "Workflow", "Execute"))
            return;
        if (!workflow_engine || !workflow_engine->is_open()) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "workflow engine not available"),
                            "application/json");
            return;
        }

        auto workflow_id = req.matches[1].str();

        // Parse agent_ids from request body
        std::vector<std::string> agent_ids;
        try {
            auto j = nlohmann::json::parse(req.body);
            if (j.contains("agent_ids") && j["agent_ids"].is_array()) {
                for (const auto& aid : j["agent_ids"])
                    agent_ids.push_back(aid.get<std::string>());
            }
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid request body"), "application/json");
            return;
        }

        if (agent_ids.empty()) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "agent_ids array is required"),
                            "application/json");
            return;
        }

        // K-R7-02 / PLAN-006: derive the operator's DispatchCaller ONCE for this
        // request and thread it into every step dispatch below, so a workflow
        // step is confined AND identified exactly as /api/command and MCP are.
        // An UNWIRED derivation fails CLOSED on visibility (present-empty set →
        // reaches nobody).
        const yuzu::server::DispatchCaller caller =
            caller_fn ? caller_fn(req)
                      : yuzu::server::DispatchCaller{
                            .exec_visible = yuzu::server::authz::deny_all()};

        // --- Pre-validate approval gates on all workflow steps ---------------
        // If any instruction in the workflow requires approval, reject the
        // entire execution rather than allowing partial bypass.
        if (approval_manager && instruction_store && instruction_store->is_open()) {
            auto workflow_result = workflow_engine->get_workflow(workflow_id);
            if (!workflow_result) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res, yuzu::server::genericize_db_error(
                                              "get_workflow", workflow_result.error())),
                    "application/json");
                return;
            }
            // Not-found falls through unchanged — execute() below reports the same
            // "workflow not found" error this pre-check would otherwise skip ahead of.
            if (*workflow_result) {
                const auto& workflow = **workflow_result;
                auto session = auth_fn(req, res);
                if (!session)
                    return;
                for (const auto& step : workflow.steps) {
                    // ADR-0058: get_definition now returns std::expected — distinguish a
                    // genuine DB error (503) from "no such instruction" (400, unchanged).
                    auto step_def_result = instruction_store->get_definition(step.instruction_id);
                    if (!step_def_result) {
                        res.status = 503;
                        res.set_content(detail::a4_error(res, "instruction store unavailable"),
                                        "application/json");
                        return;
                    }
                    if (!*step_def_result) {
                        res.status = 400;
                        res.set_content(
                            detail::a4_error(res, "workflow step '" + step.label +
                                                      "' references unknown instruction: " +
                                                      step.instruction_id),
                            "application/json");
                        return;
                    }
                    const auto& step_def = **step_def_result;
                    if (step_def.approval_mode == "auto")
                        continue;
                    bool blocked = false;
                    if (step_def.approval_mode == "always") {
                        blocked = true;
                    } else if (step_def.approval_mode == "role-gated") {
                        // effective_role so an active JIT admin elevation bypasses
                        // role-gated approval, consistent with require_admin.
                        blocked = (auth::effective_role(*session) != auth::Role::admin);
                    } else {
                        blocked = true; // unknown mode — fail closed
                    }
                    if (blocked) {
                        res.status = 403;
                        res.set_content(
                            detail::a4_error(
                                res, "workflow step '" + step.label +
                                        "' references instruction '" + step.instruction_id +
                                        "' which requires approval (mode: " +
                                        step_def.approval_mode +
                                        "). Submit each instruction individually for approval."),
                            "application/json");
                        return;
                    }
                }
            }
        }

        // --- BR3-001 (branch-review round 3): preflight destructive/forensic --
        // targeting for EVERY step before workflow_engine->execute() is called
        // at all. BR2-001 (below, inside dispatch_fn) correctly gates the
        // per-step dispatch on evaluate_destructive_targeting, so a bad-target
        // Forensics/Destructive step genuinely reaches zero agents — but
        // dispatch_fn has no metrics/audit_fn/req/res (it returns
        // std::expected<std::string,std::string>, consumed internally by
        // WorkflowEngine::execute), so that refusal was silently absorbed into
        // the one step's own failed-step result while THIS route
        // unconditionally audited "workflow.execute"/"success" once execute()
        // returned — regardless of whether every step actually ran.
        // docs/observability-conventions.md: "Denied operations MUST emit an
        // audit event." Preflighting every step against the SAME
        // evaluate_destructive_targeting call closes that gap: any step that
        // would be refused refuses the WHOLE request up front — audited,
        // metered, 400 — and execute() is never invoked. dispatch_fn's own
        // per-step gate stays in place as defense-in-depth for a workflow
        // definition mutated between this preflight and execute(), or a future
        // dispatch_fn caller that skips this preflight — BR4-001 (round 4)
        // closed that specific race's own audit/metric gap: dispatch_fn now
        // reports a late refusal back to this route via the
        // late_targeting_denied/late_targeting_reason pair declared just above
        // the dispatch_fn definition below, so a definition mutated in the
        // window between this preflight and dispatch_fn's re-read still gets a
        // denied audit event and the rejection metric, instead of the blanket
        // "success" this route audits once execute() returns an execution id.
        //
        // Unwired instruction_store/capability_registry: skip the preflight
        // entirely rather than fail closed on a structural absence neither of
        // this route's other checks treats as fatal — dispatch_fn's own guards
        // ("instruction store not available" / "capability registry not
        // available") remain the backstop for that case, unchanged from today.
        if (instruction_store && instruction_store->is_open() && capability_registry) {
            auto preflight_wf = workflow_engine->get_workflow(workflow_id);
            if (!preflight_wf) {
                res.status = 503;
                res.set_content(
                    nlohmann::json(
                        {{"error", {{"code", 503},
                                    {"message", yuzu::server::genericize_db_error(
                                                    "get_workflow", preflight_wf.error())}}},
                         {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            // Not-found falls through unchanged, same as the approval
            // pre-validation above — execute() below reports the canonical
            // "workflow not found" error this preflight would otherwise skip
            // ahead of.
            if (*preflight_wf) {
                for (const auto& step : (*preflight_wf)->steps) {
                    // ADR-0058: get_definition returns std::expected — a
                    // genuine DB error fails the WHOLE request closed (503);
                    // "no such instruction" is not a targeting decision this
                    // preflight can make, so it defers to the existing per-step
                    // handling (the approval block above, or dispatch_fn's own
                    // "unknown instruction" failure) as the backstop.
                    auto step_def_result = instruction_store->get_definition(step.instruction_id);
                    if (!step_def_result) {
                        res.status = 503;
                        res.set_content(
                            nlohmann::json(
                                {{"error",
                                  {{"code", 503},
                                   {"message", yuzu::server::genericize_db_error(
                                                   "workflow preflight instruction lookup",
                                                   step_def_result.error())}}},
                                 {"meta", {{"api_version", "v1"}}}})
                                .dump(),
                            "application/json");
                        return;
                    }
                    if (!*step_def_result)
                        continue;
                    const auto& step_def = **step_def_result;
                    // SAME chokepoint dispatch_fn's own per-step gate below
                    // uses — evaluate_destructive_targeting from
                    // dispatch_destructive_gate.hpp, not a copy. scope_key_present
                    // is always false: WorkflowStep carries no per-step scope
                    // field, exactly matching dispatch_fn's own derivation.
                    const auto gate = yuzu::server::evaluate_destructive_targeting(
                        capability_registry->classify(step_def.plugin, step_def.action),
                        /*valid_nonempty_agent_ids=*/!agent_ids.empty(),
                        /*scope_key_present=*/false,
                        /*agent_id_count=*/agent_ids.size());
                    if (gate.verdict != yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted)
                        continue;
                    // Counted on the SAME series as the instruction-execute,
                    // /api/command, MCP and dashboard refusals, with this
                    // route's own `route="workflow"` label — a NEW emission
                    // point, not a reuse of "instruction_execute".
                    if (metrics) {
                        try {
                            metrics
                                ->counter("yuzu_server_dispatch_target_rejected_total",
                                          {{"route", "workflow"},
                                           {"reason", std::string(gate.refusal_reason)}})
                                .increment();
                        } catch (const std::exception& e) {
                            spdlog::error(
                                "dispatch_target_rejected_total counter threw for {}:{} "
                                "(reason={}): {}",
                                step_def.plugin, step_def.action, gate.refusal_reason, e.what());
                        } catch (...) {
                            spdlog::error(
                                "dispatch_target_rejected_total counter threw for {}:{} "
                                "(reason={})",
                                step_def.plugin, step_def.action, gate.refusal_reason);
                        }
                    }
                    audit_fn(req, "workflow.execute", "denied", "workflow", workflow_id,
                             "reason=" + std::string(gate.refusal_reason));
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 400},
                                                   {"message", std::string(gate.refusal_message)}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                    return;
                }
            }
        }

        // BR4-001 (branch-review round 4): dispatch_fn's per-step gate below is the
        // correct backstop for a workflow/instruction definition mutated between this
        // route's own preflight (above) and execute() reaching this step — it still
        // refuses the actual agent dispatch — but that refusal reaches
        // WorkflowEngine::execute as an ordinary failed-step result, indistinguishable
        // from any other step failure, and this route unconditionally audits
        // "workflow.execute"/"success" once execute() returns an execution id
        // regardless of what happened inside. execute() runs dispatch_fn synchronously
        // on THIS thread (no background thread, no async handoff — the whole step loop
        // completes before execute() returns below), so a plain by-reference capture
        // set inside dispatch_fn is safely observable here immediately after execute()
        // returns, with no cross-thread lifetime concern.
        bool late_targeting_denied = false;
        std::string late_targeting_reason;

        // Create a dispatch function that uses the real command dispatch.
        // caller is captured by value (workflow_engine->execute invokes this
        // synchronously below, but a value capture is lifetime-safe
        // regardless) so every step narrows to AND identifies the operator.
        auto dispatch_fn =
            [instruction_store, &cmd_dispatch, &cmd_dispatch_concurrency, caller,
             capability_registry, &late_targeting_denied, &late_targeting_reason](  // BR2-001/BR4-001
                const std::string& instruction_id, const std::string& agent_ids_json,
                const std::string& parameters_json) -> std::expected<std::string, std::string> {
            // Look up the instruction definition to get plugin + action
            if (!instruction_store || !instruction_store->is_open())
                return std::unexpected<std::string>("instruction store not available");

            // ADR-0058: get_definition now returns std::expected — a genuine DB error
            // and "no such instruction" are distinct dispatch-path failures, both
            // fail the step (neither can silently widen or narrow the target set).
            auto def_result = instruction_store->get_definition(instruction_id);
            if (!def_result)
                // Gate 2 SEC-1: def_result.error() carries raw PQerrorMessage() text on a
                // genuine DB failure — genericized before it reaches the stored step result
                // (GET /api/workflow-executions/:id echoes this verbatim to any Workflow:Read
                // holder).
                return std::unexpected<std::string>(yuzu::server::genericize_db_error(
                    "dispatch_fn instruction lookup", def_result.error()));
            if (!*def_result)
                return std::unexpected<std::string>("unknown instruction: " + instruction_id);
            const auto& def = **def_result;

            // Parse agent_ids from JSON array
            std::vector<std::string> target_ids;
            try {
                auto j = nlohmann::json::parse(agent_ids_json);
                if (j.is_array()) {
                    // Build into a scratch vector and commit only on FULL
                    // success. `get<std::string>()` throws on the first
                    // non-string, and the bare catch below swallows it — so
                    // pushing directly into `target_ids` left a PARTIALLY
                    // filled list on `["a","b",3,"d"]` and this step then
                    // dispatched to the truncated prefix, reporting
                    // `agents_reached: 2` as success. That is #2500's defect
                    // pointing the other way: a target the caller named,
                    // silently NARROWED rather than widened. Both directions
                    // are the same lie — the set that ran is not the set that
                    // was asked for (governance, Gate 5 CH-1).
                    std::vector<std::string> parsed_ids;
                    parsed_ids.reserve(j.size());
                    for (const auto& a : j)
                        parsed_ids.push_back(a.get<std::string>());
                    target_ids = std::move(parsed_ids);
                }
            } catch (...) {
                // target_ids stays EMPTY on any malformed stored targeting.
                // Empty reaches nobody at the shared sink (#2500), so a corrupt
                // or legacy `agent_ids_json` fails this step loudly instead of
                // dispatching to whatever happened to parse — or, before the
                // inversion, to the entire fleet.
                target_ids.clear();
            }

            // Parse parameters from JSON object
            std::unordered_map<std::string, std::string> params;
            try {
                auto j = nlohmann::json::parse(parameters_json);
                if (j.is_object()) {
                    for (auto& [k, v] : j.items())
                        params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                }
            } catch (...) {}

            // BR2-001 (round-2 branch review): the instruction-execute route's
            // BR-001 fix gated `/api/instructions/{id}/execute` but this SIBLING
            // route's own step dispatcher — reached from workflow execution, not
            // that route — was a second real CommandRequest producer nobody had
            // wired. SAME chokepoint (dispatch_destructive_gate.hpp), not a copy:
            // a Forensics/Destructive-classified step now refuses a multi-agent
            // or omitted-scope target instead of fanning out to every `target_ids`
            // entry. `metrics`/`audit_fn` are not threaded into this per-step
            // closure (it returns std::expected<std::string,std::string>, not an
            // httplib::Response, and has no `req` to audit against) — the refusal
            // surfaces as a failed step through workflow_engine's own per-step
            // error/audit path exactly like every other dispatch_fn failure above
            // (instruction store down, unknown instruction, no agents reached).
            if (!capability_registry)
                return std::unexpected<std::string>("capability registry not available");
            {
                const auto gate = yuzu::server::evaluate_destructive_targeting(
                    capability_registry->classify(def.plugin, def.action),
                    /*valid_nonempty_agent_ids=*/!target_ids.empty(),
                    /*scope_key_present=*/false,
                    /*agent_id_count=*/target_ids.size());
                switch (gate.verdict) {
                case yuzu::server::DestructiveTargetingVerdict::NotDestructive:
                case yuzu::server::DestructiveTargetingVerdict::ClassifyMiss:
                case yuzu::server::DestructiveTargetingVerdict::Targeted:
                    break;
                case yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted:
                    // BR4-001: surfaced to the route below so a refusal reached via a
                    // late (post-preflight) definition mutation still gets the denied
                    // audit event and rejection metric a step-level failure alone
                    // cannot carry (dispatch_fn has no audit_fn/metrics of its own —
                    // see the capture-site comment above).
                    late_targeting_denied = true;
                    late_targeting_reason = std::string(gate.refusal_reason);
                    return std::unexpected<std::string>(std::string(gate.refusal_message));
                }
            }

            // Dispatch via gRPC. PR 2: workflow-step dispatch path
            // does not yet wire execution_id correlation (CONSIST-2 /
            // sec-M2 — PR 2.x will close); pass empty execution_id so
            // record_execution_id is skipped and responses arrive with
            // the legacy sentinel (legacy fallback in detail handler
            // covers the rendering).
            // ADR-1007: per-device concurrency gate, when wired — falls back
            // to the ungated dispatch when unwired (test harnesses that
            // don't construct an ExecutionTracker), matching the
            // ConcurrencyDispatchFn doc contract.
            auto dispatch_outcome =
                cmd_dispatch_concurrency
                    ? cmd_dispatch_concurrency(def.plugin, def.action, target_ids, "", params,
                                              /*execution_id=*/"", caller, def.id,
                                              def.concurrency_mode)
                    : cmd_dispatch(def.plugin, def.action, target_ids, "", params,
                                   /*execution_id=*/"", caller);
            const auto& command_id = dispatch_outcome.command_id;
            const auto sent = dispatch_outcome.sent;

            if (sent == 0)
                return std::unexpected<std::string>("no agents reached for " + instruction_id);

            return nlohmann::json({{"status", "dispatched"},
                                   {"command_id", command_id},
                                   {"agents_reached", sent}})
                .dump();
        };

        // Condition evaluator using compliance_eval
        auto condition_fn = [](const std::string& expression,
                               const std::map<std::string, std::string>& fields) -> bool {
            return evaluate_compliance_bool(expression, fields);
        };

        auto result = workflow_engine->execute(workflow_id, agent_ids, dispatch_fn, condition_fn);

        if (!result) {
            if (yuzu::server::is_generic_db_error(result.error())) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res, yuzu::server::genericize_db_error(
                                              "execute", result.error())),
                    "application/json");
                return;
            }
            res.status = 400;
            res.set_content(detail::a4_error(res, result.error()), "application/json");
            return;
        }
        if (late_targeting_denied) {
            // BR4-001: at least one step's dispatch was refused by the SAME
            // evaluate_destructive_targeting chokepoint the preflight above uses —
            // just reached late, via a definition that changed after the preflight
            // read it. The dispatch itself was correctly blocked (dispatch_fn's
            // return), but that alone leaves no denied audit event and no rejection
            // metric — docs/observability-conventions.md: "Denied operations MUST
            // emit an audit event." Counted on the SAME series/route label as the
            // preflight's own denial so the two paths are equally visible.
            if (metrics) {
                try {
                    metrics
                        ->counter("yuzu_server_dispatch_target_rejected_total",
                                  {{"route", "workflow"}, {"reason", late_targeting_reason}})
                        .increment();
                } catch (const std::exception& e) {
                    spdlog::error(
                        "dispatch_target_rejected_total counter threw for late workflow "
                        "targeting refusal (reason={}): {}",
                        late_targeting_reason, e.what());
                } catch (...) {
                    spdlog::error(
                        "dispatch_target_rejected_total counter threw for late workflow "
                        "targeting refusal (reason={})",
                        late_targeting_reason);
                }
            }
            audit_fn(req, "workflow.execute", "denied", "workflow", workflow_id,
                     "reason=" + late_targeting_reason + " (late; execution_id=" + *result + ")");
        } else {
            audit_fn(req, "workflow.execute", "success", "workflow", workflow_id,
                     "execution_id=" + *result);
        }
        emit_fn("workflow.executed", req);
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Workflow execution started","level":"success"}})");
        res.status = 202;
        res.set_content(nlohmann::json({{"execution_id", *result}, {"status", "running"}}).dump(),
                        "application/json");
    });

    // GET /api/workflow-executions/:id -- get execution status
    sink.Get(R"(/api/workflow-executions/([^/]+))", [fleet_read_fn,
                                                     workflow_engine](const httplib::Request& req,
                                                                      httplib::Response& res) {
        // #4030 Gate 8 fix: was `perm_fn` (plain permission check, no
        // confinement at all) -- swapped for `fleet_read_fn`, the SAME
        // gate the v1 twin below uses, per FleetReadFn's own doc comment
        // ("MUST be that route's SOLE authorization gate -- never stacked
        // with perm_fn for the same securable/operation"). This route
        // predates "Workflow" existing as a cataloged RBAC securable at
        // all (rbac_store.cpp, this same PR's seeding commit) -- under
        // RBAC-enabled deployments it was previously unreachable to ANY
        // role, including Administrator. This PR's own seeding is what
        // makes it reachable to confined, non-admin roles for the first
        // time (security-guardian Gate 2 finding #2).
        if (!fleet_read_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }
        auto gate = fleet_read_fn(req, res, "Workflow", "Read");
        if (!gate.admitted)
            return; // gate already wrote the response.
        if (!workflow_engine) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto exec_result = workflow_engine->get_execution(id);
        if (!exec_result) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, yuzu::server::genericize_db_error(
                                          "get_execution", exec_result.error())),
                "application/json");
            return;
        }
        if (!*exec_result) {
            res.status = 404;
            // #1552/#4030 anti-oracle (test_workflow_routes.cpp "zero-overlap
            // confined caller gets the same 404 as a nonexistent id"): a
            // per-request correlation_id in the BODY would let a confined
            // caller distinguish "record exists but I can't see it" from
            // "record does not exist" by diffing the two 404 bodies,
            // defeating the whole point of this route's Gate 8 confinement
            // fix. Both not-found branches below build the body via the pure
            // `error_json_a4` builder with a fixed empty correlation_id
            // (byte-identical by construction) rather than `a4_error`, which
            // would echo the per-request header value into the body. The
            // response still stamps a real `X-Correlation-Id` header
            // (`ensure_correlation_id`) for grep-ability — only the body is
            // exempt, and only on this route's two not-found branches.
            detail::ensure_correlation_id(res);
            res.set_content(detail::error_json_a4(404, "execution not found", ""),
                            "application/json");
            return;
        }
        const auto& exec = **exec_result;
        // #4030 Gate 8 fix: record-level confinement gate -- no audit call
        // existed on this route before this fix (unlike the v1 twin,
        // which audits every fetch) and none is added here; adding a
        // first-ever audit call to this route is a separate, unrelated
        // decision, out of scope for this fix. Denial 404-collapses
        // identically to the not-found body above (same fixed-empty-cid
        // construction, see the comment there).
        if (!workflow_execution_visible(exec, gate.scope)) {
            res.status = 404;
            detail::ensure_correlation_id(res);
            res.set_content(detail::error_json_a4(404, "execution not found", ""),
                            "application/json");
            return;
        }

        nlohmann::json steps_arr = nlohmann::json::array();
        for (const auto& sr : exec.step_results) {
            steps_arr.push_back({{"step_index", sr.step_index},
                                 {"instruction_id", sr.instruction_id},
                                 {"status", sr.status},
                                 {"result", confined_workflow_step_result_json(
                                                sr.result_json, static_cast<bool>(gate.scope))},
                                 {"started_at", sr.started_at},
                                 {"completed_at", sr.completed_at},
                                 {"attempt", sr.attempt}});
        }

        res.set_content(nlohmann::json({{"id", exec.id},
                                        {"workflow_id", exec.workflow_id},
                                        {"status", exec.status},
                                        {"agent_ids", confined_workflow_agent_ids_json(
                                                          exec.agent_ids_json, gate.scope)},
                                        {"current_step", exec.current_step},
                                        {"started_at", exec.started_at},
                                        {"completed_at", exec.completed_at},
                                        {"steps", steps_arr}})
                            .dump(),
                        "application/json");
    });

    // -- REST v1 twins (#4030: executions/workflows/schedules read-twin programme) --
    //
    // Each route below is a genuine v1 twin of an existing unversioned/fragment
    // route above: same gate, same store call, same data -- but the JSON body
    // is built by a SHARED pure function from workflow_model.hpp
    // (workflow_row_json/workflow_detail_json/workflow_execution_detail_json/
    // schedule_row_json) that the MCP twins (list_workflows/get_workflow/
    // get_workflow_execution/list_schedules, mcp_server.cpp) call too --
    // docs/api-twin-recipe.md Rule 1: REST and MCP cannot drift on field set
    // by construction. New v1 error paths use the A4 envelope helpers
    // (detail::a4_error) per the recipe's guidance, unlike this file's older
    // unversioned handlers above (predate the recipe; left as-is, out of
    // scope for this twin PR).

    // GET /api/v1/workflows -- v1 twin of GET /api/workflows above.
    // ADR-0031 WS-A4 (eighth family): routed through the WorkflowApi seam —
    // list_workflows() already returned a checked std::expected to this
    // route pre-seam, so dropping the separate `!is_open()` pre-check and
    // relying on the seam call's own result introduces no new
    // honest-empty-vs-failure distinction (see workflow_api.cpp's doc
    // comment); it only removes the direct presentation -> store reach.
    sink.Get("/api/v1/workflows", [perm_fn, workflow_api](const httplib::Request& req,
                                                          httplib::Response& res) {
        if (!perm_fn(req, res, "Workflow", "Read"))
            return;
        if (!workflow_api) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "workflow engine not available"),
                            "application/json");
            return;
        }
        WorkflowQuery q;
        if (req.has_param("name"))
            q.name_filter = req.get_param_value("name");
        try {
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid numeric query parameter"),
                            "application/json");
            return;
        }
        if (q.limit <= 0) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "limit must be a positive integer"),
                            "application/json");
            return;
        }
        // #4030 Gate 8 fix (architect, Gate 3): was floor-only -- no upper
        // clamp reached Postgres, asymmetric with this route's own MCP twin
        // (clamped to 500) and the sibling GET /api/v1/executions (also
        // capped 500).
        q.limit = std::min(q.limit, 500);
        auto workflows_result = workflow_api->list_workflows(q);
        if (!workflows_result) {
            res.status = 503;
            res.set_content(detail::a4_error(res,
                                             yuzu::server::genericize_db_error(
                                                 "list_workflows", workflows_result.error()),
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& w : *workflows_result)
            arr.push_back(workflow_row_json(w));
        // #4030 Gate 8 fix (sre, Gate 6): the sibling Executions v1 routes
        // set X-Correlation-Id unconditionally (success and error); this
        // route only got it on error paths (via a4_error) before this fix.
        detail::ensure_correlation_id(res);
        res.set_content(
            nlohmann::json(
                {{"data", arr},
                 {"pagination", {{"total", arr.size()}, {"start", 0}, {"page_size", 50}}},
                 {"meta", {{"api_version", "v1"}}}})
                .dump(),
            "application/json");
    });

    // GET /api/v1/workflows/:id -- v1 twin of GET /api/workflows/:id above.
    // ADR-0031 WS-A4 (eighth family): routed through the WorkflowApi seam.
    sink.Get(R"(/api/v1/workflows/([^/]+))",
            [perm_fn, workflow_api](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Workflow", "Read"))
                    return;
                if (!workflow_api) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "service unavailable"),
                                    "application/json");
                    return;
                }
                auto id = req.matches[1].str();
                auto workflow_result = workflow_api->get_workflow(id);
                if (!workflow_result) {
                    res.status = 503;
                    res.set_content(
                        detail::a4_error(res,
                                         yuzu::server::genericize_db_error(
                                             "get_workflow", workflow_result.error()),
                                         {.retry_after_ms = 5000}),
                        "application/json");
                    return;
                }
                if (!*workflow_result) {
                    res.status = 404;
                    res.set_content(detail::a4_error(res, "workflow not found"),
                                    "application/json");
                    return;
                }
                // #4030 Gate 8 fix (sre, Gate 6): X-Correlation-Id parity
                // with the success path (see GET /api/v1/workflows above).
                detail::ensure_correlation_id(res);
                res.set_content(nlohmann::json({{"data", workflow_detail_json(**workflow_result)},
                                                {"meta", {{"api_version", "v1"}}}})
                                    .dump(),
                                "application/json");
            });

    // GET /api/v1/workflow-executions/:id -- v1 twin of
    // GET /api/workflow-executions/:id above. #4030 confinement decision:
    // WorkflowExecution.agent_ids_json names agents directly, so this route
    // gates on fleet_read_fn (not the legacy route's plain perm_fn) and
    // confines the emitted agent_ids array to the caller's visible scope --
    // reviewer-flagged scope point in the issue, resolved here.
    // ADR-0031 WS-A4 (eighth family): routed through the WorkflowApi seam.
    sink.Get(R"(/api/v1/workflow-executions/([^/]+))",
            [fleet_read_fn, audit_fn, workflow_api](const httplib::Request& req,
                                                    httplib::Response& res) {
                if (!fleet_read_fn) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "service unavailable"),
                                    "application/json");
                    return;
                }
                auto gate = fleet_read_fn(req, res, "Workflow", "Read");
                if (!gate.admitted)
                    return; // gate already wrote the response.
                if (!workflow_api) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "service unavailable"),
                                    "application/json");
                    return;
                }
                auto id = req.matches[1].str();
                auto exec_result = workflow_api->get_workflow_execution(id);
                if (!exec_result) {
                    res.status = 503;
                    res.set_content(
                        detail::a4_error(res,
                                         yuzu::server::genericize_db_error(
                                             "get_execution", exec_result.error()),
                                         {.retry_after_ms = 5000}),
                        "application/json");
                    return;
                }
                if (!*exec_result) {
                    res.status = 404;
                    res.set_content(detail::a4_error(res, "execution not found"),
                                    "application/json");
                    return;
                }
                const auto& exec = **exec_result;
                // #4030 Gate 8 fix: record-level confinement gate --
                // workflow_execution_detail_json only ever field-filters
                // `agent_ids`; it has no way to withhold `status`/
                // `current_step`/`steps[]` for a caller with zero
                // visibility into this execution (security-guardian Gate 2
                // finding: the original cut called the builder
                // unconditionally for any id the caller supplied). Denial
                // 404-collapses identically to the not-found body above
                // (same `detail::a4_error` call, same message -- byte-
                // identical body, anti-enumeration) and is audited
                // DISTINCTLY from a successful fetch -- never folded into
                // the "success" call below, which would audit a denied
                // read as a success immediately before refusing it (Gate 4
                // unhappy-path finding UP-1 / chaos_test 2).
                if (!workflow_execution_visible(exec, gate.scope)) {
                    if (audit_fn)
                        audit_fn(req, "workflow_execution.detail.fetch", "denied",
                                "WorkflowExecution", exec.id,
                                "not found or outside caller's fleet-read scope "
                                "(management-group confinement)");
                    res.status = 404;
                    res.set_content(detail::a4_error(res, "execution not found"),
                                    "application/json");
                    return;
                }
                // #4030 audit decision: workflow-execution results carry
                // operator-supplied step parameters/output, worth the same
                // audit posture as instruction executions -- audited, verb
                // `workflow_execution.detail.fetch` (new; distinct from the
                // aggregate `execution.detail.fetch` verb, a different data
                // model per the issue's own disambiguation). This file's
                // AuditFn is void-returning (predates rest_audit.hpp's
                // checked-bool try_persist_audit/emit_behavioral_audit --
                // widening that type ripples through every call site + the
                // server.cpp wiring lambda, out of scope for this twin PR),
                // so this is a set-and-proceed call, not REST's usual
                // fail-closed posture.
                if (audit_fn)
                    audit_fn(req, "workflow_execution.detail.fetch", "success",
                            "WorkflowExecution", exec.id, "");
                // #4030 Gate 8 fix (sre, Gate 6): X-Correlation-Id parity
                // with the success path (see GET /api/v1/workflows above).
                detail::ensure_correlation_id(res);
                res.set_content(
                    nlohmann::json({{"data", workflow_execution_detail_json(exec, gate.scope)},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
            });

    // GET /api/v1/schedules -- v1 twin of GET /fragments/schedules above; same
    // two-stage gate (deny_service_scoped_schedule_list, already declared
    // above, then Schedule:Read) -- schedules carry no per-agent axis, so
    // fleet_read_fn does not apply here (matches the fragment's own gate
    // shape, not a per-agent list).
    sink.Get("/api/v1/schedules",
            [perm_fn, schedule_api, deny_service_scoped_schedule_list](
                const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_schedule_list(req, res))
                    return;
                if (!perm_fn(req, res, "Schedule", "Read"))
                    return;
                if (!schedule_api) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "schedule engine not available"),
                                    "application/json");
                    return;
                }
                // #2146 A2-R1 (gov docs-writer/cpp-expert fix round): definition_id/
                // enabled_only query params. The legacy GET /api/schedules route
                // treats ANY presence of enabled_only as true, regardless of value
                // -- this v1 twin does NOT reproduce that quirk. It follows the
                // #4034 precedent already set on this same REST v1 surface
                // (compliance_routes.cpp's PolicyQuery enabled_only fix) and
                // matches the MCP twin list_schedules, which already honors the
                // boolean value: presence alone must not decide it, or
                // enabled_only=false would silently behave like enabled_only=true
                // (the caller asked to see disabled/all schedules and got the
                // opposite). An unrecognized value 400s.
                ScheduleQuery q;
                if (req.has_param("definition_id"))
                    q.definition_id = req.get_param_value("definition_id");
                if (req.has_param("enabled_only")) {
                    auto v = req.get_param_value("enabled_only");
                    if (v == "true" || v == "1") {
                        q.enabled_only = true;
                    } else if (v == "false" || v == "0") {
                        q.enabled_only = false;
                    } else {
                        res.status = 400;
                        res.set_content(
                            detail::a4_error(res, "invalid boolean query parameter: enabled_only"),
                            "application/json");
                        return;
                    }
                }
                // #4030 review finding (blocking): was the unchecked
                // query_schedules(), which collapsed a pool-exhaustion or
                // query failure into the same empty vector a genuinely
                // empty table returns -- matches GET /api/v1/workflows
                // above, which already has this checked/503 shape.
                // ADR-0031 WS-A4 (seventh family): now routed through the
                // ScheduleApi seam (schedule_api.hpp) — the SAME checked call
                // the dashboard fragment and MCP list_schedules also make.
                auto scheds_result = schedule_api->list_schedules(q);
                if (!scheds_result) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res,
                                                     yuzu::server::genericize_db_error(
                                                         "list_schedules", scheds_result.error()),
                                                     {.retry_after_ms = 5000}),
                                    "application/json");
                    return;
                }
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& s : scheds_result->schedules)
                    arr.push_back(schedule_row_json(s));
                // #4030 Gate 8 fix (sre, Gate 6): X-Correlation-Id parity
                // with the success path (see GET /api/v1/workflows above).
                detail::ensure_correlation_id(res);
                // #4030 review finding (blocking): `total` below is the
                // COUNT RETURNED, not necessarily the fleet's true count --
                // query_schedules_checked() hard-caps at kScheduleListCap
                // rows with no way for this route to page past it. Before
                // this fix `total` silently asserted completeness even when
                // truncated; now a truncated response says so explicitly
                // (precedent: MCP query_responses's result_truncated_by_cap)
                // instead of the caller having no way to tell.
                nlohmann::json pagination{
                    {"total", arr.size()}, {"start", 0}, {"page_size", 50}};
                if (scheds_result->truncated)
                    pagination["result_truncated_by_cap"] = true;
                res.set_content(
                    nlohmann::json(
                        {{"data", arr},
                         {"pagination", pagination},
                         {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
            });

    // -- Single Instruction Execution API --------------------------------------

    // POST /api/instructions/:id/execute — dispatch a single instruction definition
    sink.Post(R"(/api/instructions/([^/]+)/execute)", [auth_fn, perm_fn, audit_fn, emit_fn,
                                                       instruction_store, cmd_dispatch,
                                                       cmd_dispatch_concurrency, caller_fn,
                                                       execution_tracker, approval_manager,
                                                       metrics,
                                                       capability_registry](const httplib::Request& req,
                                                                httplib::Response& res) {
        if (!perm_fn(req, res, "Execution", "Execute"))
            return;
        if (!instruction_store || !instruction_store->is_open()) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "instruction store not available"),
                            "application/json");
            return;
        }

        auto def_id = req.matches[1].str();
        // ADR-0058: get_definition now returns std::expected — distinguish a genuine
        // DB error (503, same shape as the store-unavailable check above) from
        // "no such definition" (404, unchanged).
        auto def_result = instruction_store->get_definition(def_id);
        if (!def_result) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "instruction store not available"),
                            "application/json");
            return;
        }
        if (!*def_result) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "instruction definition not found"),
                            "application/json");
            return;
        }
        const auto& def = **def_result;

        // #2437-class guard: raw-text depth check before parse - a
        // parsed-then-dumped "params" value below (`v.dump()`, non-string
        // coercion) still crashes on the dump, so this has to run on the raw
        // text before any allocation.
        if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "request body nests too deeply"),
                            "application/json");
            return;
        }

        // Parse request body
        nlohmann::json j;
        try {
            j = nlohmann::json::parse(req.body);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid request body"), "application/json");
            return;
        }

        // `check_targeting_shape` requires an OBJECT: nlohmann's contains() is
        // false for an array or scalar, so a body of `["dev-1","dev-2"]` would
        // read as "named no target" and broadcast to the whole fleet — the exact
        // class this route is being fixed for, arriving through the guard itself.
        // Found independently by three Gate-3 reviewers.
        if (!j.is_object()) {
            if (metrics) {
                metrics
                    ->counter("yuzu_server_dispatch_target_rejected_total",
                              {{"route", "instruction_execute"}, {"reason", std::string(kReasonBodyType)}})
                    .increment();
            }
            if (audit_fn) {
                audit_fn(req, "instruction.execute", "denied", "instruction", def_id,
                         std::string("reason=") + std::string(kReasonBodyType));
            }
            res.status = 400;
            res.set_content(detail::a4_error(res, "request body must be a JSON object"),
                            "application/json");
            return;
        }

        // ── Targeting shape: supplied-but-names-nothing is an ERROR (#2500) ──
        // The same rule, from the same function, that MCP execute_instruction
        // enforces (#2492). Before this, `{"agent_ids": []}`, a non-array
        // `agent_ids` and a non-string `scope` all fell through to the sink's
        // broadcast default and dispatched to the entire fleet.
        //
        // It runs BEFORE the extraction below rather than after, because
        // extraction is where a non-string entry used to be refused — by
        // `get<std::string>()` throwing `type_error` into the generic catch and
        // surfacing as "invalid request body". That 400 was accidental, said
        // nothing about targeting, emitted no metric and no audit row, and was
        // one refactor away from disappearing. Rejecting here makes it
        // deliberate and countable, and the extraction loop below now operates
        // on types this function has already guaranteed.
        if (auto bv = yuzu::server::check_targeting_shape(j)) {
            if (metrics) {
                metrics
                    ->counter("yuzu_server_dispatch_target_rejected_total",
                              {{"route", "instruction_execute"}, {"reason", bv->reason}})
                    .increment();
            }
            if (audit_fn) {
                audit_fn(req, "instruction.execute", "denied", "instruction", def_id,
                         std::string("reason=") + bv->reason);
            }
            res.status = 400;
            res.set_content(detail::a4_error(res, bv->message), "application/json");
            return;
        }

        std::vector<std::string> agent_ids;
        std::string scope_expr;
        std::unordered_map<std::string, std::string> params;
        try {
            if (j.contains("agent_ids") && j["agent_ids"].is_array()) {
                for (const auto& a : j["agent_ids"])
                    agent_ids.push_back(a.get<std::string>());
            }
            if (j.contains("scope") && j["scope"].is_string())
                scope_expr = j["scope"].get<std::string>();
            if (j.contains("params") && j["params"].is_object()) {
                for (auto& [k, v] : j["params"].items())
                    params[k] = v.is_string() ? v.get<std::string>() : v.dump();
            }
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid request body"), "application/json");
            return;
        }

        // Resolve the authenticated user once for audit and approval.
        auto session = auth_fn(req, res);
        if (!session)
            return;

        // --- Approval gate ---------------------------------------------------
        // If the definition requires approval and the approval manager is
        // available, create a pending approval instead of dispatching immediately.
        // Unknown approval_mode values are treated as requiring approval
        // (fail-closed) to prevent typos from silently bypassing the gate.
        if (!approval_manager && def.approval_mode != "auto") {
            spdlog::error("instruction '{}' requires approval (mode={}) but "
                          "approval_manager is not available — rejecting execution",
                          def_id, def.approval_mode);
            res.status = 503;
            res.set_content(
                detail::a4_error(
                    res, "approval system unavailable — cannot execute approval-gated instruction"),
                "application/json");
            return;
        }
        if (approval_manager && def.approval_mode != "auto") {
            bool needs_approval = false;
            if (def.approval_mode == "always") {
                needs_approval = true;
            } else if (def.approval_mode == "role-gated") {
                // role-gated: admins (incl. an active JIT elevation) bypass, all
                // others need approval — effective_role for elevation consistency.
                needs_approval = (auth::effective_role(*session) != auth::Role::admin);
            } else {
                // Unknown mode — fail closed (require approval)
                spdlog::warn("instruction '{}' has unrecognized approval_mode '{}' "
                             "— requiring approval (fail-closed)",
                             def_id, def.approval_mode);
                needs_approval = true;
            }

            if (needs_approval) {
                // Declaring the origin (#2442) is what makes a ticket minted
                // here REFUSABLE at the MCP recall: def_id is caller-influenced
                // and scope_expr is caller-supplied verbatim, and the MCP recall
                // matches on exactly that pair.
                //
                // It does NOT bar this path from minting into the reserved
                // namespace — nothing does, deliberately. So this argument is
                // load-bearing rather than decorative: `submit()`'s `origin`
                // parameter is no longer defaulted (#2442's closing half), so
                // dropping it is a compile error today, not a silent
                // `kUnspecified` — but get it wrong (e.g. pass kMcp for a
                // non-MCP mint) and the ticket is falsely refusable or, worse,
                // falsely exempt.
                // #1398 hardening: bind target_plugin/target_action (two
                // separate fields, not a concatenated string — see
                // Approval::target_plugin's doc comment) so a FUTURE
                // interactive ticket-redemption implementation (design doc
                // follow-up #6 — none exists on this route today) inherits
                // the same definition-mutation protection ScheduleRunner
                // needed, rather than requiring its own security round later.
                auto result = approval_manager->submit(def_id, session->username, scope_expr, "",
                                                       ApprovalOrigin::kInstruction, def.plugin,
                                                       def.action);
                if (!result) {
                    spdlog::error("approval submit failed for '{}': {}", def_id, result.error());
                    res.status = 500;
                    res.set_content(detail::a4_error(res, "failed to create approval request"),
                                    "application/json");
                    return;
                }
                audit_fn(req, "instruction.approval_required", "pending", "instruction", def_id,
                         "approval_id=" + *result + " mode=" + def.approval_mode);
                emit_fn("approval.created", req);
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Approval required — request submitted","level":"warning"}})");
                res.status = 202;
                res.set_content(nlohmann::json({{"status", "pending_approval"},
                                                {"approval_id", *result},
                                                {"definition_id", def_id}})
                                    .dump(),
                                "application/json");
                return;
            }
        }

        // OMITTED agent_ids + OMITTED scope = broadcast to all agents. That is
        // still the contract and is deliberate. What changed in #2500 is the
        // other half: a targeting argument the caller SUPPLIED can no longer
        // arrive here having silently resolved to nothing — `{"agent_ids": []}`,
        // a non-array `agent_ids` and a non-string `scope` are refused above, so
        // reaching this point empty now means the caller genuinely named no
        // target rather than named one the parser threw away.
        //
        // BR-001 (branch review) — the ONE exception to the broadcast contract
        // just stated: a `def.plugin`/`def.action` classified Destructive or
        // Forensics (`dispatch_destructive_gate.hpp`'s `requires_explicit_
        // targets`) refuses an omitted/broadcast/multi-agent target instead of
        // reaching every agent. This route resolves a free-form plugin.action
        // pair and can fan it out exactly like the three siblings the same
        // header already documents (`/api/command` [command_routes.cpp], MCP
        // `execute_instruction` [mcp_server.cpp], the exec console
        // [dashboard_routes.cpp]) — it was simply the fourth real
        // CommandRequest producer nobody had wired yet. SAME chokepoint, not a
        // copy: `evaluate_destructive_targeting` and both refusal strings come
        // from `dispatch_destructive_gate.hpp` unchanged, so this surface
        // cannot drift from the other three.
        //
        // #4254: two sibling call sites in this same file guard
        // `capability_registry` before dereferencing it (the dispatch_fn
        // closure above, and the BR3-001 preflight block) — this site
        // originally did not. Production always wires this member (mirrors
        // command_routes::Deps::capability_registry, never conditional), so
        // this is defense-in-depth, not a live gap; guard it anyway so a test
        // harness that leaves it unwired gets the same clear 503 the sibling
        // sites answer with, rather than a null dereference.
        if (!capability_registry) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"capability registry not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        {
            const auto gate = yuzu::server::evaluate_destructive_targeting(
                capability_registry->classify(def.plugin, def.action),
                /*valid_nonempty_agent_ids=*/!agent_ids.empty(),
                // scope_expr is already the post-validation shape the
                // header's caller contract requires (check_targeting_shape
                // above refused a supplied-but-empty scope as `scope_empty`),
                // never a raw extraction result.
                /*scope_key_present=*/!scope_expr.empty(),
                /*agent_id_count=*/agent_ids.size());
            // Exhaustive, no `default:` — the same switch shape the other
            // three callers use over this enum (ClassifyMiss is an
            // enumerator the caller must handle, never a skippable `if`).
            switch (gate.verdict) {
            case yuzu::server::DestructiveTargetingVerdict::NotDestructive:
                // ReadOnly/Mutating, non-Forensics: this gate does not apply
                // and dispatch proceeds exactly as before this fix.
                break;
            case yuzu::server::DestructiveTargetingVerdict::ClassifyMiss:
                // Policy B, same choice as the other three callers
                // (dispatch_destructive_gate.hpp's file doc comment): this
                // route has no downstream classify-based backstop of its
                // own, so an early denial here would be a NEW policy rather
                // than a shared one — out of scope for a fix that closes the
                // targeting gap for a row that DOES classify as Destructive/
                // Forensics. An Unclassified/Ambiguous plugin.action keeps
                // today's (pre-fix) behaviour unchanged.
                break;
            case yuzu::server::DestructiveTargetingVerdict::Targeted:
                // Explicit target(s) named correctly for this capability's
                // class — proceed to dispatch below. The shared
                // dispatch_confined seam (#1788), reached via cmd_dispatch/
                // cmd_dispatch_concurrency, still narrows agent_ids to the
                // operator's visible set downstream exactly as it does for
                // every other dispatch arm through this route.
                break;
            case yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted: {
                // Counted on the SAME series as the /api/command, MCP and
                // dashboard refusals, with this surface's own `route` label.
                if (metrics) {
                    try {
                        metrics
                            ->counter("yuzu_server_dispatch_target_rejected_total",
                                      {{"route", "instruction_execute"},
                                       {"reason", std::string(gate.refusal_reason)}})
                            .increment();
                    } catch (const std::exception& e) {
                        spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                                     "(reason={}): {}",
                                     def.plugin, def.action, gate.refusal_reason, e.what());
                    } catch (...) {
                        spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                                     "(reason={})",
                                     def.plugin, def.action, gate.refusal_reason);
                    }
                }
                if (audit_fn) {
                    audit_fn(req, "instruction.execute", "denied", "instruction", def_id,
                             std::string("reason=") + std::string(gate.refusal_reason));
                }
                // Same envelope shape this route already answers with for
                // every other targeting refusal above (#2500) — never a new
                // response shape for this fifth reason string.
                res.status = 400;
                res.set_content(
                    nlohmann::json({{"error", {{"code", 400},
                                               {"message", std::string(gate.refusal_message)}}},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            }
        }

        // PR 2: create the execution row BEFORE dispatch so the
        // execution_id is known when cmd_dispatch generates command_id —
        // closes the UP2-4 FAST-agent race where a sub-millisecond
        // loopback agent could reply before a post-dispatch
        // register-mapping call landed. cmd_dispatch registers the
        // mapping (HA WS-1(1b): PG-backed via
        // `ExecutionTracker::record_command_execution`) BEFORE any RPC is
        // sent so the response handler always finds the entry.
        // agents_targeted is updated below once dispatch confirms `sent`.
        std::string execution_id;
        if (execution_tracker) {
            Execution exec;
            exec.definition_id = def_id;
            exec.status = "running";
            exec.scope_expression = scope_expr;
            // #3136 blocker: persist a REDACTED copy — the live dispatch
            // below still uses the raw `params` map. See
            // sensitive_instruction_params.hpp.
            exec.parameter_values =
                nlohmann::json(redact_sensitive_instruction_params(params)).dump();
            exec.dispatched_by = session->username;
            if (auto created = execution_tracker->create_execution(exec); created.has_value()) {
                execution_id = *created;
            }
        }

        // Dispatch
        std::string command_id;
        int sent = 0;
        // #3424/#3511: mirrors the outer command_id/sent pattern -- dispatch_outcome
        // itself lives inside the try block below and goes out of scope at its
        // closing brace, so the discriminator fields it carries must be copied out
        // to these outer locals if the sent==0 branch further down is to use them.
        bool containment_unreadable = false;
        // WS-4 4.2b Task D: mirrors containment_unreadable exactly — copied
        // out of dispatch_outcome for the same reason (the try block's own
        // scope ends before the sent==0 branch below reads it).
        bool route_unreadable = false;
        std::size_t denied_quarantined_count = 0;
        std::size_t unknown_plugin_count = 0;
        std::optional<std::string> scope_parse_error;
        try {
            // #2500: NAME the broadcast rather than expressing it as "both
            // fields happen to be empty". The shape check above guarantees that
            // arriving here empty means the caller OMITTED both, so this maps
            // the deliberate case onto the sink's explicit `__all__` branch and
            // leaves an accidental empty — from any future code path that skips
            // the check — reaching nobody instead of everybody.
            const std::string dispatch_scope = (agent_ids.empty() && scope_expr.empty())
                                                   ? std::string(kBroadcastScope)
                                                   : scope_expr;
            // K-R7-02 / PLAN-006: confine to AND identify the operator via the
            // shared dispatch_confined seam. `session` is already resolved
            // above; re-derive from the request (fail CLOSED on visibility if
            // the callback is unwired — present-empty set → reaches nobody).
            const yuzu::server::DispatchCaller caller =
                caller_fn ? caller_fn(req)
                          : yuzu::server::DispatchCaller{
                                .exec_visible = yuzu::server::authz::deny_all()};
            // ADR-1007: per-device concurrency gate, when wired.
            const auto dispatch_outcome =
                cmd_dispatch_concurrency
                    ? cmd_dispatch_concurrency(def.plugin, def.action, agent_ids, dispatch_scope,
                                              params, execution_id, caller, def.id,
                                              def.concurrency_mode)
                    : cmd_dispatch(def.plugin, def.action, agent_ids, dispatch_scope, params,
                                   execution_id, caller);
            command_id = dispatch_outcome.command_id;
            sent = dispatch_outcome.sent;
            containment_unreadable = dispatch_outcome.containment_unreadable;
            route_unreadable = dispatch_outcome.route_unreadable;
            denied_quarantined_count = dispatch_outcome.denied_quarantined_count;
            unknown_plugin_count = dispatch_outcome.unknown_plugin_count;
            scope_parse_error = dispatch_outcome.scope_parse_error;
        } catch (const std::exception& e) {
            spdlog::error("instruction dispatch failed: {}", e.what());
            // Pattern C / hardening regression close: the pre-created
            // execution row would otherwise sit at status='running'
            // forever on dispatch failure. mark_cancelled records the
            // attempt for forensic audit instead of orphaning it as a
            // phantom in-flight run that the LIST handler keeps showing.
            if (execution_tracker && !execution_id.empty() &&
                !execution_tracker->mark_cancelled(execution_id, session->username)) {
                spdlog::error("workflow_routes: mark_cancelled failed for execution_id={}",
                              execution_id);
            }
            res.status = 500;
            res.set_content(detail::a4_error(res, "dispatch failed"), "application/json");
            return;
        }

        if (sent == 0) {
            if (execution_tracker && !execution_id.empty() &&
                !execution_tracker->mark_cancelled(execution_id, session->username)) {
                spdlog::error("workflow_routes: mark_cancelled failed for execution_id={}",
                              execution_id);
            }
            // #881/#3424/#3511: "no agents reached" covers several distinct
            // causes this route did not used to discriminate — every target
            // withheld by quarantine, the containment gate failing closed
            // fleet-wide, or (#3511) the dispatched plugin absent from every
            // target's reported inventory. `dispatch_outcome` (above) has
            // carried this discrimination since the #3424/#3511 widening of
            // ConfinedDispatchOutcome; this route just wasn't reading it yet.
            // ADR-1007 adds a further condition this struct does NOT carry:
            // for a `per-device` definition, every target may have been
            // excluded by an already-open concurrency claim rather than being
            // unreachable at all — check yuzu_server_dispatch_concurrency_skipped_total
            // too, same as before, folded into the generic catch-all below.
            if (scope_parse_error) {
                // #3424/#3511 PR review fix round: this route accepts a
                // scope expression (dispatch_scope, above) and reaches the
                // same ConfinedDispatchOutcome::scope_parse_error field
                // mcp_server.cpp's execute_instruction reads -- checked
                // first, same priority as there, since a malformed
                // expression is a caller error, not a fleet-state fact,
                // and 400 (not 503) since this is a client mistake, not a
                // server-side condition. Body shape matches the three 503
                // siblings immediately below (this handler's own local
                // convention, consistency-auditor Gate 4 finding F1) rather
                // than a bare string -- `reason` names the branch and
                // `retry_after_ms: null` is present per rest_a4_envelope.hpp's
                // contract that the key is ALWAYS present, never omitted.
                // `reason` is a route-local extension beyond A4ErrorOpts'
                // fixed field set (retry_after_ms/remediation/permission/
                // approval_id/status_url only) — built by hand rather than
                // via `detail::a4_error` so `reason` survives, with
                // `correlation_id` added via `detail::ensure_correlation_id`
                // to still satisfy A4's required-field set.
                res.status = 400;
                res.set_content(
                    nlohmann::json({{"error",
                                     {{"code", 400},
                                      {"message", "invalid scope: " + *scope_parse_error},
                                      {"reason", "invalid_scope"},
                                      {"retry_after_ms", nullptr},
                                      {"correlation_id", detail::ensure_correlation_id(res)}}},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            res.status = 503;
            // Same route-local `reason`-carrying extension as the
            // scope_parse_error branch above — hand-built, not
            // `detail::a4_error`, to keep `reason` alongside the A4-required
            // `correlation_id`.
            if (containment_unreadable) {
                res.set_content(
                    nlohmann::json(
                        {{"error", {{"code", 503},
                                   {"message", "containment state is unreadable — dispatch is "
                                               "failing closed and reaching no agent; check the "
                                               "quarantine store"},
                                   {"reason", "containment_unreadable"},
                                   {"retry_after_ms", 5000},
                                   {"correlation_id", detail::ensure_correlation_id(res)}}},
                         {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
            } else if (route_unreadable) {
                // WS-4 4.2b Task D: the exact sibling of containment_unreadable
                // above — a degraded gateway routing-directory read, not a
                // per-target fact. Same priority tier, checked right after.
                res.set_content(
                    nlohmann::json(
                        {{"error", {{"code", 503},
                                   {"message", "the gateway routing directory could not be "
                                               "read for one or more targets — dispatch is "
                                               "failing closed rather than guessing where to "
                                               "route"},
                                   {"reason", "route_unreadable"},
                                   {"retry_after_ms", 5000},
                                   {"correlation_id", detail::ensure_correlation_id(res)}}},
                         {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
            } else if (denied_quarantined_count > 0) {
                res.set_content(
                    nlohmann::json(
                        {{"error", {{"code", 503},
                                   {"message", "every target is quarantined — dispatch was "
                                               "withheld, not attempted"},
                                   {"reason", "quarantined"},
                                   {"retry_after_ms", nullptr},
                                   {"correlation_id", detail::ensure_correlation_id(res)}}},
                         {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
            } else if (unknown_plugin_count > 0) {
                res.set_content(
                    nlohmann::json(
                        {{"error", {{"code", 503},
                                   {"message", "the dispatched plugin is not in any target's "
                                               "reported inventory — dispatch was withheld, not "
                                               "attempted"},
                                   {"reason", "plugin_not_found"},
                                   {"retry_after_ms", nullptr},
                                   {"correlation_id", detail::ensure_correlation_id(res)}}},
                         {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
            } else {
                res.set_content(
                    detail::a4_error(
                        res, "no agents reached: every target was unreachable or excluded by an "
                             "in-flight per-device concurrency claim. Check "
                             "yuzu_server_dispatch_concurrency_skipped_total before treating this "
                             "as an agent-connectivity fault."),
                    "application/json");
            }
            return;
        }

        // Update the pre-created execution row with the actual targeted
        // count and refresh agents_responded counters now that dispatch
        // has confirmed how many agents the command went to.
        if (execution_tracker && !execution_id.empty()) {
            if (!execution_tracker->set_agents_targeted(execution_id, sent)) {
                spdlog::error("workflow_routes: set_agents_targeted failed for execution_id={}",
                              execution_id);
            }
        }

        // governance R1 happy-LOW-1 (#1088 round): include execution_id
        // in audit detail so SOC 2 investigators can join the audit row
        // to the execution tracker row without a separate lookup.
        audit_fn(req, "instruction.execute", "success", "instruction", def_id,
                 "command_id=" + command_id + " execution_id=" + execution_id +
                     " agents=" + std::to_string(sent));
        emit_fn("instruction.executed", req);

        auto trigger_msg = std::string("{\"showToast\":{\"message\":\"Instruction dispatched to ") +
                           std::to_string(sent) + " agent(s)\",\"level\":\"success\"}}";
        res.set_header("HX-Trigger", trigger_msg);
        // #1088 — include execution_id in the response so an agentic
        // worker can immediately subscribe to /api/v1/events with it
        // (the agentic-first endpoint requires execution_id, not
        // command_id). Empty execution_id when execution_tracker is
        // unavailable is included anyway as an empty string so the
        // response shape stays stable.
        res.set_content(nlohmann::json({{"command_id", command_id},
                                        {"execution_id", execution_id},
                                        {"agents_reached", sent},
                                        {"definition_id", def_id}})
                            .dump(),
                        "application/json");
    });

    // -- Product Pack API (Phase 7) -------------------------------------------

    // GET /api/product-packs -- list installed product packs
    sink.Get("/api/product-packs", [perm_fn, product_pack_store](const httplib::Request& req,
                                                                 httplib::Response& res) {
        if (!perm_fn(req, res, "ProductPack", "Read"))
            return;
        if (!product_pack_store || !product_pack_store->is_open()) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "product pack store not available"),
                            "application/json");
            return;
        }

        ProductPackQuery q;
        if (req.has_param("name"))
            q.name_filter = req.get_param_value("name");
        try {
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid numeric query parameter"),
                            "application/json");
            return;
        }

        auto packs_result = product_pack_store->list(q);
        if (!packs_result) {
            res.status = product_pack_error_status(packs_result.error());
            res.set_content(detail::a4_error(res, product_pack_client_message(
                                                       "GET /api/product-packs",
                                                       packs_result.error())),
                            "application/json");
            return;
        }
        auto& packs = *packs_result;
        // #4029: shared builder (product_pack_model.hpp) — the same function
        // GET /api/v1/product-packs and MCP list_product_packs call, so this
        // route's shape cannot silently drift from theirs.
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& p : packs)
            arr.push_back(product_pack_row_json(p));
        res.set_content(nlohmann::json({{"product_packs", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });

    // POST /api/product-packs -- install product pack from YAML bundle
    sink.Post("/api/product-packs", [perm_fn, audit_fn, emit_fn, product_pack_store,
                                     instruction_store, policy_store, workflow_engine](
                                        const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ProductPack", "Write"))
            return;
        if (!product_pack_store || !product_pack_store->is_open()) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "product pack store not available"),
                            "application/json");
            return;
        }

        std::string yaml_bundle;
        if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
            try {
                auto j = nlohmann::json::parse(req.body);
                yaml_bundle = j.value("yaml_source", "");
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "invalid request body"), "application/json");
                return;
            }
        } else {
            yaml_bundle = req.body;
        }

        // F033/#3481: optional client-supplied dedup key. Missing header -> empty string ->
        // install()'s existing unguarded behavior, unchanged. Length-bounded before it ever
        // reaches the store — an unbounded header is an easy way to bloat the idempotency_key
        // column/index for no functional benefit.
        std::string idempotency_key = req.get_header_value("Idempotency-Key");
        if (idempotency_key.size() > 200) {
            res.status = 400;
            res.set_content(
                detail::a4_error(res, "Idempotency-Key header too long (max 200 characters)"),
                "application/json");
            return;
        }

        // Install callback: delegate each document to the appropriate store
        auto install_fn =
            [instruction_store, policy_store, workflow_engine](
                const std::string& kind,
                const std::string& yaml_source) -> std::expected<std::string, std::string> {
            if (kind == "InstructionDefinition") {
                if (!instruction_store || !instruction_store->is_open())
                    return std::unexpected("instruction store not available");
                // Parse YAML into InstructionDefinition and create
                InstructionDefinition def;
                def.name = ProductPackStore::extract_yaml_value(yaml_source, "displayName");
                if (def.name.empty())
                    def.name = ProductPackStore::extract_yaml_value(yaml_source, "name");
                def.version = ProductPackStore::extract_yaml_value(yaml_source, "version");
                if (def.version.empty())
                    def.version = "1.0.0";
                def.type = ProductPackStore::extract_yaml_value(yaml_source, "type");
                if (def.type.empty())
                    def.type = "question";
                def.plugin = ProductPackStore::extract_yaml_value(yaml_source, "plugin");
                def.action = ProductPackStore::extract_yaml_value(yaml_source, "action");
                // Normalize action to lowercase — agent plugins match case-sensitively
                for (auto& c : def.action)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                def.description = ProductPackStore::extract_yaml_value(yaml_source, "description");
                def.yaml_source = yaml_source;
                def.platforms = ProductPackStore::extract_yaml_value(yaml_source, "platforms");
                def.approval_mode = ProductPackStore::extract_yaml_value(yaml_source, "mode");
                if (def.approval_mode.empty())
                    def.approval_mode = "auto";
                // Validate approval_mode — reject unknown values at creation time
                if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
                    def.approval_mode != "always") {
                    return std::unexpected("invalid approval mode: " + def.approval_mode +
                                           " (must be auto, role-gated, or always)");
                }
                return instruction_store->create_definition(def);
            } else if (kind == "PolicyFragment") {
                if (!policy_store || !policy_store->is_open())
                    return std::unexpected("policy store not available");
                return policy_store->create_fragment(yaml_source);
            } else if (kind == "Policy") {
                if (!policy_store || !policy_store->is_open())
                    return std::unexpected("policy store not available");
                return policy_store->create_policy(yaml_source);
            } else if (kind == "Workflow") {
                // kProductPackDbErrorPrefix-tagged (ADR-0064 governance fix): a null/unopen
                // engine is a genuine unavailability the REST layer must 503, not a validation
                // rejection — matches the InstructionDefinition arm's identical shape above.
                if (!workflow_engine || !workflow_engine->is_open())
                    return std::unexpected(std::string(kProductPackDbErrorPrefix) +
                                           "workflow engine unavailable");
                return workflow_engine->create_workflow(yaml_source);
            } else {
                return std::unexpected("unsupported kind: " + kind);
            }
        };

        // F031/#3481: best-effort undo of whatever install_fn already committed, if the final
        // persist transaction below fails.
        auto compensate_fn = make_item_delete_fn(instruction_store, policy_store, workflow_engine);
        // #3479: per-document detail — a bundle where some (not all) documents fail no longer
        // silently drops which ones and why behind a bare "installed" response.
        InstallPartialResult partial_result;
        auto result = product_pack_store->install(yaml_bundle, install_fn, compensate_fn,
                                                  idempotency_key, &partial_result);
        if (!result) {
            // gov W7.4 R1 UP-1 / compliance CC6.7 / sre B2: SOC 2 CC6.7
            // requires "all access decisions logged". The pack-install
            // rejection IS an access decision — without this audit row, an
            // attacker probing enforcement state via repeated unsigned-pack
            // POSTs leaves zero rows in the audit store. This becomes a
            // primary code path once #802's default-true flip ships, so the
            // audit gap goes from "MEDIUM, edge case" to "HIGH, every prod
            // server with unsigned packs in its environment hits this".
            //
            // target_id is empty: install failed pre-id-generation, no
            // pack_id exists yet. The pack-name field is attacker-controlled
            // YAML so we don't echo it into target_id (would create an
            // attacker-influenced audit key); the pack name is recoverable
            // from the request body if forensics need it.
            //
            // Gate 4 Finding B / Gate 6 CO-1 (third instance of SEC-1/ARCH-1's class):
            // result.error() can carry a genuine kDbErrorPrefix failure from any
            // install_fn arm (InstructionStore/PolicyStore/WorkflowEngine) — the response
            // body was already genericized below via product_pack_client_message, but this
            // audit row previously stored the raw driver text verbatim AND hardcoded
            // "denied" even on an infrastructure failure, misclassifying an outage as an
            // access decision (the exact vocabulary bug commit 849cf6a34 fixed at 7 other
            // sites, missed here).
            audit_fn(req, "product_pack.install",
                     yuzu::server::is_generic_db_error(result.error()) ? "error" : "denied",
                     "ProductPack", "",
                     yuzu::server::genericize_db_error("product_pack.install", result.error()));
            res.status = product_pack_error_status(result.error());
            res.set_content(detail::a4_error(res, product_pack_client_message(
                                                       "POST /api/product-packs", result.error())),
                            "application/json");
            return;
        }
        // gov W7.4 R2 sec-MEDIUM: target_type "ProductPack" matches the
        // denied sibling above, the RBAC perm_fn calls in this file
        // (1484/1533/1647/1692), and the audit-log.md docs entry. Was
        // "product_pack" pre-W7.4 R2 — SIEM rules filtering on either
        // string would have missed half the rows for this action.
        // #3479: audit detail names the partial-failure count too, so an auditor doesn't need
        // to reconstruct it from the response body — same "identity, not just outcome" bar the
        // compensation N/M suffix (#3481) already set for the denied path.
        std::string audit_detail;
        nlohmann::json response_body{{"id", *result}, {"status", "installed"}};
        if (!partial_result.errors.empty()) {
            response_body["errors"] = partial_result.errors;
            response_body["installed_count"] = partial_result.installed_count;
            response_body["total_items"] = partial_result.total_items;
            audit_detail = std::to_string(partial_result.errors.size()) + "/" +
                           std::to_string(partial_result.total_items) +
                           " item(s) failed to install";
        }
        audit_fn(req, "product_pack.install", "success", "ProductPack", *result, audit_detail);
        emit_fn("product_pack.installed", req);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Product pack installed","level":"success"}})");
        res.status = 201;
        // Gate 8 review (security-guardian, #3479/#3481): unlike `id` (server-generated hex,
        // always valid UTF-8), `errors[]` entries can reflect attacker-controlled YAML field
        // values (e.g. an invalid `mode:` value quoted verbatim into the error string) — the
        // default strict dump() throws on invalid UTF-8, which would 500 AFTER the partial
        // install (and its audit row) already committed. error_handler_t::replace (established
        // convention — see analytics_event_store.cpp/bundle_service.cpp/preflight_eval.cpp)
        // substitutes U+FFFD instead.
        res.set_content(
            response_body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace),
            "application/json");
    });

    // GET /api/product-packs/:id -- get product pack detail
    sink.Get(R"(/api/product-packs/([^/]+))", [perm_fn,
                                               product_pack_store](const httplib::Request& req,
                                                                   httplib::Response& res) {
        if (!perm_fn(req, res, "ProductPack", "Read"))
            return;
        if (!product_pack_store) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto pack_result = product_pack_store->get(id);
        if (!pack_result) {
            res.status = product_pack_error_status(pack_result.error());
            res.set_content(detail::a4_error(res, product_pack_client_message(
                                                       "GET /api/product-packs/:id",
                                                       pack_result.error())),
                            "application/json");
            return;
        }
        if (!*pack_result) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "product pack not found"), "application/json");
            return;
        }
        auto& pack = *pack_result;

        // #4029: shared builder (product_pack_model.hpp) — the same function
        // GET /api/v1/product-packs/{id} and MCP get_product_pack call.
        res.set_content(product_pack_detail_json(*pack).dump(), "application/json");
    });

    // DELETE /api/product-packs/:id -- uninstall product pack
    sink.Delete(R"(/api/product-packs/([^/]+))", [perm_fn, audit_fn, emit_fn, product_pack_store,
                                                  instruction_store, policy_store,
                                                  workflow_engine](const httplib::Request& req,
                                                                   httplib::Response& res) {
        if (!perm_fn(req, res, "ProductPack", "Delete"))
            return;
        if (!product_pack_store) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();

        // Uninstall callback: delegate to the appropriate store (same dispatch install's
        // compensate_fn uses — see make_item_delete_fn's doc comment for the per-kind
        // db_error/not_found split, currently unreachable here since instruction_store_ and
        // product_pack_store_ share one boot latch, kept as defense-in-depth).
        auto uninstall_fn = make_item_delete_fn(instruction_store, policy_store, workflow_engine);

        auto result = product_pack_store->uninstall(id, uninstall_fn);
        if (!result) {
            // gov W7.4 R1 UP-1 parity (see install's denied branch above): a
            // rejected uninstall — not-found, or a mid-uninstall DB failure —
            // is an access decision SOC 2 CC6.7 requires logged. Pre-fix, this
            // branch returned without ever calling audit_fn, so a probe of a
            // nonexistent/unreachable pack id left zero audit rows. "denied"
            // (not a distinct "error" result) matches install's own vocabulary
            // for this same three-way not-found/validation/db-error split.
            //
            // gov Gate 8 round-2 (security-guardian + docs-writer, independently):
            // uninstall()'s not_found check reads via get() first, whose own
            // query-error branch can embed a raw PQerrorMessage() fragment —
            // unlike install()'s db-error branch, which never does. Genericize
            // ONCE and reuse the result for both the audit `detail` and the
            // client response, rather than calling product_pack_client_message
            // twice (it spdlog::errors as a side effect — calling it twice would
            // double-log the same failure).
            const std::string client_msg = product_pack_client_message(
                "DELETE /api/product-packs/:id", result.error());
            audit_fn(req, "product_pack.uninstall", "denied", "ProductPack", id, client_msg);
            res.status = product_pack_error_status(result.error());
            res.set_content(detail::a4_error(res, client_msg), "application/json");
            return;
        }
        // gov W7.4 R2 sec-MEDIUM: target_type "ProductPack" sibling parity
        // (see install handler above).
        audit_fn(req, "product_pack.uninstall", "success", "ProductPack", id, "");
        emit_fn("product_pack.uninstalled", req);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Product pack uninstalled","level":"success"}})");
        res.set_content(R"({"status":"uninstalled"})", "application/json");
    });
}

} // namespace yuzu::server
