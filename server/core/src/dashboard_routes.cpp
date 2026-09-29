#include "dashboard_routes.hpp"

#include "dispatch_destructive_gate.hpp" // PR6.0b: the shared Destructive targeting gate (#3685)
#include "on_behalf_guard.hpp"              // sanitize_for_log
#include "dispatch_target_shape.hpp" // kBroadcastScope (#2500), kReasonDestructiveUntargeted
#include "rest_a4_envelope_http.hpp" // detail::a4_error, make_correlation_id (#4027 REST twin)
#include "tar_tree_routes.hpp" // TarRetentionPausedScan/TarPausedSourceRow/tar_retention_paused_json (#4027)

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <format>
#include <regex>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <spdlog/spdlog.h>

#include "agent_registry.hpp" // provides detail::AgentRegistry
#include "event_bus.hpp"
#include "http_route_sink.hpp"
#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "response_store.hpp"
#include "response_templates_engine.hpp"
#include "visualization_engine.hpp"
#include "result_parsing.hpp"
#include "tag_store.hpp"
#include "web_utils.hpp"

namespace yuzu::server {

// -- Helper: clamp an integer to [lo, hi] -------------------------------------
static int clamp(int val, int lo, int hi) {
    return std::max(lo, std::min(val, hi));
}

// -- Helper: format epoch seconds as a coarse "Xd Yh ago" age -----------------
//
// Used by the TAR retention-paused list. Intentionally coarse: operators care
// about "this has been paused for days/hours" not seconds. Returns "—" for 0
// (sentinel for "never paused").
static std::string format_age(int64_t epoch_then, int64_t now_epoch) {
    if (epoch_then <= 0) return "—";
    int64_t delta = now_epoch - epoch_then;
    if (delta < 0) delta = 0;
    if (delta < 60) return std::format("{}s ago", delta);
    if (delta < 3600) return std::format("{}m ago", delta / 60);
    if (delta < 86400) return std::format("{}h {}m ago", delta / 3600, (delta % 3600) / 60);
    int64_t days = delta / 86400;
    int64_t hours = (delta % 86400) / 3600;
    if (days < 30) return std::format("{}d {}h ago", days, hours);
    return std::format("{}d ago", days);
}

// -- Helper: format epoch seconds as ISO-ish "YYYY-MM-DD HH:MM UTC" -----------
static std::string format_utc(int64_t epoch_secs) {
    if (epoch_secs <= 0) return "—";
    std::time_t t = static_cast<std::time_t>(epoch_secs);
    std::tm tm_val{};
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    return std::format("{:04}-{:02}-{:02} {:02}:{:02} UTC",
                        tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
                        tm_val.tm_hour, tm_val.tm_min);
}

// -- Helper: epoch-seconds "now" for human-facing age math ---------------------
static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

// -- Helper: safe int from query param ----------------------------------------
static int param_int(const httplib::Request& req, const char* name, int def) {
    if (!req.has_param(name)) return def;
    try { return std::stoi(req.get_param_value(name)); }
    catch (...) { return def; }
}

// -- Helper: column index by name (case-insensitive, excl. Agent col) ---------
static int col_index_for_name(const std::vector<std::string>& cols, const std::string& name) {
    // cols[0] is "Agent" — field indices are 0-based starting after Agent
    for (size_t i = 1; i < cols.size(); ++i) {
        auto& c = cols[i];
        if (c.size() == name.size() &&
            std::equal(c.begin(), c.end(), name.begin(),
                       [](char a, char b) { return std::tolower(a) == std::tolower(b); })) {
            return static_cast<int>(i - 1); // field index (0-based, excl. Agent)
        }
    }
    return -1;
}

/// Parse CLI-style "plugin action key=val key2=\"quoted val\"" into command + params.
static std::pair<std::string, std::unordered_map<std::string, std::string>>
parse_instruction_params(const std::string& text) {
    std::unordered_map<std::string, std::string> params;
    std::string command;

    size_t pos = 0;
    size_t len = text.size();

    while (pos < len) {
        // Skip whitespace
        while (pos < len && text[pos] == ' ') ++pos;
        if (pos >= len) break;

        // Look ahead to find '=' in this token
        size_t scan = pos;
        while (scan < len && text[scan] != ' ' && text[scan] != '=') ++scan;

        if (scan < len && text[scan] == '=' && scan > pos) {
            // key=value pair — key is lowercase, value preserves case
            std::string key = text.substr(pos, scan - pos);
            for (auto& c : key) c = static_cast<char>(std::tolower(c));
            ++scan; // skip '='

            std::string val;
            if (scan < len && text[scan] == '"') {
                // Quoted value: read until closing quote
                ++scan;
                size_t close = text.find('"', scan);
                if (close == std::string::npos) close = len;
                val = text.substr(scan, close - scan);
                pos = (close < len) ? close + 1 : len;
            } else {
                // Unquoted value: read until space
                size_t vstart = scan;
                while (scan < len && text[scan] != ' ') ++scan;
                val = text.substr(vstart, scan - vstart);
                pos = scan;
            }
            params[key] = val;
        } else {
            // Regular word — part of the command
            size_t end = pos;
            while (end < len && text[end] != ' ') ++end;
            if (!command.empty()) command += ' ';
            command += text.substr(pos, end - pos);
            pos = end;
        }
    }
    return {command, params};
}

// ---------------------------------------------------------------------------
// register_routes
// ---------------------------------------------------------------------------

// httplib::Server& overload — wraps the server in an HttplibRouteSink and
// delegates, so production registration and the in-process test registration
// run the exact same handler-construction code (#1786).
void DashboardRoutes::register_routes(httplib::Server& svr,
                                       AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                                       ResponseStore* response_store,
                                       ManagementGroupStore* mgmt_group_store,
                                       detail::AgentRegistry* registry, TagStore* tag_store,
                                       detail::EventBus* event_bus,
                                       AgentsJsonFn agents_json_fn,
                                       DispatchFn dispatch_fn,
                                       CallerFn caller_fn,
                                       ResolveFn resolve_fn,
                                       yuzu::MetricsRegistry* metrics,
                                       InstructionStore* instruction_store,
                                       VisibleSetFn visible_set_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    response_store, mgmt_group_store, registry, tag_store, event_bus,
                    std::move(agents_json_fn), std::move(dispatch_fn), std::move(caller_fn),
                    std::move(resolve_fn), metrics, instruction_store,
                    std::move(visible_set_fn));
}

void DashboardRoutes::register_routes(HttpRouteSink& sink,
                                       AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                                       ResponseStore* response_store,
                                       ManagementGroupStore* mgmt_group_store,
                                       detail::AgentRegistry* registry, TagStore* tag_store,
                                       detail::EventBus* event_bus,
                                       AgentsJsonFn agents_json_fn,
                                       DispatchFn dispatch_fn,
                                       CallerFn caller_fn,
                                       ResolveFn resolve_fn,
                                       yuzu::MetricsRegistry* metrics,
                                       InstructionStore* instruction_store,
                                       VisibleSetFn visible_set_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    response_store_ = response_store;
    mgmt_group_store_ = mgmt_group_store;
    registry_ = registry;
    tag_store_ = tag_store;
    event_bus_ = event_bus;
    agents_json_fn_ = std::move(agents_json_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    caller_fn_ = std::move(caller_fn);
    resolve_fn_ = std::move(resolve_fn);
    metrics_ = metrics;
    instruction_store_ = instruction_store;
    visible_set_fn_ = std::move(visible_set_fn);

    // Phase 15.A — issue #547 metric registrations. The design doc
    // (docs/tar-dashboard.md §7) defines the catalog; PR-A implements the
    // two that are operational today (the rest land with their owning PRs).
    if (metrics_) {
        metrics_->describe(
            "yuzu_tar_dashboard_view_total",
            "Operator views of the TAR dashboard fragments by frame and result.",
            "counter");
        metrics_->describe(
            "yuzu_tar_retention_paused_devices",
            "Number of devices currently reporting a paused TAR source, by source name.",
            "gauge");
        metrics_->describe(
            "yuzu_tar_scan_dispatched_total",
            "Operator-triggered tar.status scans dispatched by result (success / "
            "rate_limited / no_visible_agents / no_connected_agents / denied).",
            "counter");
        metrics_->describe(
            "yuzu_tar_source_reenable_total",
            "Operator-triggered TAR source re-enable attempts by result "
            "(success / scope_violation / agent_not_connected / denied / invalid_input).",
            "counter");
        metrics_->describe(
            "yuzu_tar_source_purge_total",
            "Operator-triggered TAR retention-paused source purge (destructive) attempts by "
            "result (success / scope_violation / agent_not_connected / denied / invalid_input). "
            "Counts DISPATCH outcomes; the agent's rows_deleted / source_not_paused outcome is in "
            "the command response record.",
            "counter");
    }

    // -- GET /fragments/results -----------------------------------------------
    sink.Get("/fragments/results",
            [this](const httplib::Request& req, httplib::Response& res) {
                // #1712 / #3290 Phase 2 — migrated onto require_fleet_read
                // (fleet_read_fn_), mirroring query_installed_software: the
                // gate is now the SOLE authorization check (never stacked
                // with perm_fn_ — the BLOCKING defect require_fleet_read's
                // own doc comment warns against).
                if (!fleet_read_fn_) {
                    spdlog::error("/fragments/results: fleet_read_fn_ unwired — "
                                  "misconfigured call site; failing closed");
                    res.status = 503;
                    res.set_content(
                        "<tbody id=\"results-tbody\"><tr><td class=\"empty-state\">"
                        "Service unavailable.</td></tr></tbody>",
                        "text/html; charset=utf-8");
                    return;
                }
                auto gate = fleet_read_fn_(req, res, "Response", "Read");
                if (!gate.admitted)
                    return; // gate already wrote the A4 error body + status
                            // (JSON — same shape perm_fn_'s require_permission
                            // already wrote on this route pre-migration; not a
                            // content-type change for an HTMX consumer).

                auto command_id = req.get_param_value("command_id");
                auto plugin = req.get_param_value("plugin");
                if (command_id.empty() || plugin.empty()) {
                    res.status = 400;
                    res.set_content(
                        "<tbody id=\"results-tbody\"><tr><td class=\"empty-state\">"
                        "Missing command_id or plugin.</td></tr></tbody>",
                        "text/html; charset=utf-8");
                    return;
                }

                // Hardening (governance F-3): treat ?dir= as evidence the
                // operator set sort intent. Without this, a URL of
                // ?template_id=X&dir=desc silently overrides the operator's
                // chosen direction with whatever the template carries.
                bool sort_explicit = req.has_param("sort") || req.has_param("dir");
                auto sort_col = req.get_param_value("sort");
                auto sort_dir = req.get_param_value("dir");
                if (sort_col.empty()) sort_col = "agent";
                if (sort_dir.empty()) sort_dir = "asc";

                int page = clamp(param_int(req, "page", 1), 1, 100000);
                int per_page = clamp(param_int(req, "per_page", 50), 10, 200);

                auto filters = parse_filters(req, plugin);
                bool filters_explicit = !filters.empty();
                auto text_query = req.get_param_value("q");

                // Issue #587: when the dispatcher knew the definition_id
                // (e.g. an instruction text resolved to a definition with
                // spec.visualization), it propagates here so the chart
                // deck is re-rendered as an OOB swap alongside the tbody.
                static const std::regex kIdRegex{"^[A-Za-z0-9._-]{1,128}$"};
                std::string definition_id;
                if (req.has_param("definition_id")) {
                    auto raw = req.get_param_value("definition_id");
                    if (std::regex_match(raw, kIdRegex))
                        definition_id = raw;
                    // Silently drop malformed values rather than 400 — this
                    // is an OOB enrichment, not a primary contract; the
                    // results table still renders.
                }

                // Issue #254 (Phase 8.2) — response template resolution.
                // When the operator picks a template from the dropdown,
                // the chosen template_id arrives here. We resolve it
                // against the definition and use its sort/filter/columns
                // as defaults for any axis the URL did not explicitly
                // override. Operator URL state always wins.
                std::string template_id;
                std::vector<std::string> visible_columns;
                static const std::regex kTplIdRegex{"^[A-Za-z0-9_-]{1,64}$"};
                if (req.has_param("template_id")) {
                    auto raw = req.get_param_value("template_id");
                    if (std::regex_match(raw, kTplIdRegex)) template_id = raw;
                }
                if (!template_id.empty() && !definition_id.empty() &&
                    instruction_store_ && instruction_store_->is_open()) {
                    // ADR-0058: a DB-error outer result skips this best-effort template
                    // resolution, same as a not-found inner optional did pre-migration.
                    auto def_result = instruction_store_->get_definition(definition_id);
                    if (def_result && *def_result) {
                        const auto& def = **def_result;
                        ResponseTemplatesEngine engine;
                        std::vector<ResponseTemplate> templates;
                        if (auto parsed = engine.parse(def.response_templates_spec); parsed)
                            templates = std::move(*parsed);
                        auto resolved = engine.resolve(templates, template_id,
                                                      def.result_schema, def.plugin);
                        // Sort default — only when URL didn't supply one.
                        if (!sort_explicit && !resolved.sort_column.empty()) {
                            // The dashboard sort param uses lowercased,
                            // space-as-underscore column keys (matches
                            // the convention in render_results below).
                            std::string key;
                            for (char c : resolved.sort_column) {
                                if (c == ' ' || c == '-') key += '_';
                                else key += static_cast<char>(std::tolower(c));
                            }
                            sort_col = key;
                            sort_dir = resolved.sort_dir.empty() ? "asc" : resolved.sort_dir;
                        }
                        // Filter defaults — only the equals-op filters
                        // map onto FacetFilter's exact-match contract.
                        // Other ops (contains/starts_with/...) are
                        // honoured by REST consumers but not auto-applied
                        // by the dashboard for now.
                        if (!filters_explicit) {
                            auto render_cols = resolve_render_columns(plugin, definition_id);
                            for (const auto& tf : resolved.filters) {
                                if (tf.op != "equals") continue;
                                int col_idx = col_index_for_name(render_cols, tf.column);
                                if (col_idx < 0) continue;
                                FacetFilter f;
                                f.col_idx = col_idx;
                                f.value = tf.value;
                                filters.push_back(std::move(f));
                            }
                        }
                        visible_columns = resolved.columns;
                    }
                }

                auto html = render_results(command_id, plugin, sort_col, sort_dir,
                                           page, per_page, filters, text_query,
                                           definition_id, template_id,
                                           visible_columns, gate.scope);
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- GET /fragments/results/filter-bar ------------------------------------
    sink.Get("/fragments/results/filter-bar",
            [this](const httplib::Request& req, httplib::Response& res) {
                // Flat gate (ADR-0017 PR-B admission migration onto
                // require_list_read/authorize_list_read is out of scope
                // here): a caller whose only Response:Read grant is
                // management-group-scoped is still denied at this line
                // (require_list_read's documented non-composition,
                // auth_routes.hpp).
                if (!perm_fn_(req, res, "Response", "Read")) return;
                auto session = auth_fn_(req, res);
                if (!session) return;

                auto command_id = req.get_param_value("command_id");
                auto plugin = req.get_param_value("plugin");
                if (command_id.empty() || plugin.empty()) {
                    res.status = 400;
                    res.set_content("<div id=\"filter-bar\"></div>",
                                    "text/html; charset=utf-8");
                    return;
                }

                static const std::regex kIdRegex{"^[A-Za-z0-9._-]{1,128}$"};
                std::string definition_id;
                if (req.has_param("definition_id")) {
                    auto raw = req.get_param_value("definition_id");
                    if (std::regex_match(raw, kIdRegex))
                        definition_id = raw;
                }
                static const std::regex kTplIdRegex{"^[A-Za-z0-9_-]{1,64}$"};
                std::string template_id;
                if (req.has_param("template_id")) {
                    auto raw = req.get_param_value("template_id");
                    if (std::regex_match(raw, kTplIdRegex)) template_id = raw;
                }

                auto html = render_filter_bar(command_id, plugin, definition_id, template_id,
                                              session->username, auth::is_elevated(*session));
                // The body is now principal-specific (confined per caller's
                // visible scope) rather than fleet-common, so an unpartitioned
                // shared cache would replay one operator's facet values to
                // another — same guard the per-operator TAR fragments use.
                res.set_header("Cache-Control", "no-store, private");
                res.set_header("Vary", "Cookie");
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- GET /fragments/executions/{id}/visualization (issue #253) ------------
    //
    // HTMX placeholder for instruction-response chart cards. Lives here
    // (next to /fragments/results) rather than in server.cpp so the
    // dashboard fragment surface is in one file. Closes arch-S6 / #589.
    //
    // Returns either:
    //   * a `<div class="yuzu-chart-deck">` containing one
    //     `<div data-yuzu-chart-url="...&index=K">` per configured chart
    //     (issue #587 — definitions may declare multiple charts) that the
    //     yuzu-charts.js auto-render hook (htmx:afterSettle) populates,
    //   * an empty body when the definition is missing or has no
    //     visualization configured (so the dashboard suppresses the
    //     deck entirely rather than showing a "no data" placeholder).
    //
    // Securable: Response:Read — sibling parity with /fragments/results
    // and the /api/v1/executions/{id}/visualization REST endpoint.
    sink.Get(R"(/fragments/executions/([A-Za-z0-9._-]+)/visualization)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Response", "Read")) return;
                auto execution_id = req.matches[1].str();
                std::string definition_id;
                if (req.has_param("definition_id"))
                    definition_id = req.get_param_value("definition_id");
                // Validate definition_id with the same character set the
                // path-bound execution_id uses. Closes sec-H1: without
                // this check a value containing `"` or `>` would break
                // out of the `data-yuzu-chart-url` attribute below
                // (reflected XSS).
                static const std::regex kIdRegex{"^[A-Za-z0-9._-]{1,128}$"};
                if (execution_id.empty() || definition_id.empty() ||
                    !std::regex_match(definition_id, kIdRegex)) {
                    res.status = 400;
                    res.set_content(
                        R"(<div class="yuzu-chart-empty">Missing or malformed execution id or definition_id.</div>)",
                        "text/html; charset=utf-8");
                    return;
                }
                // Pre-flight count: skip the entire deck when no chart is
                // configured. count() handles both legacy single-object
                // and canonical array shapes.
                int chart_count = 0;
                if (instruction_store_ && instruction_store_->is_open()) {
                    // ADR-0058: a DB-error outer result leaves chart_count at 0 (deck
                    // skipped below), same as a not-found inner optional did pre-migration.
                    auto def_result = instruction_store_->get_definition(definition_id);
                    if (def_result && *def_result)
                        chart_count = VisualizationEngine::count((*def_result)->visualization_spec);
                }
                if (chart_count <= 0) {
                    res.set_content("", "text/html; charset=utf-8");
                    return;
                }

                // Both ids regex-bounded by this point — safe to embed
                // verbatim into the attribute value. One placeholder per
                // chart; yuzu-charts.js fetches each independently so a
                // slow/failed render of one chart doesn't block siblings.
                // Use `&amp;` (not raw `&`) inside HTML attribute values for
                // strict HTML5 conformance and consistency with render_results
                // base_url emission. Closes governance C-14 / sec-F5 / UP-36.
                std::string html = R"(<div class="yuzu-chart-deck">)";
                for (int i = 0; i < chart_count; ++i) {
                    html += R"(<div class="yuzu-chart-card" data-yuzu-chart-url=")";
                    html += "/api/v1/executions/" + execution_id
                          + "/visualization?definition_id=" + definition_id
                          + "&amp;index=" + std::to_string(i);
                    html += R"("></div>)";
                }
                html += "</div>";
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- GET /fragments/create-group-form -------------------------------------
    sink.Get("/fragments/create-group-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                // Flat ManagementGroup:Write admission stays until ADR-0017
                // PR-B; management-group-scoped Response:Read is applied only
                // as a filter below and does not compose into this gate
                // (auth_routes.hpp).
                if (!perm_fn_(req, res, "ManagementGroup", "Write")) return;
                auto session = auth_fn_(req, res);
                if (!session) return;

                auto command_id = req.get_param_value("command_id");
                auto plugin = req.get_param_value("plugin");
                auto filters = parse_filters(req, plugin);
                // JIT-elevated: full-fleet view, not a username-derived RBAC
                // re-check that can't see the session's live elevation (see
                // render_filter_bar's identical comment).
                auto agent_scope = resolve_visible_scope(*session);

                // nullopt (unwired store, or filters.empty() with no store
                // call attempted) renders the same as a genuine store
                // degrade — #2691 finding #7 is specifically that a REAL
                // degrade must not render as "0 agents", not that the
                // no-store/no-filter cases need a NEW distinction from it.
                std::optional<int64_t> agent_count;
                if (response_store_ && !filters.empty())
                    agent_count = response_store_->facet_agent_count(command_id, filters,
                                                                      agent_scope);
                else if (filters.empty())
                    agent_count = 0; // genuine: no filter → no scoped count

                auto html = render_create_group_form(command_id, plugin, filters,
                                                      agent_count);
                // Same cross-operator shared-cache concern as filter-bar above.
                res.set_header("Cache-Control", "no-store, private");
                res.set_header("Vary", "Cookie");
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- POST /api/dashboard/group-from-results -------------------------------
    sink.Post("/api/dashboard/group-from-results",
             [this](const httplib::Request& req, httplib::Response& res) {
                 // Flat ManagementGroup:Write admission stays until ADR-0017
                 // PR-B; management-group-scoped Response:Read is applied only
                 // as a filter below and does not compose into this gate
                 // (auth_routes.hpp).
                 if (!perm_fn_(req, res, "ManagementGroup", "Write")) return;
                 auto session = auth_fn_(req, res);
                 if (!session) return;

                 // CSRF same-site gate (parity with the TAR re-enable/purge
                 // fragments; defense-in-depth on top of SameSite=Lax, which
                 // does not stop a same-site sibling origin). This route
                 // materialises management-group membership and had no such
                 // gate — pre-existing gap, closed here.
                 {
                     const std::string origin = req.get_header_value("Origin");
                     const std::string referer = req.get_header_value("Referer");
                     const bool same_site =
                         !(origin.empty() && referer.empty()) &&
                         origin_is_same_site(req.get_header_value("Host"), origin, referer,
                                             csrf_trusted_origins_);
                     if (!same_site) {
                         audit_fn_(req, "group.create_from_results", "denied",
                                   "ManagementGroup", "", "csrf_cross_origin");
                         res.status = 403;
                         res.set_header("HX-Retarget", "#group-form-slot");
                         res.set_content(
                             "<span class=\"feedback-error\">Cross-origin request refused.</span>",
                             "text/html; charset=utf-8");
                         return;
                     }
                 }

                 auto group_name = extract_form_value(req.body, "group_name");
                 auto command_id = extract_form_value(req.body, "command_id");
                 auto plugin = extract_form_value(req.body, "plugin");

                 if (group_name.empty()) {
                     res.status = 400;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">Group name is required.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Reconstruct filters from form
                 auto filters = parse_filters(req, plugin);

                 if (!response_store_ || !mgmt_group_store_) {
                     res.status = 500;
                     res.set_content(
                         "<span class=\"feedback-error\">Server not configured.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Get matching agent IDs from faceted index. #2691 (Doomgoose
                 // finding #7): a degraded read must not read as "no agents
                 // match" — that's a wrong-result-presented-as-correct claim on
                 // a write-adjacent action (it would tell the operator their
                 // filters are bad when the store just couldn't be read).
                 auto agent_ids_opt = response_store_->facet_agent_ids(command_id, filters);
                 if (!agent_ids_opt.has_value()) {
                     res.status = 503;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "Agent count unavailable — the response store could not be read. "
                         "Retry shortly.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }
                 auto& agent_ids = *agent_ids_opt;

                 // D2: intersect against the caller's Response:Read-visible
                 // scope before the empty check — the raw (unscoped) list
                 // never reaches the caller, and an all-dropped result falls
                 // straight into the pre-existing 422 below rather than a
                 // bespoke error. JIT-elevated: full-fleet view (see
                 // render_filter_bar's identical comment).
                 auto agent_scope = resolve_visible_scope(*session);
                 if (agent_scope) {
                     std::unordered_set<std::string> scope_set(agent_scope->begin(),
                                                                agent_scope->end());
                     std::size_t before = agent_ids.size();
                     std::erase_if(agent_ids, [&scope_set](const std::string& id) {
                         return !scope_set.contains(id);
                     });
                     std::size_t dropped = before - agent_ids.size();
                     if (dropped > 0) {
                         // target_type "Execution" matches the existing response.read
                         // denied-row convention (server.cpp's aggregate surface), not
                         // "Response" — so SIEM rules filtering on the established
                         // taxonomy see this row too.
                         audit_fn_(req, "response.read", "denied", "Execution", command_id,
                                   "scope_dropped=" + std::to_string(dropped) +
                                       " surface=group_from_results");
                     }
                 }

                 if (agent_ids.empty()) {
                     res.status = 422;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "No agents match the current filters.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Check for duplicate name
                 auto existing = mgmt_group_store_->find_group_by_name(group_name);
                 if (existing) {
                     res.status = 400;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "A group with that name already exists.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Create the static group
                 ManagementGroup mg;
                 mg.name = group_name;
                 mg.description = "Created from filtered results (command " +
                                  command_id + ")";
                 mg.membership_type = "static";
                 mg.created_by = session->username;
                 auto group_result = mgmt_group_store_->create_group(mg);
                 if (!group_result) {
                     res.status = 500;
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "Failed to create group: " +
                         html_escape(group_result.error()) + "</span>",
                         "text/html; charset=utf-8");
                     return;
                 }
                 auto& group_id = *group_result;

                 // Add all matching agents as static members. A partial
                 // failure must not be swallowed — the group already exists
                 // (no rollback), so silently reporting full-count success
                 // would leave the operator with an honestly-under-populated
                 // group and no signal to review it.
                 std::size_t added = 0;
                 std::size_t failed = 0;
                 for (const auto& aid : agent_ids) {
                     if (mgmt_group_store_->add_member(group_id, aid)) {
                         ++added;
                     } else {
                         ++failed;
                     }
                 }

                 if (failed > 0) {
                     audit_fn_(req, "group.create_from_results", "failure",
                              "ManagementGroup", group_id,
                              "partial_materialisation added=" + std::to_string(added) +
                                  " failed=" + std::to_string(failed));
                     res.status = 500;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">Group '" + html_escape(group_name) +
                             "' was created but only " + std::to_string(added) + " of " +
                             std::to_string(agent_ids.size()) +
                             " agents could be added. Review the group's membership before "
                             "use.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 audit_fn_(req, "group.create_from_results", "success",
                          "ManagementGroup", group_id,
                          group_name + " (" + std::to_string(agent_ids.size()) +
                              " agents from " + command_id + ")");

                 // Response: no body, side-effects via HX-Trigger headers
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":"Group ')" +
                     html_escape(group_name) + "' created with " +
                     std::to_string(agent_ids.size()) +
                     R"( agents","level":"success"},"agentChanged":true})");
                 res.set_content("", "text/html; charset=utf-8");
             });

    // -- POST /api/dashboard/execute — HTMX-native instruction dispatch --------
    sink.Post("/api/dashboard/execute",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Execution", "Execute")) return;

                 auto instruction = extract_form_value(req.body, "instruction");

                 // CDX-P1-01: read the DECODED param first (httplib percent-decodes
                 // both keys and values when it parses an
                 // application/x-www-form-urlencoded body into req.params), falling
                 // back to the raw-body helper only for a non-form Content-Type
                 // httplib does not parse into req.params (UP-10). A raw-byte scan
                 // alone (the prior form of this line) cannot see a percent-encoded
                 // field NAME — e.g. `sc%6fpe=` decodes to `scope` in req.params but
                 // never matches the literal `scope=` needle `extract_form_value`
                 // scans for — so encoding the key name reopened exactly the
                 // supplied-vs-omitted collapse CDX-R8-01 closed. Mirrors
                 // tar-execute's identical fix below.
                 auto scope = req.get_param_value("scope");
                 if (scope.empty())
                     scope = extract_form_value(req.body, "scope");

                 if (instruction.empty()) {
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">"
                         "No instruction entered.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Parse CLI-style key=value parameters from instruction text
                 auto [command_text, inline_params] = parse_instruction_params(instruction);

                 // Handle built-in "help" command — render directly
                 auto lower_cmd = command_text;
                 for (auto& c : lower_cmd) c = static_cast<char>(std::tolower(c));
                 if (lower_cmd == "help" || lower_cmd.starts_with("help ")) {
                     std::string filter;
                     if (lower_cmd.size() > 5)
                         filter = lower_cmd.substr(5);

                     // Get help content — contains <tr> rows then OOB elements.
                     // Extract only the <tr> rows (everything up to the first
                     // <span or <thead OOB tag) for the tbody swap.
                     auto full = registry_->help_html(filter);
                     auto oob_start = full.find("<span ");
                     std::string rows_only = (oob_start != std::string::npos)
                                                 ? full.substr(0, oob_start)
                                                 : full;
                     // Count rows (each data row is a <tr class="result-row">)
                     int row_count = 0;
                     for (size_t p = 0; (p = rows_only.find("result-row", p)) != std::string::npos; ++p)
                         ++row_count;

                     std::string context = filter.empty() ? "help \u2014 all plugins"
                                                           : "help " + html_escape(filter);

                     // Build OOB response — each element is a standalone OOB swap
                     std::string html;
                     html += "<thead id=\"results-thead\" hx-swap-oob=\"innerHTML\">"
                             "<tr><th class=\"col-agent\">Plugin</th>"
                             "<th>Action</th><th>Description</th></tr></thead>";
                     html += "<tbody id=\"results-tbody\" hx-swap-oob=\"innerHTML\">"
                             + rows_only + "</tbody>";
                     html += "<span id=\"result-context\" hx-swap-oob=\"true\""
                             " style=\"font-size:0.75rem;color:#8b949e\">"
                             + html_escape(context) + "</span>";
                     html += "<strong id=\"row-count\" hx-swap-oob=\"true\">"
                             + std::to_string(row_count) + "</strong>";
                     // Clear filter bar and pagination for help display
                     html += "<div id=\"filter-bar\" hx-swap-oob=\"innerHTML\"></div>";
                     html += "<nav id=\"result-pagination\" hx-swap-oob=\"innerHTML\"></nav>";
                     html += "<div id=\"result-summary\" hx-swap-oob=\"innerHTML\"></div>";
                     html += "<div id=\"group-form-slot\" hx-swap-oob=\"innerHTML\"></div>";
                     // Clear any chart deck from a prior query — help is
                     // a no-chart command so any lingering deck would
                     // overlay the help table. The hx-on::before-request
                     // JS hook on #instr-form clears it client-side too;
                     // this OOB swap is defence-in-depth so a future
                     // refactor of the form-handler attribute can't
                     // silently leave stale charts on the page.
                     html += "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\"></div>";
                     res.set_content(html, "text/html; charset=utf-8");
                     return;
                 }

                 // Resolve instruction text → plugin/action
                 auto [plugin, action] = resolve_fn_(lower_cmd);
                 if (plugin.empty()) {
                     // Defensive: clear any chart deck from a prior
                     // query so the unknown-command banner isn't
                     // overlaid on a stale chart.
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:var(--mds-color-theme-indicator-error)\">"
                         "Unknown command: &quot;" + html_escape(instruction) +
                         "&quot;. Type &quot;help&quot; to list all commands.</span>"
                         "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\"></div>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Issue #587: reverse-lookup an InstructionDefinition that
                 // matches (plugin, action) AND either has a
                 // spec.visualization OR a non-empty result_schema. When
                 // found, propagate the definition_id through the
                 // result-render flow so the chart deck renders inline
                 // (visualization match) and/or render_results resolves
                 // per-action columns via resolve_render_columns
                 // (result_schema match, PR1.7 remediation) instead of
                 // falling back to columns_for_plugin's fixed per-plugin
                 // schema — the fix for actions like registry's
                 // list_profiles, whose column shape columns_for_plugin
                 // does not know at all. A result_schema-only match still
                 // resolves an empty chart deck (VisualizationEngine::count
                 // is 0 without a visualization_spec), so this is a no-op
                 // for every definition that doesn't also declare charts.
                 //
                 // Closes governance CP-1 / sec-F1 / ER-NEW-2: gate the
                 // reverse-lookup on `InstructionDefinition:Read` so a
                 // principal with `Execution:Execute` but denied
                 // `InstructionDefinition:Read` cannot enumerate definition
                 // IDs via this side channel. The dispatch itself is
                 // already authorised — we only suppress the chart-deck
                 // enrichment, not the command. perm_fn_'s deny path
                 // writes 403 to its res argument, so we hand it a
                 // throwaway Response and discard the side effect.
                 std::string def_id;
                 httplib::Response def_perm_res;
                 bool can_read_defs = perm_fn_(req, def_perm_res,
                                               "InstructionDefinition", "Read");
                 if (can_read_defs && instruction_store_ &&
                     instruction_store_->is_open()) {
                     InstructionQuery q;
                     q.plugin_filter = plugin;
                     q.enabled_only = true;
                     q.limit = 50;
                     // ADR-0058: a DB-error result leaves def_id empty (enrichment
                     // skipped below), same as an empty result did pre-migration.
                     auto defs_result = instruction_store_->query_definitions(q);
                     if (defs_result) {
                         for (const auto& d : *defs_result) {
                             if (d.action != action) continue;
                             if (!VisualizationEngine::has_visualization(d.visualization_spec) &&
                                 d.result_schema.empty())
                                 continue;
                             def_id = d.id;
                             break;
                         }
                     }
                 }

                 // Resolve scope → agent_ids or scope expression.
                 //
                 // CDX-R8-01: a SUPPLIED `scope=` that resolves to nothing is an
                 // ERROR, not a fleet broadcast — `extract_form_value` returns ""
                 // for an absent key and an empty one alike, so the two must be
                 // told apart HERE or they collapse into the same request
                 // (dispatch_target_shape.hpp:14-16). `__all__` is passed THROUGH
                 // as a named broadcast rather than stripped to empty+empty, so
                 // the fleet is reached by NAME, never inferred from emptiness.
                 std::vector<std::string> agent_ids;
                 std::string scope_expr;
                 if (!scope.empty() && scope.starts_with("group:")) {
                     scope_expr = scope;
                 } else if (!scope.empty() && scope != yuzu::server::kBroadcastScope) {
                     agent_ids.push_back(scope);
                 } else if (scope == yuzu::server::kBroadcastScope) {
                     scope_expr = std::string(yuzu::server::kBroadcastScope);
                 } else if (req.has_param("scope") || form_value_supplied(req.body, "scope")) {
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">"
                         "No target selected. Choose agents, or pick All agents "
                         "to reach the fleet.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }
                 // scope omitted entirely → the legacy UI contract: the whole fleet
                 // (still narrowed to the operator's visible set by the seam).

                 // Dispatch with inline CLI parameters. CDX-R7-02: narrow to the
                 // operator's Execution:Execute visible set via the shared
                 // dispatch_confined seam (same confinement as /api/command +
                 // MCP). An UNWIRED derivation fails CLOSED (present-empty set →
                 // reaches nobody), never nullopt/unfiltered.
                 yuzu::server::DispatchCaller caller =
                     caller_fn_ ? caller_fn_(req)
                               : yuzu::server::DispatchCaller{
                                     .exec_visible = yuzu::server::authz::deny_all()};

                 // ── PR6.0b: Destructive-class TARGETING gate ────────────────
                 // The exec console is the third operator-facing surface that
                 // resolves a free-form plugin.action and can fan it out
                 // (`scope=__all__`, `scope=group:<id>`, or `scope` omitted
                 // entirely — the legacy UI contract read a few lines above as
                 // "the whole fleet"). #3685 gated the other two, /api/command
                 // and MCP execute_instruction; this one reaches agents through
                 // ServerImpl::dispatch_confined instead and was left
                 // untargeted-fan-out-capable for every Destructive row that
                 // does not additionally carry ExecuteGate::AdminOrApproval —
                 // tar.purge_source, registry.delete_key, filesystem
                 // .delete_lines, tags.clear, storage.clear and the rest.
                 //
                 // SAME chokepoint, not a copy: evaluate_destructive_targeting
                 // and confine_destructive_targets come from
                 // dispatch_destructive_gate.hpp unchanged, and both refusal
                 // strings are that header's named constants, so this surface
                 // cannot drift from the other two. That header's own doc
                 // comment records why the gate belongs HERE, in route/handler
                 // code, and NOT in the shared dispatch_confined seam (D3: a
                 // scheduled Destructive fire legitimately targets by scope,
                 // and gating the seam would silently kill every one of them).
                 {
                     if (!classify_fn_) {
                         // FAIL-CLOSED, matching McpServer::ClassifyFn's
                         // contract. A silently-unwired classifier would revert
                         // this gate while every other test stayed green — the
                         // ContainmentGate{} class of regression. Production
                         // wires it unconditionally in server.cpp; reaching
                         // this branch on a live request means that regressed.
                         spdlog::error("dashboard execute: capability classifier unwired — "
                                       "refusing dispatch of {}:{} (Destructive targeting "
                                       "cannot be decided)",
                                       plugin, action);
                         audit_fn_(req, "command.dispatch", "denied", "command", "",
                                   "reason=classifier_unavailable " +
                                       onbehalf::sanitize_for_log(plugin, 128) + ":" +
                                       onbehalf::sanitize_for_log(action, 128));
                         res.set_content(
                             "<span id=\"result-context\" hx-swap-oob=\"true\""
                             " style=\"font-size:0.75rem;color:#f85149\">"
                             "Command classification is unavailable. Cannot dispatch.</span>"
                             "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\"></div>",
                             "text/html; charset=utf-8");
                         return;
                     }
                     const auto gate = yuzu::server::evaluate_destructive_targeting(
                         classify_fn_(plugin, action),
                         /*valid_nonempty_agent_ids=*/!agent_ids.empty(),
                         // The handler has already collapsed the supplied-vs-
                         // omitted question above (CDX-R8-01) and turned a
                         // group:/__all__ selection into scope_expr, so this is
                         // the post-validation shape the header's caller
                         // contract requires — never a raw extraction result.
                         /*scope_key_present=*/!scope_expr.empty(),
                         /*agent_id_count=*/agent_ids.size());
                     // Exhaustive, no `default:` — the same switch shape
                     // /api/command and MCP's backstop use over this enum, and
                     // the reason ClassifyMiss is an enumerator rather than a
                     // skippable `if` branch.
                     switch (gate.verdict) {
                     case yuzu::server::DestructiveTargetingVerdict::NotDestructive:
                         // ReadOnly / Mutating: this gate does not apply and
                         // must not narrow anything. Dispatch proceeds byte-
                         // identically to pre-PR6.0b.
                         break;
                     case yuzu::server::DestructiveTargetingVerdict::ClassifyMiss:
                         // Policy B, same as /api/command and MCP's backstop:
                         // fall through to the shared dispatch chokepoint,
                         // which denies a real miss unconditionally with its
                         // own taxonomy, metric and audit shape. An early
                         // denial here would only duplicate — and risk
                         // drifting from — that evidence.
                         break;
                     case yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted: {
                         // Counted on the SAME series as the /api/command and
                         // MCP refusals, with this surface's own `route` label
                         // — not a fourth metric for a third surface, and
                         // deliberately not the `yuzu_server_dispatch_denied
                         // _total` family, which means "classification or
                         // authorization refused this dispatch" and is owned by
                         // build_classified_command. Guarded like both existing
                         // sites: an increment failure must never skip the
                         // audit write or the response below it.
                         if (metrics_) {
                             try {
                                 metrics_
                                     ->counter("yuzu_server_dispatch_target_rejected_total",
                                               {{"route", "dashboard"},
                                                {"reason", std::string(gate.refusal_reason)}})
                                     .increment();
                             } catch (...) { // NOLINT(bugprone-empty-catch)
                             }
                         }
                         // scope_expr is operator-supplied and percent-decoded, so a
                         // %0a would inject a line break into the server log. The
                         // sibling /api/command refusal sanitises its logged fields
                         // for exactly this reason; match it rather than deviate.
                         // Wave 7 PR7.2: this arm now also covers a Forensics
                         // single-target refusal (reason=forensic_untargeted).
                         spdlog::warn("dashboard execute: refusing {}:{} — {} "
                                      "(scope='{}')",
                                      plugin, action, gate.refusal_reason,
                                      onbehalf::sanitize_for_log(scope_expr, 128));
                         // Audited under this surface's own command.dispatch
                         // verb, with the same `reason=` detail prefix
                         // /api/command's twin refusal writes.
                         audit_fn_(req, "command.dispatch", "denied", "command", "",
                                   "reason=" + std::string(gate.refusal_reason) + " " +
                                       onbehalf::sanitize_for_log(plugin, 128) + ":" +
                                       onbehalf::sanitize_for_log(action, 128));
                         // In-surface denial shape: every other refusal in this
                         // handler is a 200 carrying an OOB result-context
                         // span, because the caller is htmx swapping fragments
                         // into a live page — a 4xx with a JSON envelope would
                         // leave the console silent. The chart-deck clear
                         // mirrors the unknown-command arm above.
                         res.set_content(
                             "<span id=\"result-context\" hx-swap-oob=\"true\""
                             " style=\"font-size:0.75rem;color:#f85149\">" +
                                 html_escape(std::string(gate.refusal_message)) +
                                 "</span>"
                                 "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\"></div>",
                             "text/html; charset=utf-8");
                         return;
                     }
                     case yuzu::server::DestructiveTargetingVerdict::Targeted: {
                         // Confine to the operator's visible agents, exactly as
                         // /api/command does. DestructiveVisibleAgents' nullopt
                         // means FAIL-CLOSED (deny-all) — the OPPOSITE of
                         // authz::VisibleSet's nullopt; the explicit
                         // constructor is what forces this call site to say so.
                         // An absent store or an ADR-0042-degraded read
                         // therefore empties the list rather than widening it.
                         std::optional<std::vector<std::string>> vis;
                         if (mgmt_group_store_)
                             vis = mgmt_group_store_->get_visible_agents(caller.principal);
                         // Kept for the refusal log below: confinement
                         // overwrites agent_ids, so the requested set is
                         // otherwise unrecoverable by the time we know it was
                         // emptied.
                         const std::vector<std::string> requested_ids = agent_ids;
                         agent_ids = yuzu::server::confine_destructive_targets(
                             agent_ids, yuzu::server::DestructiveVisibleAgents{std::move(vis)});
                         if (agent_ids.empty()) {
                             // /api/command answers 404 here; this surface
                             // answers in its own idiom for the reason given in
                             // the RefuseUntargeted arm. Audited as a scope
                             // violation, matching the sibling destructive
                             // fragment (tar retention-paused purge) — as of
                             // #2557's fix #5, /api/command now ALSO audits
                             // and counts this arm (it previously audited
                             // nothing here) — an operator dropped by
                             // confinement is exactly the event an incident
                             // review looks for.
                             // Log the requested target. Without this the
                             // agent an operator actually asked for is in
                             // NEITHER channel on this arm: the audit row
                             // carries an empty target_id, and the only other
                             // gate-arm log (the RefuseUntargeted warn above)
                             // records scope_expr, which is empty precisely
                             // when the caller named one explicit agent. An
                             // incident responder reconstructing the attempted
                             // blast radius of a refused Destructive dispatch
                             // would find nothing and could reasonably read the
                             // absence as log loss or tampering. Sanitised and
                             // capped because these ids ARE operator-supplied:
                             // `scope` comes straight off the request. (The
                             // sibling arms above log `plugin`/`action` raw and
                             // sanitise only `scope_expr` -- correct there,
                             // because those two are resolved against the
                             // registry's help_json and cannot carry request
                             // bytes. Do not read those as the convention for
                             // an operator-supplied value.)
                             std::string requested;
                             for (const auto& id : requested_ids) {
                                 if (!requested.empty()) requested += ",";
                                 requested += onbehalf::sanitize_for_log(id, 128);
                             }
                             spdlog::warn(
                                 "dashboard execute: destructive '{}:{}' refused -- none of the "
                                 "requested agents [{}] are in the caller's visible set",
                                 onbehalf::sanitize_for_log(plugin, 128),
                                 onbehalf::sanitize_for_log(action, 128), requested);
                             audit_fn_(req, "command.dispatch", "denied", "command", "",
                                       "reason=scope_violation " +
                                           onbehalf::sanitize_for_log(plugin, 128) + ":" +
                                           onbehalf::sanitize_for_log(action, 128));
                             res.set_content(
                                 "<span id=\"result-context\" hx-swap-oob=\"true\""
                                 " style=\"font-size:0.75rem;color:#f85149\">" +
                                     html_escape(std::string(
                                         yuzu::server::kDestructiveNoVisibleAgentMessage)) +
                                     "</span>"
                                     "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\">"
                                     "</div>",
                                 "text/html; charset=utf-8");
                             return;
                         }
                         break;
                     }
                     }
                 }

                 auto dispatch_outcome =
                     dispatch_fn_(plugin, action, agent_ids, scope_expr, inline_params, caller);
                 auto& command_id = dispatch_outcome.command_id;
                 auto& sent = dispatch_outcome.sent;
                 if (sent == 0) {
                     // #3424/#3511: don't blame connectivity for a fail-closed
                     // containment gate, a quarantine denial, or a withheld
                     // plugin-absent dispatch — same discrimination /api/command
                     // already surfaces, so the operator reading THIS console
                     // isn't pointed at the wrong remediation.
                     const char* message = "No agents connected. Cannot dispatch command.";
                     if (dispatch_outcome.scope_parse_error) {
                         // #3424/#3511 PR review fix round: this console
                         // accepts a scope expression (scope_expr, above)
                         // and reaches the same ConfinedDispatchOutcome
                         // scope_parse_error field mcp_server.cpp's
                         // execute_instruction reads -- checked first, same
                         // as there, since a malformed expression is a
                         // caller error, not a fleet-state fact.
                         message = "Invalid scope expression -- dispatch was not attempted. "
                                    "Fix the expression and resubmit; retrying unchanged will "
                                    "not help.";
                     } else if (dispatch_outcome.containment_unreadable) {
                         message = "Containment state is unreadable — dispatch is failing "
                                    "closed and reaching no agent; check the quarantine store.";
                     } else if (dispatch_outcome.route_unreadable) {
                         // WS-4 4.2b Task D: the exact sibling of the
                         // containment branch above — a degraded gateway
                         // routing-directory read, not a per-target fact.
                         message = "The gateway routing directory could not be read for one "
                                    "or more targets — dispatch is failing closed rather than "
                                    "guessing where to route.";
                     } else if (dispatch_outcome.denied_quarantined_count > 0) {
                         message = "Every target is quarantined — dispatch was withheld, "
                                    "not attempted.";
                     } else if (dispatch_outcome.unknown_plugin_count > 0) {
                         message = "The dispatched plugin is not in any target's reported "
                                    "inventory — dispatch was withheld, not attempted.";
                     }
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">" +
                             html_escape(message) + "</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Success: return OOB swaps for the results area. Uses the
                 // same schema-aware resolution as render_results (PR1.7
                 // remediation) so a schema-only action's initial thead
                 // matches what the 2s-later chart-deck-host refresh
                 // renders, instead of flashing columns_for_plugin's
                 // fallback shape first.
                 auto col_names = resolve_render_columns(plugin, def_id);

                 std::string html;
                 html.reserve(4096);

                 // OOB: thead with column headers
                 html += "<thead id=\"results-thead\" hx-swap-oob=\"true\"><tr>";
                 for (size_t i = 0; i < col_names.size(); ++i) {
                     html += (i == 0) ? "<th class=\"col-agent\">" : "<th>";
                     html += html_escape(col_names[i]);
                     html += "</th>";
                 }
                 html += "</tr></thead>";

                 // tbody is cleared via the SSE command-status:RUNNING
                 // event (published by the DispatchFn before this POST
                 // response returns).  Clearing it here would race with
                 // SSE output events — fast agents respond before the
                 // browser receives this POST reply, so an innerHTML OOB
                 // here would wipe already-displayed result rows.

                 // Status badge and row count are set by the SSE
                 // command-status:RUNNING event (no OOB here — it
                 // would race with SSE updates from fast agents).

                 // OOB: result context (only set here, no SSE race)
                 html += "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#8b949e\">" +
                         html_escape(instruction) + " &rarr; " +
                         std::to_string(sent) + " agent" +
                         (sent != 1 ? "s" : "") + "</span>";

                 // OOB: filter bar — initially empty, self-refreshes after
                 // results arrive (facets are stored when agent responds,
                 // which is after this HTTP response returns).
                 // Issue #587: include definition_id when known so the
                 // re-fetched filter bar emits it as a hidden input and
                 // every subsequent /fragments/results call carries it,
                 // which keeps the chart deck rendered as filters change.
                 html += "<div id=\"filter-bar\" hx-swap-oob=\"true\""
                         " hx-get=\"/fragments/results/filter-bar?command_id=" +
                         html_escape(command_id) + "&amp;plugin=" + html_escape(plugin);
                 if (!def_id.empty())
                     html += "&amp;definition_id=" + html_escape(def_id);
                 html += "\" hx-trigger=\"load delay:2s\" hx-swap=\"outerHTML\"></div>";

                 // OOB: chart deck — empty initially, self-refreshes once
                 // responses are in. Same delay window as the filter bar.
                 // Without this, the deck only appears after the operator
                 // touches a filter; users expect the chart to render as
                 // soon as the data arrives. `hx-swap-oob="true"` replaces
                 // the whole element (outerHTML) so the new hx-get /
                 // hx-trigger attributes attach; `innerHTML` would lose
                 // them.
                 if (!def_id.empty()) {
                     html += "<div id=\"chart-deck-host\" hx-swap-oob=\"true\""
                             " hx-get=\"/fragments/results?command_id=" +
                             html_escape(command_id) + "&amp;plugin=" + html_escape(plugin) +
                             "&amp;definition_id=" + html_escape(def_id) +
                             "\" hx-trigger=\"load delay:2s\" hx-swap=\"none\"></div>";
                 } else {
                     // Clear any deck left over from a prior command.
                     html += "<div id=\"chart-deck-host\" hx-swap-oob=\"true\"></div>";
                 }

                 // OOB: clear pagination and summary
                 html += "<nav id=\"result-pagination\" hx-swap-oob=\"true\"></nav>";
                 html += "<div id=\"result-summary\" hx-swap-oob=\"true\"></div>";
                 html += "<div id=\"group-form-slot\" hx-swap-oob=\"true\"></div>";

                 // Toast via HX-Trigger
                 res.set_header("HX-Trigger",
                     "{\"showToast\":{\"message\":\"Command sent to " +
                     std::to_string(sent) +
                     " agent(s)\",\"level\":\"success\"}}");

                 // Closes governance CP-2 / C-16: append definition_id when
                 // the reverse-lookup resolved one, so SIEM correlation
                 // between command.dispatch and execution.visualization.fetch
                 // (2s later) is traceable by definition.
                 std::string detail =
                     plugin + ":" + action + " -> " + std::to_string(sent) + " agent(s)";
                 if (!def_id.empty())
                     detail += " definition_id=" + def_id;
                 audit_fn_(req, "command.dispatch", "success", "command", command_id, detail);

                 res.set_content(html, "text/html; charset=utf-8");
             });

    // -- POST /api/dashboard/tar-execute (TAR warehouse SQL query) -------------
    sink.Post("/api/dashboard/tar-execute",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Execution", "Execute")) return;

                 auto sql = req.get_param_value("sql");
                 if (sql.empty()) {
                     res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                     " style=\"font-size:0.75rem;color:#f85149\">"
                                     "Missing SQL query.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 // M5: Server-side SQL validation with keyword blocklist (defense in depth)
                 if (sql.size() > 4096) {
                     res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                     " style=\"font-size:0.75rem;color:#f85149\">"
                                     "SQL query exceeds 4KB limit.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }
                 {
                     auto upper = sql;
                     for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                     size_t start = upper.find_first_not_of(" \t\r\n");
                     if (start == std::string::npos || !upper.substr(start).starts_with("SELECT")) {
                         res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                         " style=\"font-size:0.75rem;color:#f85149\">"
                                         "Only SELECT queries are allowed.</span>",
                                         "text/html; charset=utf-8");
                         return;
                     }
                     // Block dangerous keywords server-side too
                     static const char* blocked[] = {
                         "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
                         "ATTACH", "DETACH", "PRAGMA", "LOAD_EXTENSION", nullptr
                     };
                     for (auto kw = blocked; *kw; ++kw) {
                         if (upper.find(*kw) != std::string::npos) {
                             res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                             " style=\"font-size:0.75rem;color:#f85149\">"
                                             "Query contains forbidden keyword.</span>",
                                             "text/html; charset=utf-8");
                             return;
                         }
                     }
                 }

                 // CDX-R8-01, the TAR sibling of the execute route above: tell a
                 // SUPPLIED-but-empty `scope=` apart from an omitted one, and pass
                 // `__all__` through by NAME instead of stripping it to empty+empty.
                 //
                 // UP-10: req.has_param()/get_param_value() only see the query
                 // string or a body httplib parsed into req.params — which happens
                 // ONLY for an `application/x-www-form-urlencoded` Content-Type. A
                 // non-form POST leaves a body-supplied `scope=` invisible to both,
                 // so the refusal below was silently skippable by sending any other
                 // Content-Type. Fall back to reading the raw body directly (the
                 // same form_value_supplied/extract_form_value the execute route
                 // above uses), which is Content-Type-independent.
                 auto scope = req.get_param_value("scope");
                 if (scope.empty())
                     scope = extract_form_value(req.body, "scope");
                 std::vector<std::string> agent_ids;
                 std::string scope_expr;
                 if (!scope.empty() && scope.starts_with("group:")) {
                     scope_expr = scope;
                 } else if (!scope.empty() && scope != yuzu::server::kBroadcastScope) {
                     agent_ids.push_back(scope);
                 } else if (scope == yuzu::server::kBroadcastScope) {
                     scope_expr = std::string(yuzu::server::kBroadcastScope);
                 } else if (req.has_param("scope") || form_value_supplied(req.body, "scope")) {
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">"
                         "No target selected. Choose agents, or pick All agents "
                         "to reach the fleet.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 std::unordered_map<std::string, std::string> params;
                 params["sql"] = sql;
                 // CDX-R7-02: same confinement as /api/dashboard/execute — narrow
                 // to the operator's visible set, fail CLOSED if unwired.
                 yuzu::server::DispatchCaller caller =
                     caller_fn_ ? caller_fn_(req)
                               : yuzu::server::DispatchCaller{
                                     .exec_visible = yuzu::server::authz::deny_all()};
                 auto dispatch_outcome =
                     dispatch_fn_("tar", "sql", agent_ids, scope_expr, params, caller);
                 auto& command_id = dispatch_outcome.command_id;
                 auto& sent = dispatch_outcome.sent;

                 if (sent == 0) {
                     res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                     " style=\"font-size:0.75rem;color:#f85149\">"
                                     "No agents connected.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 // Success: return OOB swaps for the results area
                 std::string html;
                 html += "<thead id=\"results-thead\" hx-swap-oob=\"innerHTML\">"
                         "<tr><th class=\"col-agent\">Agent</th>"
                         "<th>Waiting for schema...</th></tr></thead>";
                 html += "<tbody id=\"results-tbody\" hx-swap-oob=\"innerHTML\">"
                         "<tr id=\"empty-row\"><td colspan=\"99\" style=\"text-align:center;"
                         "color:#8b949e;padding:2rem 0\">"
                         "Waiting for results...</td></tr></tbody>";
                 html += "<span id=\"status-badge\" class=\"badge-running\""
                         " hx-swap-oob=\"outerHTML\">RUNNING</span>";
                 html += "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#8b949e\">TAR SQL &rarr; " +
                         std::to_string(sent) + " agent" +
                         (sent != 1 ? "s" : "") + "</span>";
                 html += "<strong id=\"row-count\" hx-swap-oob=\"true\">0</strong>";
                 html += "<nav id=\"result-pagination\" hx-swap-oob=\"true\"></nav>";
                 html += "<div id=\"result-summary\" hx-swap-oob=\"true\"></div>";

                 res.set_header("HX-Trigger",
                     "{\"showToast\":{\"message\":\"TAR query sent to " +
                     std::to_string(sent) +
                     " agent(s)\",\"level\":\"success\"}}");

                 audit_fn_(req, "tar.sql", "success", "command", command_id,
                          "TAR SQL -> " + std::to_string(sent) + " agent(s)");

                 res.set_content(html, "text/html; charset=utf-8");
             });

    // -- GET /fragments/scope-list (enhanced with groups) ----------------------
    sink.Get("/fragments/scope-list",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Infrastructure", "Read")) return;
                auto session = auth_fn_(req, res);
                if (!session) return;

                std::string selected = req.get_param_value("selected");
                if (selected.empty()) selected = "__all__";

                auto html = render_scope_list(selected, session->username);
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- TAR retention-paused source list (Phase 15.A — issue #547) -----------
    //
    // GET renders the table for the calling operator from THEIR most-recent
    // tar.status scan (per-username state); POST dispatches a fresh scan
    // **scoped to the operator's visible agents** and records the new
    // command_id under the username key. Both routes filter rendered
    // responses by the operator's visible agent set so an operator without
    // visibility on a device cannot see its TAR config even via cached
    // scan results.
    //
    // Permission tiers (after Gate 2 hardening):
    //   GET  scan list      → Infrastructure:Read   (read-only render)
    //   POST scan dispatch  → Execution:Execute     (dispatches commands)
    //   POST reenable       → Execution:Execute     (mutates agent state)
    //
    // The two routes are deliberately separate (rather than one auto-fetch
    // route) so an operator viewing the page does not silently re-scan the
    // fleet on every page load — the dispatch is an explicit operator action,
    // surfaced in the audit trail.

    sink.Get("/fragments/tar/retention-paused",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Infrastructure", "Read")) {
                    if (metrics_) {
                        metrics_->counter("yuzu_tar_dashboard_view_total",
                                          {{"frame", "retention"},
                                           {"result", "denied"}}).increment();
                    }
                    return;
                }
                auto session = auth_fn_(req, res);
                if (!session) return;
                // Per-operator scoped data — must not be cached by any
                // shared upstream proxy. UP-11 from Gate 4 unhappy-path:
                // a corporate proxy honoring default text/html caching
                // would re-replay one operator's filtered, visibility-
                // scoped table to a different operator on a shared
                // session-less URL.
                res.set_header("Cache-Control", "no-store, private");
                res.set_header("Vary", "Cookie");
                // Probe effective permissions WITHOUT mutating the real response
                // (perm_fn_ writes a 403 into whatever Response it's handed on
                // denial — feed it a throwaway, same pattern as the def-perm probe
                // at ~line 637). Gates which row actions render: Re-enable needs
                // Execution:Execute, Purge needs the higher Infrastructure:Delete.
                httplib::Response perm_probe;
                bool can_execute = perm_fn_(req, perm_probe, "Execution", "Execute");
                bool can_delete = perm_fn_(req, perm_probe, "Infrastructure", "Delete");
                res.set_content(
                    render_tar_retention_paused(session->username, can_execute, can_delete),
                    "text/html; charset=utf-8");
                if (metrics_) {
                    metrics_->counter("yuzu_tar_dashboard_view_total",
                                      {{"frame", "retention"},
                                       {"result", "success"}}).increment();
                }
            });

    // -- REST v1 twin: same per-operator scan/paused-source list, JSON (#4027).
    // Per-operator-scoped Cache-Control posture as the fragment above;
    // unaudited on the success path — scan/config metadata, not per-device
    // behavioral content (matches this fragment's own today-unaudited posture; see
    // docs/api-twin-recipe.md's list_software_deployments worked example for the
    // same "metadata, not behavioral PII" reasoning).
    //
    // #4027 fix round (CDX-P1-01/K4): gate migrated from bare perm_fn_
    // (require_permission — a GLOBAL grant check that 403s a management-group
    // -scoped Infrastructure:Read holder before gather_tar_retention_paused
    // ever runs) to fleet_read_fn_ (require_fleet_read, the ADR-0017
    // admit-then-filter chokepoint) — same seam this class already wires for
    // /fragments/results above. The explicit service-scoped-token 403 BELOW is
    // deliberately kept even though fleet_read_fn_ would otherwise admit a
    // correctly-confined service-scoped caller here: this route previously
    // denied EVERY service-scoped token outright (perm_fn_'s empty
    // kServiceScopeGlobalSafe default-deny), matching this tool's own
    // list_tar_retention_paused MCP twin (C8 ServiceScopeClass::denied) and the
    // two REST device-picker twins (deny_fleet_wide_device_enumeration) — this
    // fix round repairs the management-group-scope gap, not a decision to
    // widen service-token access on this one surface while its twins stay
    // denied.
    sink.Get("/api/v1/tar/retention-paused",
            [this](const httplib::Request& req, httplib::Response& res) {
                const auto cid = detail::make_correlation_id();
                res.set_header("X-Correlation-Id", cid);
                auto session = auth_fn_(req, res);
                if (!session) return; // auth_fn_ already wrote the A4 401 body
                if (!session->token_scope_service.empty()) {
                    // #4027 fix round 2 (adversarial review CDX-P2-08): the
                    // gate this replaced (perm_fn_/require_permission) audited
                    // this exact denial via AuthRoutes::audit_log (its
                    // service-scope default-deny branch, auth_routes.cpp). This
                    // explicit check must not silently drop that durable
                    // evidence row — a metric alone carries no principal/request
                    // detail and cannot serve as audit evidence.
                    res.status = 403;
                    res.set_content(
                        detail::a4_denial(
                            res, 403,
                            "service-scoped tokens may not read the fleet-wide retention scan"),
                        "application/json");
                    audit_fn_(req, "tar.retention_paused.view", "denied", "Infrastructure", "",
                             "service-scoped token denied fleet-wide retention scan read");
                    if (metrics_) {
                        metrics_->counter("yuzu_tar_dashboard_view_total",
                                          {{"frame", "retention_rest"},
                                           {"result", "denied"}}).increment();
                    }
                    return;
                }
                if (!fleet_read_fn_) {
                    spdlog::error("tar.retention_paused: fleet_read_fn_ unwired — "
                                  "misconfigured call site; failing closed; cid={}", cid);
                    res.status = 503;
                    res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                                    "application/json");
                    return;
                }
                auto gate = fleet_read_fn_(req, res, "Infrastructure", "Read");
                if (!gate.admitted) {
                    if (metrics_) {
                        metrics_->counter("yuzu_tar_dashboard_view_total",
                                          {{"frame", "retention_rest"},
                                           {"result", "denied"}}).increment();
                    }
                    return; // gate already wrote the A4 error body + status
                }
                // Per-operator scoped data — see the fragment route's UP-11 comment.
                res.set_header("Cache-Control", "no-store, private");
                res.set_header("Vary", "Cookie");
                // #4143 review fix: gate.scope is authoritative here — see
                // gather_tar_retention_paused's doc comment.
                const TarRetentionPausedScan scan = gather_tar_retention_paused(
                    session->username, gate.scope, /*extra_scope_is_authoritative=*/true);
                res.set_content(
                    std::string("{\"data\":") + tar_retention_paused_json(scan) +
                        ",\"meta\":{\"api_version\":\"v1\"}}",
                    "application/json");
                if (metrics_) {
                    metrics_->counter("yuzu_tar_dashboard_view_total",
                                      {{"frame", "retention_rest"},
                                       {"result", "success"}}).increment();
                }
            });

    sink.Post("/fragments/tar/retention-paused/scan",
             [this](const httplib::Request& req, httplib::Response& res) {
                 // Dispatching a command to the fleet is an Execute action,
                 // not a Read. Sibling dispatch handlers (`run-instruction`,
                 // `tar-execute`) all gate on Execution:Execute — match.
                 if (!perm_fn_(req, res, "Execution", "Execute")) {
                     // Compliance F1: emit a denied audit row so SIEM rules
                     // alerting on RBAC-rejection probing have a data source.
                     // Without this, the audit catalog overclaims coverage.
                     audit_fn_(req, "tar.status.scan", "denied", "command",
                              "", "rbac_denied");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_scan_dispatched_total",
                                           {{"result", "denied"}}).increment();
                     }
                     return;
                 }
                 auto session = auth_fn_(req, res);
                 if (!session) return;
                 if (!dispatch_fn_) {
                     res.status = 503;
                     res.set_content("<div class=\"empty-state\">Dispatch "
                                     "unavailable.</div>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 // sre CAP-1: per-operator 30-second scan cooldown to defend
                 // against an operator (or compromised session) clicking Scan
                 // in a tight loop and storming the fleet with tar.status
                 // RPCs. Uses the already-stored dispatched_at field; no new
                 // state needed.
                 constexpr int64_t kScanCooldownSec = 30;
                 {
                     std::lock_guard<std::mutex> lk(tar_scan_mu_);
                     auto it = tar_scans_by_user_.find(session->username);
                     if (it != tar_scans_by_user_.end()) {
                         auto since = now_epoch() - it->second.dispatched_at;
                         if (since < kScanCooldownSec) {
                             res.status = 429;
                             res.set_header("Retry-After",
                                 std::to_string(kScanCooldownSec - since));
                             res.set_content(std::format(
                                 "<div class=\"empty-state\">Please wait "
                                 "<strong>{}</strong> second{} before "
                                 "scanning again.</div>",
                                 kScanCooldownSec - since,
                                 (kScanCooldownSec - since) == 1 ? "" : "s"),
                                 "text/html; charset=utf-8");
                             audit_fn_(req, "tar.status.scan", "denied",
                                      "command", "",
                                      std::format("rate_limited cooldown={}s",
                                                   kScanCooldownSec - since));
                             if (metrics_) {
                                 metrics_->counter(
                                     "yuzu_tar_scan_dispatched_total",
                                     {{"result", "rate_limited"}}).increment();
                             }
                             return;
                         }
                     }
                 }

                 // Scope dispatch to the operator's visible agents only —
                 // never fan out to devices the operator cannot see.
                 // Empty visible set = nobody to scan; return early.
                 // ADR-0042: get_visible_agents is degrade-distinguishable —
                 // nullopt (store degraded) is treated as an empty visible set
                 // (fail-closed: scan nobody rather than fan out un-scoped).
                 std::vector<std::string> agent_ids;
                 if (mgmt_group_store_) {
                     if (auto vis = mgmt_group_store_->get_visible_agents(session->username))
                         agent_ids = std::move(*vis);
                 }
                 if (agent_ids.empty()) {
                     res.set_content(
                         "<div class=\"empty-state\">You have no agents "
                         "in scope to scan. Check your management-group "
                         "role assignments.</div>",
                         "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_scan_dispatched_total",
                                           {{"result", "no_visible_agents"}}).increment();
                     }
                     return;
                 }

                 std::unordered_map<std::string, std::string> params;
                 // CDX-R7-02: this TAR scan already narrows `agent_ids` by
                 // management-group (username) visibility above; ALSO narrow to
                 // the caller's Execution:Execute visible set via the shared
                 // dispatch_confined seam, so a service-scoped token cannot scan
                 // an out-of-service device its username visibility would admit.
                 // Fail CLOSED (present-empty) if the derivation is unwired.
                 yuzu::server::DispatchCaller caller =
                     caller_fn_ ? caller_fn_(req)
                               : yuzu::server::DispatchCaller{
                                     .exec_visible = yuzu::server::authz::deny_all()};
                 auto dispatch_outcome = dispatch_fn_(
                     "tar", "status", agent_ids, /*scope_expr=*/"", params, caller);
                 auto& command_id = dispatch_outcome.command_id;
                 auto& sent = dispatch_outcome.sent;

                 {
                     std::lock_guard<std::mutex> lk(tar_scan_mu_);
                     // Bounded LRU: drop the oldest entry by dispatched_at if
                     // we'd exceed the cap. Keeps memory bounded across
                     // operator turnover without per-request fairness games.
                     if (tar_scans_by_user_.size() >= kTarScanStateCap &&
                         !tar_scans_by_user_.contains(session->username)) {
                         auto oldest = tar_scans_by_user_.begin();
                         for (auto it = tar_scans_by_user_.begin();
                              it != tar_scans_by_user_.end(); ++it) {
                             if (it->second.dispatched_at <
                                 oldest->second.dispatched_at) {
                                 oldest = it;
                             }
                         }
                         tar_scans_by_user_.erase(oldest);
                     }
                     auto& st = tar_scans_by_user_[session->username];
                     st.command_id = command_id;
                     st.dispatched_count = sent;
                     st.dispatched_at = now_epoch();
                 }

                 audit_fn_(req, "tar.status.scan", "success", "command",
                          command_id,
                          std::format("dispatched to {} agent(s) in scope",
                                       sent));

                 std::string body;
                 if (sent == 0) {
                     body = "<div class=\"empty-state\">None of the agents "
                            "in your scope are currently connected. Bring "
                            "an agent online and click "
                            "<strong>Scan fleet</strong> again.</div>";
                     // Suppress the success-level toast on zero-reach — Gate 4
                     // happy-NICE-1 flagged "dispatched to 0 agent(s)" as
                     // misleading. Use a warning toast that matches the body.
                     res.set_header("HX-Trigger",
                         "{\"showToast\":{\"message\":\"No connected agents "
                         "in scope to scan\",\"level\":\"warning\"}}");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_scan_dispatched_total",
                                           {{"result", "no_connected_agents"}}).increment();
                     }
                 } else {
                     body = std::format(
                         "<div class=\"empty-state\">Scanning <strong>{}"
                         "</strong> agent{} (command <code>{}</code>) — "
                         "click <strong>Refresh</strong> in a moment to see "
                         "the results.</div>",
                         sent, sent == 1 ? "" : "s",
                         html_escape(std::string{command_id}));
                     res.set_header("HX-Trigger", std::format(
                         "{{\"showToast\":{{\"message\":\"TAR scan dispatched "
                         "to {} agent(s)\",\"level\":\"success\"}}}}", sent));
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_scan_dispatched_total",
                                           {{"result", "success"}}).increment();
                     }
                 }
                 // Cache-Control: no-store applies to all fragment responses
                 // — fragment data is per-operator (post-hardening-round-1)
                 // and a shared upstream proxy that caches text/html could
                 // re-replay one operator's filtered scan result to a
                 // different operator (UP-11). Vary on Cookie so any
                 // proxy-cache that does honor CC still keys per-session.
                 res.set_header("Cache-Control", "no-store, private");
                 res.set_header("Vary", "Cookie");
                 res.set_content(body, "text/html; charset=utf-8");
             });

    // POST /fragments/tar/retention-paused/reenable
    //   form params: device_id, source
    //
    // Dispatches `tar.configure` with `<source>_enabled=true` to the single
    // named device. Per-source independence (the #539 invariant) means this
    // does not touch the other three sources on the device.
    //
    // Permission: Execution:Execute (dispatches a configure command — same
    // tier as run-instruction and tar-sql siblings; Gate 2 governance flagged
    // the original Infrastructure:Update as a tier mismatch).
    //
    // RBAC scope: device_id MUST be in the operator's visible agents set;
    // out-of-scope device_ids are rejected with the same 404 body as
    // not-connected so non-operators cannot use this endpoint as an
    // existence-enumeration oracle.
    sink.Post("/fragments/tar/retention-paused/reenable",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Execution", "Execute")) {
                     // Compliance F1: denied audit on RBAC rejection.
                     audit_fn_(req, "tar.source.reenable", "denied",
                              "command", "", "rbac_denied");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_reenable_total",
                                           {{"result", "denied"}}).increment();
                     }
                     return;
                 }
                 auto session = auth_fn_(req, res);
                 if (!session) return;
                 // CSRF same-site gate (parity with the purge fragment; defense-in-depth
                 // on top of SameSite=Lax). Reject cross-origin/header-less cookie POSTs.
                 {
                     const std::string origin = req.get_header_value("Origin");
                     const std::string referer = req.get_header_value("Referer");
                     const bool same_site =
                         !(origin.empty() && referer.empty()) &&
                         origin_is_same_site(req.get_header_value("Host"), origin, referer,
                                             csrf_trusted_origins_);
                     if (!same_site) {
                         audit_fn_(req, "tar.source.reenable", "denied", "command", "",
                                   "csrf_cross_origin");
                         if (metrics_) {
                             metrics_->counter("yuzu_tar_source_reenable_total",
                                               {{"result", "denied"}})
                                 .increment();
                         }
                         res.status = 403;
                         res.set_content(
                             "<span class=\"tar-row-error\">Cross-origin request refused.</span>",
                             "text/html; charset=utf-8");
                         return;
                     }
                 }
                 if (!dispatch_fn_) {
                     res.status = 503;
                     res.set_content("<span class=\"tar-row-error\">Dispatch "
                                     "unavailable.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 auto device_id = req.has_param("device_id")
                     ? req.get_param_value("device_id")
                     : extract_form_value(req.body, "device_id");
                 auto source = req.has_param("source")
                     ? req.get_param_value("source")
                     : extract_form_value(req.body, "source");

                 if (device_id.empty() || source.empty()) {
                     res.status = 400;
                     res.set_content("<span class=\"tar-row-error\">"
                                     "device_id and source are required."
                                     "</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_reenable_total",
                                           {{"result", "invalid_input"}}).increment();
                     }
                     return;
                 }
                 // Validate source against the canonical four. Anything else
                 // would be a forged form submission; reject rather than
                 // dispatch a configure command with an arbitrary key.
                 if (source != "process" && source != "tcp" &&
                     source != "service" && source != "user") {
                     res.status = 400;
                     res.set_content("<span class=\"tar-row-error\">"
                                     "Unknown source — must be one of "
                                     "process, tcp, service, user.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_reenable_total",
                                           {{"result", "invalid_input"}}).increment();
                     }
                     return;
                 }

                 // Per-device RBAC visibility check. Out-of-scope device_ids
                 // collapse to the same 404 path as not-connected devices so
                 // the response cannot be used to enumerate device existence.
                 // Audit detail records the real reason on the server side.
                 bool visible = false;
                 if (mgmt_group_store_) {
                     // ADR-0042: nullopt (store degraded) → not visible (fail-closed).
                     if (auto visible_ids = mgmt_group_store_->get_visible_agents(
                             session->username)) {
                         for (const auto& vid : *visible_ids) {
                             if (vid == device_id) { visible = true; break; }
                         }
                     }
                 }

                 if (!visible) {
                     audit_fn_(req, "tar.source.reenable", "failure",
                              "command", "",
                              std::format("scope_violation source={}",
                                           source));
                     res.status = 404;
                     res.set_content("<span class=\"tar-row-error\">"
                                     "Agent not reachable.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_reenable_total",
                                           {{"result", "scope_violation"}}).increment();
                     }
                     return;
                 }

                 std::unordered_map<std::string, std::string> params;
                 params[std::format("{}_enabled", source)] = "true";
                 // CDX-R7-02: reaches a single visibility-gated device_id — ALSO
                 // narrow to the caller's Execution:Execute visible set (the Ids
                 // arm of dispatch_confined drops an out-of-scope device_id), so
                 // a service-scoped token cannot re-enable capture on a device
                 // outside its service. Fail CLOSED if the derivation is unwired.
                 yuzu::server::DispatchCaller caller =
                     caller_fn_ ? caller_fn_(req)
                               : yuzu::server::DispatchCaller{
                                     .exec_visible = yuzu::server::authz::deny_all()};
                 auto dispatch_outcome = dispatch_fn_(
                     "tar", "configure", {device_id}, /*scope_expr=*/"",
                     params, caller);
                 auto& command_id = dispatch_outcome.command_id;
                 auto& sent = dispatch_outcome.sent;

                 if (sent == 0) {
                     audit_fn_(req, "tar.source.reenable", "failure",
                              "command", "",
                              std::format("agent_not_connected source={}",
                                           source));
                     res.status = 404;
                     res.set_content("<span class=\"tar-row-error\">"
                                     "Agent not reachable.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_reenable_total",
                                           {{"result", "agent_not_connected"}}).increment();
                     }
                     return;
                 }

                 audit_fn_(req, "tar.source.reenable", "success",
                          "command", command_id,
                          std::format("device={} source={}",
                                       device_id, source));
                 if (metrics_) {
                     metrics_->counter("yuzu_tar_source_reenable_total",
                                       {{"result", "success"}}).increment();
                 }

                 res.set_header("HX-Trigger", std::format(
                     "{{\"showToast\":{{\"message\":\"Re-enabling {} on "
                     "{}\",\"level\":\"success\"}}}}",
                     source, html_escape(std::string{device_id})));
                 // No-store on every fragment response (UP-11 mitigation).
                 res.set_header("Cache-Control", "no-store, private");
                 res.set_header("Vary", "Cookie");
                 // Empty response body — combined with hx-swap=delete on
                 // the row, this drops the row optimistically. The next
                 // Refresh will reconcile against a fresh tar.status.
                 res.set_content("", "text/html; charset=utf-8");
             });

    // POST /fragments/tar/retention-paused/purge — Phase 15.A destructive purge.
    // Mirrors /reenable but (a) gates on Infrastructure:Delete (higher tier than
    // re-enable's Execution:Execute), (b) dispatches tar.purge_source, and (c)
    // leaves the source PAUSED (purge drops data without re-enabling collection).
    // The agent refuses if the source is still enabled — that is the authoritative
    // TOCTOU guard. Dispatch is fire-and-forget, so rows_deleted is computed
    // agent-side (returned in the response record) and is NOT in this audit row.
    sink.Post("/fragments/tar/retention-paused/purge",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Infrastructure", "Delete")) {
                     audit_fn_(req, "tar.source.purge", "denied", "command", "", "rbac_denied");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_purge_total", {{"result", "denied"}})
                             .increment();
                     }
                     return;
                 }
                 auto session = auth_fn_(req, res);
                 if (!session) return;
                 // CSRF same-site gate for this destructive cookie-authenticated POST
                 // (mirrors ca_routes.cpp ca.revoke / ca.import-chain). Reject a
                 // cross-origin OR header-less request before the irreversible dispatch —
                 // SameSite=Lax on the session cookie already blocks the naive cross-site
                 // top-level POST, this is defense-in-depth + convention. Programmatic
                 // callers use the structured POST /api/v1/tar/retention-paused/purge, not
                 // this dashboard fragment, so requiring an Origin/Referer here is safe.
                 {
                     const std::string origin = req.get_header_value("Origin");
                     const std::string referer = req.get_header_value("Referer");
                     const bool same_site =
                         !(origin.empty() && referer.empty()) &&
                         origin_is_same_site(req.get_header_value("Host"), origin, referer,
                                             csrf_trusted_origins_);
                     if (!same_site) {
                         audit_fn_(req, "tar.source.purge", "denied", "command", "",
                                   "csrf_cross_origin");
                         if (metrics_) {
                             metrics_->counter("yuzu_tar_source_purge_total", {{"result", "denied"}})
                                 .increment();
                         }
                         res.status = 403;
                         res.set_content(
                             "<span class=\"tar-row-error\">Cross-origin request refused.</span>",
                             "text/html; charset=utf-8");
                         return;
                     }
                 }
                 if (!dispatch_fn_) {
                     res.status = 503;
                     res.set_content("<span class=\"tar-row-error\">Dispatch unavailable.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 auto device_id = req.has_param("device_id") ? req.get_param_value("device_id")
                                                             : extract_form_value(req.body, "device_id");
                 auto source = req.has_param("source") ? req.get_param_value("source")
                                                       : extract_form_value(req.body, "source");

                 if (device_id.empty() || source.empty()) {
                     res.status = 400;
                     res.set_content("<span class=\"tar-row-error\">"
                                     "device_id and source are required.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_purge_total", {{"result", "invalid_input"}})
                             .increment();
                     }
                     return;
                 }
                 // Same source scope as the frame (the four core diff sources); a
                 // forged form value is rejected rather than dispatched.
                 if (source != "process" && source != "tcp" && source != "service" &&
                     source != "user") {
                     res.status = 400;
                     res.set_content("<span class=\"tar-row-error\">"
                                     "Unknown source — must be one of "
                                     "process, tcp, service, user.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_purge_total", {{"result", "invalid_input"}})
                             .increment();
                     }
                     return;
                 }

                 // Per-device RBAC visibility (same 404-collapse as reenable so the
                 // response cannot enumerate device existence; real reason audited).
                 bool visible = false;
                 if (mgmt_group_store_) {
                     // ADR-0042: nullopt (store degraded) → not visible (fail-closed).
                     if (auto visible_ids = mgmt_group_store_->get_visible_agents(session->username)) {
                         for (const auto& vid : *visible_ids) {
                             if (vid == device_id) {
                                 visible = true;
                                 break;
                             }
                         }
                     }
                 }
                 if (!visible) {
                     audit_fn_(req, "tar.source.purge", "failure", "command", "",
                              std::format("scope_violation source={}", source));
                     res.status = 404;
                     res.set_content("<span class=\"tar-row-error\">Agent not reachable.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_purge_total",
                                           {{"result", "scope_violation"}})
                             .increment();
                     }
                     return;
                 }

                 std::unordered_map<std::string, std::string> params;
                 params["source"] = source;
                 // CDX-R7-02: purge_source is DESTRUCTIVE (drops a device's TAR
                 // data), so narrowing to the caller's Execution:Execute visible
                 // set matters most here — a service-scoped token must not purge
                 // a device outside its service even if username visibility would
                 // admit it. The Ids arm of dispatch_confined drops an
                 // out-of-scope device_id; fail CLOSED if the derivation is unwired.
                 yuzu::server::DispatchCaller caller =
                     caller_fn_ ? caller_fn_(req)
                               : yuzu::server::DispatchCaller{
                                     .exec_visible = yuzu::server::authz::deny_all()};
                 auto dispatch_outcome =
                     dispatch_fn_("tar", "purge_source", {device_id}, /*scope_expr=*/"", params,
                                  caller);
                 auto& command_id = dispatch_outcome.command_id;
                 auto& sent = dispatch_outcome.sent;

                 if (sent == 0) {
                     audit_fn_(req, "tar.source.purge", "failure", "command", "",
                              std::format("agent_not_connected source={}", source));
                     res.status = 404;
                     res.set_content("<span class=\"tar-row-error\">Agent not reachable.</span>",
                                     "text/html; charset=utf-8");
                     if (metrics_) {
                         metrics_->counter("yuzu_tar_source_purge_total",
                                           {{"result", "agent_not_connected"}})
                             .increment();
                     }
                     return;
                 }

                 audit_fn_(req, "tar.source.purge", "success", "command", command_id,
                          std::format("device={} source={}", device_id, source));
                 if (metrics_) {
                     metrics_->counter("yuzu_tar_source_purge_total", {{"result", "success"}})
                         .increment();
                 }

                 res.set_header("HX-Trigger",
                                std::format("{{\"showToast\":{{\"message\":\"Purging {} data on "
                                            "{}\",\"level\":\"success\"}}}}",
                                            source, html_escape(std::string{device_id})));
                 res.set_header("Cache-Control", "no-store, private");
                 res.set_header("Vary", "Cookie");
                 // The source stays paused (purge does not re-enable), so the row
                 // remains — replace the action buttons with a dispatched note; a
                 // Scan reconciles the (now-zero) counts.
                 res.set_content("<span class=\"tar-row-note\">Purge dispatched — Scan to "
                                 "refresh.</span>",
                                 "text/html; charset=utf-8");
             });

    spdlog::info("DashboardRoutes: registered fragment endpoints");
}

// ---------------------------------------------------------------------------
// parse_filters — extract f_<column_name>=value from request params
// ---------------------------------------------------------------------------

std::vector<FacetFilter> DashboardRoutes::parse_filters(const httplib::Request& req,
                                                         const std::string& plugin) const {
    std::vector<FacetFilter> filters;
    auto& cols = columns_for_plugin(plugin);
    // cols[0] is "Agent" — skip it, field indices are 0-based after Agent
    for (size_t i = 1; i < cols.size(); ++i) {
        std::string param_name = "f_";
        // Lowercase the column name for the param key
        for (char c : cols[i]) {
            if (c == ' ' || c == '-') param_name += '_';
            else param_name += static_cast<char>(std::tolower(c));
        }
        auto val = req.get_param_value(param_name);
        if (val.empty()) {
            // Also try form-encoded body
            val = extract_form_value(req.body, param_name);
        }
        if (!val.empty()) {
            FacetFilter f;
            f.col_idx = static_cast<int>(i - 1);
            f.value = val;
            filters.push_back(f);
        }
    }
    return filters;
}

// ---------------------------------------------------------------------------
// resolve_visible_scope — D3 Response:Read visibility for the facet/scope
// surfaces (unwired visible_set_fn_ == legacy-open, nullopt)
// ---------------------------------------------------------------------------

std::optional<std::vector<std::string>> DashboardRoutes::resolve_visible_scope(
    const std::string& username) const {
    if (!visible_set_fn_) return std::nullopt;
    auto scope = visible_set_fn_(username);
    if (!scope) return std::nullopt;
    return std::vector<std::string>(scope->begin(), scope->end());
}

std::optional<std::vector<std::string>> DashboardRoutes::resolve_visible_scope(
    const auth::Session& session) const {
    if (auth::is_elevated(session)) return std::nullopt;
    return resolve_visible_scope(session.username);
}

// ---------------------------------------------------------------------------
// resolve_render_columns
// ---------------------------------------------------------------------------

std::vector<std::string> DashboardRoutes::resolve_render_columns(
    const std::string& plugin, const std::string& definition_id) const {
    if (!definition_id.empty() && instruction_store_ && instruction_store_->is_open()) {
        // ADR-0058: a DB-error outer result falls through to columns_for_plugin below,
        // same as a not-found inner optional did pre-migration.
        if (auto def_result = instruction_store_->get_definition(definition_id);
            def_result && *def_result && !(*def_result)->result_schema.empty()) {
            ResponseTemplatesEngine engine;
            auto tmpl = engine.synthesise_default((*def_result)->result_schema, plugin);
            if (!tmpl.columns.empty()) {
                std::vector<std::string> cols{"Agent"};
                cols.insert(cols.end(), tmpl.columns.begin(), tmpl.columns.end());
                return cols;
            }
        }
    }
    return columns_for_plugin(plugin);
}

// ---------------------------------------------------------------------------
// render_results
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_results(
    const std::string& command_id, const std::string& plugin,
    const std::string& sort_col, const std::string& sort_dir,
    int page, int per_page,
    const std::vector<FacetFilter>& filters,
    const std::string& text_query,
    const std::string& definition_id,
    const std::string& template_id,
    const std::vector<std::string>& visible_columns,
    const authz::VisibleSet& scope) {

    if (!response_store_) {
        return "<tbody id=\"results-tbody\"><tr><td class=\"empty-state\">"
               "Response store not available.</td></tr></tbody>";
    }

    auto col_names = resolve_render_columns(plugin, definition_id);

    // Issue #254 (Phase 8.2): when a template specified a visible-column
    // subset, build the set of plugin column indices to render. Index 0
    // is the "Agent" pseudo-column which is always shown. Indices ≥ 1
    // are filtered by name match (case-insensitive). An empty
    // visible_columns list means "render everything" (legacy behaviour).
    std::vector<size_t> visible_indices; // includes 0 (Agent) when non-empty
    if (!visible_columns.empty()) {
        visible_indices.push_back(0); // Agent always
        for (size_t i = 1; i < col_names.size(); ++i) {
            for (const auto& vc : visible_columns) {
                if (vc.size() == col_names[i].size() &&
                    std::equal(col_names[i].begin(), col_names[i].end(), vc.begin(),
                               [](char a, char b) {
                                   return std::tolower(static_cast<unsigned char>(a)) ==
                                          std::tolower(static_cast<unsigned char>(b));
                               })) {
                    visible_indices.push_back(i);
                    break;
                }
            }
        }
    }
    auto is_visible = [&](size_t plugin_col_idx) {
        if (visible_indices.empty()) return true;
        for (auto idx : visible_indices) if (idx == plugin_col_idx) return true;
        return false;
    };

    // Phase 1: determine which responses match the filters
    std::vector<StoredResponse> responses;
    int64_t total_agent_count = 0;

    // #2691 (Doomgoose finding #7): the render still degrades to empty (ADR-0039
    // deny-or-benign — a read failure is not a target/enforce decision here), but
    // `store_degraded` keeps that fact distinguishable through to the two render
    // sites below (tbody empty-state, #result-summary) so an operator sees "store
    // degraded, not zero matches" rather than a silently wrong "no results".
    bool store_degraded = false;
    if (filters.empty()) {
        // No filters — load all responses for this instruction
        ResponseQuery q;
        q.limit = 10000; // upper bound
        auto responses_opt = response_store_->query(command_id, q);
        store_degraded = !responses_opt.has_value();
        responses = responses_opt.value_or(std::vector<StoredResponse>{});
        total_agent_count = static_cast<int64_t>(responses.size());
    } else {
        // Use faceted index to get matching response IDs, then load them
        auto resp_ids_opt = response_store_->facet_response_ids(command_id, filters, 10000, 0);
        store_degraded = !resp_ids_opt.has_value();
        auto resp_ids = resp_ids_opt.value_or(std::vector<int64_t>{});
        auto responses_opt = response_store_->query_by_ids(resp_ids);
        store_degraded = store_degraded || !responses_opt.has_value();
        responses = responses_opt.value_or(std::vector<StoredResponse>{});
        // facet_agent_count is degrade-distinguishable too — a degraded count
        // also hides the "Create Group" button below, the safer default for a
        // write-adjacent action on an uncertain count.
        //
        // Deliberately left unscoped here (and facet_response_ids above,
        // same reasoning) — superseded by the #1712 in-handler recompute
        // plan (per the PR-4 re-enumeration); no behaviour change at this
        // site.
        auto count_opt = response_store_->facet_agent_count(command_id, filters);
        store_degraded = store_degraded || !count_opt.has_value();
        total_agent_count = count_opt.value_or(0);
    }

    // #1712 / #3290 Phase 2 — scope filter (the gate's composed
    // meet(management-group, service-scope) VisibleSet), applied BEFORE
    // total_agent_count is used anywhere below: a fleet-wide count served
    // to a confined caller is the same disclosure class this migration
    // closes, so `total_agent_count` is recomputed from the filtered set
    // rather than left at its pre-filter (facet_agent_count/response-count)
    // value. nullopt (TOP) ⇒ unfiltered, byte-identical to the pre-#1712
    // path for that caller class.
    if (scope) {
        std::vector<StoredResponse> visible;
        visible.reserve(responses.size());
        for (auto& r : responses) {
            if (authz::in_scope(scope, r.agent_id))
                visible.push_back(std::move(r));
        }
        responses.swap(visible);
        total_agent_count = static_cast<int64_t>(responses.size());
    }

    // Phase 2: parse output lines, apply per-line filters and text search
    struct ResultLine {
        std::string agent_name;
        std::vector<std::string> fields; // excludes Agent column
    };
    std::vector<ResultLine> all_lines;
    all_lines.reserve(responses.size() * 4);

    for (const auto& resp : responses) {
        auto agent_name = registry_ ? registry_->display_name(resp.agent_id)
                                     : resp.agent_id;
        auto lines = split_output_lines(resp.output);
        for (const auto& line : lines) {
            auto fields = split_fields(plugin, line);

            // Apply per-field filters
            bool match = true;
            for (const auto& f : filters) {
                if (f.col_idx >= 0 && f.col_idx < static_cast<int>(fields.size())) {
                    if (fields[f.col_idx] != f.value) { match = false; break; }
                }
            }
            if (!match) continue;

            // Apply free-text search
            if (!text_query.empty()) {
                bool found = false;
                for (const auto& fld : fields) {
                    if (fld.find(text_query) != std::string::npos) { found = true; break; }
                }
                if (!found && agent_name.find(text_query) == std::string::npos)
                    continue;
            }

            ResultLine rl;
            rl.agent_name = agent_name;
            rl.fields = std::move(fields);
            all_lines.push_back(std::move(rl));
        }
    }

    // Phase 3: sort
    int sort_idx = -1; // -1 = sort by agent name
    if (sort_col != "agent") {
        sort_idx = col_index_for_name(col_names, sort_col);
    }
    bool ascending = (sort_dir == "asc");

    std::sort(all_lines.begin(), all_lines.end(),
              [sort_idx, ascending](const ResultLine& a, const ResultLine& b) {
                  std::string va, vb;
                  if (sort_idx < 0) {
                      va = a.agent_name;
                      vb = b.agent_name;
                  } else {
                      va = (sort_idx < static_cast<int>(a.fields.size())) ? a.fields[sort_idx] : "";
                      vb = (sort_idx < static_cast<int>(b.fields.size())) ? b.fields[sort_idx] : "";
                  }
                  return ascending ? (va < vb) : (va > vb);
              });

    // Phase 4: paginate
    int64_t total_lines = static_cast<int64_t>(all_lines.size());
    int64_t total_pages = std::max(int64_t{1}, (total_lines + per_page - 1) / per_page);
    if (page > total_pages) page = static_cast<int>(total_pages);
    int64_t start = static_cast<int64_t>(page - 1) * per_page;
    int64_t end = std::min(start + per_page, total_lines);

    // Phase 5: render HTML

    // Build base URL for sort/page links (preserving all current params)
    auto base_url = [&](const std::string& new_sort, const std::string& new_dir,
                        int new_page) {
        std::string url = "/fragments/results?command_id=" + html_escape(command_id) +
                          "&amp;plugin=" + html_escape(plugin) +
                          "&amp;sort=" + html_escape(new_sort) +
                          "&amp;dir=" + html_escape(new_dir) +
                          "&amp;page=" + std::to_string(new_page) +
                          "&amp;per_page=" + std::to_string(per_page);
        if (!definition_id.empty())
            url += "&amp;definition_id=" + html_escape(definition_id);
        if (!template_id.empty())
            url += "&amp;template_id=" + html_escape(template_id);
        for (const auto& f : filters) {
            // Reconstruct f_<col> params
            if (f.col_idx >= 0 && f.col_idx + 1 < static_cast<int>(col_names.size())) {
                std::string pname = "f_";
                for (char c : col_names[f.col_idx + 1]) {
                    if (c == ' ' || c == '-') pname += '_';
                    else pname += static_cast<char>(std::tolower(c));
                }
                url += "&amp;" + pname + "=" + html_escape(f.value);
            }
        }
        if (!text_query.empty())
            url += "&amp;q=" + html_escape(text_query);
        return url;
    };

    std::string html;
    html.reserve(all_lines.size() * 300 + 4096);

    // Compute the visible-column count once for colspans below.
    size_t visible_col_count =
        visible_indices.empty() ? col_names.size() : visible_indices.size();

    // Primary: tbody rows
    html += "<tbody id=\"results-tbody\">";
    if (store_degraded) {
        // #2691 (Doomgoose finding #7): distinguishable from a genuine
        // zero-match answer — the response store could not be read.
        html += "<tr><td colspan=\"" + std::to_string(visible_col_count) +
                "\" class=\"empty-state result-degrade-banner\"><b>Results unavailable.</b> "
                "The response store could not be read (Postgres pool/query degraded). "
                "This is <b>not</b> \"no results\" — retry shortly.</td></tr>";
    } else if (all_lines.empty()) {
        html += "<tr><td colspan=\"" + std::to_string(visible_col_count) +
                "\" class=\"empty-state\">No results match your filters.</td></tr>";
    } else {
        for (int64_t i = start; i < end; ++i) {
            const auto& rl = all_lines[i];
            // Data row
            html += "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">";
            // Agent column (always visible when visible_indices is empty
            // OR contains 0; render_results currently always pushes 0).
            if (is_visible(0)) {
                html += "<td class=\"col-agent\" title=\"" + html_escape(rl.agent_name) +
                        "\">" + html_escape(rl.agent_name) + "</td>";
            }
            // Field columns — only render columns whose plugin index
            // (c + 1 because rl.fields skips Agent) is visible.
            for (size_t c = 0; c < rl.fields.size(); ++c) {
                if (!is_visible(c + 1)) continue;
                auto esc = html_escape(rl.fields[c]);
                // #4187: a cell whose raw value has a documented non-obvious
                // meaning (e.g. autoruns' enabled=unknown) gets an
                // explanatory title= instead of the value echoed back at
                // itself, plus a visible affordance so it's not hover-only
                // discoverable -- matches the retention-paused table's
                // existing badge-with-title precedent elsewhere in this file.
                auto hint = cell_hint_for(plugin, rl.fields, c);
                if (hint.empty()) {
                    html += "<td title=\"" + esc + "\">" + esc + "</td>";
                } else {
                    html += "<td class=\"cell-hint\" title=\"" +
                           html_escape(std::string{hint}) + "\">" + esc + "</td>";
                }
            }
            html += "</tr>";
            // Detail drawer — show every column regardless of template
            // visibility. The drawer is the "expand for full record"
            // affordance; hiding values there would defeat its purpose.
            html += "<tr class=\"result-detail\"><td colspan=\"" +
                    std::to_string(visible_col_count) +
                    "\"><div class=\"detail-content\">";
            html += "<div class=\"detail-label\">Agent</div>"
                    "<div class=\"detail-value\">" + html_escape(rl.agent_name) + "</div>";
            for (size_t c = 0; c < rl.fields.size(); ++c) {
                auto label = (c + 1 < col_names.size()) ? col_names[c + 1]
                                                         : ("Column " + std::to_string(c + 2));
                html += "<div class=\"detail-label\">" + html_escape(label) + "</div>"
                        "<div class=\"detail-value\">" + html_escape(rl.fields[c]) + "</div>";
            }
            html += "</div></td></tr>";
        }
    }
    html += "</tbody>";

    // OOB: thead with sort indicators
    html += "<thead id=\"results-thead\" hx-swap-oob=\"true\"><tr>";
    // Agent column header
    if (is_visible(0)) {
        auto new_dir = (sort_col == "agent" && sort_dir == "asc") ? "desc" : "asc";
        html += "<th class=\"col-agent sortable\" hx-get=\"" +
                base_url("agent", new_dir, 1) +
                "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\""
                " hx-indicator=\"#results-loading\">"
                "Agent";
        if (sort_col == "agent")
            html += (sort_dir == "asc") ? " &#9650;" : " &#9660;";
        html += "</th>";
    }
    // Other column headers
    for (size_t i = 1; i < col_names.size(); ++i) {
        if (!is_visible(i)) continue;
        std::string col_key;
        for (char c : col_names[i]) {
            if (c == ' ' || c == '-') col_key += '_';
            else col_key += static_cast<char>(std::tolower(c));
        }
        auto new_dir = (sort_col == col_key && sort_dir == "asc") ? "desc" : "asc";
        html += "<th class=\"sortable\" hx-get=\"" +
                base_url(col_key, new_dir, 1) +
                "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\""
                " hx-indicator=\"#results-loading\">" +
                html_escape(col_names[i]);
        if (sort_col == col_key)
            html += (sort_dir == "asc") ? " &#9650;" : " &#9660;";
        html += "</th>";
    }
    html += "</tr></thead>";

    // OOB: pagination
    html += "<nav id=\"result-pagination\" hx-swap-oob=\"true\">";
    if (total_lines > 0) {
        html += "<span>Showing " + std::to_string(start + 1) + "-" +
                std::to_string(end) + " of " + std::to_string(total_lines) + "</span>";
        if (page > 1) {
            html += " <button class=\"btn-page\" hx-get=\"" +
                    base_url(sort_col, sort_dir, page - 1) +
                    "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\">"
                    "Prev</button>";
        }
        if (page < static_cast<int>(total_pages)) {
            html += " <button class=\"btn-page\" hx-get=\"" +
                    base_url(sort_col, sort_dir, page + 1) +
                    "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\">"
                    "Next</button>";
        }
    }
    html += "</nav>";

    // OOB: summary with group-creation affordance
    html += "<div id=\"result-summary\" hx-swap-oob=\"true\">";
    if (store_degraded) {
        html += "<span class=\"result-degrade-banner\">store degraded — count unavailable</span>";
    } else if (total_lines > 0) {
        html += std::to_string(total_lines) + " result" +
                (total_lines != 1 ? "s" : "") + " across " +
                std::to_string(total_agent_count) + " agent" +
                (total_agent_count != 1 ? "s" : "");

        // Confined-caller withhold (Gate 6 enterprise-readiness finding, this
        // round): /fragments/create-group-form and /api/dashboard/group-from-
        // results gate on ManagementGroup:Write only — a DIFFERENT securable,
        // unrelated to this caller's Response:Read confinement — and apply no
        // per-agent scope filter of their own (tracked, deliberately deferred:
        // ADR-0017 "Doc honesty"/#3489). Before this migration a confined-only
        // (AdmitScoped) caller could not reach /fragments/results at all, so
        // could never see this button. Now that require_fleet_read admits
        // them, withhold the button itself when scope is engaged rather than
        // surface an entry point into a flow that would silently re-widen to
        // the unscoped facet count/ids on submit.
        if (!filters.empty() && total_agent_count > 0 && !scope) {
            // Build filter params for the create-group-form URL
            std::string filter_params;
            for (const auto& f : filters) {
                if (f.col_idx >= 0 && f.col_idx + 1 < static_cast<int>(col_names.size())) {
                    std::string pname = "f_";
                    for (char c : col_names[f.col_idx + 1]) {
                        if (c == ' ' || c == '-') pname += '_';
                        else pname += static_cast<char>(std::tolower(c));
                    }
                    filter_params += "&amp;" + pname + "=" + html_escape(f.value);
                }
            }
            html += " <button class=\"btn-create-group\" hx-get=\"/fragments/create-group-form"
                    "?command_id=" + html_escape(command_id) +
                    "&amp;plugin=" + html_escape(plugin) + filter_params +
                    "\" hx-target=\"#group-form-slot\" hx-swap=\"innerHTML\">"
                    "Create Group from " + std::to_string(total_agent_count) +
                    " Agent" + (total_agent_count != 1 ? "s" : "") + "</button>";
        }
    }
    html += "</div>";

    // Issue #587 — OOB chart deck. When the dispatched command came from an
    // InstructionDefinition that has a `spec.visualization`, populate
    // #chart-deck-host with one chart-card div per configured chart.
    // yuzu-charts.js (loaded in dashboard.html) re-runs auto-render on
    // htmx:afterSettle and fetches each chart's REST URL independently.
    // When no definition_id is supplied or the definition has no charts,
    // we still emit an empty <div> so any prior chart deck from a previous
    // command is cleared.
    int chart_count = 0;
    if (!definition_id.empty() && instruction_store_ && instruction_store_->is_open()) {
        // ADR-0058: a DB-error outer result leaves chart_count at 0 (empty deck
        // below), same as a not-found inner optional did pre-migration.
        auto def_result = instruction_store_->get_definition(definition_id);
        if (def_result && *def_result)
            chart_count = VisualizationEngine::count((*def_result)->visualization_spec);
    }
    html += R"(<div id="chart-deck-host" hx-swap-oob="innerHTML">)";
    if (chart_count > 0) {
        html += R"(<div class="yuzu-chart-deck">)";
        for (int i = 0; i < chart_count; ++i) {
            html += R"(<div class="yuzu-chart-card" data-yuzu-chart-url=")";
            html += "/api/v1/executions/" + html_escape(command_id) +
                    "/visualization?definition_id=" + html_escape(definition_id) +
                    "&amp;index=" + std::to_string(i);
            html += R"("></div>)";
        }
        html += "</div>";
    }
    html += "</div>";

    return html;
}

// ---------------------------------------------------------------------------
// render_filter_bar
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_filter_bar(const std::string& command_id,
                                                const std::string& plugin,
                                                const std::string& definition_id,
                                                const std::string& template_id,
                                                const std::string& username,
                                                bool elevated) {
    auto& cols = columns_for_plugin(plugin);
    // JIT-elevated sessions get the full-fleet view (nullopt), matching
    // auth_routes.cpp's is_elevated short-circuit: RBAC re-derivation from
    // username alone cannot see the session's in-memory elevated_until, so
    // it must never be consulted for an elevated caller (would otherwise
    // silently scope an admin down to nothing rather than up to everything).
    auto agent_scope = elevated ? std::nullopt : resolve_visible_scope(username);

    std::string html;
    html += "<form id=\"filter-bar\" class=\"filter-bar\" hx-sync=\"this:abort\">"
            "<input type=\"hidden\" name=\"command_id\" value=\"" +
            html_escape(command_id) + "\">"
            "<input type=\"hidden\" name=\"plugin\" value=\"" +
            html_escape(plugin) + "\">";
    if (!definition_id.empty()) {
        html += "<input type=\"hidden\" name=\"definition_id\" value=\"" +
                html_escape(definition_id) + "\">";
    }

    // Issue #254 (Phase 8.2) — response template selector.
    // Rendered as the first control in the filter bar so operators can
    // pick a saved view without scrolling. The synthesised default
    // (kDefaultId) is always available, even when no operator templates
    // are authored. Selecting an option triggers an HTMX swap of
    // /fragments/results with template_id=<chosen>; the route handler
    // resolves the template and applies sort/filter/columns defaults.
    if (!definition_id.empty() && instruction_store_ && instruction_store_->is_open()) {
        // ADR-0058: a DB-error outer result skips this best-effort template
        // selector, same as a not-found inner optional did pre-migration.
        auto def_result = instruction_store_->get_definition(definition_id);
        if (def_result && *def_result) {
            const auto& def = **def_result;
            ResponseTemplatesEngine engine;
            std::vector<ResponseTemplate> templates;
            if (auto parsed = engine.parse(def.response_templates_spec); parsed)
                templates = std::move(*parsed);
            // The dropdown lists the synthesised default first when no
            // operator template is marked default; otherwise it omits
            // the synth default and uses the operator default instead.
            bool operator_has_default = false;
            for (const auto& t : templates) if (t.is_default) {
                operator_has_default = true; break;
            }
            std::string current = template_id.empty()
                                    ? std::string(ResponseTemplatesEngine::kDefaultId)
                                    : template_id;
            html += "<label>View</label>";
            html += "<select name=\"template_id\""
                    " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
                    " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
                    " hx-sync=\"closest form:abort\">";
            if (!operator_has_default) {
                html += "<option value=\"" +
                        html_escape(ResponseTemplatesEngine::kDefaultId) + "\"";
                if (current == ResponseTemplatesEngine::kDefaultId) html += " selected";
                html += ">Default</option>";
            }
            for (const auto& t : templates) {
                html += "<option value=\"" + html_escape(t.id) + "\"";
                if (current == t.id) html += " selected";
                html += ">" + html_escape(t.name);
                if (t.is_default) html += " (default)";
                html += "</option>";
            }
            html += "</select>";
        }
    }

    // Per-column filter controls (skip Agent at index 0)
    for (size_t i = 1; i < cols.size(); ++i) {
        std::string param_name = "f_";
        for (char c : cols[i]) {
            if (c == ' ' || c == '-') param_name += '_';
            else param_name += static_cast<char>(std::tolower(c));
        }

        // Get distinct facet values for this column
        int col_idx = static_cast<int>(i - 1);
        std::vector<FacetValue> facet_vals;
        bool facet_degraded = false;
        if (response_store_) {
            auto facet_opt = response_store_->facet_values(command_id, col_idx, agent_scope);
            facet_degraded = !facet_opt.has_value();
            facet_vals = std::move(facet_opt).value_or(std::vector<FacetValue>{});
        }

        html += "<label>" + html_escape(cols[i]) + "</label>";

        // #2691 (Gate 4 consistency-auditor): a degraded read must not render
        // as an empty "All" dropdown — that's indistinguishable from "this
        // column genuinely has no other values", right next to a results
        // table that correctly banners the same degrade. Disable the control
        // instead of silently offering a filter that can't be trusted.
        if (facet_degraded) {
            html += "<select name=\"" + param_name + "\" disabled title=\"Filter values "
                    "unavailable — response store degraded\">"
                    "<option value=\"\">(unavailable)</option></select>";
        } else if (facet_vals.size() <= 20) {
            // Dropdown for small cardinality
            html += "<select name=\"" + param_name + "\""
                    " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
                    " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
                    " hx-sync=\"closest form:abort\">"
                    "<option value=\"\">All</option>";
            for (const auto& fv : facet_vals) {
                html += "<option value=\"" + html_escape(fv.value) + "\">" +
                        html_escape(fv.value) + " (" + std::to_string(fv.line_count) +
                        ")</option>";
            }
            html += "</select>";
        } else {
            // Text input for high cardinality
            html += "<input type=\"text\" name=\"" + param_name + "\""
                    " placeholder=\"Filter " + html_escape(cols[i]) + "...\""
                    " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
                    " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
                    " hx-trigger=\"input changed delay:300ms\""
                    " hx-sync=\"closest form:abort\">";
        }
    }

    // Free-text search
    html += "<label>Search</label>"
            "<input type=\"search\" name=\"q\" placeholder=\"Free text...\""
            " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
            " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
            " hx-trigger=\"input changed delay:300ms\""
            " hx-sync=\"closest form:abort\">";

    html += "</form>";
    return html;
}

// ---------------------------------------------------------------------------
// render_create_group_form
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_create_group_form(
    const std::string& command_id, const std::string& plugin,
    const std::vector<FacetFilter>& filters, std::optional<int64_t> agent_count) {

    auto& col_names = columns_for_plugin(plugin);

    std::string html;
    html += "<form class=\"create-group-form\""
            " hx-post=\"/api/dashboard/group-from-results\" hx-swap=\"none\""
            " hx-indicator=\"#group-form-slot\">"
            "<input type=\"hidden\" name=\"command_id\" value=\"" +
            html_escape(command_id) + "\">"
            "<input type=\"hidden\" name=\"plugin\" value=\"" +
            html_escape(plugin) + "\">";

    // Include current filter values as hidden fields
    for (const auto& f : filters) {
        if (f.col_idx >= 0 && f.col_idx + 1 < static_cast<int>(col_names.size())) {
            std::string pname = "f_";
            for (char c : col_names[f.col_idx + 1]) {
                if (c == ' ' || c == '-') pname += '_';
                else pname += static_cast<char>(std::tolower(c));
            }
            html += "<input type=\"hidden\" name=\"" + pname + "\" value=\"" +
                    html_escape(f.value) + "\">";
        }
    }

    std::string count_hint;
    if (agent_count.has_value()) {
        count_hint = std::to_string(*agent_count) + " agent" + (*agent_count != 1 ? "s" : "") +
                    " will be added";
    } else {
        // #2691 (Doomgoose finding #7): the store read degraded — say so,
        // never silently claim "0 agents" (a materially different, wrong
        // answer the operator could act on by submitting an empty group).
        count_hint = "agent count unavailable (store degraded) — submitting now will add "
                     "whichever agents match at write time";
    }
    html += "<input name=\"group_name\" type=\"text\" placeholder=\"Group name\""
            " required maxlength=\"128\" autofocus>"
            " <button type=\"submit\">Create Static Group</button>"
            " <span class=\"form-hint\">" + count_hint + "</span></form>";

    return html;
}

// ---------------------------------------------------------------------------
// render_scope_list
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_scope_list(const std::string& selected,
                                                const std::string& username) {
    std::string html;
    html.reserve(4096);

    // "All Agents" item
    html += "<div class=\"scope-item";
    if (selected == "__all__") html += " selected";
    html += "\" data-scope=\"__all__\" onclick=\"selectScope(this)\">"
            "<span class=\"scope-item-name scope-item-all\">All Agents</span>"
            "<span class=\"scope-item-meta\">Broadcast to every connected agent</span>"
            "</div>";

    // Groups section
    if (mgmt_group_store_) {
        auto groups = mgmt_group_store_->list_groups();
        if (!groups.empty()) {
            html += "<div class=\"scope-section-header\">Groups</div>";
            for (const auto& g : groups) {
                auto members = mgmt_group_store_->get_members(g.id);
                auto member_count = members.size();
                std::string scope_key = "group:" + g.id;

                html += "<div class=\"scope-item";
                if (selected == scope_key) html += " selected";
                html += "\" data-scope=\"" + html_escape(scope_key) +
                        "\" onclick=\"selectScope(this)\">"
                        "<span class=\"scope-item-name\">" +
                        html_escape(g.name) + "</span>"
                        "<span class=\"scope-item-meta\">" +
                        std::to_string(member_count) + " agent" +
                        (member_count != 1 ? "s" : "") + " &middot; " +
                        html_escape(g.membership_type) + "</span></div>";
            }
        }
    }

    // Individual agents section
    if (agents_json_fn_) {
        auto agents_json_str = agents_json_fn_();
        auto agents_arr = nlohmann::json::parse(agents_json_str, nullptr, false);
        if (agents_arr.is_array()) {
            std::sort(agents_arr.begin(), agents_arr.end(),
                      [](const nlohmann::json& a, const nlohmann::json& b) {
                          return a.value("agent_id", "") < b.value("agent_id", "");
                      });

            html += "<div class=\"scope-section-header\">Agents</div>";
            for (const auto& a : agents_arr) {
                auto id = a.value("agent_id", "");
                auto hostname = a.value("hostname", "");
                auto os = a.value("os", "?");
                auto arch = a.value("arch", "?");
                auto version = a.value("agent_version", "");
                auto short_id = (id.size() > 12) ? id.substr(0, 12) : id;

                html += "<div class=\"scope-item";
                if (selected == id) html += " selected";
                html += "\" data-scope=\"" + html_escape(id) +
                        "\" onclick=\"selectScope(this)\">"
                        "<span class=\"scope-item-name\"><span class=\"online-dot\"></span>" +
                        html_escape(hostname.empty() ? id : hostname) +
                        "</span><span class=\"scope-item-meta\">" +
                        html_escape(short_id) + " &middot; " +
                        html_escape(os) + "/" + html_escape(arch) +
                        (version.empty() ? "" : " &middot; v" + html_escape(version)) +
                        "</span></div>";
            }

            // OOB: agent count badge
            auto count = agents_arr.size();
            html += "<span id=\"agent-count\" hx-swap-oob=\"true\">" +
                    std::to_string(count) + " agent" +
                    (count != 1u ? "s" : "") + "</span>";

            // Hidden data carrier
            html += "<div id=\"scope-data\" data-agents=\"" +
                    html_escape(agents_arr.dump()) +
                    "\" style=\"display:none\"></div>";
        }
    }

    return html;
}

// ---------------------------------------------------------------------------
// render_tar_retention_paused — Phase 15.A retention-paused source list
// ---------------------------------------------------------------------------
//
// Reads THIS OPERATOR'S most-recent tar.status scan (per-username state),
// queries the response store for that command_id, **filters responses to
// the operator's visible agents**, parses each agent's
// `config|<source>_enabled|false` lines plus the matching paused_at /
// live_rows / oldest_ts companions, and returns an HTML table fragment.
//
// Per-username state + visibility filter together close the Gate 2
// governance HIGH finding (cross-operator data leak via shared scan slot).
//
// Empty states (no scan run yet, scan returned zero rows) render as
// informational placeholders rather than table-with-zero-rows so the
// operator gets actionable guidance.

// #4027: the data-gathering half, extracted from render_tar_retention_paused so the
// HTML fragment renderer below AND the new GET /api/v1/tar/retention-paused REST twin
// + list_tar_retention_paused MCP twin all read the SAME scan state / response store /
// visibility filter exactly once (api-twin-recipe.md Rule 1) rather than the REST/MCP
// surface re-deriving it. `store_degraded` covers BOTH "response_store_ was never
// wired" and "the store was wired but the query itself failed" — the caller (the HTML
// renderer's empty-state branch, or the JSON builder) doesn't need the distinction,
// only "was this data trustworthy."
TarRetentionPausedScan
DashboardRoutes::gather_tar_retention_paused(const std::string& username,
                                             const authz::VisibleSet& extra_scope,
                                             bool extra_scope_is_authoritative) const {
    TarRetentionPausedScan scan;
    {
        std::lock_guard<std::mutex> lk(tar_scan_mu_);
        auto it = tar_scans_by_user_.find(username);
        if (it != tar_scans_by_user_.end()) {
            scan.scan_id = it->second.command_id;
            scan.scan_count = it->second.dispatched_count;
            scan.scan_at = it->second.dispatched_at;
        }
    }
    if (scan.scan_id.empty())
        return scan; // no scan yet for this operator
    if (!response_store_) {
        scan.store_degraded = true;
        return scan;
    }

    // Build the operator's visible-agent allow-set so we can filter the
    // raw response stream against it. Defense-in-depth: even if the scan
    // dispatch already scoped to visible agents, a separate operator who
    // shares the command_id (no longer possible after per-user state but
    // kept for layered safety) still cannot see out-of-scope data.
    // ADR-0042: nullopt (store degraded) → empty visible set (fail-closed: the
    // filter admits nothing rather than the un-scoped raw stream).
    std::unordered_set<std::string> visible_set;
    if (mgmt_group_store_) {
        if (auto visible_ids = mgmt_group_store_->get_visible_agents(username)) {
            visible_set.reserve(visible_ids->size());
            for (auto& v : *visible_ids) visible_set.insert(std::move(v));
        }
    }

    // Pull every response stored for the scan command_id. #2691 (Doomgoose
    // finding #7): still degrades to empty for the row-building logic below
    // (ADR-0039 deny-or-benign), but `store_degraded` is threaded to the
    // empty-state render so "store couldn't be read" doesn't get reported as
    // "every collector is running normally" — the operator-facing claim this
    // view exists to make.
    ResponseQuery q;
    q.limit = 10000;
    auto responses_opt = response_store_->query(scan.scan_id, q);
    scan.store_degraded = !responses_opt.has_value();
    auto responses = responses_opt.value_or(std::vector<StoredResponse>{});

    // Each response is from one agent. Parse each line for
    //   config|<source>_enabled|<value>
    //   config|<source>_paused_at|<ts>
    //   config|<source>_live_rows|<count>
    //   config|<source>_oldest_ts|<ts>
    // and emit one row for every (agent, source) pair where `<source>_enabled` ==
    // "false". Sources with `enabled=true` are dropped — callers want the *paused*
    // set, not the whole fleet.

    // #561 — a malicious or buggy agent can spam many responses under one
    // command_id (no (command_id, agent_id) uniqueness at the write path). Dedup
    // to the most-recent response per agent BEFORE the per-response parse, so
    // render work is bounded to O(visible_agents × sources), not O(responses).
    // (The store-side per-pair cap is the complementary defence.)
    //
    // Recency uses ONLY `received_at_ms` — the SERVER ingest stamp, which the
    // agent cannot forge. We deliberately do NOT fall back to the agent-claimed
    // `timestamp`: a compromised agent could backdate it to make a stale
    // "enabled=true" response win the dedup and hide its actually-paused/errored
    // state (the exact thing #560 surfaces). Legacy pre-v3 rows (received_at_ms
    // == 0) sort as oldest and lose to any stamped response — correct.
    auto resp_recency = [](const StoredResponse& r) -> int64_t { return r.received_at_ms; };
    std::unordered_map<std::string, const StoredResponse*> latest_by_agent;
    latest_by_agent.reserve(responses.size());
    for (const auto& resp : responses) {
        auto [it, inserted] = latest_by_agent.try_emplace(resp.agent_id, &resp);
        if (!inserted && resp_recency(resp) >= resp_recency(*it->second))
            it->second = &resp;
    }

    for (const auto& [dedup_agent_id, resp_ptr] : latest_by_agent) {
        const StoredResponse& resp = *resp_ptr;
        // Visibility gate: drop responses from agents the operator cannot
        // see. If mgmt_group_store_ is unavailable, fail closed (drop all
        // — operator sees an empty list rather than unscoped data).
        // #4027 fix round: `extra_scope` (nullopt/TOP for the HTML fragment
        // caller, `FleetReadGate::scope` for the REST/MCP twins) is ANDed
        // in here for the fragment caller — a row dropped by either axis
        // counts toward `agents_filtered_out_of_scope` the same way, so the
        // honesty counters never silently disagree with what `rows` actually
        // holds.
        //
        // #4143 review fix (BLOCKING): for the REST/MCP twins
        // (`extra_scope_is_authoritative`), `extra_scope` (= `gate.scope`,
        // ADR-0017-authorized) is the SOLE filter — `visible_set`'s
        // direct-membership-only check is skipped, so an ancestor-scoped
        // (not direct-member) admitted operator no longer has their rows
        // silently dropped by the older resolver. See set_all_devices_fn's
        // doc comment (tar_tree_routes.hpp) for the identical rationale on
        // the two device pickers.
        const bool out_of_scope = extra_scope_is_authoritative
                                       ? !authz::in_scope(extra_scope, resp.agent_id)
                                       : (!visible_set.contains(resp.agent_id) ||
                                          !authz::in_scope(extra_scope, resp.agent_id));
        if (out_of_scope) {
            ++scan.agents_filtered_out_of_scope;
            continue;
        }
        ++scan.agents_responded;
        std::unordered_map<std::string, std::string> kv;
        auto lines = split_output_lines(resp.output);
        for (const auto& line : lines) {
            if (!line.starts_with("config|")) continue;
            // line shape: config|<key>|<value>
            auto first_pipe = line.find('|', 7);
            if (first_pipe == std::string::npos) continue;
            std::string key = line.substr(7, first_pipe - 7);
            std::string val = line.substr(first_pipe + 1);
            kv[std::move(key)] = std::move(val);
        }

        bool any_paused_for_this_agent = false;
        // Iterate the four canonical sources. Hardcoding here is fine — these
        // are stable across the project; new sources land via TAR registry
        // changes, and the dashboard list is robust to unknown sources by
        // simply not rendering them (they will surface in PR-A.6 follow-up).
        for (const char* source : {"process", "tcp", "service", "user"}) {
            std::string enabled_key = std::string{source} + "_enabled";
            auto it = kv.find(enabled_key);
            if (it == kv.end()) continue;          // source not reported by this agent
            if (it->second == "true") continue;    // collecting normally — not paused
            // #560 — tri-state: "false" is genuinely paused; ANYTHING ELSE
            // ("errored" from a corrupt/tampered agent DB, or a garbage value)
            // must surface with a value-error badge, NOT be silently dropped
            // (silent omission shows clean state for an actually-paused source).
            const bool value_error = (it->second != "false");

            TarPausedSourceRow row;
            row.agent_id = resp.agent_id;
            row.agent_display = registry_ ? registry_->display_name(resp.agent_id)
                                          : resp.agent_id;
            row.source = source;
            row.value_error = value_error;
            if (value_error)
                row.enabled_raw = it->second;
            if (auto p = kv.find(std::string{source} + "_paused_at");
                p != kv.end()) {
                try { row.paused_at = std::stoll(p->second); } catch (...) {}
            }
            if (auto lr = kv.find(std::string{source} + "_live_rows");
                lr != kv.end()) {
                try { row.live_rows = std::stoll(lr->second); } catch (...) {}
            }
            if (auto ot = kv.find(std::string{source} + "_oldest_ts");
                ot != kv.end()) {
                try { row.oldest_ts = std::stoll(ot->second); } catch (...) {}
            }
            scan.rows.push_back(std::move(row));
            any_paused_for_this_agent = true;
        }
        if (!any_paused_for_this_agent) ++scan.agents_with_no_paused_sources;
    }

    return scan;
}

std::string DashboardRoutes::render_tar_retention_paused(
    const std::string& username, bool can_execute, bool can_delete) const {
    TarRetentionPausedScan scan = gather_tar_retention_paused(username);
    const std::string& scan_id = scan.scan_id;
    const int scan_count = scan.scan_count;
    const int64_t scan_at = scan.scan_at;
    const bool store_degraded = scan.store_degraded;
    const int agents_responded = scan.agents_responded;
    const int agents_with_no_paused_sources = scan.agents_with_no_paused_sources;
    const int agents_filtered_out_of_scope = scan.agents_filtered_out_of_scope;
    // Local, mutable alias (the HTML rendering below sorts in place) so the
    // unchanged HTML-building code (which iterates `rows` and reads
    // `TarPausedSourceRow` fields) needs no further edits.
    std::vector<TarPausedSourceRow>& rows = scan.rows;

    if (scan_id.empty()) {
        return "<div class=\"empty-state\">No scan data yet — click "
               "<strong>Scan fleet</strong> above to query the agents "
               "in your scope for TAR retention state.</div>";
    }

    int64_t now = now_epoch();

    // sre OBS-1: surface retention-paused fleet posture as a gauge per
    // source so SREs can alert on "process retention is paused on N
    // devices" trends. We compute per-source counts here from the
    // already-iterated row set, clearing the gauge family first so an
    // operator's narrowed-by-visibility view doesn't leave stale values
    // when their group composition shrinks.
    if (metrics_) {
        std::unordered_map<std::string, int64_t> per_source_counts{
            {"process", 0}, {"tcp", 0}, {"service", 0}, {"user", 0}};
        for (const auto& r : rows) {
            ++per_source_counts[r.source];
        }
        for (const auto& [src, count] : per_source_counts) {
            metrics_->gauge("yuzu_tar_retention_paused_devices",
                            {{"source", src}})
                .set(static_cast<double>(count));
        }
    }

    // Header showing scan provenance and an honest "responded N of M" count.
    // Includes the in-scope filter so the operator understands the
    // visibility-bounded view.
    std::string html;
    html.reserve(2048);
    html += "<div style=\"margin-bottom:0.75rem;font-size:0.8rem;color:#8b949e\">";
    html += std::format(
        "Scan <code>{}</code> &middot; dispatched to <strong>{}</strong> "
        "agent{} in your scope {} &middot; <strong>{}</strong> in-scope "
        "responded &middot; <strong>{}</strong> have all sources collecting "
        "normally",
        html_escape(scan_id),
        scan_count, scan_count == 1 ? "" : "s",
        format_age(scan_at, now),
        agents_responded,
        agents_with_no_paused_sources);
    if (agents_filtered_out_of_scope > 0) {
        html += std::format(" &middot; <strong>{}</strong> out-of-scope "
                            "agent{} dropped",
                            agents_filtered_out_of_scope,
                            agents_filtered_out_of_scope == 1 ? "" : "s");
    }
    html += "</div>";

    if (rows.empty()) {
        // Distinguish "scan still in progress" from "scan complete and clean"
        // from "the store couldn't be read" — conflating the last with either
        // of the first two tells the operator every collector is fine (or
        // just slow) when the truth is the read failed.
        if (store_degraded) {
            html += "<div class=\"empty-state result-degrade-banner\">"
                    "<b>Retention state unavailable.</b> The response store "
                    "could not be read (Postgres pool/query degraded). This is "
                    "<b>not</b> confirmation every collector is running — "
                    "retry shortly."
                    "</div>";
        } else if (agents_responded < scan_count) {
            html += "<div class=\"empty-state\">"
                    "<strong>No paused sources detected yet.</strong> The "
                    "scan is still in progress — click "
                    "<strong>Refresh</strong> in a moment for more responses."
                    "</div>";
        } else {
            html += "<div class=\"empty-state\">"
                    "<strong>No paused sources detected</strong> &mdash; all "
                    "agents in your scope responded and every collector is "
                    "running normally."
                    "</div>";
        }
        return html;
    }

    // Sort: value-error rows first (they need operator attention), then
    // paused-longest-first, then by agent display name. #558 — an unknown
    // paused_at (0) here means the agent reported the source disabled but never
    // wrote a paused_at (a pre-v0.12.0 agent), i.e. it has been paused at least
    // since that build — it is OLDER than any known-timestamp transition, not
    // newer. The previous `0 ? INT64_MAX` sank these longest-paused sources to
    // the BOTTOM, inverting operator intent; sort 0 as the smallest (oldest)
    // instead so they rank at the top.
    std::sort(rows.begin(), rows.end(),
              [](const TarPausedSourceRow& a, const TarPausedSourceRow& b) {
                  if (a.value_error != b.value_error)
                      return a.value_error; // errors float to the top
                  if (a.paused_at != b.paused_at)
                      return a.paused_at < b.paused_at; // smaller (incl. 0) = older = first
                  return a.agent_display < b.agent_display;
              });

    html += "<table>";
    html += "<thead><tr>"
            "<th>Device</th>"
            "<th>Source</th>"
            "<th>Paused since</th>"
            "<th>Paused for</th>"
            "<th style=\"text-align:right\">Live rows</th>"
            "<th>Oldest data</th>"
            "<th></th>"
            "</tr></thead><tbody>";

    for (const auto& r : rows) {
        html += "<tr>";
        html += "<td>" + html_escape(r.agent_display) + "</td>";
        // #560 — a value-error source carries a badge in the source column so
        // an operator sees that the agent reported a non-canonical enabled value
        // (corruption / tampering / pre-tri-state agent) instead of the source
        // being silently absent from the list.
        if (r.value_error) {
            html += "<td><span class=\"source-pill\">" + html_escape(r.source) +
                    "</span> <span class=\"badge badge-danger\" title=\"agent reported "
                    "&#39;" + html_escape(r.enabled_raw) +
                    "&#39; for this source's enabled flag — expected true/false; check the "
                    "agent's tar.db\">value error</span></td>";
        } else {
            html += "<td><span class=\"source-pill\">" + html_escape(r.source) + "</span></td>";
        }
        // #558 — an agent that reported the source disabled but no paused_at
        // (paused_at == 0) is a pre-v0.12.0 agent that lacks the field. Render an
        // explicit "schema-older-than-server" badge instead of a bare em-dash, so
        // the operator knows the row needs the agent upgraded rather than reading
        // "—" as "unknown / not paused".
        if (r.value_error) {
            html += "<td colspan=\"2\"><span style=\"color:#8b949e\">reported <code>" +
                    html_escape(r.enabled_raw) + "</code></span></td>";
        } else if (r.paused_at == 0) {
            html += "<td colspan=\"2\"><span class=\"badge badge-warning\" title=\"this agent "
                    "predates the paused-since field (v0.12.0); upgrade the agent to record the "
                    "transition time\">schema older than server</span></td>";
        } else {
            html += "<td>" + format_utc(r.paused_at) + "</td>";
            html += "<td>" + format_age(r.paused_at, now) + "</td>";
        }
        html += "<td style=\"text-align:right\">";
        if (r.live_rows < 0) {
            html += "<span style=\"color:#8b949e\">—</span>";
        } else {
            html += std::format("{}", r.live_rows);
        }
        html += "</td>";
        html += "<td>" + format_age(r.oldest_ts, now) + "</td>";
        // Re-enable button: HTMX POST with the device_id + source as form
        // values, swap=delete on the closest tr so the row drops
        // optimistically on success. The next operator-triggered Refresh
        // will reconcile against a fresh tar.status if the agent failed
        // to apply the configure for any reason.
        //
        // hx-vals carries JSON inside an HTML attribute. JSON-escape FIRST
        // (so `"` becomes `\"`) then HTML-escape the result (the browser
        // un-HTML-escapes attribute values *before* HTMX's JSON parser
        // sees them). Skipping the JSON-escape pass here was the Gate 2
        // sec-M3 finding — a malicious agent registering with a `device_id`
        // containing `"` could close the JSON string and inject keys.
        // Effective-permission gating (governance LOW): the POST routes stay
        // authoritative, but only render an action the viewer can actually use —
        // Re-enable needs Execution:Execute, Purge needs the higher Infrastructure:
        // Delete. A read-only / Execute-only operator sees no destructive button.
        html += "<td style=\"text-align:right;white-space:nowrap\">";
        if (can_execute) {
            html += std::format(
                "<button class=\"btn-secondary\" style=\"padding:0.2rem 0.6rem;"
                "font-size:0.75rem\" "
                "hx-post=\"/fragments/tar/retention-paused/reenable\" "
                "hx-vals='{{\"device_id\":\"{}\",\"source\":\"{}\"}}' "
                "hx-target=\"closest tr\" hx-swap=\"delete\" "
                "hx-confirm=\"Re-enable {} collector on {}?\">"
                "Re-enable"
                "</button> ",
                html_escape(json_escape(r.agent_id)), html_escape(json_escape(r.source)),
                html_escape(r.source), html_escape(r.agent_display));
        }
        if (can_delete) {
            // Purge is destructive: a typed-hostname confirm (tarPurgeConfirm, a
            // native prompt) gates it — no hx-confirm. Data via HTML-escaped
            // data-* attrs (read by the JS), never interpolated into script.
            html += std::format(
                "<button class=\"btn-danger\" style=\"padding:0.2rem 0.6rem;"
                "font-size:0.75rem\" "
                "data-device=\"{}\" data-host=\"{}\" data-source=\"{}\" "
                "onclick=\"tarPurgeConfirm(this)\" "
                "title=\"Permanently delete this source's stored data (source stays "
                "paused)\">"
                "Purge data"
                "</button>",
                html_escape(r.agent_id), html_escape(r.agent_display), html_escape(r.source));
        }
        if (!can_execute && !can_delete) {
            html += "<span class=\"tar-row-note\">&mdash;</span>";
        }
        html += "</td>";
        html += "</tr>";
    }
    html += "</tbody></table>";

    if (agents_responded < scan_count) {
        html += std::format(
            "<div style=\"margin-top:0.75rem;font-size:0.75rem;color:#8b949e\">"
            "{} of {} agent{} still pending — click "
            "<strong>Refresh</strong> to pick up additional responses.</div>",
            scan_count - agents_responded, scan_count,
            scan_count == 1 ? "" : "s");
    }

    return html;
}

} // namespace yuzu::server
