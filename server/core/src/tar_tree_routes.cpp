/// @file tar_tree_routes.cpp
/// Route registration for the TAR process-tree viewer (Frame 3 of `/tar`).
/// See tar_tree_routes.hpp for the auth/caching contract.

#include "tar_tree_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial, detail::a4_error, make_correlation_id
#include "rest_audit.hpp"     // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)
#include "secure_random.hpp" // random_hex (CSPRNG cache token, #801)
#include "web_utils.hpp"      // html_escape, audit_token, now_epoch_seconds

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <format>
#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {
using json = nlohmann::json;

// A4 success envelope — mirrors rest_api_v1.cpp's `ok_json` (rest_api_v1.cpp:211):
// takes an ALREADY-SERIALIZED JSON `data` payload and wraps it, no re-parse. Not
// shared via a header (see docs/api-twin-recipe.md §2: `ok_json`/`list_json` are
// rest_api_v1.cpp-local; other self-registering `*_routes.cpp` modules —
// ca_routes.cpp, viz_routes.cpp — each hand-roll their own envelope the same way
// rather than reach across translation units for it).
std::string ok_json(std::string_view data_json) {
    return std::string("{\"data\":") + std::string(data_json) +
          ",\"meta\":{\"api_version\":\"v1\"}}";
}

// Percent-encode for query values (mirrors device_routes' url_enc).
std::string url_enc(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += static_cast<char>(c);
        else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

void note(httplib::Response& res, const std::string& text) {
    res.set_content("<div class=\"tar-tree-note\">" + text + "</div>", "text/html; charset=utf-8");
}

std::string get_param(const httplib::Request& req, const char* k) {
    return req.has_param(k) ? req.get_param_value(k) : std::string{};
}
// parse_ts_param lives in tar_process_tree.{hpp,cpp} (pure + unit-tested).
// The reconstruction cache token is a CSPRNG hex string (random_hex, secure_random.hpp,
// #801) minted at the /result generation site — never a std::mt19937_64 value.

// One device's OS string via the unscoped lookup (for the names-only caption).
std::string device_os(const std::optional<DeviceRow>& d) { return d ? d->os : std::string{}; }

// The server-rendered toolbar + targets (Frame-3 body). Host options come from the
// operator-scoped device list. Preset chips hx-get /run with the preset in the URL
// and the host via hx-include; the Apply chip also includes the custom inputs.
std::string render_frame(const std::vector<DeviceRow>& devices) {
    std::string h;
    h += "<div class=\"tar-tree-toolbar\">";
    // Host picker.
    h += "<select id=\"tar-tree-host\" name=\"device\" class=\"scope-chip-select\" "
         "hx-get=\"/fragments/tar/process-tree/run?preset=10m\" hx-target=\"#tar-tree\" "
         "hx-trigger=\"change\">";
    h += "<option value=\"\">Select a host\xE2\x80\xA6</option>";
    std::vector<DeviceRow> rows = devices;
    std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
        return (a.hostname.empty() ? a.agent_id : a.hostname) <
               (b.hostname.empty() ? b.agent_id : b.hostname);
    });
    for (const auto& d : rows) {
        if (!d.online)
            continue;
        const std::string label = (d.hostname.empty() ? d.agent_id : d.hostname) +
                                  (d.os.empty() ? "" : (" (" + d.os + ")"));
        h += "<option value=\"" + html_escape(d.agent_id) + "\">" + html_escape(label) + "</option>";
    }
    h += "</select>";

    // Preset chips.
    const std::array<std::pair<const char*, const char*>, 6> presets = {{{"on_boot", "On boot"},
                                                                         {"on_install", "On agent install"},
                                                                         {"1m", "Last minute"},
                                                                         {"10m", "Last 10m"},
                                                                         {"1h", "Last hour"},
                                                                         {"1d", "Last day"}}};
    h += "<div class=\"tar-tree-presets\">";
    for (const auto& [tok, label] : presets) {
        h += std::string("<a class=\"tar-chip\" hx-get=\"/fragments/tar/process-tree/run?preset=") +
             tok + "\" hx-include=\"#tar-tree-host\" hx-target=\"#tar-tree\">" + label + "</a>";
    }
    h += "</div>";

    // Custom from/to (UTC) + Apply.
    h += "<div class=\"tar-tree-custom\">";
    h += "<label>From (UTC) <input id=\"tar-tree-from\" name=\"from\" type=\"datetime-local\"></label>";
    h += "<label>To (UTC) <input id=\"tar-tree-to\" name=\"to\" type=\"datetime-local\"></label>";
    h += "<a class=\"tar-chip\" hx-get=\"/fragments/tar/process-tree/run?preset=custom\" "
         "hx-include=\"#tar-tree-host,#tar-tree-from,#tar-tree-to\" hx-target=\"#tar-tree\">Apply</a>";
    h += "</div>";

    h += "</div>"; // toolbar (host + time range)

    // Filter bar — client-side state + anomalies + text filters (no round-trip;
    // re-applied after every tree swap via the htmx:afterSettle listener).
    h += "<div class=\"tar-tree-filterbar\">";
    h += "<span class=\"tt-filter-label\">Show</span>";
    h += "<a class=\"tar-chip on\" data-statechip=\"all\" onclick=\"tarTreeState('all',this)\">All</a>";
    h += "<a class=\"tar-chip\" data-statechip=\"running\" onclick=\"tarTreeState('running',this)\">"
         "Running</a>";
    h += "<a class=\"tar-chip\" data-statechip=\"exited\" onclick=\"tarTreeState('exited',this)\">"
         "Exited</a>";
    h += "<label class=\"tt-anom-toggle\"><input type=\"checkbox\" id=\"tar-tree-anom-only\" "
         "onchange=\"applyTarTreeFilters()\"> Anomalies only</label>";
    h += "<input id=\"tar-tree-filter\" class=\"tar-tree-filter\" type=\"text\" "
         "placeholder=\"Filter name / IP / PID\xE2\x80\xA6\" oninput=\"applyTarTreeFilters()\">";
    h += "</div>";

    // Two-column layout: scrollable tree on the left, a sticky always-visible detail
    // panel on the right (stacks on narrow viewports).
    h += "<div class=\"tar-tree-layout\">";
    h += "<div class=\"tar-tree-main\"><div id=\"tar-tree\"><div class=\"tar-tree-empty\">Pick a host "
         "and a timescale to reconstruct its point-in-time process tree.</div></div></div>";
    h += "<aside class=\"tar-tree-side\"><div id=\"tar-tree-detail\"><div class=\"tar-tree-mute\">"
         "Select a process to see its path, user, connections and anomaly evidence.</div></div></aside>";
    h += "</div>";

    // Device-level DNS cache + ARP table panels (ADR-0015). Loaded when the host
    // picker changes — htmx `from:` selector fires this alongside the tree run, with
    // no hx-on (CSP-safe). Device view, NOT per-process (the DNS cache carries no pid).
    h += "<div id=\"tar-devnet\" hx-get=\"/fragments/tar/process-tree/device-net\" "
         "hx-include=\"#tar-tree-host\" hx-trigger=\"change from:#tar-tree-host\" "
         "hx-swap=\"innerHTML\"></div>";
    return h;
}

// The self-re-issuing polling fragment (mirrors device live_pending).
std::string tree_pending(const std::string& device, const std::string& preset,
                         const std::string& from, const std::string& to,
                         const std::string& pcmd, const std::string& tcmd, int attempt) {
    // Explicit hx-target="this" so the poll replaces ITSELF (inside #tar-tree) and
    // never inherits an ancestor's hx-target — otherwise the outerHTML swap would
    // clobber the whole frame body, taking the toolbar with it.
    return "<div hx-get=\"/fragments/tar/process-tree/result?device=" + url_enc(device) +
           "&amp;preset=" + url_enc(preset) + "&amp;from=" + url_enc(from) + "&amp;to=" +
           url_enc(to) + "&amp;pcmd=" + url_enc(pcmd) + "&amp;tcmd=" + url_enc(tcmd) +
           "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:700ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"tar-tree-loading\">Reconstructing the process tree\xE2\x80\xA6</div>";
}

// Self-re-issuing poll for the device-net (DNS cache + ARP table) panels (ADR-0015).
// Carries both dispatched command_ids; ready when DNS + ARP queries both complete.
std::string devnet_pending(const std::string& device, const std::string& dcmd,
                           const std::string& acmd, int attempt) {
    return "<div hx-get=\"/fragments/tar/process-tree/device-net?device=" + url_enc(device) +
           "&amp;dcmd=" + url_enc(dcmd) + "&amp;acmd=" + url_enc(acmd) +
           "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:700ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"tar-tree-loading\">Loading device DNS / ARP\xE2\x80\xA6</div>";
}

// Capture-sources frame body: device picker (operator-scoped) + a target the table
// loads into on host change. Mirrors render_frame's picker (ADR-0015).
std::string render_cap_frame(const std::vector<DeviceRow>& devices) {
    std::string h = "<div class=\"picker-row\"><label for=\"cap-host\">Device</label>";
    h += "<select id=\"cap-host\" name=\"device\" class=\"scope-chip-select\" "
         "hx-get=\"/fragments/tar/capture-sources/load\" hx-target=\"#cap-sources-body\" "
         "hx-trigger=\"change\"><option value=\"\">Select a host\xE2\x80\xA6</option>";
    std::vector<DeviceRow> rows = devices;
    std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
        return (a.hostname.empty() ? a.agent_id : a.hostname) <
               (b.hostname.empty() ? b.agent_id : b.hostname);
    });
    for (const auto& d : rows) {
        if (!d.online)
            continue;
        const std::string label =
            (d.hostname.empty() ? d.agent_id : d.hostname) + (d.os.empty() ? "" : (" (" + d.os + ")"));
        h += "<option value=\"" + html_escape(d.agent_id) + "\">" + html_escape(label) + "</option>";
    }
    h += "</select><span class=\"src-note\">Toggling <b>stages</b> a change \xE2\x80\x94 nothing is "
         "sent until you <b>Push</b> (a guardrail against accidentally enabling a source).</span></div>";
    h += "<div id=\"cap-sources-body\"><div class=\"tar-tree-empty\">Select a host to view and manage "
         "its capture sources.</div></div>";
    return h;
}

// Self-re-issuing poll for the capture-sources table (carries the status + compat
// command_ids; ready when both complete).
std::string cap_pending(const std::string& device, const std::string& scmd, const std::string& ccmd,
                        int attempt) {
    return "<div hx-get=\"/fragments/tar/capture-sources/load?device=" + url_enc(device) +
           "&amp;scmd=" + url_enc(scmd) + "&amp;ccmd=" + url_enc(ccmd) +
           "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:600ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"tar-tree-loading\">Loading capture sources\xE2\x80\xA6</div>";
}

// Poll one dispatched command for `device`: ready when it has output OR a terminal
// status. Returns {ready, output, failed, error}.
struct PollResult {
    bool ready = false;
    bool failed = false;
    std::string output;
    std::string error;
};
PollResult poll_command(const TarTreeRoutes::ResponsesFn& responses_fn, const std::string& command_id,
                        const std::string& device) {
    PollResult pr;
    if (!responses_fn)
        return pr;
    // #1634: scope the poll read at the store seam (q.agent_id); the post-filter
    // on `device` below is retained as defense-in-depth.
    const auto rows = responses_fn(command_id, device);
    const DexAgentResponse* with_output = nullptr;
    const DexAgentResponse* terminal = nullptr;
    for (const auto& r : rows) {
        if (r.agent_id != device)
            continue;
        if (!r.output.empty())
            with_output = &r;
        if (r.status >= 1)
            terminal = &r;
    }
    if (with_output) {
        pr.ready = true;
        pr.output = with_output->output;
        return pr;
    }
    if (terminal) {
        pr.ready = true; // completed, possibly with no rows
        if (terminal->status >= 2) {
            pr.failed = true;
            pr.error = terminal->error_detail;
        }
        return pr;
    }
    return pr;
}

} // namespace

namespace {

// Shared row shape behind BOTH tar_process_tree_frame_json and
// tar_capture_sources_devices_json — the two public builders are separate names
// (matching the AC's own naming; the two frames are distinct capabilities) but must
// not become two independently-maintained JSON shapes for the same DeviceRow (Rule
// 1). Sort matches render_frame/render_cap_frame's own device sort (display name
// ascending) so the JSON twin and the HTML picker present devices in the same order.
std::string device_picker_json(const std::vector<DeviceRow>& devices) {
    std::vector<DeviceRow> rows = devices;
    std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
        return (a.hostname.empty() ? a.agent_id : a.hostname) <
               (b.hostname.empty() ? b.agent_id : b.hostname);
    });
    json arr = json::array();
    for (const auto& d : rows) {
        arr.push_back({{"agent_id", d.agent_id},
                       {"hostname", d.hostname},
                       {"os", d.os},
                       {"arch", d.arch},
                       {"agent_version", d.agent_version},
                       {"online", d.online}});
    }
    return arr.dump();
}

} // namespace

std::string tar_process_tree_frame_json(const std::vector<DeviceRow>& devices) {
    return device_picker_json(devices);
}

std::string tar_capture_sources_devices_json(const std::vector<DeviceRow>& devices) {
    return device_picker_json(devices);
}

std::string tar_retention_paused_json(const TarRetentionPausedScan& scan) {
    // Same sort as DashboardRoutes::render_tar_retention_paused: value-error rows
    // float to the top, then oldest-paused-first (0 == oldest, per #558), then by
    // display name — kept in lockstep with the HTML renderer's own std::sort so the
    // two surfaces agree on row order (see gather_tar_retention_paused's doc comment
    // for why the SORT itself still lives twice: the HTML renderer sorts its own
    // internal PausedRow vector, and duplicating a five-line comparator is far lower
    // risk than threading a shared-order guarantee through two different row types).
    std::vector<TarPausedSourceRow> rows = scan.rows;
    std::sort(rows.begin(), rows.end(),
              [](const TarPausedSourceRow& a, const TarPausedSourceRow& b) {
                  if (a.value_error != b.value_error)
                      return a.value_error;
                  if (a.paused_at != b.paused_at)
                      return a.paused_at < b.paused_at;
                  return a.agent_display < b.agent_display;
              });
    json rows_json = json::array();
    for (const auto& r : rows) {
        rows_json.push_back({{"agent_id", r.agent_id},
                             {"agent_display", r.agent_display},
                             {"source", r.source},
                             {"paused_at", r.paused_at},
                             {"live_rows", r.live_rows},
                             {"oldest_ts", r.oldest_ts},
                             {"value_error", r.value_error},
                             {"enabled_raw", r.enabled_raw}});
    }
    return json{{"scan_id", scan.scan_id},
               {"scan_count", scan.scan_count},
               {"scan_at", scan.scan_at},
               {"agents_responded", scan.agents_responded},
               {"agents_with_no_paused_sources", scan.agents_with_no_paused_sources},
               {"agents_filtered_out_of_scope", scan.agents_filtered_out_of_scope},
               {"store_degraded", scan.store_degraded},
               {"rows", rows_json}}
        .dump();
}

bool TarTreeRoutes::deny_fleet_wide_device_enumeration(const httplib::Request& req,
                                                       httplib::Response& res,
                                                       std::optional<auth::Session>* out_session) {
    auto session = auth_fn_(req, res);
    if (!session) {
        // #4027 fix (adversarial review round 1, CDX-P1-03/K2): `auth_fn_`
        // (require_auth) already wrote a correct A4 JSON 401 body onto `res`
        // — do NOT overwrite it with plain text here. This helper feeds both
        // the pre-existing HTML fragment routes and the new `/api/v1/tar/*`
        // JSON REST twins; the fragments already accept a JSON error body on
        // their 403 path (see `deny_fleet_wide_device_enumeration`'s own 403
        // branch just below, and `/fragments/results`' identical convention
        // in dashboard_routes.cpp), so this is not a new content-type
        // surprise for an HTMX consumer — just a return-without-overwrite.
        return true;
    }
    if (!session->token_scope_service.empty()) {
        // Write the 403 FIRST, audit after (normalized — #3167). `.permission`
        // omitted: kServiceScopeGlobalSafe is compile-time-empty, so no grant admits
        // a service-scoped caller here; naming one would be a false
        // self-remediation claim.
        res.status = 403;
        res.set_content(
            detail::a4_denial(res, 403,
                              "service-scoped tokens may not read the fleet-wide device list"),
            "application/json");
        (void)detail::try_persist_audit(
            audit_fn_, req, "tar.device_picker.view", "denied", "Infrastructure", "",
            "fleet-wide TAR device picker denied to a service-scoped token "
            "(path=" + req.path + ")");
        return true;
    }
    if (out_session)
        *out_session = std::move(session);
    return false;
}

void TarTreeRoutes::cache_put(const std::string& token, ReconEntry entry) {
    std::lock_guard<std::mutex> lk(cache_mu_);
    const std::int64_t now = now_epoch_seconds();
    // Drop expired entries opportunistically.
    for (auto it = cache_order_.begin(); it != cache_order_.end();) {
        auto e = cache_.find(*it);
        if (e == cache_.end() || now - e->second.created > kCacheTtlSeconds) {
            if (e != cache_.end())
                cache_.erase(e);
            it = cache_order_.erase(it);
        } else {
            ++it;
        }
    }
    cache_[token] = std::move(entry);
    cache_order_.push_back(token);
    while (cache_.size() > kCacheCap && !cache_order_.empty()) {
        cache_.erase(cache_order_.front());
        cache_order_.pop_front();
    }
}

std::optional<std::string> TarTreeRoutes::cache_render_detail(const std::string& token,
                                                              std::size_t node_id,
                                                              std::string* out_device_id) {
    std::lock_guard<std::mutex> lk(cache_mu_);
    auto it = cache_.find(token);
    if (it == cache_.end())
        return std::nullopt;
    if (now_epoch_seconds() - it->second.created > kCacheTtlSeconds) {
        cache_.erase(it);
        return std::nullopt;
    }
    const ReconEntry& e = it->second;
    if (out_device_id)
        *out_device_id = e.device_id;
    if (node_id >= e.tree.nodes.size())
        return std::string("<div class=\"tar-tree-note\">That process is no longer in the "
                           "reconstruction. Re-run the tree.</div>");
    const TarProcNode& node = e.tree.nodes[node_id];
    std::vector<TarTcpConn> conns;
    for (const auto& c : e.conns)
        if (c.pid == node.pid)
            conns.push_back(c);
    std::sort(conns.begin(), conns.end(),
              [](const TarTcpConn& a, const TarTcpConn& b) { return a.ts > b.ts; });
    return render_tar_proc_detail(node, conns, e.os);
}

void TarTreeRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                    ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                    LookupFn lookup_fn, DispatchFn dispatch_fn,
                                    ResponsesFn responses_fn, AuditFn audit_fn,
                                    CallerFn caller_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(devices_fn), std::move(lookup_fn), std::move(dispatch_fn),
                    std::move(responses_fn), std::move(audit_fn), std::move(caller_fn));
}

void TarTreeRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                    ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                    LookupFn lookup_fn, DispatchFn dispatch_fn,
                                    ResponsesFn responses_fn, AuditFn audit_fn,
                                    CallerFn caller_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    devices_fn_ = std::move(devices_fn);
    lookup_fn_ = std::move(lookup_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);
    audit_fn_ = std::move(audit_fn);
    caller_fn_ = std::move(caller_fn);

    // Soft Execute probe (htmx swallows a raw 403 → render an in-panel note instead).
    auto can_execute = [this](const httplib::Request& req, const std::string& id) {
        httplib::Response probe;
        return scoped_perm_fn_ && scoped_perm_fn_(req, probe, "Execution", "Execute", id);
    };

    // -- Frame body: toolbar + targets (host list is operator-scoped). --
    // #4027 fix round (recorded exception, Kimi K4): stays on perm_fn_, NOT
    // migrated to fleet_read_fn_ this round — out of scope (this round fixes
    // only the six brand-new #4027 list surfaces: the two REST device-picker
    // twins below, the REST retention twin, and their three MCP tools). This
    // pre-existing HTML fragment route shares the exact same bare-
    // require_permission gap the REST twin below no longer has; migrating it
    // is a deliberate follow-up, not an oversight.
    sink.Get("/fragments/tar/process-tree", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        std::optional<auth::Session> session;
        if (deny_fleet_wide_device_enumeration(req, res, &session))
            return;
        if (!perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        std::vector<DeviceRow> devices =
            devices_fn_ ? devices_fn_(session->username) : std::vector<DeviceRow>{};
        res.set_content(render_frame(devices), "text/html; charset=utf-8");
    });

    // -- REST v1 twin: fleet device list, JSON (#4027). Gate sequence:
    // deny_fleet_wide_device_enumeration (service-scoped tokens denied outright,
    // unchanged), THEN fleet_read_fn_ — the ADR-0017 admit-then-filter chokepoint
    // (#4027 fix round, CDX-P1-01/K4), NOT perm_fn_. perm_fn_/require_permission is
    // a bare GLOBAL grant check that 403s a caller whose Infrastructure:Read is
    // management-group-scoped before any row source ever runs (auth_routes.hpp's
    // own require_list_read doc comment names this exact stacking mistake);
    // fleet_read_fn_/require_fleet_read admits that caller with a real, composed
    // meet(management-group, service-scope) VisibleSet instead. The
    // unaudited-on-success posture is unchanged — a device identity/online list,
    // not per-device behavioral content (api-twin-recipe.md's
    // list_software_deployments precedent).
    //
    // #4143 review fix (external colleague review, BLOCKING, confirmed against
    // ADR-0017 INV-4/INV-7 by direct source inspection): gate.scope is now the
    // SOLE filter, applied over an UNFILTERED registry snapshot (all_devices_fn_ —
    // the SAME source GET /api/v1/devices (#4033) and MCP's list_agents read
    // from), not an intersection with devices_fn_'s older, direct-membership-only
    // pre-filter. The prior "intersection, never widens" design let admit and the
    // row filter disagree for a management-group-scoped-but-not-direct-member
    // grant (INV-4) via two divergent resolvers (INV-7) — a real defect, not a
    // merely-conservative one: an ADMITTED operator seeing an incomplete/empty
    // list is a functional-correctness break. devices_fn_ remains wired for the
    // un-migrated fragment route above only (see its own registration comment).
    sink.Get("/api/v1/tar/process-tree", [this](const httplib::Request& req,
                                                httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        std::optional<auth::Session> session;
        if (deny_fleet_wide_device_enumeration(req, res, &session))
            return;
        if (!fleet_read_fn_ || !all_devices_fn_) {
            spdlog::error("tar.process_tree.device_picker: fleet_read_fn_/"
                          "all_devices_fn_ unwired — misconfigured call site; "
                          "failing closed; cid={}", cid);
            res.status = 503;
            res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                            "application/json");
            return;
        }
        auto gate = fleet_read_fn_(req, res, "Infrastructure", "Read");
        if (!gate.admitted)
            return; // gate already wrote the A4 error body + status
        std::vector<DeviceRow> devices = all_devices_fn_();
        if (gate.scope) {
            std::vector<DeviceRow> visible;
            visible.reserve(devices.size());
            for (auto& d : devices)
                if (authz::in_scope(gate.scope, d.agent_id))
                    visible.push_back(std::move(d));
            devices.swap(visible);
        }
        res.set_content(
            ok_json(std::string("{\"devices\":") + tar_process_tree_frame_json(devices) + "}"),
            "application/json");
    });

    // -- Run: scope + execute gate -> dispatch two canned tar.sql -> poll fragment. --
    sink.Get("/fragments/tar/process-tree/run", [this, can_execute](const httplib::Request& req,
                                                                    httplib::Response& res) {
        const std::string device = get_param(req, "device");
        const std::string preset = get_param(req, "preset");
        const std::string from = get_param(req, "from");
        const std::string to = get_param(req, "to");
        if (device.empty()) {
            note(res, "Select a host to reconstruct its process tree.");
            return;
        }
        // Per-device scoped Read floor (tier + management group).
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Reconstructing the tree dispatches a read-only query to the device and "
                      "needs the <b>Execute</b> permission.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query is unavailable on this server.");
            return;
        }
        // SQL fetch is bounded only at the TOP (ts <= to) for a custom `to`; the lower
        // bound stays oldest-retained so a long-running process started before the
        // window is still captured (the engine applies `from` as an interval filter).
        std::int64_t fetch_to = 0;
        if (preset == "custom")
            fetch_to = parse_ts_param(to);
        // SECURITY: `fetch_to` is interpolated into the tar.sql query STRING handed to
        // the agent. The agent forbids parameterized/recursive CTEs, so there is NO
        // bind-parameter path here — this is safe ONLY because `fetch_to` is a
        // std::int64_t produced by parse_ts_param (digits → number, never a string).
        // Never interpolate a string-typed value into this query without an
        // allowlist / quote-escape; doing so would be SQL injection into tar.sql.
        const std::string where = fetch_to > 0 ? std::format(" WHERE ts <= {}", fetch_to) : "";
        const std::string psql =
            "SELECT ts, action, pid, ppid, name, cmdline, user FROM $Process_Live" + where +
            " ORDER BY ts DESC LIMIT 100000";
        const std::string tsql =
            "SELECT pid, process_name, proto, local_port, remote_addr, remote_port, state, ts, "
            "action FROM $TCP_Live" +
            where + " ORDER BY ts DESC LIMIT 5000";
        const auto caller = caller_fn_(req);
        const auto pout = dispatch_fn_("tar", "sql", {device}, "", {{"sql", psql}}, caller);
        const auto tout = dispatch_fn_("tar", "sql", {device}, "", {{"sql", tsql}}, caller);
        const auto& pcmd = pout.command_id;
        const auto psent = pout.sent;
        const auto& tcmd = tout.command_id;
        const auto tsent = tout.sent;
        // Audit at DISPATCH (parity with device-live-info / DEX-perf): the live query
        // hitting the endpoint is the access event and must be recorded even when it
        // reaches no agent or the later poll never completes. Shared #1647 chokepoint:
        // catches a throwing audit_fn (catch-arm parity) and surfaces Sec-Audit-Failed
        // on a dropped row; dispatch/render posture unchanged (still renders below).
        (void)detail::emit_behavioral_audit(
            audit_fn_, req, res, "tar.process_tree.read", psent > 0 ? "dispatched" : "no_agents",
            "Agent", device,
            std::format("dispatch preset={} command_id={}", canonical_tar_preset(preset),
                        audit_token(pcmd)));
        if (psent == 0 || tsent == 0) {
            note(res, "Device offline \xE2\x80\x94 the process tree needs a connected agent.");
            return;
        }
        res.set_content(tree_pending(device, preset, from, to, pcmd, tcmd, 1),
                        "text/html; charset=utf-8");
    });

    // -- Result: poll both commands -> reconstruct -> cache -> render tree. --
    sink.Get("/fragments/tar/process-tree/result", [this, can_execute](const httplib::Request& req,
                                                                        httplib::Response& res) {
        // Resolve the session up front: the reconstruction cache binds to the
        // originating principal so a leaked token can't be replayed by another
        // operator (an unauthenticated poll must 401, not render a fragment).
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string device = get_param(req, "device");
        const std::string preset = get_param(req, "preset");
        const std::string from = get_param(req, "from");
        const std::string to = get_param(req, "to");
        const std::string pcmd = get_param(req, "pcmd");
        const std::string tcmd = get_param(req, "tcmd");
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Live device query needs the <b>Execute</b> permission.");
            return;
        }
        // Only tar.sql commands for the named agent are pollable here.
        if (device.empty() || pcmd.size() > 64 || tcmd.size() > 64 ||
            !pcmd.starts_with("tar-") || !tcmd.starts_with("tar-")) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query is unavailable on this server.");
            return;
        }
        constexpr int kMaxAttempts = 40;      // ~28s at 700ms — overall budget
        constexpr int kTcpGraceAttempts = 12; // ~8s — then render the tree WITHOUT
                                              // connections rather than let a hung TCP
                                              // query block the whole process view.
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, kMaxAttempts);
            } catch (...) {
            }
        }
        const PollResult proc = poll_command(responses_fn_, pcmd, device);
        const PollResult tcp = poll_command(responses_fn_, tcmd, device);
        // The process query is essential; the TCP query is best-effort past its grace.
        const bool tcp_done = tcp.ready || attempt >= kTcpGraceAttempts;
        if (!proc.ready || !tcp_done) {
            if (attempt >= kMaxAttempts) {
                note(res, "No response from the device (timed out) \xE2\x80\x94 it may have gone "
                          "offline. Re-run to retry.");
                return;
            }
            res.set_content(tree_pending(device, preset, from, to, pcmd, tcmd, attempt + 1),
                            "text/html; charset=utf-8");
            return;
        }
        if (proc.failed) {
            note(res, "The device failed the process query: " + html_escape(proc.error.substr(0, 200)));
            return;
        }
        if (proc.output.starts_with("error|")) {
            note(res, "The device reported an error: " + html_escape(proc.output.substr(6, 200)));
            return;
        }

        // Defense-in-depth byte cap before parse (a compromised agent controls
        // proc.output; gRPC already bounds the message, but don't rely on it). Reject
        // an over-cap process payload rather than truncate — a torn process stream
        // produces phantom roots, so an honest "narrow the timescale" is better.
        if (proc.output.size() > kMaxTarProcOutputBytes) {
            note(res, "The device returned an unexpectedly large process dataset for this "
                      "window. Narrow the timescale and re-run.");
            return;
        }

        // TCP is included only if it completed cleanly AND fits the byte cap; otherwise
        // the tree still renders (without inline per-process connections) and says so.
        const bool tcp_ok = tcp.ready && !tcp.failed && !tcp.output.starts_with("error|") &&
                            tcp.output.size() <= kMaxTarTcpOutputBytes;
        auto events = parse_tar_process_output(proc.output);
        auto conns = tcp_ok ? parse_tar_tcp_output(tcp.output) : std::vector<TarTcpConn>{};
        const auto anchors = compute_tar_anchors(events);
        const std::int64_t now = now_epoch_seconds();
        const TarWindow win =
            resolve_tar_window(preset, parse_ts_param(from), parse_ts_param(to), anchors, now);
        auto tree = reconstruct_tar_process_tree(events, win.from_ts, win.to_ts, anchors);

        const std::string os = device_os(lookup_fn_ ? lookup_fn_(device) : std::nullopt);
        // CSPRNG cache token (#801). random_hex(16) → 32 lowercase hex chars, matching
        // the /detail token-format check. On entropy failure surface an in-panel error
        // and record a `failure` audit (the SOC2 CC7.2/7.3 evidence row) — we do NOT
        // 503 (htmx suppresses the swap on a non-2xx response, so the operator would
        // see nothing) and we never cache a half-built entry under a weak token.
        auto token_exp = random_hex(16);
        if (!token_exp) {
            (void)detail::emit_behavioral_audit(audit_fn_, req, res, "tar.process_tree.read",
                                                "failure", "Agent", device, "csprng_unavailable");
            note(res, "The server could not generate a secure token for this reconstruction "
                      "(entropy temporarily unavailable). Retry in a few seconds.");
            return;
        }
        const std::string token = std::move(*token_exp);
        const int node_count = tree.running_count + tree.exited_count;
        const int anomaly_count = tree.anomaly_count;

        // Full tree, rendered once; running/exited/anomalies/text filtering is applied
        // client-side from the toolbar (each row carries data-state/data-anom), so a
        // filter toggle needs no re-dispatch.
        std::string body;
        if (!tcp_ok)
            body += "<div class=\"tar-tree-warn\">Connection data was unavailable for this host; "
                    "the process tree is shown without per-process network info.</div>";
        body += render_tar_tree_fragment(tree, conns, device, token, os);

        ReconEntry entry;
        entry.device_id = device;
        entry.principal = session->username; // fail-closed binding for /detail replay
        entry.os = os;
        entry.conns = std::move(conns);
        entry.tree = std::move(tree);
        entry.created = now;
        cache_put(token, std::move(entry));

        // Record the data class exposed (works-council access-audit posture): `os`
        // distinguishes a names-only Windows read from a behavioral Linux/macOS read
        // (which carries command lines); `conns` flags whether connection data was shown.
        (void)detail::emit_behavioral_audit(
            audit_fn_, req, res, "tar.process_tree.read", "success", "Agent", device,
            std::format("preset={} from={} to={} nodes={} anomalies={} os={} conns={}",
                        canonical_tar_preset(preset), win.from_ts, win.to_ts, node_count,
                        anomaly_count, normalize_tar_os(os), tcp_ok ? 1 : 0));
        res.set_content(body, "text/html; charset=utf-8");
    });

    // -- Device-net panels: DNS cache + ARP table for the selected host (ADR-0015).
    // Dispatches two canned read-only tar.sql ($DNS_Live, $ARP_Live), polls, renders
    // DEVICE-level panels (never per-process — the DNS cache has no pid). Same scoped
    // Read + Execute-probe tier as the tree run; audits tar.dns.read / tar.arp.read as
    // DISTINCT verbs (DNS is usage-class PII, kept separately countable). --
    sink.Get("/fragments/tar/process-tree/device-net", [this, can_execute](
                                                            const httplib::Request& req,
                                                            httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string device = get_param(req, "device");
        if (device.empty()) {
            res.set_content("", "text/html; charset=utf-8"); // no host picked yet
            return;
        }
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Live device DNS/ARP needs the <b>Execute</b> permission.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query is unavailable on this server.");
            return;
        }
        std::string dcmd = get_param(req, "dcmd");
        std::string acmd = get_param(req, "acmd");
        if (dcmd.empty() || acmd.empty()) {
            // First call: dispatch the two queries (newest-first; the render reduces the
            // appeared/removed stream to the current cache).
            const std::string dsql =
                "SELECT name, record_type, data, ttl_remaining_s, source, ts, action "
                "FROM $DNS_Live ORDER BY ts DESC LIMIT 20000";
            const std::string asql =
                "SELECT interface, ip_address, mac_address, entry_type, ts, action "
                "FROM $ARP_Live ORDER BY ts DESC LIMIT 20000";
            const auto caller = caller_fn_(req);
            const auto dout = dispatch_fn_("tar", "sql", {device}, "", {{"sql", dsql}}, caller);
            const auto aout = dispatch_fn_("tar", "sql", {device}, "", {{"sql", asql}}, caller);
            const auto& dc = dout.command_id;
            const auto dsent = dout.sent;
            const auto& ac = aout.command_id;
            const auto asent = aout.sent;
            // Shared #1647 chokepoint: catch-arm parity + Sec-Audit-Failed per verb
            // (DNS is usage-class PII, kept separately countable). Dispatch posture
            // unchanged; if either evidence row drops, the header is set.
            (void)detail::emit_behavioral_audit(audit_fn_, req, res, "tar.dns.read",
                                                dsent > 0 ? "dispatched" : "no_agents", "Agent",
                                                device,
                                                std::format("command_id={}", audit_token(dc)));
            (void)detail::emit_behavioral_audit(audit_fn_, req, res, "tar.arp.read",
                                                asent > 0 ? "dispatched" : "no_agents", "Agent",
                                                device,
                                                std::format("command_id={}", audit_token(ac)));
            if (dsent == 0 || asent == 0) {
                note(res, "Device offline \xE2\x80\x94 the DNS/ARP panels need a connected agent.");
                return;
            }
            res.set_content(devnet_pending(device, dc, ac, 1), "text/html; charset=utf-8");
            return;
        }
        // Poll: validate the command-id shape (same guard as the tree result route).
        if (dcmd.size() > 64 || acmd.size() > 64 || !dcmd.starts_with("tar-") ||
            !acmd.starts_with("tar-")) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        constexpr int kMaxAttempts = 30; // ~21s at 700ms
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, kMaxAttempts);
            } catch (...) {
            }
        }
        const PollResult dns = poll_command(responses_fn_, dcmd, device);
        const PollResult arp = poll_command(responses_fn_, acmd, device);
        if (!dns.ready || !arp.ready) {
            if (attempt >= kMaxAttempts) {
                note(res, "No response from the device (timed out). Re-select the host to retry.");
                return;
            }
            res.set_content(devnet_pending(device, dcmd, acmd, attempt + 1),
                            "text/html; charset=utf-8");
            return;
        }
        auto dns_rows = (!dns.failed && !dns.output.starts_with("error|") &&
                         dns.output.size() <= kMaxTarDeviceNetOutputBytes)
                            ? parse_tar_dns_output(dns.output)
                            : std::vector<TarDnsCacheEntry>{};
        auto arp_rows = (!arp.failed && !arp.output.starts_with("error|") &&
                         arp.output.size() <= kMaxTarDeviceNetOutputBytes)
                            ? parse_tar_arp_output(arp.output)
                            : std::vector<TarArpEntry>{};
        const std::string body = "<div class=\"devnet-row\">" + render_tar_dns_panel(dns_rows) +
                                 render_tar_arp_panel(arp_rows) + "</div>";
        res.set_content(body, "text/html; charset=utf-8");
    });

    // ── Capture-sources frame (ADR-0015): the /tar enable/disable surface. The
    // frame route renders an operator-scoped device picker; /load dispatches
    // `tar status` + `tar compatibility` and renders the table; /push dispatches
    // `tar configure <src>_enabled=<bool>` per staged change. Same scoped Read +
    // Execute-probe tier as the tree; the staged-then-push guardrail lives in the
    // page JS (a toggle never dispatches — only Push does). ──
    // #4027 fix round (recorded exception, Kimi K4): stays on perm_fn_ — see
    // the identical note on /fragments/tar/process-tree above.
    sink.Get("/fragments/tar/capture-sources", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        std::optional<auth::Session> session;
        if (deny_fleet_wide_device_enumeration(req, res, &session))
            return;
        if (!perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        std::vector<DeviceRow> devices =
            devices_fn_ ? devices_fn_(session->username) : std::vector<DeviceRow>{};
        res.set_content(render_cap_frame(devices), "text/html; charset=utf-8");
    });

    // -- REST v1 twin: fleet device list, JSON (#4027). Same gate sequence
    // (deny_fleet_wide_device_enumeration then fleet_read_fn_, NOT perm_fn_) +
    // unaudited success-path posture + the #4143 review fix (gate.scope as the
    // SOLE filter over all_devices_fn_'s unfiltered snapshot) as
    // GET /api/v1/tar/process-tree above — see that route's comment. --
    sink.Get("/api/v1/tar/capture-sources", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        std::optional<auth::Session> session;
        if (deny_fleet_wide_device_enumeration(req, res, &session))
            return;
        if (!fleet_read_fn_ || !all_devices_fn_) {
            spdlog::error("tar.capture_sources.device_picker: fleet_read_fn_/"
                          "all_devices_fn_ unwired — misconfigured call site; "
                          "failing closed; cid={}", cid);
            res.status = 503;
            res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                            "application/json");
            return;
        }
        auto gate = fleet_read_fn_(req, res, "Infrastructure", "Read");
        if (!gate.admitted)
            return; // gate already wrote the A4 error body + status
        std::vector<DeviceRow> devices = all_devices_fn_();
        if (gate.scope) {
            std::vector<DeviceRow> visible;
            visible.reserve(devices.size());
            for (auto& d : devices)
                if (authz::in_scope(gate.scope, d.agent_id))
                    visible.push_back(std::move(d));
            devices.swap(visible);
        }
        res.set_content(
            ok_json(std::string("{\"devices\":") + tar_capture_sources_devices_json(devices) + "}"),
            "application/json");
    });

    sink.Get("/fragments/tar/capture-sources/load", [this, can_execute](const httplib::Request& req,
                                                                        httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string device = get_param(req, "device");
        if (device.empty()) {
            res.set_content("<div class=\"tar-tree-empty\">Select a host to view and manage its "
                            "capture sources.</div>",
                            "text/html; charset=utf-8");
            return;
        }
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Reading a device's capture-source state dispatches a read-only query and "
                      "needs the <b>Execute</b> permission.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query is unavailable on this server.");
            return;
        }
        std::string scmd = get_param(req, "scmd");
        std::string ccmd = get_param(req, "ccmd");
        if (scmd.empty() || ccmd.empty()) {
            const auto caller = caller_fn_(req);
            const auto sout = dispatch_fn_("tar", "status", {device}, "", {}, caller);
            const auto cout = dispatch_fn_("tar", "compatibility", {device}, "", {}, caller);
            const auto& sc = sout.command_id;
            const auto ssent = sout.sent;
            const auto& cc = cout.command_id;
            const auto csent = cout.sent;
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, "tar.sources.read", ssent > 0 ? "dispatched" : "no_agents",
                "Agent", device,
                std::format("status_command_id={} compat_command_id={}", audit_token(sc),
                            audit_token(cc)));
            if (ssent == 0 || csent == 0) {
                note(res, "Device offline \xE2\x80\x94 capture-source management needs a connected agent.");
                return;
            }
            res.set_content(cap_pending(device, sc, cc, 1), "text/html; charset=utf-8");
            return;
        }
        if (scmd.size() > 64 || ccmd.size() > 64 || !scmd.starts_with("tar-") ||
            !ccmd.starts_with("tar-")) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        constexpr int kMaxAttempts = 30;
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, kMaxAttempts);
            } catch (...) {
            }
        }
        const PollResult st = poll_command(responses_fn_, scmd, device);
        const PollResult cp = poll_command(responses_fn_, ccmd, device);
        if (!st.ready || !cp.ready) {
            if (attempt >= kMaxAttempts) {
                note(res, "No response from the device (timed out). Re-select the host to retry.");
                return;
            }
            res.set_content(cap_pending(device, scmd, ccmd, attempt + 1), "text/html; charset=utf-8");
            return;
        }
        if (st.failed || st.output.starts_with("error|")) {
            // Carry the agent's REASON, not just the fact of failure. The
            // storage-offline line names why collection stopped and which read
            // path still works (`tar sql`); a generic "failed" here discarded
            // that sentence on the one frame an operator opens to ask why a
            // device's data is missing. Same shape as the process query above --
            // strip the `error|` prefix, cap, escape -- but a longer cap,
            // because 200 bytes truncates that message mid-recovery-advice.
            note(res, st.output.starts_with("error|")
                          ? "The device failed the status query: " +
                                html_escape(agent_error_display(st.output))
                          : "The device failed the status query.");
            return;
        }
        const std::string compat = (!cp.failed && !cp.output.starts_with("error|")) ? cp.output : "";
        res.set_content(render_tar_capture_sources(device, st.output, compat),
                        "text/html; charset=utf-8");
    });

    // Push: apply staged enable/disable changes. POST body: device + changes
    // ("src=on,src2=off"). One `tar configure` dispatch per source, each audited
    // separately (tar.sources.configure) — DNS enable is its own audit row.
    sink.Post("/fragments/tar/capture-sources/push", [this, can_execute](const httplib::Request& req,
                                                                         httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string device = get_param(req, "device");
        if (device.empty()) {
            note(res, "No device selected.");
            return;
        }
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Pushing capture-source changes needs the <b>Execute</b> permission.");
            return;
        }
        if (!dispatch_fn_) {
            note(res, "Live device dispatch is unavailable on this server.");
            return;
        }
        // Allowlist of source names — never interpolate an arbitrary token into the
        // `<src>_enabled` configure key.
        static const std::array<std::string_view, 10> kKnown = {
            "process", "tcp", "service", "user",   "perf",
            "procperf", "netqual", "module", "arp", "dns"};
        const std::string changes = get_param(req, "changes");
        // Review finding (#3133): this route gates only Infrastructure:Read above,
        // but `tar.configure` is classified Infrastructure:Write — the route relied
        // on the chokepoint to enforce Write, and the chokepoint only does that when
        // handed a real, non-system caller. Deriving it here (not a bare Read-only
        // gate) is the complete fix: an operator who lacks Write is refused by
        // build_classified_command exactly like every other Write-classified action.
        const auto caller = caller_fn_(req);
        int applied = 0;
        int refused_or_unreached = 0;
        std::size_t pos = 0;
        while (pos < changes.size()) {
            const auto comma = changes.find(',', pos);
            std::string tok =
                changes.substr(pos, (comma == std::string::npos ? changes.size() : comma) - pos);
            pos = (comma == std::string::npos) ? changes.size() : comma + 1;
            const auto eq = tok.find('=');
            if (eq == std::string::npos)
                continue;
            const std::string src = tok.substr(0, eq);
            const std::string val = tok.substr(eq + 1);
            if (std::find(kKnown.begin(), kKnown.end(), src) == kKnown.end())
                continue; // reject unknown source name
            if (val != "on" && val != "off")
                continue;
            const std::string enabled = (val == "on") ? "true" : "false";
            const auto outcome = dispatch_fn_("tar", "configure", {device}, "",
                                              {{src + "_enabled", enabled}}, caller);
            const auto& cmd = outcome.command_id;
            const auto sent = outcome.sent;
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, "tar.sources.configure", sent > 0 ? "dispatched" : "no_agents",
                "Agent", device,
                std::format("{}_enabled={} command_id={}", src, enabled, audit_token(cmd)));
            // Only count a change the operator can observe as applied: when the dispatch
            // reached no agents (sent==0) the audit records `no_agents`, so the toast must
            // not claim it was pushed (ADR-0015 review LOW-D).
            if (sent > 0)
                ++applied;
            else
                ++refused_or_unreached;
        }
        // #3133 round-2 review minor: a chokepoint denial (the operator lacks
        // the Infrastructure:Write that tar.configure is classified as) used
        // to render the same "0 change(s) pushed" as an offline agent. The
        // dispatch return can't distinguish the two ({command_id, 0} either
        // way), so when nothing landed, probe scoped Write the same soft way
        // can_execute probes Execute — for the MESSAGE only. The probe
        // approximates the chokepoint's decision for display; the chokepoint
        // itself remains the enforcement authority either way.
        if (applied == 0 && refused_or_unreached > 0) {
            httplib::Response probe;
            const bool likely_authorized =
                scoped_perm_fn_ && scoped_perm_fn_(req, probe, "Infrastructure", "Write", device);
            if (!likely_authorized) {
                note(res, "No changes pushed: modifying capture sources dispatches "
                          "<code>tar.configure</code>, which needs the <b>Infrastructure "
                          "Write</b> permission.");
                return;
            }
        }
        res.set_content(std::format("<span data-applied=\"{}\">{} change(s) pushed</span>", applied,
                                    applied),
                        "text/html; charset=utf-8");
    });

    // -- Detail: render one node from the cached reconstruction. Holds the SAME tier as
    // the reconstruction (scoped Read + Execute on the cached device) and binds to the
    // originating principal, so a predicted/leaked token can't cross scope, downgrade
    // the Execute tier, or be replayed under another session. --
    sink.Get("/fragments/tar/process-tree/detail",
             [this, can_execute](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string token = get_param(req, "token");
        std::size_t node_id = 0;
        try {
            node_id = static_cast<std::size_t>(std::stoul(get_param(req, "node")));
        } catch (...) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        if (token.size() != 32 ||
            !std::all_of(token.begin(), token.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); })) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        // Resolve the cached device + binding fields first (without rendering), then
        // re-check the SCOPED Read + Execute on it and the principal binding.
        std::string device_id;
        std::string principal;
        std::string os;
        {
            std::lock_guard<std::mutex> lk(cache_mu_);
            auto it = cache_.find(token);
            if (it != cache_.end()) {
                device_id = it->second.device_id;
                principal = it->second.principal;
                os = it->second.os;
            }
        }
        if (device_id.empty()) {
            note(res, "The reconstruction expired. Re-run the tree.");
            return;
        }
        // Fail-closed principal binding: a token is usable only by the operator who ran
        // the reconstruction — a leaked/shared token can't be replayed under a different
        // identity even within the same management scope. An empty principal can never
        // match (a valid session always carries a non-empty username — auth_db rejects
        // empty — but enforce it locally so the binding never degrades to ""=="").
        if (principal.empty() || principal != session->username) {
            note(res, "This reconstruction belongs to a different session. Re-run the tree.");
            return;
        }
        // A leaked token must not cross management scope (scoped Read) nor downgrade the
        // Execute tier the reconstruction itself required.
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device_id))
            return;
        if (!can_execute(req, device_id)) {
            note(res, "Viewing process detail needs the <b>Execute</b> permission "
                      "(the same gate used to reconstruct the tree).");
            return;
        }
        auto html = cache_render_detail(token, node_id, nullptr);
        if (!html) {
            note(res, "The reconstruction expired. Re-run the tree.");
            return;
        }
        // Per-drilldown access audit (works-council "who viewed which process" posture,
        // mirrors dex.signal.view). Fires once per row-click — intentionally per-click,
        // bounded by the Execute + scoped-Read + principal gates above. `os` is
        // normalized so the agent-controlled value can't forge an audit field.
        (void)detail::emit_behavioral_audit(
            audit_fn_, req, res, "tar.process_tree.detail", "success", "Agent", device_id,
            std::format("node={} os={}", node_id, normalize_tar_os(os)));
        res.set_content(*html, "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
