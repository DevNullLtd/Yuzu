/// @file echo_tree_routes.cpp
/// Route registration for the Echo process-tree viewer (Frame 3 of `/echo`).
/// See echo_tree_routes.hpp for the auth/caching contract.

#include "echo_tree_routes.hpp"
#include "query_int_parse.hpp" // parse_query_int / strict_stoi / strict_stoll (#4644)

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
#include <functional>
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
    res.set_content("<div class=\"echo-tree-note\">" + text + "</div>", "text/html; charset=utf-8");
}

// The DNS / ARP panels live outside `#echo-tree`, so a tree swap does not clear them. This
// empty out-of-band replacement clears them; every answer that is not a finished tree for the
// device carries it, so one host's tables never sit under another host's view.
const char* const kDevnetReset = "<div id=\"echo-devnet\" hx-swap-oob=\"true\"></div>";

// A note for the tree frame (`/run`, `/result`): the note plus the panel reset.
void tree_note(httplib::Response& res, const std::string& text) {
    res.set_content("<div class=\"echo-tree-note\">" + text + "</div>" + kDevnetReset,
                    "text/html; charset=utf-8");
}

std::string get_param(const httplib::Request& req, const char* k) {
    return req.has_param(k) ? req.get_param_value(k) : std::string{};
}
// parse_ts_param lives in echo_process_tree.{hpp,cpp} (pure + unit-tested).

// Resolve the request's `preset`/`from`/`to` into whole hourly buckets plus the optional
// selected `hour`. An unparseable custom window or hour is refused with an in-panel note
// (#4644: the lenient parser read it as "unset", which dispatched a query for a window the
// operator had not typed); returns false when it wrote that note.
bool parse_tree_window(const httplib::Request& req, httplib::Response& res, std::int64_t now,
                       EchoWindow& win, std::int64_t& hour) {
    const std::string preset = get_param(req, "preset");
    const auto from_ts = parse_ts_param_strict(get_param(req, "from"));
    const auto to_ts = parse_ts_param_strict(get_param(req, "to"));
    const auto hour_ts = parse_ts_param_strict(get_param(req, "hour"));
    if (preset == "custom" && (!from_ts || !to_ts)) {
        tree_note(res, "The custom window is not a valid time. Use the From and To pickers "
                       "(UTC), or epoch seconds, and re-run.");
        return false;
    }
    if (!hour_ts) {
        tree_note(res, "The hour is not a valid time. Pick an hour from the list and re-run.");
        return false;
    }
    win = resolve_echo_window(preset, from_ts.value_or(0), to_ts.value_or(0), now);
    hour = *hour_ts;
    return true;
}

// The Hour selector for a rendered tree: the hours that carry process rows, newest first.
// A change re-runs the same window for the SAME device (carried in the URL, not read from the
// host picker, which may have moved on) with that `hour` (htmx includes the select's own value).
std::string render_hour_select(const std::vector<std::int64_t>& hours, std::int64_t selected,
                               const std::string& device, const std::string& preset,
                               const std::string& from, const std::string& to) {
    if (hours.empty())
        return {};
    std::string h =
        "<div class=\"echo-tree-hourbar\"><label class=\"tt-filter-label\" "
        "for=\"echo-tree-hour\">Hour</label><select id=\"echo-tree-hour\" name=\"hour\" "
        "class=\"scope-chip-select\" hx-get=\"/fragments/echo/process-tree/run?device=" +
        url_enc(device) + "&amp;preset=" + url_enc(canonical_echo_preset(preset)) +
        "&amp;from=" + url_enc(from) + "&amp;to=" + url_enc(to) +
        "\" hx-trigger=\"change\" hx-target=\"#echo-tree\">";
    for (std::size_t i = 0; i < hours.size() && i < static_cast<std::size_t>(kEchoMaxWindowHours);
         ++i)
        h += "<option value=\"" + std::to_string(hours[i]) + "\"" +
             (hours[i] == selected ? " selected" : "") + ">" +
             html_escape(format_iso_utc(hours[i])) + "</option>";
    h += "</select></div>";
    return h;
}
// The reconstruction cache token is a CSPRNG hex string (random_hex, secure_random.hpp,
// #801) minted at the /result generation site — never a std::mt19937_64 value.

// One device's OS string via the unscoped lookup (for the names-only caption).
std::string device_os(const std::optional<DeviceRow>& d) { return d ? d->os : std::string{}; }

// The server-rendered toolbar + targets (Frame-3 body). Host options come from the
// operator-scoped device list. Preset chips hx-get /run with the preset in the URL
// and the host via hx-include; the Apply chip also includes the custom inputs.
std::string render_frame(const std::vector<DeviceRow>& devices) {
    std::string h;
    h += "<div class=\"echo-tree-toolbar\">";
    // Host picker.
    h += "<select id=\"echo-tree-host\" name=\"device\" class=\"scope-chip-select\" "
         "hx-get=\"/fragments/echo/process-tree/run?preset=24h\" hx-target=\"#echo-tree\" "
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
    // Whole-hour windows over the hourly roll-up; `custom` is the Apply chip below.
    const std::array<std::pair<const char*, const char*>, 3> presets = {
        {{"1h", "Last hour"}, {"24h", "Last 24 hours"}, {"7d", "Last 7 days"}}};
    h += "<div class=\"echo-tree-presets\">";
    for (const auto& [tok, label] : presets) {
        h += std::string("<a class=\"echo-chip\" hx-get=\"/fragments/echo/process-tree/run?preset=") +
             tok + "\" hx-include=\"#echo-tree-host\" hx-target=\"#echo-tree\">" + label + "</a>";
    }
    h += "</div>";

    // Custom from/to (UTC) + Apply.
    h += "<div class=\"echo-tree-custom\">";
    h += "<label>From (UTC) <input id=\"echo-tree-from\" name=\"from\" type=\"datetime-local\"></label>";
    h += "<label>To (UTC) <input id=\"echo-tree-to\" name=\"to\" type=\"datetime-local\"></label>";
    h += "<a class=\"echo-chip\" hx-get=\"/fragments/echo/process-tree/run?preset=custom\" "
         "hx-include=\"#echo-tree-host,#echo-tree-from,#echo-tree-to\" hx-target=\"#echo-tree\">Apply</a>";
    h += "</div>";

    h += "</div>"; // toolbar (host + time range)

    // Filter bar — client-side anomalies + text filters (no round-trip; re-applied after
    // every tree swap via the htmx:afterSettle listener). No run state without pids, so
    // there are no Running/Exited chips.
    h += "<div class=\"echo-tree-filterbar\">";
    h += "<span class=\"tt-filter-label\">Show</span>";
    h += "<label class=\"tt-anom-toggle\"><input type=\"checkbox\" id=\"echo-tree-anom-only\" "
         "onchange=\"applyEchoTreeFilters()\"> Anomalies only</label>";
    h += "<input id=\"echo-tree-filter\" class=\"echo-tree-filter\" type=\"text\" "
         "placeholder=\"Filter name, user or IP\xE2\x80\xA6\" oninput=\"applyEchoTreeFilters()\">";
    h += "</div>";

    // Two-column layout: scrollable tree on the left, a sticky always-visible detail
    // panel on the right (stacks on narrow viewports).
    h += "<div class=\"echo-tree-layout\">";
    h += "<div class=\"echo-tree-main\"><div id=\"echo-tree\"><div class=\"echo-tree-empty\">Pick "
         "a host "
         "and a time range to see its process tree for one hour.</div></div></div>";
    h += "<aside class=\"echo-tree-side\"><div id=\"echo-tree-detail\"><div "
         "class=\"echo-tree-mute\">"
         "Select a process name to see what the hourly record kept for it.</div></div></aside>";
    h += "</div>";

    // Device-level DNS cache + ARP table panels (ADR-0015) for the hour the tree shows.
    // The tree result swaps this placeholder out-of-band with one that loads the panels
    // for the selected hour (no hx-on: CSP-safe). Device view, NOT per-process.
    h += "<div id=\"echo-devnet\"></div>";
    return h;
}

// The self-re-issuing polling fragment (mirrors device live_pending). Carries the three
// dispatched command ids (the hours list, the process rows, the connections) and the resolved
// hour, and clears the DNS / ARP panels while the tree is rebuilt.
std::string tree_pending(const std::string& device, const std::string& preset,
                         const std::string& from, const std::string& to, const std::string& hour,
                         const std::string& pcmd, const std::string& tcmd, const std::string& hcmd,
                         int attempt) {
    // Explicit hx-target="this" so the poll replaces ITSELF (inside #echo-tree) and
    // never inherits an ancestor's hx-target — otherwise the outerHTML swap would
    // clobber the whole frame body, taking the toolbar with it.
    return "<div hx-get=\"/fragments/echo/process-tree/result?device=" + url_enc(device) +
           "&amp;preset=" + url_enc(preset) + "&amp;from=" + url_enc(from) +
           "&amp;to=" + url_enc(to) + "&amp;hour=" + url_enc(hour) + "&amp;pcmd=" + url_enc(pcmd) +
           "&amp;tcmd=" + url_enc(tcmd) + "&amp;hcmd=" + url_enc(hcmd) +
           "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:700ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"echo-tree-loading\">Reconstructing the process tree\xE2\x80\xA6</div>" +
           kDevnetReset;
}

// Self-re-issuing poll for the device-net (DNS cache + ARP table) panels (ADR-0015).
// Carries both dispatched command_ids; ready when DNS + ARP queries both complete.
std::string devnet_pending(const std::string& device, const std::string& dcmd,
                           const std::string& acmd, const std::string& hour, int attempt) {
    return "<div hx-get=\"/fragments/echo/process-tree/device-net?device=" + url_enc(device) +
           "&amp;dcmd=" + url_enc(dcmd) + "&amp;acmd=" + url_enc(acmd) +
           "&amp;hour=" + url_enc(hour) + "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:700ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"echo-tree-loading\">Loading device DNS / ARP activity\xE2\x80\xA6</div>";
}

// Capture-sources frame body: device picker (operator-scoped) + a target the table
// loads into on host change. Mirrors render_frame's picker (ADR-0015).
std::string render_cap_frame(const std::vector<DeviceRow>& devices) {
    std::string h = "<div class=\"picker-row\"><label for=\"cap-host\">Device</label>";
    h += "<select id=\"cap-host\" name=\"device\" class=\"scope-chip-select\" "
         "hx-get=\"/fragments/echo/capture-sources/load\" hx-target=\"#cap-sources-body\" "
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
    h += "<div id=\"cap-sources-body\"><div class=\"echo-tree-empty\">Select a host to view and manage "
         "its capture sources.</div></div>";
    return h;
}

// Self-re-issuing poll for the capture-sources table (carries the status + compat
// command_ids; ready when both complete).
std::string cap_pending(const std::string& device, const std::string& scmd, const std::string& ccmd,
                        int attempt) {
    return "<div hx-get=\"/fragments/echo/capture-sources/load?device=" + url_enc(device) +
           "&amp;scmd=" + url_enc(scmd) + "&amp;ccmd=" + url_enc(ccmd) +
           "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:600ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"echo-tree-loading\">Loading capture sources\xE2\x80\xA6</div>";
}

// The hour list is at most kEchoAgentRowCap epoch lines (~21 bytes each, ~210 KiB), so an honest
// answer fits well inside this; anything bigger is refused like the other answers' caps.
constexpr std::size_t kMaxEchoHoursOutputBytes = 256 * 1024;

// Poll one dispatched command for `device`: ready when it has output AND a terminal status
// (the agent flushes a long answer as several frames, so output seen before the terminal
// status may be only the head of it), or a terminal status alone. A failure status on ANY of
// the device's rows fails the whole answer, whatever frames sit beside it and whatever order the
// store broke ties in: a torn head of a failed answer must never read as complete. The merge
// stops appending once `max_bytes` is passed, so memory is bounded at the cap plus one frame and
// the output stays over the cap for the caller's own over-cap branch. Returns
// {ready, output, failed, error}.
struct PollResult {
    bool ready = false;
    bool failed = false;
    std::string output;
    std::string error;
};
PollResult poll_command(const EchoTreeRoutes::ResponsesFn& responses_fn, const std::string& command_id,
                        const std::string& device, std::size_t max_bytes) {
    PollResult pr;
    if (!responses_fn)
        return pr;
    // #1634: scope the poll read at the store seam (q.agent_id); the post-filter
    // on `device` below is retained as defense-in-depth.
    const auto rows = responses_fn(command_id, device);
    std::vector<const DexAgentResponse*> frames; // every frame that carries output
    const DexAgentResponse* terminal = nullptr;
    const DexAgentResponse* failure = nullptr; // not `terminal`: that keeps only the LAST row
    for (const auto& r : rows) {
        if (r.agent_id != device)
            continue;
        if (!r.output.empty())
            frames.push_back(&r);
        if (r.status >= 1)
            terminal = &r;
        if (r.status >= 2 && !failure)
            failure = &r;
    }
    if (failure) {
        pr.ready = true;
        pr.failed = true;
        pr.error = failure->error_detail;
        return pr;
    }
    if (!frames.empty()) {
        if (!terminal)
            return pr; // still streaming
        // The store answers newest first. Merge frames oldest first, with the frame that opens
        // with the `__schema__` header ahead of the rest, so the parse order does not depend on
        // how the store broke ties.
        std::reverse(frames.begin(), frames.end());
        std::stable_partition(frames.begin(), frames.end(), [](const DexAgentResponse* f) {
            return f->output.starts_with("__schema__|");
        });
        for (std::size_t i = 0; i < frames.size(); ++i) {
            if (pr.output.size() > max_bytes)
                break; // over the caller's cap already: it will refuse this answer
            if (i > 0)
                pr.output += '\n';
            pr.output += frames[i]->output;
        }
        pr.ready = true;
        return pr;
    }
    if (terminal)
        pr.ready = true; // completed, possibly with no rows
    return pr;
}

// One device-net read (DNS or ARP): its rows, or `notes` saying why there are none. A failed
// read, an agent error, an oversize or unreadable answer is an error in the panel, never "No
// ... recorded"; an answer at the agent's row cap or with dropped rows is flagged.
template <class Row, class ParseFn>
std::vector<Row> read_devnet(const PollResult& pr, ParseFn parse, EchoReadNotes& notes) {
    if (pr.failed || pr.output.starts_with("error|")) {
        notes.error = echo_agent_error_note(pr.failed ? pr.error : pr.output);
        return {};
    }
    if (pr.output.size() > kMaxEchoDeviceNetOutputBytes) {
        notes.error = "The device returned an unexpectedly large dataset for this hour. Re-select "
                      "the host to retry.";
        return {};
    }
    EchoParseStats st;
    auto rows = parse(pr.output, &st);
    if (!st.schema) {
        notes.error = "The device's answer could not be read. Re-select the host to retry.";
        return {};
    }
    notes.unreadable = st.unreadable;
    notes.cut = rows.size() + st.unreadable >= kEchoAgentRowCap;
    return rows;
}

} // namespace

namespace {

// Shared row shape behind BOTH echo_process_tree_frame_json and
// echo_capture_sources_devices_json — the two public builders are separate names
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

std::string echo_process_tree_frame_json(const std::vector<DeviceRow>& devices) {
    return device_picker_json(devices);
}

std::string echo_capture_sources_devices_json(const std::vector<DeviceRow>& devices) {
    return device_picker_json(devices);
}

std::string echo_retention_paused_json(const EchoRetentionPausedScan& scan) {
    // Same sort as DashboardRoutes::render_echo_retention_paused: value-error rows
    // float to the top, then oldest-paused-first (0 == oldest, per #558), then by
    // display name — kept in lockstep with the HTML renderer's own std::sort so the
    // two surfaces agree on row order (see gather_echo_retention_paused's doc comment
    // for why the SORT itself still lives twice: the HTML renderer sorts its own
    // internal PausedRow vector, and duplicating a five-line comparator is far lower
    // risk than threading a shared-order guarantee through two different row types).
    std::vector<EchoPausedSourceRow> rows = scan.rows;
    std::sort(rows.begin(), rows.end(),
              [](const EchoPausedSourceRow& a, const EchoPausedSourceRow& b) {
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
                             {"hourly_rows", r.hourly_rows},
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
               // A cut scan also reports store_degraded so a client that predates
               // result_truncated_by_cap still sees the result is not complete;
               // result_truncated_by_cap is the discriminator between "the read failed"
               // and "the read was cut". The dashboard page uses the two fields
               // separately (scan.store_degraded stays "the read failed").
               {"store_degraded", scan.store_degraded || scan.result_truncated_by_cap},
               {"result_truncated_by_cap", scan.result_truncated_by_cap},
               {"rows", rows_json}}
        .dump();
}

bool EchoTreeRoutes::deny_fleet_wide_device_enumeration(const httplib::Request& req,
                                                       httplib::Response& res,
                                                       std::optional<auth::Session>* out_session) {
    auto session = auth_fn_(req, res);
    if (!session) {
        // #4027 fix (adversarial review round 1, CDX-P1-03/K2): `auth_fn_`
        // (require_auth) already wrote a correct A4 JSON 401 body onto `res`
        // — do NOT overwrite it with plain text here. This helper feeds both
        // the pre-existing HTML fragment routes and the new `/api/v1/echo/*`
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
            audit_fn_, req, "echo.device_picker.view", "denied", "Infrastructure", "",
            "fleet-wide Echo device picker denied to a service-scoped token "
            "(path=" + req.path + ")");
        return true;
    }
    if (out_session)
        *out_session = std::move(session);
    return false;
}

void EchoTreeRoutes::cache_put(const std::string& token, ReconEntry entry) {
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

std::optional<std::string> EchoTreeRoutes::cache_render_detail(const std::string& token,
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
        return std::string("<div class=\"echo-tree-note\">That process is no longer in the "
                           "reconstruction. Re-run the tree.</div>");
    const EchoProcNode& node = e.tree.nodes[node_id];
    // The hourly tier has no pid: connections join the node by process NAME.
    std::vector<EchoTcpHourRow> conns;
    for (const auto& c : e.conns)
        if (c.process_name == node.name)
            conns.push_back(c);
    std::sort(conns.begin(), conns.end(), [](const EchoTcpHourRow& a, const EchoTcpHourRow& b) {
        return a.connect_count > b.connect_count;
    });
    return render_echo_proc_detail(node, conns);
}

void EchoTreeRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                    ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                    LookupFn lookup_fn, DispatchFn dispatch_fn,
                                    ResponsesFn responses_fn, AuditFn audit_fn,
                                    CallerFn caller_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(devices_fn), std::move(lookup_fn), std::move(dispatch_fn),
                    std::move(responses_fn), std::move(audit_fn), std::move(caller_fn));
}

void EchoTreeRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
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
    sink.Get("/fragments/echo/process-tree", [this](const httplib::Request& req,
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
    sink.Get("/api/v1/echo/process-tree", [this](const httplib::Request& req,
                                                httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        std::optional<auth::Session> session;
        if (deny_fleet_wide_device_enumeration(req, res, &session))
            return;
        if (!fleet_read_fn_ || !all_devices_fn_) {
            spdlog::error("echo.process_tree.device_picker: fleet_read_fn_/"
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
            ok_json(std::string("{\"devices\":") + echo_process_tree_frame_json(devices) + "}"),
            "application/json");
    });

    // -- Run: scope + execute gate -> dispatch three canned echo.sql -> poll fragment. --
    sink.Get("/fragments/echo/process-tree/run", [this, can_execute](const httplib::Request& req,
                                                                    httplib::Response& res) {
        const std::string device = get_param(req, "device");
        const std::string preset = get_param(req, "preset");
        const std::string from = get_param(req, "from");
        const std::string to = get_param(req, "to");
        if (device.empty()) {
            tree_note(res, "Select a host to see its process tree.");
            return;
        }
        // Per-device scoped Read floor (tier + management group).
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            tree_note(res, "Reconstructing the tree dispatches a read-only query to the device and "
                           "needs the <b>Execute</b> permission.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            tree_note(res, "Live device query is unavailable on this server.");
            return;
        }
        // The window's whole hourly buckets feed the Hour selector; the tree and connections
        // are read for ONE hour. A custom window that does not parse is refused here (#4644).
        EchoWindow win;
        std::int64_t hour_req = 0;
        if (!parse_tree_window(req, res, now_epoch_seconds(), win, hour_req))
            return;
        // The requested hour, else the window's last complete bucket.
        const std::int64_t hour_ts = hour_req > 0 ? hour_req : win.to_ts;
        // SECURITY: the bucket bounds are interpolated into the echo.sql query STRING handed
        // to the agent. The agent forbids parameterized/recursive CTEs, so there is NO
        // bind-parameter path here — this is safe ONLY because every bound is a
        // std::int64_t value (resolve_echo_window / parse_ts_param_strict: digits → number,
        // never a string). Never interpolate a string-typed value into these queries without
        // an allowlist / quote-escape; doing so would be SQL injection into echo.sql.
        //
        // One hour per query: the agent answers at most kEchoAgentRowCap rows whatever LIMIT
        // the text names (see that constant), so a whole window could not be read.
        const std::string psql = std::format(
            "SELECT hour_ts, name, parent_name, user, start_count, stop_count, abnormal_exit_count "
            "FROM $Process_Hourly WHERE hour_ts = {} LIMIT {}",
            hour_ts, kEchoAgentRowCap);
        const std::string tsql = std::format(
            "SELECT hour_ts, remote_addr, remote_port, proto, process_name, connect_count, "
            "disconnect_count, failed_count FROM $TCP_Hourly WHERE hour_ts = {} LIMIT {}",
            hour_ts, kEchoAgentRowCap);
        const std::string hsql = std::format(
            "SELECT DISTINCT hour_ts FROM $Process_Hourly WHERE hour_ts >= {} AND hour_ts <= {} "
            "ORDER BY hour_ts DESC LIMIT {}",
            win.from_ts, win.to_ts, kEchoMaxWindowHours);
        const auto caller = caller_fn_(req);
        const auto pout = dispatch_fn_("echo", "sql", {device}, "", {{"sql", psql}}, caller);
        const auto tout = dispatch_fn_("echo", "sql", {device}, "", {{"sql", tsql}}, caller);
        const auto hout = dispatch_fn_("echo", "sql", {device}, "", {{"sql", hsql}}, caller);
        const auto& pcmd = pout.command_id;
        const auto psent = pout.sent;
        const auto& tcmd = tout.command_id;
        const auto tsent = tout.sent;
        const auto& hcmd = hout.command_id;
        const auto hsent = hout.sent;
        // Audit at DISPATCH (parity with device-live-info / DEX-perf): the live query
        // hitting the endpoint is the access event and must be recorded even when it
        // reaches no agent or the later poll never completes. Shared #1647 chokepoint:
        // catches a throwing audit_fn (catch-arm parity) and surfaces Sec-Audit-Failed
        // on a dropped row; dispatch/render posture unchanged (still renders below).
        (void)detail::emit_behavioral_audit(
            audit_fn_, req, res, "echo.process_tree.read", psent > 0 ? "dispatched" : "no_agents",
            "Agent", device,
            std::format("dispatch preset={} from={} to={} hour={} command_id={}",
                        canonical_echo_preset(preset), win.from_ts, win.to_ts, hour_ts,
                        audit_token(pcmd)));
        if (psent == 0 || tsent == 0 || hsent == 0) {
            tree_note(res, "Device offline \xE2\x80\x94 the process tree needs a connected agent.");
            return;
        }
        res.set_content(
            tree_pending(device, preset, from, to, std::to_string(hour_ts), pcmd, tcmd, hcmd, 1),
            "text/html; charset=utf-8");
    });

    // -- Result: poll the three commands -> reconstruct -> cache -> render tree. --
    sink.Get("/fragments/echo/process-tree/result", [this, can_execute](const httplib::Request& req,
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
        const std::string hcmd = get_param(req, "hcmd");
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            tree_note(res, "Live device query needs the <b>Execute</b> permission.");
            return;
        }
        // Only echo.sql commands for the named agent are pollable here.
        if (device.empty() || pcmd.size() > 64 || tcmd.size() > 64 || hcmd.size() > 64 ||
            !pcmd.starts_with("echo-") || !tcmd.starts_with("echo-") || !hcmd.starts_with("echo-")) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        if (!responses_fn_) {
            tree_note(res, "Live device query is unavailable on this server.");
            return;
        }
        constexpr int kMaxAttempts = 40;      // ~28s at 700ms — overall budget
        constexpr int kTcpGraceAttempts = 12; // ~8s — then render the tree WITHOUT
                                              // connections / the hour list rather than let a
                                              // hung side query block the whole process view.
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, kMaxAttempts);
            } catch (...) {
            }
        }
        const PollResult proc = poll_command(responses_fn_, pcmd, device, kMaxEchoProcOutputBytes);
        const PollResult tcp = poll_command(responses_fn_, tcmd, device, kMaxEchoTcpOutputBytes);
        const PollResult hrs = poll_command(responses_fn_, hcmd, device, kMaxEchoHoursOutputBytes);
        // The process query is essential; the TCP and hour-list queries are best-effort past
        // their grace.
        const bool side_done = (tcp.ready && hrs.ready) || attempt >= kTcpGraceAttempts;
        if (!proc.ready || !side_done) {
            if (attempt >= kMaxAttempts) {
                tree_note(res, "No response from the device (timed out) \xE2\x80\x94 it may have "
                               "gone offline. Re-run to retry.");
                return;
            }
            // The hour carried by the poll is the resolved one (see /run); an absent one falls
            // back to the window's last complete bucket below.
            res.set_content(tree_pending(device, preset, from, to, get_param(req, "hour"), pcmd,
                                         tcmd, hcmd, attempt + 1),
                            "text/html; charset=utf-8");
            return;
        }
        if (proc.failed) {
            tree_note(res, html_escape(echo_agent_error_note(proc.error)));
            return;
        }
        if (proc.output.starts_with("error|")) {
            tree_note(res, html_escape(echo_agent_error_note(proc.output)));
            return;
        }

        // Defense-in-depth byte cap before parse (a compromised agent controls
        // proc.output; gRPC already bounds the message, but don't rely on it). Reject
        // an over-cap process payload rather than truncate — a torn process stream
        // produces phantom roots, so an honest "narrow the timescale" is better.
        if (proc.output.size() > kMaxEchoProcOutputBytes) {
            tree_note(res, "The device returned an unexpectedly large process dataset for this "
                           "window. Narrow the timescale and re-run.");
            return;
        }

        const std::int64_t now = now_epoch_seconds();
        EchoWindow win;
        std::int64_t hour_req = 0;
        if (!parse_tree_window(req, res, now, win, hour_req))
            return;
        EchoParseStats proc_stats;
        const auto rows = parse_echo_process_hourly_output(proc.output, 120000, &proc_stats);
        if (!proc_stats.schema) {
            tree_note(res, "The device's answer could not be read as process activity. Re-run to "
                           "retry.");
            return;
        }
        // TCP is included only if it completed cleanly, fits the byte cap and reads; otherwise
        // the tree still renders (without inline per-process connections) and says why.
        EchoParseStats tcp_stats;
        std::vector<EchoTcpHourRow> all_conns;
        std::string tcp_reason;
        if (!tcp.ready) {
            tcp_reason = "it did not answer in time";
        } else if (tcp.failed || tcp.output.starts_with("error|")) {
            tcp_reason = echo_agent_error_note(tcp.failed ? tcp.error : tcp.output);
        } else if (tcp.output.size() > kMaxEchoTcpOutputBytes) {
            tcp_reason = "its answer was over the size limit";
        } else {
            all_conns = parse_echo_tcp_hourly_output(tcp.output, 20000, &tcp_stats);
            if (!tcp_stats.schema)
                tcp_reason = "its answer could not be read";
        }
        const bool tcp_ok = tcp_reason.empty();
        // The tree shows ONE hour: the requested one, else the window's last complete bucket.
        // The Hour selector lists the hours the device reported, plus the shown hour when the
        // device did not report it, so the box and the banner always agree.
        const std::int64_t shown_hour = hour_req > 0 ? hour_req : win.to_ts;
        EchoParseStats hrs_stats;
        std::vector<std::int64_t> hours;
        if (hrs.ready && !hrs.failed && !hrs.output.starts_with("error|") &&
            hrs.output.size() <= kMaxEchoHoursOutputBytes)
            hours = parse_echo_hours_output(hrs.output, &hrs_stats);
        if (std::find(hours.begin(), hours.end(), shown_hour) == hours.end()) {
            hours.push_back(shown_hour);
            std::sort(hours.begin(), hours.end(), std::greater<>());
        }
        auto tree = build_echo_process_tree(rows, shown_hour);
        std::vector<EchoTcpHourRow> conns;
        for (const auto& c : all_conns)
            if (c.hour_ts == shown_hour)
                conns.push_back(c);

        const std::string os = device_os(lookup_fn_ ? lookup_fn_(device) : std::nullopt);
        // CSPRNG cache token (#801). random_hex(16) → 32 lowercase hex chars, matching
        // the /detail token-format check. On entropy failure surface an in-panel error
        // and record a `failure` audit (the SOC2 CC7.2/7.3 evidence row) — we do NOT
        // 503 (htmx suppresses the swap on a non-2xx response, so the operator would
        // see nothing) and we never cache a half-built entry under a weak token.
        auto token_exp = random_hex(16);
        if (!token_exp) {
            (void)detail::emit_behavioral_audit(audit_fn_, req, res, "echo.process_tree.read",
                                                "failure", "Agent", device, "csprng_unavailable");
            tree_note(res, "The server could not generate a secure token for this reconstruction "
                           "(entropy temporarily unavailable). Retry in a few seconds.");
            return;
        }
        const std::string token = std::move(*token_exp);
        const int node_count = static_cast<int>(tree.nodes.size());
        const int anomaly_count = tree.anomaly_count;

        // Full tree, rendered once; anomalies/text filtering is applied client-side from
        // the toolbar (each row carries data-anom), so a filter toggle needs no re-dispatch.
        std::string body = render_hour_select(hours, shown_hour, device, preset, from, to);
        if (!hrs_stats.schema)
            body += "<div class=\"echo-tree-warn\">The list of other hours was unavailable; only "
                    "this hour is offered.</div>";
        if (!tcp_ok)
            body += "<div class=\"echo-tree-warn\">Connection data was unavailable for this host (" +
                    html_escape(tcp_reason) +
                    "); the process tree is shown without per-process network info.</div>";
        // An answer at the agent's row cap is cut, never complete; so is a row the parser dropped.
        EchoReadNotes proc_notes{.unreadable = proc_stats.unreadable,
                                 .cut = rows.size() + proc_stats.unreadable >= kEchoAgentRowCap};
        EchoReadNotes tcp_notes{.unreadable = tcp_stats.unreadable,
                                .cut = tcp_ok && all_conns.size() + tcp_stats.unreadable >=
                                                     kEchoAgentRowCap};
        body += render_echo_read_notes(proc_notes);
        body += render_echo_read_notes(tcp_notes, "Connection results", "connection rows");
        body += render_echo_tree_fragment(tree, conns, token);
        // Out-of-band: point the DNS / ARP panels at the hour this tree shows, for THIS device
        // (not whatever the host picker holds by the time the panel loads).
        body += "<div id=\"echo-devnet\" hx-swap-oob=\"true\" "
                "hx-get=\"/fragments/echo/process-tree/device-net?device=" +
                url_enc(device) + "&amp;hour=" + std::to_string(shown_hour) +
                "\" hx-trigger=\"load\" hx-swap=\"innerHTML\"></div>";

        ReconEntry entry;
        entry.device_id = device;
        entry.principal = session->username; // fail-closed binding for /detail replay
        entry.os = os;
        entry.conns = std::move(conns);
        entry.tree = std::move(tree);
        entry.created = now;
        cache_put(token, std::move(entry));

        // Record the data class exposed (works-council access-audit posture): `os` is the
        // device's normalized OS; `conns` flags whether connection data was shown.
        (void)detail::emit_behavioral_audit(
            audit_fn_, req, res, "echo.process_tree.read", "success", "Agent", device,
            std::format("preset={} from={} to={} hour={} nodes={} anomalies={} os={} conns={}",
                        canonical_echo_preset(preset), win.from_ts, win.to_ts, shown_hour,
                        node_count, anomaly_count, normalize_echo_os(os), tcp_ok ? 1 : 0));
        res.set_content(body, "text/html; charset=utf-8");
    });

    // -- Device-net panels: DNS cache + ARP table activity for the selected host and hour
    // (ADR-0015). Dispatches two canned read-only echo.sql ($DNS_Hourly, $ARP_Hourly),
    // polls, renders DEVICE-level panels (never per-process — the DNS cache has no
    // process). Same scoped Read + Execute-probe tier as the tree run; audits
    // echo.dns.read / echo.arp.read as DISTINCT verbs (DNS is usage-class PII, kept
    // separately countable). --
    sink.Get("/fragments/echo/process-tree/device-net", [this, can_execute](
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
        const std::string hour = get_param(req, "hour");
        const auto hour_ts = parse_ts_param_strict(hour);
        if (!hour_ts) {
            note(res, "The hour is not a valid time. Re-select the host to retry.");
            return;
        }
        if (dcmd.empty() || acmd.empty()) {
            // First call: dispatch the two queries for the hour the tree shows, or for the
            // default 24-hour window when none was picked (the render then takes the newest
            // hour that has rows). Both bounds are std::int64_t (see the /run SECURITY note).
            const EchoWindow win = *hour_ts > 0
                                       ? EchoWindow{*hour_ts, *hour_ts}
                                       : resolve_echo_window("24h", 0, 0, now_epoch_seconds());
            const std::string range =
                std::format(" WHERE hour_ts >= {} AND hour_ts <= {}", win.from_ts, win.to_ts);
            // Only the counts the agent measures (see EchoDnsHourRow / EchoArpHourRow); the
            // LIMIT is the agent's own row cap, which is what applies whatever the text says.
            const std::string tail = std::format(" ORDER BY hour_ts DESC LIMIT {}", kEchoAgentRowCap);
            const std::string dsql =
                "SELECT hour_ts, name, record_type, data, appear_count, remove_count "
                "FROM $DNS_Hourly" +
                range + tail;
            const std::string asql =
                "SELECT hour_ts, interface, ip_address, mac_address, appear_count, remove_count "
                "FROM $ARP_Hourly" +
                range + tail;
            const auto caller = caller_fn_(req);
            const auto dout = dispatch_fn_("echo", "sql", {device}, "", {{"sql", dsql}}, caller);
            const auto aout = dispatch_fn_("echo", "sql", {device}, "", {{"sql", asql}}, caller);
            const auto& dc = dout.command_id;
            const auto dsent = dout.sent;
            const auto& ac = aout.command_id;
            const auto asent = aout.sent;
            // Shared #1647 chokepoint: catch-arm parity + Sec-Audit-Failed per verb
            // (DNS is usage-class PII, kept separately countable). Dispatch posture
            // unchanged; if either evidence row drops, the header is set.
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, "echo.dns.read", dsent > 0 ? "dispatched" : "no_agents",
                "Agent", device, std::format("hour={} command_id={}", *hour_ts, audit_token(dc)));
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, "echo.arp.read", asent > 0 ? "dispatched" : "no_agents",
                "Agent", device, std::format("hour={} command_id={}", *hour_ts, audit_token(ac)));
            if (dsent == 0 || asent == 0) {
                note(res, "Device offline \xE2\x80\x94 the DNS/ARP panels need a connected agent.");
                return;
            }
            res.set_content(devnet_pending(device, dc, ac, hour, 1), "text/html; charset=utf-8");
            return;
        }
        // Poll: validate the command-id shape (same guard as the tree result route).
        if (dcmd.size() > 64 || acmd.size() > 64 || !dcmd.starts_with("echo-") ||
            !acmd.starts_with("echo-")) {
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
        const PollResult dns = poll_command(responses_fn_, dcmd, device, kMaxEchoDeviceNetOutputBytes);
        const PollResult arp = poll_command(responses_fn_, acmd, device, kMaxEchoDeviceNetOutputBytes);
        if (!dns.ready || !arp.ready) {
            if (attempt >= kMaxAttempts) {
                note(res, "No response from the device (timed out). Re-select the host to retry.");
                return;
            }
            res.set_content(devnet_pending(device, dcmd, acmd, hour, attempt + 1),
                            "text/html; charset=utf-8");
            return;
        }
        EchoReadNotes dns_notes;
        EchoReadNotes arp_notes;
        const auto dns_rows = read_devnet<EchoDnsHourRow>(
            dns,
            [](const std::string& out, EchoParseStats* st) {
                return parse_echo_dns_hourly_output(out, 20000, st);
            },
            dns_notes);
        const auto arp_rows = read_devnet<EchoArpHourRow>(
            arp,
            [](const std::string& out, EchoParseStats* st) {
                return parse_echo_arp_hourly_output(out, 20000, st);
            },
            arp_notes);
        // The requested hour, else the newest hour either panel has rows for.
        std::int64_t shown_hour = *hour_ts;
        if (shown_hour <= 0) {
            for (const auto& r : dns_rows)
                shown_hour = (std::max)(shown_hour, r.hour_ts);
            for (const auto& r : arp_rows)
                shown_hour = (std::max)(shown_hour, r.hour_ts);
        }
        // Audit what was rendered, per verb (DNS is kept separately countable): the rows of the
        // shown hour as an int64 count, or a failure with no free text. Only this render shows
        // the rows, so this is where the read is recorded (mirrors device_routes.cpp).
        const auto audit_read = [&](const char* action, const auto& rows, const EchoReadNotes& n) {
            std::int64_t shown_rows = 0;
            for (const auto& r : rows)
                if (r.hour_ts == shown_hour)
                    ++shown_rows;
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, action, n.error.empty() ? "success" : "failure", "Agent",
                device,
                n.error.empty() ? std::format("hour={} rows={}", shown_hour, shown_rows)
                                : std::format("hour={}", shown_hour));
        };
        audit_read("echo.dns.read", dns_rows, dns_notes);
        audit_read("echo.arp.read", arp_rows, arp_notes);
        const std::string body = "<div class=\"devnet-row\">" +
                                 render_echo_dns_panel(dns_rows, shown_hour, dns_notes) +
                                 render_echo_arp_panel(arp_rows, shown_hour, arp_notes) + "</div>";
        res.set_content(body, "text/html; charset=utf-8");
    });

    // ── Capture-sources frame (ADR-0015): the /echo enable/disable surface. The
    // frame route renders an operator-scoped device picker; /load dispatches
    // `echo status` + `echo compatibility` and renders the table; /push dispatches
    // `echo configure <src>_enabled=<bool>` per staged change. Same scoped Read +
    // Execute-probe tier as the tree; the staged-then-push guardrail lives in the
    // page JS (a toggle never dispatches — only Push does). ──
    // #4027 fix round (recorded exception, Kimi K4): stays on perm_fn_ — see
    // the identical note on /fragments/echo/process-tree above.
    sink.Get("/fragments/echo/capture-sources", [this](const httplib::Request& req,
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
    // GET /api/v1/echo/process-tree above — see that route's comment. --
    sink.Get("/api/v1/echo/capture-sources", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        std::optional<auth::Session> session;
        if (deny_fleet_wide_device_enumeration(req, res, &session))
            return;
        if (!fleet_read_fn_ || !all_devices_fn_) {
            spdlog::error("echo.capture_sources.device_picker: fleet_read_fn_/"
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
            ok_json(std::string("{\"devices\":") + echo_capture_sources_devices_json(devices) + "}"),
            "application/json");
    });

    sink.Get("/fragments/echo/capture-sources/load", [this, can_execute](const httplib::Request& req,
                                                                        httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string device = get_param(req, "device");
        if (device.empty()) {
            res.set_content("<div class=\"echo-tree-empty\">Select a host to view and manage its "
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
            const auto sout = dispatch_fn_("echo", "status", {device}, "", {}, caller);
            const auto cout = dispatch_fn_("echo", "compatibility", {device}, "", {}, caller);
            const auto& sc = sout.command_id;
            const auto ssent = sout.sent;
            const auto& cc = cout.command_id;
            const auto csent = cout.sent;
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, "echo.sources.read", ssent > 0 ? "dispatched" : "no_agents",
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
        if (scmd.size() > 64 || ccmd.size() > 64 || !scmd.starts_with("echo-") ||
            !ccmd.starts_with("echo-")) {
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
        const PollResult st = poll_command(responses_fn_, scmd, device, kMaxEchoStatusOutputBytes);
        const PollResult cp = poll_command(responses_fn_, ccmd, device, kMaxEchoStatusOutputBytes);
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
            // path still works (`echo sql`); a generic "failed" here discarded
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
        // Defense-in-depth byte cap before parse, like the other three answers: a compromised
        // agent controls this output.
        if (st.output.size() > kMaxEchoStatusOutputBytes) {
            note(res, "The device returned an unexpectedly large status reply. Re-select the "
                      "host to retry.");
            return;
        }
        res.set_content(render_echo_capture_sources(device, st.output), "text/html; charset=utf-8");
    });

    // Push: apply staged enable/disable changes. POST body: device + changes
    // ("src=on,src2=off"). One `echo configure` dispatch per source, each audited
    // separately (echo.sources.configure) — DNS enable is its own audit row.
    sink.Post("/fragments/echo/capture-sources/push", [this, can_execute](const httplib::Request& req,
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
        static const std::array<std::string_view, 11> kKnown = {
            "process", "tcp", "service", "user",   "perf",
            "procperf", "netqual", "module", "arp", "dns", "registry"};
        const std::string changes = get_param(req, "changes");
        // Review finding (#3133): this route gates only Infrastructure:Read above,
        // but `echo.configure` is classified Infrastructure:Write — the route relied
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
            const auto outcome = dispatch_fn_("echo", "configure", {device}, "",
                                              {{src + "_enabled", enabled}}, caller);
            const auto& cmd = outcome.command_id;
            const auto sent = outcome.sent;
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, "echo.sources.configure", sent > 0 ? "dispatched" : "no_agents",
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
        // the Infrastructure:Write that echo.configure is classified as) used
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
                          "<code>echo.configure</code>, which needs the <b>Infrastructure "
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
    sink.Get("/fragments/echo/process-tree/detail",
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
            // stoul would accept "-1" (wraps to SIZE_MAX) and "5abc" (-> 5): parse strictly.
            const auto parsed_node = yuzu::server::parse_query_int<long long>(get_param(req, "node"));
            if (!parsed_node || *parsed_node < 0)
                throw std::invalid_argument("node");
            node_id = static_cast<std::size_t>(*parsed_node);
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
            audit_fn_, req, res, "echo.process_tree.detail", "success", "Agent", device_id,
            std::format("node={} os={}", node_id, normalize_echo_os(os)));
        res.set_content(*html, "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
