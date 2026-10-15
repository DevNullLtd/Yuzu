#include "settings_general_routes.hpp"

#include "web_utils.hpp" // html_escape

#include <array>
#include <string_view>
#include <utility>

// The baked page, defined in settings_general_ui.cpp (global scope, like kSettingsHtml).
extern const char* const kSettingsGeneralHtml;

namespace yuzu::server::settings_general {

namespace {

// The log levels PUT /api/config/log_level accepts (runtime_config_store.cpp). The logger's
// own names differ for one of them (`warning`), and the logger can also be at `critical`
// or `off`, which the route refuses.
constexpr std::array<std::string_view, 5> kSettableLevels = {"trace", "debug", "info", "warn",
                                                              "error"};

std::string normalise_level(std::string_view level) {
    return level == "warning" ? "warn" : std::string(level);
}

bool is_settable(std::string_view level) {
    for (const auto l : kSettableLevels)
        if (l == level)
            return true;
    return false;
}

constexpr std::string_view kHeartbeatHint =
    "Seconds, 30 or more. Default 90. Applies to agents connected directly to this server, from its next "
    "sweep. Agents behind a gateway are not covered. Other server replicas keep their own value "
    "and pick the stored one up when they restart.";
constexpr std::string_view kLogLevelHint =
    "Trace and debug add per-command and per-agent lines and raise log volume. Applies to this "
    "server process now. Stored, and re-applied at restart over the --log-level flag.";

std::string chip(std::string_view label, const std::string& value_html) {
    return "<span class=\"chip\">" + std::string(label) + "<b>" + value_html + "</b></span>";
}

} // namespace

// ── Runtime form ────────────────────────────────────────────────────────

std::string render_general_runtime(const RuntimeView& v) {
    const std::string level = normalise_level(v.log_level);
    const std::string hb = std::to_string(v.heartbeat_seconds);
    const bool off = !v.store_available;

    std::string html = "<form id=\"general-runtime-form\" class=\"form\" novalidate"
                       " data-loaded-heartbeat=\"" +
                       hb + "\" data-loaded-log-level=\"" + html_escape(level) + "\">";
    if (off)
        html += "<div class=\"note\" role=\"status\">Runtime settings cannot be saved: the "
                "configuration store is unavailable.</div>";

    html += "<div class=\"row2\"><div class=\"fld\"><label for=\"gen-heartbeat\">Agent heartbeat "
            "timeout (seconds)</label><input class=\"in\" id=\"gen-heartbeat\" "
            "name=\"heartbeat_timeout\" type=\"number\" min=\"30\" step=\"1\" "
            "inputmode=\"numeric\" value=\"" +
            hb + "\" aria-describedby=\"gen-heartbeat-hint\"" + (off ? " disabled" : "") +
            "><span class=\"hint\" id=\"gen-heartbeat-hint\">" + std::string(kHeartbeatHint) +
            "</span><span class=\"field-err\" id=\"gen-heartbeat-err\" role=\"alert\" hidden>"
            "Enter a whole number of seconds, 30 or more.</span></div>";

    html += "<div class=\"fld\"><label for=\"gen-log-level\">Log level</label><select "
            "id=\"gen-log-level\" name=\"log_level\" aria-describedby=\"gen-log-level-hint\"" +
            std::string(off ? " disabled" : "") + ">";
    for (const auto l : kSettableLevels) {
        html += "<option value=\"" + std::string(l) + "\"";
        if (l == level)
            html += " selected";
        html += ">" + std::string(l) + "</option>";
    }
    // The server can be at a level the route will not accept (critical, off). Show it as the
    // current value, disabled, so the form never silently selects a different level.
    if (!is_settable(level))
        html += "<option value=\"" + html_escape(level) + "\" selected disabled>" +
                html_escape(level) + " (current; cannot be set here)</option>";
    html += "</select><span class=\"hint\" id=\"gen-log-level-hint\">" + std::string(kLogLevelHint) +
            "</span></div></div>";

    if (!off)
        html += "<div class=\"gen-actions\"><button class=\"btn primary\" type=\"submit\" "
                "id=\"gen-save\" disabled>Save changes</button></div>";
    html += "</form>";
    return html;
}

// ── Recent events ───────────────────────────────────────────────────────

std::string render_analytics_events(const EventsView& v) {
    // Off by configuration: the store was never constructed.
    if (!v.collection_enabled)
        return "<p class=\"muted off-note\">Event collection is turned off. This server was "
               "started with <code>--no-analytics</code>.</p>";
    // Enabled but there is no store object at all (no pool, or startup failed before it).
    if (!v.store_present)
        return "<div class=\"alert alert-error\" role=\"alert\"><div><b>Event collection is "
               "enabled but not running.</b> This is not 'no events'.</div></div>";
    // The store stays constructed when its migration failed: a different, startup-time fault.
    if (!v.store_open)
        return "<div class=\"alert alert-error\" role=\"alert\"><div><b>Event collection is "
               "enabled but its store did not open at startup.</b> This is not 'no "
               "events'.</div></div>";

    std::string html = "<div class=\"counts\">";
    html += chip("Pending",
                 v.pending ? std::to_string(*v.pending) : "<span class=\"unk\">Unknown</span>");
    html += chip("Emitted by this server since it started",
                 std::to_string(v.emitted_by_this_server));
    html += "</div>";

    if (!v.sink_configured)
        html += "<div class=\"note warn nosink-note\">No sink is configured, so events stay in the "
                "database buffer and are not forwarded.</div>";

    if (!v.recent) {
        html += "<div class=\"alert alert-error\" role=\"alert\"><div><b>Recent events could not "
                "be read.</b> This is not 'no events'.</div></div>";
        return html;
    }
    if (v.recent->empty()) {
        html += "<div class=\"empty-state\"><b>No events buffered yet.</b></div>";
        return html;
    }

    html += "<div class=\"tbox tw\"><table><thead><tr><th>Event type</th><th>Source</th>"
            "<th>Severity</th><th>Time (UTC)</th></tr></thead><tbody>";
    for (const auto& e : *v.recent) {
        html += "<tr><td class=\"et\"><code>" + html_escape(e.event_type) + "</code></td><td>" +
                html_escape(e.source) + "</td><td>" + html_escape(e.severity) +
                "</td><td class=\"tm\">" + format_iso_utc(e.event_time_ms / 1000) + "</td></tr>";
    }
    html += "</tbody></table></div>";
    html += "<p class=\"hint evt-foot\">Newest " + std::to_string(kRecentEventsLimit) +
            " events. Event details are not shown.</p>";
    return html;
}

// ── Routes ──────────────────────────────────────────────────────────────

void register_settings_general_routes(HttpRouteSink& sink, Deps deps) {
    // The page: a non-admin is refused by the gate (a 403 body and a denied audit row, both
    // written by `require_admin`) and then sent to `/`, exactly as `/settings` does.
    sink.Get("/settings/general", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.admin_fn(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_header("Cache-Control", "no-store");
        res.set_content(kSettingsGeneralHtml, "text/html; charset=utf-8");
    });

    sink.Get("/fragments/settings/general-runtime",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.admin_fn(req, res))
                     return;
                 res.set_header("Cache-Control", "no-store");
                 res.set_content(render_general_runtime(deps.runtime_fn()),
                                 "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/analytics-events",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.admin_fn(req, res))
                     return;
                 res.set_header("Cache-Control", "no-store");
                 res.set_content(render_analytics_events(deps.events_fn()),
                                 "text/html; charset=utf-8");
             });
}

} // namespace yuzu::server::settings_general
