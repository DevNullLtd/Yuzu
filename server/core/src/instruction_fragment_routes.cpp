#include "instruction_fragment_routes.hpp"

#include "http_route_sink.hpp"
#include "instruction_store.hpp"
#include "web_utils.hpp" // html_escape

#include <httplib.h>

#include <cctype>
#include <string>
#include <string_view>

namespace yuzu::server::instruction_fragment {

namespace {

// -- Server-side YAML syntax highlighter ----------------------------------
// Used by the instruction editor's yaml-preview fragment below. Moved
// (not duplicated) from ServerImpl's private statics in server.cpp
// (#2542 PR-12) — see this file's header comment for why these three
// functions, unlike validate_yaml_source, were not promoted to a shared
// header. A SEPARATE, independent copy exists in settings_routes.cpp
// (anonymous namespace) for the unrelated Settings YAML preview feature —
// not the same function (single-argument, no `key`-based semantic
// classes) and intentionally left untouched by this move.

std::string highlight_yaml_value(const std::string& val, const std::string& key = {}) {
    if (val.empty())
        return {};
    auto trimmed = val;
    auto sp = trimmed.find_first_not_of(' ');
    if (sp == std::string::npos)
        return html_escape(val);
    trimmed = trimmed.substr(sp);
    // Semantic highlighting: color specific key:value pairs to match the legend.
    if (key == "type" && (trimmed == "question" || trimmed == "\"question\""))
        return "<span class=\"yq\">" + html_escape(val) + "</span>";
    if (key == "type" && (trimmed == "action" || trimmed == "\"action\""))
        return "<span class=\"yact\">" + html_escape(val) + "</span>";
    if (key == "approval" && (trimmed == "required" || trimmed == "\"required\""))
        return "<span class=\"yar\">" + html_escape(val) + "</span>";
    if (key == "concurrency" && (trimmed == "single" || trimmed == "serial" ||
                                 trimmed == "\"single\"" || trimmed == "\"serial\""))
        return "<span class=\"ycc\">" + html_escape(val) + "</span>";
    if (trimmed == "true" || trimmed == "false" || trimmed == "True" || trimmed == "False")
        return "<span class=\"yb\">" + html_escape(val) + "</span>";
    bool is_number = !trimmed.empty();
    for (char c : trimmed) {
        if (c != '-' && c != '.' && (c < '0' || c > '9')) {
            is_number = false;
            break;
        }
    }
    if (is_number && !trimmed.empty())
        return "<span class=\"yn\">" + html_escape(val) + "</span>";
    return "<span class=\"yv\">" + html_escape(val) + "</span>";
}

std::string highlight_yaml_kv(const std::string& line) {
    std::size_t i = 0;
    while (i < line.size() && line[i] == ' ')
        ++i;
    auto key_start = i;
    while (i < line.size() && (std::isalnum(static_cast<unsigned char>(line[i])) ||
                               line[i] == '_' || line[i] == '-' || line[i] == '.'))
        ++i;
    if (i >= line.size() || line[i] != ':' || i == key_start)
        return html_escape(line);
    auto indent = line.substr(0, key_start);
    auto key = line.substr(key_start, i - key_start);
    auto rest = line.substr(i + 1);
    bool is_schema = (key == "apiVersion" || key == "kind");
    std::string key_cls = is_schema ? "ya" : "yk";
    return html_escape(indent) + "<span class=\"" + key_cls + "\">" + html_escape(key) +
           "</span>:" + highlight_yaml_value(rest, key);
}

std::string highlight_yaml(std::string_view source) {
    std::string result;
    result.reserve(source.size() * 2);
    int line_num = 1;
    std::size_t pos = 0;
    while (pos <= source.size()) {
        auto nl = source.find('\n', pos);
        std::string line;
        if (nl == std::string_view::npos) {
            line = std::string(source.substr(pos));
            pos = source.size() + 1;
        } else {
            line = std::string(source.substr(pos, nl - pos));
            pos = nl + 1;
        }
        result +=
            "<div class=\"yl\"><span class=\"ln\">" + std::to_string(line_num++) + "</span>";
        auto trimmed_start = line.find_first_not_of(' ');
        if (trimmed_start == std::string::npos) {
            result += "&nbsp;";
        } else if (line[trimmed_start] == '#') {
            result += "<span class=\"yc\">" + html_escape(line) + "</span>";
        } else if (line == "---" || line == "...") {
            result += "<span class=\"yd\">" + html_escape(line) + "</span>";
        } else if (line[trimmed_start] == '-' && trimmed_start + 1 < line.size() &&
                   line[trimmed_start + 1] == ' ') {
            auto indent2 = line.substr(0, trimmed_start);
            auto after_dash = line.substr(trimmed_start + 2);
            result += html_escape(indent2) + "<span class=\"yd\">-</span> ";
            if (after_dash.find(':') != std::string::npos)
                result += highlight_yaml_kv(after_dash);
            else
                result += highlight_yaml_value(after_dash);
        } else if (line.find(':') != std::string::npos) {
            result += highlight_yaml_kv(line);
        } else {
            result += html_escape(line);
        }
        result += "</div>";
    }
    return result;
}

} // namespace

void register_instruction_fragment_routes(HttpRouteSink& sink, Deps deps) {
    // -- HTMX Fragment Routes for Instructions UI -------------------------

    sink.Get(
        "/fragments/instructions", [deps](const httplib::Request& req, httplib::Response& res) {
            // guardian-confinement-2298 PR3 §3e: require_auth-only; the
            // role check below (`can_author`) gates only the New/Edit
            // buttons, not the definitions list itself.
            if (deps.deny_service_scoped_fn(
                    req, res, "instructions.fragment.access_denied",
                    "service-scoped tokens may not read the fleet-wide instruction "
                    "definitions list",
                    "", ""))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!deps.store) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            // ADR-0058: query_definitions now returns std::expected — a genuine DB
            // error degrades to the same "Not available" fragment as a null store.
            auto defs_result = deps.store->query_definitions();
            if (!defs_result) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }
            const auto& defs = *defs_result;

            // Check if user has PlatformEngineer or Administrator role
            // PlatformEngineer or Administrator can author definitions.
            // When RBAC enforcement is fully wired, this will check the
            // PlatformEngineer role via RbacStore::check_permission().
            // effective_role so an active JIT elevation also reveals the
            // authoring UI (the POST already gates on effective_role).
            bool can_author = (auth::effective_role(*session) == auth::Role::admin);

            std::string html;
            // Toolbar with New button for Platform Engineers
            html += "<div class=\"toolbar\"><div>";
            html += "<strong>" + std::to_string(defs.size()) + "</strong> definitions";
            html += "</div><div>";
            if (can_author) {
                html += "<button class=\"btn btn-primary\" onclick=\"openEditor()\">"
                        "New Definition</button>";
            }
            html += "</div></div>";

            if (defs.empty()) {
                html += "<div class=\"empty-state\">No instruction definitions yet.";
                if (can_author)
                    html += " Click <strong>New Definition</strong> to create one.";
                html += "</div>";
            } else {
                html += "<table><thead><tr><th>Name</th><th>Plugin:Action</th><th>Type</"
                        "th><th>Enabled</th><th>Set</th><th></th></tr></thead><tbody>";
                for (const auto& d : defs) {
                    auto type_cls = d.type == "question" ? "status-running" : "status-pending";
                    bool is_legacy = d.id.starts_with("legacy.");
                    html += "<tr><td><strong>" + html_escape(d.name) + "</strong>";
                    if (is_legacy)
                        html += " <span class=\"legacy-badge\">legacy</span>";
                    html += "<br><span style=\"font-size:0.65rem;color:#8b949e\">" +
                            html_escape(d.id.substr(0, 12)) +
                            "</span></td>"
                            "<td><code>" +
                            html_escape(d.plugin) + ":" + html_escape(d.action) +
                            "</code></td>"
                            "<td><span class=\"status-badge " +
                            type_cls + "\">" + html_escape(d.type) +
                            "</span></td>"
                            "<td>" +
                            std::string(d.enabled ? "Yes" : "No") +
                            "</td>"
                            "<td>" +
                            html_escape(d.instruction_set_id.empty()
                                            ? "-"
                                            : d.instruction_set_id.substr(0, 8)) +
                            "</td>"
                            "<td>";
                    // d.id is operator-chosen since #402 (JSON create) /
                    // #1993 (YAML metadata.id). The store now bounds NEW
                    // ids to [A-Za-z0-9._-]{1,128}, but a row that predates
                    // that gate may hold arbitrary text — so encode it for
                    // the DOM at every interpolation (governance sec-M1).
                    // The Edit control carries the id in a data-attribute
                    // (html_escape makes it a safe attribute value) and
                    // reads it back via this.dataset.defId, NOT string-
                    // interpolated into the onclick JS: the browser
                    // entity-decodes an attribute BEFORE the JS parser runs,
                    // so a bare html_escape inside onclick="openEditor('…')"
                    // would still let a legacy id break out of the string
                    // and execute in the admin's session (Gate 8 SEC-1).
                    if (can_author) {
                        html += "<button class=\"btn btn-secondary btn-sm\" "
                                "data-def-id=\"" +
                                html_escape(d.id) +
                                "\" onclick=\"openEditor(this.dataset.defId)\">Edit</button> ";
                    }
                    html += "<button class=\"btn btn-danger btn-sm\" "
                            "hx-delete=\"/api/instructions/" +
                            html_escape(d.id) +
                            "\" hx-target=\"#tab-definitions\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Delete definition '" +
                            html_escape(d.name) + "'?\">Delete</button></td></tr>";
                }
                html += "</tbody></table>";
            }
            res.set_content(html, "text/html; charset=utf-8");
        });

    // -- YAML preview endpoint (server-side highlighting + validation) --
    sink.Post(
        "/fragments/instructions/yaml-preview",
        [deps](const httplib::Request& req, httplib::Response& res) {
            if (!deps.perm_fn(req, res, "InstructionDefinition", "Read"))
                return;

            auto yaml_source = req.get_param_value("yaml_source");
            auto highlighted = highlight_yaml(yaml_source);
            auto errors = validate_yaml_source(yaml_source);

            std::string html = highlighted;
            if (!errors.empty()) {
                html += R"(<div id="yaml-errors" hx-swap-oob="innerHTML:#yaml-errors">)";
                for (const auto& e : errors)
                    html += "<div class='err'>" + html_escape(e) + "</div>";
                html += "</div>";
            } else {
                html += R"(<div id="yaml-errors" hx-swap-oob="innerHTML:#yaml-errors"></div>)";
            }
            res.set_content(html, "text/html");
        });
}

} // namespace yuzu::server::instruction_fragment
