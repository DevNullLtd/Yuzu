#include "instruction_fragment_routes.hpp"

#include "http_route_sink.hpp"
#include "instruction_extras_render.hpp"
#include "instruction_store.hpp"
#include "response_templates_engine.hpp"
#include "web_utils.hpp" // html_escape

#include <httplib.h>

#include <cctype>
#include <expected>
#include <regex>
#include <string>
#include <string_view>

namespace yuzu::server::instruction_fragment {

namespace {

// Percent-encode everything outside RFC 3986 "unreserved" so a legacy id holding arbitrary
// text cannot inject a query parameter into an hx-get URL.
std::string url_encode(const std::string& v) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : v) {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 15];
        }
    }
    return out;
}

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
        // The text sits in one .yt span so a flex .yl row keeps its indentation (a bare
        // whitespace text node is not rendered as a flex item).
        result += "<div class=\"yl\"><span class=\"ln\">" + std::to_string(line_num++) +
                  "</span><span class=\"yt\">";
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
        result += "</span></div>";
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

            // Filters and page size. `limit+1` is requested so a full page can be told
            // apart from a truncated one; the extra row is never rendered. Over-long
            // filter text cannot match any real name/plugin/type and is refused
            // rather than silently shortened (which would widen the match).
            constexpr std::size_t kMaxFilterLen = 128;
            InstructionQuery q;
            q.name_filter = req.get_param_value("name");
            q.plugin_filter = req.get_param_value("plugin");
            q.type_filter = req.get_param_value("type");
            if (q.name_filter.size() > kMaxFilterLen || q.plugin_filter.size() > kMaxFilterLen ||
                q.type_filter.size() > kMaxFilterLen) {
                res.set_content("<div class=\"empty-state\">Filter text is too long.</div>",
                                "text/html; charset=utf-8");
                return;
            }
            const int limit = instruction_extras::clamp_library_limit(req.get_param_value("limit"));
            q.limit = limit + 1;

            // ADR-0058: query_definitions returns std::expected -- a genuine DB error
            // is a degraded read, never an empty library.
            auto defs_result = deps.store->query_definitions(q);
            if (!defs_result) {
                res.set_content(instruction_extras::render_library_degraded(),
                                "text/html; charset=utf-8");
                return;
            }
            auto& defs = *defs_result;
            const bool truncated = defs.size() > static_cast<std::size_t>(limit);
            if (truncated)
                defs.resize(static_cast<std::size_t>(limit));

            // Capability probes, at most once each per render (never per row). An
            // unwired probe means "cannot decide": no extra is rendered, the New/Edit
            // buttons keep the role test, and the output is the pre-extras fragment.
            const bool wired = static_cast<bool>(deps.probe_perm_fn);
            auto probe = [&](const char* securable, const char* op) {
                return wired && deps.probe_perm_fn(req, securable, op);
            };
            const bool show_approval = probe("InstructionDefinition", "Read");
            const bool def_write = probe("InstructionDefinition", "Write");
            const bool def_delete = probe("InstructionDefinition", "Delete");
            const bool show_sets = probe("InstructionSet", "Read");
            const bool set_write = show_sets && probe("InstructionSet", "Write");
            const bool set_delete = show_sets && probe("InstructionSet", "Delete");
            const bool probe_sets = wired;

            // New/Edit are a permission (a PlatformEngineer who may write sees them), not
            // a role; with no probe wired the legacy admin test stands. effective_role so
            // an active JIT elevation also reveals the authoring UI.
            const bool can_author =
                wired ? def_write : (auth::effective_role(*session) == auth::Role::admin);
            // Delete is shown to every viewer today; with a probe it follows the permission.
            const bool can_delete = wired ? def_delete : true;

            // Sets are read once, up front: the set select on each row and the sets panel
            // share the one read. Absent when the caller may not read sets or it degraded.
            std::expected<std::vector<InstructionSet>, std::string> sets_read =
                std::unexpected(std::string("not read"));
            if (show_sets)
                sets_read = deps.store->list_sets();

            std::string html;
            // Panel header with New button for Platform Engineers
            html += "<section class=\"panel\"><div class=\"hd\"><h2>";
            html += "<strong>" + std::to_string(defs.size()) + "</strong> definitions";
            html += "</h2><div class=\"end\">";
            if (can_author) {
                html += "<button class=\"btn btn-primary\" onclick=\"openEditor()\">"
                        "New Definition</button>";
                if (wired)
                    html += " <button type=\"button\" class=\"btn btn-secondary\" "
                            "data-ox=\"import\">Import definition</button>";
            }
            html += "</div></div>";
            if (wired)
                html += instruction_extras::render_library_filter_form(
                    q.name_filter, q.plugin_filter, q.type_filter);
            // Host for the per-definition templates panel (loaded by the row's Templates
            // button). Directly under the toolbar, above the table: below a 100-row table it
            // loaded off-screen and the click looked like it did nothing.
            if (show_approval)
                html += "<div id=\"ox-templates\"></div>";

            if (defs.empty()) {
                html += "<div class=\"empty-state\">No instruction definitions yet.";
                if (can_author)
                    html += " Click <strong>New Definition</strong> to create one.";
                html += "</div>";
            } else {
                html += "<div class=\"tw\"><table><thead><tr><th>Name</th><th>Plugin:Action</"
                        "th><th>Type</th>";
                if (show_approval)
                    html += "<th>Needs approval</th>";
                html += "<th>Enabled</th><th>Set</th><th></th></tr></thead><tbody>";
                for (const auto& d : defs) {
                    bool is_legacy = d.id.starts_with("legacy.");
                    html += "<tr><td><strong>" + html_escape(d.name) + "</strong>";
                    if (is_legacy)
                        html += " <span class=\"legacy-badge\">legacy</span>";
                    html += "<span class=\"sub-id\">" + html_escape(d.id.substr(0, 12)) +
                            "</span></td>"
                            "<td><code>" +
                            html_escape(d.plugin) + ":" + html_escape(d.action) +
                            "</code></td>"
                            "<td><span class=\"status-badge status-idle\">" +
                            html_escape(d.type) +
                            "</span></td>";
                    if (show_approval)
                        html += std::string("<td>") +
                                instruction_extras::approval_label(d.approval_mode) + "</td>";
                    html += "<td>" + std::string(d.enabled ? "Yes" : "No") + "</td><td>";
                    // Assignment is PUT /api/instructions/:id, gated on InstructionDefinition:Write, so the
                    // select needs that, not just InstructionSet:Write.
                    if (set_write && def_write && sets_read) {
                        html += instruction_extras::render_set_select(d.id, d.instruction_set_id,
                                                                      *sets_read);
                    } else {
                        html += html_escape(d.instruction_set_id.empty()
                                                ? "-"
                                                : d.instruction_set_id.substr(0, 8));
                    }
                    html += "</td><td class=\"act\">";
                    if (show_approval) {
                        html += "<button type=\"button\" class=\"btn btn-secondary btn-sm\" "
                                "hx-get=\"/fragments/instructions/templates?id=" +
                                url_encode(d.id) +
                                "\" hx-target=\"#ox-templates\" "
                                "hx-swap=\"innerHTML show:#ox-templates:top\">"
                                "Templates</button> "
                                "<button type=\"button\" class=\"btn btn-secondary btn-sm\" "
                                "data-ox=\"export\" data-def-id=\"" +
                                html_escape(d.id) + "\" data-def-name=\"" + html_escape(d.name) +
                                "\">Export</button> ";
                    }
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
                    if (can_delete) {
                        html += "<button class=\"btn btn-danger btn-sm\" "
                                "hx-delete=\"/api/instructions/" +
                                html_escape(d.id) +
                                "\" hx-target=\"#tab-definitions\" hx-swap=\"innerHTML\" "
                                "hx-confirm=\"Delete definition '" +
                                html_escape(d.name) + "'?\">Delete</button>";
                    }
                    html += "</td></tr>";
                }
                html += "</tbody></table></div>";
            }
            html += instruction_extras::render_library_foot(limit, truncated);
            html += "</section>";

            if (probe_sets) {
                if (!show_sets) {
                    html += instruction_extras::render_sets_denied();
                } else if (!sets_read) {
                    html += instruction_extras::render_sets_degraded();
                } else {
                    // Exact per-set counts from a GROUP BY: independent of the filtered /
                    // truncated library page, and never capped.
                    auto counts = deps.store->count_definitions_per_set();
                    if (!counts) {
                        html += instruction_extras::render_sets_degraded();
                    } else {
                        std::vector<instruction_extras::SetRow> rows;
                        for (const auto& st : *sets_read) {
                            const auto it = counts->find(st.id);
                            rows.push_back({st, it == counts->end() ? 0 : it->second});
                        }
                        html += instruction_extras::render_instruction_sets_panel(
                            rows, /*counts_partial=*/false, set_write, set_delete);
                    }
                }
            }
            res.set_content(html, "text/html; charset=utf-8");
        });

    // -- Response templates for one definition (twin of REST v1
    // GET /api/v1/definitions/{id}/response-templates). Loud gate; a denial is an HTTP 200
    // note because htmx drops 4xx bodies. Writes go straight to REST v1 from the dialogs.
    sink.Get(
        "/fragments/instructions/templates",
        [deps](const httplib::Request& req, httplib::Response& res) {
            auto emit = [&](const std::string& body) {
                res.set_content(body, "text/html; charset=utf-8");
            };
            if (deps.deny_service_scoped_fn(
                    req, res, "instructions.fragment.access_denied",
                    "service-scoped tokens may not read response templates", "", ""))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (deps.probe_perm_fn) {
                if (!deps.probe_perm_fn(req, "InstructionDefinition", "Read")) {
                    emit(instruction_extras::render_templates_denied());
                    return;
                }
            } else if (!deps.perm_fn(req, res, "InstructionDefinition", "Read")) {
                return;
            }
            static const std::regex kId{"^[A-Za-z0-9._-]{1,128}$"};
            const auto id = req.get_param_value("id");
            if (!deps.store || !std::regex_match(id, kId)) {
                emit(instruction_extras::render_templates_degraded());
                return;
            }
            auto def = deps.store->get_definition(id);
            if (!def) {
                emit(instruction_extras::render_templates_degraded());
                return;
            }
            if (!*def) {
                emit(instruction_extras::render_templates_not_found());
                return;
            }
            ResponseTemplatesEngine engine;
            auto parsed = engine.parse((*def)->response_templates_spec);
            if (!parsed) {
                emit(instruction_extras::render_templates_degraded());
                return;
            }
            const bool can_write =
                deps.probe_perm_fn && deps.probe_perm_fn(req, "InstructionDefinition", "Write");
            emit(instruction_extras::render_templates_panel(id, (*def)->name, *parsed, can_write));
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
