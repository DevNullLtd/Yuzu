#include "developer_render.hpp"

#include "web_utils.hpp" // html_escape

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace yuzu::server::developer {

namespace {

using nlohmann::json;

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool contains_ci(std::string_view hay, const std::string& needle_lower) {
    return needle_lower.empty() || lower(hay).find(needle_lower) != std::string::npos;
}

std::string str_of(const json& j, const char* key) {
    if (j.is_object()) {
        const auto it = j.find(key);
        if (it != j.end() && it->is_string())
            return it->get<std::string>();
    }
    return {};
}

std::string pct_encode(std::string_view s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0xF];
        }
    }
    return out;
}

std::string esc(std::string_view s) {
    return html_escape(std::string(s));
}

std::string cap_banner(std::size_t shown, std::size_t total) {
    return "<p class=\"hint\" style=\"padding:10px 16px\">Showing " + std::to_string(shown) + " of " +
           std::to_string(total) + ". Narrow the filter.</p>";
}

std::string table_open(const char* c1, const char* c2, const char* c3 = nullptr) {
    std::string h = "<div class=\"tw\"><table><thead><tr><th>";
    h += c1;
    h += "</th><th>";
    h += c2;
    h += "</th>";
    if (c3) {
        h += "<th>";
        h += c3;
        h += "</th>";
    }
    h += "</tr></thead><tbody>";
    return h;
}

constexpr const char* kTableClose = "</tbody></table></div>";

} // namespace

std::string clean_filter(std::string_view raw) {
    std::string out(raw.substr(0, kFilterMaxLen));
    for (auto& c : out)
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f)
            c = ' ';
    return out;
}

std::string render_state(std::string_view kind, std::string_view text) {
    const bool fail = kind == "fail";
    std::string h = "<div class=\"note";
    h += fail ? " warn\" role=\"alert\"" : "\" role=\"note\"";
    h += " data-state=\"";
    h += esc(kind);
    h += "\">";
    h += esc(text);
    h += "</div>";
    return h;
}

std::string render_api_panel(std::size_t operation_count) {
    std::string h = "<div class=\"kvl\">"
                    "<div><span>OpenAPI document</span><b class=\"mono\">/api/v1/openapi.json</b></div>"
                    "<div><span>Operations documented in OpenAPI</span><b>";
    h += operation_count > 0 ? std::to_string(operation_count) : std::string("Unavailable");
    h += "</b></div>"
         "<div><span>MCP endpoint</span><b class=\"mono\">POST /mcp/v1/</b></div></div>";
    if (operation_count == 0)
        h += render_state("fail", "The route catalogue could not be read.");
    h += "<p class=\"hint\" style=\"padding:12px 16px 0\">The document is maintained by hand and can "
         "omit a route that exists.</p>"
         "<p class=\"hint\" style=\"padding:6px 16px 0\">Send a session cookie, <span class=\"mono\">"
         "Authorization: Bearer &lt;token&gt;</span> or <span class=\"mono\">X-Yuzu-Token: "
         "&lt;token&gt;</span>. Create tokens under API Tokens in Settings.</p>"
         "<div class=\"btns\" style=\"padding-top:12px\"><a class=\"btn primary\" "
         "href=\"/api/v1/openapi.json\" target=\"_blank\" rel=\"noopener\">Open OpenAPI "
         "document</a></div>";
    return h;
}

std::string render_routes_table(const json& doc, std::string_view q_raw) {
    const auto routes = doc.is_object() ? doc.find("routes") : doc.end();
    const std::size_t total =
        doc.is_object() && doc.contains("count") && doc["count"].is_number_unsigned()
            ? doc["count"].get<std::size_t>()
            : 0;
    if (!doc.is_object() || routes == doc.end() || !routes->is_array() || total == 0)
        return render_state("fail", "The route catalogue could not be read.");

    const std::string q = lower(clean_filter(q_raw));
    std::vector<const json*> match;
    for (const auto& r : *routes) {
        if (!r.is_object())
            continue;
        if (q.empty() || contains_ci(str_of(r, "path"), q) || contains_ci(str_of(r, "summary"), q))
            match.push_back(&r);
    }
    if (match.empty())
        return render_state("empty", "No operation matches \"" + clean_filter(q_raw) + "\".");

    const std::size_t shown = std::min(match.size(), kRoutesCap);
    std::string h = "<p class=\"hint\" style=\"padding:10px 16px\">REST v1 only. The dashboard's own "
                    "routes (/api/..., /fragments/...) are not listed.</p>";
    h += table_open("Method", "Path", "Tags");
    for (std::size_t i = 0; i < shown; ++i) {
        const json& r = *match[i];
        h += "<tr><td><span class=\"pill idle\">" + esc(str_of(r, "method")) + "</span></td><td><div "
             "class=\"mono\">" +
             esc(str_of(r, "path")) + "</div>";
        if (const auto s = str_of(r, "summary"); !s.empty())
            h += "<div class=\"hint\">" + esc(s) + "</div>";
        h += "</td><td>";
        if (r.contains("tags") && r["tags"].is_array())
            for (const auto& t : r["tags"])
                if (t.is_string())
                    h += "<span class=\"pill info\">" + esc(t.get<std::string>()) + "</span> ";
        h += "</td></tr>";
    }
    h += kTableClose;
    if (match.size() > shown)
        h += cap_banner(shown, match.size());
    return h;
}

std::string render_permissions_table(const json& doc, std::string_view q_raw) {
    if (!doc.is_object() || !doc.contains("securable_types") || !doc["securable_types"].is_array() ||
        !doc.contains("operations") || !doc["operations"].is_array())
        return render_state("fail",
                            "The permission catalogue could not be read. This is not an empty list.");

    const auto& types = doc["securable_types"];
    const auto& ops = doc["operations"];
    std::string h = "<p class=\"hint\" style=\"padding:10px 16px\">" + std::to_string(types.size()) +
                    " securable types, " + std::to_string(ops.size()) + " operations</p>";

    if (doc.value("roles_omitted", false)) {
        h += render_state("denied", "Role grants need the Users and roles read permission "
                                    "(UserManagement:Read). The permission names themselves are "
                                    "not shown without it.");
        return h;
    }

    // Roles that allow each (securable, operation), in document order.
    std::map<std::pair<std::string, std::string>, std::vector<std::string>> used_by;
    if (doc.contains("roles") && doc["roles"].is_array()) {
        for (const auto& role : doc["roles"]) {
            const auto name = str_of(role, "name");
            if (name.empty() || !role.contains("permissions") || !role["permissions"].is_array())
                continue;
            for (const auto& p : role["permissions"])
                if (str_of(p, "effect") == "allow")
                    used_by[{str_of(p, "securable_type"), str_of(p, "operation")}].push_back(name);
        }
    }

    const std::string q = lower(clean_filter(q_raw));
    std::vector<std::pair<std::string, const std::vector<std::string>*>> rows;
    for (const auto& t : types) {
        if (!t.is_string() || !contains_ci(t.get<std::string>(), q))
            continue;
        for (const auto& o : ops) {
            if (!o.is_string())
                continue;
            const auto it = used_by.find({t.get<std::string>(), o.get<std::string>()});
            if (it != used_by.end())
                rows.emplace_back(t.get<std::string>() + ":" + o.get<std::string>(), &it->second);
        }
    }
    if (rows.empty())
        return h + render_state("empty", "No permission matches \"" + clean_filter(q_raw) + "\".");

    const std::size_t shown = std::min(rows.size(), kPermissionsCap);
    h += table_open("Permission", "Used by");
    for (std::size_t i = 0; i < shown; ++i) {
        h += "<tr><td class=\"mono\">" + esc(rows[i].first) + "</td><td>";
        const auto& roles = *rows[i].second;
        for (std::size_t k = 0; k < roles.size(); ++k)
            h += (k ? ", " : "") + esc(roles[k]);
        h += "</td></tr>";
    }
    h += kTableClose;
    if (rows.size() > shown)
        h += cap_banner(shown, rows.size());
    h += "<p class=\"hint\" style=\"padding:10px 16px\">These grants take effect while RBAC "
         "enforcement is on. With it off, only the account role is checked.</p>";
    return h;
}

namespace {

std::string platforms_cell(const json& manifest) {
    static constexpr std::pair<const char*, const char*> kOs[] = {
        {"linux", "Linux"}, {"macos", "macOS"}, {"windows", "Windows"}};
    static const std::set<std::string> kKnown{"supported", "constrained", "planned", "unsupported",
                                              "undeclared"};
    std::string out;
    const auto pf = manifest.is_object() && manifest.contains("platforms") ? manifest["platforms"]
                                                                           : json::object();
    for (const auto& [key, label] : kOs) {
        std::string v = str_of(pf, key);
        if (!kKnown.count(v))
            v = "unknown";
        out += std::string(out.empty() ? "" : ", ") + label + " " + esc(v);
    }
    return out;
}

std::set<std::string> documented_names(const json& docs_doc) {
    std::set<std::string> names;
    if (docs_doc.is_object() && docs_doc.contains("plugins") && docs_doc["plugins"].is_array())
        for (const auto& p : docs_doc["plugins"])
            if (const auto n = str_of(p, "name"); !n.empty())
                names.insert(n);
    return names;
}

} // namespace

std::string render_plugins_table(const json& docs) {
    if (!docs.is_object() || !docs.contains("plugins") || !docs["plugins"].is_array())
        return render_state("fail", "The plugin documentation could not be read.");

    std::string h;
    if (docs.value("skipped_invalid", 0) > 0)
        h += render_state("fail", std::to_string(docs.value("skipped_invalid", 0)) +
                                      " plugin manifests in this build could not be read.");
    const auto& plugins = docs["plugins"];
    const std::size_t shown = std::min(plugins.size(), kPluginsCap);
    h += table_open("Plugin", "Platforms", "Docs");
    for (std::size_t i = 0; i < shown; ++i) {
        const json& p = plugins[i];
        const auto name = str_of(p, "name");
        h += "<tr><td><div class=\"mono\">" + esc(name) + "</div>";
        if (const auto d = str_of(p, "description"); !d.empty())
            h += "<div class=\"hint\" style=\"white-space:normal\">" + esc(d) + "</div>";
        if (p.contains("kind") && p["kind"].is_object()) {
            const auto& k = p["kind"];
            h += k.value("collector", false) ? "<span class=\"pill idle\">Collector</span> " : "";
            h += k.value("mutating", false) ? "<span class=\"pill warn\">Changes devices</span>" : "";
        }
        h += "</td><td>" + platforms_cell(p) + "</td><td><a href=\"/api/v1/discover/plugin-docs/" +
             pct_encode(name) + "\" target=\"_blank\" rel=\"noopener\">Manifest (JSON)</a></td></tr>";
    }
    h += kTableClose;
    if (plugins.size() > shown)
        h += cap_banner(shown, plugins.size());
    h += "<div class=\"btns\" style=\"padding-top:12px\"><button type=\"button\" class=\"btn sm\" "
         "hx-get=\"/fragments/settings/developer/plugins/observed\" "
         "hx-target=\"#dev-plugins-observed\" hx-swap=\"innerHTML\">Show plugins reported by "
         "connected devices</button></div><div id=\"dev-plugins-observed\" "
         "class=\"dev-body\"></div>";
    return h;
}

std::string render_observed_plugins(const json& plugins_doc, const json& docs_doc) {
    if (!plugins_doc.is_object() || !plugins_doc.contains("plugins") ||
        !plugins_doc["plugins"].is_array())
        return render_state("fail", "The list of plugins reported by devices could not be read.");

    const auto documented = documented_names(docs_doc);
    std::set<std::string> seen; // dedupe, sorted
    for (const auto& p : plugins_doc["plugins"])
        if (const auto n = str_of(p, "name"); !n.empty())
            seen.insert(n);
    if (seen.empty())
        return render_state("empty", "No device is connected, so no plugins are being reported. "
                                     "The plugins documented in this build are listed above.");

    std::string h = table_open("Reported by devices", "Documented");
    std::size_t shown = 0;
    for (const auto& n : seen) {
        if (shown++ >= kPluginsCap)
            break;
        h += "<tr><td class=\"mono\">" + esc(n) + "</td><td>";
        // Link only names that are in the compiled catalogue: the string is
        // agent-reported, so it is never trusted as a path.
        if (documented.count(n))
            h += "<a href=\"/api/v1/discover/plugin-docs/" + pct_encode(n) +
                 "\" target=\"_blank\" rel=\"noopener\">Manifest (JSON)</a>";
        else
            h += "No manifest";
        h += "</td></tr>";
    }
    h += kTableClose;
    if (seen.size() > kPluginsCap)
        h += cap_banner(kPluginsCap, seen.size());
    return h;
}

} // namespace yuzu::server::developer
