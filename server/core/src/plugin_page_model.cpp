#include "plugin_page_model.hpp"

#include "web_utils.hpp"

namespace yuzu::server::plugin_page {

namespace {

std::string esc(const std::string& s) {
    return html_escape(s);
}

std::string degraded_note(const char* what) {
    return std::string("<div class=\"failbox\" role=\"alert\"><b>") + what +
           " could not be read.</b> This is not an empty list. Reload to retry.</div>";
}

std::string pill(const char* cls, const std::string& text, const std::string& title = {}) {
    std::string h = std::string("<span class=\"pill ") + cls + "\"";
    if (!title.empty())
        h += " title=\"" + esc(title) + "\"";
    return h + ">" + esc(text) + "</span>";
}

std::string when_ms(std::int64_t ms) {
    return ms > 0 ? format_iso_utc(ms / 1000) : std::string("\xE2\x80\x94");
}

} // namespace

std::string denied_note(const char* permission) {
    return "<div class=\"empty\" data-denied=\"1\"><b>Not permitted</b>You need the " +
           std::string(permission) + " permission to see this panel.</div>";
}

std::string layer_label(const std::string& os) {
    if (os == "windows")
        return "Windows";
    if (os == "linux")
        return "Linux";
    if (os == "darwin")
        return "macOS";
    return "All operating systems";
}

std::string clip_for_display(const std::string& s, std::size_t max_bytes) {
    return truncate_utf8(s, max_bytes);
}

// ── Plugin configuration ──────────────────────────────────────────────────

std::string render_config_panel(const ConfigPanel& p) {
    if (p.state == PanelState::Denied)
        return denied_note("PluginConfig:Read");
    if (p.state == PanelState::Degraded)
        return degraded_note("Plugin configuration");

    std::string h;
    h += "<div class=\"note\">Stored on the server. Delivery to agents is not built yet, so no "
         "plugin reads these values today. Values are plain and readable: put credentials in a "
         "secret, not here. Secrets are sealed when stored and cannot be listed or read back.</div>";
    h += "<div class=\"tw\"><table><thead><tr><th>Plugin</th><th>Setting</th><th>Value</th>"
         "<th>Updated by</th><th>Updated</th></tr></thead><tbody>";
    if (p.rows.empty())
        h += "<tr><td colspan=\"5\" class=\"muted\">No plugin settings stored.</td></tr>";
    for (const auto& r : p.rows) {
        h += "<tr><td><code>" + esc(r.plugin) + "</code></td><td><code>" + esc(r.key) +
             "</code></td><td class=\"wrap\" title=\"" + esc(r.value) + "\"><span class=\"mono\">" +
             esc(clip_for_display(r.value)) + "</span></td><td>" + esc(r.updated_by) +
             "</td><td class=\"nw\">" + when_ms(r.updated_at_ms) + "</td></tr>";
    }
    h += "</tbody></table></div>";
    if (p.truncated)
        h += "<div class=\"pb hint\">First " + std::to_string(p.row_cap) +
             " shown. Filter with <code>GET /api/v1/plugin-config?plugin=</code>.</div>";
    h += "<div class=\"pb hint\">Change a value with <code>PUT "
         "/api/v1/plugin-config/{plugin}/{key}</code> (MCP: <code>set_plugin_config</code>) and "
         "remove one with <code>DELETE</code> on the same path. Secrets: <code>PUT "
         ".../{key}/secret</code> (MCP: <code>set_plugin_secret</code>).</div>";
    return h;
}

// ── Kill switch ───────────────────────────────────────────────────────────

std::string render_kill_switch_panel(const KillSwitchPanel& p) {
    if (p.state == PanelState::Denied)
        return denied_note("PluginConfig:Read");
    if (p.state == PanelState::Degraded)
        return degraded_note("Kill switch state");

    std::string h;
    h += "<div class=\"note\">New commands for a switched-off plugin are refused by the server. "
         "Commands already sent, and work an agent starts by itself, are not recalled.</div>";

    h += "<form class=\"form row2\" hx-get=\"/fragments/settings/kill-switch\" "
         "hx-target=\"#kill-switch-section\" hx-swap=\"innerHTML\">"
         "<div class=\"fld\"><label for=\"ks-plugin\">Plugin</label>"
         "<input id=\"ks-plugin\" class=\"in\" name=\"plugin\" list=\"ks-plugins\" required "
         "autocomplete=\"off\" spellcheck=\"false\" maxlength=\"64\" value=\"" +
         esc(p.plugin) + "\"><datalist id=\"ks-plugins\">";
    for (const auto& n : p.known_plugins)
        h += "<option value=\"" + esc(n) + "\">";
    h += "</datalist></div><div class=\"fld\"><label for=\"ks-action\">Action "
         "<span class=\"hint\">(optional)</span></label>"
         "<input id=\"ks-action\" class=\"in\" name=\"action\" autocomplete=\"off\" "
         "spellcheck=\"false\" maxlength=\"64\" value=\"" +
         esc(p.action) +
         "\"></div><div class=\"btns\"><button class=\"btn\" type=\"submit\">Look up</button>"
         "</div></form>";

    if (!p.input_error.empty())
        return h + "<div class=\"pb\"><p class=\"feedback-error\">" + esc(p.input_error) +
               "</p></div>";
    if (p.plugin.empty())
        return h + "<div class=\"pb hint\">Enter a plugin to see its switch at the all-OS layer "
                   "and each OS layer. A plugin with no switch set runs.</div>";

    if (p.protective)
        h += "<div class=\"pb\"><div class=\"alert alert-warning\" role=\"status\"><span>The "
             "protective actions of this plugin are never refused by a kill switch. A row is "
             "stored and shown, but has no dispatch effect on them.</span></div></div>";
    // The catalogue is what connected agents have reported, so an unseen name is a warning,
    // not a refusal: a plugin no agent currently reports is legitimate.
    if (p.catalogue_available && (!p.plugin_known || (!p.action.empty() && !p.action_known))) {
        h += "<div class=\"pb\"><div class=\"alert alert-warning\" role=\"status\"><span>This "
             "server has not seen plugin '" +
             esc(p.plugin) + "'" +
             (p.plugin_known ? " action '" + esc(p.action) + "'" : std::string()) +
             " on any connected agent. A switch for a name that does not exist stops "
             "nothing.</span></div></div>";
    }

    h += "<div class=\"pb hint\">Switches at the all-OS layer and each OS layer. A per-OS row "
         "only narrows. Agents whose operating system is not yet known are not covered by a "
         "per-OS switch; if the presence read is degraded the server refuses the command "
         "instead.</div>";
    h += "<div class=\"tw\"><table><thead><tr><th>Layer</th><th>State</th><th>Reason</th>"
         "<th>Set by</th><th>When</th><th>Decided by</th></tr></thead><tbody>";
    for (const auto& l : p.layers) {
        h += "<tr><td>" + esc(layer_label(l.os)) + "</td><td>";
        switch (l.state) {
        case SwitchState::Enabled:
            h += pill("ok", "Enabled");
            break;
        case SwitchState::Disabled:
            h += pill("bad", "Disabled");
            break;
        case SwitchState::Unknown:
            h += pill("warn", "Unknown", "State unknown, store unavailable");
            break;
        }
        const bool has_row = !l.source.empty();
        h += "</td><td class=\"wrap\">" + (has_row ? esc(l.reason) : std::string("\xE2\x80\x94")) +
             "</td><td>" + (has_row ? esc(l.set_by) : std::string("\xE2\x80\x94")) +
             "</td><td class=\"nw\">" + (has_row ? when_ms(l.updated_at_ms) : "\xE2\x80\x94") +
             "</td><td>" +
             (has_row ? "<code>" + esc(l.source) + "</code>" : std::string("No switch set")) +
             "</td></tr>";
    }
    h += "</tbody></table></div>";
    h += "<div class=\"pb hint\">Set or clear a switch with <code>PUT "
         "/api/v1/plugin-config/{plugin}/kill-switch?action=&amp;os=</code> (MCP: "
         "<code>set_plugin_kill_switch</code>). Elsewhere in the console a refused dispatch "
         "reads as \"permission denied\" or \"no agents connected\".</div>";
    return h;
}

// ── Product packs ─────────────────────────────────────────────────────────

std::string render_packs_panel(const PacksPanel& p) {
    if (p.state == PanelState::Denied)
        return denied_note("ProductPack:Read");
    if (p.state == PanelState::Degraded)
        return degraded_note("Product packs");

    std::string h = "<div class=\"tw\"><table><thead><tr><th>Pack</th><th>Version</th>"
                    "<th>Items</th><th>Signed</th><th>Installed</th></tr></thead><tbody>";
    if (p.rows.empty())
        h += "<tr><td colspan=\"5\" class=\"muted\">No product packs installed.</td></tr>";
    for (const auto& r : p.rows) {
        h += "<tr><td class=\"wrap\"><b>" + esc(r.name) + "</b>";
        if (!r.description.empty())
            h += "<span class=\"sub\">" + esc(clip_for_display(r.description, 200)) + "</span>";
        h += "</td><td><code>" + esc(r.version) + "</code></td><td class=\"wrap\"><details><summary>" +
             std::to_string(r.items.size()) + (r.items.size() == 1 ? " item" : " items") +
             "</summary><ul class=\"pack-items\">";
        for (const auto& it : r.items)
            h += "<li><span class=\"muted\">" + esc(it.kind) + "</span> " + esc(it.name) +
                 " <code>" + esc(it.item_id) + "</code></li>";
        h += "</ul><a href=\"/api/v1/product-packs/" + esc(r.id) +
             "\">Open pack detail (JSON)</a></details></td><td>";
        // "Verified" here means exactly: valid for a key carried inside the pack itself. It is
        // not a trust decision by this server, so the pill is neutral and says so.
        h += r.verified ? pill("idle", "Signed", "Valid for the key in the pack")
                        : pill("idle", "Unsigned");
        h += "</td><td class=\"nw\">" + (r.installed_at > 0 ? format_iso_utc(r.installed_at)
                                                            : std::string("\xE2\x80\x94")) +
             "</td></tr>";
    }
    h += "</tbody></table></div>";
    if (p.more)
        h += "<div class=\"pb hint\">First " + std::to_string(p.shown_limit) +
             " shown. Page through the rest with <code>GET /api/v1/product-packs?limit=</code>."
             "</div>";
    h += "<div class=\"pb hint\">Unsigned packs are rejected on import unless the server runs "
         "with <code>--allow-unsigned-packs</code>. A pack's signature is checked against the "
         "key inside the pack. Deleting a pack attempts to remove the items it installed.</div>";
    return h;
}

} // namespace yuzu::server::plugin_page
