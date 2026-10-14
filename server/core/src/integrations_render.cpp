#include "integrations_render.hpp"

#include "web_utils.hpp" // html_escape

#include <string>
#include <utility>

namespace yuzu::server::integrations {

namespace {

std::string pill(std::string_view cls, std::string_view text) {
    return "<span class=\"pill " + std::string(cls) + "\">" + std::string(text) + "</span>";
}

std::string kv(std::string_view label, const std::string& value_html) {
    return "<div><span>" + std::string(label) + "</span><b>" + value_html + "</b></div>";
}

std::string radio(std::string_view name, std::string_view value, bool checked,
                  std::string_view label) {
    return "<label><input type=\"radio\" name=\"" + std::string(name) + "\" value=\"" +
           std::string(value) + "\"" + (checked ? " checked" : "") + ">" + std::string(label) +
           "</label>";
}

// Occurrences of `key` as a whole form field name, and the value of the last one.
struct Field {
    int count{0};
    std::string_view value;
};

Field find_field(std::string_view body, std::string_view key) {
    Field f;
    while (!body.empty()) {
        const auto amp = body.find('&');
        const auto pair = body.substr(0, amp);
        body = amp == std::string_view::npos ? std::string_view{} : body.substr(amp + 1);
        const auto eq = pair.find('=');
        const auto name = pair.substr(0, eq);
        if (name != key)
            continue;
        ++f.count;
        f.value = eq == std::string_view::npos ? std::string_view{} : pair.substr(eq + 1);
    }
    return f;
}

std::expected<bool, std::string> take_bool(std::string_view body, std::string_view key) {
    const auto f = find_field(body, key);
    if (f.count == 0)
        return std::unexpected(std::string(key) + " is required");
    if (f.count > 1)
        return std::unexpected(std::string(key) + " must be supplied exactly once");
    if (f.value == "true")
        return true;
    if (f.value == "false")
        return false;
    return std::unexpected(std::string(key) + " must be true or false");
}

} // namespace

// ── MCP ─────────────────────────────────────────────────────────────────

std::string render_mcp_panel(const McpView& v) {
    std::string html = "<div class=\"kvl\">";
    html += kv("Status", pill(v.enabled ? "ok" : "idle", v.enabled ? "Enabled" : "Disabled") +
                             " " +
                             pill(v.read_only ? "warn" : "info",
                                  v.read_only ? "Read-only" : "Full access"));
    html += kv("Endpoint", "<code>" + html_escape(v.endpoint_url) + "</code>");
    html += "</div>";

    // One form, one Save. Each radio group posts exactly one value for its name; the confirm
    // texts ride on the form as data attributes (the page script picks one by resulting state;
    // `hx-confirm` is the fallback wherever that script is not loaded).
    html += "<form id=\"mcp-form\" class=\"form\" hx-post=\"/api/settings/mcp\" "
            "hx-target=\"#mcp-section\" hx-swap=\"innerHTML\" hx-confirm=\"" +
            html_escape(std::string(kMcpConfirmGeneric)) + "\" data-confirm-full=\"" +
            html_escape(std::string(kMcpConfirmFull)) + "\" data-confirm-readonly=\"" +
            html_escape(std::string(kMcpConfirmReadOnly)) + "\" data-confirm-off=\"" +
            html_escape(std::string(kMcpConfirmOff)) + "\">";
    html += "<div class=\"fld\"><span class=\"lb\" id=\"mcp-lb-enabled\">MCP server</span>"
            "<div class=\"seg\" role=\"radiogroup\" aria-labelledby=\"mcp-lb-enabled\">" +
            radio("enabled", "true", v.enabled, "Enabled") +
            radio("enabled", "false", !v.enabled, "Disabled") + "</div></div>";
    html += "<div class=\"fld\"><span class=\"lb\" id=\"mcp-lb-mode\">Access mode</span>"
            "<div class=\"seg\" role=\"radiogroup\" aria-labelledby=\"mcp-lb-mode\">" +
            radio("read_only", "true", v.read_only, "Read-only") +
            radio("read_only", "false", !v.read_only, "Full access") +
            "</div><span class=\"hint\">Read-only allows read tools only. Full access also "
            "allows write and execute tools.</span></div>";
    html += "<div><button class=\"btn primary\" type=\"submit\">Save MCP settings</button></div>";
    html += "</form>";

    html += "<div class=\"pb\">";
    html += "<p class=\"note\">Changes apply until the server restarts, then the start-up flags "
            "apply again.";
    if (!v.enabled)
        html += " If this server was started with <code>--mcp-disable</code> "
                "(<code>YUZU_MCP_DISABLE</code>), turning MCP on has no effect until it "
                "restarts.";
    html += "</p>";
    html += "<p class=\"hint\">MCP authentication uses API tokens with an MCP tier (readonly, "
            "operator or supervised). Create them in the API Tokens panel on the "
            "<a href=\"/settings\">Settings</a> page.</p>";
    html += "<div class=\"note\"><b>MCP client connection</b><br>Endpoint: <code>" +
            html_escape(v.endpoint_url) +
            "</code><br><span class=\"hint\">Transport: HTTP + JSON-RPC 2.0 &nbsp;|&nbsp; "
            "Auth: <code>Authorization: Bearer &lt;mcp-token&gt;</code></span></div>";
    html += "</div>";
    return html;
}

std::expected<McpForm, std::string> parse_mcp_form(std::string_view body) {
    auto enabled = take_bool(body, "enabled");
    if (!enabled)
        return std::unexpected(std::move(enabled.error()));
    auto read_only = take_bool(body, "read_only");
    if (!read_only)
        return std::unexpected(std::move(read_only.error()));
    return McpForm{*enabled, *read_only};
}

// ── Gateway ─────────────────────────────────────────────────────────────

std::string render_gateway_panel(const GatewayView& v) {
    std::string html = "<div class=\"kvl\">";
    html += kv("Upstream service",
               pill(v.enabled ? "ok" : "idle", v.enabled ? "Enabled" : "Disabled"));
    if (v.enabled) {
        html += kv("Listen address", "<code>" + html_escape(v.listen_address) + "</code>");
        html += kv("Gateway mode", pill(v.gateway_mode ? "ok" : "idle",
                                         v.gateway_mode ? "Active" : "Inactive"));
        html += kv("Agents via gateway",
                   std::to_string(v.active_sessions) + (v.active_sessions == 1 ? " agent" : " agents"));
    }
    html += "</div>";

    if (!v.enabled)
        html += "<div class=\"pb\"><p class=\"note\">The gateway upstream service is not running. "
                "Start the server with <code>--gateway-upstream 0.0.0.0:50055</code> to enable "
                "it. The service requires an authorized gateway peer: pin the gateway's key "
                "with <code>--gateway-peer-pin</code> or <code>--gateway-peer-pin-file</code> "
                "(automatic on the built-in default certificates), or, on a plaintext "
                "development rig only, acknowledge that peer authorization is disabled with "
                "<code>--insecure-gateway-peer</code>. Without one of these the server refuses "
                "to start. Pins are read once at boot; changing them needs a restart.</p></div>";

    html += "<div class=\"pb\"><details><summary>Erlang gateway environment variables</summary>"
            "<div class=\"tw\"><table><thead><tr><th>Variable</th><th>Description</th>"
            "<th>Default</th></tr></thead><tbody>"
            "<tr><td><code>YUZU_GW_UPSTREAM_ADDR</code></td><td>C++ server hostname</td>"
            "<td><code>127.0.0.1</code></td></tr>"
            "<tr><td><code>YUZU_GW_UPSTREAM_PORT</code></td><td>C++ server port</td>"
            "<td><code>50055</code></td></tr>"
            "<tr><td><code>YUZU_GW_AGENT_PORT</code></td><td>Agent-facing listener port</td>"
            "<td><code>50051</code></td></tr>"
            "<tr><td><code>YUZU_GW_MGMT_PORT</code></td><td>Management listener port</td>"
            "<td><code>50052</code></td></tr>"
            "<tr><td><code>YUZU_GW_TLS_ENABLED</code></td><td>TLS master switch</td>"
            "<td><code>auto</code></td></tr>"
            "<tr><td><code>YUZU_GW_TLS_CERTFILE</code></td><td>Gateway certificate path</td>"
            "<td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_TLS_KEYFILE</code></td><td>Gateway private key path</td>"
            "<td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_TLS_CACERTFILE</code></td><td>CA certificate bundle</td>"
            "<td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_PROMETHEUS_PORT</code></td><td>Prometheus metrics port</td>"
            "<td><code>9568</code></td></tr>"
            "<tr><td><code>YUZU_GW_HEALTH_PORT</code></td><td>Health endpoint port</td>"
            "<td><code>8080</code></td></tr>"
            "</tbody></table></div></details></div>";
    return html;
}

} // namespace yuzu::server::integrations
