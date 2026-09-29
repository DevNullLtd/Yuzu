/// @file settings_routes.cpp
/// Settings page HTMX routes, fragment renderers, and YAML helpers.
/// Extracted from server.cpp — Phase 1 of the god-object decomposition.

#include "settings_routes.hpp"

#include "ota_signature_sidecar.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error

#include <atomic>
#include <cstdio>

#include "access_review_model.hpp" // Periodic Access Reviews (SOC 2 CC6.2) — pure read-model
#include "access_review_store.hpp" // Periodic Access Reviews — campaign persistence
#include "config_secret_keys.hpp" // is_exactly_redaction_placeholder in the OIDC handler
#include "dex_alert_router.hpp" // F1: parse_routed_types / routed_types_to_json
#include "dex_blast_radius.hpp" // F1: BlastRadiusConfig defaults for the threshold form
#include "deprovision_revoke.hpp" // ADR-2001 §§1,3: dashboard user DELETE revoke seam
#include "dex_routes.hpp"       // F1: dex_signal_groups / dex_signal_label
#include "directory_sync.hpp"   // access-review read-model optional email enrichment
#include "http_route_sink.hpp"
#include "json_extract.hpp" // #2557: shared extract_json_string (was an anonymous-namespace copy)
#include "mcp_policy.hpp"
#include "rbac_admin_predicate.hpp" // is_self_target — shared #397/#403 self-target comparison
#include "rbac_store.hpp"       // access-review read-model direct-grant reads
#include "tag_store.hpp" // F2a PR3: TagStore::validate_key for the cohort export key
#include "mfa_qr.hpp"
#include "plugin_signing_helpers.hpp"
#include "rest_a4_envelope.hpp"      // #4028 — detail::error_json_a4 for the settings read-twins
#include "rest_a4_envelope_http.hpp" // #4028 — detail::a4_error/ensure_correlation_id
#include "rest_audit.hpp"            // #4028 — detail::emit_behavioral_audit (fail-closed REST reads)
#include "settings_model.hpp"        // #4028 — shared REST/fragment read-twin builders
#include "web_utils.hpp"
#include <yuzu/server/server.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_store.hpp> // ScimStore::is_open (deprovision resolver, ADR-2001)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// httplib compat: v0.18+ moved file upload helpers to req.form (MultipartFormData).
#if __has_include(<httplib.h>)
namespace yuzu::settings_detail {
template <typename T, typename = void> struct has_form_member : std::false_type {};
template <typename T>
struct has_form_member<T, std::void_t<decltype(std::declval<T>().form)>> : std::true_type {};
} // namespace yuzu::settings_detail
template <typename Req> bool settings_req_has_file(const Req& req, const std::string& name) {
    if constexpr (yuzu::settings_detail::has_form_member<Req>::value)
        return req.form.has_file(name);
    else
        return req.has_file(name);
}
template <typename Req> auto settings_req_get_file(const Req& req, const std::string& name) {
    if constexpr (yuzu::settings_detail::has_form_member<Req>::value)
        return req.form.get_file(name);
    else
        return req.get_file_value(name);
}
#define SETTINGS_REQ_HAS_FILE(req, name) settings_req_has_file(req, name)
#define SETTINGS_REQ_GET_FILE(req, name) settings_req_get_file(req, name)
#endif

// Settings page HTML template (defined in settings_ui.cpp).
extern const char* const kSettingsHtml;

// GatewayUpstreamServiceImpl and AgentRegistry are inner classes of server.cpp.
// We use callbacks (AgentsJsonFn, GatewaySessionCountFn) to avoid depending on
// their incomplete types.

namespace yuzu::server {

// ── Anonymous namespace: YAML helpers and JSON extraction ────────────────────

namespace {

// governance round (arch-S1) — percent-encode a URL query-PARAMETER VALUE
// (RFC 3986 unreserved set — alnum, `-`, `_`, `.`, `~` pass through
// unchanged; everything else, including `#`, `&`, `%`, `+`, and space, is
// percent-escaped). Distinct from `html_escape`: `html_escape` neutralises
// HTML metacharacters for BODY text and does NOT touch `#`, so a value
// containing `#` (e.g. the durable SSO principal `oidc:<iss>#<sub>`,
// #1852) embedded via `html_escape` alone into an
// `hx-delete="...?username=" + html_escape(v)` attribute is silently
// truncated by the browser, which treats the un-encoded `#` as a URL
// fragment separator — the server then receives a truncated query value
// with no error signal. Use `url_encode` for the query-parameter VALUE and
// reserve `html_escape` for the surrounding HTML-attribute quoting / any
// body-text rendering of the same value. Mirrors the identical helper
// already local to device_ui.cpp / dex_routes.cpp / inventory_ui.cpp et al.
// (deliberately per-file, not centralised in web_utils.hpp — several of
// those files declare the same name in their own anonymous namespace, so a
// namespace-scope version there is ambiguous against unqualified lookup).
std::string url_encode(const std::string& s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string highlight_yaml_value(const std::string& val) {
    if (val.empty())
        return {};
    auto trimmed = val;
    auto sp = trimmed.find_first_not_of(' ');
    if (sp == std::string::npos)
        return html_escape(val);
    trimmed = trimmed.substr(sp);

    // Booleans
    if (trimmed == "true" || trimmed == "false" || trimmed == "True" || trimmed == "False")
        return "<span class=\"yb\">" + html_escape(val) + "</span>";
    // Numbers
    bool is_number = !trimmed.empty();
    for (char c : trimmed) {
        if (c != '-' && c != '.' && (c < '0' || c > '9')) {
            is_number = false;
            break;
        }
    }
    if (is_number && !trimmed.empty())
        return "<span class=\"yn\">" + html_escape(val) + "</span>";
    // String value (quoted or bare)
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
           "</span>:" + highlight_yaml_value(rest);
}

[[maybe_unused]] std::string highlight_yaml(std::string_view source) {
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

        result += "<div class=\"yl\"><span class=\"ln\">" + std::to_string(line_num++) + "</span>";

        auto trimmed_start = line.find_first_not_of(' ');
        if (trimmed_start == std::string::npos) {
            result += "&nbsp;";
        } else if (line[trimmed_start] == '#') {
            result += "<span class=\"yc\">" + html_escape(line) + "</span>";
        } else if (line == "---" || line == "...") {
            result += "<span class=\"yd\">" + html_escape(line) + "</span>";
        } else if (line[trimmed_start] == '-' && trimmed_start + 1 < line.size() &&
                   line[trimmed_start + 1] == ' ') {
            auto indent = line.substr(0, trimmed_start);
            auto after_dash = line.substr(trimmed_start + 2);
            result += html_escape(indent) + "<span class=\"yd\">-</span> ";
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

[[maybe_unused]] std::vector<std::string> validate_yaml_source(const std::string& yaml_source) {
    std::vector<std::string> errors;
    if (yaml_source.empty())
        errors.push_back("YAML source is empty");
    if (yaml_source.find("apiVersion:") == std::string::npos)
        errors.push_back("Missing apiVersion field");
    if (yaml_source.find("kind:") == std::string::npos)
        errors.push_back("Missing kind field");
    if (yaml_source.find("plugin:") == std::string::npos)
        errors.push_back("Missing spec.plugin field");
    if (yaml_source.find("action:") == std::string::npos)
        errors.push_back("Missing spec.action field");
    return errors;
}

// extract_json_string moved to json_extract.hpp (#2557) — SettingsRoutes
// lives in namespace yuzu::server, so this unqualified name still resolves.

// #4028 — success-envelope wrapper matching rest_api_v1.cpp's ok_json() wire
// shape ({"data":...,"meta":{"api_version":"v1"}}) exactly. ok_json() itself
// is TU-local to rest_api_v1.cpp (declared in its own anonymous namespace,
// not a shared header), so this file — which already builds every response
// via nlohmann::json rather than rest_api_v1.cpp's local JObj/JArr string
// builders (see the existing /api/v1/agent/plugin-policy handler below) —
// gets its own copy of the same shape rather than reaching across TUs.
nlohmann::json settings_ok_envelope(nlohmann::json data) {
    nlohmann::json out;
    out["data"] = std::move(data);
    out["meta"] = {{"api_version", "v1"}};
    return out;
}

} // anonymous namespace

// ── Fragment renderers ──────────────────────────────────────────────────────

std::string SettingsRoutes::render_server_config_fragment() {
    // #4028 — shared builder (settings_model.hpp); the REST twin
    // GET /api/v1/settings/server-config formats the SAME JSON as its
    // response body instead of re-deriving these fields from cfg_.
    const auto v = settings_model::build_server_config_settings(*cfg_);

    std::string html;

    html += "<table class=\"user-table\" style=\"font-size:0.8rem\">"
            "<thead><tr><th>Setting</th><th>Value</th></tr></thead>"
            "<tbody>";

    html += "<tr><td>Agent gRPC Address</td><td><code>" +
            html_escape(v.at("agent_grpc_address").get<std::string>()) + "</code></td></tr>";
    html += "<tr><td>Management gRPC Address</td><td><code>" +
            html_escape(v.at("management_grpc_address").get<std::string>()) + "</code></td></tr>";
    html += "<tr><td>Web UI Address</td><td><code>" +
            html_escape(v.at("web_address").get<std::string>()) + "</code></td></tr>";
    html += "<tr><td>Web UI Port</td><td><code>" + std::to_string(v.at("web_port").get<int>()) +
            "</code></td></tr>";

    html += "<tr><td>Session Timeout</td><td><code>" +
            std::to_string(v.at("session_timeout_seconds").get<std::int64_t>()) +
            "s</code></td></tr>";
    html += "<tr><td>Max Agents</td><td><code>" +
            std::to_string(v.at("max_agents").get<std::int64_t>()) + "</code></td></tr>";

    std::string auth_path = v.at("auth_config_path").get<std::string>();
    std::string auth_path_str =
        auth_path.empty() ? std::string("(default)") : html_escape(auth_path);
    html += "<tr><td>Auth Config Path</td><td><span class=\"file-name\">" + auth_path_str +
            "</span></td></tr>";

    html += "<tr><td>API Rate Limit</td><td><code>" +
            std::to_string(v.at("rate_limit_per_ip").get<int>()) + "</code> req/s per IP</td></tr>";
    html += "<tr><td>Login Rate Limit</td><td><code>" +
            std::to_string(v.at("login_rate_limit_per_ip").get<int>()) +
            "</code> req/s per IP</td></tr>";

    // Agent OTA pull bounds (#913 / #911). Read-only, like every row here.
    html += "<tr><td>OTA Concurrency (per peer)</td><td><code>" +
            std::to_string(v.at("ota_max_concurrent_per_peer").get<int>()) +
            "</code> parallel downloads</td></tr>";
    // Format the two doubles to one decimal place: std::to_string renders a
    // double as "1.000000", which is the only row on this fragment that does not
    // read like a configured value.
    {
        char rate_buf[64];
        std::snprintf(rate_buf, sizeof(rate_buf), "%.1f",
                      v.at("ota_rate_refill_per_min").get<double>());
        char burst_buf[64];
        std::snprintf(burst_buf, sizeof(burst_buf), "%.1f", v.at("ota_rate_capacity").get<double>());
        html += std::string("<tr><td>OTA Rate (per peer)</td><td><code>") + rate_buf +
                "</code>/min, burst <code>" + burst_buf + "</code></td></tr>";
    }
    html += "<tr><td>OTA Transfers (server-wide)</td><td><code>" +
            std::to_string(v.at("ota_max_concurrent_total").get<int>()) +
            "</code> concurrent</td></tr>";
    html += "<tr><td>OTA Peer Map Cap</td><td><code>" +
            std::to_string(v.at("ota_max_peers_tracked").get<int>()) + "</code> keys</td></tr>";
    html += "<tr><td>OTA Transfer Deadline</td><td><code>" +
            std::to_string(v.at("ota_transfer_deadline_secs").get<int>()) +
            "</code> s (chunk <code>" +
            std::to_string(v.at("ota_chunk_write_deadline_secs").get<int>()) + "</code> s)</td></tr>";
    html += "<tr><td>gRPC Stream Cap</td><td><code>" +
            std::to_string(v.at("grpc_max_concurrent_streams").get<int>()) +
            "</code> streams/connection, quota <code>" +
            std::to_string(v.at("grpc_max_resource_memory_mb").get<int>()) + "</code> MiB</td></tr>";

    html += "</tbody></table>";
    return html;
}

std::string SettingsRoutes::render_tls_fragment() {
    // #4028 — shared builder; GET /api/v1/settings/tls formats the SAME
    // JSON as its response body instead of re-deriving these fields.
    const auto v = settings_model::build_tls_settings(*cfg_);
    const bool tls_enabled = v.at("enabled").get<bool>();

    std::string checked = tls_enabled ? " checked" : "";
    std::string status_color = tls_enabled ? "#3fb950" : "#f85149";
    std::string status_text = tls_enabled ? "Enabled" : "Disabled";
    std::string fields_opacity = tls_enabled ? "1" : "0.4";

    auto path_or_no_file = [](const nlohmann::json& j) -> std::string {
        auto s = j.get<std::string>();
        return s.empty() ? "No file" : html_escape(s);
    };
    std::string cert_name = path_or_no_file(v.at("server_cert_path"));
    std::string key_name = path_or_no_file(v.at("server_key_path"));
    std::string ca_name = path_or_no_file(v.at("ca_cert_path"));

    std::string html =
        "<form id=\"tls-form\">"
        "<div class=\"form-row\">"
        "  <label>gRPC mTLS</label>"
        "  <label class=\"toggle\">"
        "    <input type=\"checkbox\" name=\"tls_enabled\" value=\"true\"" +
        checked +
        "           hx-post=\"/api/settings/tls\" hx-target=\"#tls-feedback\""
        "           hx-swap=\"innerHTML\">"
        "    <span class=\"slider\"></span>"
        "  </label>"
        "  <span style=\"font-size:0.75rem;color:" +
        status_color + ";margin-left:0.5rem\">" + status_text +
        "</span>"
        "</div>"
        "<div style=\"margin-top:1rem;opacity:" +
        fields_opacity +
        "\">"
        "  <div class=\"form-row\">"
        "    <label>Server Certificate</label>"
        "    <div class=\"file-upload\">"
        "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
        "hx-swap=\"innerHTML\""
        "            hx-encoding=\"multipart/form-data\" "
        "style=\"display:flex;align-items:center;gap:0.75rem\">"
        "        <input type=\"hidden\" name=\"type\" value=\"cert\">"
        "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
        "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
        "id=\"cert-file\">"
        "        <button type=\"button\" class=\"btn btn-secondary\""
        "                onclick=\"document.getElementById('cert-file').click()\">Upload "
        "PEM</button>"
        "        <span class=\"file-name\">" +
        cert_name +
        "</span>"
        "      </form>"
        "      <details style=\"margin-top:0.5rem\">"
        "        <summary class=\"btn btn-secondary\" "
        "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
        "        <form hx-post=\"/api/settings/cert-paste\" "
        "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
        "              style=\"margin-top:0.5rem\">"
        "          <input type=\"hidden\" name=\"type\" value=\"cert\">"
        "          <textarea name=\"content\" "
        "            style=\"width:100%;min-height:150px;font-family:monospace;"
        "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
        "                   border:1px solid var(--border);border-radius:4px;"
        "                   padding:0.5rem;resize:vertical\" "
        "            placeholder=\"-----BEGIN CERTIFICATE-----&#10;...paste PEM content...&#10;"
        "-----END CERTIFICATE-----\"></textarea>"
        "          <button type=\"submit\" class=\"btn btn-primary\" "
        "            style=\"margin-top:0.5rem\">Save</button>"
        "        </form>"
        "      </details>"
        "    </div>"
        "  </div>"
        "  <div class=\"form-row\">"
        "    <label>Server Private Key</label>"
        "    <div class=\"file-upload\">"
        "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
        "hx-swap=\"innerHTML\""
        "            hx-encoding=\"multipart/form-data\" "
        "style=\"display:flex;align-items:center;gap:0.75rem\">"
        "        <input type=\"hidden\" name=\"type\" value=\"key\">"
        "        <input type=\"file\" name=\"file\" accept=\".pem,.key\""
        "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
        "id=\"key-file\">"
        "        <button type=\"button\" class=\"btn btn-secondary\""
        "                onclick=\"document.getElementById('key-file').click()\">Upload "
        "PEM</button>"
        "        <span class=\"file-name\">" +
        key_name +
        "</span>"
        "      </form>"
        "      <details style=\"margin-top:0.5rem\">"
        "        <summary class=\"btn btn-secondary\" "
        "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
        "        <form hx-post=\"/api/settings/cert-paste\" "
        "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
        "              style=\"margin-top:0.5rem\">"
        "          <input type=\"hidden\" name=\"type\" value=\"key\">"
        "          <textarea name=\"content\" "
        "            style=\"width:100%;min-height:150px;font-family:monospace;"
        "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
        "                   border:1px solid var(--border);border-radius:4px;"
        "                   padding:0.5rem;resize:vertical\" "
        "            placeholder=\"-----BEGIN PRIVATE KEY-----&#10;...paste PEM content...&#10;"
        "-----END PRIVATE KEY-----\"></textarea>"
        "          <button type=\"submit\" class=\"btn btn-primary\" "
        "            style=\"margin-top:0.5rem\">Save</button>"
        "        </form>"
        "      </details>"
        "    </div>"
        "  </div>"
        "  <div class=\"form-row\">"
        "    <label>CA Certificate</label>"
        "    <div class=\"file-upload\">"
        "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
        "hx-swap=\"innerHTML\""
        "            hx-encoding=\"multipart/form-data\" "
        "style=\"display:flex;align-items:center;gap:0.75rem\">"
        "        <input type=\"hidden\" name=\"type\" value=\"ca\">"
        "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
        "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
        "id=\"ca-file\">"
        "        <button type=\"button\" class=\"btn btn-secondary\""
        "                onclick=\"document.getElementById('ca-file').click()\">Upload "
        "PEM</button>"
        "        <span class=\"file-name\">" +
        ca_name +
        "</span>"
        "      </form>"
        "      <details style=\"margin-top:0.5rem\">"
        "        <summary class=\"btn btn-secondary\" "
        "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
        "        <form hx-post=\"/api/settings/cert-paste\" "
        "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
        "              style=\"margin-top:0.5rem\">"
        "          <input type=\"hidden\" name=\"type\" value=\"ca\">"
        "          <textarea name=\"content\" "
        "            style=\"width:100%;min-height:150px;font-family:monospace;"
        "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
        "                   border:1px solid var(--border);border-radius:4px;"
        "                   padding:0.5rem;resize:vertical\" "
        "            placeholder=\"-----BEGIN CERTIFICATE-----&#10;...paste PEM content...&#10;"
        "-----END CERTIFICATE-----\"></textarea>"
        "          <button type=\"submit\" class=\"btn btn-primary\" "
        "            style=\"margin-top:0.5rem\">Save</button>"
        "        </form>"
        "      </details>"
        "    </div>"
        "  </div>"
        "</div>"
        "</form>";

    // Insecure-skip-client-verify (one-way TLS) — color red when enabled to flag the
    // weakened posture in the operator dashboard, not just the warm-orange "warning" hue.
    const bool insecure_skip = v.at("insecure_skip_client_verify").get<bool>();
    std::string owt_color = insecure_skip ? "#f85149" : "#8b949e";
    std::string owt_text = insecure_skip
                               ? "Client cert verification DISABLED (--insecure-skip-client-verify)"
                               : "Disabled (mTLS enforced)";
    html += "<div class=\"form-row\" style=\"margin-top:0.75rem\">"
            "  <label>Insecure Skip Client Verify</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            owt_color + "\">" + owt_text +
            "</span>"
            "</div>";

    // Management TLS overrides
    auto path_or_using_agent = [](const nlohmann::json& j) -> std::string {
        auto s = j.get<std::string>();
        return s.empty() ? "Using agent TLS" : html_escape(s);
    };
    std::string mgmt_cert = path_or_using_agent(v.at("mgmt_server_cert_path"));
    std::string mgmt_key = path_or_using_agent(v.at("mgmt_server_key_path"));
    std::string mgmt_ca = path_or_using_agent(v.at("mgmt_ca_cert_path"));

    html +=
        "<div style=\"margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
        "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
        "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
        "Management Listener TLS Override</div>"
        "<div class=\"form-row\">"
        "  <label>Mgmt Certificate</label>"
        "  <span class=\"file-name\">" +
        mgmt_cert +
        "</span>"
        "</div>"
        "<div class=\"form-row\">"
        "  <label>Mgmt Private Key</label>"
        "  <span class=\"file-name\">" +
        mgmt_key +
        "</span>"
        "</div>"
        "<div class=\"form-row\">"
        "  <label>Mgmt CA Cert</label>"
        "  <span class=\"file-name\">" +
        mgmt_ca +
        "</span>"
        "</div>"
        "</div>";

    html += "<div class=\"feedback\" id=\"tls-feedback\"></div>";
    return html;
}

std::string SettingsRoutes::render_users_fragment(const std::string& current_username) {
    auto users = auth_mgr_->list_users();
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>Username</th><th>Role</th><th></th></tr></thead>"
                       "  <tbody>";

    if (users.empty()) {
        html += "<tr><td colspan=\"3\" style=\"color:#484f58\">No users</td></tr>";
    } else {
        for (const auto& u : users) {
            auto role_str = auth::role_to_string(u.role);
            auto cls = (u.role == auth::Role::admin) ? "role-admin" : "role-user";
            const bool is_self = !current_username.empty() && u.username == current_username;
            // #1852 — a durable SSO row (`identity_source != "local"`, e.g.
            // an auto-provisioned `oidc:<iss>#<sub>` principal) now appears
            // in this list. Its `username` fails the STRICT
            // `is_valid_username` gate that guards local-account mutation
            // routes (delete, password-reset, role-change — see
            // auth_db.hpp's `is_valid_principal` doc), so those buttons are
            // suppressed for it below rather than rendering a button that
            // always 400s. Session-revoke and elevation-eligibility are
            // principal-keyed (`is_valid_principal`) and stay available.
            const bool is_sso = u.identity_source != "local";
            html += "<tr><td>" + html_escape(u.username);
            if (is_sso) {
                html += " <span class=\"role-badge\" style=\"background:#1f6feb22;"
                        "color:#58a6ff;font-size:0.6rem;margin-left:0.3rem\" "
                        "title=\"Auto-provisioned via SSO (identity_source=" +
                        html_escape(u.identity_source) + ")\">SSO</span>";
            }
            html += "</td>"
                    "<td><span class=\"role-badge " +
                    std::string(cls) + "\">" + html_escape(role_str) +
                    "</span></td>"
                    "<td>";
            if (is_self) {
                // Self-deletion lockout guard (#397/#403): the Remove button
                // is suppressed for the currently authenticated operator's
                // own row so that deleting the sole admin — and thereby
                // locking every user out of the running server — is not a
                // two-click operation in the dashboard. The DELETE handler
                // also rejects self-targeted requests; both halves are load-
                // bearing because the UI guard alone does not stop a hand-
                // crafted HTTP DELETE.
                //
                // Self-revoke is permitted (recoverable — operator just
                // re-authenticates) and routes through `/api/v1/sessions/me`
                // so the audit row records `session.revoke_all.self`.
                html += "<span class=\"current-user-badge\" "
                        "style=\"color:#484f58;font-size:0.7rem;"
                        "font-style:italic;margin-right:0.5rem\" "
                        "title=\"You cannot remove your own account\">"
                        "Current user</span>"
                        "<button class=\"btn btn-secondary\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/v1/sessions/me\" "
                        "hx-confirm=\"Sign out of every device AND revoke "
                        "every API token you own? You will be redirected to "
                        "the login page; any of your CI/CD or automation "
                        "tokens will need to be re-issued.\" "
                        "hx-on::after-request=\"window.location='/login'\""
                        ">Sign out everywhere</button>";
            } else {
                // governance round (arch-S1) — the query-parameter VALUE
                // must be URL-encoded, not HTML-escaped: `html_escape`
                // leaves `#` untouched, and a durable SSO principal
                // (`oidc:<iss>#<sub>`, #1852) embedded raw here has its
                // `#` treated by the browser as a URL-fragment separator,
                // silently truncating the request the server receives —
                // a no-op "Revoke sessions" click with no visible error.
                // `html_escape` is still applied to the confirm-dialog TEXT
                // below (a body-text rendering, not a URL).
                html += "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem;"
                        "margin-right:0.3rem\" "
                        "hx-delete=\"/api/v1/sessions?username=" +
                        url_encode(u.username) +
                        "\" "
                        "hx-target=\"#user-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Force &quot;" +
                        html_escape(u.username) +
                        "&quot; to log in again? Active dashboard sessions "
                        "will end immediately. Their API tokens are NOT revoked.\""
                        ">Revoke sessions</button>";
                // #1852 — the Remove button is suppressed for an SSO row:
                // DELETE /api/settings/users/:username stays gated by the
                // STRICT `is_valid_username` (local-account charset only —
                // see the file header comment on that route), so it would
                // always 400 against an `oidc:<iss>#<sub>` principal. There
                // is no local-delete equivalent for a durable SSO identity
                // yet — its lifecycle is IdP-driven (see `last_seen_at` /
                // docs/auth-architecture.md).
                if (!is_sso) {
                    html += "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-delete=\"/api/settings/users/" +
                            html_escape(u.username) +
                            "\" "
                            "hx-target=\"#user-section\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Remove user &quot;" +
                            html_escape(u.username) +
                            "&quot;?\""
                            ">Remove</button>";
                }
            }
            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/users\" "
            "      hx-target=\"#user-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Username</label>"
            "    <input type=\"text\" name=\"username\" placeholder=\"username\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Password <span style=\"color:#8b949e;font-weight:normal;"
            "font-size:0.7rem\">(min 12 chars)</span></label>"
            "    <input type=\"password\" name=\"password\" placeholder=\"password\" "
            "           minlength=\"12\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Role</label>"
            "    <select name=\"role\">"
            "      <option value=\"user\">User</option>"
            "      <option value=\"admin\">Admin</option>"
            "    </select>"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Add User</button>"
            "</form>"
            "<div class=\"feedback\" id=\"user-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_tokens_fragment(const std::string& new_raw_token) {
    auto tokens = auth_mgr_->list_enrollment_tokens();
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>ID</th><th>Label</th><th>Uses</th>"
                       "  <th>Expires</th><th>Status</th><th></th></tr></thead>"
                       "  <tbody>";

    if (tokens.empty()) {
        html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No tokens created</td></tr>";
    } else {
        for (const auto& t : tokens) {
            auto uses = t.max_uses == 0
                            ? std::to_string(t.use_count) + " / \xe2\x88\x9e"
                            : std::to_string(t.use_count) + " / " + std::to_string(t.max_uses);

            std::string exp;
            if (t.expires_at == (std::chrono::system_clock::time_point::max)()) {
                exp = "Never";
            } else {
                auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                 t.expires_at.time_since_epoch())
                                 .count();
                exp = std::to_string(epoch);
            }

            std::string status_cls, status_txt;
            if (t.revoked) {
                status_cls = "role-user";
                status_txt = "Revoked";
            } else if (t.max_uses > 0 && t.use_count >= t.max_uses) {
                status_cls = "role-user";
                status_txt = "Exhausted";
            } else {
                status_cls = "role-admin";
                status_txt = "Active";
            }

            html += "<tr><td><code>" + html_escape(t.token_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(t.label) +
                    "</td>"
                    "<td>" +
                    uses +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    exp +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\">" + status_txt +
                    "</span></td>"
                    "<td>";
            if (!t.revoked) {
                html += "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/enrollment-tokens/" +
                        html_escape(t.token_id) +
                        "\" "
                        "hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Revoke token &quot;" +
                        html_escape(t.token_id) +
                        "&quot;? Agents using this token will no longer be able to enroll.\""
                        ">Revoke</button>";
            }
            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/enrollment-tokens\" "
            "      hx-target=\"#token-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Label</label>"
            "    <input type=\"text\" name=\"label\" placeholder=\"e.g. NYC rollout\" "
            "style=\"width:160px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Max Uses</label>"
            "    <input type=\"text\" name=\"max_uses\" placeholder=\"0 = unlimited\" "
            "style=\"width:80px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>TTL (hours)</label>"
            "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" "
            "style=\"width:80px\">"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Generate Token</button>"
            "</form>"
            "<div class=\"feedback\" id=\"token-feedback\"></div>";

    if (!new_raw_token.empty()) {
        html += "<div class=\"token-reveal\">"
                "  <div class=\"token-reveal-header\">"
                "    COPY THIS TOKEN NOW — it will not be shown again"
                "  </div>"
                "  <code>" +
                html_escape(new_raw_token) +
                "</code><br>"
                "  <button class=\"btn btn-secondary\" "
                "style=\"margin-top:0.5rem;font-size:0.7rem\" "
                "          data-copy-token>Copy to Clipboard</button>"
                "</div>";
    }

    return html;
}

std::string SettingsRoutes::render_api_tokens_fragment(const std::string& new_raw_token,
                                                       const std::string& filter_principal) {
    if (!api_token_store_ || !api_token_store_->is_open()) {
        return "<span style=\"color:#484f58\">API token store unavailable.</span>";
    }

    auto fmt_epoch = [](int64_t epoch) -> std::string {
        if (epoch == 0)
            return "Never";
        auto tt = static_cast<std::time_t>(epoch);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &tt);
#else
        gmtime_r(&tt, &tm_buf);
#endif
        char buf[32]{};
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_buf);
        return std::string(buf) + " UTC";
    };

    // Scope by caller principal for non-admin sessions. list_tokens already
    // supports a principal_id filter — the same one used by
    // `GET /api/v1/tokens` at rest_api_v1.cpp:826 — so admins get the full
    // fleet view while regular users see only their own tokens. Closes the
    // cross-user token enumeration path that governance Gate 4 consistency
    // auditor flagged as BLOCKING (finding C1).
    auto tokens_res = api_token_store_->list_tokens(filter_principal);
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Owner</th>"
                       "  <th>Created</th><th>Expires</th><th>Last Used</th>"
                       "  <th>Status</th><th></th></tr></thead>"
                       "  <tbody>";

    if (!tokens_res.has_value()) {
        // Authoritative store (ADR-0012 §1): surface a read failure rather than
        // render an empty "No API tokens" table that could hide a live credential.
        html += "<tr><td colspan=\"9\" style=\"color:#f85149\">"
                "Token store unavailable — please retry.</td></tr></tbody></table>";
        return html;
    }
    const auto& tokens = *tokens_res;
    if (tokens.empty()) {
        html += "<tr><td colspan=\"9\" style=\"color:#484f58\">No API tokens created</td></tr>";
    } else {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        for (const auto& t : tokens) {
            std::string exp = t.expires_at == 0 ? "Never" : fmt_epoch(t.expires_at);

            bool expired = t.expires_at > 0 && t.expires_at < now;

            std::string status_cls, status_txt;
            if (t.revoked) {
                status_cls = "role-user";
                status_txt = "Revoked";
            } else if (expired) {
                status_cls = "role-user";
                status_txt = "Expired";
            } else {
                status_cls = "role-admin";
                status_txt = "Active";
            }

            std::string type_text = t.mcp_tier.empty() ? "API" : "MCP";
            std::string type_detail =
                t.mcp_tier.empty() ? "" : " (" + html_escape(t.mcp_tier) + ")";
            std::string type_color = t.mcp_tier.empty() ? "#484f58" : "#8957e5";

            html += "<tr><td><code>" + html_escape(t.token_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(t.name) +
                    "</td>"
                    "<td><span class=\"role-badge\" style=\"background:" +
                    type_color + ";color:#fff\">" + type_text + "</span>" + type_detail +
                    "</td>"
                    "<td>" +
                    html_escape(t.principal_id) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    fmt_epoch(t.created_at) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    exp +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    fmt_epoch(t.last_used_at) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\">" + status_txt +
                    "</span></td>"
                    "<td>";
            if (!t.revoked) {
                html += "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/api-tokens/" +
                        html_escape(t.token_id) +
                        "\" "
                        "hx-target=\"#api-token-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Revoke API token &quot;" +
                        html_escape(t.token_id) +
                        "&quot;? Applications using this token will lose access.\""
                        ">Revoke</button>";
            }
            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/api-tokens\" "
            "      hx-target=\"#api-token-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Name</label>"
            "    <input type=\"text\" name=\"name\" placeholder=\"e.g. CI/CD pipeline\" "
            "style=\"width:160px\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>TTL (hours)</label>"
            "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" "
            "style=\"width:80px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>MCP Tier</label>"
            "    <select name=\"mcp_tier\" style=\"width:120px\">"
            "      <option value=\"\">(none — API)</option>"
            "      <option value=\"readonly\">readonly</option>"
            "      <option value=\"operator\">operator</option>"
            "      <option value=\"supervised\">supervised</option>"
            "    </select>"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Create Token</button>"
            "</form>"
            "<div class=\"feedback\" id=\"api-token-feedback\"></div>";

    if (!new_raw_token.empty()) {
        html += "<div class=\"token-reveal\">"
                "  <div class=\"token-reveal-header\">"
                "    COPY THIS API TOKEN NOW — it will not be shown again"
                "  </div>"
                "  <code>" +
                html_escape(new_raw_token) +
                "</code><br>"
                "  <button class=\"btn btn-secondary\" "
                "style=\"margin-top:0.5rem;font-size:0.7rem\" "
                "          data-copy-token>Copy to Clipboard</button>"
                "</div>";
    }

    return html;
}

std::string SettingsRoutes::render_engine_principals_fragment() {
    if (!engine_principal_store_ || !engine_principal_store_->is_open()) {
        return "<span style=\"color:#484f58\">Engine Principals store unavailable "
               "(not configured — requires PostgreSQL, design doc §3.1).</span>";
    }

    auto fmt_epoch = [](int64_t epoch) -> std::string {
        if (epoch == 0)
            return "—";
        auto tt = static_cast<std::time_t>(epoch);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &tt);
#else
        gmtime_r(&tt, &tm_buf);
#endif
        char buf[32]{};
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_buf);
        return std::string(buf) + " UTC";
    };

    // Admin/auditor list surface — every engine principal, any lifecycle
    // state, so revoked rows stay visible (never quietly dropped from the
    // console — design doc §3.1 / §12 decision 1).
    auto principals = engine_principal_store_->list_all(/*include_revoked=*/true);

    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>Principal ID</th><th>Display Name</th><th>Owner</th>"
                       "  <th>Classification</th><th>Lifecycle</th><th>Active Creds</th>"
                       "  <th>Revocation</th><th></th></tr></thead>"
                       "  <tbody>";

    if (principals.empty()) {
        html += "<tr><td colspan=\"8\" style=\"color:#484f58\">No engine principals</td></tr>";
    } else {
        for (const auto& p : principals) {
            const bool active = p.lifecycle_state == "active";
            const std::string status_cls = active ? "role-admin" : "role-user";
            const std::string status_txt = active ? "Active" : "Revoked";

            std::size_t active_creds = 0;
            if (api_token_store_ && api_token_store_->is_open()) {
                active_creds = api_token_store_->list_active_for_principal(p.principal_id).size();
            }

            // Revoked rows MUST surface the `superseded_by` linkage AND the
            // recorded revoke detail explicitly (design doc §3.1 / §12
            // decision 1) — never a seamless merged history that hides that
            // a revocation occurred. `EnginePrincipalRow` carries no reason
            // column of its own (`revoke()` takes no reason parameter —
            // store schema is frozen for this PR); best-effort recover the
            // audit trail's own detail string, which the REAL REST DELETE
            // route (rest_api_v1.cpp) records as
            // "credentials_revoked=N[; superseded_by=X]" — NOT an
            // operator-supplied free-text reason (the route has no such
            // field; an earlier draft of this fragment assumed one).
            // Two DIFFERENT outcomes, distinguished: "(not recorded)" when the
            // store answered and had no such row, "(unavailable)" when it could
            // not answer at all. Collapsing them would state an absence the read
            // never established — the revocation facts beside it come from the
            // principal store and are unaffected either way.
            std::string revocation_cell = "—";
            if (!active) {
                std::string linkage =
                    p.superseded_by.empty()
                        ? "<em style=\"color:#484f58\">no successor recorded</em>"
                        : ("superseded by <code>" + html_escape(p.superseded_by) + "</code>");
                std::string audit_detail = "(not recorded)";
                if (audit_store_) {
                    AuditQuery q;
                    q.target_type = "EnginePrincipal";
                    q.target_id = p.principal_id;
                    q.action_prefixes = {"engine_principal.revoke"};
                    q.limit = 1;
                    // Best-effort HTML cell (not an evidence endpoint): on a
                    // degrade (nullopt, ADR-0040) say so rather than 503-ing the
                    // whole settings page.
                    auto events = audit_store_->query(q);
                    if (!events)
                        audit_detail = "(unavailable)";
                    else if (!events->empty() && !events->front().detail.empty())
                        audit_detail = events->front().detail;
                }
                revocation_cell = linkage +
                                  "<br><span style=\"font-size:0.7rem;color:"
                                  "var(--mds-color-theme-text-tertiary)\">Detail: " +
                                  html_escape(audit_detail) + "</span>";
                if (p.revoked_at > 0) {
                    revocation_cell += "<br><span style=\"font-size:0.7rem;color:"
                                        "var(--mds-color-theme-text-tertiary)\">" +
                                        fmt_epoch(p.revoked_at) + "</span>";
                }
            }

            html += "<tr><td><code>" + html_escape(p.principal_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(p.display_name) +
                    "</td>"
                    "<td>" +
                    html_escape(p.owner_username) +
                    "</td>"
                    "<td>" +
                    html_escape(p.classification) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\">" + status_txt +
                    "</span></td>"
                    "<td>" +
                    std::to_string(active_creds) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    revocation_cell +
                    "</td>"
                    "<td>";

            if (active) {
                // Every mutation form below is a PLAIN <form> — deliberately
                // NO hx-post/hx-target/hx-swap. The real REST surface
                // (rest_api_v1.cpp's /api/v1/engine-principals/*) parses a
                // JSON body (`nlohmann::json::parse(req.body, ...)`), but
                // htmx's native form submission serializes
                // `application/x-www-form-urlencoded` — every one of those
                // routes would 400 "invalid JSON" if htmx submitted them
                // directly (there is no bundled json-enc extension). The
                // page's body-level delegated `submit` listener
                // (settings_ui.cpp) intercepts these via their
                // `data-engine-action`/`data-principal-id` markers, builds
                // the JSON body itself, and does a plain `fetch()` — the
                // SAME pattern instruction_ui.cpp's execute-instruction
                // button already uses for a JSON REST endpoint. That
                // listener also fires `refreshEnginePrincipals` on success
                // (the fragment's own `hx-trigger` above listens for it) and
                // extracts a freshly-minted/rotated secret from the response
                // body's real key (`data.token`, under the `ok_json`
                // envelope's `data` wrapper) into #engine-principal-reveal
                // below — never the guessed `token|raw_token|secret|
                // raw_secret` union an earlier draft used before the actual
                // route was read.
                //
                // `data-confirm` is a plain string the same listener passes
                // to `window.confirm()` before firing the request — NOT
                // htmx's own `hx-confirm` (that only fires for htmx-owned
                // hx-post/hx-get triggers, which these forms deliberately
                // are not).
                if (active_creds == 0) {
                    // No live credential yet — this principal needs an
                    // initial mint (POST .../credentials), not a rotate
                    // (rotate_engine_credential requires exactly one active
                    // credential already).
                    html += "<form style=\"display:inline\" data-engine-action=\"mint\" "
                            "data-principal-id=\"" +
                            html_escape(p.principal_id) +
                            "\">"
                            "<input type=\"hidden\" name=\"ttl_days\" value=\"90\">"
                            "<button class=\"btn btn-secondary\" type=\"submit\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\">"
                            "Mint</button></form> ";
                } else {
                    // Rotate credential — overlap-pair rotation (design doc §7).
                    html += "<form style=\"display:inline\" data-engine-action=\"rotate\" "
                            "data-principal-id=\"" +
                            html_escape(p.principal_id) +
                            "\">"
                            "<input type=\"hidden\" name=\"overlap_secs\" value=\"86400\">"
                            "<button class=\"btn btn-secondary\" type=\"submit\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "data-confirm=\"Rotate credential for &quot;" +
                            html_escape(p.principal_id) +
                            "&quot;? A 24h overlap window keeps both credentials valid.\">"
                            "Rotate</button></form> ";
                }

                // Admin-forced owner transfer — never depends on the
                // outgoing owner's cooperation (design doc §3.1).
                html += "<form style=\"display:inline\" data-engine-action=\"transfer\" "
                        "data-principal-id=\"" +
                        html_escape(p.principal_id) +
                        "\">"
                        "<input type=\"text\" name=\"new_owner\" placeholder=\"new owner\" "
                        "style=\"width:90px;font-size:0.7rem\" required>"
                        "<button class=\"btn btn-secondary\" type=\"submit\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\">"
                        "Transfer</button></form> ";

                // Revoke — terminal, never un-revocable (design doc §3.1 /
                // §12 decision 1). The REST DELETE route's only body field
                // is the OPTIONAL `superseded_by` (a revoke-and-replace
                // link) — it has no operator-reason field at all, so this
                // input is optional, not required (an earlier draft
                // required a free-text "reason" the route never consumed).
                html += "<form style=\"display:inline\" data-engine-action=\"revoke\" "
                        "data-principal-id=\"" +
                        html_escape(p.principal_id) +
                        "\">"
                        "<input type=\"text\" name=\"superseded_by\" "
                        "placeholder=\"successor id (optional)\" "
                        "style=\"width:130px;font-size:0.7rem\">"
                        "<button class=\"btn btn-danger\" type=\"submit\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "data-confirm=\"Revoke engine principal &quot;" +
                        html_escape(p.principal_id) +
                        "&quot;? This is TERMINAL — never un-revocable; recovery mints a "
                        "successor.\">Revoke</button></form>";
            }

            html += "</td></tr>";
        }
    }

    html += "  </tbody></table>";

    // NOTE: the one-time-reveal target (#engine-principal-reveal) is
    // DELIBERATELY NOT emitted here — it lives in the static page shell
    // (settings_ui.cpp), OUTSIDE this fragment's own auto-refreshing
    // container. This fragment's entire innerHTML is replaced on every
    // `refreshEnginePrincipals` trigger — including the one a successful
    // mint/rotate fires immediately after populating the reveal panel — so
    // a reveal element nested in here would be wiped the instant it
    // appeared. See settings_ui.cpp's comment at the same id.

    // Plain <form> (no hx-post) — same JSON-vs-form-urlencoded reasoning as
    // the per-row mutation forms above; the body-level submit listener
    // (settings_ui.cpp) builds the REST route's actual JSON body
    // `{slug, display_name, owner_username, justification, classification}`
    // (the route derives `principal_id = "engine:" + slug` itself — the
    // field the form submits is the bare slug, not a pre-built
    // "engine:"-prefixed principal_id).
    html += "<form class=\"add-user-form\" data-engine-action=\"create\">"
            "  <div class=\"mini-field\">"
            "    <label>Slug</label>"
            "    <input type=\"text\" name=\"slug\" placeholder=\"vuln-uce\" "
            "style=\"width:140px\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Display Name</label>"
            "    <input type=\"text\" name=\"display_name\" placeholder=\"Vuln UCE\" "
            "style=\"width:120px\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Owner</label>"
            "    <input type=\"text\" name=\"owner_username\" placeholder=\"username\" "
            "style=\"width:100px\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Classification</label>"
            "    <select name=\"classification\" style=\"width:90px\" required>"
            "      <option value=\"internal\">internal</option>"
            "      <option value=\"external\">external</option>"
            "    </select>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Justification</label>"
            "    <input type=\"text\" name=\"justification\" placeholder=\"grant reason\" "
            "style=\"width:140px\" required>"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Create</button>"
            "</form>"
            "<div class=\"feedback\" id=\"engine-principal-feedback\"></div>";

    return html;
}

namespace {

/// Format an epoch-milliseconds timestamp for display; 0 -> "n/a" (matches
/// AccessReviewRow::last_activity_ms / AccessReviewAttestationRow::
/// decided_at_ms's "0 = unknown/not yet" convention).
std::string ar_fmt_epoch_ms(int64_t epoch_ms) {
    if (epoch_ms == 0)
        return "n/a";
    auto tt = static_cast<std::time_t>(epoch_ms / 1000);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_buf);
    return std::string(buf) + " UTC";
}

/// The self-contained JS helper block for the Access Reviews fragment's
/// write actions. Emitted ONCE, inside the top-level fragment
/// (render_access_review_fragment) — the campaign sub-fragment is always
/// swapped as a DESCENDANT of that fragment's DOM (see #ar-campaign below),
/// so these globals stay available across every `arLoadCampaign` refresh
/// without re-declaring them. htmx re-executes inline <script> tags found in
/// swapped content (`allowScriptTags` default true — see static_js_bundle.cpp),
/// but redeclaring `function` statements is itself harmless in JS, so a
/// double-load (e.g. re-selecting the Settings nav item) is not a bug either
/// way.
///
/// Deliberately plain `fetch()`, not `hx-post` — the target REST endpoints
/// (rest_api_v1.cpp) parse a JSON body (`nlohmann::json::parse(req.body)`,
/// no bundled json-enc extension), while htmx's native form/attribute
/// submission serializes `application/x-www-form-urlencoded` and would 400
/// "invalid JSON". Same reasoning + precedent as the Engine Principals
/// fragment's data-engine-action forms above. Also CSP-safe: a plain
/// `onclick="arFoo(this)"` attribute (allowed by `unsafe-inline`), never
/// `hx-on` (blocked — compiles via `new Function()`, `unsafe-eval` is not
/// granted).
const char* const kAccessReviewScript = R"JS(
<script>
function arFeedback(msg, isError) {
  var fb = document.getElementById('ar-feedback');
  if (!fb) return;
  fb.textContent = msg;
  fb.style.color = isError ? '#f85149' : '#3fb950';
}
function arPost(url, body, onSuccess) {
  fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {})
  }).then(function (r) {
    return r.text().then(function (t) {
      var data = {};
      try { data = JSON.parse(t); } catch (e) {}
      if (!r.ok) {
        var msg = (data && (data.error || data.message)) || ('Action failed (' + r.status + ')');
        arFeedback(msg, true);
        return;
      }
      arFeedback('Done.', false);
      if (onSuccess) onSuccess(data);
    });
  }).catch(function () {
    arFeedback('Network error — the action may not have applied', true);
  });
}
function arLoadCampaign(id) {
  htmx.ajax('GET', '/fragments/settings/access-reviews/campaign?id=' + encodeURIComponent(id),
            {target: '#ar-campaign', swap: 'innerHTML'});
}
function arOpenCampaign(form) {
  var title = (form.elements['title'].value || '').trim();
  if (!title) return false;
  arPost('/api/v1/access-reviews', {title: title}, function (data) {
    if (data && data.campaign_id) arLoadCampaign(data.campaign_id);
  });
  return false;
}
function arAttest(btn) {
  var d = btn.dataset;
  if (d.decision === 'flagged_revoke' &&
      !window.confirm('Flag ' + d.principalType + ' "' + d.principalId + '" role "' + d.roleName +
                       '" for revocation? This records evidence only — it does NOT revoke the grant.')) {
    return;
  }
  var row = btn.closest('tr');
  var justEl = row ? row.querySelector('[data-ar-justification]') : null;
  arPost('/api/v1/access-reviews/' + encodeURIComponent(d.campaignId) + '/attestations', {
    principal_type: d.principalType,
    principal_id: d.principalId,
    role_name: d.roleName,
    decision: d.decision,
    justification: justEl ? justEl.value : ''
  }, function () { arLoadCampaign(d.campaignId); });
}
function arCloseCampaign(btn) {
  var id = btn.dataset.campaignId;
  if (!window.confirm('Close review campaign ' + id + '? An incomplete review can still be closed.'))
    return;
  arPost('/api/v1/access-reviews/' + encodeURIComponent(id) + '/close', null,
         function () { arLoadCampaign(id); });
}
</script>
)JS";

} // namespace

std::string SettingsRoutes::render_access_review_fragment(const httplib::Request& req) {
    // Periodic Access Reviews (SOC 2 CC6.2). This dashboard fragment is a
    // CONVENIENCE surface only — GET /api/v1/access-reviews/export and the
    // full /api/v1/access-reviews* campaign lifecycle (rest_api_v1.cpp) plus
    // their MCP twins are the ADR-1005 API-parity surface; the write
    // controls below call those same REST routes directly (see
    // kAccessReviewScript) rather than duplicating AccessReviewStore writes
    // in this file.
    // NOTE: deliberately no outer `<div id="access-review-section">` wrapper
    // here — that id belongs to the STATIC shell div in settings_ui.cpp
    // (hx-swap="innerHTML" target); this fragment's output becomes that
    // div's inner content, mirroring render_api_tokens_fragment's convention.
    std::string html;
    html += kAccessReviewScript;
    html += "<div class=\"feedback\" id=\"ar-feedback\"></div>";

    html += "<div style=\"margin-bottom:0.75rem\">"
            "<a class=\"btn btn-secondary\" style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
            "href=\"/api/v1/access-reviews/export?format=csv\">Download CSV</a>"
            "</div>";

    auto* auth_db = auth_mgr_ ? auth_mgr_->auth_db_ptr() : nullptr;
    auto rows_res = build_access_review(auth_db, rbac_store_, engine_principal_store_,
                                        api_token_store_, directory_sync_);

    html += "<table class=\"user-table\">"
            "<thead><tr><th>Principal</th><th>Roles</th><th>Perms</th>"
            "<th>Last activity</th><th>Classification</th><th>Lifecycle</th><th>Source</th>"
            "</tr></thead><tbody>";

    if (!rows_res.has_value()) {
        // Mirrors render_api_tokens_fragment's read-failure posture (ADR-0012
        // §1): surface the failure rather than render an empty table that
        // could be misread as "zero grants exist" — a false negative in
        // exactly the evidence this feature exists to produce.
        html += "<tr><td colspan=\"7\" style=\"color:#f85149\">Access review data unavailable (" +
                html_escape(rows_res.error()) + ") — please retry.</td></tr></tbody></table>";
        return html;
    }

    const auto& rows = *rows_res;
    if (rows.empty()) {
        html += "<tr><td colspan=\"7\" style=\"color:#484f58\">No principals found</td></tr>";
    } else {
        // Render-capped so a large RBAC population can't emit an unbounded
        // HTML fragment (mirrors inventory_ui.cpp's kDeviceRenderCap
        // pattern) — the CSV export above is the authoritative full-set
        // evidence surface, not this table.
        constexpr std::size_t kAccessReviewRenderCap = 1000;
        const std::size_t total = rows.size();
        const std::size_t shown = total > kAccessReviewRenderCap ? kAccessReviewRenderCap : total;
        for (std::size_t i = 0; i < shown; ++i) {
            const auto& r = rows[i];
            std::string roles_joined;
            for (std::size_t j = 0; j < r.roles.size(); ++j) {
                if (j)
                    roles_joined += ", ";
                roles_joined += r.roles[j];
            }
            std::string principal_label =
                r.display_name.empty() ? r.principal_id : r.display_name;
            std::string last_activity = r.last_activity_ms == 0
                                            ? "n/a"
                                            : ar_fmt_epoch_ms(r.last_activity_ms) + " (" +
                                                  r.last_activity_kind + ")";

            html += "<tr><td><span class=\"role-badge\">" + html_escape(r.principal_type) +
                    "</span> " + html_escape(principal_label);
            if (!r.owner_or_email.empty()) {
                html += "<br><span style=\"font-size:0.7rem;color:"
                        "var(--mds-color-theme-text-tertiary)\">" +
                        html_escape(r.owner_or_email) + "</span>";
            }
            html += "</td>"
                    "<td style=\"font-size:0.8rem\">" +
                    html_escape(roles_joined) +
                    "</td>"
                    "<td>" +
                    std::to_string(r.effective_permission_count) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    html_escape(last_activity) +
                    "</td>"
                    "<td>" +
                    html_escape(r.classification) +
                    "</td>"
                    "<td>" +
                    html_escape(r.lifecycle_state) +
                    "</td>"
                    "<td>" +
                    html_escape(r.source) +
                    "</td></tr>";
        }
        html += "</tbody></table>";
        if (total > kAccessReviewRenderCap) {
            html += "<div style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary);"
                    "margin-top:0.3rem\">Showing " +
                    std::to_string(shown) + " of " + std::to_string(total) +
                    " principals — the CSV export above has the complete evidence set.</div>";
        }
    }
    if (rows.empty())
        html += "</tbody></table>";

    // Open-review-campaign control — probed against a throwaway response so
    // a read-only auditor gets an honest omission rather than a swallowed
    // 403 (mirrors dex_routes.cpp's can_execute pattern). The probe is
    // against the SAME securable:operation the REST POST route itself
    // gates (AccessReview:Attest).
    httplib::Response probe;
    bool can_attest = perm_fn_(req, probe, "AccessReview", "Attest");

    if (can_attest) {
        html += "<form onsubmit=\"return arOpenCampaign(this)\" "
                "style=\"display:flex;gap:0.5rem;align-items:flex-end;margin-top:1rem\">"
                "<div class=\"mini-field\" style=\"flex:1\">"
                "<label>Campaign title</label>"
                "<input type=\"text\" name=\"title\" placeholder=\"e.g. Q3 2026 access review\" "
                "required>"
                "</div>"
                "<button class=\"btn btn-primary\" type=\"submit\">Open review campaign</button>"
                "</form>";
    }

    std::string campaign_id = req.has_param("campaign_id") ? req.get_param_value("campaign_id") : "";
    html += render_access_review_campaign_fragment(req, campaign_id);

    return html;
}

std::string
SettingsRoutes::render_access_review_campaign_fragment(const httplib::Request& req,
                                                        const std::string& campaign_id) {
    std::string html = "<div id=\"ar-campaign\">";
    if (campaign_id.empty()) {
        html += "</div>";
        return html;
    }

    if (!access_review_store_ || !access_review_store_->is_open()) {
        html += "<div style=\"color:#f85149\">Access review campaign store unavailable — "
                "please retry.</div></div>";
        return html;
    }

    auto view_res = access_review_store_->get_campaign(campaign_id);
    if (!view_res.has_value()) {
        // Covers both the store's machine-checkable "not_found: ..." (unknown
        // campaign id) and a genuine read failure — either way, an honest
        // notice rather than a blank panel.
        html += "<div style=\"color:#f85149\">" + html_escape(view_res.error()) + "</div></div>";
        return html;
    }
    const auto& view = *view_res;

    httplib::Response probe;
    bool can_attest = perm_fn_(req, probe, "AccessReview", "Attest");
    bool is_open_campaign = view.campaign.status == "open";

    html += "<h4 style=\"margin:1rem 0 0.25rem\">Campaign: " + html_escape(view.campaign.title) +
            " <span class=\"role-badge " + (is_open_campaign ? "role-admin" : "role-user") +
            "\">" + html_escape(view.campaign.status) + "</span></h4>";
    html += "<div style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary);"
            "margin-bottom:0.5rem\">" +
            std::to_string(view.pending_count) + " pending of " +
            std::to_string(view.attestations.size()) + " grant(s) reviewed — opened by " +
            html_escape(view.campaign.created_by);
    if (!view.campaign.closed_by.empty()) {
        html += ", closed by " + html_escape(view.campaign.closed_by);
    }
    html += "</div>";

    if (can_attest && is_open_campaign) {
        html += "<button class=\"btn btn-secondary\" "
                "style=\"padding:0.3rem 0.8rem;font-size:0.75rem;margin-bottom:0.5rem\" "
                "data-campaign-id=\"" +
                html_escape(campaign_id) + "\" onclick=\"arCloseCampaign(this)\">Close campaign</button>";
    }

    html += "<table class=\"user-table\"><thead><tr><th>Principal</th><th>Role</th>"
            "<th>Decision</th><th>Reviewer</th><th>Decided</th>";
    if (can_attest)
        html += "<th>Justification</th><th></th>";
    html += "</tr></thead><tbody>";

    if (view.attestations.empty()) {
        html += "<tr><td colspan=\"" + std::to_string(can_attest ? 7 : 5) +
                "\" style=\"color:#484f58\">No frozen grants in this campaign</td></tr>";
    } else {
        for (const auto& a : view.attestations) {
            bool pending = a.decision == "pending";
            std::string decision_cls = pending || a.decision == "flagged_revoke" ? "role-user"
                                                                                  : "role-admin";
            html += "<tr><td><span class=\"role-badge\">" + html_escape(a.principal_type) +
                    "</span> " + html_escape(a.principal_id) +
                    "</td>"
                    "<td>" +
                    html_escape(a.role_name) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    decision_cls + "\">" + html_escape(a.decision) +
                    "</span></td>"
                    "<td>" +
                    (a.reviewer.empty() ? "—" : html_escape(a.reviewer)) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    ar_fmt_epoch_ms(a.decided_at_ms) + "</td>";
            if (can_attest) {
                html += "<td>";
                if (pending && is_open_campaign) {
                    html += "<input type=\"text\" data-ar-justification placeholder=\"optional\" "
                            "style=\"width:110px;font-size:0.7rem\">";
                } else {
                    html += a.justification.empty() ? "—" : html_escape(a.justification);
                }
                html += "</td><td>";
                if (pending && is_open_campaign) {
                    html += "<button class=\"btn btn-primary\" "
                            "style=\"padding:0.15rem 0.5rem;font-size:0.7rem\" "
                            "data-campaign-id=\"" +
                            html_escape(campaign_id) + "\" data-principal-type=\"" +
                            html_escape(a.principal_type) + "\" data-principal-id=\"" +
                            html_escape(a.principal_id) + "\" data-role-name=\"" +
                            html_escape(a.role_name) +
                            "\" data-decision=\"attested\" "
                            "onclick=\"arAttest(this)\">Attest</button> "
                            "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.15rem 0.5rem;font-size:0.7rem\" "
                            "data-campaign-id=\"" +
                            html_escape(campaign_id) + "\" data-principal-type=\"" +
                            html_escape(a.principal_type) + "\" data-principal-id=\"" +
                            html_escape(a.principal_id) + "\" data-role-name=\"" +
                            html_escape(a.role_name) +
                            "\" data-decision=\"flagged_revoke\" "
                            "onclick=\"arAttest(this)\">Flag for revocation (records evidence; "
                            "does not revoke)</button>";
                }
                html += "</td>";
            }
            html += "</tr>";
        }
    }
    html += "</tbody></table></div>";
    return html;
}

std::string SettingsRoutes::render_mfa_fragment(const std::string& username,
                                                const std::string& new_otpauth_uri,
                                                const std::string& new_secret_b32,
                                                const std::vector<std::string>& new_recovery_codes,
                                                const std::string& enrollment_pending_for_verify,
                                                const std::string& error_msg) {
    // The fragment renders one of three lifecycle states:
    //   1. Not enrolled — "Enable MFA" button
    //   2. Provisional (enrollment initiated, code not yet verified) —
    //      secret/URI shown, "Enter code to verify" form
    //   3. Enrolled — status + "Regenerate recovery codes" + "Disable" buttons
    auto* auth_db = auth_mgr_ ? auth_mgr_->auth_db_ptr() : nullptr;
    if (!auth_db) {
        return "<span style=\"color:#484f58\">MFA store unavailable (no AuthDB configured).</span>";
    }

    std::string html;
    if (!error_msg.empty()) {
        html += "<div class=\"error-msg\" role=\"alert\" style=\"color: var(--red); "
                "font-size: 0.8rem; margin-bottom: 0.75rem;\">" +
                html_escape(error_msg) + "</div>";
    }

    // Provisional verification panel. Two shapes:
    //   (a) First reveal post-init — `new_otpauth_uri` and
    //       `new_secret_b32` are non-empty, render the QR/URI + verify
    //       form (one-time reveal).
    //   (b) Retry after a failed verify — empty new_otpauth_uri /
    //       new_secret_b32 but `enrollment_pending_for_verify` is set:
    //       render only the verify form with a hint to wait for the
    //       next 30s window. We DO NOT re-reveal the secret here —
    //       repeatedly re-emitting it on every failed verify would
    //       defeat the one-time-reveal property (Gate 4 happy-path B3
    //       + security defence-in-depth: an attacker triggering verify
    //       failures should not fish the secret back).
    if (!enrollment_pending_for_verify.empty()) {
        if (!new_otpauth_uri.empty()) {
            // Server-rendered QR (issue #1232). The SVG is from the trusted
            // qrcodegen encoder over our own otpauth URI — not operator input —
            // so it is injected raw (it must not be html_escaped or it won't
            // render). Empty on encode failure → text fallback still shows.
            const std::string qr_svg = otpauth_qr_svg(new_otpauth_uri);
            html += "<div class=\"token-reveal\">"
                    "  <div class=\"token-reveal-header\">"
                    "    SCAN THIS WITH YOUR AUTHENTICATOR APP — secret shown only once"
                    "  </div>";
            if (!qr_svg.empty()) {
                html += "  <div style=\"display:flex;justify-content:center;margin:0.75rem 0\">"
                        "    <div style=\"background:#fff;padding:8px;border-radius:6px;"
                        "line-height:0\">" +
                        qr_svg +
                        "</div>"
                        "  </div>"
                        "  <div style=\"font-size:0.7rem;color:var(--mds-color-theme-text-tertiary);"
                        "text-align:center\">Can't scan? Enter the secret below manually.</div>";
            }
            html += "  <div style=\"font-size:0.7rem;color:var(--mds-color-theme-text-tertiary);"
                    "margin-top:0.5rem\">Base32 secret (manual entry):</div>"
                    "  <code>" +
                    html_escape(new_secret_b32) +
                    "</code>"
                    "  <div style=\"font-size:0.7rem;color:var(--mds-color-theme-text-tertiary);"
                    "margin-top:0.5rem\">otpauth URI:</div>"
                    "  <code style=\"display:block;word-break:break-all\">" +
                    html_escape(new_otpauth_uri) +
                    "</code>"
                    "</div>";
        } else {
            html += "<div style=\"font-size:0.8rem;color:var(--mds-color-theme-text-tertiary);"
                    "margin-bottom:0.75rem\">"
                    "Codes refresh every 30 seconds — wait for the next code shown by your "
                    "authenticator and try again. If you have lost the original QR code, "
                    "press <strong>Disable MFA</strong> below and restart enrollment."
                    "</div>";
        }
        html += "<form hx-post=\"/api/settings/mfa/verify\""
                "      hx-target=\"#mfa-section\" hx-swap=\"innerHTML\""
                "      style=\"margin-top:1rem\">"
                "  <div class=\"mini-field\">"
                "    <label>Verification code from your app</label>"
                "    <input type=\"text\" name=\"code\" inputmode=\"numeric\" "
                "autocomplete=\"one-time-code\" autocapitalize=\"none\" autocorrect=\"off\" "
                "spellcheck=\"false\" required style=\"width:120px\">"
                "  </div>"
                "  <button class=\"btn btn-primary\" type=\"submit\">Confirm</button>"
                "  <button class=\"btn btn-secondary\" type=\"submit\""
                "          hx-post=\"/api/settings/mfa/disable\""
                "          hx-target=\"#mfa-section\" hx-swap=\"innerHTML\""
                "          formnovalidate"
                "          style=\"margin-left:0.5rem\">Disable MFA</button>"
                "</form>";
        return html;
    }

    auto status_res = auth_db->mfa_status(username);
    if (!status_res) {
        // Read-only display path — no session/MFA-skip decision is made
        // here either way, but ★ (architect BLOCK follow-through) the
        // message must not misreport a store/decrypt failure
        // (SecretUnavailable/QueryFailed) as "user not found" — that would
        // mislead an operator into thinking the account is gone rather than
        // that MFA state is temporarily unreadable (retry, don't panic).
        const bool store_unavailable = is_store_unavailable(status_res.error());
        if (store_unavailable && metrics_registry_) {
            metrics_registry_
                ->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_enroll"}})
                .increment();
        }
        return html +
               (store_unavailable
                    ? "<span style=\"color:#484f58\">MFA status is temporarily unavailable "
                      "(authentication store error) — retry shortly.</span>"
                    : "<span style=\"color:#484f58\">User not found for MFA status.</span>");
    }
    const auto& status = *status_res;

    if (!new_recovery_codes.empty()) {
        html += "<div class=\"token-reveal\">"
                "  <div class=\"token-reveal-header\">"
                "    STORE THESE RECOVERY CODES NOW — each can be used once to bypass MFA"
                "  </div>"
                "  <ul style=\"font-family:var(--mono);margin:0.5rem 0;padding-left:1.25rem\">";
        for (const auto& code : new_recovery_codes) {
            html += "<li><code>" + html_escape(code) + "</code></li>";
        }
        html += "</ul></div>";
    }

    html += "<div style=\"display:flex;align-items:center;gap:1rem;margin-bottom:1rem\">";
    if (status.enrolled) {
        html += "<span class=\"yb\">Enabled</span>"
                "<span style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
                "Enrolled " +
                html_escape(status.enrolled_at) + " UTC</span>";
    } else if (!status.disabled_at.empty()) {
        html += "<span class=\"yn\">Disabled</span>"
                "<span style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
                "Last disabled " +
                html_escape(status.disabled_at) + " UTC</span>";
    } else {
        html += "<span class=\"yn\">Not enrolled</span>";
    }
    html += "</div>";

    if (status.enrolled) {
        html += "<div style=\"font-size:0.8rem;margin-bottom:0.75rem\">"
                "Recovery codes remaining: <strong>" +
                std::to_string(status.recovery_codes_remaining) +
                "</strong></div>"
                "<form hx-post=\"/api/settings/mfa/recovery-codes\""
                "      hx-target=\"#mfa-section\" hx-swap=\"innerHTML\""
                "      style=\"display:inline-block;margin-right:0.5rem\">"
                "  <button class=\"btn btn-secondary\" type=\"submit\">Regenerate recovery codes</button>"
                "</form>"
                "<form hx-post=\"/api/settings/mfa/disable\""
                "      hx-target=\"#mfa-section\" hx-swap=\"innerHTML\""
                "      hx-confirm=\"Disable MFA for your account? Step-up authentication will no "
                "longer be required.\""
                "      style=\"display:inline-block\">"
                "  <button class=\"btn btn-danger\" type=\"submit\">Disable MFA</button>"
                "</form>";
    } else {
        html += "<form hx-post=\"/api/settings/mfa/init\""
                "      hx-target=\"#mfa-section\" hx-swap=\"innerHTML\">"
                "  <button class=\"btn btn-primary\" type=\"submit\">Enable MFA</button>"
                "</form>";
    }
    return html;
}

std::string SettingsRoutes::render_pending_fragment() {
    auto all_agents = auth_mgr_->list_pending_agents();
    // Filter out enrolled (approved) agents — they don't need admin attention.
    // Only show pending and denied entries in the approval queue.
    std::vector<auth::PendingAgent> agents;
    for (auto& a : all_agents) {
        if (a.status != auth::PendingStatus::approved) {
            agents.push_back(std::move(a));
        }
    }
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th>"
                       "  <th>Version</th><th>Status</th><th></th></tr></thead>"
                       "  <tbody>";

    if (agents.empty()) {
        html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No pending agents</td></tr>";
    } else {
        for (const auto& a : agents) {
            auto status_str = auth::pending_status_to_string(a.status);
            std::string status_cls, status_style;
            if (a.status == auth::PendingStatus::approved) {
                status_cls = "role-admin";
            } else if (a.status == auth::PendingStatus::denied) {
                status_cls = "role-user";
            } else {
                status_style = "background:var(--yellow);color:#000";
            }

            auto short_id = a.agent_id.size() > 12 ? a.agent_id.substr(0, 12) + "..." : a.agent_id;

            html += "<tr>"
                    "<td><code style=\"font-size:0.7rem\">" +
                    html_escape(short_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(a.hostname) +
                    "</td>"
                    "<td>" +
                    html_escape(a.os) + " " + html_escape(a.arch) +
                    "</td>"
                    "<td>" +
                    html_escape(a.agent_version) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\" style=\"" + status_style + "\">" + html_escape(status_str) +
                    "</span></td>"
                    "<td>";

            if (a.status == auth::PendingStatus::pending) {
                html += "<button class=\"btn btn-primary\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem;margin-right:0.3rem\" "
                        "hx-post=\"/api/settings/pending-agents/" +
                        html_escape(a.agent_id) +
                        "/approve\" "
                        "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                        ">Approve</button>"
                        "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-post=\"/api/settings/pending-agents/" +
                        html_escape(a.agent_id) +
                        "/deny\" "
                        "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Deny agent enrollment?\""
                        ">Deny</button>";
            } else {
                html += "<button class=\"btn btn-secondary\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/pending-agents/" +
                        html_escape(a.agent_id) +
                        "\" "
                        "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                        ">Remove</button>";
            }

            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>";

    auto pending_count = std::count_if(agents.begin(), agents.end(), [](const auto& a) {
        return a.status == auth::PendingStatus::pending;
    });
    if (pending_count > 1) {
        html += "<div style=\"margin-top:0.75rem;display:flex;gap:0.5rem\">"
                "<button class=\"btn btn-primary\" "
                "style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
                "onclick=\"twoClickConfirm(this, function() { "
                "htmx.ajax('POST','/api/settings/pending-agents/bulk-approve',"
                "{target:'#pending-section',swap:'innerHTML'}); })\">"
                "Approve All (" +
                std::to_string(pending_count) +
                ")</button>"
                "<button class=\"btn btn-danger\" "
                "style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
                "onclick=\"twoClickConfirm(this, function() { "
                "htmx.ajax('POST','/api/settings/pending-agents/bulk-deny',"
                "{target:'#pending-section',swap:'innerHTML'}); })\">"
                "Deny All (" +
                std::to_string(pending_count) +
                ")</button>"
                "</div>";
    }

    html += "<div class=\"feedback\" id=\"pending-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_auto_approve_fragment() {
    auto rules = auto_approve_->list_rules();
    std::string html;

    html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
            "<label>Match mode</label>"
            "<select name=\"mode\" "
            "hx-post=\"/api/settings/auto-approve/mode\" "
            "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
            "style=\"flex:0 0 auto;width:180px\">"
            "<option value=\"any\"" +
            std::string(auto_approve_->require_all() ? "" : " selected") +
            ">Any rule (first match)</option>"
            "<option value=\"all\"" +
            std::string(auto_approve_->require_all() ? " selected" : "") +
            ">All rules must match</option>"
            "</select>"
            "</div>";

    html += "<table class=\"user-table\">"
            "<thead><tr><th>Type</th><th>Value</th><th>Label</th>"
            "<th>Enabled</th><th></th></tr></thead><tbody>";

    if (rules.empty()) {
        html += "<tr><td colspan=\"5\" style=\"color:#484f58\">No auto-approve rules "
                "configured</td></tr>";
    } else {
        auto type_str = [](auth::AutoApproveRuleType t) -> std::string {
            switch (t) {
            case auth::AutoApproveRuleType::trusted_ca:
                return "Trusted CA";
            case auth::AutoApproveRuleType::hostname_glob:
                return "Hostname Glob";
            case auth::AutoApproveRuleType::ip_subnet:
                return "IP Subnet";
            case auth::AutoApproveRuleType::cloud_provider:
                return "Cloud Provider";
            }
            return "Unknown";
        };

        for (size_t i = 0; i < rules.size(); ++i) {
            const auto& r = rules[i];
            auto idx = std::to_string(i);
            html += "<tr>"
                    "<td>" +
                    html_escape(type_str(r.type)) +
                    "</td>"
                    "<td><code style=\"font-size:0.75rem\">" +
                    html_escape(r.value) +
                    "</code></td>"
                    "<td>" +
                    html_escape(r.label) +
                    "</td>"
                    "<td>"
                    "<label class=\"toggle\">"
                    "<input type=\"checkbox\"" +
                    std::string(r.enabled ? " checked" : "") +
                    " hx-post=\"/api/settings/auto-approve/" + idx +
                    "/toggle\" "
                    "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\">"
                    "<span class=\"slider\"></span></label></td>"
                    "<td><button class=\"btn btn-danger\" "
                    "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                    "hx-delete=\"/api/settings/auto-approve/" +
                    idx +
                    "\" "
                    "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Remove this auto-approve rule?\" "
                    ">Remove</button></td></tr>";
        }
    }

    html += "</tbody></table>";

    html += "<div class=\"add-user-form\">"
            "<form hx-post=\"/api/settings/auto-approve\" "
            "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
            "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
            "<div class=\"mini-field\">"
            "<label>Type</label>"
            "<select name=\"type\" style=\"width:140px\">"
            "<option value=\"hostname_glob\">Hostname Glob</option>"
            "<option value=\"ip_subnet\">IP Subnet</option>"
            "<option value=\"trusted_ca\">Trusted CA</option>"
            "<option value=\"cloud_provider\">Cloud Provider</option>"
            "</select></div>"
            "<div class=\"mini-field\" style=\"flex:1\">"
            "<label>Value</label>"
            "<input type=\"text\" name=\"value\" placeholder=\"*.prod.example.com\" required>"
            "</div>"
            "<div class=\"mini-field\" style=\"flex:1\">"
            "<label>Label</label>"
            "<input type=\"text\" name=\"label\" placeholder=\"Production servers\">"
            "</div>"
            "<button class=\"btn btn-primary\" type=\"submit\">Add Rule</button>"
            "</form></div>"
            "<div class=\"feedback\" id=\"auto-approve-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_tag_compliance_fragment() {
    const auto& categories = get_tag_categories();

    std::string html;
    html += "<table class=\"user-table\">"
            "<thead><tr>"
            "<th>Category</th>"
            "<th>Display Name</th>"
            "<th>Agents Tagged</th>"
            "<th>Agents Missing</th>"
            "<th>Allowed Values</th>"
            "</tr></thead><tbody>";

    // Two bulk reads (ADR-0050 — the pre-migration version issued up to nine
    // queries per render: gaps + agents_with_tag per category twice over).
    // Dashboard render caller: a degraded read returns an explicit error
    // fragment rather than silently rendering "0 tagged / 0 missing" as if
    // the fleet were compliant.
    std::vector<std::pair<std::string, std::vector<std::string>>> gaps;
    std::unordered_map<std::string, int> tagged_count;
    size_t total_agents = 0;
    if (tag_store_) {
        auto gaps_res = tag_store_->get_compliance_gaps();
        auto values_res = tag_store_->get_values_for_keys(
            std::vector<std::string>(std::begin(kCategoryKeys), std::end(kCategoryKeys)));
        if (!gaps_res || !values_res) {
            return "<div style=\"color:#f85149\">Tag store unavailable — tag-compliance data "
                   "cannot be read right now.</div>";
        }
        gaps = std::move(*gaps_res);
        std::unordered_set<std::string> seen;
        for (const auto& [aid, m] : gaps)
            seen.insert(aid);
        for (const auto& [aid, keys] : *values_res) {
            seen.insert(aid);
            for (const auto& [k, v] : keys)
                tagged_count[k]++;
        }
        total_agents = seen.size();
    }

    std::unordered_map<std::string, int> missing_count;
    for (const auto& [agent_id, missing] : gaps) {
        for (const auto& k : missing)
            missing_count[k]++;
    }

    for (const auto& cat : categories) {
        std::string key_str(cat.key);
        int tagged = tagged_count.count(key_str) ? tagged_count[key_str] : 0;
        int missing = missing_count.count(key_str) ? missing_count[key_str] : 0;

        std::string vals_str;
        if (cat.allowed_values.empty()) {
            vals_str = "<span style=\"color:#8b949e\">Free-form</span>";
        } else {
            for (size_t i = 0; i < cat.allowed_values.size(); ++i) {
                if (i > 0)
                    vals_str += ", ";
                vals_str += std::string(cat.allowed_values[i]);
            }
        }

        std::string missing_style = missing > 0 ? "color:#f85149;font-weight:600" : "color:#3fb950";
        html += "<tr><td><code>" + key_str + "</code></td>";
        html += "<td>" + std::string(cat.display_name) + "</td>";
        html += "<td>" + std::to_string(tagged) + "</td>";
        html += "<td style=\"" + missing_style + "\">" + std::to_string(missing) + "</td>";
        html += "<td>" + vals_str + "</td></tr>";
    }

    html += "</tbody></table>";

    if (total_agents > 0) {
        size_t compliant = total_agents - gaps.size();
        html += "<div style=\"margin-top:0.75rem;font-size:0.75rem;color:#8b949e\">"
                "Compliance: " +
                std::to_string(compliant) + "/" + std::to_string(total_agents) +
                " agents have all required tags</div>";
    }

    return html;
}

std::string SettingsRoutes::render_management_groups_fragment() {
    if (!mgmt_group_store_ || !mgmt_group_store_->is_open())
        return "<span style=\"color:#484f58\">Management group store not available</span>";

    auto groups = mgmt_group_store_->list_groups();

    std::unordered_map<std::string, std::vector<const ManagementGroup*>> children_map;
    std::vector<const ManagementGroup*> roots;
    for (const auto& g : groups) {
        if (g.parent_id.empty())
            roots.push_back(&g);
        else
            children_map[g.parent_id].push_back(&g);
    }

    std::sort(roots.begin(), roots.end(), [](const ManagementGroup* a, const ManagementGroup* b) {
        if (a->id == ManagementGroupStore::kRootGroupId)
            return true;
        if (b->id == ManagementGroupStore::kRootGroupId)
            return false;
        return a->name < b->name;
    });

    std::string html;

    html += "<div style=\"margin-bottom:0.75rem;font-size:0.75rem;color:#8b949e\">"
            "Total groups: " +
            std::to_string(groups.size()) + " &middot; Total memberships: " +
            std::to_string(mgmt_group_store_->count_all_members()) + "</div>";

    html += "<table class=\"user-table\">"
            "<thead><tr>"
            "<th>Group</th>"
            "<th>Type</th>"
            "<th>Members</th>"
            "<th>Actions</th>"
            "</tr></thead><tbody>";

    std::function<void(const ManagementGroup*, int)> render_node = [&](const ManagementGroup* g,
                                                                       int depth) {
        auto member_count = mgmt_group_store_->count_members(g->id);
        bool is_root = (g->id == ManagementGroupStore::kRootGroupId);

        std::string indent;
        for (int i = 0; i < depth; ++i)
            indent += "&nbsp;&nbsp;&nbsp;&nbsp;";
        if (depth > 0)
            indent += "<span style=\"color:#484f58\">&boxur;</span> ";

        std::string name_style = is_root ? "font-weight:600" : "";
        std::string type_badge;
        if (g->membership_type == "dynamic") {
            type_badge = "<span style=\"background:#1f6feb;color:#fff;padding:1px 6px;"
                         "border-radius:3px;font-size:0.7rem\">dynamic</span>";
        } else {
            type_badge = "<span style=\"background:#484f58;color:#c9d1d9;padding:1px 6px;"
                         "border-radius:3px;font-size:0.7rem\">static</span>";
        }

        html += "<tr>";
        html += "<td>" + indent + "<span style=\"" + name_style + "\">" + html_escape(g->name) +
                "</span></td>";
        html += "<td>" + type_badge + "</td>";
        html += "<td>" + std::to_string(member_count) + "</td>";
        html += "<td>";
        if (!is_root) {
            html += "<button class=\"btn btn-sm\" "
                    "hx-delete=\"/api/settings/management-groups/" +
                    html_escape(g->id) +
                    "\" "
                    "hx-target=\"#mgmt-groups-section\" "
                    "hx-confirm=\"Delete group '" +
                    html_escape(g->name) +
                    "' and all children?\" "
                    "style=\"font-size:0.7rem;padding:1px 6px;color:#f85149;border-color:#f85149"
                    "\">Delete</button>";
        }
        html += "</td></tr>";

        auto it = children_map.find(g->id);
        if (it != children_map.end()) {
            auto sorted_children = it->second;
            std::sort(sorted_children.begin(), sorted_children.end(),
                      [](const ManagementGroup* a, const ManagementGroup* b) {
                          return a->name < b->name;
                      });
            for (const auto* child : sorted_children)
                render_node(child, depth + 1);
        }
    };

    for (const auto* root : roots)
        render_node(root, 0);

    html += "</tbody></table>";

    html += "<div style=\"margin-top:0.75rem\">"
            "<details><summary style=\"cursor:pointer;color:#58a6ff;font-size:0.8rem\">"
            "Create group</summary>"
            "<form hx-post=\"/api/settings/management-groups\" "
            "hx-target=\"#mgmt-groups-section\" "
            "hx-swap=\"innerHTML\" "
            "style=\"display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.5rem;align-items:end\">"
            "<div><label style=\"font-size:0.7rem;color:#8b949e\">Name</label>"
            "<input type=\"text\" name=\"name\" required "
            "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
            "padding:4px 8px;border-radius:4px;font-size:0.8rem\"></div>"
            "<div><label style=\"font-size:0.7rem;color:#8b949e\">Parent</label>"
            "<select name=\"parent_id\" "
            "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
            "padding:4px 8px;border-radius:4px;font-size:0.8rem\">"
            "<option value=\"\">— root —</option>";
    for (const auto& g : groups) {
        html += "<option value=\"" + html_escape(g.id) + "\">" + html_escape(g.name) + "</option>";
    }
    html += "</select></div>"
            "<div><label style=\"font-size:0.7rem;color:#8b949e\">Type</label>"
            "<select name=\"membership_type\" "
            "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
            "padding:4px 8px;border-radius:4px;font-size:0.8rem\">"
            "<option value=\"static\">static</option>"
            "<option value=\"dynamic\">dynamic</option>"
            "</select></div>"
            "<button type=\"submit\" class=\"btn\" "
            "style=\"font-size:0.8rem;padding:4px 12px\">Create</button>"
            "</form></details></div>";

    return html;
}

std::string SettingsRoutes::render_updates_fragment() {
    std::string html;

    std::string ota_color = cfg_->ota_enabled ? "#3fb950" : "#484f58";
    std::string ota_text = cfg_->ota_enabled ? "Enabled" : "Disabled";
    html += "<div class=\"form-row\">"
            "  <label>OTA Updates</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            ota_color + ";font-weight:600\">" + ota_text +
            "</span>"
            "</div>";

    std::string update_dir_str = cfg_->update_dir.empty() ? std::string("(default)")
                                                          : html_escape(cfg_->update_dir.string());
    html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
            "  <label>Update Directory</label>"
            "  <span class=\"file-name\">" +
            update_dir_str +
            "</span>"
            "</div>";

    if (!update_registry_) {
        html += "<span style=\"color:#484f58\">OTA updates are disabled "
                "(start server with <code>--ota-enabled</code>).</span>";
        return html;
    }

    auto packages = update_registry_->list_packages();

    // Fleet version summary — use the callback to avoid incomplete-type dep
    if (agents_json_fn_) {
        auto agents_json_str = agents_json_fn_();
        std::unordered_map<std::string, int> version_counts;
        try {
            auto arr = nlohmann::json::parse(agents_json_str);
            for (const auto& a : arr) {
                auto v = a.value("agent_version", std::string("unknown"));
                version_counts[v]++;
            }
        } catch (...) {}

        if (!version_counts.empty()) {
            html += "<div style=\"margin-bottom:1rem;padding:0.5rem 0.75rem;"
                    "background:#0d1117;border:1px solid #30363d;border-radius:0.3rem\">"
                    "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
                    "margin-bottom:0.3rem;text-transform:uppercase;letter-spacing:0.05em\">"
                    "Fleet Versions</div>";
            for (const auto& [ver, cnt] : version_counts) {
                html += "<span style=\"display:inline-block;margin-right:1rem;"
                        "font-size:0.75rem\"><code>" +
                        html_escape(ver) + "</code> &times; " + std::to_string(cnt) + "</span>";
            }
            html += "</div>";
        }
    }

    html += "<table class=\"user-table\">"
            "<thead><tr><th>Platform</th><th>Arch</th><th>Version</th>"
            "<th>Size</th><th>Signed</th><th>Rollout</th><th>Mandatory</th><th></th>"
            "</tr></thead>"
            "<tbody>";

    if (packages.empty()) {
        html += "<tr><td colspan=\"8\" style=\"color:#484f58\">"
                "No update packages uploaded</td></tr>";
    } else {
        for (const auto& pkg : packages) {
            auto size_str = pkg.file_size < 1024 * 1024
                                ? std::to_string(pkg.file_size / 1024) + " KB"
                                : std::to_string(pkg.file_size / (1024 * 1024)) + " MB";

            html += "<tr>"
                    "<td>" +
                    html_escape(pkg.platform) +
                    "</td>"
                    "<td>" +
                    html_escape(pkg.arch) +
                    "</td>"
                    "<td><code style=\"font-size:0.75rem\">" +
                    html_escape(pkg.version) +
                    "</code></td>"
                    "<td style=\"font-size:0.75rem\">" +
                    size_str +
                    "</td>"
                    // Read from disk, not from a stored flag: the sidecar is the
                    // artifact an agent is actually served, so this shows what the
                    // fleet will see rather than what the upload intended. Without
                    // it an operator has no way to tell a signed package from an
                    // unsigned one short of reading server logs.
                    "<td style=\"font-size:0.75rem\">" +
                    // The SAME decision CheckForUpdate makes, not just exists():
                    // an over-cap, unreadable or zero-byte sidecar is present on
                    // disk but served as UNSIGNED, so exists() alone would tell
                    // the operator "signed" while every agent is told otherwise —
                    // the one thing this column exists to prevent.
                    (update_registry_ &&
                     signature_sidecar_outcome(update_registry_->signature_path(pkg)) ==
                         SidecarOutcome::kServed
                         // A served signature that CANNOT cover the binary beside
                         // it gets its own state. Reporting it as "signed" is the
                         // worst of the three: the docs nominate this column as
                         // the confirmation check, so the operator reads success
                         // while every anchored agent refuses the package.
                         ? (signature_sidecar_covers_binary(
                                update_registry_->binary_path(pkg),
                                update_registry_->signature_path(pkg))
                                ? std::string("<span title=\"A detached signature is stored "
                                              "for this package\">signed</span>")
                                : std::string(
                                      "<span style=\"color:#d29922\" title=\"The stored "
                                      "signature is NEWER than the binary beside it, so it "
                                      "cannot be confirmed to cover it. Usually an upload that "
                                      "did not complete; a restore that did not preserve "
                                      "timestamps looks the same. Agents refuse a signature "
                                      "that does not verify, in both modes. Re-upload the "
                                      "binary and its signature together to clear "
                                      "it.\">signature mismatch</span>"))
                         : std::string("<span style=\"color:#8b949e\" title=\"No usable "
                                       "signature is being served: either none is stored, or "
                                       "the stored one is unreadable, empty or over the size "
                                       "cap (see the server log). Agents running "
                                       "--update-require-signature will refuse this "
                                       "package.\">unsigned</span>")) +
                    "</td>"
                    "<td>"
                    "<form style=\"display:flex;align-items:center;gap:0.4rem\" "
                    "hx-post=\"/api/settings/updates/" +
                    html_escape(pkg.platform) + "/" + html_escape(pkg.arch) + "/" +
                    html_escape(pkg.version) +
                    "/rollout\" "
                    "hx-target=\"#updates-section\" hx-swap=\"innerHTML\">"
                    "<input type=\"range\" name=\"rollout_pct\" min=\"0\" max=\"100\" "
                    "value=\"" +
                    std::to_string(pkg.rollout_pct) +
                    "\" "
                    "style=\"width:60px\" "
                    "onchange=\"this.nextElementSibling.textContent=this.value+'%'\">"
                    "<span style=\"font-size:0.7rem;width:2.5em\">" +
                    std::to_string(pkg.rollout_pct) +
                    "%</span>"
                    "<button class=\"btn btn-secondary\" type=\"submit\" "
                    "style=\"padding:0.15rem 0.5rem;font-size:0.65rem\">Set</button>"
                    "</form></td>"
                    "<td style=\"font-size:0.75rem\">" +
                    std::string(pkg.mandatory ? "Yes" : "No") +
                    "</td>"
                    "<td><button class=\"btn btn-danger\" "
                    "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                    "hx-delete=\"/api/settings/updates/" +
                    html_escape(pkg.platform) + "/" + html_escape(pkg.arch) + "/" +
                    html_escape(pkg.version) +
                    "\" "
                    "hx-target=\"#updates-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Delete update package " +
                    html_escape(pkg.version) + " for " + html_escape(pkg.platform) + "/" +
                    html_escape(pkg.arch) +
                    "?\""
                    ">Delete</button></td></tr>";
        }
    }

    html += "</tbody></table>";

    html += "<div class=\"add-user-form\">"
            "<form hx-post=\"/api/settings/updates/upload\" "
            "hx-target=\"#updates-section\" hx-swap=\"innerHTML\" "
            "hx-encoding=\"multipart/form-data\" "
            "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
            "<div class=\"mini-field\">"
            "<label>Platform</label>"
            "<select name=\"platform\" style=\"width:100px\">"
            "<option value=\"windows\">Windows</option>"
            "<option value=\"linux\">Linux</option>"
            "<option value=\"darwin\">macOS</option>"
            "</select></div>"
            "<div class=\"mini-field\">"
            "<label>Arch</label>"
            "<select name=\"arch\" style=\"width:100px\">"
            "<option value=\"x86_64\">x86_64</option>"
            "<option value=\"aarch64\">aarch64</option>"
            "</select></div>"
            "<div class=\"mini-field\">"
            "<label>Binary</label>"
            "<input type=\"file\" name=\"file\" required></div>"
            // Optional detached CMS signature (#416/#3807). Without this input
            // the documented signing workflow is unreachable from the UI and an
            // operator would ship an unsigned package believing it signed.
            // `mini-field`, matching every sibling in this inline row — `form-row`
            // is the stacked full-width variant and breaks the row's layout.
            "<div class=\"mini-field\">"
            "<label>Signature <span class=\"muted\">(optional, .sig)</span></label>"
            // No accept filter: ".sig" is only convention — ".p7s" and ".pem" are
            // common names for the same detached CMS blob, and filtering the picker
            // to one suffix hides the operator's actual file.
            "<input type=\"file\" name=\"signature\"></div>"
            "<div class=\"mini-field\">"
            "<label>Rollout %</label>"
            "<input type=\"text\" name=\"rollout_pct\" value=\"100\" style=\"width:50px\"></div>"
            "<div class=\"mini-field\" style=\"display:flex;align-items:center;gap:0.3rem\">"
            "<label>Mandatory</label>"
            "<input type=\"checkbox\" name=\"mandatory\" value=\"true\"></div>"
            "<button class=\"btn btn-primary\" type=\"submit\">Upload</button>"
            "</form></div>"
            "<div class=\"feedback\" id=\"updates-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_gateway_fragment() {
    // #4028 — shared builder; GET /api/v1/settings/gateway formats the SAME
    // JSON as its response body instead of re-deriving these fields.
    auto count = gateway_session_count_fn_ ? gateway_session_count_fn_() : 0;
    const auto v = settings_model::build_gateway_settings(*cfg_, gateway_enabled_, count);
    bool enabled = v.at("enabled").get<bool>();
    std::string status_color = enabled ? "#3fb950" : "#484f58";
    std::string status_text = enabled ? "Enabled" : "Disabled";

    std::string html;

    html += "<div class=\"form-row\">"
            "  <label>Upstream Service</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            status_color + ";font-weight:600\">" + status_text +
            "</span>"
            "</div>";

    if (enabled) {
        html += "<div class=\"form-row\">"
                "  <label>Listen Address</label>"
                "  <code style=\"font-size:0.8rem\">" +
                html_escape(v.at("listen_address").get<std::string>()) +
                "</code>"
                "</div>";

        const bool gw_mode = v.at("gateway_mode").get<bool>();
        html += "<div class=\"form-row\">"
                "  <label>Gateway Mode</label>"
                "  <span style=\"font-size:0.8rem;color:" +
                std::string(gw_mode ? "#3fb950" : "#8b949e") + "\">" +
                (gw_mode ? "Active" : "Inactive") +
                "</span>"
                "</div>";

        auto shown_count = v.at("active_sessions").get<std::int64_t>();
        html += "<div class=\"form-row\">"
                "  <label>Active Sessions</label>"
                "  <span style=\"font-size:0.8rem\">" +
                std::to_string(shown_count) + " agent" + (shown_count != 1 ? "s" : "") +
                " via gateway</span>"
                "</div>";
    } else {
        html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                "The gateway upstream service is not running. Start the server with "
                "<code>--gateway-upstream 0.0.0.0:50055</code> to enable it.</p>";
    }

    html += "<div style=\"margin-top:1rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
            "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
            "Erlang Gateway Environment Variables</div>"
            "<table class=\"user-table\" style=\"font-size:0.75rem\">"
            "<thead><tr><th>Variable</th><th>Description</th><th>Default</th></tr></thead>"
            "<tbody>"
            "<tr><td><code>YUZU_GW_UPSTREAM_ADDR</code></td>"
            "    <td>C++ server hostname</td><td><code>127.0.0.1</code></td></tr>"
            "<tr><td><code>YUZU_GW_UPSTREAM_PORT</code></td>"
            "    <td>C++ server port</td><td><code>50055</code></td></tr>"
            "<tr><td><code>YUZU_GW_AGENT_PORT</code></td>"
            "    <td>Agent-facing listener port</td><td><code>50051</code></td></tr>"
            "<tr><td><code>YUZU_GW_MGMT_PORT</code></td>"
            "    <td>Management listener port</td><td><code>50052</code></td></tr>"
            "<tr><td><code>YUZU_GW_TLS_ENABLED</code></td>"
            "    <td>TLS master switch</td><td><code>auto</code></td></tr>"
            "<tr><td><code>YUZU_GW_TLS_CERTFILE</code></td>"
            "    <td>Gateway certificate path</td><td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_TLS_KEYFILE</code></td>"
            "    <td>Gateway private key path</td><td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_TLS_CACERTFILE</code></td>"
            "    <td>CA certificate bundle</td><td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_PROMETHEUS_PORT</code></td>"
            "    <td>Prometheus metrics port</td><td><code>9568</code></td></tr>"
            "<tr><td><code>YUZU_GW_HEALTH_PORT</code></td>"
            "    <td>Health endpoint port</td><td><code>8080</code></td></tr>"
            "</tbody></table>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_https_fragment() {
    // #4028 — shared builder; GET /api/v1/settings/https formats the SAME
    // JSON as its response body instead of re-deriving these fields.
    const auto v = settings_model::build_https_settings(*cfg_);
    const bool https_enabled = v.at("enabled").get<bool>();

    std::string html;

    std::string status_color = https_enabled ? "#3fb950" : "#484f58";
    std::string status_text = https_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>HTTPS</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            status_color + ";font-weight:600\">" + status_text +
            "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>HTTPS Port</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(v.at("port").get<int>()) +
            "</code>"
            "</div>";

    auto path_or_not_configured = [](const nlohmann::json& j) -> std::string {
        auto s = j.get<std::string>();
        return s.empty() ? "Not configured" : html_escape(s);
    };
    std::string https_cert = path_or_not_configured(v.at("cert_path"));
    std::string https_key = path_or_not_configured(v.at("key_path"));

    html += "<div class=\"form-row\">"
            "  <label>Certificate</label>"
            "  <span class=\"file-name\">" +
            https_cert +
            "</span>"
            "</div>";
    html += "<div class=\"form-row\">"
            "  <label>Private Key</label>"
            "  <span class=\"file-name\">" +
            https_key +
            "</span>"
            "</div>";

    const bool redirect = v.at("redirect").get<bool>();
    std::string redir_color = redirect ? "#3fb950" : "#8b949e";
    std::string redir_text = redirect ? "Enabled" : "Disabled";
    html += "<div class=\"form-row\">"
            "  <label>HTTP Redirect</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            redir_color + "\">" + redir_text +
            "</span>"
            "</div>";

    if (!https_enabled) {
        html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                "Start the server with <code>--https --https-cert &lt;path&gt; --https-key "
                "&lt;path&gt;</code> to enable.</p>";
    }

    return html;
}

std::string SettingsRoutes::render_analytics_fragment() {
    // #4028 — shared builder; GET /api/v1/settings/analytics formats the
    // SAME JSON as its response body instead of re-deriving these fields.
    // SECURITY FIX (#4028 Evidence): the ClickHouse URL is now sanitized of
    // embedded userinfo credentials by the builder before it ever reaches
    // this renderer — previously this fragment rendered cfg_->clickhouse_url
    // verbatim, leaking a credential embedded in the URL even though the
    // separate clickhouse_password field was masked below.
    const auto v = settings_model::build_analytics_settings(*cfg_);

    std::string html;

    std::string status_color = v.at("enabled").get<bool>() ? "#3fb950" : "#484f58";
    std::string status_text = v.at("enabled").get<bool>() ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>Analytics</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            status_color + ";font-weight:600\">" + status_text +
            "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Drain Interval</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(v.at("drain_interval_seconds").get<int>()) +
            "s</code>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Batch Size</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(v.at("batch_size").get<int>()) +
            "</code>"
            "</div>";

    bool ch_configured = v.at("clickhouse_configured").get<bool>();
    std::string ch_color = ch_configured ? "#3fb950" : "#484f58";
    std::string ch_text =
        ch_configured ? html_escape(v.at("clickhouse_url").get<std::string>()) : "Not configured";

    html +=
        "<div style=\"margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
        "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
        "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
        "ClickHouse Integration</div>";
    html += "<div class=\"form-row\">"
            "  <label>URL</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            ch_color + "\">" + ch_text +
            "</span>"
            "</div>";
    if (ch_configured) {
        html += "<div class=\"form-row\">"
                "  <label>Database</label>"
                "  <code style=\"font-size:0.8rem\">" +
                html_escape(v.at("clickhouse_database").get<std::string>()) +
                "</code>"
                "</div>";
        html += "<div class=\"form-row\">"
                "  <label>Table</label>"
                "  <code style=\"font-size:0.8rem\">" +
                html_escape(v.at("clickhouse_table").get<std::string>()) +
                "</code>"
                "</div>";
        std::string username = v.at("clickhouse_username").get<std::string>();
        html += "<div class=\"form-row\">"
                "  <label>Username</label>"
                "  <code style=\"font-size:0.8rem\">" +
                (username.empty() ? std::string("(default)") : html_escape(username)) +
                "</code></div>";
        html += "<div class=\"form-row\">"
                "  <label>Password</label>"
                "  <span style=\"font-size:0.8rem;color:#8b949e\">" +
                (v.at("clickhouse_password_set").get<bool>() ? std::string("********")
                                                              : std::string("(not set)")) +
                "</span></div>";
    }
    html += "</div>";

    std::string jsonl = v.at("jsonl_export_path").get<std::string>();
    std::string jsonl_path = jsonl.empty() ? "Not configured" : html_escape(jsonl);
    html += "<div class=\"form-row\" style=\"margin-top:0.5rem\">"
            "  <label>JSONL Export</label>"
            "  <span class=\"file-name\">" +
            jsonl_path +
            "</span>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_data_retention_fragment() {
    // #4028 — shared builder; GET /api/v1/settings/data-retention formats
    // the SAME JSON as its response body instead of re-deriving these fields.
    const auto v = settings_model::build_data_retention_settings(*cfg_);

    std::string html;

    html += "<div class=\"form-row\">"
            "  <label>Response Data</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(v.at("response_retention_days").get<int>()) +
            " days</code>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Audit Logs</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(v.at("audit_retention_days").get<int>()) +
            " days</code>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_dex_alerts_fragment() {
    // Current state straight from runtime_config (the single source of truth;
    // the live router/detector were fed the same values via the apply fn).
    // Defaults derive from BlastRadiusConfig{} so the form can never drift from
    // the struct defaults the POST clamp + update_alert_shape use (gov N1).
    const BlastRadiusConfig kBlastDefaults{};
    std::unordered_set<std::string> routed;
    std::string min_dev = std::to_string(kBlastDefaults.min_devices);
    std::string win_s = std::to_string(kBlastDefaults.window_seconds);
    std::string cool_s = std::to_string(kBlastDefaults.cooldown_seconds);
    std::string export_key; // F2a PR3: empty = cohort export disabled (the default)
    if (runtime_config_store_ && runtime_config_store_->is_open()) {
        routed = parse_routed_types(runtime_config_store_->get_value("dex_alert_routing"));
        auto v = runtime_config_store_->get_value("dex_blast_min_devices");
        if (!v.empty()) min_dev = v;
        v = runtime_config_store_->get_value("dex_blast_window_seconds");
        if (!v.empty()) win_s = v;
        v = runtime_config_store_->get_value("dex_blast_cooldown_seconds");
        if (!v.empty()) cool_s = v;
        export_key = runtime_config_store_->get_value("dex_cohort_export_key");
    }

    std::string html;

    // ── Blast-radius alert shape ─────────────────────────────────────────────
    html += "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin-bottom:0.4rem\">FLEET BLAST-RADIUS THRESHOLDS</div>";
    html += "<form hx-post=\"/api/settings/dex-alerts/blast\" "
            "hx-target=\"#dex-alerts-section\" hx-swap=\"innerHTML\">";
    auto num_row = [&](const char* label, const char* name, const std::string& value,
                       const char* hint) {
        html += "<div class=\"form-row\"><label>" + std::string(label) +
                "</label><input type=\"number\" name=\"" + name + "\" value=\"" +
                html_escape(value) +
                "\" style=\"width:7rem\"> <span style=\"font-size:0.7rem;color:#8b949e\">" +
                hint + "</span></div>";
    };
    num_row("Min devices", "min_devices", min_dev, "distinct devices that make an incident (>= 2)");
    num_row("Window (s)", "window_seconds", win_s, "sliding window, 60..86400");
    num_row("Cooldown (s)", "cooldown_seconds", cool_s, "per-incident re-alert suppression");
    html += "<button type=\"submit\" class=\"btn btn-secondary\" "
            "style=\"margin-top:0.3rem\">Save thresholds</button></form>";

    // ── Cohort metrics export (F2a PR3 — Grafana) ────────────────────────────
    html += "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin:1rem 0 0.4rem\">COHORT METRICS EXPORT (PROMETHEUS)</div>"
            "<p style=\"font-size:0.72rem;color:#8b949e;margin-bottom:0.5rem\">"
            "When a tag key is set, per-cohort fleet performance gauges "
            "(<code>yuzu_fleet_perf_cohort_*</code>) are exported on /metrics for that key's "
            "cohorts &mdash; top 50 by population, 10-device statistical floor, a "
            "<code>_clipped</code> gauge makes any capping visible. Empty disables the export "
            "(the default). Fleet-level gauges are always exported. <b>The key's tag values "
            "become Prometheus labels</b> visible to whatever scrapes /metrics &mdash; choose "
            "keys whose values are non-sensitive organizational identifiers (hardware model, "
            "image name), never personnel-relevant strings.</p>";
    html += "<form hx-post=\"/api/settings/dex-alerts/cohort-export\" "
            "hx-target=\"#dex-alerts-section\" hx-swap=\"innerHTML\">"
            "<div class=\"form-row\"><label>Export tag key</label>"
            "<input type=\"text\" name=\"export_key\" value=\"" +
            html_escape(export_key) +
            "\" placeholder=\"e.g. model\" style=\"width:12rem\"> "
            "<span style=\"font-size:0.7rem;color:#8b949e\">[A-Za-z0-9_.:-], max 64; empty = "
            "off</span></div>"
            "<button type=\"submit\" class=\"btn btn-secondary\" "
            "style=\"margin-top:0.3rem\">Save export key</button></form>";

    // ── Per-signal routing ───────────────────────────────────────────────────
    html += "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin:1rem 0 0.4rem\">PER-SIGNAL ALERTS</div>"
            "<p style=\"font-size:0.72rem;color:#8b949e;margin-bottom:0.5rem\">"
            "A routed signal raises an operator notification and fires the "
            "<code>dex.signal</code> webhook event, once per device per hour. "
            "Nothing is routed by default — blast-radius incidents always alert.</p>";
    html += "<form hx-post=\"/api/settings/dex-alerts/routing\" "
            "hx-target=\"#dex-alerts-section\" hx-swap=\"innerHTML\">";
    std::unordered_set<std::string> known;
    for (const auto& g : dex_signal_groups()) {
        // Open families that contain a routed type so current state is visible.
        bool any_routed = false;
        for (const char* t : g.types)
            if (routed.count(t)) any_routed = true;
        html += std::string("<details") + (any_routed ? " open" : "") +
                "><summary style=\"cursor:pointer;font-size:0.78rem;padding:0.2rem 0\">" +
                html_escape(g.name) + "</summary><div style=\"padding:0.2rem 0 0.4rem 1rem\">";
        for (const char* t : g.types) {
            known.insert(t);
            const bool checked = routed.count(t) > 0;
            html += std::string("<label style=\"display:block;font-size:0.75rem;"
                                "padding:0.1rem 0\"><input type=\"checkbox\" name=\"types\" "
                                "value=\"") +
                    t + "\"" + (checked ? " checked" : "") + "> " + dex_signal_label(t) +
                    " <code style=\"font-size:0.65rem;color:#8b949e\">" + t + "</code></label>";
        }
        html += "</div></details>";
    }
    // Routed types no longer in the catalogue (config drift / newer-agent
    // types): keep them visible and clearable rather than silently sticky.
    std::string strays;
    for (const auto& t : routed)
        if (!known.count(t))
            strays += "<label style=\"display:block;font-size:0.75rem\"><input "
                      "type=\"checkbox\" name=\"types\" value=\"" +
                      html_escape(t) + "\" checked> <code>" + html_escape(t) + "</code></label>";
    if (!strays.empty())
        html += "<details open><summary style=\"font-size:0.78rem\">Other routed types"
                "</summary><div style=\"padding:0.2rem 0 0.4rem 1rem\">" +
                strays + "</div></details>";
    html += "<button type=\"submit\" class=\"btn btn-secondary\" "
            "style=\"margin-top:0.5rem\">Save routing</button></form>";
    return html;
}

std::string SettingsRoutes::render_mcp_fragment() {
    // #4028 — shared builder; GET /api/v1/settings/mcp formats the SAME
    // JSON as its response body instead of re-deriving these fields.
    const auto v = settings_model::build_mcp_settings(*cfg_);

    std::string html;
    bool mcp_enabled = v.at("enabled").get<bool>();

    std::string status_color = mcp_enabled ? "#3fb950" : "#484f58";
    std::string status_text = mcp_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>Status</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            status_color + ";font-weight:600\">" + status_text +
            "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Endpoint</label>"
            "  <code style=\"font-size:0.8rem\">POST /mcp/v1/</code>"
            "</div>";

    std::string enabled_checked = mcp_enabled ? " checked" : "";
    html += "<form hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\" hx-swap=\"innerHTML\">"
            "<div class=\"form-row\">"
            "  <label>MCP Enabled</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"hidden\" name=\"enabled\" value=\"false\">"
            "    <input type=\"checkbox\" name=\"enabled\" value=\"true\"" +
            enabled_checked +
            " hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\""
            " hx-swap=\"innerHTML\" hx-include=\"closest form\">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "</div>";

    const bool mcp_read_only = v.at("read_only").get<bool>();
    std::string readonly_checked = mcp_read_only ? " checked" : "";
    std::string readonly_color = mcp_read_only ? "#d29922" : "#484f58";
    std::string readonly_text = mcp_read_only ? "Read-Only" : "Full Access";
    html += "<div class=\"form-row\">"
            "  <label>Access Mode</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"hidden\" name=\"read_only\" value=\"false\">"
            "    <input type=\"checkbox\" name=\"read_only\" value=\"true\"" +
            readonly_checked +
            " hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\""
            " hx-swap=\"innerHTML\" hx-include=\"closest form\">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "  <span style=\"font-size:0.75rem;color:" +
            readonly_color + ";margin-left:0.5rem\">" + readonly_text +
            "</span>"
            "</div>";

    html += "</form>";

    html += "<p style=\"font-size:0.7rem;color:#484f58;margin-top:0.75rem\">"
            "MCP authentication uses API Tokens with an MCP tier. "
            "Create tokens in the <strong>API Tokens</strong> section above — "
            "select an MCP tier (readonly, operator, or supervised) from the dropdown."
            "</p>";

    std::string url = v.at("endpoint_url").get<std::string>();

    html += "<div style=\"margin-top:0.75rem;padding:0.75rem;background:#0d1117;"
            "border:1px solid var(--border);border-radius:0.3rem\">"
            "  <div style=\"font-size:0.7rem;color:#8b949e;margin-bottom:0.3rem;"
            "font-weight:600\">MCP CLIENT CONNECTION</div>"
            "  <div style=\"font-size:0.75rem;margin-bottom:0.3rem\">"
            "    Endpoint: <code>" +
            html_escape(url) +
            "</code></div>"
            "  <div style=\"font-size:0.7rem;color:#484f58\">"
            "    Transport: HTTP + JSON-RPC 2.0 &nbsp;|&nbsp; "
            "    Auth: <code>Authorization: Bearer &lt;mcp-token&gt;</code>"
            "  </div>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_nvd_fragment() {
    std::string html;

    std::string status_color = cfg_->nvd_sync_enabled ? "#3fb950" : "#484f58";
    std::string status_text = cfg_->nvd_sync_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>NVD Sync</label>"
            "  <span style=\"font-size:0.8rem;color:" +
            status_color + ";font-weight:600\">" + status_text +
            "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Sync Interval</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(cfg_->nvd_sync_interval.count() / 3600) +
            " hours</code>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>API Key</label>"
            "  <span style=\"font-size:0.8rem;color:#8b949e\">" +
            (cfg_->nvd_api_key.empty() ? std::string("Not configured (lower rate limits)")
                                       : std::string("Configured")) +
            "</span></div>";

    html += "<div class=\"form-row\">"
            "  <label>HTTP Proxy</label>"
            "  <span style=\"font-size:0.8rem\">" +
            (cfg_->nvd_proxy.empty()
                 ? std::string("<span style=\"color:#8b949e\">None</span>")
                 : std::string("<code>") + html_escape(cfg_->nvd_proxy) + "</code>") +
            "</span></div>";

    if (!cfg_->nvd_sync_enabled) {
        html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                "Start the server without <code>--no-nvd-sync</code> (or unset "
                "<code>YUZU_NO_NVD_SYNC</code>) to enable CVE feed synchronization.</p>";
    }

    return html;
}

std::string SettingsRoutes::render_directory_fragment() {
    std::string html;

    bool oidc_configured = !cfg_->oidc_issuer.empty() && !cfg_->oidc_client_id.empty();

    if (oidc_configured) {
        html += "<div style=\"margin-bottom:1rem\">"
                "  <span style=\"font-size:0.75rem;background:#238636;color:#fff;"
                "padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">"
                "Configured</span>"
                "</div>";
    } else {
        html += "<div style=\"margin-bottom:1rem\">"
                "  <span style=\"font-size:0.75rem;background:#9e6a03;color:#fff;"
                "padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">"
                "Not configured</span>"
                "</div>";
    }

    html += "<form hx-post=\"/api/settings/oidc\" "
            "hx-target=\"#directory-section\" hx-swap=\"innerHTML\">";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Issuer URL</label>"
            "  <input type=\"text\" name=\"issuer\" "
            "value=\"" +
            html_escape(cfg_->oidc_issuer) +
            "\" "
            "placeholder=\"https://login.microsoftonline.com/{tenant}/v2.0\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Client ID</label>"
            "  <input type=\"text\" name=\"client_id\" "
            "value=\"" +
            html_escape(cfg_->oidc_client_id) +
            "\" "
            "placeholder=\"Application (client) ID from Azure portal\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Client Secret</label>"
            "  <input type=\"password\" name=\"client_secret\" "
            "value=\"\" "
            "placeholder=\"" +
            (cfg_->oidc_client_secret.empty() ? std::string("Client secret value")
                                              : std::string("********")) +
            "\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Redirect URI</label>"
            "  <input type=\"text\" name=\"redirect_uri\" "
            "value=\"" +
            html_escape(cfg_->oidc_redirect_uri) +
            "\" "
            "placeholder=\"(auto-computed from web address)\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Admin Group ID</label>"
            "  <input type=\"text\" name=\"admin_group\" "
            "value=\"" +
            html_escape(cfg_->oidc_admin_group) +
            "\" "
            "placeholder=\"Entra group object ID for admin role mapping\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    std::string tls_checked = cfg_->oidc_skip_tls_verify ? " checked" : "";
    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Skip TLS Verify</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"checkbox\" name=\"skip_tls_verify\" value=\"true\"" +
            tls_checked +
            ">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "  <span style=\"font-size:0.7rem;color:#f85149;margin-left:0.5rem\">"
            "Insecure — dev only</span>"
            "</div>";

    html += "<div style=\"margin-top:1rem;display:flex;gap:0.75rem;align-items:center\">"
            "  <button class=\"btn btn-primary\" type=\"submit\">Save OIDC Configuration</button>"
            "  <button class=\"btn btn-secondary\" type=\"button\" "
            "hx-post=\"/api/settings/oidc/test\" "
            "hx-target=\"#oidc-feedback\" hx-swap=\"innerHTML\" "
            "hx-include=\"closest form\">Test Connection</button>"
            "</div>";

    html += "</form>";

    html += "<div class=\"feedback\" id=\"oidc-feedback\"></div>";

    return html;
}

// ── Plugin code-signing settings ────────────────────────────────────────────
//
// Storage model (intentionally minimal — see SKILL.md auth-and-authz §10
// for the full design):
//   * The PEM trust bundle lives at <cert-dir>/plugin-trust-bundle.pem.
//   * Presence of that file = "signing enabled". No separate enabled flag
//     so disk + DB cannot drift out of sync — clearing the file disables
//     signing atomically.
//   * The require flag lives in runtime_config under the
//     plugin_signing::kPluginSigningRequiredKey key.
//   * Bundle metadata (cert count, SHA-256) is recomputed from the file
//     each render rather than denormalised — keeps the source of truth
//     single (the file), at cost of a few-ms re-parse per /settings load.

namespace {

using ::yuzu::server::plugin_signing::trust_bundle_path;
using ::yuzu::server::plugin_signing::TrustBundleStats;
using ::yuzu::server::plugin_signing::validate_trust_bundle_pem;

// Read+validate the on-disk bundle (may be missing). Returns nullopt if the
// file is absent. Returns an error string if present but unreadable / parse
// failure (so the UI can surface "bundle on disk is corrupt" rather than
// silently downgrading to "no bundle").
std::optional<std::expected<TrustBundleStats, std::string>> read_on_disk_bundle() {
    std::error_code ec;
    auto path = trust_bundle_path();
    if (!std::filesystem::exists(path, ec)) {
        return std::nullopt;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return std::expected<TrustBundleStats, std::string>(std::unexpect,
                                                            "cannot open " + path.string());
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return validate_trust_bundle_pem(content);
}

} // namespace

std::string SettingsRoutes::render_plugin_signing_fragment() {
    std::string html;

    // #4028 — shared builder (also feeds the hardened
    // GET /api/v2/agent/plugin-policy, plugin-signing's only REST twin —
    // #4144 moved it from /v1/, now deprecated);
    // this renderer reads the view's fields rather than `bundle`/`required`
    // directly, so both surfaces present the identical underlying data.
    auto bundle = read_on_disk_bundle();

    // #4028 fix-round finding UP-3/CH-2 (governance Gate 4/5, re-derived by
    // sre/compliance-officer/enterprise-readiness): `get_value()` collapses
    // a genuine runtime_config_store read failure to "", identically to a
    // healthy "not required" — and this badge/toggle IS the deliverable an
    // operator reads to know the require-signature state (I3: the caller
    // cannot tell degraded from healthy). This flag is a status RECORD
    // only — no server-side check consumes it today (see the corrected
    // runtime_config_store.hpp file header; an earlier round of this fix
    // wrongly cited ProductPackStore::require_signed_packs_ here, which
    // governs YAML product-pack content, a different artifact from
    // compiled plugin binaries — consistency-auditor's Gate 8 catch).
    // Plugin-binary signature verification, where configured, is local to
    // each agent via its own --plugin-require-signature/--plugin-trust-
    // bundle flags. So this is a display-honesty fix, not an
    // enforcement-bypass fix. `get()` lets a degraded read say so instead
    // of silently reporting "false". The REST handler below applies the
    // identical `get()` switch — keep both in sync (sre finding: a
    // REST/dashboard divergence here would be worse than the original
    // bug).
    bool required = false;
    bool required_status_unknown = false;
    if (runtime_config_store_) {
        auto rc = runtime_config_store_->get(plugin_signing::kPluginSigningRequiredKey);
        if (!rc.has_value()) {
            required_status_unknown = true;
        } else {
            required = rc->has_value() && rc->value().value == "true";
        }
    }
    const auto v = settings_model::build_plugin_signing_settings(required, bundle);
    const bool enabled = v.at("enabled").get<bool>();

    // Status badge
    std::string badge_color, badge_text;
    if (required_status_unknown) {
        badge_color = "#da3633"; // red -- distinct from every real state below
        badge_text = "Require-signature status unknown (config store unavailable)";
    } else if (enabled && required) {
        badge_color = "#238636"; // green
        badge_text = "Enforced (required)";
    } else if (enabled) {
        badge_color = "#9e6a03"; // amber
        badge_text = "Trust bundle loaded (transitional)";
    } else {
        badge_color = "#484f58"; // muted
        badge_text = "Disabled";
    }
    html += "<div style=\"margin-bottom:1rem\">"
            "  <span style=\"font-size:0.75rem;background:" +
            badge_color + ";color:#fff;padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">" +
            badge_text + "</span></div>";
    if (required_status_unknown) {
        html += "<div class=\"feedback feedback-error\">Runtime config store is unavailable, "
                "so the Require-signature toggle's saved value could not be read. This flag "
                "is a status record only -- no server-side check consumes it today. Plugin "
                "signature verification, where an agent is configured for it, is local to "
                "that agent (its own <code>--plugin-require-signature</code> / "
                "<code>--plugin-trust-bundle</code> flags) and is unaffected by this outage. "
                "It means this page cannot currently show whether Require is on or off. "
                "Retry shortly.</div>";
    }

    // Current state
    if (enabled) {
        html += "<div class=\"form-row\"><label>Trust anchors</label>"
                "<span style=\"font-size:0.8rem\">" +
                std::to_string(v.at("cert_count").get<int>()) + " certificate(s)</span></div>";
        html += "<div class=\"form-row\"><label>Bundle SHA-256</label>"
                "<code style=\"font-size:0.7rem;word-break:break-all\">" +
                v.at("sha256").get<std::string>() + "</code></div>";
        const auto subjects = v.at("subjects").get<std::vector<std::string>>();
        if (!subjects.empty()) {
            html += "<div class=\"form-row\" style=\"align-items:flex-start\">"
                    "<label>Subjects</label>"
                    "<div style=\"font-size:0.75rem;flex:1;min-width:0\">";
            for (const auto& s : subjects) {
                html += "<div "
                        "style=\"font-family:monospace;color:var(--mds-color-theme-text-secondary);"
                        "overflow-wrap:anywhere\">" +
                        html_escape(s) + "</div>";
            }
            html += "</div></div>";
        }
    } else if (v.at("bundle_unreadable").get<bool>()) {
        html += "<div class=\"feedback feedback-error\">Bundle on disk is unreadable: " +
                html_escape(v.at("bundle_error").get<std::string>()) + "</div>";
    } else {
        html += "<p style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
                "No trust bundle uploaded. Plugin signature verification is off "
                "for every agent connected to this server.</p>";
    }

    // Fleet-suicide warning: Yuzu-shipped plugins are not currently
    // signed. An operator who enables Require=on without first signing
    // the in-tree plugins will reject every Yuzu-shipped plugin
    // fleet-wide on next agent restart. Make the risk explicit before
    // they touch the toggle (governance hardening round 1, ER-1).
    html += "<div class=\"feedback feedback-warning\" "
            "style=\"font-size:0.75rem;background:#664d03;color:#fff;"
            "padding:0.5rem 0.75rem;border-radius:4px;margin-top:0.5rem\">"
            "<strong>Heads up.</strong> Yuzu-shipped plugins do not yet "
            "include CMS signatures. Enabling <em>Require signed plugins</em> "
            "will cause agents to reject every Yuzu-bundled plugin at next "
            "scan. Use the transitional mode (bundle uploaded, Require off) "
            "until you have signed every plugin your fleet uses, including "
            "the ones shipped under <code>agents/plugins/</code>."
            "</div>";

    // Upload form (multipart so curl/UI both work)
    html += "<hr style=\"border:none;border-top:1px solid var(--mds-color-theme-border-secondary);"
            "margin:1rem 0\">";
    html += "<form hx-post=\"/api/settings/plugin-signing/upload\" "
            "hx-target=\"#plugin-signing-section\" hx-swap=\"innerHTML\" "
            "hx-encoding=\"multipart/form-data\">";
    html += "<div class=\"form-row\" style=\"align-items:center\">"
            "<label style=\"min-width:140px\">PEM trust bundle</label>"
            "<input type=\"file\" name=\"file\" accept=\".pem,.crt,application/x-pem-file\" "
            "required style=\"flex:1;min-width:0\"></div>";
    html += "<div class=\"form-row\"><label></label>"
            "<button type=\"submit\" class=\"btn btn-primary\">"
            "Upload &amp; verify</button></div>";
    html += "</form>";

    // Toggle: require signature (only meaningful when bundle is loaded).
    // #4028 fix-round finding (consistency-auditor/unhappy-path, Gate 8):
    // also gated on !required_status_unknown -- otherwise this form
    // renders with the checkbox defaulted UNCHECKED (since `required`
    // stays false when its true value could not be read) while the
    // banner above says the value is unknown, and submitting Save writes
    // "false" unconditionally, silently discarding whatever the real
    // prior value was the moment the store recovers. Suppress the whole
    // form (and the Clear button below it) until a real read succeeds --
    // forcing a retry is strictly safer than presenting a write control
    // whose displayed state the page itself just declared untrustworthy.
    if (enabled && !required_status_unknown) {
        html += "<form hx-post=\"/api/settings/plugin-signing/require\" "
                "hx-target=\"#plugin-signing-section\" hx-swap=\"innerHTML\" "
                "style=\"margin-top:0.75rem\">";
        html += "<div class=\"form-row\">"
                "<label style=\"min-width:140px\">Require signed plugins</label>"
                "<label style=\"display:flex;align-items:center;gap:0.5rem;flex:1\">"
                "<input type=\"checkbox\" name=\"required\" value=\"true\"" +
                std::string(required ? " checked" : "") +
                "><span style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
                "Reject unsigned plugins instead of allowing them through (transitional vs "
                "enforced).</span>"
                "</label></div>";
        html += "<div class=\"form-row\"><label></label>"
                "<button type=\"submit\" class=\"btn btn-secondary\">Save</button></div>";
        html += "</form>";

        // Clear button — separate form so it can have a confirm.
        // Confirm copy is deliberate about what is and isn't possible
        // today: there is no automatic agent-side bundle refresh, so a
        // running agent that already loaded plugins continues to use
        // its in-process verification state. The bundle on the server
        // is removed; new agent starts (or future auto-refresh) will
        // see no bundle. Operators rotating away from a compromised CA
        // need to also restart agents (governance hardening round 1,
        // UP-5).
        html += "<form hx-post=\"/api/settings/plugin-signing/clear\" "
                "hx-target=\"#plugin-signing-section\" hx-swap=\"innerHTML\" "
                "hx-confirm=\"Remove the plugin trust bundle and reset the require flag? "
                "This stops new agent starts from verifying signatures, but already-running "
                "agents keep their in-process state until they restart. "
                "If you are rotating away from a compromised CA, restart your agents.\" "
                "style=\"margin-top:0.75rem\">";
        html += "<div class=\"form-row\"><label></label>"
                "<button type=\"submit\" class=\"btn btn-danger\">Remove trust bundle</button>"
                "</div></form>";
    }

    // Operator help
    html += "<hr style=\"border:none;border-top:1px solid var(--mds-color-theme-border-secondary);"
            "margin:1rem 0\">";
    html += "<p style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary);"
            "margin-bottom:0.4rem\"><strong>Agent distribution.</strong> The bundle "
            "is served at <code>GET /api/v2/agent/plugin-policy</code> "
            "(<em>admin-only</em> — operators distribute to agents via the "
            "standard config-management flow; the deprecated "
            "<code>/v1/</code> shape still works during its announced "
            "removal window). Agents are pointed at a local "
            "file via <code>--plugin-trust-bundle</code>; automatic agent-side "
            "fetch is a forthcoming change, at which point this endpoint will "
            "gain a dedicated agent identity.</p>";
    html += "<p style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
            "<strong>Signing recipe:</strong> "
            "<code>openssl cms -sign -binary -nodetach=false -signer signer.pem "
            "-inkey signer.key -in plugin.so -outform pem -out plugin.so.sig</code>. "
            "See <a href=\"/docs#plugin-code-signing\">user manual</a> for the full workflow.</p>";

    return html;
}

// ── Route registration ──────────────────────────────────────────────────────

// Production overload — wraps httplib::Server in an HttplibRouteSink and
// delegates to the sink-based implementation below. Tests bypass this and
// call the sink overload directly with their own TestRouteSink (#438).
void SettingsRoutes::register_routes(
    httplib::Server& svr, AuthFn auth_fn, AdminFn admin_fn, PermFn perm_fn, AuditFn audit_fn,
    Config& cfg, auth::AuthManager& auth_mgr, auth::AutoApproveEngine& auto_approve,
    ApiTokenStore* api_token_store, ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
    UpdateRegistry* update_registry, RuntimeConfigStore* runtime_config_store,
    AuditStore* audit_store, bool gateway_enabled, GatewaySessionCountFn gateway_session_count_fn,
    AgentsJsonFn agents_json_fn, std::shared_mutex& oidc_mu,
    std::unique_ptr<oidc::OidcProvider>& oidc_provider, yuzu::MetricsRegistry* metrics_registry,
    StepUpFn step_up_fn, AuditReadFn audit_read_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(admin_fn), std::move(perm_fn),
                    std::move(audit_fn), cfg, auth_mgr, auto_approve, api_token_store,
                    mgmt_group_store, tag_store, update_registry, runtime_config_store, audit_store,
                    gateway_enabled, std::move(gateway_session_count_fn), std::move(agents_json_fn),
                    oidc_mu, oidc_provider, metrics_registry, std::move(step_up_fn),
                    std::move(audit_read_fn));
}

void SettingsRoutes::register_routes(
    HttpRouteSink& sink, AuthFn auth_fn, AdminFn admin_fn, PermFn perm_fn, AuditFn audit_fn,
    Config& cfg, auth::AuthManager& auth_mgr, auth::AutoApproveEngine& auto_approve,
    ApiTokenStore* api_token_store, ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
    UpdateRegistry* update_registry, RuntimeConfigStore* runtime_config_store,
    AuditStore* audit_store, bool gateway_enabled, GatewaySessionCountFn gateway_session_count_fn,
    AgentsJsonFn agents_json_fn, std::shared_mutex& oidc_mu,
    std::unique_ptr<oidc::OidcProvider>& oidc_provider, yuzu::MetricsRegistry* metrics_registry,
    StepUpFn step_up_fn, AuditReadFn audit_read_fn) {
    // Store dependency pointers
    auth_fn_ = std::move(auth_fn);
    admin_fn_ = std::move(admin_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    audit_read_fn_ = std::move(audit_read_fn);
    cfg_ = &cfg;
    auth_mgr_ = &auth_mgr;
    auto_approve_ = &auto_approve;
    api_token_store_ = api_token_store;
    mgmt_group_store_ = mgmt_group_store;
    tag_store_ = tag_store;
    update_registry_ = update_registry;
    runtime_config_store_ = runtime_config_store;
    audit_store_ = audit_store;
    gateway_enabled_ = gateway_enabled;
    gateway_session_count_fn_ = std::move(gateway_session_count_fn);
    agents_json_fn_ = std::move(agents_json_fn);
    oidc_mu_ = &oidc_mu;
    oidc_provider_ = &oidc_provider;
    metrics_registry_ = metrics_registry;
    step_up_fn_ = std::move(step_up_fn);

    // -- Settings page (admin only) -------------------------------------------
    sink.Get("/settings", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_content(kSettingsHtml, "text/html; charset=utf-8");
    });

    // -- Settings HTMX fragment endpoints -------------------------------------
    //
    // NOTE: the Settings → Internal CA panel — `GET /fragments/settings/ca` and
    // `POST /api/settings/ca/revoke` — is NOT here; it lives in `ca_routes.cpp`
    // (PKI PR4b), which already owns the CaStore + CRL-publish callback. Look
    // there for those two `/...settings/ca...` handlers.

    sink.Get("/fragments/settings/tls",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. TlsConfig:Read (Administrator-only via the
    // rbac_store.cpp seed, floored in authz_topology_floor.hpp so an
    // RBAC-off deployment stays admin-gated). Audited fail-closed (§4):
    // TLS/mTLS posture + cert paths are named recon value in #4028's
    // Evidence section (same reasoning the plugin-signing route below
    // already carries in its own comment).
    sink.Get("/api/v1/settings/tls", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "TlsConfig", "Read"))
            return;
        if (!detail::emit_behavioral_audit(audit_read_fn_, req, res, "settings.tls.read",
                                           "success", "TlsConfig", "tls", "REST settings read")) {
            res.status = 503;
            res.set_content(detail::a4_error(res,
                                             "audit subsystem unavailable; refusing to "
                                             "serve settings data without durable evidence",
                                             detail::A4ErrorOpts{
                                                 .retry_after_ms = 5000,
                                                 .remediation = "retry after the audit subsystem "
                                                                "recovers"}),
                            "application/json");
            return;
        }
        res.set_content(settings_ok_envelope(settings_model::build_tls_settings(*cfg_)).dump(),
                        "application/json");
    });

    sink.Get(
        "/fragments/settings/users", [this](const httplib::Request& req, httplib::Response& res) {
            if (!admin_fn_(req, res))
                return;
            auto session = auth_fn_(req, res);
            if (!session) {
                // Match the DELETE handler's defensive branch: if
                // admin_fn_ passes but auth_fn_ returns nullopt the
                // two callbacks have disagreed (concurrent logout,
                // stale cookie, OIDC session expiry between calls).
                // Refuse to render with empty self_name — that path
                // would emit Remove buttons on every row including
                // the operator's own, resurrecting #403 inside the
                // dashboard fragment.
                res.status = 401;
                return;
            }
            if (session->username.empty()) {
                // Defense-in-depth against an upstream auth bug
                // (e.g. OIDC mis-config returning empty
                // preferred_username). Empty session->username would
                // make the is_self comparison in render_users_fragment
                // never match any row, and would also let a hand-
                // crafted DELETE against an empty-username row
                // succeed via "" == "" — see governance Gate 4 UP-1.
                spdlog::error("/fragments/settings/users: session has empty username; "
                              "refusing to render (likely upstream auth misconfiguration)");
                res.status = 500;
                return;
            }
            res.set_content(render_users_fragment(session->username), "text/html; charset=utf-8");
        });

    sink.Get("/fragments/settings/tokens",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/pending",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/auto-approve",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/api-tokens", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        if (!perm_fn_(req, res, "ApiToken", "Read"))
            return;
        auto session = auth_fn_(req, res);
        if (!session)
            return;
        // Non-admins see only their own tokens (Gate 4 finding C1).
        std::string filter = auth::effective_role(*session) == auth::Role::admin
                                 ? std::string{}
                                 : session->username; // JIT elevation → admin view
        res.set_content(render_api_tokens_fragment({}, filter), "text/html; charset=utf-8");
    });

    // Engine Principals admin console (design doc §3.1, plan PR 4.3). Read-
    // only render — every mutation (create/rotate/revoke/transfer-owner)
    // posts directly to the REST surface at /api/v1/engine-principals/...
    // (built alongside this task); this fragment refreshes on the
    // `refreshEnginePrincipals` body event that REST mutation's `HX-Trigger`
    // response header fires, mirroring the API-tokens block's refresh
    // pattern. Admin-only, same posture as /fragments/settings/tokens.
    sink.Get("/fragments/settings/engine-principals",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_engine_principals_fragment(), "text/html; charset=utf-8");
             });

    // Periodic Access Reviews (SOC 2 CC6.2) — Settings convenience surface.
    // Gated on AccessReview:Read (matches the REST export/get routes); the
    // fragment renderer itself probes AccessReview:Attest to decide whether
    // to show the write controls (open/attest/flag/close) — see
    // render_access_review_fragment()'s doc comment. The REST endpoints
    // under /api/v1/access-reviews* (rest_api_v1.cpp) and their MCP twins
    // are the ADR-1005 API-parity surface this fragment is a convenience
    // layer over, not a replacement for.
    sink.Get("/fragments/settings/access-reviews",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "AccessReview", "Read"))
                     return;
                 res.set_content(render_access_review_fragment(req), "text/html; charset=utf-8");
             });

    // Campaign-view sub-fragment — used both for the `?campaign_id=` deep
    // link (e.g. an auditor following an access_review.campaign_opened
    // audit-log row to its target_id) and for the JS-driven refresh after
    // an attest/flag/close action (arLoadCampaign in kAccessReviewScript).
    sink.Get("/fragments/settings/access-reviews/campaign",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "AccessReview", "Read"))
                     return;
                 std::string id = req.has_param("id") ? req.get_param_value("id") : "";
                 res.set_content(render_access_review_campaign_fragment(req, id),
                                 "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/management-groups",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "ManagementGroup", "Read"))
                     return;
                 res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/tag-compliance",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Tag", "Read"))
                     return;
                 res.set_content(render_tag_compliance_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/updates",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/gateway",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_gateway_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. ServerConfig:Read (Administrator-only,
    // floored in authz_topology_floor.hpp). NOT audited — "nothing secret"
    // per #4028's Evidence section (operational/infra config), matching this
    // fragment's own unaudited posture today.
    sink.Get("/api/v1/settings/gateway",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "ServerConfig", "Read"))
                     return;
                 auto count = gateway_session_count_fn_ ? gateway_session_count_fn_() : 0;
                 res.set_content(settings_ok_envelope(settings_model::build_gateway_settings(
                                                          *cfg_, gateway_enabled_, count))
                                     .dump(),
                                 "application/json");
             });

    sink.Get("/fragments/settings/server-config",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_server_config_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. ServerConfig:Read. NOT audited — "nothing
    // secret" per #4028's Evidence section.
    sink.Get("/api/v1/settings/server-config",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "ServerConfig", "Read"))
                     return;
                 res.set_content(
                     settings_ok_envelope(settings_model::build_server_config_settings(*cfg_)).dump(),
                     "application/json");
             });

    sink.Get("/fragments/settings/https",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_https_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. TlsConfig:Read (grouped with tls — same
    // sub-area, #4028 acceptance criteria). Audited fail-closed (§4) — same
    // recon-value reasoning as GET /api/v1/settings/tls.
    sink.Get("/api/v1/settings/https", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "TlsConfig", "Read"))
            return;
        if (!detail::emit_behavioral_audit(audit_read_fn_, req, res, "settings.https.read",
                                           "success", "TlsConfig", "https", "REST settings read")) {
            res.status = 503;
            res.set_content(detail::a4_error(res,
                                             "audit subsystem unavailable; refusing to "
                                             "serve settings data without durable evidence",
                                             detail::A4ErrorOpts{
                                                 .retry_after_ms = 5000,
                                                 .remediation = "retry after the audit subsystem "
                                                                "recovers"}),
                            "application/json");
            return;
        }
        res.set_content(settings_ok_envelope(settings_model::build_https_settings(*cfg_)).dump(),
                        "application/json");
    });

    sink.Get("/fragments/settings/analytics",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_analytics_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. AnalyticsConfig:Read. Audited fail-closed
    // (§4) — "mixed, leans high (embedded credential risk)" per #4028's
    // Evidence section. The ClickHouse URL is sanitized of userinfo by the
    // shared builder before it reaches this response (see
    // settings_model::sanitize_url_userinfo); the raw password is never
    // read into the payload at all.
    sink.Get("/api/v1/settings/analytics",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "AnalyticsConfig", "Read"))
                     return;
                 if (!detail::emit_behavioral_audit(audit_read_fn_, req, res,
                                                    "settings.analytics.read", "success",
                                                    "AnalyticsConfig", "analytics",
                                                    "REST settings read")) {
                     res.status = 503;
                     res.set_content(
                         detail::a4_error(res,
                                          "audit subsystem unavailable; refusing to serve "
                                          "settings data without durable evidence",
                                          detail::A4ErrorOpts{
                                              .retry_after_ms = 5000,
                                              .remediation = "retry after the audit subsystem "
                                                             "recovers"}),
                         "application/json");
                     return;
                 }
                 res.set_content(
                     settings_ok_envelope(settings_model::build_analytics_settings(*cfg_)).dump(),
                     "application/json");
             });

    sink.Get("/fragments/settings/data-retention",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_data_retention_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. ServerConfig:Read. NOT audited — "lowest
    // sensitivity of the eight" per #4028's Evidence section.
    sink.Get("/api/v1/settings/data-retention",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "ServerConfig", "Read"))
                     return;
                 res.set_content(settings_ok_envelope(
                                     settings_model::build_data_retention_settings(*cfg_))
                                     .dump(),
                                 "application/json");
             });

    sink.Get("/fragments/settings/mcp",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_mcp_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — REST v1 read-twin. ServerConfig:Read. NOT audited — "low
    // sensitivity... an MCP client with a valid token already knows this
    // endpoint exists" per #4028's Evidence section. #520 (see this PR's
    // commit message / docs/mcp-server.md): this route stays REST-only —
    // NOT itself a candidate MCP tool, since #520 explicitly bars MCP
    // tokens from server administration surfaces including "settings".
    sink.Get("/api/v1/settings/mcp", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "ServerConfig", "Read"))
            return;
        res.set_content(settings_ok_envelope(settings_model::build_mcp_settings(*cfg_)).dump(),
                        "application/json");
    });

    // -- F1: DEX alerting (per-signal routing + blast-radius thresholds) ------
    sink.Get("/fragments/settings/dex-alerts",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_dex_alerts_fragment(), "text/html; charset=utf-8");
             });

    sink.Post("/api/settings/dex-alerts/routing", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        if (!runtime_config_store_ || !runtime_config_store_->is_open()) {
            res.status = 503;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Config store unavailable","level":"error"}})");
            // A4 body alongside the dashboard's own HX-Trigger toast (NOT
            // redundant/dead — do not strip): the dashboard's global htmx
            // config sets responseHandling swap:false for every 4xx/5xx
            // response (see dex_routes.cpp/guardian_routes.cpp), so htmx
            // never renders this body — but a non-htmx caller (REST client,
            // agentic worker) hitting this same /api/settings/* endpoint
            // gets a real A4 envelope instead of an empty body.
            res.set_content(detail::a4_error(res, "Config store unavailable"),
                            "application/json");
            return;
        }
        // Collect every checked "types" value from the urlencoded body and
        // allowlist it against the catalogue — a hand-crafted POST cannot
        // inject arbitrary strings into the stored routing set. (Types absent
        // from the catalogue but ALREADY routed stay re-saveable so the
        // "Other routed types" rows remain clearable; brand-new unknown
        // strings are dropped.)
        std::unordered_set<std::string> catalogue;
        for (const auto& g : dex_signal_groups())
            for (const char* t : g.types)
                catalogue.insert(t);
        const auto previously =
            parse_routed_types(runtime_config_store_->get_value("dex_alert_routing"));
        std::unordered_set<std::string> selected;
        std::size_t pos = 0;
        while (pos < req.body.size() && selected.size() < 512) {
            const auto amp = req.body.find('&', pos);
            const auto pair = req.body.substr(
                pos, (amp == std::string::npos ? req.body.size() : amp) - pos);
            pos = (amp == std::string::npos) ? req.body.size() : amp + 1;
            if (!pair.starts_with("types="))
                continue;
            std::string v = pair.substr(6);
            // obs_types are [a-z_.] — percent-decode just %2E defensively and
            // reject anything else encoded (no legitimate type needs it).
            std::string decoded;
            decoded.reserve(v.size());
            bool bad = false;
            for (std::size_t i = 0; i < v.size(); ++i) {
                const char c = v[i];
                if (c == '%') {
                    if (v.compare(i, 3, "%2E") == 0 || v.compare(i, 3, "%2e") == 0) {
                        decoded += '.';
                        i += 2;
                    } else {
                        bad = true;
                        break;
                    }
                } else if (c == '+') {
                    bad = true; // no spaces in obs_types
                    break;
                } else {
                    decoded += c;
                }
            }
            if (bad || decoded.empty() || decoded.size() > 128)
                continue;
            if (catalogue.count(decoded) || previously.count(decoded))
                selected.insert(std::move(decoded));
        }
        auto session = auth_fn_(req, res);
        const auto json = routed_types_to_json(selected);
        auto rc = runtime_config_store_->set("dex_alert_routing", json,
                                             session ? session->username : "unknown");
        if (!rc) {
            res.status = 500;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Failed to save routing","level":"error"}})");
            // A4 body alongside the toast (swap:false discards it on the
            // dashboard, but a non-htmx caller now gets a real envelope).
            res.set_content(detail::a4_error(res, rc.error()), "application/json");
            return;
        }
        if (dex_alert_apply_fn_)
            dex_alert_apply_fn_(); // live — no restart
        // Record the FULL routed set, not just a count: runtime_config is a
        // key→value store with no history, so this audit row is the sole
        // change-management evidence of WHICH types were routed (gov compliance).
        audit_fn_(req, "settings.dex_alerts.routing", "success", "RuntimeConfig",
                  "dex_alert_routing", "routed=" + json);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"DEX alert routing saved","level":"success"}})");
        res.set_content(render_dex_alerts_fragment(), "text/html; charset=utf-8");
    });

    sink.Post("/api/settings/dex-alerts/blast", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        if (!runtime_config_store_ || !runtime_config_store_->is_open()) {
            res.status = 503;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Config store unavailable","level":"error"}})");
            res.set_content(detail::a4_error(res, "Config store unavailable"),
                            "application/json");
            return;
        }
        // Clamp server-side to the same ranges update_alert_shape enforces, so
        // the STORED values always match the LIVE values (no silent divergence
        // between what the UI shows and what the detector runs).
        auto clamp_int = [&](const char* field, int lo, int hi, int fallback) {
            try {
                const auto v = extract_form_value(req.body, field);
                if (!v.empty())
                    return std::clamp(std::stoi(v), lo, hi);
            } catch (...) {}
            return fallback;
        };
        const BlastRadiusConfig d{};
        const int min_dev = clamp_int("min_devices", 2, 100000, d.min_devices);
        const int win_s = clamp_int("window_seconds", 60, 86400, d.window_seconds);
        const int cool_s = clamp_int("cooldown_seconds", 0, 7 * 86400, d.cooldown_seconds);
        auto session = auth_fn_(req, res);
        const std::string by = session ? session->username : "unknown";
        bool ok = true;
        ok &= runtime_config_store_->set("dex_blast_min_devices", std::to_string(min_dev), by)
                  .has_value();
        ok &= runtime_config_store_->set("dex_blast_window_seconds", std::to_string(win_s), by)
                  .has_value();
        ok &= runtime_config_store_->set("dex_blast_cooldown_seconds", std::to_string(cool_s), by)
                  .has_value();
        if (!ok) {
            res.status = 500;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Failed to save thresholds","level":"error"}})");
            res.set_content(detail::a4_error(res, "Failed to save thresholds"),
                            "application/json");
            return;
        }
        if (dex_alert_apply_fn_)
            dex_alert_apply_fn_(); // live — no restart
        audit_fn_(req, "settings.dex_alerts.blast", "success", "RuntimeConfig",
                  "dex_blast_thresholds",
                  "min_devices=" + std::to_string(min_dev) + ", window=" + std::to_string(win_s) +
                      "s, cooldown=" + std::to_string(cool_s) + "s");
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Blast-radius thresholds saved","level":"success"}})");
        res.set_content(render_dex_alerts_fragment(), "text/html; charset=utf-8");
    });

    // -- F2a PR3: cohort metrics export key (Grafana) --------------------------
    sink.Post("/api/settings/dex-alerts/cohort-export", [this](const httplib::Request& req,
                                                               httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        if (!runtime_config_store_ || !runtime_config_store_->is_open()) {
            res.status = 503;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Config store unavailable","level":"error"}})");
            res.set_content(detail::a4_error(res, "Config store unavailable"),
                            "application/json");
            return;
        }
        // extract_form_value already percent-decodes (':' → %3A is in the
        // tag-key alphabet) — do NOT decode twice (G2 sec-L1: a double decode
        // diverges from the sibling POSTs; validate_key runs after and fails
        // closed either way). Empty disables the export — a valid, auditable
        // choice.
        const std::string key = extract_form_value(req.body, "export_key");
        if (!key.empty() && !TagStore::validate_key(key)) {
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"j({"showToast":{"message":"Invalid tag key ([A-Za-z0-9_.:-], max 64)","level":"error"}})j");
            res.set_content(
                detail::a4_error(res, "Invalid tag key ([A-Za-z0-9_.:-], max 64)"),
                "application/json");
            return;
        }
        auto session = auth_fn_(req, res);
        auto rc = runtime_config_store_->set("dex_cohort_export_key", key,
                                             session ? session->username : "unknown");
        if (!rc) {
            res.status = 500;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Failed to save export key","level":"error"}})");
            res.set_content(detail::a4_error(res, rc.error()), "application/json");
            return;
        }
        if (dex_alert_apply_fn_)
            dex_alert_apply_fn_(); // live — next gauge sweep uses the new key
        audit_fn_(req, "settings.dex_alerts.cohort_export", "success", "RuntimeConfig",
                  "dex_cohort_export_key",
                  key.empty() ? "export disabled" : "export_key=" + key);
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Cohort export key saved","level":"success"}})");
        res.set_content(render_dex_alerts_fragment(), "text/html; charset=utf-8");
    });

    sink.Get("/fragments/settings/plugin-signing",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_plugin_signing_fragment(), "text/html; charset=utf-8");
             });

    // #4028 — no parallel `/api/v1/settings/plugin-signing` route: the
    // acceptance criteria is explicit that plugin-signing's REST twin is the
    // hardened `GET /api/v2/agent/plugin-policy` below (already existed
    // off-ledger at /v1/; #4144 moved the hardening there — see that
    // handler's own comment), not a second route duplicating its data.

    // -- Plugin Code Signing: upload PEM trust bundle (admin) -----------------
    sink.Post("/api/settings/plugin-signing/upload", [this](const httplib::Request& req,
                                                            httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        std::string content;
        if (SETTINGS_REQ_HAS_FILE(req, "file")) {
            content = SETTINGS_REQ_GET_FILE(req, "file").content;
        }
        if (content.empty()) {
            res.status = 400;
            res.set_header("HX-Retarget", "#plugin-signing-section");
            res.set_content("<span class=\"feedback-error\">Upload a PEM file.</span>",
                            "text/html; charset=utf-8");
            return;
        }
        if (content.size() > 256 * 1024) {
            res.status = 400;
            res.set_header("HX-Retarget", "#plugin-signing-section");
            res.set_content(
                "<span class=\"feedback-error\">PEM bundle too large (max 256 KB).</span>",
                "text/html; charset=utf-8");
            return;
        }

        auto stats = validate_trust_bundle_pem(content);
        if (!stats) {
            res.status = 400;
            res.set_header("HX-Retarget", "#plugin-signing-section");
            res.set_content("<span class=\"feedback-error\">Rejected: " +
                                html_escape(stats.error()) + "</span>",
                            "text/html; charset=utf-8");
            // result="failure" — PEM validation rejected the operator's input.
            // Vocabulary: success/failure/denied per audit_store.hpp:28.
            // ("rejected" was a novel token that silently undercounts
            // the Prometheus events_other_ bucket — fixed in
            // governance hardening round 1, arch-B1 / CONS-B2 / CC7.2.)
            audit_fn_(req, "plugin_signing.bundle.uploaded", "failure", "PluginTrustBundle",
                      "trust-bundle", stats.error());
            return;
        }

        auto cert_dir = auth::default_cert_dir();
        std::error_code ec;
        std::filesystem::create_directories(cert_dir, ec);
        if (ec) {
            res.status = 500;
            res.set_header("HX-Retarget", "#plugin-signing-section");
            res.set_content("<span class=\"feedback-error\">Cannot create cert directory.</span>",
                            "text/html; charset=utf-8");
            return;
        }
        // Atomic write: stage in a sibling temp file, then rename
        // over the destination. Same-directory rename is
        // POSIX-atomic and Windows-replace-atomic via MoveFileExW.
        // Prevents the torn-read window where a concurrent
        // /api/v1/agent/plugin-policy fetch reads a 0-byte or
        // partial PEM mid-write (sec-MED-1 / UP-1 / UP-2 / UP-16
        // / hp-S1).
        auto out_path = trust_bundle_path();
        auto tmp_path = out_path;
        tmp_path += ".tmp";
        {
            std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                res.status = 500;
                res.set_header("HX-Retarget", "#plugin-signing-section");
                res.set_content(
                    "<span class=\"feedback-error\">Cannot write trust bundle file.</span>",
                    "text/html; charset=utf-8");
                return;
            }
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
            f.flush();
            // Surface short-write / disk-full / EIO before we
            // attempt the atomic rename. Without this, a partial
            // tmp file would be renamed into place and the
            // operator would see "uploaded" while agents see
            // a corrupt bundle (hp-S1 / UP-16).
            if (!f.good()) {
                std::error_code rmec;
                std::filesystem::remove(tmp_path, rmec);
                res.status = 500;
                res.set_header("HX-Retarget", "#plugin-signing-section");
                res.set_content(
                    "<span class=\"feedback-error\">Trust bundle write failed (disk full?).</span>",
                    "text/html; charset=utf-8");
                return;
            }
        }
        std::error_code rnec;
        std::filesystem::rename(tmp_path, out_path, rnec);
        if (rnec) {
            std::error_code rmec;
            std::filesystem::remove(tmp_path, rmec);
            res.status = 500;
            res.set_header("HX-Retarget", "#plugin-signing-section");
            res.set_content(
                "<span class=\"feedback-error\">Atomic rename of trust bundle failed: " +
                    html_escape(rnec.message()) + "</span>",
                "text/html; charset=utf-8");
            return;
        }
        // Trust bundles are public-readable (only contains
        // X.509 certs, no private keys).

        spdlog::info("Plugin trust bundle uploaded: {} ({} certs, sha256 {})", out_path.string(),
                     stats->cert_count, stats->sha256_hex);
        audit_fn_(req, "plugin_signing.bundle.uploaded", "success", "PluginTrustBundle",
                  "trust-bundle",
                  std::to_string(stats->cert_count) + " cert(s), sha256=" + stats->sha256_hex);

        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Trust bundle uploaded","level":"success"}})");
        res.set_content(render_plugin_signing_fragment(), "text/html; charset=utf-8");
    });

    // -- Plugin Code Signing: clear trust bundle (admin) ----------------------
    sink.Post("/api/settings/plugin-signing/clear", [this](const httplib::Request& req,
                                                           httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        // Two-phase commit: clear the DB flag FIRST, then remove
        // the file. If the flag write fails we surface a 500 and
        // never touch the file — agents continue to verify
        // against the existing bundle and the operator sees an
        // explicit error rather than a silent "file gone but
        // require still on" state (UP-4).
        if (runtime_config_store_) {
            auto rc = runtime_config_store_->set(plugin_signing::kPluginSigningRequiredKey, "false",
                                                 "system");
            if (!rc) {
                res.status = 500;
                res.set_header("HX-Retarget", "#plugin-signing-section");
                res.set_content("<span class=\"feedback-error\">Cannot clear "
                                "require flag: " +
                                    html_escape(rc.error()) +
                                    ". Trust bundle was not removed.</span>",
                                "text/html; charset=utf-8");
                audit_fn_(req, "plugin_signing.bundle.cleared", "failure", "PluginTrustBundle",
                          "trust-bundle", "require-flag write failed: " + rc.error());
                return;
            }
        }
        auto path = trust_bundle_path();
        std::error_code ec;
        bool removed = std::filesystem::remove(path, ec);

        spdlog::info("Plugin trust bundle cleared (file {}, require flag reset)",
                     removed ? "removed" : "absent");
        audit_fn_(req, "plugin_signing.bundle.cleared", "success", "PluginTrustBundle",
                  "trust-bundle", removed ? "file removed" : "no file present");

        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Trust bundle cleared","level":"info"}})");
        res.set_content(render_plugin_signing_fragment(), "text/html; charset=utf-8");
    });

    // -- Plugin Code Signing: toggle require flag (admin) ---------------------
    sink.Post("/api/settings/plugin-signing/require", [this](const httplib::Request& req,
                                                             httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        // HTML checkbox semantics: present-and-"true" = required;
        // absent = not required. Reuse the form parser the rest
        // of settings uses.
        const std::string val = extract_form_value(req.body, "required");
        const std::string new_val = (val == "true" || val == "on") ? "true" : "false";
        if (runtime_config_store_) {
            auto rc = runtime_config_store_->set(plugin_signing::kPluginSigningRequiredKey, new_val,
                                                 "ui");
            if (!rc) {
                res.status = 500;
                res.set_header("HX-Retarget", "#plugin-signing-section");
                res.set_content("<span class=\"feedback-error\">" + html_escape(rc.error()) +
                                    "</span>",
                                "text/html; charset=utf-8");
                return;
            }
        }
        audit_fn_(req, "plugin_signing.require.changed", "success", "RuntimeConfig",
                  plugin_signing::kPluginSigningRequiredKey, new_val);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Require flag updated","level":"success"}})");
        res.set_content(render_plugin_signing_fragment(), "text/html; charset=utf-8");
    });

    // -- Plugin Code Signing: distribution endpoint (v1, FROZEN) -------------
    //
    // #4144 review fix (external colleague review, BLOCKING, confirmed
    // against docs/api-versioning-policy.md by direct fetch): this route
    // predates #4028 (present since the F2 OpenAPI backfill), and #4028's
    // hardening reshaped its response envelope (flat body -> data/meta) and
    // added new fields/error codes IN PLACE at this same /api/v1/ path — a
    // breaking change per the policy's own "changing an error envelope's
    // shape" clause, shipped with no version bump, no deprecation cycle, and
    // no ADR-1005 exception-ledger entry. The policy's narrow
    // security-tightening carve-out doesn't apply here (it requires a
    // CHANGELOG Security entry citing a tracked vulnerability; this PR's own
    // changelog carries a SEPARATE .security.md fragment for its actual
    // security fix — the ClickHouse sanitizer — proving the classification
    // was deliberate, not an oversight).
    //
    // Fix: this handler is now FROZEN at exactly its pre-#4028 shape (see
    // git show <pre-#4028 SHA>:server/core/src/settings_routes.cpp for the
    // byte-for-byte source) — flat body, admin_fn_ gate, no audit call, the
    // old ad hoc error envelope. All of #4028's hardening (RBAC securable,
    // audit-fail-closed, A4 envelope, new fields, the TOCTOU fix) lives
    // ONLY at GET /api/v2/agent/plugin-policy below. Per
    // docs/api-versioning-policy.md's deprecation cycle: this v1 route is
    // formally deprecated (see changelog.d/4144-plugin-policy-v1-deprecated
    // .deprecated.md + docs/user-manual/upgrading.md) and stays live for the
    // full window (>= 90 days AND >= one intervening feature release) before
    // removal.
    sink.Get("/api/v1/agent/plugin-policy", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto disk = read_on_disk_bundle();
        const bool required =
            runtime_config_store_ &&
            runtime_config_store_->get_value(plugin_signing::kPluginSigningRequiredKey) == "true";

        // Bundle absent → 200 success-shape with enabled=false.
        // Status code 404 was misleading: "no bundle uploaded" is
        // a normal operational state, not a fetch failure
        // (CONS-B1 part 2).
        if (!disk) {
            nlohmann::json out;
            out["enabled"] = false;
            out["required"] = required;
            out["trust_bundle_pem"] = "";
            res.set_content(out.dump(), "application/json");
            return;
        }
        if (!disk->has_value()) {
            // A4 envelope — same shape as every other error site
            // (auth_routes, rest_api_v1, etc.).
            res.status = 500;
            res.set_content(detail::a4_error(res, "Trust bundle on disk is unreadable"),
                            "application/json");
            return;
        }

        // Re-read the file so the response carries the actual
        // bytes, not a regenerated copy.
        std::ifstream f(trust_bundle_path(), std::ios::binary);
        std::string pem((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        nlohmann::json out;
        out["enabled"] = true;
        out["required"] = required;
        out["trust_bundle_pem"] = pem;
        out["cert_count"] = disk->value().cert_count;
        out["sha256"] = disk->value().sha256_hex;
        res.set_content(out.dump(), "application/json");
    });

    // -- Plugin Code Signing: distribution endpoint (v2) ----------------------
    //
    // Returns the current trust bundle and require flag as JSON for
    // out-of-band distribution to agents (operators curl this into
    // /etc/yuzu/plugin-trust-bundle.pem on each agent host, then pass
    // --plugin-trust-bundle to the agent). Future automatic agent-side
    // fetch will use the same shape.
    //
    // #4028 — HARDENED onto the A4 envelope + the shared
    // settings_model::build_plugin_signing_settings builder (the SAME
    // builder the /fragments/settings/plugin-signing HTML fragment calls)
    // rather than duplicating a second bespoke JSON shape for this route.
    // This route stays the SUPERSET over the fragment's own data: it alone
    // adds `trust_bundle_pem` (the raw bundle bytes), applied as an explicit
    // override below rather than via the builder's own omit-when-empty
    // default (the fragment renderer passes an empty string on purpose so
    // the field is absent there).
    //
    // #4144 review fix: promoted to /api/v2/ — see the v1 handler above's
    // comment for why. #4144 ALSO fixed the TOCTOU the earlier #4028 fix
    // round only partially closed (Important finding, confirmed by direct
    // source read): the old two-read design (read_on_disk_bundle() for
    // stats, a SEPARATE ifstream re-read for the raw PEM bytes) guarded
    // against the bundle being DELETED between the two reads, but not
    // REPLACED (the upload handler does write-temp-then-atomic-rename(), so
    // a second read against a concurrently-replaced file simply succeeds —
    // against the NEW file). That let a response pair the OLD read's
    // sha256/cert_count/subjects with the NEW read's trust_bundle_pem bytes,
    // defeating the integrity property (sha256 describes trust_bundle_pem)
    // this route exists to provide. Fixed: ONE read of the raw bytes,
    // validate_trust_bundle_pem() derives cert_count/sha256/subjects from
    // THOSE SAME bytes — sha256 and trust_bundle_pem can no longer disagree,
    // by construction.
    //
    // Authorization: PluginSigning:Read (dedicated securable, minted by
    // #4028 — Administrator-only via the rbac_store.cpp seed, floored in
    // authz_topology_floor.hpp so an RBAC-off deployment stays admin-gated).
    // That flooring alone is NOT the same practical posture the prior
    // admin_fn_ (require_admin) gate had for an MCP-tier token: require_admin
    // rejects every mcp_tier session outright regardless of role, while the
    // topology floor's legacy-role fallback admits an admin-owned MCP token
    // exactly like an interactive admin session (mcp_policy.hpp's tier_allows()
    // comment). The actual parity fix is at that chokepoint: TlsConfig/
    // PluginSigning/ServerConfig/AnalyticsConfig are denied at every MCP tier
    // there, so an MCP token 403s before it ever reaches this route's
    // perm_fn_ call. The bundle PEM holds X.509 certificates (no private
    // keys) so the security
    // blast radius of disclosure is small, but a non-admin token holder
    // learning when the trust anchor rotates (sha256 changes) is useful
    // reconnaissance for a supply-chain attacker. CC6.1 least-privilege
    // requires we restrict even read access to security-critical config to
    // admin principals (governance hardening round 1: sec-LOW-4 / UP-13 /
    // CC6.1) — now also audited fail-closed (§4) under the
    // `settings.plugin_signing.read` verb.
    sink.Get("/api/v2/agent/plugin-policy", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!perm_fn_(req, res, "PluginSigning", "Read"))
            return;
        if (!detail::emit_behavioral_audit(audit_read_fn_, req, res, "settings.plugin_signing.read",
                                           "success", "PluginSigning", "trust_bundle",
                                           "agent plugin-policy fetch")) {
            res.status = 503;
            res.set_content(detail::a4_error(res,
                                             "audit subsystem unavailable; refusing to "
                                             "serve settings data without durable evidence",
                                             detail::A4ErrorOpts{
                                                 .retry_after_ms = 5000,
                                                 .remediation = "retry after the audit subsystem "
                                                                "recovers"}),
                            "application/json");
            return;
        }

        // #4028 fix-round finding UP-3/CH-2 (governance Gate 4/5, re-derived
        // by sre/compliance-officer/enterprise-readiness): this route's
        // `required` field IS the deliverable an operator or automation
        // polls to learn the require-signature state -- `get_value()`
        // collapsed a genuine runtime_config_store read failure to "",
        // identical to a healthy "not required" (I3: the caller cannot
        // tell degraded from healthy). This flag is a status RECORD only
        // -- no server-side check consumes it today (an earlier round of
        // this fix wrongly cited ProductPackStore::require_signed_packs_
        // here, which governs YAML product-pack content, a different
        // artifact from compiled plugin binaries -- consistency-auditor's
        // Gate 8 catch; see the corrected runtime_config_store.hpp file
        // header). Plugin-binary signature verification, where
        // configured, is local to each agent via its own
        // --plugin-require-signature/--plugin-trust-bundle flags. So this
        // is a display-honesty fix, not an enforcement-bypass fix: a
        // degraded read now fails the REQUEST closed (503) rather than
        // answer with a value it cannot stand behind. The dashboard
        // fragment renderer above applies the identical `get()` switch --
        // keep both in sync.
        bool required = false;
        if (runtime_config_store_) {
            auto rc = runtime_config_store_->get(plugin_signing::kPluginSigningRequiredKey);
            if (!rc.has_value()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(
                        res,
                        "runtime config store unavailable; plugin-signing required status "
                        "could not be determined",
                        detail::A4ErrorOpts{
                            .retry_after_ms = 5000,
                            .remediation =
                                "Retry shortly; if this persists, check Postgres connectivity "
                                "for the runtime_config_store schema. This flag is a status "
                                "record only -- no server-side check consumes it, and "
                                "plugin-binary verification (where an agent is configured for "
                                "it, via that agent's own local flags) is unaffected by this "
                                "outage."}),
                    "application/json");
                return;
            }
            required = rc->has_value() && rc->value().value == "true";
        }

        // #4144 review fix: ONE filesystem read for both the raw PEM bytes
        // and the derived stats — see this route's header comment above for
        // the TOCTOU this closes. Bundle absent (does not exist on disk) is
        // a normal operational state (CONS-B1 part 2): falls through with
        // enabled=false, empty pem.
        std::error_code ec;
        auto bundle_path = trust_bundle_path();
        std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>> stats;
        std::string pem;
        if (std::filesystem::exists(bundle_path, ec)) {
            std::ifstream f(bundle_path, std::ios::binary);
            if (!f) {
                // Existed a moment ago (exists() above); a concurrent
                // upload/clear removed it before this open() — same
                // "changed while serving this request" fail-closed posture
                // #4028 introduced, just guarding the (now sole) read.
                res.status = 503;
                res.set_content(
                    detail::a4_error(
                        res, "trust bundle changed while serving this request",
                        detail::A4ErrorOpts{
                            .retry_after_ms = 1000,
                            .remediation = "retry -- the bundle was modified concurrently"}),
                    "application/json");
                return;
            }
            pem.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
            stats = plugin_signing::validate_trust_bundle_pem(pem);
            if (!stats->has_value()) {
                // Bundle unreadable (exists on disk, failed to parse) → 500.
                res.status = 500;
                res.set_content(detail::a4_error(res, "Trust bundle on disk is unreadable"),
                                "application/json");
                return;
            }
        }
        auto data = settings_model::build_plugin_signing_settings(required, stats);
        data["trust_bundle_pem"] = pem; // superset field — always present on this route alone
        res.set_content(settings_ok_envelope(std::move(data)).dump(), "application/json");
    });

    sink.Get("/fragments/settings/nvd",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_nvd_fragment(), "text/html; charset=utf-8");
             });

    sink.Get("/fragments/settings/directory",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 res.set_content(render_directory_fragment(), "text/html; charset=utf-8");
             });

    // -- Settings API: TLS toggle (HTMX POST) ---------------------------------
    sink.Post("/api/settings/tls", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto val = extract_form_value(req.body, "tls_enabled");
        cfg_->tls_enabled = (val == "true");
        spdlog::info("TLS setting changed to {} (restart required)",
                     cfg_->tls_enabled ? "enabled" : "disabled");
        res.set_header("HX-Retarget", "#tls-section");
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"TLS settings saved","level":"success"}})");
        res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: Certificate upload (admin only, multipart) --------------
    sink.Post("/api/settings/cert-upload", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        std::string type;
        std::string content;

        if (req.has_param("type")) {
            type = req.get_param_value("type");
        }

        if (SETTINGS_REQ_HAS_FILE(req, "file")) {
            content = SETTINGS_REQ_GET_FILE(req, "file").content;
        }

        if (type.empty() || content.empty()) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">Type and file are required.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto cert_dir = auth::default_cert_dir();
        std::error_code ec;
        std::filesystem::create_directories(cert_dir, ec);
        if (ec) {
            res.status = 500;
            res.set_content("<span class=\"feedback-error\">Cannot create cert directory.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        std::string out_name;
        if (type == "cert")
            out_name = "server.pem";
        else if (type == "key")
            out_name = "server-key.pem";
        else if (type == "ca")
            out_name = "ca.pem";
        else {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto out_path = cert_dir / out_name;
        {
            std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                res.status = 500;
                res.set_content("<span class=\"feedback-error\">Cannot write cert file.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

        if (type == "cert")
            cfg_->tls_server_cert = out_path;
        else if (type == "key")
            cfg_->tls_server_key = out_path;
        else if (type == "ca")
            cfg_->tls_ca_cert = out_path;

#ifndef _WIN32
        if (type == "key") {
            std::filesystem::permissions(
                out_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace);
        }
#endif

        spdlog::info("Certificate uploaded: {} -> {}", type, out_path.string());
        audit_fn_(req, "cert.upload", "success", "Certificate", type, "");

        res.set_header("HX-Retarget", "#tls-section");
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Certificate uploaded","level":"success"}})");
        res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: Paste PEM content (admin only, HTMX) --------------------
    sink.Post("/api/settings/cert-paste", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto type = extract_form_value(req.body, "type");
        auto content = extract_form_value(req.body, "content");

        if (type.empty() || content.empty()) {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content(
                "<span class=\"feedback-error\">Type and PEM content are required.</span>",
                "text/html; charset=utf-8");
            return;
        }

        if (content.size() > 65536) {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content(
                "<span class=\"feedback-error\">PEM content too large (max 64 KB).</span>",
                "text/html; charset=utf-8");
            return;
        }

        if (content.find("-----BEGIN") == std::string::npos ||
            content.find("-----END") == std::string::npos) {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content("<span class=\"feedback-error\">Invalid PEM: must contain -----BEGIN "
                            "and -----END markers.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        std::erase(content, '\r');

        std::string out_name;
        if (type == "cert")
            out_name = "server.pem";
        else if (type == "key")
            out_name = "server-key.pem";
        else if (type == "ca")
            out_name = "ca.pem";
        else {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content("<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto cert_dir = auth::default_cert_dir();
        std::error_code ec;
        std::filesystem::create_directories(cert_dir, ec);
        if (ec) {
            res.status = 500;
            res.set_content("<span class=\"feedback-error\">Cannot create cert directory.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto out_path = cert_dir / out_name;
        {
            std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                res.status = 500;
                res.set_content("<span class=\"feedback-error\">Cannot write cert file.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

#ifndef _WIN32
        if (type == "key") {
            std::filesystem::permissions(
                out_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace);
        }
#endif

        if (type == "cert")
            cfg_->tls_server_cert = out_path;
        else if (type == "key")
            cfg_->tls_server_key = out_path;
        else if (type == "ca")
            cfg_->tls_ca_cert = out_path;

        spdlog::info("Certificate pasted: {} -> {}", type, out_path.string());
        audit_fn_(req, "cert.paste", "success", "Certificate", type, "");

        res.set_header("HX-Retarget", "#tls-section");
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Certificate saved from paste","level":"success"}})");
        res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: OIDC configuration (admin only, HTMX) -------------------
    sink.Post("/api/settings/oidc", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto issuer = extract_form_value(req.body, "issuer");
        auto client_id = extract_form_value(req.body, "client_id");
        auto client_secret = extract_form_value(req.body, "client_secret");
        auto redirect_uri = extract_form_value(req.body, "redirect_uri");
        auto admin_group = extract_form_value(req.body, "admin_group");
        auto skip_tls_verify = extract_form_value(req.body, "skip_tls_verify");

        if (issuer.empty() || client_id.empty()) {
            res.status = 400;
            auto html = render_directory_fragment() +
                        "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                        "hx-swap-oob=\"true\">Issuer URL and Client ID are required.</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        // The redaction placeholder is not a credential. It reaches this handler when an
        // operator copies it out of the startup log or a config.update audit detail -- the
        // two surfaces that emit it. GET /api/config is NOT one of them: it omits a
        // secret's value rather than substituting a placeholder. So an exact one is treated
        // like a blank field, meaning "leave the stored secret alone". Without that the
        // store still refuses it further down -- but by then cfg_ and the live provider
        // have already been updated, so the two would diverge behind a "saved" toast.
        //
        // The predicate here and the one at the sink are deliberately DIFFERENT, and both
        // are needed. This one is EXACT: only the bare placeholder means "unchanged" (the
        // form renders the field with `value=""` unconditionally, so the literal never
        // originates here -- only the greyed placeholder ATTRIBUTE varies with whether a
        // secret is stored, and an attribute is never submitted). A secret that merely
        // CONTAINS the token falls through on purpose -- the sink refuses it and the
        // failure branch below tells the operator. Clearing it here instead discarded a
        // real credential and reported SAVED, the same false-success this change exists to
        // remove (found by four reviewers). The sink's predicate is the broad CONTAINMENT
        // one, and it covers every other caller (PUT /api/config included).
        if (is_exactly_redaction_placeholder(client_secret))
            client_secret.clear();
        auto effective_secret = client_secret.empty() ? cfg_->oidc_client_secret : client_secret;
        bool skip_tls = (skip_tls_verify == "true");

        std::unique_ptr<oidc::OidcProvider> new_provider;
        try {
            oidc::OidcConfig oidc_cfg;
            oidc_cfg.issuer = issuer;
            oidc_cfg.client_id = client_id;
            oidc_cfg.client_secret = effective_secret;
            oidc_cfg.redirect_uri = redirect_uri;
            oidc_cfg.admin_group_id = admin_group;
            oidc_cfg.skip_tls_verify = skip_tls;
            // ADR-2001 §1 gap (Task 2 follow-up): this hot-reload path builds its
            // own local OidcConfig and previously left scim_link_claim at its
            // struct default ("sub"), silently reverting an operator's
            // `--oidc-scim-link-claim oid` (Entra) to `sub` the moment they saved
            // ANY OIDC setting via this form — until the next process restart
            // re-read the flag. Mirrors server.cpp's boot-time wiring
            // (`oidc_cfg.scim_link_claim = cfg_.oidc_scim_link_claim;`).
            oidc_cfg.scim_link_claim = cfg_->oidc_scim_link_claim;
            if (skip_tls)
                spdlog::warn(
                    "OIDC TLS certificate verification DISABLED — do not use in production");

            auto v2_pos = issuer.rfind("/v2.0");
            if (v2_pos != std::string::npos) {
                auto base = issuer.substr(0, v2_pos);
                oidc_cfg.authorization_endpoint = base + "/oauth2/v2.0/authorize";
                oidc_cfg.token_endpoint = base + "/oauth2/v2.0/token";
            } else {
                oidc_cfg.authorization_endpoint = issuer + "/authorize";
                oidc_cfg.token_endpoint = issuer + "/token";
            }

            auto src_script =
                std::filesystem::current_path() / "scripts" / "oidc_token_exchange.py";
            if (std::filesystem::exists(src_script))
                oidc_cfg.exchange_script = src_script.string();

            new_provider = std::make_unique<oidc::OidcProvider>(std::move(oidc_cfg));
        } catch (const std::exception& e) {
            spdlog::error("OIDC provider reinit failed: {}", e.what());
            res.status = 500;
            auto html = render_directory_fragment() +
                        "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                        "hx-swap-oob=\"true\">OIDC init failed: " +
                        html_escape(e.what()) + "</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        {
            std::unique_lock lock(*oidc_mu_);
            cfg_->oidc_issuer = issuer;
            cfg_->oidc_client_id = client_id;
            cfg_->oidc_client_secret = effective_secret;
            cfg_->oidc_redirect_uri = redirect_uri;
            cfg_->oidc_admin_group = admin_group;
            cfg_->oidc_skip_tls_verify = skip_tls;
            *oidc_provider_ = std::move(new_provider);
        }
        spdlog::info("OIDC provider reinitialized via Settings UI (issuer={})", issuer);

        std::vector<std::string> persist_errors;
        // NO silent else. Guarding the whole persist block on is_open() and falling
        // through to the success toast is the same false-success this fold exists to
        // remove -- a degraded store would report "saved" for a save that never
        // happened. A null store is recorded as an error here; a store that is merely
        // not open reports itself, because every set() below returns "store not open"
        // and the failure branch renders it (the DEX siblings at :3300/:3351 already
        // rely on that and carry no is_open() guard).
        if (!runtime_config_store_) {
            persist_errors.emplace_back("store: runtime configuration store unavailable");
        } else {
            auto who = std::string("admin");
            auto session = auth_fn_(req, res);
            if (session)
                who = session->username;
            // Every result is observed. `set()` is [[nodiscard]] for this reason: a
            // discarded rejection reported "saved" for a write the store refused.
            auto note = [&](const char* k, std::expected<void, std::string> r) {
                if (!r)
                    persist_errors.push_back(std::string(k) + ": " + r.error());
            };
            note("oidc_issuer", runtime_config_store_->set("oidc_issuer", issuer, who));
            note("oidc_client_id", runtime_config_store_->set("oidc_client_id", client_id, who));
            if (!client_secret.empty())
                note("oidc_client_secret",
                     runtime_config_store_->set("oidc_client_secret", client_secret, who));
            note("oidc_redirect_uri",
                 runtime_config_store_->set("oidc_redirect_uri", redirect_uri, who));
            note("oidc_admin_group",
                 runtime_config_store_->set("oidc_admin_group", admin_group, who));
            note("oidc_skip_tls_verify",
                 runtime_config_store_->set("oidc_skip_tls_verify", skip_tls ? "true" : "false", who));
        }

        if (!persist_errors.empty()) {
            // The live provider is already swapped in, but the store refused part of the
            // write, so the running config and the persisted config disagree and a restart
            // would silently revert. Say so instead of reporting success.
            // Every component is a hardcoded key plus a fixed error literal -- no value
            // is ever in here -- so there is no disclosure reason to collapse the list,
            // and collapsing it discarded WHICH key failed from the one audit row that
            // documents a partial persist.
            std::string joined;
            for (const auto& e : persist_errors) {
                if (!joined.empty())
                    joined += ", ";
                joined += e;
            }
            audit_fn_(req, "oidc.configure", "failure", "OidcConfig", issuer,
                      "persist failed: " + joined);
            auto html = render_directory_fragment() +
                        "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                        "hx-swap-oob=\"true\">OIDC applied to the running server, but these "
                        "settings could NOT be saved: " +
                        html_escape(joined) +
                        ". Any other settings in this form WERE saved, so the stored "
                        "configuration is now inconsistent with the running server. Fix the "
                        "cause and save again.</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        audit_fn_(req, "oidc.configure", "success", "OidcConfig", issuer, "");

        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"OIDC configuration saved","level":"success"}})");
        res.set_content(render_directory_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: OIDC test connection (admin only, HTMX) -----------------
    sink.Post("/api/settings/oidc/test", [this](const httplib::Request& req,
                                                httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto issuer = extract_form_value(req.body, "issuer");
        auto skip_tls_str = extract_form_value(req.body, "skip_tls_verify");
        bool skip_tls = (skip_tls_str == "true") || cfg_->oidc_skip_tls_verify;

        if (issuer.empty())
            issuer = cfg_->oidc_issuer;

        if (issuer.empty()) {
            res.set_content("<span class=\"feedback-error\">Enter an Issuer URL first.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto discovery_url = issuer;
        if (!discovery_url.ends_with("/"))
            discovery_url += "/";
        discovery_url += ".well-known/openid-configuration";

        audit_fn_(req, "oidc.test", "attempt", "OidcConfig", issuer, "");

        try {
            std::string url = discovery_url;
            std::string scheme;
            if (url.starts_with("https://")) {
                scheme = "https://";
                url = url.substr(8);
            } else if (url.starts_with("http://")) {
                scheme = "http://";
                url = url.substr(7);
            } else {
                res.set_content("<span class=\"feedback-error\">Invalid issuer URL scheme (must be "
                                "http or https).</span>",
                                "text/html; charset=utf-8");
                return;
            }
            auto slash = url.find('/');
            auto host = (slash != std::string::npos) ? url.substr(0, slash) : url;
            auto path = (slash != std::string::npos) ? url.substr(slash) : "/";

            auto client = std::make_unique<httplib::Client>(scheme + host);
            client->set_connection_timeout(10);
            client->set_read_timeout(10);
            client->set_write_timeout(10);
            client->enable_server_certificate_verification(!skip_tls);

            auto result = client->Get(path);

            int status_code = result ? result->status : 0;
            std::string body_copy = result ? result->body : "";
            std::string err_str = result ? "" : httplib::to_string(result.error());
            client.reset();

            if (status_code == 200) {
                auto j = nlohmann::json::parse(body_copy);
                std::string auth_ep = j.value("authorization_endpoint", "");
                std::string token_ep = j.value("token_endpoint", "");
                if (!auth_ep.empty() && !token_ep.empty()) {
                    res.set_content(
                        "<span class=\"feedback-ok\" style=\"color:#3fb950;font-size:0.8rem\">"
                        "Connected &#x2014; discovered authorization and token endpoints</span>",
                        "text/html; charset=utf-8");
                } else {
                    res.set_content(
                        "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                        "Discovery succeeded but missing authorization/token endpoints.</span>",
                        "text/html; charset=utf-8");
                }
            } else if (status_code == 0) {
                res.set_content(
                    "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                    "Discovery failed: " +
                        html_escape(err_str) + "</span>",
                    "text/html; charset=utf-8");
            } else {
                res.set_content(
                    "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                    "Discovery failed: HTTP " +
                        std::to_string(status_code) + "</span>",
                    "text/html; charset=utf-8");
            }
        } catch (const nlohmann::json::exception& e) {
            res.set_content(
                "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                "Discovery response is not valid JSON: " +
                    html_escape(e.what()) + "</span>",
                "text/html; charset=utf-8");
        } catch (const std::exception& e) {
            res.set_content(
                "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                "Discovery failed: " +
                    html_escape(e.what()) + "</span>",
                "text/html; charset=utf-8");
        }
    });

    // -- Settings API: User management (admin only, HTMX) ----------------------
    sink.Post("/api/settings/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session) {
            // Match DELETE defensive branch — see GET handler comment.
            res.status = 401;
            return;
        }
        if (session->username.empty()) {
            spdlog::error("POST /api/settings/users: session has empty username; "
                          "refusing to upsert (likely upstream auth misconfiguration)");
            res.status = 500;
            return;
        }
        auto username = extract_form_value(req.body, "username");
        auto password = extract_form_value(req.body, "password");

        // C1 FIX: Role parameter is IGNORED on user creation.
        // New users are ALWAYS created as 'user' role. To change a user's
        // role, use the dedicated POST /api/settings/users/:username/role
        // endpoint (enhanced audit logging, session invalidation).
        // This prevents privilege escalation where a compromised admin
        // silently creates additional admin accounts.
        auth::Role role = auth::Role::user;

        if (username.empty() || password.empty()) {
            res.status = 400;
            res.set_content(render_users_fragment(session->username) +
                                "<script>document.getElementById('user-feedback')."
                                "className='feedback feedback-error';"
                                "document.getElementById('user-feedback').textContent='"
                                "Username and password required.';</script>",
                            "text/html; charset=utf-8");
            return;
        }

        // H1 FIX: Validate username format (alphanumeric + ._- only, no ':')
        if (!is_valid_username(username)) {
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid username: must be 1-64 chars, alphanumeric + ._- only","level":"error"}})");
            res.set_content(
                detail::a4_error(res, "Invalid username: must be 1-64 chars, alphanumeric + ._- "
                                       "only"),
                "application/json");
            return;
        }

        // #1837 governance follow-up — reserve the `oidc:`/`saml:`/`ad:` SSO-
        // principal namespace prefixes on LOCAL user creation. Defense-in-
        // depth: is_valid_username's ':' rejection already makes the exact
        // stable principal string unconstructable here, but an explicit
        // reservation documents intent and survives a future charset change.
        if (is_reserved_identity_prefix(username)) {
            spdlog::warn("POST /api/settings/users: username '{}' uses a reserved SSO-principal "
                        "prefix — rejected",
                        username);
            audit_fn_(req, "user.create", "denied", "User", username, "reserved_prefix");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Username cannot begin with a reserved prefix: oidc:, saml:, or ad:","level":"error"}})");
            res.set_content(
                detail::a4_error(res, "Username cannot begin with a reserved prefix: oidc:, "
                                       "saml:, or ad:"),
                "application/json");
            return;
        }

        // #399: reject duplicate username on the create path.
        if (auth_mgr_->get_user_role(username).has_value()) {
            spdlog::warn("POST /api/settings/users: username '{}' already exists — rejected",
                         username);
            audit_fn_(req, "user.create", "denied", "User", username, "duplicate_username");
            res.status = 409;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Username already exists","level":"error"}})");
            res.set_content(detail::a4_error(res, "Username already exists"),
                            "application/json");
            return;
        }
        // C1 FIX: Self-password-change is allowed, but role is always 'user' on creation.
        // Role changes must go through POST /api/settings/users/:username/role.
        // The self-demotion guard is no longer needed on this path since
        // new users are always created as 'user' role.
        if (!auth_mgr_->upsert_user(username, password, role)) {
            spdlog::warn("POST /api/settings/users: upsert rejected for '{}' "
                         "(weak_password — minimum 12 characters)",
                         username);
            audit_fn_(req, "user.create", "denied", "User", username, "weak_password");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Password must be at least 12 characters","level":"error"}})");
            res.set_content(detail::a4_error(res, "Password must be at least 12 characters"),
                            "application/json");
            return;
        }
        if (!auth_mgr_->save_config()) {
            spdlog::error("Failed to save config after user create");
        }
        std::string role_str = auth::role_to_string(role);
        spdlog::info("User '{}' created (role={})", username, role_str);
        // SOC 2 CC7.2: privileged user lifecycle operations must appear
        // in audit_store, not just spdlog (governance Gate 6 CO-1).
        audit_fn_(req, "user.create", "success", "User", username, "role=" + role_str);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"User created","level":"success"}})");
        res.set_content(render_users_fragment(session->username), "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/users/(.+))", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session) {
            // admin_fn_ already authenticated the caller; this branch is
            // defensive — if the two callbacks disagree there is a deeper
            // bug and we refuse to proceed rather than delete on a stale
            // or unresolvable session.
            res.status = 401;
            return;
        }
        // PR2 — MFA step-up gate. Deleting a user destroys a principal;
        // require fresh MFA proof. Sits after admin_fn (no point step-
        // upping a non-admin) but before any state mutation.
        if (step_up_fn_ &&
            !step_up_fn_(req, res, *session, "DELETE /api/settings/users/{username}"))
            return;
        if (session->username.empty()) {
            // Defense-in-depth: an empty session->username would let
            // a hand-crafted DELETE against an empty-username row
            // succeed via the "" == "" comparison below. The root
            // cause of empty session->username is upstream (typically
            // OIDC mis-config returning empty preferred_username), but
            // the handler fails closed regardless. Governance Gate 4 UP-1.
            spdlog::error("DELETE /api/settings/users: session has empty username; "
                          "refusing to delete (likely upstream auth misconfiguration)");
            res.status = 500;
            return;
        }
        auto username = req.matches[1].str();
        // Username allowlist before any state mutation. Without this a
        // hand-crafted DELETE against `..%2Ffoo` or characters that
        // bypass URL canonicalisation reaches remove_user() with bytes
        // that should never have entered the user-store path.
        if (!is_valid_username(username)) {
            audit_fn_(req, "user.delete", "denied", "User", username, "invalid_username");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid username format","level":"error"}})");
            res.set_content(detail::a4_error(res, "Invalid username format"), "application/json");
            return;
        }
        // Self-deletion lockout guard (#397). Deleting the currently
        // authenticated operator — typically the sole admin on a single-
        // seat deployment — leaves the running server with zero usable
        // credentials until it is restarted against its on-disk config.
        // The UI suppresses the Remove button for the self row (#403),
        // but the handler must reject independently because a hand-
        // crafted HTTP DELETE bypasses the dashboard entirely.
        //
        // Shared comparison (rbac_admin_predicate.hpp's is_self_target) —
        // this is call site #1 of the third-call-site trigger named below.
        if (is_self_target(*session, username)) {
            spdlog::warn("User '{}' attempted to delete their own account via "
                         "/api/settings/users — rejected",
                         session->username);
            // SOC 2 CC7.2: rejected privileged operations must appear
            // in audit_store, not just spdlog (governance Gate 6 CO-1).
            // SIEM ingestion paths read audit events; spdlog rotation
            // alone is not the evidence chain.
            audit_fn_(req, "user.delete", "denied", "User", username, "self_delete_blocked");
            res.status = 403;
            // Toast wording must stay in sync with docs/user-manual/server-admin.md
            // and the CHANGELOG Fixed entry — operators search both.
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Cannot delete your own account","level":"error"}})");
            res.set_content(detail::a4_error(res, "Cannot delete your own account"),
                            "application/json");
            return;
        }
        // Owner-delete guard (design doc §3.1, GOVERNANCE HARD PRECONDITION).
        // A user who owns an active engine principal must transfer that
        // ownership (via the engine-principal transfer-owner surface) before
        // their account can be deleted — otherwise the principal's audit
        // trail loses its named responsible human. FAIL CLOSED: once the
        // store is wired, treat `count_active_owned_by`'s nullopt
        // (store-unreachable / cannot verify) the SAME as ">0 owned" — both
        // block the delete. There is no downgrade path from "cannot verify"
        // to "safe to delete".
        //
        // G6 (governance hardening, security-guardian): a null
        // `engine_principal_store_` skips this guard entirely rather than
        // failing closed — deliberately, and ONLY defensible because it is
        // provably unreachable in production. server.cpp constructs
        // EnginePrincipalStore unconditionally whenever `pg_pool_` is set
        // (server.cpp's boot sequence, "EnginePrincipalStore — born-on-PG
        // identity store") and sets `startup_failed_ = true` — refusing to
        // start serving at all — if it fails to open; a live server
        // therefore NEVER reaches this handler with a null store. The null
        // path exists solely so `test_settings_routes_users.cpp`'s
        // pre-existing harness (which predates this feature and does not
        // wire an EnginePrincipalStore) keeps passing — see
        // SettingsOwnerDeleteHarness in test_engine_principal_lifecycle.cpp
        // for the wired-store coverage of the 409/nullopt paths themselves.
        // If a future change ever makes EnginePrincipalStore constructible
        // without a hard-fail boot path (e.g. an optional/feature-flagged
        // deployment mode), this skip becomes a real fail-open and MUST be
        // revisited — do not carry this comment forward unexamined.
        if (engine_principal_store_) {
            auto owned = engine_principal_store_->count_active_owned_by(username);
            if (!owned.has_value() || *owned > 0) {
                audit_fn_(req, "user.delete", "denied", "User", username,
                          owned.has_value() ? "owns_active_engine_principal"
                                             : "engine_store_unreachable");
                res.status = 409;
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Cannot delete: user owns an active engine )"
                    R"(principal — transfer ownership first","level":"error"}})");
                res.set_content(
                    detail::a4_error(res, "Cannot delete: user owns an active engine "
                                           "principal — transfer ownership first"),
                    "application/json");
                return;
            }
        }
        // ADR-2001 §§1,3 — credentials-FIRST revoke across the resolved
        // principal set (the deleted username + every OIDC identity linked
        // to it via SCIM, if any) BEFORE the account is removed. Mirrors
        // the SCIM deprovision seams' ordering and fail-closed posture:
        // `resolve_deprovision_principals_for_username` fails closed
        // (nullopt) only on a genuine link-lookup failure for a KNOWN SCIM
        // user — never on "not a SCIM user"/"SCIM store unwired", which
        // degrade to the slug-only set (see its doc comment).
        std::string revoke_detail;
        if (api_token_store_) {
            auto principals = resolve_deprovision_principals_for_username(scim_store_, username);
            if (!principals.has_value()) {
                spdlog::error("DELETE /api/settings/users: identity-link resolution failed for "
                             "'{}' — refusing to delete (a store blip must not read as \"no "
                             "linked identities to revoke\")",
                             username);
                audit_fn_(req, "user.delete", "failure", "User", username,
                         "identity_link_resolution_failed");
                res.status = 500;
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Failed to resolve linked identities — try )"
                    R"(again","level":"error"}})");
                res.set_content(
                    detail::a4_error(res, "Failed to resolve linked identities — try again"),
                    "application/json");
                return;
            }
            if (!api_token_store_->is_open()) {
                spdlog::error("DELETE /api/settings/users: ApiTokenStore unavailable — "
                             "refusing to delete '{}' without being able to revoke its "
                             "credentials",
                             username);
                audit_fn_(req, "user.delete", "failure", "User", username,
                         "api_token_store_unavailable");
                res.status = 503;
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Credential store unavailable — try )"
                    R"(again","level":"error"}})");
                res.set_content(detail::a4_error(res, "Credential store unavailable — try again"),
                                "application/json");
                return;
            }
            auto revoke_result =
                revoke_deprovision_credentials(*api_token_store_, *auth_mgr_, *principals);
            revoke_detail =
                "api_tokens_revoked=" + std::to_string(revoke_result.api_tokens_revoked) +
                " sessions_revoked=" + std::to_string(revoke_result.sessions_revoked) +
                " principals=" + std::to_string(principals->size()) +
                // Governance Gate 7 SHOULD fix (UP-5): enumerate the actual
                // principal strings, not just the count — mirrors the SCIM
                // seam's `revoke_linked_credentials_or_fail`.
                enumerate_principals_for_audit(*principals);
            if (!revoke_result.api_tokens_persisted) {
                revoke_detail += " api_tokens_db_error=true";
                spdlog::error("DELETE /api/settings/users: revoke_for_principal did not "
                             "persist for one or more principals linked to '{}' — refusing to "
                             "report a clean delete (ADR-2001 §3 fail-closed)",
                             username);
                audit_fn_(req, "user.delete", "partial", "User", username, revoke_detail);
                res.status = 500;
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Failed to revoke API tokens for one or more )"
                    R"(linked identities — try again","level":"error"}})");
                res.set_content(
                    detail::a4_error(res, "Failed to revoke API tokens for one or more linked "
                                           "identities — try again"),
                    "application/json");
                return;
            }
        } else {
            // Governance Gate 7 BLOCKING fix (UP-7): FAIL CLOSED here —
            // mirror the SCIM seam's `revoke_linked_credentials_or_fail`
            // (scim_routes.cpp), which 503s + audits
            // "api_token_store_unavailable" rather than skip-and-proceed
            // when its token_store is null/not open. A null ApiTokenStore
            // means credentials CANNOT be revoked, and proceeding to
            // `remove_user` below anyway would silently leave every linked
            // principal's API tokens live — exactly the CC6.8 gap ADR-2001
            // exists to close. server.cpp constructs ApiTokenStore
            // unconditionally whenever pg_pool_ is set and fails the whole
            // boot otherwise, so a live server NEVER reaches this handler
            // with a null store — this branch is test-harness-only
            // (SettingsRoutesHarness/SettingsOwnerDeleteHarness, which
            // predate ADR-2001) and every wired-store outcome is covered by
            // SettingsAdr2001Harness's PG-backed tests.
            spdlog::error("DELETE /api/settings/users: no ApiTokenStore wired — refusing to "
                         "delete '{}' without being able to revoke its credentials (ADR-2001)",
                         username);
            audit_fn_(req, "user.delete", "failure", "User", username,
                     "api_token_store_unavailable");
            res.status = 503;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Credential store unavailable — try )"
                R"(again","level":"error"}})");
            res.set_content(detail::a4_error(res, "Credential store unavailable — try again"),
                            "application/json");
            return;
        }

        if (auth_mgr_->remove_user(username)) {
            if (!auth_mgr_->save_config()) {
                spdlog::error("Failed to save config after user removal");
            }
            spdlog::info("User '{}' removed", username);
            audit_fn_(req, "user.delete", "success", "User", username, revoke_detail);
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"User deleted","level":"success"}})");
            res.set_content(render_users_fragment(session->username), "text/html; charset=utf-8");
            return;
        }
        // remove_user() returns false when the username is not in the
        // user store. A no-op DELETE is still a privileged-mutation
        // attempt and must surface in the audit chain.
        audit_fn_(req, "user.delete", "denied", "User", username, "user_not_found");
        res.status = 404;
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"User not found","level":"error"}})");
        res.set_content(detail::a4_error(res, "User not found"), "application/json");
    });

    // -- Settings API: Role change (admin only, C1 fix) -------------------------
    // Dedicated endpoint for changing user roles. Separated from user creation
    // to enforce enhanced audit logging and session invalidation.
    sink.Post(R"(/api/settings/users/(.+)/role)", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            return;
        }
        // PR2 — MFA step-up gate. Role changes promote/demote a
        // principal's authority; require fresh MFA proof.
        if (step_up_fn_ &&
            !step_up_fn_(req, res, *session, "POST /api/settings/users/{username}/role"))
            return;
        if (session->username.empty()) {
            spdlog::error("POST /api/settings/users/:username/role: session has empty username");
            res.status = 500;
            return;
        }
        auto target_username = req.matches[1].str();

        // H1 FIX: Validate username in path parameter
        if (!is_valid_username(target_username)) {
            // SOC 2 CC7.2: every denied branch on a privileged-mutation
            // endpoint emits an audit event so the SIEM evidence chain is
            // complete (governance PR4 audit-coverage).
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "invalid_username");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid username format","level":"error"}})");
            res.set_content(detail::a4_error(res, "Invalid username format"), "application/json");
            return;
        }

        // Self-demotion guard — can't change your own role. Shared
        // comparison (rbac_admin_predicate.hpp's is_self_target) — call site
        // #2 of the third-call-site trigger named at the DELETE handler
        // above (#397/#403); A2's unassign-own-Administrator-grant guard is
        // the third, per that guard's own doc comment.
        if (is_self_target(*session, target_username)) {
            spdlog::warn("User '{}' attempted to change their own role via "
                         "/api/settings/users/:username/role — rejected",
                         session->username);
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "self_role_change_blocked");
            res.status = 403;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Cannot change your own role","level":"error"}})");
            res.set_content(detail::a4_error(res, "Cannot change your own role"),
                            "application/json");
            return;
        }

        // Parse requested role from JSON body
        std::string requested_role;
        try {
            auto json = nlohmann::json::parse(req.body);
            if (!json.contains("role") || !json["role"].is_string()) {
                audit_fn_(req, "user.role_change", "denied", "User", target_username,
                          "missing_role");
                res.status = 400;
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Missing or invalid 'role' field","level":"error"}})");
                res.set_content(detail::a4_error(res, "Missing or invalid 'role' field"),
                                "application/json");
                return;
            }
            requested_role = json["role"].get<std::string>();
        } catch (const std::exception& e) {
            audit_fn_(req, "user.role_change", "denied", "User", target_username, "invalid_json");
            res.status = 400;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Invalid JSON body","level":"error"}})");
            res.set_content(detail::a4_error(res, "Invalid JSON body"), "application/json");
            return;
        }

        // Allowlist check — only 'admin' or 'user' allowed
        auth::Role new_role;
        if (requested_role == "admin") {
            new_role = auth::Role::admin;
        } else if (requested_role == "user") {
            new_role = auth::Role::user;
        } else {
            audit_fn_(req, "user.role_change", "denied", "User", target_username, "invalid_role");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid role: must be 'admin' or 'user'","level":"error"}})");
            res.set_content(detail::a4_error(res, "Invalid role: must be 'admin' or 'user'"),
                            "application/json");
            return;
        }

        // Get current role for audit logging
        auto current_entry_opt = auth_mgr_->get_user_role(target_username);
        if (!current_entry_opt) {
            audit_fn_(req, "user.role_change", "denied", "User", target_username, "user_not_found");
            res.status = 404;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"User not found","level":"error"}})");
            res.set_content(detail::a4_error(res, "User not found"), "application/json");
            return;
        }
        auth::Role old_role = *current_entry_opt;

        // No-op if role unchanged
        if (old_role == new_role) {
            // No state change, but audit the operator's intent — distinguishes
            // "tried to set already-current role" from "no request was made"
            // for compliance review.
            audit_fn_(req, "user.role_change", "no_op", "User", target_username,
                      "same_role=" + auth::role_to_string(new_role));
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Role unchanged","level":"info"}})");
            res.set_content(render_users_fragment(session->username), "text/html; charset=utf-8");
            return;
        }

        // Perform role change (AuthManager.update_role() handles DB + session invalidation)
        if (!auth_mgr_->update_role(target_username, new_role)) {
            spdlog::error("Failed to update role for '{}'", target_username);
            audit_fn_(req, "user.role_change", "denied", "User", target_username, "db_failure");
            res.status = 500;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Failed to update role","level":"error"}})");
            res.set_content(detail::a4_error(res, "Failed to update role"), "application/json");
            return;
        }

        // Enhanced audit logging (C1 requirement)
        std::string old_role_str = auth::role_to_string(old_role);
        std::string new_role_str = auth::role_to_string(new_role);
        spdlog::info("User role changed: {} {} -> {} by {}", target_username, old_role_str,
                     new_role_str, session->username);
        audit_fn_(req, "user.role_change", "success", "User", target_username,
                  "old_role=" + old_role_str + ",new_role=" + new_role_str);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Role updated","level":"success"}})");
        res.set_content(render_users_fragment(session->username), "text/html; charset=utf-8");
    });

    // -- Settings API: Enrollment tokens (admin only, HTMX) --------------------
    sink.Post("/api/settings/enrollment-tokens", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto label = extract_form_value(req.body, "label");
        auto max_uses_s = extract_form_value(req.body, "max_uses");
        auto ttl_s = extract_form_value(req.body, "ttl_hours");

        int max_uses = 0;
        int ttl_hours = 0;
        try {
            if (!max_uses_s.empty())
                max_uses = std::stoi(max_uses_s);
            if (!ttl_s.empty())
                ttl_hours = std::stoi(ttl_s);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid numeric parameter"),
                            "application/json");
            return;
        }

        auto ttl = ttl_hours > 0 ? std::chrono::seconds(ttl_hours * 3600) : std::chrono::seconds(0);

        auto raw_token = auth_mgr_->create_enrollment_token(label, max_uses, ttl);

        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Enrollment token created","level":"success"}})");
        res.set_content(render_tokens_fragment(raw_token), "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/enrollment-tokens/(.+))", [this](const httplib::Request& req,
                                                                  httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto token_id = req.matches[1].str();
        auth_mgr_->revoke_enrollment_token(token_id);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Enrollment token revoked","level":"success"}})");
        res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
    });

    // -- Batch enrollment token generation (JSON API for scripting) -------------
    sink.Post("/api/settings/enrollment-tokens/batch", [this](const httplib::Request& req,
                                                              httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto label = extract_json_string(req.body, "label");
        auto count_s = extract_json_string(req.body, "count");
        auto max_uses_s = extract_json_string(req.body, "max_uses");
        auto ttl_s = extract_json_string(req.body, "ttl_hours");

        int count = 10;
        int max_uses = 1;
        int ttl_hours = 0;
        try {
            if (!count_s.empty())
                count = std::stoi(count_s);
            if (!max_uses_s.empty())
                max_uses = std::stoi(max_uses_s);
            if (!ttl_s.empty())
                ttl_hours = std::stoi(ttl_s);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid numeric parameter"),
                            "application/json");
            return;
        }

        if (count < 1 || count > 10000) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "count must be 1-10000"), "application/json");
            return;
        }

        auto ttl = ttl_hours > 0 ? std::chrono::seconds(ttl_hours * 3600) : std::chrono::seconds(0);

        auto tokens = auth_mgr_->create_enrollment_tokens_batch(label, count, max_uses, ttl);

        res.set_content(nlohmann::json({{"count", tokens.size()}, {"tokens", tokens}}).dump(),
                        "application/json");
    });

    // -- Settings API: API tokens (admin only, HTMX) ---------------------------
    sink.Post("/api/settings/api-tokens", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!perm_fn_(req, res, "ApiToken", "Write"))
            return;
        auto session = auth_fn_(req, res);
        if (!session)
            return;

        auto name = extract_form_value(req.body, "name");
        auto ttl_s = extract_form_value(req.body, "ttl_hours");
        auto mcp_tier = extract_form_value(req.body, "mcp_tier");

        if (name.empty()) {
            res.set_content("<span class=\"feedback-error\">Token name is required.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        // UP-H2 (gov Gate 4, unhappy-path): clamp `name` length BEFORE
        // any audit emission. Same DoS-via-oversized-payload class as
        // the REST /api/v1/tokens site — see comment there for the full
        // rationale. The HTMX form input has an HTML `maxlength="64"`
        // attribute but the server cannot trust client-side limits;
        // mirror the same 256-char cap as the REST surface.
        if (name.size() > 256) {
            res.set_content("<span class=\"feedback-error\">invalid_input_length: name "
                            "exceeds 256 chars.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        if (!mcp::is_valid_tier(mcp_tier)) {
            res.set_content("<span class=\"feedback-error\">Invalid MCP tier. Must be readonly, "
                            "operator, or supervised.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        int64_t expires_at = 0;
        if (!ttl_s.empty()) {
            try {
                int ttl_hours = std::stoi(ttl_s);
                if (ttl_hours > 0) {
                    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                    expires_at = now + static_cast<int64_t>(ttl_hours) * 3600;
                }
            } catch (const std::exception&) {
                res.set_content("<span class=\"feedback-error\">Invalid TTL value.</span>",
                                "text/html; charset=utf-8");
                return;
            }
        }

        auto result =
            api_token_store_->create_token(name, session->username, expires_at, {}, mcp_tier);
        if (!result) {
            // sre-1 (gov Gate 6): Prometheus signal for CSPRNG failure
            // on the HTMX surface (parity with the REST surfaces). Uses
            // `site="api_token_htmx"` so SRE rules can distinguish
            // dashboard-driven failures from API-driven failures if
            // needed, while a label-agnostic alert
            //   rate(yuzu_secure_random_failure_total[5m]) > 0
            // still fires for both.
            if (metrics_registry_) {
                metrics_registry_
                    ->counter("yuzu_secure_random_failure_total",
                              {{"reason", "prng_failure"}, {"site", "api_token_htmx"}})
                    .increment();
            }
            // F-002 (gov Gate 2, security-guardian): mirror the REST
            // failure-path audit at the HTMX surface. Same SOC 2 CC7.2/CC7.3
            // requirement applies — a token-issuance attempt rejected for
            // a CSPRNG entropy failure is a security-relevant event and
            // must produce an audit row even though the request never made
            // it to the store-side success path. Detail field carries the
            // `csprng_unavailable:` marker for SIEM correlation. Logged
            // before the response is sent so a mid-response crash still
            // leaves the audit trail (defensive ordering).
            //
            // UP-H1 (gov Gate 4): capture the AuditStore::log bool return
            // and wrap in try/catch so an exception from the SQLite
            // audit pipeline does not abort the dashboard fragment
            // response. On silent persist failure or exception, set
            // `Sec-Audit-Failed: true` header so HTMX-aware operator
            // tooling can detect the partial-success on the dashboard
            // surface (parity with the REST envelopes). The fragment
            // body is also annotated with a hidden marker for tests.
            bool audit_emitted = true;
            if (audit_store_) {
                try {
                    audit_emitted =
                        audit_store_->log({.principal = session->username,
                                           .principal_role = auth::role_to_string(auth::effective_role(*session)),
                                           .action = "api_token.create",
                                           .target_type = "ApiToken",
                                           .target_id = name,
                                           .detail = "csprng_unavailable: " + result.error(),
                                           .source_ip = req.remote_addr,
                                           .result = "failure"});
                } catch (const std::exception& ex) {
                    spdlog::error("api_token.create (HTMX) audit emission threw: {}", ex.what());
                    audit_emitted = false;
                } catch (...) {
                    spdlog::error("api_token.create (HTMX) audit emission threw unknown");
                    audit_emitted = false;
                }
            }
            // sre-2 (gov Gate 6, sre): the HTMX surface returns 200 by
            // default because htmx swaps the fragment regardless of
            // status; the operator-facing signal is the rendered error
            // span. To stay consistent with the REST surfaces (which
            // closes #1046) we also set status=503 + Retry-After: 5 so
            // HTTP-level monitoring (LB 5xx rate, browser dev tools)
            // sees the failure correctly. htmx's hx-swap-oob fallback
            // handling continues to render the feedback span as the
            // dashboard surface for the operator.
            res.status = 503;
            res.set_header("Retry-After", "5");
            if (!audit_emitted)
                res.set_header("Sec-Audit-Failed", "true");
            res.set_content("<span class=\"feedback-error\"" +
                                std::string(audit_emitted ? "" : " data-audit-emitted=\"false\"") +
                                ">CSPRNG unavailable: " + html_escape(result.error()) + "</span>",
                            "text/html; charset=utf-8");
            return;
        }

        spdlog::info("API token '{}' created by {}", name, session->username);

        if (audit_store_) {
            // Success-path audit fire-and-forget — bool intentionally
            // discarded because the response is the success fragment
            // regardless; if the audit row fails to persist, the
            // AuditStore::emit_failed_ counter still increments and
            // the operator-visible metric paths catch it.
            (void)audit_store_->log({.principal = session->username,
                                     .principal_role = auth::role_to_string(auth::effective_role(*session)),
                                     .action = "api_token.create",
                                     .target_type = "ApiToken",
                                     .target_id = name,
                                     .source_ip = req.remote_addr,
                                     .result = "success"});
        }

        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"API token created","level":"success"}})");
        std::string filter = auth::effective_role(*session) == auth::Role::admin
                                 ? std::string{}
                                 : session->username; // JIT elevation → admin view
        res.set_content(render_api_tokens_fragment(result.value(), filter),
                        "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/api-tokens/(.+))", [this](const httplib::Request& req,
                                                           httplib::Response& res) {
        if (!perm_fn_(req, res, "ApiToken", "Delete"))
            return;
        auto session = auth_fn_(req, res);
        if (!session)
            return;
        auto token_id = req.matches[1].str();

        // Owner-scoped revocation (fixes the sibling IDOR to #222 on
        // the HTMX dashboard path). A caller with ApiToken:Delete
        // may only revoke their own tokens; the global admin role
        // is the only bypass. We return a generic "not found"
        // fragment in both the missing-id and the not-owner cases
        // so the dashboard does not become an enumeration oracle.
        auto existing = api_token_store_->get_token(token_id);
        if (!existing.has_value()) {
            // DB error on the ownership pre-check — surface a retryable error,
            // not a misleading "Token not found" that reads as already-gone
            // while the token may still be live (ADR-0012 §1).
            spdlog::error("API token '{}' ownership check failed for {}: {}", token_id,
                          session->username, existing.error());
            res.status = 503;
            res.set_header("Retry-After", "2");
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Token store unavailable — please retry","level":"error"}})");
            res.set_content(
                detail::a4_error(res, "Token store unavailable — please retry", {.retry_after_ms = 2000}),
                "application/json");
            return;
        }
        auto& tok = *existing; // std::optional<ApiToken>
        bool denied = tok && tok->principal_id != session->username &&
                      auth::effective_role(*session) != auth::Role::admin; // honour JIT elevation
        if (!tok || denied) {
            if (denied && audit_store_) {
                // [[nodiscard]] on AuditStore::log is the SOC 2 CC6.6
                // evidence-integrity flag (PR #883 HIGH-2 pattern); the
                // denied audit path already returns 404 so the persist
                // failure is bookkeeping-only here. Cast to void.
                (void)audit_store_->log({.principal = session->username,
                                         .principal_role = auth::role_to_string(auth::effective_role(*session)),
                                         .action = "api_token.revoke",
                                         .target_type = "ApiToken",
                                         .target_id = token_id,
                                         .detail = "owner=" + tok->principal_id,
                                         .source_ip = req.remote_addr,
                                         .result = "denied"});
            }
            // Return a minimal error-only fragment with zero token
            // data. An earlier iteration of this fix rendered the
            // full token table via render_api_tokens_fragment(),
            // which leaked every user's token IDs to a denied
            // probe — see governance Gate 4 unhappy-path UP-11.
            // The pre-existing "success path renders all tokens"
            // bug on `list_tokens()` with no owner filter is a
            // separate follow-up (tracked: render_api_tokens_fragment
            // must be scoped to the caller's principal or the
            // panel must become admin-only).
            res.status = 404;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Token not found","level":"error"}})");
            res.set_content(detail::a4_error(res, "Token not found"), "application/json");
            return;
        }

        auto revoked = api_token_store_->revoke_token(token_id);
        if (!revoked.has_value()) {
            // The revoke did NOT persist (lease timeout / query error). Do NOT
            // toast or audit success — that would tell an operator revoking a
            // stolen laptop's token that it died when it did not (ADR-0030
            // §Posture; the old code discarded this bool and always claimed
            // success). Audit the failure and surface a retryable error.
            spdlog::error("API token '{}' revoke did not persist (requested by {}): {}", token_id,
                          session->username, revoked.error());
            if (audit_store_) {
                (void)audit_store_->log(
                    {.principal = session->username,
                     .principal_role = auth::role_to_string(auth::effective_role(*session)),
                     .action = "api_token.revoke",
                     .target_type = "ApiToken",
                     .target_id = token_id,
                     .detail = "owner=" + tok->principal_id + " db_error=true",
                     .source_ip = req.remote_addr,
                     .result = "failure"});
            }
            res.status = 503;
            res.set_header("Retry-After", "2");
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Revoke did not persist — please retry","level":"error"}})");
            res.set_content(
                detail::a4_error(res, "Revoke did not persist — please retry", {.retry_after_ms = 2000}),
                "application/json");
            return;
        }
        if (!*revoked) {
            // DB write succeeded but no row matched — the token was already gone
            // (a concurrent revoke/delete after the ownership check). Mirror the
            // not-found fragment rather than claim a fresh revoke.
            res.status = 404;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Token not found","level":"error"}})");
            res.set_content(detail::a4_error(res, "Token not found"), "application/json");
            return;
        }

        spdlog::info("API token '{}' revoked by {}", token_id, session->username);

        if (audit_store_) {
            (void)audit_store_->log({.principal = session->username,
                                     .principal_role = auth::role_to_string(auth::effective_role(*session)),
                                     .action = "api_token.revoke",
                                     .target_type = "ApiToken",
                                     .target_id = token_id,
                                     .detail = "owner=" + tok->principal_id,
                                     .source_ip = req.remote_addr,
                                     .result = "success"});
        }

        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"API token revoked","level":"success"}})");
        std::string filter = auth::effective_role(*session) == auth::Role::admin
                                 ? std::string{}
                                 : session->username; // JIT elevation → admin view
        res.set_content(render_api_tokens_fragment({}, filter), "text/html; charset=utf-8");
    });

    // -- Settings API: Pending agents (admin only, HTMX) -----------------------

    // Bulk approve/deny — registered BEFORE the (.+) catch-all patterns
    sink.Post("/api/settings/pending-agents/bulk-approve", [this](const httplib::Request& req,
                                                                  httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        int count = 0;
        for (const auto& a : auth_mgr_->list_pending_agents()) {
            if (a.status == auth::PendingStatus::pending) {
                auth_mgr_->approve_pending_agent(a.agent_id);
                ++count;
            }
        }
        spdlog::info("Bulk approved {} pending agent(s)", count);
        res.set_header("HX-Trigger", R"({"showToast":{"message":")" + std::to_string(count) +
                                         R"( agent(s) approved","level":"success"}})");
        res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
    });

    sink.Post("/api/settings/pending-agents/bulk-deny", [this](const httplib::Request& req,
                                                               httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        int count = 0;
        for (const auto& a : auth_mgr_->list_pending_agents()) {
            if (a.status == auth::PendingStatus::pending) {
                auth_mgr_->deny_pending_agent(a.agent_id);
                ++count;
            }
        }
        spdlog::info("Bulk denied {} pending agent(s)", count);
        res.set_header("HX-Trigger", R"({"showToast":{"message":")" + std::to_string(count) +
                                         R"( agent(s) denied","level":"warning"}})");
        res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
    });

    sink.Post(R"(/api/settings/pending-agents/(.+)/approve)",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  auto agent_id = req.matches[1].str();
                  auth_mgr_->approve_pending_agent(agent_id);
                  res.set_header("HX-Trigger",
                                 R"({"showToast":{"message":"Agent approved","level":"success"}})");
                  res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
              });

    sink.Post(R"(/api/settings/pending-agents/(.+)/deny)",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  auto agent_id = req.matches[1].str();
                  auth_mgr_->deny_pending_agent(agent_id);
                  res.set_header("HX-Trigger",
                                 R"({"showToast":{"message":"Agent denied","level":"warning"}})");
                  res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
              });

    sink.Delete(R"(/api/settings/pending-agents/(.+))",
                [this](const httplib::Request& req, httplib::Response& res) {
                    if (!admin_fn_(req, res))
                        return;
                    auto agent_id = req.matches[1].str();
                    auth_mgr_->remove_pending_agent(agent_id);
                    res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
                });

    // -- Settings API: Auto-approve rules (HTMX) ------------------------------

    sink.Post("/api/settings/auto-approve",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  auto type_s = extract_form_value(req.body, "type");
                  auto value = extract_form_value(req.body, "value");
                  auto label = extract_form_value(req.body, "label");

                  auth::AutoApproveRuleType type;
                  if (type_s == "trusted_ca")
                      type = auth::AutoApproveRuleType::trusted_ca;
                  else if (type_s == "ip_subnet")
                      type = auth::AutoApproveRuleType::ip_subnet;
                  else if (type_s == "cloud_provider")
                      type = auth::AutoApproveRuleType::cloud_provider;
                  else
                      type = auth::AutoApproveRuleType::hostname_glob;

                  auto_approve_->add_rule({type, value, label, true});
                  spdlog::info("Auto-approve rule added: {}:{} ({})", type_s, value, label);
                  res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
              });

    sink.Post("/api/settings/auto-approve/mode",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  auto mode = extract_form_value(req.body, "mode");
                  auto_approve_->set_require_all(mode == "all");
                  auto_approve_->save();
                  spdlog::info("Auto-approve mode changed to {}", mode);
                  res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
              });

    sink.Post(R"(/api/settings/auto-approve/(\d+)/toggle)",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                  auto rules = auto_approve_->list_rules();
                  if (idx < rules.size()) {
                      auto_approve_->set_enabled(idx, !rules[idx].enabled);
                  }
                  res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
              });

    sink.Delete(R"(/api/settings/auto-approve/(\d+))",
                [this](const httplib::Request& req, httplib::Response& res) {
                    if (!admin_fn_(req, res))
                        return;
                    auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                    auto_approve_->remove_rule(idx);
                    spdlog::info("Auto-approve rule {} removed", idx);
                    res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
                });

    // -- Settings API: Management Groups (HTMX) --------------------------------

    sink.Post("/api/settings/management-groups", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!perm_fn_(req, res, "ManagementGroup", "Write"))
            return;
        auto name = extract_form_value(req.body, "name");
        auto parent_id = extract_form_value(req.body, "parent_id");
        auto mtype = extract_form_value(req.body, "membership_type");
        if (name.empty()) {
            res.set_content("<span class=\"feedback-error\">Name required</span>",
                            "text/html; charset=utf-8");
            return;
        }
        ManagementGroup g;
        g.name = name;
        g.parent_id = parent_id;
        g.membership_type = mtype.empty() ? "static" : mtype;
        auto session = auth_fn_(req, res);
        if (session)
            g.created_by = session->username;
        auto result = mgmt_group_store_->create_group(g);
        if (!result) {
            res.set_content("<span class=\"feedback-error\">" + result.error() + "</span>",
                            "text/html; charset=utf-8");
            return;
        }
        if (audit_store_) {
            AuditEvent ae;
            ae.principal = session ? session->username : "unknown";
            ae.action = "management_group.create";
            ae.target_type = "ManagementGroup";
            ae.target_id = *result;
            ae.detail = name;
            ae.result = "success";
            (void)audit_store_->log(ae);
        }
        res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
    });

    sink.Delete(
        R"(/api/settings/management-groups/([a-f0-9]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "ManagementGroup", "Delete"))
                return;
            auto id = req.matches[1].str();
            auto result = mgmt_group_store_->delete_group(id);
            if (!result) {
                res.set_content("<span class=\"feedback-error\">" + result.error() + "</span>",
                                "text/html; charset=utf-8");
                return;
            }
            auto session = auth_fn_(req, res);
            if (audit_store_) {
                AuditEvent ae;
                ae.principal = session ? session->username : "unknown";
                ae.action = "management_group.delete";
                ae.target_type = "ManagementGroup";
                ae.target_id = id;
                ae.result = "success";
                (void)audit_store_->log(ae);
            }
            res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
        });

    // -- Settings API: MCP toggle (HTMX POST) ---------------------------------
    sink.Post("/api/settings/mcp", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto enabled_val = extract_form_value(req.body, "enabled");
        auto read_only_val = extract_form_value(req.body, "read_only");
        cfg_->mcp_disable = (enabled_val != "true");
        cfg_->mcp_read_only = (read_only_val == "true");
        spdlog::info("MCP settings changed: enabled={}, read_only={}", !cfg_->mcp_disable,
                     cfg_->mcp_read_only);
        audit_fn_(req, "settings.mcp", "success", "MCP", "mcp_settings",
                  "enabled=" + std::string(!cfg_->mcp_disable ? "true" : "false") +
                      ", read_only=" + std::string(cfg_->mcp_read_only ? "true" : "false"));
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"MCP settings saved","level":"success"}})");
        res.set_content(render_mcp_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: Update package management (admin only) -------------------

    sink.Post("/api/settings/updates/upload", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        if (!update_registry_) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">OTA disabled.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        std::string platform, arch, rollout_s, mandatory_s;
        if (req.has_param("platform"))
            platform = req.get_param_value("platform");
        if (req.has_param("arch"))
            arch = req.get_param_value("arch");
        if (req.has_param("rollout_pct"))
            rollout_s = req.get_param_value("rollout_pct");
        if (req.has_param("mandatory"))
            mandatory_s = req.get_param_value("mandatory");

        if (!SETTINGS_REQ_HAS_FILE(req, "file")) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">No file uploaded.</span>",
                            "text/html; charset=utf-8");
            return;
        }
        // Optional detached CMS signature (#416/#3807). Optional because a fleet
        // that has not adopted signing yet must still be able to upload, and
        // because the agent — not this server — decides whether an unsigned
        // package is acceptable. Uploading one here does not make it trusted:
        // the agent checks it against an anchor this server never supplies.
        std::string signature_pem;
        if (SETTINGS_REQ_HAS_FILE(req, "signature")) {
            signature_pem = SETTINGS_REQ_GET_FILE(req, "signature").content;
            if (signature_pem.size() > kMaxSignatureBytes) {
                res.status = 400;
                res.set_content("<span class=\"feedback-error\">Signature file is too large "
                                "(max 64 KB). A detached CMS signature is a few KB — check you "
                                "selected the .sig file and not the binary.</span>",
                                "text/html; charset=utf-8");
                return;
            }
        }

        auto uploaded = SETTINGS_REQ_GET_FILE(req, "file");
        // Case-INSENSITIVE: the server may store packages on a case-insensitive
        // filesystem (macOS, Windows), where "foo.SIG" and "foo.sig" are the
        // same file, so a case-sensitive guard is bypassable there.
        auto ends_with_sig = [](std::string n) {
            if (n.size() < 4)
                return false;
            n = n.substr(n.size() - 4);
            std::transform(n.begin(), n.end(), n.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return n == ".sig";
        };
        if (ends_with_sig(uploaded.filename)) {
            // Signature sidecars are derived as "<binary>.sig", so a package
            // literally named X.sig would occupy package X's sidecar slot. It
            // fails closed (X's agents then see a signature over the wrong
            // bytes and refuse), but the cause would be invisible.
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">Package filenames may not end in "
                            "'.sig' — that suffix is reserved for signature sidecars.</span>",
                            "text/html; charset=utf-8");
            return;
        }
        if (uploaded.content.empty()) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">Empty file.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        int rollout_pct = 100;
        try {
            if (!rollout_s.empty())
                rollout_pct = std::stoi(rollout_s);
        } catch (...) {}
        if (rollout_pct < 0)
            rollout_pct = 0;
        if (rollout_pct > 100)
            rollout_pct = 100;

        // Shape-check the signature BEFORE the binary is written. A well-sized
        // file of garbage would otherwise be stored, reported "signed" by the
        // settings column, served by CheckForUpdate, and then refused by every
        // anchored agent in BOTH enforcement modes — including permissive, where
        // the documented contract is that unsigned packages are accepted with a
        // warning. The operator's only signal would be a fleet gauge rising after
        // the fact.
        //
        // Placed here, ahead of the write, so a rejection leaves the PREVIOUS
        // package and its signature completely untouched: the operator retries an
        // upload rather than recovering a half-replaced package.
        if (!signature_pem.empty() && !looks_like_pem_cms(signature_pem)) {
            spdlog::warn("OTA upload for {}/{}: rejected — the signature is not PEM-armoured CMS",
                         platform, arch);
            // 400, not the httplib default. Leaving the status unset answered 200
            // for an upload that wrote nothing, so a scripted uploader recorded
            // success and the fleet silently kept the old package. 400 rather than
            // 500 because the input is malformed — the server is fine.
            res.status = 400;
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"That signature file is not a PEM CMS )"
                           R"(signature (expected a -----BEGIN CMS----- block). Nothing was )"
                           R"(changed.","level":"error"}})");
            res.set_content(
                detail::a4_error(res, "That signature file is not a PEM CMS signature "
                                       "(expected a -----BEGIN CMS----- block). Nothing was "
                                       "changed."),
                "application/json");
            return;
        }

        auto orig_name =
            uploaded.filename.empty() ? "yuzu-agent-" + platform + "-" + arch : uploaded.filename;

        // #3863: the name is operator-supplied and every artifact path is built
        // from it — the binary, its .sig sidecar and the .upload staging file —
        // so a traversal or absolute name writes all three outside update_dir_.
        // Rejected BEFORE any path is derived from it.
        if (!is_safe_package_filename(orig_name)) {
            spdlog::warn("OTA upload for {}/{}: rejected unsafe package filename", platform, arch);
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">The package filename must be a plain "
                            "filename \u2014 no directory separators, drive letters, or "
                            "<code>..</code>.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto out_path =
            update_registry_->binary_path(UpdatePackage{platform, arch, "", "", orig_name});
        std::error_code ec;
        std::filesystem::create_directories(out_path.parent_path(), ec);

        // ORDERING RULE: THE STEP THAT WEAKENS THE SIGNATURE GOES LAST.
        //
        // Which step that is depends on the upload, so the order is not fixed:
        //
        //   signed upload   -> sidecar, then binary. Writing the binary first
        //                      leaves new-binary + no-signature if we die in
        //                      between, and on the FIRST signed upload of a
        //                      filename there is no predecessor to fall back on,
        //                      so that window spans the whole signing rollout.
        //
        //   unsigned upload -> binary, then remove the sidecar. Removing first
        //                      leaves OLD-binary + no-signature if the binary
        //                      write then fails, which strips protection from a
        //                      package still being served. (This is the hole the
        //                      first version of this reorder left: it removed
        //                      unconditionally up front.)
        //
        // Both orders leave only fail-closed intermediates: a mismatched pair,
        // which every anchored agent refuses. Never the unprotected pair.
        //
        // The sidecar path derives from the filename alone (UpdateRegistry::
        // signature_path -> binary_path = update_dir_ / filename), so it is known
        // here, before `pkg` exists.
        const auto sidecar_path = signature_sidecar_path(out_path);
        const bool signed_upload = !signature_pem.empty();

        if (signed_upload && !replace_signature_sidecar(sidecar_path, signature_pem)) {
            // Nothing has been written yet: the previous binary and its signature
            // are both untouched, so this is a clean refusal, not a partial state.
            spdlog::error("OTA upload for {}/{}: the signature sidecar could not be written; "
                          "the previous package is unchanged",
                          platform, arch);
            res.status = 500;
            res.set_content("<span class=\"feedback-error\">Could not store the signature. "
                            "Nothing was changed \u2014 retry the upload.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        // STAGE AND RENAME, for the same reason the sidecar does. Writing in place
        // with ios::trunc means an ENOSPC part-way through leaves a TRUNCATED
        // binary on the live path — and one whose mtime is NEWER than the sidecar,
        // so the mtime consistency check sees a well-ordered pair and the column
        // reports "signed" for a package whose signature covers nothing that is
        // there. Staging keeps a partial write off the served path entirely.
        //
        // The staging name carries the request's own suffix: a fixed name lets two
        // concurrent uploads of the same filename interleave into one file, and
        // whichever rename loses publishes bytes that do not match its own row.
        static std::atomic<unsigned long long> upload_seq{0};
        auto bin_tmp = out_path;
        bin_tmp += ".upload." + std::to_string(upload_seq.fetch_add(1)) + ".tmp";

        const auto fail_binary = [&](const char* msg) {
            std::error_code rm_ec;
            std::filesystem::remove(bin_tmp, rm_ec);
            res.status = 500;
            res.set_content(std::string("<span class=\"feedback-error\">") + msg + "</span>",
                            "text/html; charset=utf-8");
        };

        {
            std::ofstream f(bin_tmp, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                fail_binary("Cannot write file.");
                return;
            }
            f.write(uploaded.content.data(), static_cast<std::streamsize>(uploaded.content.size()));
            // Same reasoning as the sidecar's own close: testing before
            // destruction misses whatever ~ofstream flushes, and a truncated
            // agent binary that reports success is a fleet-wide apply failure.
            f.close();
            if (!f) {
                fail_binary("Could not write the binary completely.");
                return;
            }
        }
        // Durable before publication, matching the sidecar. Without this a crash
        // just after the rename can expose the live name pointing at unflushed
        // (zero-length) bytes.
        if (!fsync_file(bin_tmp)) {
            fail_binary("Could not flush the uploaded binary to disk.");
            return;
        }
        std::error_code bin_ren_ec;
        std::filesystem::rename(bin_tmp, out_path, bin_ren_ec);
        if (bin_ren_ec) {
            fail_binary("Could not publish the uploaded binary.");
            return;
        }

        // The binary is live. NOW drop the signature, if this upload is unsigned —
        // last, per the ordering rule above, so no failure above this line could
        // have left the served package unprotected.
        if (!signed_upload && !replace_signature_sidecar(sidecar_path, signature_pem)) {
            spdlog::error("OTA upload for {}/{}: the stale signature could not be removed; "
                          "the package is served with a signature that does not cover it",
                          platform, arch);
            res.status = 500;
            res.set_content("<span class=\"feedback-error\">The binary was published but its "
                            "old signature could not be removed. Agents will refuse this "
                            "package until you retry.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto sha = auth::AuthManager::sha256_hex(uploaded.content);
        auto version = orig_name;
        for (const auto* ext : {".exe", ".bin", ".tar.gz", ".zip", ".msi"}) {
            if (version.size() > std::strlen(ext) &&
                version.substr(version.size() - std::strlen(ext)) == ext) {
                version = version.substr(0, version.size() - std::strlen(ext));
                break;
            }
        }

        UpdatePackage pkg;
        pkg.platform = platform;
        pkg.arch = arch;
        pkg.version = version;
        pkg.sha256 = sha;
        pkg.filename = orig_name;
        pkg.mandatory = (mandatory_s == "true");
        pkg.rollout_pct = rollout_pct;
        pkg.file_size = static_cast<int64_t>(uploaded.content.size());

        // Upload path: the row is best-effort here and the failure is already
        // visible in the log; the rollout path is the one that audits a committed
        // transition and therefore must not discard this.
        (void)update_registry_->upsert_package(pkg);
        spdlog::info("OTA package uploaded: {}/{} v{} ({}B, rollout={}%)", platform, arch, version,
                     pkg.file_size, rollout_pct);

        if (!signature_pem.empty())
            spdlog::info("OTA package {}: detached signature stored ({} bytes)", pkg.filename,
                         signature_pem.size());

        // AUDIT. This changes what code the fleet will execute, so it belongs in
        // the evidence store, not only in the server log. `signed=` is the field
        // that matters: an upload with the Signature field left empty silently
        // downgrades the package from signed to unsigned for every endpoint, and
        // without this row that transition has no actor, no timestamp and no
        // outcome. The sibling plugin_signing.bundle.* handler in this same file
        // has recorded exactly this for its own trust artifact all along.
        audit_fn_(req, "ota.package.uploaded", "success", "UpdatePackage",
                  platform + "/" + arch + "/" + version,
                  "file=" + orig_name + " sha256=" + sha +
                      " signed=" + (signature_pem.empty() ? "false" : "true") +
                      " rollout=" + std::to_string(rollout_pct) + "%");

        res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+))",
                [this](const httplib::Request& req, httplib::Response& res) {
                    if (!admin_fn_(req, res))
                        return;
                    if (!update_registry_) {
                        res.status = 400;
                        return;
                    }

                    auto platform = req.matches[1].str();
                    auto arch = req.matches[2].str();
                    auto version = req.matches[3].str();

                    PackageDeleteOutcome outcome;
                    // Each remove gets its OWN error_code. Sharing one lets the
                    // second call's result overwrite the first, so a failed
                    // binary delete followed by a clean sidecar delete reads as
                    // wholly successful.
                    std::error_code bin_ec;
                    std::error_code sig_ec;
                    auto packages = update_registry_->list_packages();
                    for (const auto& pkg : packages) {
                        if (pkg.platform == platform && pkg.arch == arch &&
                            pkg.version == version) {
                            outcome.matched = true;
                            auto bin_path = update_registry_->binary_path(pkg);
                            outcome.binary_removed = std::filesystem::remove(bin_path, bin_ec);
                            // Remove the signature sidecar with it. Leaving it
                            // behind would let a later upload of a same-named
                            // package inherit a signature made over DIFFERENT
                            // bytes — which the agent would then reject as
                            // tampered, with no obvious cause.
                            outcome.signature_removed = std::filesystem::remove(
                                update_registry_->signature_path(pkg), sig_ec);
                            if (bin_ec) {
                                outcome.binary_error = bin_ec.message();
                            }
                            if (sig_ec) {
                                outcome.signature_error = sig_ec.message();
                            }
                            break;
                        }
                    }

                    update_registry_->remove_package(platform, arch, version);
                    spdlog::info("OTA package deleted: {}/{} v{}", platform, arch, version);
                    // Audited for the same reason as the upload: this removes a
                    // binary AND its signature from the fleet's update surface.
                    // Report what actually happened. A delete naming a package that
                    // is not there removes nothing, and recording that as a
                    // successful removal puts a fictional event in the evidence
                    // store — and hides probing of the endpoint from a SIEM rule.
                    //
                    // The result/detail derivation is a pure function in
                    // ota_signature_sidecar.hpp — including why a failed unlink is
                    // never audited as a removal, and why the rejection token is
                    // `denied` rather than a bespoke `not_found`. It lives there
                    // because the failed-unlink branch cannot be reached from a
                    // unit test of this route.
                    const auto audit = describe_package_delete(outcome);
                    audit_fn_(req, "ota.package.deleted", audit.result, "UpdatePackage",
                              platform + "/" + arch + "/" + version, audit.detail);
                    res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
                });

    sink.Post(R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout)",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  if (!update_registry_) {
                      res.status = 400;
                      return;
                  }

                  auto platform = req.matches[1].str();
                  auto arch = req.matches[2].str();
                  auto version = req.matches[3].str();
                  auto pct_s = extract_form_value(req.body, "rollout_pct");

                  int pct = 100;
                  try {
                      if (!pct_s.empty())
                          pct = std::stoi(pct_s);
                  } catch (...) {}
                  if (pct < 0)
                      pct = 0;
                  if (pct > 100)
                      pct = 100;

                  // Capture the PRIOR percentage before the write. It is the whole
                  // evidentiary value of this row: #3692's scenario is an admin —
                  // or a compromised admin session — silently de-prioritising a
                  // mandatory security patch, and "rollout is 0%" does not
                  // distinguish that from a package that was never rolled out.
                  // "from=100% to=0%" does. `mandatory` is carried for the same
                  // reason: it is what makes the de-prioritisation consequential.
                  // A CHECKED read, NOT list_packages: the ordinary reads on
                  // this store fail SOFT, returning an empty vector on a closed
                  // store, a pool-acquire timeout or a query error. That carve-out
                  // (ADR-0061) was granted because no downstream branch treated an
                  // empty list as a signal — and an audit branch does. Deriving
                  // "not_found" from a soft-failed read would let a PG blip during
                  // a legitimate admin rollout both manufacture key-enumeration
                  // alerts (audit-log.md names `denied` as that filter) and assert,
                  // in the evidence record, that a package which exists did not.
                  // ONE store call, not a find-then-upsert pair. Read and write
                  // are the same row-locked transaction, so the `from=` this row
                  // reports is provably the value the commit replaced. As two
                  // autocommit statements a concurrent write to the same key
                  // could land between them — and it does not take two admins:
                  // one session firing two near-simultaneous requests is enough,
                  // which is exactly the compromised-admin case #3692 exists to
                  // catch. Same shape as `AuditStore::stamp_complete` (ADR-0040,
                  // #2697); see update_registry.hpp.
                  auto change =
                      update_registry_->update_rollout_checked(platform, arch, version, pct);
                  // NOT `status == kFound`: the row can be found inside the
                  // transaction and the write still fail to commit, which is a
                  // distinct outcome the audit row reports differently.
                  const bool committed = change.committed;
                  if (committed)
                      spdlog::info("OTA rollout updated: {}/{} v{} {}% -> {}%", platform, arch,
                                   version, change.prior_rollout_pct, pct);
                  else if (change.status == UpdateRegistry::PackageLookup::kFound)
                      spdlog::error("OTA rollout NOT applied for {}/{} v{}: the package exists "
                                    "at {}% but the registry write did not commit",
                                    platform, arch, version, change.prior_rollout_pct);
                  else if (change.status == UpdateRegistry::PackageLookup::kUnavailable)
                      spdlog::error("OTA rollout for {}/{} v{}: the registry could not be read; "
                                    "the package's existence is UNKNOWN, not absent",
                                    platform, arch, version);

                  // Audited AFTER the write, and reporting what actually happened.
                  // A rollout change alters which endpoints receive a given binary,
                  // so it belongs in the same evidence chain as the upload and the
                  // delete; `spdlog::info` is the application log, not the audit
                  // log, and nothing else in the request path emits an audit row.
                  //
                  // A request naming a package that does not exist changes nothing,
                  // so it must not record a fictional success. The token is
                  // `denied` with the reason in `detail`, NOT a bespoke
                  // `not_found` result: this file's own rejection branches use
                  // that shape (`user.delete` -> "denied" / "invalid_username"),
                  // and audit-log.md's probe-detection recipe tells operators to
                  // filter on `result == "denied"` to surface enumeration — a
                  // fourth token would be invisible to exactly the rule this row
                  // exists to feed.
                  // THE RESULT IS DERIVED FROM THE COMMIT, NOT FROM THE LOOKUP.
                  // `upsert_package` degrades silently on a closed store, a
                  // pool-acquire timeout or a query error, so deriving `success`
                  // from "we found the package" would let this row assert a
                  // "from=100% to=0%" transition that never reached the database —
                  // evidence disagreeing with state, in the one record an incident
                  // responder is meant to be able to trust. `failure` is the
                  // documented token for a failure the handler audits itself.
                  // THREE DISTINCT OUTCOMES, and the store-degraded one is NOT
                  // absence. `denied` is reserved for a package the store actually
                  // reported as absent, because audit-log.md tells operators to
                  // filter on it to surface enumeration; a degraded read reports
                  // `failure`, which is the documented token for a failure the
                  // handler audits itself. Neither the degraded nor the
                  // uncommitted branch may claim a `from=`/`to=` transition — the
                  // detail records what was ATTEMPTED, which asserts nothing false.
                  const char* result = "failure";
                  std::string detail;
                  switch (change.status) {
                  case UpdateRegistry::PackageLookup::kFound:
                      result = committed ? "success" : "failure";
                      // `from=` is now provably the value this write replaced —
                      // it was read under a row lock in the same transaction, so
                      // no concurrent writer can have changed it in between.
                      detail = (committed ? "from=" : "attempted_from=") +
                               std::to_string(change.prior_rollout_pct) +
                               (committed ? "% to=" : "% attempted_to=") + std::to_string(pct) +
                               "% mandatory=" + (change.prior_mandatory ? "true" : "false") +
                               (committed ? "" : " outcome=write_not_committed");
                      break;
                  case UpdateRegistry::PackageLookup::kAbsent:
                      result = "denied";
                      detail = "not_found";
                      break;
                  case UpdateRegistry::PackageLookup::kUnavailable:
                      result = "failure";
                      detail = "attempted_to=" + std::to_string(pct) +
                               "% outcome=store_unavailable existence_unknown=true";
                      break;
                  }
                  audit_fn_(req, "ota.package.rollout_changed", result, "UpdatePackage",
                            platform + "/" + arch + "/" + version, detail);

                  res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
              });

    // ── MFA / TOTP self-service (`/auth-and-authz` P0 #1, SOC 2 CC6.6) ──────
    //
    // Admin-only for PR1 — non-admin operator UX is a follow-up. Each
    // mutation re-renders the panel via the same `#mfa-section` target so
    // the new state (or one-time reveal) lands without a full page reload.
    //
    // Audit verbs use `target_type="User"` (PascalCase per
    // observability-conventions.md spec) and `result ∈ {ok, error}`
    // (spec vocabulary), distinct from the historical lowercase
    // `target_type="user"` + `success/failure` used elsewhere in
    // auth_routes — Gate 4 consistency B1+B2 picks the spec lane.
    //
    // `Cache-Control: no-store, private` is set on every response that
    // contains a one-time secret (init's otpauth URI / base32 secret,
    // verify's recovery codes, recovery-codes regenerate) so the
    // browser/proxy/CDN cannot retain the material past the response
    // lifetime (Gate 4 unhappy-path UP-9).
    auto set_no_store = [](httplib::Response& res) {
        res.set_header("Cache-Control", "no-store, private");
        res.set_header("Pragma", "no-cache");
        res.set_header("Referrer-Policy", "no-referrer");
    };

    // Origin/Referer CSRF gate — Hermes Agent red-team finding MEDIUM #2
    // (2026-05-29). Every Settings MFA POST mutates per-user MFA state
    // using session-cookie auth alone.
    //
    // Corrected on #2641 review: an earlier version of this comment said
    // `SameSite=Lax` "is not strict enough to stop a cross-site form POST".
    // That is wrong. Lax sends the cookie on a cross-site top-level
    // navigation only for SAFE methods; POST is not safe, so a purely
    // cross-site form POST arrives with no cookie at all. (Chrome's
    // Lax+POST intervention applies only to cookies with NO SameSite
    // attribute — `auth_routes.cpp` sets it explicitly.) What the gate
    // closes is a SAME-SITE sibling origin: subdomain takeover, XSS on a
    // neighbour, a shared-domain deployment. Those carry the cookie and
    // are a different origin, which is what Origin/Referer catches.
    //
    // We require Origin (or Referer as fallback) to carry the
    // same host as the request's Host header; absence means a non-
    // browser caller (curl, automation) which is explicitly allowed
    // because programmatic admin clients post without an Origin header.
    // Mismatched host → 403, audited as csrf.denied for SIEM correlation.
    //
    // Hardenings from the re-review round of the Hermes fixes:
    //  - audit detail is sanitised (Gate 2 MEDIUM) — operator-controlled
    //    header bytes go through a control-char-stripping helper capped
    //    at 128 bytes per field so they cannot poison the audit row;
    //  - default ports are normalised (Gate 2 LOW) so a reverse proxy
    //    that strips `:443` / `:80` from `Host` does not false-deny
    //    legitimate same-origin POSTs;
    //  - userinfo / fragment / query chars are rejected (Gate 2 LOW) —
    //    RFC 6454 forbids userinfo in `Origin` and httplib does not
    //    validate URL shape, so anything containing `@`, `?`, or `#`
    //    is treated as a fail-closed mismatch.
    //
    // Scoping note (Gate 4 SHOULD S2 — known follow-up): origin_safe is
    // wired into the 4 mutating MFA POSTs only. 11 sibling state-
    // changing Settings POSTs (/api/settings/users/*, plugin-signing,
    // OIDC, cert, enrollment-tokens, tls) remain CSRF-unprotected
    // pending a follow-up PR that wraps every admin HTMX mutation. The
    // asymmetric defence is documented in CHANGELOG and is NOT a
    // regression introduced by this PR — those sites were unprotected
    // before PR1 too.
    auto sanitise = [](std::string_view in, std::size_t max_len = 128) -> std::string {
        std::string out;
        out.reserve(std::min(in.size(), max_len));
        for (char c : in) {
            if (out.size() >= max_len)
                break;
            unsigned char u = static_cast<unsigned char>(c);
            // Strip C0 controls, DEL, and high-bit bytes — exact policy
            // from fleet_topology_store.cpp::sanitise_for_audit.
            if (u < 0x20 || u == 0x7f || u >= 0x80) {
                out.push_back(' ');
            } else {
                out.push_back(static_cast<char>(u));
            }
        }
        return out;
    };
    auto origin_safe = [this, sanitise](const httplib::Request& req, httplib::Response& res,
                                        const std::string& action_for_audit) -> bool {
        auto host = req.get_header_value("Host");
        auto origin = req.get_header_value("Origin");
        auto referer = req.get_header_value("Referer");

        // Shared same-site comparison (web_utils) — one implementation across
        // settings + ca_routes (#1241 H-1). This site keeps the 403 + csrf.denied
        // audit; ca_routes' dashboard revoke calls the same helper.
        //
        // The operator-declared external-origin allowlist (#2537) comes straight
        // from Config here, because this owner already holds one. CaRoutes and
        // DashboardRoutes take theirs via set_csrf_trusted_origins() rather than
        // acquire a Config dependency they otherwise have no use for. A null
        // cfg_ yields an empty span — same-host only, fail-closed, never open.
        if (origin_is_same_site(host, origin, referer,
                                cfg_ ? std::span<const std::string>(cfg_->csrf_trusted_origins)
                                     : std::span<const std::string>{})) {
            return true;
        }
        res.status = 403;
        res.set_content(detail::a4_error(res, "cross-origin POST refused"), "application/json");
        audit_fn_(req, "csrf.denied", "error", "Endpoint", action_for_audit,
                  "Origin/Referer host mismatch (Origin=" + sanitise(origin) +
                      " Referer=" + sanitise(referer) + " Host=" + sanitise(host) + ")");
        return false;
    };

    sink.Get("/fragments/settings/mfa", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session || session->username.empty()) {
            res.status = 401;
            return;
        }
        res.set_content(render_mfa_fragment(session->username), "text/html; charset=utf-8");
    });

    sink.Post("/api/settings/mfa/init", [this, set_no_store, origin_safe](
                                            const httplib::Request& req, httplib::Response& res) {
        if (!origin_safe(req, res, "/api/settings/mfa/init"))
            return;
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session || session->username.empty()) {
            res.status = 401;
            return;
        }
        auto* db = auth_mgr_ ? auth_mgr_->auth_db_ptr() : nullptr;
        if (!db) {
            audit_fn_(req, "mfa.enroll.initiated", "error", "User", session->username,
                      "auth_db unavailable");
            res.set_content(
                render_mfa_fragment(session->username, {}, {}, {}, {}, "MFA backend unavailable"),
                "text/html; charset=utf-8");
            return;
        }
        auto init = db->mfa_init_enrollment(session->username, "Yuzu");
        if (!init) {
            const char* msg = "Enrollment failed";
            if (init.error() == AuthDBError::MfaAlreadyEnrolled) {
                msg = "MFA is already enabled — disable it first to re-enroll";
            } else if (is_store_unavailable(init.error())) {
                // ★ SECURITY (architect BLOCK follow-through): distinguish a
                // store/decrypt failure from a generic enrollment error —
                // never mislead the operator into retrying a fundamentally
                // broken step; no MFA state changes either way.
                msg = "Authentication store is temporarily unavailable — retry shortly";
                if (metrics_registry_) {
                    metrics_registry_
                        ->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_enroll"}})
                        .increment();
                }
            }
            audit_fn_(req, "mfa.enroll.initiated", "error", "User", session->username, msg);
            res.set_content(render_mfa_fragment(session->username, {}, {}, {}, {}, msg),
                            "text/html; charset=utf-8");
            return;
        }
        audit_fn_(req, "mfa.enroll.initiated", "ok", "User", session->username, "");
        set_no_store(res);
        res.set_content(render_mfa_fragment(session->username, init->otpauth_uri,
                                            init->secret_base32, {}, session->username),
                        "text/html; charset=utf-8");
    });

    sink.Post("/api/settings/mfa/verify",
              [this, set_no_store, origin_safe](const httplib::Request& req,
                                                httplib::Response& res) {
                  if (!origin_safe(req, res, "/api/settings/mfa/verify"))
                      return;
                  if (!admin_fn_(req, res))
                      return;
                  auto session = auth_fn_(req, res);
                  if (!session || session->username.empty()) {
                      res.status = 401;
                      return;
                  }
                  auto code = extract_form_value(req.body, "code");
                  auto* db = auth_mgr_ ? auth_mgr_->auth_db_ptr() : nullptr;
                  if (!db) {
                      res.set_content(render_mfa_fragment(session->username, {}, {}, {}, {},
                                                          "MFA backend unavailable"),
                                      "text/html; charset=utf-8");
                      return;
                  }
                  auto codes_res = db->mfa_verify_enrollment(session->username, code);
                  if (!codes_res) {
                      // Re-render the verify form (no QR re-reveal — the
                      // provisional row survives so the operator's
                      // authenticator app still works at the next 30s
                      // step). Setting `enrollment_pending_for_verify`
                      // routes the renderer to the retry shape; leaving
                      // `new_otpauth_uri` empty suppresses the
                      // one-time secret reveal (Gate 4 happy-path B3).
                      //
                      // ★ SECURITY (architect BLOCK follow-through): a
                      // store/decrypt failure is NOT "code rejected" — never
                      // conflate the two (no enrollment completes / no
                      // recovery codes are issued either way, but the
                      // operator-facing message and audit detail must be
                      // honest about which happened).
                      // The account is already enrolled — a concurrent verify won
                      // the race (or it was already enrolled). It is NOT a rejected
                      // code and NOT a store outage — audit it distinctly so it
                      // does not inflate bad-code-attempt counts (#3777, CC7.2),
                      // and tell the operator the true state rather than "code
                      // rejected". `MfaAlreadyEnrolled` is not in
                      // is_store_unavailable(), so no false 503/degrade path. (A
                      // bare disable+re-init without a subsequent winning verify
                      // leaves mfa_enrolled_at NULL, so it does NOT reach here — it
                      // stays fail-closed WriteFailed.)
                      if (codes_res.error() == AuthDBError::MfaAlreadyEnrolled) {
                          audit_fn_(req, "mfa.enroll.race", "ok", "User", session->username,
                                    "already enrolled by a concurrent verify; no duplicate "
                                    "enrollment");
                          res.set_content(
                              render_mfa_fragment(session->username, {}, {}, {}, session->username,
                                                  "MFA is already enrolled on this account."),
                              "text/html; charset=utf-8");
                          return;
                      }
                      const bool store_unavailable = is_store_unavailable(codes_res.error());
                      if (store_unavailable && metrics_registry_) {
                          metrics_registry_
                              ->counter("yuzu_auth_secret_unavailable_total",
                                       {{"route", "mfa_enroll"}})
                              .increment();
                      }
                      audit_fn_(req, "mfa.enroll.failed", "error", "User", session->username,
                                store_unavailable ? "secret/store unavailable (fail-closed)"
                                                  : "code rejected");
                      const char* msg =
                          store_unavailable
                              ? "Authentication store is temporarily unavailable — retry shortly."
                              : "Code rejected. Try the next code shown by your authenticator "
                                "(codes refresh every 30 seconds).";
                      res.set_content(render_mfa_fragment(session->username, {}, {}, {},
                                                          session->username, msg),
                                      "text/html; charset=utf-8");
                      return;
                  }
                  audit_fn_(req, "mfa.enroll.verified", "ok", "User", session->username, "");
                  audit_fn_(req, "mfa.recovery_codes.generated", "ok", "User",
                            session->username, "10 codes issued");
                  set_no_store(res);
                  res.set_content(render_mfa_fragment(session->username, {}, {}, *codes_res),
                                  "text/html; charset=utf-8");
              });

    sink.Post("/api/settings/mfa/recovery-codes",
              [this, set_no_store, origin_safe](const httplib::Request& req,
                                                httplib::Response& res) {
                  if (!origin_safe(req, res, "/api/settings/mfa/recovery-codes"))
                      return;
                  if (!admin_fn_(req, res))
                      return;
                  auto session = auth_fn_(req, res);
                  if (!session || session->username.empty()) {
                      res.status = 401;
                      return;
                  }
                  auto* db = auth_mgr_ ? auth_mgr_->auth_db_ptr() : nullptr;
                  if (!db) {
                      res.set_content(render_mfa_fragment(session->username, {}, {}, {}, {},
                                                          "MFA backend unavailable"),
                                      "text/html; charset=utf-8");
                      return;
                  }
                  auto codes = db->mfa_regenerate_recovery_codes(session->username);
                  if (!codes) {
                      audit_fn_(req, "mfa.recovery_codes.generated", "error", "User",
                                session->username, "regeneration failed");
                      res.set_content(
                          render_mfa_fragment(session->username, {}, {}, {}, {},
                                              "Could not regenerate codes"),
                          "text/html; charset=utf-8");
                      return;
                  }
                  audit_fn_(req, "mfa.recovery_codes.generated", "ok", "User",
                            session->username, "10 codes issued (rotation)");
                  set_no_store(res);
                  res.set_content(render_mfa_fragment(session->username, {}, {}, *codes),
                                  "text/html; charset=utf-8");
              });

    sink.Post("/api/settings/mfa/disable",
              [this, origin_safe](const httplib::Request& req, httplib::Response& res) {
                  if (!origin_safe(req, res, "/api/settings/mfa/disable"))
                      return;
                  if (!admin_fn_(req, res))
                      return;
                  auto session = auth_fn_(req, res);
                  if (!session || session->username.empty()) {
                      res.status = 401;
                      return;
                  }
                  auto* db = auth_mgr_ ? auth_mgr_->auth_db_ptr() : nullptr;
                  if (!db) {
                      res.set_content(render_mfa_fragment(session->username, {}, {}, {}, {},
                                                          "MFA backend unavailable"),
                                      "text/html; charset=utf-8");
                      return;
                  }
                  // Self-target guard (PR3 / docs-mfa invariant #7). Under an
                  // active enforcement mode an operator may not strip MFA
                  // from their own account: it would force re-enrollment at
                  // their next login and leave the current privileged
                  // session unable to clear the step-up gate. `required`
                  // protects every role; `admin-only` protects admins. The
                  // block is audited and surfaced inline (matching the
                  // handler's other error paths — fragment + message, no
                  // status override, so the HTMX swap still renders).
                  const std::string mfa_mode = cfg_ ? cfg_->mfa_enforcement : "optional";
                  const bool enforcement_protects_self =
                      mfa_enforcement_protects(mfa_mode, session->role);
                  if (enforcement_protects_self) {
                      audit_fn_(req, "mfa.disabled", "error", "User", session->username,
                                "blocked: mfa_enforcement=" + mfa_mode);
                      res.set_content(
                          render_mfa_fragment(
                              session->username, {}, {}, {}, {},
                              "MFA is required by policy (enforcement=" + mfa_mode +
                                  ") and cannot be disabled for your account."),
                          "text/html; charset=utf-8");
                      return;
                  }
                  auto r = db->mfa_disable(session->username);
                  if (!r) {
                      audit_fn_(req, "mfa.disabled", "error", "User", session->username,
                                "disable failed");
                      res.set_content(render_mfa_fragment(session->username, {}, {}, {}, {},
                                                          "Could not disable MFA"),
                                      "text/html; charset=utf-8");
                      return;
                  }
                  audit_fn_(req, "mfa.disabled", "ok", "User", session->username, "");
                  res.set_content(render_mfa_fragment(session->username),
                                  "text/html; charset=utf-8");
              });
}

} // namespace yuzu::server
