// Pure renderers for the Security page panels — see settings_security_render.hpp.

#include "settings_security_render.hpp"

#include "web_utils.hpp"

#include <string_view>

namespace yuzu::server::security_render {

const char* const kConfirmSaveSso =
    "Save single sign-on settings? New SSO sign-ins use these values immediately. After a "
    "restart the server uses its start-up flags or environment again, so update those too. If "
    "you change or clear the Admin group ID, SSO administrators sign in as ordinary users from "
    "their next sign-in.";
const char* const kConfirmMtls =
    "Change the gRPC mTLS setting shown here? This only changes what this server reports. It is "
    "not saved and does not change the running listeners; the start-up flags decide.";
const char* const kConfirmRegenerateCodes =
    "Regenerate recovery codes? All current codes stop working, including unused ones.";
const char* const kConfirmDisableMfa =
    "Disable MFA for your account? Step-up authentication will no longer be required.";

namespace {

// One label / value row of a .kvl list. `value_html` is already-safe markup.
void kv(std::string& out, std::string_view label, const std::string& value_html) {
    out += "<div><span>";
    out += label;
    out += "</span><b>";
    out += value_html;
    out += "</b></div>";
}

std::string pill(std::string_view cls, std::string_view text) {
    std::string s = "<span class=\"pill ";
    s += cls;
    s += "\">";
    s += text;
    s += "</span>";
    return s;
}

std::string mono_or(const std::string& v, std::string_view fallback) {
    if (v.empty())
        return "<span class=\"muted\">" + std::string(fallback) + "</span>";
    return "<span class=\"mono\">" + html_escape(v) + "</span>";
}

// hx-confirm is a static attribute; the text is escaped here, never built from request data.
std::string confirm_attr(const std::string& text) {
    return " hx-confirm=\"" + html_escape(text) + "\"";
}

std::string replace_confirm(std::string_view slot) {
    return "Replace the agent connection " + std::string(slot) +
           " file? The existing file is overwritten with no backup. The running server keeps the "
           "certificates it loaded at start. After a restart the server uses this file only if "
           "--cert, --key and --ca-cert name it. If they do and the material is wrong, the "
           "server will not start.";
}

// One certificate slot: current path, an Upload form (auto-submits on file choice, behind the
// confirm) and a Paste form. The file input is visually hidden but focusable (.vh inside a
// .tls-file label) so the keyboard path a <button> gave is kept.
void tls_slot(std::string& out, std::string_view type, std::string_view label,
              std::string_view slot_noun, std::string_view accept, const std::string& path,
              std::string_view placeholder, bool pins_server_cert) {
    const std::string confirm = confirm_attr(replace_confirm(slot_noun));
    out += "<div class=\"tls-slot\" data-slot=\"";
    out += type;
    out += "\"><div class=\"kvl\">";
    kv(out, label, mono_or(path, "No file"));
    out += "</div>";
    if (pins_server_cert)
        out += "<p class=\"hint\">The gateway command plane pins the server certificate; changing "
               "it can stop command forwarding.</p>";
    out += "<div class=\"btns\">"
           "<form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
           "hx-swap=\"innerHTML\" hx-encoding=\"multipart/form-data\" hx-trigger=\"change\"" +
           confirm +
           "><input type=\"hidden\" name=\"type\" value=\"" + std::string(type) +
           "\"><label class=\"btn btn-secondary tls-file\">Upload PEM<input class=\"vh\" "
           "type=\"file\" name=\"file\" accept=\"" +
           std::string(accept) +
           "\"></label></form>"
           "<details><summary class=\"btn btn-secondary\">Paste PEM</summary>"
           "<form hx-post=\"/api/settings/cert-paste\" hx-target=\"#tls-feedback\" "
           "hx-swap=\"innerHTML\"" +
           confirm + "><input type=\"hidden\" name=\"type\" value=\"" + std::string(type) +
           "\"><div class=\"fld\"><textarea name=\"content\" autocomplete=\"off\" "
           "spellcheck=\"false\" autocapitalize=\"off\" aria-label=\"" +
           std::string(label) + " PEM\" placeholder=\"" + std::string(placeholder) +
           "\"></textarea></div><button class=\"btn btn-primary\" type=\"submit\">Save</button>"
           "</form></details></div></div>";
}

} // namespace

// ── Dashboard HTTPS ─────────────────────────────────────────────────────────

std::string render_https(const HttpsView& v) {
    std::string out = "<div class=\"kvl\">";
    kv(out, "HTTPS", v.enabled ? pill("ok", "On") : pill("idle", "Off"));
    kv(out, "Port", "<span class=\"mono\">" + std::to_string(v.port) + "</span>");
    kv(out, "Certificate", mono_or(v.cert_path, "Not configured"));
    kv(out, "Private key", mono_or(v.key_path, "Not configured"));
    kv(out, "HTTP redirect", v.redirect ? pill("ok", "On") : pill("idle", "Off"));
    out += "</div>";
    if (v.enabled) {
        out += "<p class=\"hint\" style=\"padding:12px 16px 0\">The dashboard certificate and key "
               "are set by the <code>--https-cert</code> and <code>--https-key</code> start-up "
               "flags. They reload from disk when the files change, unless the server runs with "
               "<code>--no-cert-reload</code>. They are not changed on this page.</p>";
    } else {
        out += "<p class=\"hint\" style=\"padding:12px 16px 0\">Start the server with "
               "<code>--https --https-cert &lt;path&gt; --https-key &lt;path&gt;</code> to "
               "enable.</p>";
    }
    return out;
}

// ── Agent connections (gRPC mTLS) ───────────────────────────────────────────

std::string render_tls(const TlsView& v) {
    std::string out = "<div class=\"form\">";

    // The switch is its OWN form carrying the NEW value, so cancelling the confirm leaves the
    // displayed state untouched (a bare checkbox with hx-confirm stays flipped).
    out += "<form id=\"tls-mtls-form\" hx-post=\"/api/settings/tls\" hx-target=\"#tls-section\" "
           "hx-swap=\"innerHTML\"" +
           confirm_attr(kConfirmMtls) + "><div class=\"kvl\">";
    kv(out, "Agent mTLS switch",
       v.enabled ? pill("ok", "On") : pill("bad", "Off"));
    out += "</div><input type=\"hidden\" name=\"tls_enabled\" value=\"";
    out += v.enabled ? "false" : "true";
    out += "\"><div class=\"btns\" style=\"padding:12px 0 0\"><button class=\"btn btn-secondary\" "
           "type=\"submit\">";
    out += v.enabled ? "Turn off" : "Turn on";
    out += "</button></div></form>";

    out += "<p class=\"hint\">These files are for agent (gRPC) connections, not the dashboard. "
           "The running server keeps the certificates it loaded at start.</p>";

    tls_slot(out, "cert", "Server certificate", "certificate", ".pem,.crt,.cer", v.cert_path,
             "-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----", true);
    tls_slot(out, "key", "Server private key", "private key", ".pem,.key", v.key_path,
             "-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----", true);
    tls_slot(out, "ca", "CA certificate", "CA certificate", ".pem,.crt,.cer", v.ca_path,
             "-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----", false);

    out += "<div class=\"kvl\">";
    kv(out, "Client certificate check",
       v.insecure_skip_client_verify
           ? pill("bad", "Skipped (--insecure-skip-client-verify)")
           : pill("idle", "Not skipped"));
    out += "</div>";

    out += "<div><div class=\"lb\" style=\"font-weight:500;margin-bottom:6px\">Management "
           "listener override</div><div class=\"kvl\">";
    kv(out, "Certificate", mono_or(v.mgmt_cert_path, "Using agent TLS"));
    kv(out, "Private key", mono_or(v.mgmt_key_path, "Using agent TLS"));
    kv(out, "CA certificate", mono_or(v.mgmt_ca_path, "Using agent TLS"));
    out += "</div></div>";

    out += "<div id=\"tls-feedback\" role=\"status\" aria-live=\"polite\"></div></div>";
    return out;
}

// ── Single sign-on ──────────────────────────────────────────────────────────

std::string render_directory(const DirectoryView& v) {
    std::string out = "<div style=\"padding:16px 16px 0\">";
    switch (v.state) {
    case SsoState::kRunning:
        out += pill("ok", "Running");
        break;
    case SsoState::kSavedNotRunning:
        out += pill("warn", "Saved, not running");
        break;
    case SsoState::kNotConfigured:
        out += pill("warn", "Not configured");
        break;
    }
    out += "<p class=\"hint\">The running provider is built from start-up flags; if they differ "
           "from the values shown, the provider uses the flag values.</p></div>";

    // All six fields always post: the handler persists every one on each save, so a form that
    // omitted one would blank it (an absent Admin group demotes SSO admins at next sign-in).
    out += "<form id=\"oidc-form\" class=\"form\" hx-post=\"/api/settings/oidc\" "
           "hx-target=\"#directory-section\" hx-swap=\"innerHTML\"" +
           confirm_attr(kConfirmSaveSso) + ">";
    out += "<div class=\"row2\">"
           "<div class=\"fld\"><label for=\"oidc-issuer\">Issuer URL</label>"
           "<input class=\"in mono\" id=\"oidc-issuer\" type=\"text\" name=\"issuer\" "
           "autocomplete=\"off\" value=\"" +
           html_escape(v.issuer) +
           "\" placeholder=\"https://login.microsoftonline.com/{tenant}/v2.0\"></div>"
           "<div class=\"fld\"><label for=\"oidc-client-id\">Client ID</label>"
           "<input class=\"in mono\" id=\"oidc-client-id\" type=\"text\" name=\"client_id\" "
           "autocomplete=\"off\" value=\"" +
           html_escape(v.client_id) + "\" placeholder=\"Application (client) ID\"></div></div>";
    out += "<div class=\"fld\"><label for=\"oidc-secret\">Client secret</label>"
           "<input class=\"in mono\" id=\"oidc-secret\" type=\"password\" name=\"client_secret\" "
           "autocomplete=\"new-password\" value=\"\" placeholder=\"";
    out += v.secret_stored ? "********" : "Client secret value";
    out += "\"><span class=\"hint\">Write-only. Leave blank to keep the stored secret.</span>"
           "</div>";
    out += "<div class=\"row2\">"
           "<div class=\"fld\"><label for=\"oidc-redirect\">Redirect URI</label>"
           "<input class=\"in mono\" id=\"oidc-redirect\" type=\"text\" name=\"redirect_uri\" "
           "autocomplete=\"off\" value=\"" +
           html_escape(v.redirect_uri) +
           "\" placeholder=\"(auto-computed from web address)\"></div>"
           "<div class=\"fld\"><label for=\"oidc-admin-group\">Admin group ID</label>"
           "<input class=\"in mono\" id=\"oidc-admin-group\" type=\"text\" name=\"admin_group\" "
           "autocomplete=\"off\" value=\"" +
           html_escape(v.admin_group) +
           "\" placeholder=\"Group object ID that maps to the admin role\"></div></div>";
    out += "<details";
    if (v.skip_tls_verify)
        out += " open";
    out += "><summary class=\"btn btn-ghost\">Advanced</summary><div class=\"tog\">"
           "<div class=\"t\"><b>Skip TLS verification</b><span>Do not check the identity "
           "provider's certificate. </span>" +
           pill("bad", "Insecure - dev only") +
           "</div><input class=\"sw\" id=\"oidc-skip-tls\" type=\"checkbox\" "
           "name=\"skip_tls_verify\" value=\"true\" aria-label=\"Skip TLS verification\"";
    if (v.skip_tls_verify)
        out += " checked";
    out += "></div></details></form>";

    // Save and Test sit outside the form so Test can never carry the secret (htmx includes the
    // enclosing form on a non-GET; hx-include/hx-params pin exactly two fields). Save joins the
    // form through the `form` attribute.
    out += "<div class=\"btns\"><button class=\"btn btn-primary\" type=\"submit\" "
           "form=\"oidc-form\">Save SSO settings</button>"
           "<button class=\"btn btn-secondary\" type=\"button\" "
           "hx-post=\"/api/settings/oidc/test\" hx-target=\"#oidc-feedback\" "
           "hx-swap=\"innerHTML\" hx-include=\"#oidc-issuer, #oidc-skip-tls\" "
           "hx-params=\"issuer,skip_tls_verify\">Test SSO</button></div>"
           "<p class=\"hint\" style=\"padding:0 16px 12px\">Test checks the issuer's discovery "
           "document only. Client ID and secret are not tested. Nothing is saved. The stored "
           "skip-TLS setting also applies to the test.</p>";

    out += "<div id=\"oidc-feedback\" role=\"status\" aria-live=\"polite\" "
           "style=\"padding:0 16px 16px\">";
    if (!v.message.empty()) {
        out += v.message_is_error ? "<div class=\"alert alert-error\" role=\"alert\">"
                                  : "<div class=\"alert alert-success\">";
        out += html_escape(v.message);
        out += "</div>";
    }
    out += "</div>";
    return out;
}

// ── Two-factor sign-in ──────────────────────────────────────────────────────

namespace {

const char* const kMfaRefresh =
    "hx-get=\"/fragments/settings/mfa\" hx-target=\"#mfa-section\" hx-swap=\"innerHTML\"";

void mfa_provisional(std::string& out, const MfaView& v) {
    if (!v.otpauth_uri.empty()) {
        out += "<div class=\"note warn\"><b>Scan this with your authenticator app. The secret is "
               "shown once.</b>";
        if (!v.qr_svg.empty()) {
            // The SVG comes from the trusted qrcodegen encoder over the server's own otpauth
            // URI, not operator input, so it is the one raw insert on this page.
            out += "<div style=\"display:flex;justify-content:center;margin:12px 0\"><div "
                   "style=\"background:#fff;padding:8px;border-radius:var(--rad-panel);"
                   "line-height:0\">" +
                   v.qr_svg + "</div></div><div class=\"hint\" style=\"text-align:center\">"
                              "Can't scan? Enter the secret below manually.</div>";
        }
        out += "<div class=\"hint\" style=\"margin-top:8px\">Base32 secret (manual entry):</div>"
               "<code>" +
               html_escape(v.secret_b32) +
               "</code><div class=\"hint\" style=\"margin-top:8px\">otpauth URI:</div>"
               "<code style=\"display:block;word-break:break-all\">" +
               html_escape(v.otpauth_uri) + "</code></div>";
    } else {
        out += "<p class=\"hint\">Codes refresh every 30 seconds - wait for the next code shown "
               "by your authenticator and try again.";
        if (v.enforcement_protects)
            out += " Two-factor is required for your account. Confirm a code, or wait: an "
                   "unconfirmed set-up expires after about an hour.";
        else
            out += " If you have lost the original QR code, press <b>Cancel setup</b> below and "
                   "start again.";
        out += "</p>";
    }
    out += "<form hx-post=\"/api/settings/mfa/verify\" hx-target=\"#mfa-section\" "
           "hx-swap=\"innerHTML\"><div class=\"fld\"><label for=\"mfa-code\">Code from your "
           "authenticator app</label><input class=\"in mono\" id=\"mfa-code\" type=\"text\" "
           "name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" "
           "autocapitalize=\"none\" autocorrect=\"off\" spellcheck=\"false\" required "
           "style=\"max-width:160px\"></div><div class=\"btns\" style=\"padding:12px 0 0\">"
           "<button class=\"btn btn-primary\" type=\"submit\">Confirm code</button>";
    if (!v.enforcement_protects)
        out += "<button class=\"btn btn-secondary\" type=\"submit\" "
               "hx-post=\"/api/settings/mfa/disable\" hx-target=\"#mfa-section\" "
               "hx-swap=\"innerHTML\" formnovalidate>Cancel setup</button>";
    out += "</div></form>";
}

void mfa_status(std::string& out, const MfaView& v) {
    const bool enrolled = v.kind == MfaKind::kEnrolled;
    out += "<div class=\"kvl\">";
    if (enrolled) {
        kv(out, "Status", pill("ok", "Enabled"));
        kv(out, "Enrolled", html_escape(v.enrolled_at) + " UTC");
        kv(out, "Recovery codes remaining", std::to_string(v.recovery_codes_remaining));
    } else if (!v.disabled_at.empty()) {
        kv(out, "Status", pill("idle", "Disabled"));
        kv(out, "Last disabled", html_escape(v.disabled_at) + " UTC");
    } else {
        kv(out, "Status", pill("idle", "Not enrolled"));
    }
    if (!v.enforcement_mode.empty())
        kv(out, "Two-factor policy", html_escape(v.enforcement_mode));
    out += "</div>";

    if (enrolled) {
        out += "<div class=\"btns\" style=\"padding:12px 0 0\">"
               "<form hx-post=\"/api/settings/mfa/recovery-codes\" hx-target=\"#mfa-section\" "
               "hx-swap=\"innerHTML\"" +
               confirm_attr(kConfirmRegenerateCodes) +
               "><button class=\"btn btn-secondary\" type=\"submit\">Regenerate recovery "
               "codes</button></form>";
        if (v.enforcement_protects) {
            out += "<button class=\"btn btn-danger\" type=\"button\" disabled "
                   "title=\"Required by policy\">Disable two-factor</button></div>"
                   "<p class=\"hint\">Required by policy (" +
                   html_escape(v.enforcement_mode) + "); it cannot be disabled for your account.</p>";
        } else {
            out += "<form hx-post=\"/api/settings/mfa/disable\" hx-target=\"#mfa-section\" "
                   "hx-swap=\"innerHTML\"" +
                   confirm_attr(kConfirmDisableMfa) +
                   "><button class=\"btn btn-danger\" type=\"submit\">Disable two-factor"
                   "</button></form></div>";
        }
    } else {
        out += "<div class=\"btns\" style=\"padding:12px 0 0\"><form "
               "hx-post=\"/api/settings/mfa/init\" hx-target=\"#mfa-section\" "
               "hx-swap=\"innerHTML\"><button class=\"btn btn-primary\" "
               "type=\"submit\">Set up two-factor</button></form></div>"
               "<p class=\"hint\">If you started set-up earlier and did not confirm a code, "
               "Set up shows the same secret again. An unconfirmed set-up expires after about an "
               "hour.</p>";
    }
}

} // namespace

std::string render_mfa(const MfaView& v) {
    std::string out = "<div style=\"padding:16px\">";
    if (v.kind == MfaKind::kStoreUnavailable)
        return out + "<span class=\"muted\">MFA store unavailable (no AuthDB configured).</span></div>";
    if (v.kind == MfaKind::kSsoManaged)
        return out + "<div class=\"note\">Two-factor for your account is managed by your identity "
                     "provider.</div></div>";

    if (!v.error_msg.empty())
        out += "<div class=\"alert alert-error\" role=\"alert\">" + html_escape(v.error_msg) + "</div>";

    switch (v.kind) {
    case MfaKind::kProvisional:
        mfa_provisional(out, v);
        break;
    case MfaKind::kStatusUnavailable:
        out += "<span class=\"muted\">MFA status is temporarily unavailable (authentication "
               "store error) - retry shortly.</span>";
        break;
    case MfaKind::kUserNotFound:
        out += "<span class=\"muted\">User not found for MFA status.</span>";
        break;
    case MfaKind::kNotEnrolled:
    case MfaKind::kEnrolled:
        if (!v.new_recovery_codes.empty()) {
            out += "<div class=\"note warn\"><b>Store these recovery codes now. Each can be used "
                   "once to bypass two-factor, and they are not shown again.</b>"
                   "<ul class=\"mono\" style=\"margin:8px 0;padding-left:20px\">";
            for (const auto& c : v.new_recovery_codes)
                out += "<li><code>" + html_escape(c) + "</code></li>";
            out += "</ul><button class=\"btn btn-primary\" type=\"button\" ";
            out += kMfaRefresh;
            out += ">I have stored these codes</button></div>";
        }
        mfa_status(out, v);
        break;
    default:
        break;
    }
    out += "</div>";
    return out;
}

} // namespace yuzu::server::security_render
