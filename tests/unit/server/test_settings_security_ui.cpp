/**
 * test_settings_security_ui.cpp - the Security and sign-in page and its four panels.
 *
 * Pure-string pins on the page template and the pure panel renderers
 * (settings_security_render.hpp), plus in-process route cases that need no Postgres: the
 * page gate, fragment escaping, the OIDC save feedback living INSIDE #oidc-feedback, the
 * trimmed admin group, and the cert-paste error retarget. The MFA route cases that need the
 * auth store live in test_settings_routes_mfa.cpp.
 *
 * Defects each pin was written against (reproduced in the REVIEW probe against the repo's own
 * htmx bundle): an out-of-band message into #oidc-feedback is destroyed by the main swap (A1);
 * a paste error retargeted at #tls-section replaces the whole panel (A2); the Test button
 * posts the typed client secret (A3); a bare checkbox with hx-confirm stays flipped when the
 * confirm is cancelled (A5).
 */

#include "settings_routes.hpp"
#include "settings_security_render.hpp"

#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <httplib.h>

#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>

extern const char* const kSettingsSecurityHtml;

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace sr = yuzu::server::security_render;

namespace {

std::size_t count_of(const std::string& hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

/// True when no <form> opens inside another <form> (invalid HTML that only works because htmx
/// parses fragments inside a <template>).
bool forms_not_nested(const std::string& html) {
    int depth = 0;
    for (std::size_t i = 0; i < html.size(); ++i) {
        if (html.compare(i, 5, "<form") == 0 && (html[i + 5] == ' ' || html[i + 5] == '>')) {
            if (++depth > 1)
                return false;
        } else if (html.compare(i, 7, "</form>") == 0) {
            --depth;
        }
    }
    return depth == 0;
}

const std::string kXss = "<img src=x onerror=1>";
const std::string sr_shell_end = "<!--/yuzu:shell-->";

sr::DirectoryView sso_view() {
    sr::DirectoryView v;
    v.issuer = "https://idp.example/v2.0";
    v.client_id = "cid";
    v.redirect_uri = "https://yuzu.example/auth/callback";
    v.admin_group = "grp-1";
    v.secret_stored = true;
    v.state = sr::SsoState::kRunning;
    return v;
}

} // namespace

// ── Page template ───────────────────────────────────────────────────────────

TEST_CASE("Security page: four panels in order, each loading its existing fragment",
          "[settings][security_page]") {
    const std::string html = kSettingsSecurityHtml;
    CHECK(count_of(html, "<h1") == 1);
    CHECK_THAT(html, ContainsSubstring("<h1>Security and sign-in</h1>"));
    std::size_t from = 0;
    for (const auto& [id, frag] : {std::pair{"directory-section", "/fragments/settings/directory"},
                                   std::pair{"mfa-section", "/fragments/settings/mfa"},
                                   std::pair{"https-section", "/fragments/settings/https"},
                                   std::pair{"tls-section", "/fragments/settings/tls"}}) {
        INFO(id);
        const auto at = html.find(std::string("<div id=\"") + id + "\" hx-get=\"" + frag + "\"", from);
        REQUIRE(at != std::string::npos);
        from = at;
    }
    CHECK(count_of(html, "hx-get=\"/fragments/settings/") == 4);
}

TEST_CASE("Security page: CSP-safe and keeps a revealed secret out of htmx history",
          "[settings][security_page]") {
    // The page's own markup and script: the shell block is the shell's (pinned in
    // test_nav_shells.cpp) and carries its own identity fetch.
    const std::string whole = kSettingsSecurityHtml;
    const std::string html = whole.substr(whole.find(sr_shell_end) + sr_shell_end.size());
    CHECK_THAT(whole, ContainsSubstring("{\"allowEval\":false,\"historyEnabled\":false}"));
    CHECK_THAT(html, !ContainsSubstring("hx-on"));
    for (const char* inline_handler : {" onclick=", " onchange=", " onsubmit=", " onload=", " onerror="})
        CHECK_THAT(html, !ContainsSubstring(inline_handler));
    CHECK_THAT(html, !ContainsSubstring(".innerHTML"));
    CHECK_THAT(html, !ContainsSubstring("insertAdjacentHTML"));
    CHECK_THAT(html, !ContainsSubstring("eval("));
    CHECK_THAT(html, !ContainsSubstring("new Function"));
    CHECK_THAT(html, !ContainsSubstring("fetch("));
    CHECK(count_of(html, "id=\"toast-container\"") == 1);
}

TEST_CASE("Security page: the swap override is scoped to HTML bodies from the four panels",
          "[settings][security_page]") {
    const std::string html = kSettingsSecurityHtml;
    const auto at = html.find("htmx:beforeSwap");
    REQUIRE(at != std::string::npos);
    const auto end = html.find("});", at);
    const std::string body = html.substr(at, end - at);
    CHECK_THAT(body, ContainsSubstring("closest(PANELS)"));
    CHECK_THAT(body, ContainsSubstring("text/html"));
    // The skip-TLS switch asks on change; the file forms own their confirm so a cancel resets.
    CHECK_THAT(html, ContainsSubstring("input[name=skip_tls_verify]"));
    CHECK_THAT(html, ContainsSubstring("htmx:confirm"));
    CHECK_THAT(html, ContainsSubstring("You no longer have access. Sign in again."));
}

// ── SSO panel ───────────────────────────────────────────────────────────────

TEST_CASE("SSO panel: all six fields post, the secret is never a value, current values are escaped",
          "[settings][security_page][oidc]") {
    auto v = sso_view();
    v.issuer = kXss;
    v.admin_group = "\"><script>x</script>";
    const auto html = sr::render_directory(v);
    for (const char* name : {"name=\"issuer\"", "name=\"client_id\"", "name=\"client_secret\"",
                             "name=\"redirect_uri\"", "name=\"admin_group\"",
                             "name=\"skip_tls_verify\""})
        CHECK_THAT(html, ContainsSubstring(name));
    CHECK_THAT(html, ContainsSubstring("name=\"client_secret\" autocomplete=\"new-password\" "
                                       "value=\"\" placeholder=\"********\""));
    CHECK_THAT(html, !ContainsSubstring(kXss));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
    CHECK_THAT(html, !ContainsSubstring("<script>x"));
    CHECK_THAT(html, ContainsSubstring("name=\"issuer\" autocomplete=\"off\""));
}

TEST_CASE("SSO panel: Test SSO cannot send the client secret", "[settings][security_page][oidc]") {
    const auto html = sr::render_directory(sso_view());
    const auto test_at = html.find("hx-post=\"/api/settings/oidc/test\"");
    REQUIRE(test_at != std::string::npos);
    // A3: outside the form (htmx includes the enclosing form on a non-GET) AND params-pinned.
    CHECK(html.rfind("</form>", test_at) != std::string::npos);
    CHECK(html.find("</form>", test_at) == std::string::npos);
    CHECK_THAT(html, ContainsSubstring("hx-params=\"issuer,skip_tls_verify\""));
    CHECK_THAT(html, !ContainsSubstring("closest form"));
    // Save joins the form through the `form` attribute and carries the confirm on the form.
    CHECK_THAT(html, ContainsSubstring("type=\"submit\" form=\"oidc-form\""));
    CHECK(forms_not_nested(html));
}

TEST_CASE("SSO panel: the save confirm names the admin-group and restart consequences",
          "[settings][security_page][oidc]") {
    const auto html = sr::render_directory(sso_view());
    const std::string c = sr::kConfirmSaveSso;
    CHECK_THAT(c, ContainsSubstring("immediately"));
    CHECK_THAT(c, ContainsSubstring("start-up flags or environment again"));
    CHECK_THAT(c, ContainsSubstring("Admin group ID"));
    CHECK_THAT(c, ContainsSubstring("ordinary users"));
    CHECK_THAT(html, ContainsSubstring("hx-confirm=\"Save single sign-on settings?"));
}

TEST_CASE("SSO panel: a message renders INSIDE the single #oidc-feedback, never out-of-band",
          "[settings][security_page][oidc]") {
    auto v = sso_view();
    v.message = "OIDC init failed: " + kXss;
    const auto html = sr::render_directory(v);
    CHECK(count_of(html, "id=\"oidc-feedback\"") == 1);
    CHECK_THAT(html, !ContainsSubstring("hx-swap-oob"));
    const auto fb = html.find("id=\"oidc-feedback\"");
    const auto msg = html.find("OIDC init failed: &lt;img");
    REQUIRE(msg != std::string::npos);
    CHECK(msg > fb);
    CHECK_THAT(html, !ContainsSubstring(kXss));
}

TEST_CASE("SSO panel: status is the live provider, in three states, never 'Active'",
          "[settings][security_page][oidc]") {
    auto v = sso_view();
    CHECK_THAT(sr::render_directory(v), ContainsSubstring(">Running<"));
    v.state = sr::SsoState::kSavedNotRunning;
    CHECK_THAT(sr::render_directory(v), ContainsSubstring(">Saved, not running<"));
    v.state = sr::SsoState::kNotConfigured;
    const auto html = sr::render_directory(v);
    CHECK_THAT(html, ContainsSubstring(">Not configured<"));
    CHECK_THAT(html, !ContainsSubstring("Active"));
    CHECK_THAT(html, ContainsSubstring("the provider uses the flag values"));
}

TEST_CASE("SSO panel: skip-TLS stays a normal checked control", "[settings][security_page][oidc]") {
    auto v = sso_view();
    v.skip_tls_verify = true;
    const auto html = sr::render_directory(v);
    CHECK_THAT(html, ContainsSubstring("name=\"skip_tls_verify\" value=\"true\" "
                                       "aria-label=\"Skip TLS verification\" checked"));
    CHECK_THAT(html, ContainsSubstring("<details open>"));
    CHECK_THAT(sr::render_directory(sso_view()), !ContainsSubstring("<details open>"));
}

// ── Agent mTLS panel ────────────────────────────────────────────────────────

TEST_CASE("mTLS panel: no inline handlers, no nested forms, one feedback line",
          "[settings][security_page][tls]") {
    sr::TlsView v;
    v.enabled = true;
    v.cert_path = "/etc/yuzu/" + kXss;
    const auto html = sr::render_tls(v);
    for (const char* h : {" onclick=", " onchange=", "hx-on"})
        CHECK_THAT(html, !ContainsSubstring(h));
    CHECK(forms_not_nested(html));
    CHECK(count_of(html, "id=\"tls-feedback\"") == 1);
    CHECK_THAT(html, !ContainsSubstring(kXss));
    CHECK(count_of(html, "hx-post=\"/api/settings/cert-upload\"") == 3);
    CHECK(count_of(html, "hx-post=\"/api/settings/cert-paste\"") == 3);
}

TEST_CASE("mTLS panel: the switch is its own confirmed form carrying the NEW value",
          "[settings][security_page][tls]") {
    sr::TlsView v;
    v.enabled = false;
    auto html = sr::render_tls(v);
    const auto form = html.find("<form id=\"tls-mtls-form\" hx-post=\"/api/settings/tls\"");
    REQUIRE(form != std::string::npos);
    const auto form_end = html.find("</form>", form);
    const std::string f = html.substr(form, form_end - form);
    CHECK_THAT(f, ContainsSubstring("hx-confirm=\"Change the gRPC mTLS setting shown here?"));
    CHECK_THAT(f, ContainsSubstring("name=\"tls_enabled\" value=\"true\""));
    CHECK_THAT(f, !ContainsSubstring("type=\"checkbox\""));
    v.enabled = true;
    html = sr::render_tls(v);
    CHECK_THAT(html, ContainsSubstring("name=\"tls_enabled\" value=\"false\""));
}

TEST_CASE("mTLS panel: every slot confirms the replace, names the slot, and targets #tls-feedback",
          "[settings][security_page][tls]") {
    const auto html = sr::render_tls({});
    CHECK(count_of(html, "hx-target=\"#tls-feedback\"") == 6);
    CHECK_THAT(html, ContainsSubstring("Replace the agent connection certificate file?"));
    CHECK_THAT(html, ContainsSubstring("Replace the agent connection private key file?"));
    CHECK_THAT(html, ContainsSubstring("Replace the agent connection CA certificate file?"));
    // A4: the true consequence, not "from the next start".
    CHECK_THAT(html, ContainsSubstring("only if --cert, --key and --ca-cert name it"));
    CHECK_THAT(html, ContainsSubstring("the server will not start"));
    CHECK_THAT(html, !ContainsSubstring("from the next server start"));
    CHECK_THAT(html, ContainsSubstring("gateway command plane pins the server certificate"));
}

TEST_CASE("mTLS panel: the file input is keyboard-reachable and secrets are not retained",
          "[settings][security_page][tls]") {
    const auto html = sr::render_tls({});
    CHECK_THAT(html, ContainsSubstring("<input class=\"vh\" type=\"file\" name=\"file\" "
                                       "accept=\".pem,.crt,.cer\">"));
    CHECK_THAT(html, ContainsSubstring("accept=\".pem,.key\""));
    CHECK_THAT(html, !ContainsSubstring("display:none"));
    CHECK_THAT(html, !ContainsSubstring(" hidden>"));
    CHECK(count_of(html, "autocomplete=\"off\" spellcheck=\"false\" autocapitalize=\"off\"") == 3);
    CHECK_THAT(html, ContainsSubstring("hx-trigger=\"change\""));
}

TEST_CASE("mTLS panel: honest wording for the client check and management override",
          "[settings][security_page][tls]") {
    sr::TlsView v;
    auto html = sr::render_tls(v);
    CHECK_THAT(html, ContainsSubstring("Client certificate check"));
    CHECK_THAT(html, ContainsSubstring(">Not skipped<"));
    CHECK_THAT(html, !ContainsSubstring("mTLS enforced"));
    CHECK_THAT(html, ContainsSubstring("Using agent TLS"));
    CHECK_THAT(html, ContainsSubstring("No file"));
    v.insecure_skip_client_verify = true;
    v.mgmt_cert_path = "/m/c.pem";
    html = sr::render_tls(v);
    CHECK_THAT(html, ContainsSubstring("Skipped (--insecure-skip-client-verify)"));
    CHECK_THAT(html, ContainsSubstring("/m/c.pem"));
}

// ── Dashboard HTTPS panel ───────────────────────────────────────────────────

TEST_CASE("HTTPS panel: on and off states, escaped paths, the flags note", "[settings][security_page]") {
    sr::HttpsView v;
    auto html = sr::render_https(v);
    CHECK_THAT(html, ContainsSubstring(">Off<"));
    CHECK_THAT(html, ContainsSubstring("Not configured"));
    CHECK_THAT(html, ContainsSubstring("--https --https-cert"));
    v.enabled = true;
    v.port = 8443;
    v.redirect = true;
    v.cert_path = kXss;
    html = sr::render_https(v);
    CHECK_THAT(html, ContainsSubstring(">On<"));
    CHECK_THAT(html, ContainsSubstring("8443"));
    CHECK_THAT(html, !ContainsSubstring(kXss));
    CHECK_THAT(html, !ContainsSubstring("--https --https-cert"));
    CHECK_THAT(html, ContainsSubstring("not changed on this page"));
    // No un-routed static facts (HSTS, TLS floor): omitted by default.
    CHECK_THAT(html, !ContainsSubstring("HSTS"));
}

// ── Two-factor panel ────────────────────────────────────────────────────────

TEST_CASE("2FA panel: not enrolled offers Set up, says what a re-click does, shows last-disabled",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kNotEnrolled;
    v.enforcement_mode = "optional";
    auto html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring(">Not enrolled<"));
    CHECK_THAT(html, ContainsSubstring("Set up two-factor"));
    CHECK_THAT(html, ContainsSubstring("shows the same secret again"));
    CHECK_THAT(html, !ContainsSubstring("Regenerate"));
    v.disabled_at = "2026-10-01 10:00:00";
    html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring(">Disabled<"));
    CHECK_THAT(html, ContainsSubstring("2026-10-01 10:00:00 UTC"));
}

TEST_CASE("2FA panel: provisional first reveal shows the secret once; a retry does not",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kProvisional;
    v.otpauth_uri = "otpauth://totp/Yuzu:a?secret=ABC&issuer=" + kXss;
    v.secret_b32 = "ABCDEFGH";
    v.qr_svg = "<svg id=\"qr\"></svg>";
    auto html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring("ABCDEFGH"));
    CHECK_THAT(html, ContainsSubstring("<svg id=\"qr\"></svg>"));
    CHECK_THAT(html, !ContainsSubstring(kXss));
    CHECK_THAT(html, ContainsSubstring("Cancel setup"));

    sr::MfaView retry;
    retry.kind = sr::MfaKind::kProvisional;
    retry.error_msg = "Invalid code";
    html = sr::render_mfa(retry);
    CHECK_THAT(html, !ContainsSubstring("otpauth://"));
    CHECK_THAT(html, !ContainsSubstring("Base32"));
    CHECK_THAT(html, ContainsSubstring("Invalid code"));
    CHECK_THAT(html, ContainsSubstring("name=\"code\""));
    CHECK_THAT(html, ContainsSubstring("autocomplete=\"one-time-code\""));
}

TEST_CASE("2FA panel: under enforcement there is no Cancel setup and no instruction to press it",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kProvisional;
    v.enforcement_protects = true;
    v.enforcement_mode = "required";
    auto html = sr::render_mfa(v);
    CHECK_THAT(html, !ContainsSubstring("Cancel setup"));
    CHECK_THAT(html, !ContainsSubstring("/api/settings/mfa/disable"));
    CHECK_THAT(html, !ContainsSubstring("Disable MFA"));
    CHECK_THAT(html, ContainsSubstring("expires after about an hour"));
    CHECK_THAT(html, ContainsSubstring("Confirm code"));
}

TEST_CASE("2FA panel: enrolled confirms Regenerate and Disable; enforcement disables Disable",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kEnrolled;
    v.enrolled_at = "2026-09-01 09:00:00";
    v.recovery_codes_remaining = 7;
    v.enforcement_mode = "optional";
    auto html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring(">Enabled<"));
    CHECK_THAT(html, ContainsSubstring("2026-09-01 09:00:00 UTC"));
    CHECK_THAT(html, ContainsSubstring(">7<"));
    CHECK_THAT(html, ContainsSubstring("hx-confirm=\"Regenerate recovery codes? All current codes "
                                       "stop working, including unused ones.\""));
    CHECK_THAT(html, ContainsSubstring("hx-confirm=\"Disable MFA for your account? Step-up "
                                       "authentication will no longer be required.\""));
    CHECK(forms_not_nested(html));

    v.enforcement_protects = true;
    v.enforcement_mode = "required";
    html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring("disabled title=\"Required by policy\""));
    CHECK_THAT(html, !ContainsSubstring("hx-post=\"/api/settings/mfa/disable\""));
}

TEST_CASE("2FA panel: recovery codes reveal once, escaped, with an explicit Done",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kEnrolled;
    v.recovery_codes_remaining = 10;
    v.new_recovery_codes = {"AAAA-BBBB", kXss};
    const auto html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring("Store these recovery codes now"));
    CHECK_THAT(html, ContainsSubstring("AAAA-BBBB"));
    CHECK_THAT(html, !ContainsSubstring(kXss));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/mfa\" "
                                       "hx-target=\"#mfa-section\" hx-swap=\"innerHTML\">I have "
                                       "stored these codes"));
    // The reveal is gone on the next GET: the Done target is a plain status fetch.
    sr::MfaView again = v;
    again.new_recovery_codes.clear();
    CHECK_THAT(sr::render_mfa(again), !ContainsSubstring("Store these recovery codes"));
}

TEST_CASE("2FA panel: an SSO session is told its two-factor is the IdP's, with no buttons",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kSsoManaged;
    const auto html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring("managed by your identity provider"));
    CHECK_THAT(html, !ContainsSubstring("<button"));
    CHECK_THAT(html, !ContainsSubstring("User not found"));
}

TEST_CASE("2FA panel: unavailable store and status errors never read as 'not enrolled'",
          "[settings][security_page][mfa]") {
    sr::MfaView v;
    v.kind = sr::MfaKind::kStoreUnavailable;
    CHECK_THAT(sr::render_mfa(v), ContainsSubstring("MFA store unavailable"));
    v.kind = sr::MfaKind::kStatusUnavailable;
    auto html = sr::render_mfa(v);
    CHECK_THAT(html, ContainsSubstring("temporarily unavailable"));
    CHECK_THAT(html, !ContainsSubstring("Not enrolled"));
    CHECK_THAT(html, !ContainsSubstring("Set up two-factor"));
}

// ── Routes (no Postgres) ────────────────────────────────────────────────────

namespace {

struct SecurityRoutes {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    bool is_admin{true};

    SecurityRoutes() {
        auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (!is_admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {
            return true;
        };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                               false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
    }
};

const char* kForm = "application/x-www-form-urlencoded";

} // namespace

TEST_CASE("GET /settings/security: admin gets the page, a non-admin is redirected to /",
          "[settings][security_page][routes]") {
    SecurityRoutes h;
    auto ok = h.sink.Get("/settings/security");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK_THAT(ok->body, ContainsSubstring("Security and sign-in"));

    h.is_admin = false;
    auto denied = h.sink.Get("/settings/security");
    REQUIRE(denied);
    CHECK(denied->status == 302);
    CHECK(denied->get_header_value("Location") == "/");
    CHECK_THAT(denied->body, !ContainsSubstring("Security and sign-in"));
}

TEST_CASE("Security fragments render from cfg_, escape it, and stay admin-only",
          "[settings][security_page][routes]") {
    SecurityRoutes h;
    h.cfg.oidc_issuer = kXss;
    h.cfg.oidc_client_id = "cid";
    h.cfg.oidc_client_secret = "do-not-print-me";
    h.cfg.oidc_admin_group = "grp";

    auto dir = h.sink.Get("/fragments/settings/directory");
    REQUIRE(dir);
    CHECK(dir->status == 200);
    CHECK_THAT(dir->body, !ContainsSubstring(kXss));
    CHECK_THAT(dir->body, !ContainsSubstring("do-not-print-me"));
    // Configured in cfg_ but no live provider in this harness: not "Running".
    CHECK_THAT(dir->body, ContainsSubstring(">Saved, not running<"));

    for (const char* path : {"/fragments/settings/https", "/fragments/settings/tls",
                             "/fragments/settings/directory", "/fragments/settings/mfa"}) {
        INFO(path);
        auto ok = h.sink.Get(path);
        REQUIRE(ok);
        CHECK(ok->status == 200);
    }
    h.is_admin = false;
    for (const char* path : {"/fragments/settings/https", "/fragments/settings/tls",
                             "/fragments/settings/directory", "/fragments/settings/mfa"}) {
        INFO(path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 403);
    }
}

TEST_CASE("OIDC save: a missing issuer is a 400 whose message is INSIDE the fragment",
          "[settings][security_page][routes][oidc]") {
    SecurityRoutes h;
    auto res = h.sink.Post("/api/settings/oidc", "issuer=&client_id=&client_secret=", kForm);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(count_of(res->body, "id=\"oidc-feedback\"") == 1);
    CHECK_THAT(res->body, !ContainsSubstring("hx-swap-oob"));
    const auto fb = res->body.find("id=\"oidc-feedback\"");
    const auto msg = res->body.find("Issuer URL and Client ID are required.");
    REQUIRE(msg != std::string::npos);
    CHECK(msg > fb);
}

TEST_CASE("OIDC save: issuer, client id, redirect URI and admin group are trimmed",
          "[settings][security_page][routes][oidc]") {
    SecurityRoutes h;
    // No runtime-config store here, so the response reports the persist failure; the live
    // config is what this case pins.
    auto res = h.sink.Post("/api/settings/oidc",
                           "issuer=%20https%3A%2F%2Fidp.example%20&client_id=%20cid%20"
                           "&client_secret=&redirect_uri=%20&admin_group=%20grp%20%0A"
                           "&skip_tls_verify=false",
                           kForm);
    REQUIRE(res);
    CHECK(h.cfg.oidc_issuer == "https://idp.example");
    CHECK(h.cfg.oidc_client_id == "cid");
    CHECK(h.cfg.oidc_admin_group == "grp");
    CHECK(h.cfg.oidc_redirect_uri.empty());
    CHECK_THAT(res->body, ContainsSubstring("settings could NOT be saved"));
    CHECK(count_of(res->body, "id=\"oidc-feedback\"") == 1);
}

TEST_CASE("cert paste: every 400 retargets the one-line feedback, never the whole panel",
          "[settings][security_page][routes][tls]") {
    SecurityRoutes h;
    const std::string cases[] = {
        "type=&content=",                                  // missing
        "type=cert&content=hello",                         // no PEM markers
        // (The 64 KB branch is unreachable: httplib 413s a urlencoded body first.)
    };
    for (const auto& body : cases) {
        auto res = h.sink.Post("/api/settings/cert-paste", body, kForm);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("HX-Retarget") == "#tls-feedback");
    }
    auto bad_type = h.sink.Post(
        "/api/settings/cert-paste",
        "type=nope&content=-----BEGIN%20X-----%0A-----END%20X-----", kForm);
    REQUIRE(bad_type);
    CHECK(bad_type->status == 400);
    CHECK(bad_type->get_header_value("HX-Retarget") == "#tls-feedback");
}

TEST_CASE("mTLS toggle: the toast says only the displayed value changed",
          "[settings][security_page][routes][tls]") {
    SecurityRoutes h;
    auto res = h.sink.Post("/api/settings/tls", "tls_enabled=true", kForm);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.cfg.tls_enabled);
    const auto trig = res->get_header_value("HX-Trigger");
    CHECK_THAT(trig, ContainsSubstring("It is not saved"));
    CHECK_THAT(trig, !ContainsSubstring("TLS settings saved"));
    CHECK_THAT(res->body, ContainsSubstring("name=\"tls_enabled\" value=\"false\""));
}
