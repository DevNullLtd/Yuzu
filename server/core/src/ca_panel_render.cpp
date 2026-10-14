#include "ca_panel_render.hpp"

#include "web_utils.hpp"

#include <cctype>
#include <ctime>

namespace yuzu::server::ca_panel {

namespace {

std::string utc(std::int64_t epoch, const char* fmt) {
    if (epoch == 0)
        return "\xE2\x80\x94"; // em dash
    auto tt = static_cast<std::time_t>(epoch);
    std::tm tm_buf{};
#ifdef _WIN32
    if (gmtime_s(&tm_buf, &tt) != 0)
        return "\xE2\x80\x94";
#else
    if (gmtime_r(&tt, &tm_buf) == nullptr)
        return "\xE2\x80\x94";
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), fmt, &tm_buf);
    return buf;
}

std::string esc(std::string_view s) {
    return html_escape(std::string(s));
}

std::string note_panel(const char* heading, const std::string& inner_html) {
    return "<section class=\"panel\"><div class=\"hd\"><h2>" + std::string(heading) +
           "</h2></div><div class=\"pb\">" + inner_html + "</div></section>";
}

// First 12 hex digits of the fingerprint, no colons, lower case: a cache key for the
// day-cached public root download so a pre-import file is not served after Import.
std::string fingerprint_key(const std::string& fp) {
    std::string out;
    for (char c : fp) {
        if (std::isxdigit(static_cast<unsigned char>(c)))
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (out.size() == 12)
            break;
    }
    return out;
}

std::string pill(const char* cls, const std::string& text, const std::string& title = {}) {
    std::string h = std::string("<span class=\"pill ") + cls + "\"";
    if (!title.empty())
        h += " title=\"" + esc(title) + "\"";
    return h + ">" + esc(text) + "</span>";
}

std::string ca_panel(const Model& m) {
    const auto& r = m.root;
    std::string h = "<section class=\"panel\" id=\"ca-panel\">";
    h += "<div class=\"hd\"><h2>Certificate authority</h2></div>";
    h += "<div class=\"kvl\">";
    h += "<div><span>Trust mode</span><b>" +
         std::string(r.subordinate ? "Subordinate (enterprise-rooted)"
                                   : "Built-in (self-signed root)") +
         "</b></div>";
    h += "<div><span>Algorithm</span><b>" + esc(r.algo) + "</b></div>";
    h += "<div><span>Valid to</span><b>" + format_utc_date(r.not_after) + " UTC";
    if (is_expired(r.not_after, m.now))
        h += " " + pill("bad", "Expired",
                        "not_after has passed");
    h += "</b></div>";
    h += "<div class=\"fp\"><span>SHA-256</span><b class=\"mono\" title=\"" +
         esc(r.fingerprint_sha256) + "\">" + esc(r.fingerprint_sha256) + "</b></div>";
    h += "</div>";
    h += "<div class=\"btns\">"
         "<a class=\"btn\" href=\"/api/v1/ca/root?v=" +
         fingerprint_key(r.fingerprint_sha256) +
         "\">Download CA certificate</a>"
         "<a class=\"btn\" href=\"/api/v1/ca/root-csr\">Download CSR</a></div>";
    h += "<div class=\"pb hint\">Download the root to trust the dashboard. The CSR download is "
         "recorded in the audit log.</div>";

    // Import: one form, hx-confirm because no server step-up guards a trust-root switch.
    h += "<div class=\"pb\"><details><summary>";
    h += r.subordinate ? "Enterprise subordination"
                       : "Subordinate this CA to your enterprise root (optional)";
    h += "</summary><p class=\"hint\">";
    h += r.subordinate
             ? "This issuing CA is an intermediate signed by your enterprise root; issued "
               "certificates chain to that root. To re-subordinate, download a fresh CSR above "
               "and import the newly signed intermediate."
             : "Download this CA's signing request, have your enterprise root sign it as a "
               "subordinate CA (basicConstraints CA:TRUE), then import the signed intermediate "
               "plus the parent chain. The signing key is unchanged, so already-issued "
               "certificates keep working.";
    h += "</p><form hx-post=\"/api/settings/ca/import-chain\" hx-target=\"#ca-section\" "
         "hx-swap=\"innerHTML\" hx-confirm=\"Switch this CA's trust root to the imported "
         "enterprise chain? Certificates already issued keep working (the signing key is "
         "unchanged). There is no console action to switch back.\">"
         "<input type=\"hidden\" name=\"view\" value=\"pki\">"
         "<div class=\"fld\"><label for=\"ca-intermediate\">Signed intermediate (PEM)</label>"
         "<textarea id=\"ca-intermediate\" class=\"in\" name=\"intermediate_pem\" rows=\"4\" "
         "autocomplete=\"off\" spellcheck=\"false\" placeholder=\"-----BEGIN CERTIFICATE-----\">"
         "</textarea></div>"
         "<div class=\"fld\"><label for=\"ca-chain\">Parent chain (PEM)</label>"
         "<textarea id=\"ca-chain\" class=\"in\" name=\"chain_pem\" rows=\"4\" "
         "autocomplete=\"off\" spellcheck=\"false\" placeholder=\"-----BEGIN CERTIFICATE-----\">"
         "</textarea></div>"
         "<div class=\"btns\"><button class=\"btn danger\" type=\"submit\">Import signed chain"
         "</button></div></form></details></div>";
    h += "</section>";
    return h;
}

std::string crl_panel(const Crl& c) {
    std::string h = "<section class=\"panel\" id=\"crl-panel\"><div class=\"hd\"><h2>Revocation"
                    "</h2></div><div class=\"kvl\">";
    if (!c.present) {
        h += "<div><span>Revocation list</span><b>None published, or the store could not be "
             "read</b></div>";
        h += "<div><span>Status</span><b>" +
             pill("warn", "Not yet published", "No revocation list was found, or the store could not be read") + "</b></div>";
        return h + "</div></section>";
    }
    h += "<div><span>Revocation list</span><b>" + format_utc_minute(c.published_at) +
         " UTC<small>version " + std::to_string(c.version) + "</small></b></div>";
    h += "<div><span>Next update</span><b>" + format_utc_minute(c.next_update) + " UTC</b></div>";
    h += "<div><span>Revoked entries</span><b>" +
         (c.revoked_count ? std::to_string(*c.revoked_count) : std::string("Not recorded")) +
         "</b></div>";
    h += "<div><span>Status</span><b>";
    switch (c.state) {
    case CrlState::Current:
        h += pill("ok", "Current");
        break;
    case CrlState::OutOfDate:
        h += pill("warn", "Out of date: a revocation is not on the published list",
                  "The server republishes a list that does not cover every revocation on its "
                  "periodic freshness pass.");
        break;
    case CrlState::Unconfirmed:
        h += pill("warn", "Not confirmed current",
                  "This list was published before entry counts were recorded, so it cannot be "
                  "compared with the current revoked set.");
        break;
    case CrlState::NotPublished:
        h += pill("warn", "Not yet published");
        break;
    case CrlState::Expired:
        h += pill("bad", "Expired list: the next update has passed",
                  "The published revocation list is past its next-update time, so clients may "
                  "reject it. The server republishes on its periodic freshness pass; if this "
                  "persists, check the server log.");
        break;
    }
    h += "</b></div></div>";
    // A link to a CRL that does not exist navigates to a 503 JSON body: only offer it
    // when a list is published.
    h += "<div class=\"btns\"><a class=\"btn\" href=\"/api/v1/ca/crl\">Download CRL</a></div>";
    return h + "</section>";
}

std::string issued_panel(const Model& m) {
    std::string h = "<section class=\"panel\" id=\"issued-panel\"><div class=\"hd\"><h2>Issued "
                    "certificates</h2></div>";
    if (m.inventory_error)
        return h + "<div class=\"pb\"><span class=\"feedback-error\">Certificate inventory "
                   "unavailable (store error).</span></div></section>";
    h += "<div class=\"tw\"><table class=\"issued\"><thead><tr><th>Certificate</th>"
         "<th>Purpose</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>";
    if (m.issued.empty()) {
        h += "<tr><td colspan=\"5\" class=\"muted\">No certificates issued yet</td></tr>";
    }
    for (const auto& c : m.issued) {
        const bool expired = !c.revoked && is_expired(c.not_after, m.now);
        const std::string short_serial =
            c.serial_hex.size() > 16 ? c.serial_hex.substr(0, 16) + "\xE2\x80\xA6" : c.serial_hex;
        h += "<tr><td class=\"wrap\"><b>" + esc(c.subject) + "</b><span class=\"sub mono\" "
             "title=\"" + esc(c.serial_hex) + "\">" + esc(short_serial) + "</span></td>";
        h += "<td class=\"wrap\">" + esc(purpose_label(c.purpose)) + "</td>";
        h += "<td class=\"nw\">" + format_utc_date(c.not_after) + "</td><td>";
        if (c.revoked)
            h += pill("bad", "Revoked");
        else if (expired)
            h += pill("warn", "Expired", "not_after has passed; the certificate was not revoked");
        else
            h += pill("ok", "Active");
        h += "</td><td class=\"r\">";
        if (!c.revoked) {
            h += "<form class=\"rv\" hx-post=\"/api/settings/ca/revoke\" hx-target=\"#ca-section\" "
                 "hx-swap=\"innerHTML\" hx-confirm=\"" +
                 esc(revoke_confirm_text(c.purpose, c.subject)) +
                 "\"><input type=\"hidden\" name=\"serial_hex\" value=\"" + esc(c.serial_hex) +
                 "\"><input type=\"hidden\" name=\"view\" value=\"pki\">"
                 "<input class=\"in\" type=\"text\" name=\"reason\" maxlength=\"256\" "
                 "placeholder=\"reason (optional)\" autocomplete=\"off\">"
                 "<button class=\"btn link sm danger\" type=\"submit\">Revoke</button></form>";
        }
        h += "</td></tr>";
    }
    h += "</tbody></table></div>";
    if (m.issued.size() >= m.panel_limit) {
        h += "<div class=\"pb hint\">Showing the first " + std::to_string(m.panel_limit) +
             " certificates. Use <code>GET /api/v1/ca/issued?offset=</code> to page through the "
             "full inventory.</div>";
    }
    h += "<div class=\"pb hint\">To replace the default certificates with operator- or "
         "HSM-issued material, use <a href=\"/settings\">TLS / mTLS Configuration</a> on the "
         "Settings page.</div>";
    return h + "</section>";
}

} // namespace

std::string purpose_label(std::string_view purpose) {
    if (purpose == "agent")
        return "Agent identity";
    if (purpose == "code-signing")
        return "Code signing";
    return std::string(purpose);
}

std::string revoke_confirm_text(std::string_view purpose, std::string_view subject) {
    const std::string s(subject);
    if (purpose == "agent")
        return "Revoke certificate for \"" + s +
               "\"? The agent is refused on its next direct connection. An agent connected through a "
               "gateway must also be disconnected at the gateway. This cannot be undone.";
    if (purpose == "code-signing")
        return "Revoke \"" + s +
               "\"? It is recorded on the revocation list. This does not stop it signing new "
               "plugins, and agents do not yet check the list when loading plugins. This cannot "
               "be undone.";
    return "Revoke \"" + s +
           "\"? It is recorded as revoked and the revocation list is republished. This cannot be "
           "undone.";
}

bool is_expired(std::int64_t not_after, std::int64_t now) noexcept {
    return not_after > 0 && not_after < now;
}

std::string format_utc_date(std::int64_t epoch) {
    return utc(epoch, "%Y-%m-%d");
}

std::string format_utc_minute(std::int64_t epoch) {
    return utc(epoch, "%Y-%m-%d %H:%M");
}

std::string render(const Model& m) {
    switch (m.availability) {
    case Availability::Unavailable:
        return note_panel("Certificate authority",
                          "<span class=\"muted\">Certificate authority unavailable.</span>");
    case Availability::StoreError:
        return note_panel("Certificate authority",
                          "<span class=\"feedback-error\">Certificate authority store error."
                          "</span>");
    case Availability::NoRoot:
        return note_panel("Certificate authority",
                          "<p class=\"muted\">No internal CA on this install (operator-supplied "
                          "certificates, or TLS disabled).</p>");
    case Availability::Ready:
        break;
    }
    return "<div class=\"grid2\">" + ca_panel(m) + crl_panel(m.crl) + "</div>" + issued_panel(m);
}

} // namespace yuzu::server::ca_panel
