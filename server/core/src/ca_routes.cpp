#include "ca_routes.hpp"
#include "query_int_parse.hpp" // parse_query_int / strict_stoi / strict_stoll (#4644)

#include "ca_panel_render.hpp"
#include "rest_a4_envelope.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cctype>
#include <mutex>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

std::string derive_cert_audit_target_type(CaStore& ca_store, const std::string& serial_hex) {
    std::string target_type = "Certificate";
    if (auto rec_or_err = ca_store.get_issued(serial_hex); rec_or_err && rec_or_err->has_value()) {
        const std::string& purpose = (*rec_or_err)->purpose;
        if (purpose == "agent")
            target_type = "AgentCertificate";
        else if (purpose == "code-signing")
            target_type = "CodeSigningCertificate";
    }
    return target_type;
}

nlohmann::json crl_figures_json(CaStore& ca_store) {
    nlohmann::json j = {{"crl_version", nullptr},
                        {"crl_published_at", nullptr},
                        {"crl_next_update", nullptr},
                        {"crl_revoked_count", nullptr},
                        {"crl_stale", nullptr}};
    if (auto crl = ca_store.latest_crl()) {
        j["crl_version"] = crl->version;
        j["crl_published_at"] = crl->published_at;
        j["crl_next_update"] = crl->next_update;
        if (crl->revoked_count)
            j["crl_revoked_count"] = *crl->revoked_count;
    }
    if (auto stale = ca_store.has_unpublished_revocations())
        j["crl_stale"] = *stale;
    return j;
}

void log_issued_list_failure(std::string_view surface, const std::string& error) {
    // The CaStore DegradeSampler shape: the first failure of an episode (the first ever, or
    // after a quiet gap over 60 s), then every 100th. `last_ts` is refreshed on EVERY failure,
    // so a client retrying more often than once a minute logs one line, then one per 100
    // failures. File-local state, shared by REST and MCP; the counter is a plain occurrence
    // count.
    static std::atomic<std::uint64_t> count{0};
    static std::atomic<std::int64_t> last_ts{0};
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count() +
                             1; // never 0, so 0 stays "no previous failure"
    const std::int64_t prev = last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = count.fetch_add(1, std::memory_order_relaxed) + 1;
    if (prev == 0 || (now - prev) > 60 || (n % 100) == 0)
        spdlog::warn("ca routes: {} issued-certificate list read failed: {} (occurrence {})",
                     surface, error, n);
}

namespace {

using detail::error_json_a4;
using detail::make_correlation_id;

constexpr const char* kJson = "application/json";
constexpr std::size_t kMaxRevokeBody = 64 * 1024; // bound the revoke POST body
// Bound the subordinate-CA import body before parsing. A realistic intermediate
// + parent chain is a few KB; 256 KiB is generous headroom while still refusing
// a multi-MB POST on this privileged trust-root-switching endpoint (PR6).
constexpr std::size_t kMaxImportBody = 256 * 1024;
// Bound the code-signing issuance POST body before parsing (gap-matrix #10).
// The JSON body wraps a PEM CSR (server.cpp's issue_code_signing_leaf enforces
// the same 16 KiB CSR-PEM ceiling sign_agent_csr uses) as an escaped JSON
// string — each PEM newline costs 2 bytes escaped ("\n") — plus a <=64 byte
// label and a small validity_days integer. 64 KiB is 4x the raw 16 KiB CSR
// ceiling: generous headroom over the worst-case ~2x JSON-escaping cost, with
// room to spare for the other two fields and JSON framing, while still three
// orders of magnitude under httplib's 100 MiB backstop on this privileged
// endpoint. Mirrored exactly by body_cap_policy.hpp's ca_issue_code_signing
// row — same two-authority-split precedent as kMaxRevokeBody/kMaxImportBody.
constexpr std::size_t kMaxIssueCodeSigningBody = 64 * 1024;
// gov F6/UP-7: mirrors server.cpp's issue_code_signing_leaf ceiling exactly
// (its own locally-declared constant — same per-signing-path style as
// kMaxCsrPemBytes there) so REST rejects an out-of-range validity_days at the
// door instead of deferring entirely to the server-side refusal.
constexpr int kMaxCodeSigningValidityDaysRest = 730;

// nullopt when the parameter is present but not ONE base-10 integer: the caller answers
// 400 (a malformed page size must not silently become the default, #4644).
std::optional<int> clamp_int(const httplib::Request& req, const char* key, int def, int lo,
                             int hi) {
    auto it = req.params.find(key);
    if (it == req.params.end())
        return def;
    auto parsed = yuzu::server::parse_query_int<int>(it->second);
    if (!parsed)
        return std::nullopt;
    int v = *parsed;
    if (v < lo)
        v = lo;
    if (v > hi)
        v = hi;
    return v;
}

std::string fmt_epoch(int64_t epoch) {
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
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return std::string(buf);
}

/// True when a certificate with a recorded `not_after` has lapsed at `now` (epoch seconds).
/// Pure: `now` is passed in. `not_after == 0` is "no expiry recorded" (rendered "—"), never
/// expired — the same rule the API-token table applies to its expiry.
bool cert_expired(int64_t not_after, int64_t now) { return not_after > 0 && not_after < now; }

/// Validate + normalise a serial to the canonical uppercase hex form `ca_store` stores.
/// Returns empty if it is not 1–64 hex digits. Shared by the REST + dashboard
/// revoke paths so both reject the same inputs and match the same stored serial.
std::string normalize_serial(std::string s) {
    if (s.empty() || s.size() > 64 ||
        s.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        return {};
    for (auto& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

/// Outcome of the shared revoke_core (replaces a tri-state int — cpp-expert
/// PR4b). `audit_ok` is false when any audit row failed to persist, so both
/// revoke surfaces can raise Sec-Audit-Failed (#1240 M1/M2).
// ADR-0053: StoreError is a NEW, distinct outcome from NotFound — a genuine ca_store DB/lease
// failure must never be audited/reported as "serial not found or already revoked" (a false
// compliance record; a 503 outage misreported as a 404/idempotent-denial).
enum class RevokeOutcome { NotFound, StoreError, RevokedCrlStale, RevokedCrlPublished };
struct RevokeResult {
    RevokeOutcome outcome;
    bool audit_ok;
};

constexpr const char* kSettingsPanelFooter =
    "<p class=\"section-note\">To replace the default certificates with operator- or "
    "HSM-issued material, use <strong>TLS / mTLS Configuration</strong> above. "
    "Revocation takes effect immediately server-side; the public CRL is republished "
    "automatically.</p>";

/// Server-rendered HTMX fragment for the Settings → Internal CA panel (PKI PR4b).
/// Dark-theme product UI (NOT frontend-design). All agent-controlled fields
/// (subject, SAN) go through html_escape. Revoke buttons post to the settings
/// wrapper; downloads link to the public REST endpoints.
std::string render_ca_fragment(CaStore* ca_store,
                               std::optional<std::string_view> inventory_note) {
    if (!ca_store || !ca_store->is_open())
        return "<span class=\"muted\">Certificate authority unavailable.</span>";
    auto root_or_err = ca_store->get_root();
    if (!root_or_err)
        return "<span class=\"feedback-error\">Certificate authority store error.</span>";
    auto& root = *root_or_err;
    std::string html;
    if (!root) {
        html += "<p class=\"muted\">No internal CA on this install (operator-supplied "
                "certificates, or TLS disabled).</p>";
        return html;
    }

    html += "<div style=\"margin-bottom:0.75rem\">"
            "<div><strong>Algorithm:</strong> " +
            html_escape(root->algo) + "</div>"
            "<div><strong>SHA-256:</strong> <code>" +
            html_escape(root->fingerprint_sha256) + "</code></div>"
            "<div><strong>Expires:</strong> " + fmt_epoch(root->not_after) + " UTC</div>"
            "<div><strong>Trust mode:</strong> <span class=\"role-badge " +
            (root->mode == CaMode::Subordinate ? "role-admin\">Subordinate (enterprise-rooted)"
                                               : "role-user\">Built-in (self-signed root)") +
            "</span></div>"
            "</div>"
            "<div style=\"margin-bottom:1rem;display:flex;gap:0.5rem;flex-wrap:wrap\">"
            "<a class=\"btn btn-secondary btn-sm\" "
            "href=\"/api/v1/ca/root\">Download CA certificate</a>"
            "<a class=\"btn btn-secondary btn-sm\" "
            "href=\"/api/v1/ca/crl\">Download CRL</a>"
            "</div>";

    // ── Subordinate-CA (PR6) ──────────────────────────────────────────────────
    // Builtin: offer the CSR export + an import form so an operator can re-root
    // this CA under their enterprise PKI. Subordinate: state it's done. The form
    // posts to the CSRF-gated settings wrapper (same pattern as revoke). No
    // operator-controlled value is echoed back into this fragment, so there is no
    // injection surface here (the PEMs go to the wrapper, not into the HTML).
    if (root->mode == CaMode::Subordinate) {
        html += "<details style=\"margin-bottom:1rem\">"
                "<summary style=\"cursor:pointer\">Enterprise subordination</summary>"
                "<p class=\"hint\" style=\"margin:0.4rem 0\">"
                "This issuing CA is an intermediate signed by your enterprise root; issued "
                "certificates chain to that root. To re-subordinate, export a fresh CSR below and "
                "import the newly signed intermediate.</p>";
    } else {
        html += "<details style=\"margin-bottom:1rem\">"
                "<summary style=\"cursor:pointer\">Subordinate this CA to your enterprise root "
                "(optional)</summary>"
                "<p class=\"hint\" style=\"margin:0.4rem 0\">"
                "Export this CA's signing request, have your enterprise root sign it as a "
                "subordinate CA (basicConstraints CA:TRUE), then import the signed intermediate "
                "plus the parent chain. The signing key is unchanged, so already-issued "
                "certificates keep working.</p>";
    }
    html += "<a class=\"btn btn-secondary btn-sm\" style=\"margin-bottom:0.5rem\" "
            "href=\"/api/v1/ca/root-csr\">Download CA signing request "
            "(CSR)</a>"
            "<form hx-post=\"/api/settings/ca/import-chain\" hx-target=\"#ca-section\" "
            "hx-swap=\"innerHTML\" "
            "hx-confirm=\"Switch this CA's trust root to the imported enterprise chain?\">"
            "<textarea name=\"intermediate_pem\" rows=\"4\" "
            "placeholder=\"-----BEGIN CERTIFICATE----- (enterprise-signed intermediate over THIS "
            "CA's key)\" style=\"width:100%;margin-bottom:0.3rem\"></textarea>"
            "<textarea name=\"chain_pem\" rows=\"4\" "
            "placeholder=\"-----BEGIN CERTIFICATE----- (parent chain: enterprise root [+ "
            "intermediates])\" style=\"width:100%;margin-bottom:0.3rem\"></textarea>"
            "<button class=\"btn btn-secondary\" "
            "type=\"submit\">Import signed chain</button></form></details>";

    // A caller who may not list the issued certificates (confined view, degraded or unwired
    // access check) gets everything above (CA metadata, root/CRL/CSR links, the import form) and
    // a note where the inventory would be. The store is not read for them.
    if (inventory_note) {
        html += "<p class=\"feedback-error\">" + html_escape(std::string(*inventory_note)) +
                "</p>";
        html += kSettingsPanelFooter;
        return html;
    }
    constexpr int kPanelLimit = 500;
    auto issued_or_err = ca_store->list_issued(kPanelLimit, 0);
    if (!issued_or_err)
        return html + "<p class=\"feedback-error\">Certificate inventory unavailable "
                      "(store error).</p>";
    auto& issued = *issued_or_err;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    html += "<table class=\"user-table\">"
            "<thead><tr><th>Serial</th><th>Subject</th><th>Purpose</th><th>Expires</th>"
            "<th>Status</th><th></th></tr></thead><tbody>";
    if (issued.empty()) {
        html += "<tr><td colspan=\"6\" class=\"muted\">No certificates issued yet</td></tr>";
    } else {
        for (const auto& c : issued) {
            const bool revoked = c.status == CertStatus::Revoked;
            const std::string short_serial =
                c.serial_hex.size() > 16 ? c.serial_hex.substr(0, 16) + "…" : c.serial_hex;
            html += "<tr><td><code title=\"" +
                    html_escape(c.serial_hex) + "\">" + html_escape(short_serial) +
                    "</code></td>"
                    "<td>" + html_escape(c.subject) + "</td>"
                    "<td>" + html_escape(c.purpose) + "</td>"
                    "<td>" + fmt_epoch(c.not_after) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    (revoked                           ? "role-user\">Revoked"
                     : cert_expired(c.not_after, now) ? "role-user\">Expired"
                                                      : "role-admin\">Active") +
                    "</span></td><td>";
            if (!revoked) {
                // Carry the serial in a hidden input rather than a JSON hx-vals
                // attribute: simpler, and it avoids JSON-inside-an-HTML-attribute
                // escaping entirely. html_escape covers &, <, >, " AND ' (→ &#39;,
                // see web_utils.hpp), so the double-quoted value="" is safe for any
                // serial (and a single-quoted hx-vals would have been too) — the
                // form is just the clearer, codebase-standard pattern. The serial
                // is hex-only in practice; this renders whatever ca_store holds safely.
                html += "<form hx-post=\"/api/settings/ca/revoke\" hx-target=\"#ca-section\" "
                        "hx-swap=\"innerHTML\" style=\"display:inline-flex;gap:0.3rem\" "
                        "hx-confirm=\"Revoke certificate for &quot;" +
                        html_escape(c.subject) +
                        "&quot;? The agent is refused on its next connection.\">"
                        "<input type=\"hidden\" name=\"serial_hex\" value=\"" +
                        html_escape(c.serial_hex) +
                        "\">"
                        // UP-7: let the operator record WHY (compromise vs
                        // decommission) — stored as revocation_reason.
                        "<input type=\"text\" name=\"reason\" maxlength=\"256\" "
                        "placeholder=\"reason (optional)\" "
                        "style=\"width:9rem\">"
                        "<button class=\"btn btn-danger\" "
                        "type=\"submit\">Revoke</button></form>";
            }
            html += "</td></tr>";
        }
    }
    html += "</tbody></table>";
    // UP-4: the panel caps at kPanelLimit rows. If we hit the cap there may be
    // more — say so + point at the paginated REST endpoint, so certs beyond the
    // cap aren't silently invisible/unrevocable from the dashboard.
    if (static_cast<int>(issued.size()) >= kPanelLimit) {
        html += ca_issued_paging_hint(kPanelLimit);
    }
    html += kSettingsPanelFooter;
    return html;
}

// ── System > Certificates and secrets (view=pki) ─────────────────────────────
// The artboard shape of the same fragment, selected by `?view=pki` (GET) or a hidden
// `view=pki` form field (the two wrappers). The default shape above is untouched so
// /settings and its tests are byte-for-byte unchanged.

constexpr std::size_t kPkiPanelLimit = 500;

bool wants_pki_view(const httplib::Request& req) {
    return req.get_param_value("view") == "pki";
}

ca_panel::Model build_pki_model(CaStore* ca_store,
                                std::optional<std::string_view> inventory_note) {
    ca_panel::Model m;
    m.now = static_cast<std::int64_t>(std::time(nullptr));
    m.panel_limit = kPkiPanelLimit;
    if (!ca_store || !ca_store->is_open()) {
        m.availability = ca_panel::Availability::Unavailable;
        return m;
    }
    auto root_or_err = ca_store->get_root();
    if (!root_or_err) {
        m.availability = ca_panel::Availability::StoreError;
        return m;
    }
    if (!*root_or_err) {
        m.availability = ca_panel::Availability::NoRoot;
        return m;
    }
    const auto& root = **root_or_err;
    m.availability = ca_panel::Availability::Ready;
    m.root = {.algo = root.algo,
              .fingerprint_sha256 = root.fingerprint_sha256,
              .not_after = root.not_after,
              .subordinate = root.mode == CaMode::Subordinate};

    // `latest_crl()` conflates "none published" and "read failed"; both render as the
    // honest "None published, or the store could not be read", never "0 revoked".
    if (auto crl = ca_store->latest_crl()) {
        m.crl.present = true;
        m.crl.version = crl->version;
        m.crl.published_at = crl->published_at;
        m.crl.next_update = crl->next_update;
        m.crl.revoked_count = crl->revoked_count;
        auto stale = ca_store->has_unpublished_revocations();
        if (crl->next_update > 0 && crl->next_update < m.now)
            m.crl.state = ca_panel::CrlState::Expired; // lapsed outranks every milder state
        else if (!crl->revoked_count || !stale)
            m.crl.state = ca_panel::CrlState::Unconfirmed;
        else if (*stale)
            m.crl.state = ca_panel::CrlState::OutOfDate;
        else
            m.crl.state = ca_panel::CrlState::Current;
    }

    if (inventory_note) { // not read for a caller who may not list it
        m.inventory_note = std::string(*inventory_note);
        return m;
    }
    auto issued_or_err = ca_store->list_issued(static_cast<int>(kPkiPanelLimit), 0);
    if (!issued_or_err) {
        m.inventory_error = true;
        return m;
    }
    for (const auto& c : *issued_or_err)
        m.issued.push_back({.serial_hex = c.serial_hex,
                            .subject = c.subject,
                            .purpose = c.purpose,
                            .not_after = c.not_after,
                            .revoked = c.status == CertStatus::Revoked});
    return m;
}

/// The panel in whichever shape the caller asked for. `inventory_note` (non-empty optional) =
/// withhold ONLY the issued-certificate inventory and show the note in its place.
std::string render_ca(CaStore* ca_store, bool pki_view,
                      std::optional<std::string_view> inventory_note = std::nullopt) {
    return pki_view ? ca_panel::render(build_pki_model(ca_store, inventory_note))
                    : render_ca_fragment(ca_store, inventory_note);
}

/// Surface a non-2xx wrapper outcome. htmx 2 drops every 4xx/5xx body, so without this the
/// operator sees nothing. `message` is always a code-authored constant. `ensure_ascii` keeps
/// the header value 7-bit.
void set_toast(httplib::Response& res, const std::string& message, const char* level) {
    const nlohmann::json toast = {{"showToast", {{"message", message}, {"level", level}}}};
    res.set_header("HX-Trigger", toast.dump(-1, ' ', true));
}

void set_error_toast(httplib::Response& res, const std::string& message) {
    set_toast(res, message, "error");
}

} // namespace

void CaRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                               CaStore* ca_store, PublishCrlFn publish_crl_fn,
                               ExportCsrFn export_csr_fn, ImportChainFn import_chain_fn,
                               IssueCodeSigningFn issue_code_signing_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), ca_store,
                    std::move(publish_crl_fn), std::move(export_csr_fn), std::move(import_chain_fn),
                    std::move(issue_code_signing_fn));
}

namespace {

/// The A4 error body every `/api/v1/ca/issued` refusal shares (filtered and unfiltered).
void issued_fail(httplib::Response& res, int status, std::string_view message,
                 const std::string& cid, bool retryable) {
    res.status = status;
    res.set_content(retryable ? error_json_a4(status, message, cid, 5000, {})
                              : error_json_a4(status, message, cid),
                    kJson);
}

/// One `crypto.ca.certificates.view` row; a dropped write marks the response `Sec-Audit-Failed`
/// and is returned so a served list can say `audit_persisted: false` (set-and-proceed).
bool issued_audit(const CaRoutes::AuditFn& audit_fn, const httplib::Request& req,
                  httplib::Response& res, const std::string& result, const std::string& target,
                  const std::string& detail) {
    const bool ok = audit_fn ? audit_fn(req, "crypto.ca.certificates.view", result, "Security",
                                        target, detail)
                             : false;
    if (!ok)
        res.set_header("Sec-Audit-Failed", "true");
    return ok;
}

/// The standing check BOTH `/api/v1/ca/issued` lists share (ADR-0070 R2): rows of per-agent
/// certificates (subject, SAN) are fleet-wide, so a caller whose view is confined gets the
/// withheld answer, never a narrowed list (`list_issued` has no scope parameter). Returns the
/// standing the read may proceed under (kAvailable, or kRefused: the check admitted nobody, no
/// Inventory grant or a read failure partway through it, which the answer cannot tell apart; the
/// list is served and its success row names the standing); nullopt = the response is written. An
/// unwired probe fails closed (503, no retry hint: a wiring fault lasts until a restart).
/// `needs_api` is set by the filtered list, which also reads through the CryptoApi seam. Asked
/// before any parameter is parsed, so the answer does not depend on them. `target` names the
/// list on the rows written before its parameters are read.
[[nodiscard]] std::optional<crypto_widgets::Access>
admit_issued_read(const CaRoutes::FilteredIssuedDeps& filtered, const httplib::Request& req,
                  httplib::Response& res, const CaRoutes::AuditFn& audit_fn,
                  const std::string& cid, bool needs_api, const std::string& target) {
    namespace cw = crypto_widgets;
    if (!filtered.confinement_fn) {
        static std::once_flag logged;
        std::call_once(logged, [] {
            spdlog::error("ca routes: /api/v1/ca/issued confinement probe "
                          "(FilteredIssuedDeps::confinement_fn) is unwired - answering 503");
        });
    }
    if (needs_api && !filtered.api) {
        static std::once_flag logged;
        std::call_once(logged, [] {
            spdlog::error("ca routes: filtered /api/v1/ca/issued CryptoApi "
                          "(FilteredIssuedDeps::api) is unwired - answering 503");
        });
    }
    if ((needs_api && !filtered.api) || !filtered.confinement_fn) {
        issued_fail(res, 503,
                    needs_api ? "filtered certificate list unavailable"
                              : "certificate list unavailable",
                    cid, false);
        return std::nullopt;
    }
    const cw::Access standing = filtered.confinement_fn(req);
    switch (standing) {
    case cw::Access::kConfined:
        (void)issued_audit(audit_fn, req, res, "denied", target, cw::audit_detail_ca_withheld(cid));
        issued_fail(res, 403, cw::kConfinedWithheldMessage, cid, false);
        return std::nullopt;
    case cw::Access::kDegraded:
        (void)issued_audit(audit_fn, req, res, "failure", target,
                           cw::audit_detail_ca_degraded(cid, std::nullopt,
                                                        CryptoReadCause::kAccessCheck));
        issued_fail(res, 503, "access check unavailable", cid, true);
        return std::nullopt;
    case cw::Access::kAvailable:
    case cw::Access::kRefused: // no Inventory grant at all is not a confined view
        break;
    }
    return standing;
}

/// What the Settings panel may show this caller. `may_view` is Security:Read (the panel itself
/// is that gate's); `inventory_note`, when set, withholds ONLY the issued-certificate inventory
/// (the same standing as the API list): the CA metadata, root/CSR/CRL links and the import form
/// still render, with the note where the inventory would be. Quiet: no response and no audit
/// row (the panel itself is not audited).
struct PanelAccess {
    bool may_view{false};
    std::optional<std::string_view> inventory_note;
};

/// The note a caller who may not list the inventory sees in its place. nullopt = may list.
[[nodiscard]] std::optional<std::string_view>
issued_panel_withheld(const CaRoutes::FilteredIssuedDeps& filtered, const httplib::Request& req) {
    namespace cw = crypto_widgets;
    if (!filtered.confinement_fn)
        return "Certificate inventory unavailable (access check not configured).";
    switch (filtered.confinement_fn(req)) {
    case cw::Access::kConfined:
        return cw::kConfinedWithheldMessage;
    case cw::Access::kDegraded:
        return "Certificate inventory unavailable (access check failed).";
    case cw::Access::kAvailable:
    case cw::Access::kRefused:
        break;
    }
    return std::nullopt;
}

/// The body a wrapper (revoke / import-chain) answers with: never empty (htmx would swap an
/// empty body into #ca-section and blank the panel). A caller without Security:Read gets a
/// plain note; any other caller gets the panel, its inventory withheld per `access`.
std::string wrapper_panel_body(CaStore* ca_store, bool pki_view, const PanelAccess& access) {
    if (!access.may_view)
        return "<p class=\"muted\">The certificate authority panel is not shown to this "
               "account.</p>";
    return render_ca(ca_store, pki_view, access.inventory_note);
}

/// The success reply of a wrapper (revoke / import-chain). An unconfined caller sees the result
/// in the re-rendered inventory (the Revoked pill, the Trust mode badge), byte-identical to
/// before. A caller whose inventory is withheld has nothing in the panel that shows the
/// mutation, so the reply carries an explicit confirmation (banner + success toast) that does
/// not depend on the inventory. `prefix` is any code-authored banner that goes first.
std::string wrapper_success_body(httplib::Response& res, CaStore* ca_store, bool pki_view,
                                 const PanelAccess& access, std::string_view confirmation,
                                 std::string prefix = {}) {
    if (access.may_view && access.inventory_note) {
        set_toast(res, std::string(confirmation), "success");
        prefix += "<div class=\"alert alert-success\" style=\"margin-bottom:0.75rem\">" +
                  html_escape(std::string(confirmation)) + "</div>";
    }
    return prefix + wrapper_panel_body(ca_store, pki_view, access);
}

} // namespace

void CaRoutes::serve_filtered_issued(const FilteredIssuedDeps& filtered,
                                     const httplib::Request& req, httplib::Response& res,
                                     const AuditFn& audit_fn) {
    namespace cw = crypto_widgets;
    const auto cid = make_correlation_id();
    res.set_header("Cache-Control", "no-store, private");
    res.set_header("Vary", "Authorization, Cookie, X-Yuzu-Token");
    auto fail = [&](int status, std::string_view message, bool retryable) {
        issued_fail(res, status, message, cid, retryable);
    };
    auto audit = [&](const std::string& result, const std::string& target,
                     const std::string& detail) {
        return issued_audit(audit_fn, req, res, result, target, detail);
    };
    const auto standing =
        admit_issued_read(filtered, req, res, audit_fn, cid, /*needs_api=*/true, "filtered");
    if (!standing)
        return;
    const auto q = cw::parse_cert_params(req.params);
    if (!q) {
        fail(400, q.error(), false);
        return;
    }
    const std::string target = cw::audit_target(*q);
    auto read = filtered.api->ca_certificates(*q);
    if (!read) {
        if (read.error().kind == CryptoReadError::Kind::kInvalid) {
            fail(400, read.error().message, false);
            return;
        }
        (void)audit("failure", target,
                    cw::audit_detail_ca_degraded(cid, q->as_of, read.error().cause));
        // A pool too small for the read lasts until a restart: no retry hint.
        fail(503, read.error().message, !read.error().unavailable_until_restart);
        return;
    }
    const bool persisted = audit(
        "success", target,
        cw::audit_detail_with_standing(cw::audit_detail_certs(cid, *read), *standing));
    // H2: keyset paging - next_cursor (null on the last page) is the only continuation.
    nlohmann::json meta = {{"api_version", "v1"},
                           {"limit", read->query.limit},
                           {"has_more", read->truncated}};
    nlohmann::json out = {{"items", cw::ca_items_json(*read)},
                          {"count", read->rows.size()},
                          {"filter", cw::ca_filter_json(*read)},
                          {"next_cursor", read->next_cursor.empty()
                                              ? nlohmann::json(nullptr)
                                              : nlohmann::json(read->next_cursor)},
                          {"meta", std::move(meta)}};
    if (!persisted)
        out["audit_persisted"] = false;
    res.set_header("X-Correlation-Id", cid);
    res.set_content(out.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace), kJson);
}

void CaRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                               CaStore* ca_store, PublishCrlFn publish_crl_fn,
                               ExportCsrFn export_csr_fn, ImportChainFn import_chain_fn,
                               IssueCodeSigningFn issue_code_signing_fn) {
    // auth_fn is captured by the new /issue-code-signing handler below (to
    // attribute IssuedCertRecord::issued_by to the calling operator); every
    // other handler in this file still resolves its principal from
    // audit_fn/perm_fn alone.
    spdlog::info("CA routes: registering /api/v1/ca/* + Settings CA panel");
    // The handlers capture a COPY of filtered_ below: a probe wired after this call never
    // reaches them. Say so at boot, once, instead of on the first request.
    if (!filtered_.confinement_fn)
        spdlog::error("CA routes: no confinement probe wired before register_routes "
                      "(set_filtered_issued): GET /api/v1/ca/issued answers 503 and the Settings "
                      "CA panel withholds its inventory for every caller");
    if (!filtered_.api)
        spdlog::error("CA routes: no CryptoApi wired before register_routes "
                      "(set_filtered_issued): the filtered GET /api/v1/ca/issued answers 503");

    // Shared revoke core (REST + dashboard wrapper) over an ALREADY-normalised
    // serial: revoke → audit → republish CRL → audit. Returns -1 unknown/already-
    // revoked, 0 revoked-but-CRL-stale, 1 revoked+CRL-republished. Copied by value
    // into the handler lambdas so it outlives this stack frame.
    auto revoke_core = [ca_store, audit_fn, publish_crl_fn](
                           const httplib::Request& req, const std::string& serial,
                           const std::string& reason) -> RevokeResult {
        // gov B2 (F1: arch-1 + compliance HIGH; HIGH-1): derive the audit
        // target_type from the cert's OWN recorded purpose — now that
        // code-signing certs (gap-matrix #10) are revocable through this same
        // route, hardcoding "AgentCertificate" would durably mis-audit a
        // code-signing revocation. A read failure (genuine store error,
        // distinct from "not found" — see get_issued()'s contract) and a
        // genuine "no such serial" both fall back to the neutral
        // "Certificate": the StoreError/NotFound outcomes below already carry
        // the more specific signal for that case. Shared with MCP's
        // revoke_certificate via derive_cert_audit_target_type (ca_routes.hpp)
        // so both surfaces classify identically.
        const std::string target_type = derive_cert_audit_target_type(*ca_store, serial);
        auto revoked_or_err = ca_store->revoke(serial, reason);
        if (!revoked_or_err) {
            // ADR-0053: a genuine DB/lease failure — distinct from "not found or already
            // revoked" (a business fact). Must NOT be folded into "denied": that would falsely
            // audit a database outage as a rejected revoke attempt.
            const bool ok = audit_fn(req, "ca.cert.revoked", "failure", target_type, serial,
                                     revoked_or_err.error());
            return {RevokeOutcome::StoreError, ok};
        }
        if (!*revoked_or_err) {
            // #1240: unknown/already-revoked is reject-without-state-change →
            // result="denied" (matches every destructive sibling + idempotent
            // retry-safe); "failure" is reserved for an authorized-but-errored op.
            const bool ok = audit_fn(req, "ca.cert.revoked", "denied", target_type, serial,
                                     "serial not found or already revoked");
            return {RevokeOutcome::NotFound, ok};
        }
        bool audit_ok = audit_fn(req, "ca.cert.revoked", "success", target_type, serial,
                                 reason);
        // publish_crl() now fails honestly (#1240 B-1): has_value() is true ONLY
        // when the new CRL was persisted, so crl_ok never falsely claims success.
        const bool crl_ok = publish_crl_fn && publish_crl_fn().has_value();
        if (crl_ok)
            audit_ok = audit_fn(req, "ca.crl.published", "success", "Security", serial,
                                "reason=revoke") &&
                       audit_ok;
        else
            audit_ok = audit_fn(req, "ca.crl.published", "failure", "Security", serial,
                                "reason=revoke CRL build/record failed after revocation; public "
                                "CRL may be stale") &&
                       audit_ok;
        return {crl_ok ? RevokeOutcome::RevokedCrlPublished : RevokeOutcome::RevokedCrlStale,
                audit_ok};
    };

    // ── GET /api/v1/ca/root ── PUBLIC: the CA root certificate (PEM). ─────────
    // Public by definition — clients/browsers need it to trust the install, and
    // it is already presented in the TLS handshake.
    sink.Get("/api/v1/ca/root", [ca_store](const httplib::Request&, httplib::Response& res) {
        if (!ca_store || !ca_store->is_open()) {
            res.status = 503;
            res.set_content(error_json_a4(503, "CA not available", make_correlation_id()), kJson);
            return;
        }
        auto root_or_err = ca_store->get_root();
        if (!root_or_err) {
            res.status = 503;
            res.set_content(error_json_a4(503, "CA store unavailable — try again",
                                          make_correlation_id()),
                            kJson);
            return;
        }
        auto& root = *root_or_err;
        if (!root) {
            res.status = 404;
            res.set_content(error_json_a4(404, "no CA root", make_correlation_id(),
                                          "the server has not generated or imported a CA"),
                            kJson);
            return;
        }
        // Hermes L7: offer as a download (operators trust this file) + allow
        // day-long caching — the root cert is stable for the CA's 10-year life.
        res.set_header("Content-Disposition", "attachment; filename=\"yuzu-ca.pem\"");
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(root->cert_pem, "application/x-pem-file");
    });

    // ── GET /api/v1/ca/crl ── PUBLIC: the current CRL (DER). ──────────────────
    // Serves the latest PUBLISHED CRL (cheap, DoS-safe for a public endpoint —
    // we do NOT rebuild+sign on every request); builds one on first access only.
    // Revocation republishes (see /revoke), so the served CRL stays current.
    sink.Get("/api/v1/ca/crl", [ca_store](const httplib::Request&, httplib::Response& res) {
                if (!ca_store || !ca_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_json_a4(503, "CA not available", make_correlation_id()),
                                    kJson);
                    return;
                }
                // Hermes M1: serve ONLY the already-published CRL — never build+sign
                // on this PUBLIC path. The CA key must not be loaded for an
                // anonymous caller. ServerImpl pre-publishes a CRL at startup and
                // republishes on every revoke, so latest_crl() is populated in
                // steady state; a 503 here means the startup publish failed (an
                // operator/ops condition, not an anonymous-triggerable key load).
                auto latest = ca_store->latest_crl();
                if (!latest || latest->der.empty()) {
                    res.status = 503;
                    res.set_content(error_json_a4(503, "CRL not yet published", make_correlation_id()),
                                    kJson);
                    return;
                }
                const auto& der = latest->der;
                res.set_header("Cache-Control", "no-cache, must-revalidate"); // Hermes L5
                res.set_content(
                    std::string(reinterpret_cast<const char*>(der.data()), der.size()),
                    "application/pkix-crl");
            });

    // ── GET /api/v1/ca/issued ── Security:Read: issued-cert inventory. ────────
    sink.Get("/api/v1/ca/issued",
            [filtered = filtered_, perm_fn, audit_fn, ca_store](const httplib::Request& req,
                                                                httplib::Response& res) {
                if (!perm_fn(req, res, "Security", "Read"))
                    return;
                // ADR-0070 R2-2: any filter parameter selects the filtered list behind one
                // /crypto count. Additive: a request without one never reaches this branch.
                if (crypto_widgets::has_cert_filter_params(req.params)) {
                    serve_filtered_issued(filtered, req, res, audit_fn);
                    return;
                }
                // The inventory is fleet-wide and carries per-agent subject/SAN: the same
                // confinement answer and the same audit verb as the filtered list. Asked
                // before the store is touched or a parameter parsed.
                const auto cid = make_correlation_id();
                res.set_header("Cache-Control", "no-store, private");
                res.set_header("Vary", "Authorization, Cookie, X-Yuzu-Token");
                const auto standing = admit_issued_read(filtered, req, res, audit_fn, cid,
                                                        /*needs_api=*/false, "inventory");
                if (!standing)
                    return;
                if (!ca_store || !ca_store->is_open()) {
                    (void)issued_audit(audit_fn, req, res, "failure", "inventory",
                                       "inventory store unavailable; cid=" + cid);
                    res.status = 503;
                    res.set_content(error_json_a4(503, "CA not available", cid),
                                    kJson);
                    return;
                }
                const auto limit_opt = clamp_int(req, "limit", 200, 1, 1000);
                const auto offset_opt = clamp_int(req, "offset", 0, 0, 1000000);
                if (!limit_opt || !offset_opt) {
                    res.status = 400;
                    res.set_content(error_json_a4(400, "invalid numeric query parameter",
                                                  make_correlation_id()),
                                    kJson);
                    return;
                }
                const int limit = *limit_opt;
                const int offset = *offset_opt;
                // Probe one extra row to derive a precise has_more without a
                // separate COUNT query (agentic-first A1: a paginating client must
                // be able to tell when to stop, not guess from count<limit). The
                // probe row is trimmed before render. list_issued clamps at 10000,
                // so limit+1 (<=1001) is always in range.
                auto records_or_err = ca_store->list_issued(limit + 1, offset);
                if (!records_or_err) {
                    log_issued_list_failure("rest", records_or_err.error());
                    (void)issued_audit(audit_fn, req, res, "failure", "inventory",
                                       "inventory store unavailable; cid=" + cid);
                    res.status = 503;
                    res.set_content(
                        error_json_a4(503, "CA store unavailable — try again", cid, 5000, {}),
                        kJson);
                    return;
                }
                auto records = std::move(*records_or_err);
                const bool has_more = static_cast<int>(records.size()) > limit;
                if (has_more)
                    records.resize(static_cast<std::size_t>(limit));
                // The payload is built and serialised BEFORE the success row is written, so a
                // throw here cannot leave a row claiming a page that was never served.
                // `error_handler_t::replace`: a subject or SAN holding bytes that are not UTF-8
                // must not turn the page into a bare 500.
                nlohmann::json items = nlohmann::json::array();
                for (const auto& r : records) {
                    items.push_back({
                        {"serial_hex", r.serial_hex},
                        {"subject", r.subject},
                        {"san", r.san},
                        {"purpose", r.purpose},
                        {"status", cert_status_to_string(r.status)},
                        {"not_after", r.not_after},
                        {"issued_at", r.issued_at},
                        {"revoked_at", r.revoked_at},
                        {"revocation_reason", r.revocation_reason},
                        {"issued_by", r.issued_by},
                        // #1296: stable key-based CA identity (invariant across a
                        // subordinate re-key) so an inventory consumer can group
                        // "issued by this CA" correctly. Empty on pre-v5 rows.
                        {"issuer_key_id", r.issuer_key_id},
                    });
                }
                nlohmann::json meta = {{"api_version", "v1"},
                                       {"limit", limit},
                                       {"offset", offset},
                                       {"has_more", has_more}};
                if (has_more)
                    meta["next_offset"] = offset + limit;
                meta.update(crl_figures_json(*ca_store));
                nlohmann::json out = {{"items", std::move(items)},
                                      {"count", records.size()},
                                      {"meta", std::move(meta)}};
                constexpr auto kReplace = nlohmann::json::error_handler_t::replace;
                std::string body = out.dump(-1, ' ', false, kReplace);
                // Set-and-proceed, as the filtered list: a dropped row marks the response
                // (Sec-Audit-Failed, audit_persisted false), it does not withhold the page.
                const bool persisted = issued_audit(
                    audit_fn, req, res, "success", "inventory",
                    crypto_widgets::audit_detail_with_standing(
                        crypto_widgets::audit_detail_inventory(cid, records.size(), limit, offset,
                                                               has_more),
                        *standing));
                if (!persisted) {
                    out["audit_persisted"] = false;
                    body = out.dump(-1, ' ', false, kReplace);
                }
                res.set_header("X-Correlation-Id", cid);
                res.set_content(std::move(body), kJson);
            });

    // ── POST /api/v1/ca/revoke ── Security:Delete: revoke a serial. ───────────
    // Body: {"serial_hex": "...", "reason": "..."}. Revocation takes effect
    // server-side immediately (the mTLS accept gate consults ca_store, not the CRL);
    // republishing the CRL propagates it to external consumers.
    sink.Post("/api/v1/ca/revoke", [perm_fn, ca_store, revoke_core](
                                      const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Security", "Delete"))
            return;
        if (!ca_store || !ca_store->is_open()) {
            res.status = 503;
            res.set_content(error_json_a4(503, "CA not available", make_correlation_id()), kJson);
            return;
        }
        // Hermes M3: bound the body before parsing — a multi-GB POST must not
        // reach nlohmann::json::parse on this privileged endpoint.
        if (req.body.size() > kMaxRevokeBody) {
            res.status = 413;
            res.set_content(error_json_a4(413, "request body too large", make_correlation_id()),
                            kJson);
            return;
        }
        // Hermes INJ-M1: defensively wrap the parse. allow_exceptions=false turns
        // parse errors into a discarded value (caught by !is_object below), but a
        // bad_alloc / impl-specific throw on a privileged endpoint should still
        // yield a clean 400, not propagate.
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body, nullptr, false);
        } catch (...) {
            res.status = 400;
            res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
            return;
        }
        if (!body.is_object()) {
            res.status = 400;
            res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
            return;
        }
        // Hermes BFLA-M2: reject unknown keys (mass-assignment guard + catches
        // operator typos like "serail_hex" with a clear error instead of a silent
        // empty-serial 400). The handler only acts on serial_hex + reason.
        for (const auto& [k, v] : body.items()) {
            if (k != "serial_hex" && k != "reason") {
                res.status = 400;
                res.set_content(error_json_a4(400, "unknown field in request body",
                                              make_correlation_id(),
                                              "only serial_hex and reason are accepted"),
                                kJson);
                return;
            }
        }
        std::string reason = body.value("reason", "").substr(0, 256);
        // gov security LOW: strip CR/LF so an operator-controlled reason can't
        // inject newlines into the audit detail (log-injection defence in depth).
        std::erase_if(reason, [](char c) { return c == '\n' || c == '\r'; });
        // Hermes M4: validate + normalise serial_hex (1..64 hex, uppercase) so a
        // lowercase-input revoke still matches the canonical ca_store form.
        const std::string serial = normalize_serial(body.value("serial_hex", ""));
        if (serial.empty()) {
            res.status = 400;
            res.set_content(error_json_a4(400, "serial_hex must be 1-64 hex digits",
                                          make_correlation_id(),
                                          "pass the cert's serial_hex from /api/v1/ca/issued"),
                            kJson);
            return;
        }
        const RevokeResult rv = revoke_core(req, serial, reason);
        if (rv.outcome == RevokeOutcome::StoreError) {
            if (!rv.audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 503;
            res.set_content(error_json_a4(503, "CA store unavailable — try again",
                                          make_correlation_id()),
                            kJson);
            return;
        }
        if (rv.outcome == RevokeOutcome::NotFound) {
            // M1 (#1240): a dropped denied-row is the same evidence gap as a lost
            // success row — surface it.
            if (!rv.audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 404;
            res.set_content(
                error_json_a4(404, "serial not found or already revoked", make_correlation_id()),
                kJson);
            return;
        }
        // The revoke succeeded; a dropped audit row on this privileged op is an
        // evidence-chain gap surfaced via Sec-Audit-Failed (SOC 2 CC7.2).
        if (!rv.audit_ok)
            res.set_header("Sec-Audit-Failed", "true");
        nlohmann::json out = {{"revoked", true},
                              {"serial_hex", serial},
                              {"crl_republished", rv.outcome == RevokeOutcome::RevokedCrlPublished},
                              {"meta", {{"api_version", "v1"}}}};
        res.set_content(out.dump(), kJson);
    });

    // ── POST /api/v1/ca/issue-code-signing ── Security:Write: code-signing ────
    // leaf issuance via CSR custody (gap-matrix #10). The operator holds the
    // private key and submits a CSR; the server signs and returns ONLY the
    // leaf + chain. Body: {"csr_pem","label","validity_days"?}. SAFE because
    // the injected issue_code_signing_fn (ServerImpl) hard-pins usage to
    // {.code_signing=true} and sets CN=label — see this file's ca_routes.hpp
    // header for why that never reaches the #1118 agent-identity gate.
    sink.Post(
        "/api/v1/ca/issue-code-signing",
        [perm_fn, audit_fn, auth_fn, ca_store, issue_code_signing_fn](
            const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Security", "Write"))
                return;
            if (!ca_store || !ca_store->is_open() || !issue_code_signing_fn) {
                res.status = 503;
                res.set_content(error_json_a4(503, "CA not available", make_correlation_id()),
                                kJson);
                return;
            }
            if (req.body.size() > kMaxIssueCodeSigningBody) {
                res.status = 413;
                res.set_content(
                    error_json_a4(413, "request body too large", make_correlation_id()), kJson);
                return;
            }
            nlohmann::json body;
            try {
                body = nlohmann::json::parse(req.body, nullptr, false);
            } catch (...) {
                res.status = 400;
                res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()),
                                kJson);
                return;
            }
            if (!body.is_object()) {
                res.status = 400;
                res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()),
                                kJson);
                return;
            }
            // Mass-assignment guard (mirrors POST /ca/revoke above).
            for (const auto& [k, v] : body.items()) {
                if (k != "csr_pem" && k != "label" && k != "validity_days") {
                    res.status = 400;
                    res.set_content(
                        error_json_a4(400, "unknown field in request body", make_correlation_id(),
                                     "only csr_pem, label and validity_days are accepted"),
                        kJson);
                    return;
                }
            }
            // gov F9 (cpp-1): a present-but-non-string csr_pem/label throws
            // nlohmann's type_error.302 out of `.value<std::string>()` — an
            // uncaught throw here is a bare 500 with no A4 envelope. Guard the
            // same way the validity_days check below already does.
            if (body.contains("csr_pem") && !body["csr_pem"].is_string()) {
                res.status = 400;
                res.set_content(error_json_a4(400, "csr_pem must be a string", make_correlation_id()),
                                kJson);
                return;
            }
            if (body.contains("label") && !body["label"].is_string()) {
                res.status = 400;
                res.set_content(error_json_a4(400, "label must be a string", make_correlation_id()),
                                kJson);
                return;
            }
            const std::string csr_pem = body.value("csr_pem", "");
            const std::string label = body.value("label", "");
            if (csr_pem.empty()) {
                res.status = 400;
                res.set_content(error_json_a4(400, "csr_pem is required", make_correlation_id()),
                                kJson);
                return;
            }
            if (!is_valid_code_signing_label(label)) {
                res.status = 400;
                res.set_content(error_json_a4(400, "label must match ^[A-Za-z0-9._-]{1,64}$",
                                              make_correlation_id()),
                                kJson);
                return;
            }
            std::optional<int> validity_days;
            if (body.contains("validity_days") && !body["validity_days"].is_null()) {
                if (!body["validity_days"].is_number_integer()) {
                    res.status = 400;
                    res.set_content(error_json_a4(400, "validity_days must be an integer",
                                                  make_correlation_id()),
                                    kJson);
                    return;
                }
                // gov F6/UP-7: read as int64 and range-check BEFORE narrowing to
                // int — get<int>() on an out-of-int-range JSON integer (e.g.
                // 2^32+365) silently truncates, and a truncated value landing
                // INSIDE [1,730] would sail past a post-narrowing check. Also
                // makes REST reject >730 explicitly, matching MCP's schema
                // maximum:730 (the two twins now reject identically) instead of
                // deferring the ceiling entirely to the server-side refusal.
                int64_t v64 = 0;
                try {
                    v64 = body["validity_days"].get<int64_t>();
                } catch (...) {
                    // A JSON integer outside int64_t range (e.g. an unsigned
                    // value > INT64_MAX) — definitely outside [1,730].
                    res.status = 400;
                    res.set_content(error_json_a4(400, "validity_days must be between 1 and 730",
                                                  make_correlation_id()),
                                    kJson);
                    return;
                }
                if (v64 < 1 || v64 > kMaxCodeSigningValidityDaysRest) {
                    res.status = 400;
                    res.set_content(error_json_a4(400, "validity_days must be between 1 and 730",
                                                  make_correlation_id()),
                                    kJson);
                    return;
                }
                validity_days = static_cast<int>(v64);
            }
            // Re-derive the session (perm_fn above already authenticated this
            // request) ONLY to attribute IssuedCertRecord::issued_by to the
            // calling operator — matches the discovery_routes.cpp/
            // command_routes.cpp precedent for a post-perm_fn auth_fn re-read.
            std::string issued_by = "operator:unknown";
            if (auth_fn) {
                if (auto session = auth_fn(req, res))
                    issued_by = "operator:" + session->username;
            }
            auto issued = issue_code_signing_fn(csr_pem, label, validity_days, issued_by);
            if (!issued) {
                const std::string& err = issued.error();
                const bool no_root = err.starts_with(kCodeSigningNoRootPrefix);
                const bool bad_csr = err.starts_with(kCodeSigningBadCsrPrefix);
                // gov B1 / F6/UP-5/UP-7: two more caller-attributable
                // classifications, each with its own message so a weak key or a
                // bad validity_days is never reported as "csr_pem is invalid".
                const bool weak_key = err.starts_with(kCodeSigningWeakKeyPrefix);
                const bool bad_validity = err.starts_with(kCodeSigningBadValidityPrefix);
                int status = 500;
                std::string result = "failure";
                std::string msg = "code-signing issuance failed";
                if (no_root) {
                    status = 409;
                    result = "denied";
                    msg = "no CA root to issue from (generate default certs first)";
                } else if (bad_csr) {
                    status = 400;
                    result = "denied";
                    msg = "csr_pem is invalid or fails proof-of-possession";
                } else if (weak_key) {
                    status = 400;
                    result = "denied";
                    // Already caller-safe — crafted at the server.cpp call site.
                    msg = err.substr(std::string_view(kCodeSigningWeakKeyPrefix).size());
                } else if (bad_validity) {
                    status = 400;
                    result = "denied";
                    msg = err.substr(std::string_view(kCodeSigningBadValidityPrefix).size());
                }
                const bool audit_ok = audit_fn(req, "ca.cert.issued", result,
                                               "CodeSigningCertificate", label,
                                               "purpose=code-signing reason=" + err);
                if (!audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = status;
                res.set_content(error_json_a4(status, msg, make_correlation_id()), kJson);
                return;
            }
            const bool audit_ok =
                audit_fn(req, "ca.cert.issued", "success", "CodeSigningCertificate",
                         issued->serial_hex, "purpose=code-signing label=" + label);
            if (!audit_ok) {
                // gov HIGH-2 (ADR-1005 "mutations fail closed on audit
                // failure", mirrors #2466/#2406's engine-credential-mint
                // precedent above): the leaf IS already durably recorded in
                // ca_store via record_issued — only the audit row failed to
                // persist — so it is discoverable and reissuable rather than
                // lost. WITHHOLD certificate_pem/chain_pem instead of
                // returning them in an unaudited 200; Sec-Audit-Failed alone
                // (the REVOKE convention, unchanged elsewhere in this file) is
                // not enough here because that header is easy for a caller to
                // miss while still consuming the 200 body's secret material.
                res.status = 503;
                res.set_header("Sec-Audit-Failed", "true");
                res.set_content(
                    error_json_a4(503,
                                 "code-signing certificate " + issued->serial_hex +
                                     " was issued but its audit record could not be "
                                     "persisted; the certificate was withheld. Check GET "
                                     "/api/v1/ca/issued and reissue if the serial is not "
                                     "recorded",
                                 make_correlation_id()),
                    kJson);
                return;
            }
            nlohmann::json out = {{"certificate_pem", issued->certificate_pem},
                                  {"chain_pem", issued->chain_pem},
                                  {"serial_hex", issued->serial_hex},
                                  {"not_after", issued->not_after},
                                  {"purpose", "code-signing"},
                                  {"meta", {{"api_version", "v1"}}}};
            res.set_content(out.dump(), kJson);
        });

    // ── GET /api/v1/ca/root-csr ── Security:Read: export the install CA's CSR ──
    // (PR6) for an enterprise root to sign into a subordinate-CA intermediate.
    // The CSR carries only our CA public key + subject — no secret, and the key
    // is already public via GET /ca/root — but generating it requires the CA key,
    // done by the injected export_csr_fn (this module links no crypto). Read-only
    // (no state change); audited as a notable subordinate-setup admin action.
    sink.Get("/api/v1/ca/root-csr", [perm_fn, audit_fn, ca_store, export_csr_fn](
                                        const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Security", "Read"))
            return;
        if (!ca_store || !ca_store->is_open() || !export_csr_fn) {
            res.status = 503;
            res.set_content(error_json_a4(503, "CA not available", make_correlation_id()), kJson);
            return;
        }
        auto csr = export_csr_fn();
        if (!csr) {
            (void)audit_fn(req, "ca.root_csr.exported", "failure", "CaRoot", "root", "");
            res.status = 500;
            res.set_content(error_json_a4(500, "could not generate CA CSR", make_correlation_id()),
                            kJson);
            return;
        }
        if (!audit_fn(req, "ca.root_csr.exported", "success", "CaRoot", "root", ""))
            res.set_header("Sec-Audit-Failed", "true");
        res.set_header("Content-Disposition", "attachment; filename=\"yuzu-ca.csr\"");
        res.set_content(*csr, "application/pkcs10");
    });

    // ── POST /api/v1/ca/import-chain ── Security:Write: subordinate-CA import ──
    // (PR6). Body: {"intermediate_pem","chain_pem"}. The intermediate is OUR CA
    // key signed by the enterprise (CA:TRUE); chain_pem is the parent chain
    // (enterprise root [+ intermediates]). import_chain_fn (ServerImpl, holds the
    // CA key) validates our-key + is-CA + chains-to-parent, then switches the
    // issuing identity to subordinate mode. A failed validation is a "denied"
    // security event — an operator attempting to switch the trust root with bad
    // material is exactly what the audit chain must capture (SOC 2 CC6.1/CC7.2).
    sink.Post(
        "/api/v1/ca/import-chain",
        [perm_fn, audit_fn, ca_store, import_chain_fn, publish_crl_fn](const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!perm_fn(req, res, "Security", "Write"))
                return;
            if (!ca_store || !ca_store->is_open() || !import_chain_fn) {
                res.status = 503;
                res.set_content(error_json_a4(503, "CA not available", make_correlation_id()), kJson);
                return;
            }
            if (req.body.size() > kMaxImportBody) {
                res.status = 413;
                res.set_content(error_json_a4(413, "request body too large", make_correlation_id()),
                                kJson);
                return;
            }
            std::string intermediate, chain;
            try {
                const auto j = nlohmann::json::parse(req.body);
                intermediate = j.value("intermediate_pem", "");
                chain = j.value("chain_pem", "");
            } catch (...) {
                res.status = 400;
                res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()),
                                kJson);
                return;
            }
            if (intermediate.empty() || chain.empty()) {
                res.status = 400;
                res.set_content(
                    error_json_a4(400, "intermediate_pem and chain_pem are required",
                                  make_correlation_id()),
                    kJson);
                return;
            }
            // Defensive (Hermes 6c INFO): the validator composes pki::* helpers +
            // key loading. Those don't throw in practice (OpenSSL C APIs return
            // codes), but a C++ wrapper throw (e.g. bad_alloc) must not bypass the
            // audit row on this privileged trust-root switch — catch → failure audit.
            CaRoutes::ImportOutcome outcome;
            try {
                outcome = import_chain_fn(intermediate, chain);
            } catch (const std::exception& e) {
                (void)audit_fn(req, "ca.subordinate.imported", "failure", "CaRoot", "root",
                               std::string("reason=exception detail=") + e.what());
                res.status = 500;
                res.set_content(error_json_a4(500, "import failed", make_correlation_id()), kJson);
                return;
            } catch (...) {
                (void)audit_fn(req, "ca.subordinate.imported", "failure", "CaRoot", "root",
                               "reason=exception");
                res.status = 500;
                res.set_content(error_json_a4(500, "import failed", make_correlation_id()), kJson);
                return;
            }
            int status = 200;
            std::string msg;
            std::string detail = "mode=subordinate";
            // Audit vocab (#1240): success = applied; denied = caller's material
            // rejected (reject-without-state-change); failure = authorized but the
            // server errored. StoreError is the only "failure" here.
            std::string result = "denied";
            bool ok = false;
            switch (outcome) {
            case CaRoutes::ImportOutcome::Ok:
                ok = true;
                result = "success";
                break;
            case CaRoutes::ImportOutcome::NoRoot:
                status = 409;
                msg = "no CA root to subordinate (generate default certs first)";
                detail = "reason=no_root";
                break;
            case CaRoutes::ImportOutcome::BadIntermediate:
                status = 400;
                msg = "intermediate_pem is not a valid certificate";
                detail = "reason=bad_intermediate";
                break;
            case CaRoutes::ImportOutcome::NotCa:
                status = 422;
                msg = "intermediate is not a CA certificate (basicConstraints CA:TRUE required)";
                detail = "reason=not_ca";
                break;
            case CaRoutes::ImportOutcome::KeyMismatch:
                status = 422;
                msg = "intermediate does not carry this CA's public key";
                detail = "reason=key_mismatch";
                break;
            case CaRoutes::ImportOutcome::ChainInvalid:
                status = 422;
                msg = "intermediate does not verify to the provided parent chain";
                detail = "reason=chain_invalid";
                break;
            case CaRoutes::ImportOutcome::StoreError:
                status = 500;
                msg = "failed to persist the imported chain";
                detail = "reason=store_error";
                result = "failure";
                break;
            }
            bool audit_ok =
                audit_fn(req, "ca.subordinate.imported", result, "CaRoot", "root", detail);
            if (!ok) {
                if (!audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = status;
                res.set_content(error_json_a4(status, msg, make_correlation_id()), kJson);
                return;
            }
            // Re-publish the CRL so the served CRL is signed under the new issuing
            // cert's identity (issuer_fingerprint refresh after the re-key).
            const bool crl_ok = publish_crl_fn && publish_crl_fn().has_value();
            // #4829: was previously unaudited — the only publish_crl_fn caller in this file that
            // wrote no ca.crl.published row at all, symmetric with revoke_core's own pair above.
            audit_ok = audit_fn(req, "ca.crl.published", crl_ok ? "success" : "failure",
                                "Security", "root",
                                crl_ok ? "reason=import_chain"
                                       : "reason=import_chain CRL build/record failed after "
                                         "import; public CRL may be stale under the new issuer") &&
                       audit_ok;
            if (!audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            nlohmann::json out = {{"imported", true},
                                  {"mode", "subordinate"},
                                  {"crl_republished", crl_ok},
                                  {"meta", {{"api_version", "v1"}}}};
            res.set_content(out.dump(), kJson);
        });

    // ── GET /fragments/settings/ca ── Settings → Internal CA panel (PR4b). ────
    // Server-rendered HTMX fragment (admin reaches /settings; the fragment itself
    // gates on Security:Read for RBAC parity with GET /ca/issued). Dark-theme
    // product UI; all agent-controlled fields are html_escaped in render_ca_fragment.
    sink.Get("/fragments/settings/ca",
             [perm_fn, ca_store, filtered = filtered_](const httplib::Request& req,
                                                        httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Read"))
                     return;
                 res.set_header("Cache-Control", "no-store");
                 // A confined, degraded or unwired caller still gets the CA metadata, the
                 // root/CSR/CRL links and the import form: only the issued-certificate
                 // inventory is withheld, with a note where it would be.
                 res.set_content(render_ca(ca_store, wants_pki_view(req),
                                           issued_panel_withheld(filtered, req)),
                                 "text/html; charset=utf-8");
             });

    // ── POST /api/settings/ca/revoke ── dashboard revoke wrapper (PR4b). ──────
    // Form-encoded (HTMX hx-vals); Security:Delete. Re-renders the panel fragment
    // so the HTMX swap shows the updated inventory. Shares revoke_core with the
    // JSON REST endpoint (same validation, audit, CRL republish).
    // #2537: the trusted-origin allowlist is captured BY VALUE, not read through
    // `this`. These handlers deliberately capture every dependency by value and
    // never touch the owner, so copying the (small, boot-immutable) list keeps it
    // that way and raises no question about CaRoutes outliving the sink.
    const auto csrf_trusted = csrf_trusted_origins_;
    // The wrappers answer with the panel for a Security:Read holder, its inventory withheld
    // (note in place, the rest of the panel intact) unless the caller is also unconfined: the
    // same standing as the API inventory. A caller without Security:Read gets a plain note.
    // Never an empty body: htmx swaps it into #ca-section and would blank the panel.
    const auto panel_access = [probe = read_probe_,
                               filtered = filtered_](const httplib::Request& req) -> PanelAccess {
        PanelAccess a;
        a.may_view = probe && probe(req);
        if (a.may_view)
            a.inventory_note = issued_panel_withheld(filtered, req);
        return a;
    };
    sink.Post("/api/settings/ca/revoke",
              [perm_fn, audit_fn, ca_store, revoke_core, csrf_trusted, panel_access](
                  const httplib::Request& req, httplib::Response& res) {
        // H-1 (#1241): this revoke is authorized by the yuzu_session COOKIE alone
        // (a forged revoke = fleet-wide lockout DoS), so it carries a CSRF gate.
        //
        // What that gate is actually for, corrected on #2641 review: `SameSite=Lax`
        // sends the cookie on a cross-site TOP-LEVEL NAVIGATION only for SAFE
        // methods, and POST is not safe — so a purely cross-site form POST arrives
        // with NO cookie and is already unauthenticated. (An earlier version of this
        // comment said Lax "does not block" it. That is wrong. The likely source is
        // Chrome's Lax+POST intervention, which applies only to cookies with NO
        // SameSite attribute; `auth_routes.cpp` sets `SameSite=Lax` explicitly, so
        // it does not apply here.)
        //
        // The residual the gate closes is a SAME-SITE sibling origin — subdomain
        // takeover, XSS on a neighbour, a shared-domain deployment. Those are
        // same-site for cookie purposes, so they DO carry the cookie, while being a
        // different ORIGIN, which is exactly what Origin/Referer distinguishes.
        // Getting this right matters because the next person reasons from it. Run it
        // FIRST, before perm_fn, so a cross-site probe cannot read a perm/role
        // oracle off the response (Hermes PR4b LOW). A browser HTMX POST always
        // carries Origin (or at least Referer); this DESTRUCTIVE cookie endpoint
        // therefore treats a request with NEITHER header as cross-site too —
        // closing the both-empty gap a header-stripping proxy/WebView could ride
        // (Hermes PR4b MEDIUM). Token/Bearer automation uses the REST sibling.
        const std::string origin = req.get_header_value("Origin");
        const std::string referer = req.get_header_value("Referer");
        const bool same_site =
            !(origin.empty() && referer.empty()) &&
            origin_is_same_site(req.get_header_value("Host"), origin, referer, csrf_trusted);
        if (!same_site) {
            if (!audit_fn(req, "csrf.denied", "denied", "Endpoint", "ca.revoke",
                          "cross-origin or header-less dashboard revoke refused"))
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 403;
            res.set_content("<span class=\"feedback-error\">Cross-origin request refused.</span>",
                            "text/html; charset=utf-8");
            return;
        }
        if (!perm_fn(req, res, "Security", "Delete")) {
            set_error_toast(res, "Revoke refused: not permitted, or your session has expired.");
            return;
        }
        // Error branches re-render the FULL fragment with an inline banner rather
        // than swapping a bare <span> into #ca-section (which blanked the whole
        // panel until reload — #1241 happy/UP-6).
        const bool pki_view = wants_pki_view(req);
        // The panel's inventory lists every issued serial and subject, so it goes only to a
        // caller who may list it. Quiet probe (no response, no denial row); an unwired probe
        // means cannot read.
        const PanelAccess access = panel_access(req);
        res.set_header("Cache-Control", "no-store");
        auto error_panel = [&](int status, const std::string& msg) {
            res.status = status;
            set_error_toast(res, msg);
            res.set_content("<div class=\"alert alert-error\" style=\"margin-bottom:0.75rem\">" +
                                html_escape(msg) + "</div>" +
                                wrapper_panel_body(ca_store, pki_view, access),
                            "text/html; charset=utf-8");
        };
        if (!ca_store || !ca_store->is_open()) {
            error_panel(503, "Certificate authority unavailable.");
            return;
        }
        std::string reason = req.get_param_value("reason").substr(0, 256);
        std::erase_if(reason, [](char c) { return c == '\n' || c == '\r'; });
        const std::string serial = normalize_serial(req.get_param_value("serial_hex"));
        if (serial.empty()) {
            error_panel(400, "Invalid certificate serial.");
            return;
        }
        const RevokeResult rv = revoke_core(req, serial, reason);
        if (rv.outcome == RevokeOutcome::StoreError) {
            if (!rv.audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            error_panel(503, "Certificate authority store error — try again.");
            return;
        }
        if (rv.outcome == RevokeOutcome::NotFound) {
            // Don't render a success-looking panel for a no-op revoke (Hermes
            // PR4b INFO) — tell the operator the serial was unknown/already gone.
            if (!rv.audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            error_panel(404, "Serial not found or already revoked.");
            return;
        }
        if (!rv.audit_ok)
            res.set_header("Sec-Audit-Failed", "true");
        res.set_content(wrapper_success_body(res, ca_store, pki_view, access,
                                             "Certificate revoked. The issued-certificate "
                                             "inventory is not shown (see the note below)."),
                        "text/html; charset=utf-8");
    });

    // ── POST /api/settings/ca/import-chain ── dashboard subordinate import (PR6).
    // Form-encoded (HTMX); Security:Write. SAME CSRF gate as revoke — a forged
    // trust-root switch would be catastrophic (re-root the install), so run it
    // FIRST, before perm_fn, and treat both-headers-absent as cross-site too.
    // Shares import_chain_fn with the JSON REST endpoint; re-renders the panel so
    // the new Trust mode badge shows. The submitted PEMs are NEVER echoed back
    // into the fragment, so this wrapper adds no HTML-injection surface.
    sink.Post("/api/settings/ca/import-chain",
              [perm_fn, audit_fn, ca_store, import_chain_fn, publish_crl_fn, csrf_trusted,
               panel_access](const httplib::Request& req, httplib::Response& res) {
                  const std::string origin = req.get_header_value("Origin");
                  const std::string referer = req.get_header_value("Referer");
                  const bool same_site =
                      !(origin.empty() && referer.empty()) &&
                      origin_is_same_site(req.get_header_value("Host"), origin, referer,
                                          csrf_trusted);
                  if (!same_site) {
                      if (!audit_fn(req, "csrf.denied", "denied", "Endpoint", "ca.import-chain",
                                    "cross-origin or header-less dashboard CA import refused"))
                          res.set_header("Sec-Audit-Failed", "true");
                      res.status = 403;
                      res.set_content(
                          "<span class=\"feedback-error\">Cross-origin request refused.</span>",
                          "text/html; charset=utf-8");
                      return;
                  }
                  if (!perm_fn(req, res, "Security", "Write")) {
                      set_error_toast(res, "Import refused: not permitted, or your session has expired.");
                      return;
                  }
                  const bool pki_view = wants_pki_view(req);
                  // Inventory only for a caller who may list it; unwired probe means cannot read.
                  const PanelAccess access = panel_access(req);
                  res.set_header("Cache-Control", "no-store");
                  auto error_panel = [&](int status, const std::string& msg) {
                      res.status = status;
                      set_error_toast(res, msg);
                      res.set_content(
                          "<div class=\"alert alert-error\" style=\"margin-bottom:0.75rem\">" +
                              html_escape(msg) + "</div>" +
                              wrapper_panel_body(ca_store, pki_view, access),
                          "text/html; charset=utf-8");
                  };
                  if (!ca_store || !ca_store->is_open() || !import_chain_fn) {
                      error_panel(503, "Certificate authority unavailable.");
                      return;
                  }
                  const std::string intermediate = req.get_param_value("intermediate_pem");
                  const std::string chain = req.get_param_value("chain_pem");
                  if (intermediate.empty() || chain.empty()) {
                      error_panel(
                          400, "Both the signed intermediate and the parent chain are required.");
                      return;
                  }
                  CaRoutes::ImportOutcome outcome;
                  try {
                      outcome = import_chain_fn(intermediate, chain);
                  } catch (const std::exception& e) {
                      (void)audit_fn(req, "ca.subordinate.imported", "failure", "CaRoot", "root",
                                     std::string("reason=exception via=dashboard detail=") +
                                         e.what());
                      error_panel(500, "Import failed (internal error).");
                      return;
                  } catch (...) {
                      (void)audit_fn(req, "ca.subordinate.imported", "failure", "CaRoot", "root",
                                     "reason=exception via=dashboard");
                      error_panel(500, "Import failed (internal error).");
                      return;
                  }
                  std::string result = "denied";
                  std::string emsg;
                  int status = 200;
                  bool ok = false;
                  switch (outcome) {
                  case CaRoutes::ImportOutcome::Ok:
                      ok = true;
                      result = "success";
                      break;
                  case CaRoutes::ImportOutcome::NoRoot:
                      status = 409;
                      emsg = "No CA root to subordinate.";
                      break;
                  case CaRoutes::ImportOutcome::BadIntermediate:
                      status = 400;
                      emsg = "The intermediate is not a valid certificate.";
                      break;
                  case CaRoutes::ImportOutcome::NotCa:
                      status = 422;
                      emsg = "The intermediate is not a CA certificate (CA:TRUE required).";
                      break;
                  case CaRoutes::ImportOutcome::KeyMismatch:
                      status = 422;
                      emsg = "The intermediate does not carry this CA's public key.";
                      break;
                  case CaRoutes::ImportOutcome::ChainInvalid:
                      status = 422;
                      emsg = "The intermediate does not verify to the provided parent chain.";
                      break;
                  case CaRoutes::ImportOutcome::StoreError:
                      status = 500;
                      result = "failure";
                      emsg = "Failed to persist the imported chain.";
                      break;
                  }
                  bool audit_ok =
                      audit_fn(req, "ca.subordinate.imported", result, "CaRoot", "root",
                               ok ? "mode=subordinate via=dashboard" : "via=dashboard");
                  if (!ok) {
                      if (!audit_ok)
                          res.set_header("Sec-Audit-Failed", "true");
                      error_panel(status, emsg);
                      return;
                  }
                  // Refresh the CRL under the new issuing cert (issuer_fingerprint).
                  // Hermes 6c LOW: unlike the REST endpoint (which returns
                  // crl_republished), the dashboard must SURFACE a CRL-refresh
                  // failure — the import succeeded but external CRL consumers stay
                  // on the old issuer until the next publish. Prepend a notice.
                  const bool crl_ok = publish_crl_fn && publish_crl_fn().has_value();
                  // #4829: was previously unaudited, symmetric with the REST import-chain
                  // handler's own ca.crl.published addition above.
                  audit_ok = audit_fn(req, "ca.crl.published", crl_ok ? "success" : "failure",
                                      "Security", "root",
                                      crl_ok ? "reason=import_chain via=dashboard"
                                             : "reason=import_chain via=dashboard CRL build/record "
                                               "failed after import; public CRL may be stale under "
                                               "the new issuer") &&
                             audit_ok;
                  if (!audit_ok)
                      res.set_header("Sec-Audit-Failed", "true");
                  std::string body;
                  if (!crl_ok)
                      body += "<div class=\"alert alert-warning\" style=\"margin-bottom:0.75rem\">"
                              "Subordinated, but the CRL could not be republished — external CRL "
                              "consumers will not see the new issuer until the next publish.</div>";
                  res.set_content(wrapper_success_body(
                                      res, ca_store, pki_view, access,
                                      "Signed chain imported: this CA is now subordinate to the "
                                      "imported enterprise root. The issued-certificate inventory "
                                      "is not shown (see the note below).",
                                      std::move(body)),
                                  "text/html; charset=utf-8");
              });
}

} // namespace yuzu::server
