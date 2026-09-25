#include "auth_routes.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <shared_mutex>
#include <string_view>

#include "authz_topology_floor.hpp"
#include "body_cap_policy.hpp" // resolve_body_cap — path_class label for the service-scope deny metric (#2298 PR 3)
#include "deprovision_deny_split.hpp" // record_deprovision_deny_split — ADR-2001 #3069 shared split
#include "engine_principal_store.hpp"
#include "http_route_sink.hpp"
#include "legacy_self_service_allow.hpp"
#include "mcp_policy.hpp"
#include "mfa_qr.hpp"
#include "mfa_step_up.hpp"
#include "oidc_principal.hpp" // oidc_principal_id — ADR-2001 §5 single principal-string builder
#include "oidc_scim_link.hpp" // link_oidc_login_to_scim — ADR-2001 §2/D2 login-site orchestration
#include "principal_class.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial — the unified A4 denial wrapper (#1470)
#include "saml_principal.hpp"  // saml_principal_id / is_valid_saml_component — ADR-2001 PR4a
#include "saml_scim_link.hpp"  // link_saml_login_to_scim — ADR-2001 PR4a login-site orchestration
#include "service_scope_policy.hpp" // authz::service_scope_global_safe — #2298 PR 3 default-deny table

#include <ctime>

#include <nlohmann/json.hpp>

// Login page HTML (defined in login_ui.cpp)
extern const char* const kLoginHtml;

namespace yuzu::server {

namespace {

// Max stored length of a JIT-elevation justification (anti audit-row bloat). The
// operator-supplied reason is sanitised (control bytes → space) and truncated to
// this before it reaches the audit detail.
constexpr std::size_t kMaxJustificationLength = 1024;

// Reason label for yuzu_auth_read_degrade_total (#2396 / #2401). Distinguishes
// a transient pool-acquire outage (StoreBusy — the shared pool's
// connect-backoff breaker fast-failing, or pool saturation; the class the
// bounded acquire-retry rides out) from a query that RAN and errored
// (QueryFailed / WriteFailed) and from an undecryptable/absent secret
// (SecretUnavailable) — so SRE can tell a transient retry-storm apart from a
// uniform outage instead of reading one flat counter. Closed label set,
// pre-seeded in server.cpp. Any error that is not is_store_unavailable() must
// never reach a 503 degrade site, so the default ("query_error") is a
// belt-and-braces fallback, not an expected path.
[[nodiscard]] const char* degrade_reason(AuthDBError e) noexcept {
    switch (e) {
    case AuthDBError::StoreBusy:
        return "pool_acquire_timeout"; // matches the yuzu_*_read_degrade_total family
    case AuthDBError::SecretUnavailable:
        return "secret_unavailable";
    default:
        return "query_error";
    }
}

// Max stored length of a single sanitised detail value (e.g. an OIDC
// display name or email). These are short identity labels, not free-text
// justifications, so the cap is much tighter than kMaxJustificationLength.
constexpr std::size_t kMaxDetailValueLength = 128;

// The A4 denial envelope has moved to detail::a4_denial in
// rest_a4_envelope_http.hpp (#1470 — folded into the one unified builder so
// require_admin / require_permission / require_scoped_permission and the
// service-scope gates all emit the same shape with a correlation_id and, where
// known, the structured "<securable_type>:<operation>" permission field).
// Callers below use detail::a4_denial(res, code, msg, {.permission = ...}).

// system_clock time_point → ISO-8601 UTC ("YYYY-MM-DDTHH:MM:SSZ"). Mirrors
// guardian_ingest.cpp's ts_to_iso8601 / rest_api_v1.cpp's iso_now pattern —
// the established per-file idiom for this codebase (no shared formatter
// header exists yet). Used for JIT elevation's `expires_at` (follow-up B,
// security review 2026-06-30): since HA WS-1/1a (ADR-2002 §4) the elevation
// window is itself wall-clock (`system_clock`, durably persisted), so this
// formats the absolute `elevated_until` directly — no steady→system projection.
std::string iso8601_utc(std::chrono::system_clock::time_point tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#if defined(_WIN32)
    // gmtime_s returns nonzero on failure — don't silently format a
    // zero-inited tm as 1970-01-01 (L1, adversarial review).
    if (gmtime_s(&tm, &t) != 0)
        return "invalid-time";
#else
    if (gmtime_r(&t, &tm) == nullptr)
        return "invalid-time";
#endif
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

/// Boundary-aware cookie-value extractor.
///
/// Splits the Cookie header on ";" — tolerating both the RFC 6265 §4.2.1
/// canonical "; " separator and a bare ";" (some clients/proxies omit the
/// trailing space) by skipping leading whitespace in each segment — and
/// performs an exact-name match so a cookie named "foo__Host-yuzu_saml_bind"
/// cannot shadow "__Host-yuzu_saml_bind".  Returns the value string or empty.
///
/// DOES NOT alter extract_session_cookie (which has a separate legacy call
/// site and is not affected by the SAML binding-cookie shadowing risk).
static std::string find_cookie_value(const std::string& hdr, const std::string& name) {
    const std::string prefix = name + "=";
    std::size_t pos = 0;
    while (pos < hdr.size()) {
        // Tolerate "; " and bare ";" separators: skip optional leading whitespace.
        while (pos < hdr.size() && (hdr[pos] == ' ' || hdr[pos] == '\t')) ++pos;
        const auto delim   = hdr.find(';', pos);
        const auto seg_end = (delim == std::string::npos) ? hdr.size() : delim;
        const auto seg_len = seg_end - pos;
        // Exact name match: segment starts with "name=" and is at least that long.
        if (seg_len >= prefix.size() &&
            hdr.compare(pos, prefix.size(), prefix) == 0) {
            return hdr.substr(pos + prefix.size(), seg_len - prefix.size());
        }
        if (delim == std::string::npos) break;
        pos = delim + 1; // advance past ";"
    }
    return {};
}

} // namespace

namespace detail {

// See declaration + full rationale in auth_routes.hpp. Lives in the named
// `detail` namespace (not the anonymous one above) so unit tests can link
// against it directly — mirrors the rest_a4_envelope.hpp pattern.
std::string sanitize_detail_value(std::string_view v) {
    std::string out;
    out.reserve(std::min(v.size(), kMaxDetailValueLength));
    for (char c : v) {
        const auto uc = static_cast<unsigned char>(c);
        out.push_back((c == ';' || c == '=' || c == '\r' || c == '\n' || uc < 0x20 || uc == 0x7F)
                          ? '_'
                          : c);
    }
    if (out.size() > kMaxDetailValueLength) {
        out.resize(kMaxDetailValueLength);
        std::size_t i = out.size();
        while (i > 0 && (static_cast<unsigned char>(out[i - 1]) & 0xC0) == 0x80)
            --i;
        if (i > 0) {
            const unsigned char lead = static_cast<unsigned char>(out[i - 1]);
            const std::size_t seq_len =
                lead < 0x80 ? 1 : lead < 0xE0 ? 2 : lead < 0xF0 ? 3 : 4;
            if (out.size() - (i - 1) < seq_len)
                out.resize(i - 1);
        }
    }
    return out;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

AuthRoutes::AuthRoutes(Config& cfg, auth::AuthManager& auth_mgr, RbacStore* rbac_store,
                       ApiTokenStore* api_token_store, AuditStore* audit_store,
                       ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
                       AnalyticsEventStore* analytics_store, std::shared_mutex& oidc_mu,
                       std::unique_ptr<oidc::OidcProvider>& oidc_provider,
                       saml::SamlProvider* saml_provider)
    : cfg_(cfg), auth_mgr_(auth_mgr), rbac_store_(rbac_store), api_token_store_(api_token_store),
      audit_store_(audit_store), mgmt_group_store_(mgmt_group_store), tag_store_(tag_store),
      analytics_store_(analytics_store), oidc_mu_(oidc_mu), oidc_provider_(oidc_provider),
      saml_provider_(saml_provider) {}

// ---------------------------------------------------------------------------
// Static utilities
// ---------------------------------------------------------------------------

std::string AuthRoutes::extract_session_cookie(const httplib::Request& req) {
    auto cookie = req.get_header_value("Cookie");
    const std::string prefix = "yuzu_session=";
    auto pos = cookie.find(prefix);
    if (pos == std::string::npos)
        return {};
    pos += prefix.size();
    auto end = cookie.find(';', pos);
    return cookie.substr(pos, end == std::string::npos ? end : end - pos);
}

std::string AuthRoutes::url_decode(const std::string& s) {
    // Use a hexval lookup instead of std::stoul so that malformed percent-
    // sequences ("%GH", "%G", bare "%") never throw std::invalid_argument and
    // 500 the request.  A malformed sequence is emitted literally — valid
    // input behaviour (well-formed %HH + '+') is unchanged.
    // Mirrors yuzu::server::url_decode in web_utils.hpp; kept as a static
    // member so callers that already depend on AuthRoutes::url_decode
    // (OIDC/login/SAML form parsing) do not need include changes.
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            const int hi = hexval(s[i + 1]);
            const int lo = hexval(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
            out += s[i]; // malformed → emit literal '%'
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

std::string AuthRoutes::extract_form_value(const std::string& body, const std::string& key) {
    auto needle = key + "=";
    std::size_t search_from = 0;
    for (;;) {
        auto pos = body.find(needle, search_from);
        if (pos == std::string::npos)
            return {};
        // Boundary check: only accept a match at the very start of the body
        // or immediately after an '&' field separator. Without this, a
        // field name that merely ENDS in `key` (e.g. an attacker-supplied
        // "fooSAMLResponse=attacker&SAMLResponse=real") would shadow the
        // genuine field.
        if (pos == 0 || body[pos - 1] == '&') {
            pos += needle.size();
            auto end = body.find('&', pos);
            auto raw = body.substr(pos, end == std::string::npos ? end : end - pos);
            return url_decode(raw);
        }
        search_from = pos + 1;
    }
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

std::optional<auth::Session> AuthRoutes::synthesize_token_session(const ApiToken& api_token) {
    // F4 (Hermes pass-2 HIGH H3): explicit three-way branch on the PERSISTED
    // `principal_kind` field — never on the shape of `principal_id` (design
    // doc §6/decision 7; the "engine:" prefix is defense-in-depth/
    // readability, not the discriminator). The DB CHECK constraint normally
    // limits this column to {"human","engine"}, but this is a
    // defense-in-depth chokepoint: an out-of-allowlist value (e.g. "" from a
    // NULL cell, or anything else a corrupted row / a bypassed CHECK could
    // produce) must never silently fall through to the human branch — that
    // would attribute an unknown/corrupted principal_kind as a fully
    // privileged human session. Fail closed instead.
    if (api_token.principal_kind != "human" && api_token.principal_kind != "engine") {
        spdlog::error(
            "synthesize_token_session: token principal_id='{}' has out-of-allowlist "
            "principal_kind='{}' — refusing to synthesize a session (DB corruption or a "
            "bypassed CHECK constraint)",
            api_token.principal_id, api_token.principal_kind);
        return std::nullopt;
    }

    if (api_token.principal_kind == "human") {
        // ---- human branch ---------------------------------------------
        // No longer byte-identical to pre-#2021 behavior: a service-scoped
        // token's role is now floored below, rather than always resolved
        // from the creator's live role (see the scope_service branch).
        auth::Session synth;
        synth.username = api_token.principal_id;
        // #1837: no separate display label is stored for a token; fall back to
        // the principal id itself (matches the pre-#1837 behavior for local
        // principals, and is the best available label for a stable SSO id with
        // no live session to render a human name from — there is no persistent
        // principal→display-name directory; see #1852).
        synth.display_name = api_token.principal_id;
        synth.auth_source = api_token.mcp_tier.empty() ? "api_token" : "mcp_token";
        synth.token_scope_service = api_token.scope_service;
        synth.mcp_tier = api_token.mcp_tier;
        synth.principal_kind = "human";

        if (!api_token.scope_service.empty()) {
            // A service-scoped token is capped at the user floor regardless of
            // the minter's live role — ITServiceOwner (an RBAC grant, resolved
            // elsewhere) is the sole authority ceiling for such a token, never
            // the minter's legacy role. require_admin() already denies every
            // service-scoped token outright on token_scope_service alone
            // (below, pre-dating this cap) — the exposure this closes is the
            // OTHER consumers of role/effective_role() that have no such
            // independent guard: a service-scoped token minted by a
            // currently-admin user inherited `role == admin` and satisfied
            // the workflow/instruction step-approval gates' inline
            // `effective_role(*session) == admin` check (workflow_routes.cpp,
            // meant to require a human decision) and MCP bundle-ownership's
            // raw `session->role == admin` check (mcp_server.cpp).
            synth.role = auth::Role::user;
            // Fires on every service-scoped session, not just when the cap
            // changed the outcome — proving "changed the outcome" needs the
            // creator's live role, i.e. the very get_user_role() lookup this
            // branch deliberately skips (see the else branch's comment).
            // This is a debuggability signal ("the cap is active for this
            // token"), not an anomaly counter — there is no expected-vs-
            // unexpected split to alert on here.
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_service_token_role_capped_total").increment();
            }
        } else {
            // Resolve the creator's actual legacy role fresh (not unconditional
            // admin). get_user_role() queries the current role on every call, so
            // a creator who's been demoted since the token was issued will
            // produce a user-role session.
            auto legacy_role = auth_mgr_.get_user_role(api_token.principal_id);
            synth.role = legacy_role.value_or(auth::Role::user);
        }

        return synth;
    }

    // ---- engine branch (design doc §6) -------------------------------------
    // The session IS the engine principal: no creating-user re-attribution,
    // no get_user_role (there is no user row to consult — that would either
    // 401 spuriously or, worse, silently borrow a namesake human's role).
    auth::Session synth;
    synth.username = api_token.principal_id; // "engine:<slug>"
    synth.display_name = api_token.principal_id;
    synth.auth_source = "engine_token"; // sixth auth_source value, see auth.hpp
    synth.token_scope_service = api_token.scope_service;
    synth.mcp_tier = api_token.mcp_tier;
    synth.principal_kind = "engine";
    // Legacy Role enum is pinned to the floor — real authority comes from
    // RBAC assignments resolved elsewhere (§4), never from this field for an
    // engine session.
    synth.role = auth::Role::user;

    // engine_principal_store_ not yet wired (server.cpp/T8) → fail closed:
    // an engine-kind token synthesizes NO session rather than an
    // unauthenticated one silently passing through with floor privileges.
    if (!engine_principal_store_) {
        return std::nullopt;
    }

    auto lookup = engine_principal_store_->get_for_auth(api_token.principal_id);
    switch (lookup.status) {
        case EngineLookupStatus::Active:
            return synth;
        case EngineLookupStatus::MissingOrRevoked:
            // Terminal, 401-class (store doc §3.1): the credential's backing
            // principal is dead (or never existed) — no session, no retry.
            return std::nullopt;
        case EngineLookupStatus::StoreUnreachable:
            // Retryable, 503-class (store doc §3.1) — distinct from the
            // terminal MissingOrRevoked case above in RETRY semantics only,
            // never in the authorization outcome: both deny here. Surfacing
            // the 503 end-to-end through require_auth (rather than the
            // generic 401 an empty optional produces) is a noted follow-on,
            // not required by this slice.
            return std::nullopt;
    }
    return std::nullopt; // unreachable — silences -Wreturn-type on an enum add
}

std::optional<auth::Session> AuthRoutes::resolve_session(const httplib::Request& req) {
    // 1. Try session cookie (existing browser auth)
    auto token = extract_session_cookie(req);
    // Guard against oversized cookie values before passing to validate_session (#630).
    if (token.size() > auth::kMaxSessionTokenLength)
        return std::nullopt;
    auto session = auth_mgr_.validate_session(token);
    if (session) {
        // Lazily reap a passively-lapsed JIT elevation on the cookie chokepoint
        // (residual-risk follow-up A, security review 2026-06-30): there is no
        // background reaper, so the next authenticated request after a window
        // lapses is where the `role.elevation.expired` audit row is minted.
        // Uses audit_log_for_principal (not audit_log) because audit_log's
        // make_audit_event() itself calls resolve_session(req) — calling that
        // from inside resolve_session would re-enter this function. `session`
        // already carries the base role (Session::role is never the elevated
        // view), matching the `role.elevation.revoked` audit's principal_role.
        if (auto expired_user = auth_mgr_.reap_expired_elevation(token)) {
            audit_log_for_principal(req, "role.elevation.expired", "expired", *expired_user,
                                    auth::role_to_string(session->role), "User", *expired_user,
                                    "JIT admin elevation window lapsed");
        }
        return session;
    }

    // 2. Try Authorization: Bearer <token> (API token auth)
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.size() > 7 && auth_header.substr(0, 7) == "Bearer ") {
        auto raw = auth_header.substr(7);
        // Reject overly-long API tokens early to prevent DoS via expensive hash
        // operations in ApiTokenStore::validate_token() (#630).
        if (raw.size() <= auth::kMaxApiTokenLength) {
            if (api_token_store_) {
                auto api_token = api_token_store_->validate_token(raw);
                if (api_token)
                    return synthesize_token_session(*api_token);
            }
        }
    }

    // 3. Try X-Yuzu-Token header (alternative API token header)
    auto custom_header = req.get_header_value("X-Yuzu-Token");
    if (!custom_header.empty() && custom_header.size() <= auth::kMaxApiTokenLength &&
        api_token_store_) {
        auto api_token = api_token_store_->validate_token(custom_header);
        if (api_token)
            return synthesize_token_session(*api_token);
    }

    return std::nullopt;
}

auth::CredentialCheck AuthRoutes::engine_credential_state(const ApiToken& token) const {
    using R = auth::CredentialCheck;

    // Mirrors the two gates synthesize_token_session applies AFTER the token row
    // validates. Kept beside revalidate_stream deliberately: if that function only
    // consults the api_tokens row, a live row is treated as live authority even
    // though a fresh request carrying the same header would be refused.

    // Gate 1: the principal_kind allowlist. An out-of-allowlist value means DB
    // corruption or a bypassed CHECK constraint; synthesize_token_session refuses to
    // mint a session for it, so an existing stream must not survive on it either.
    if (token.principal_kind != "human" && token.principal_kind != "engine") {
        return R::kRevoked;
    }
    if (token.principal_kind != "engine") {
        return R::kValid; // human tokens have no further backing-principal gate
    }

    // Gate 2: the engine principal must still be Active. Unwired store = fail closed,
    // matching synthesize_token_session (an engine token must never authenticate
    // through an unwired store).
    if (!engine_principal_store_) {
        return R::kRevoked;
    }
    // The ONE cached-lookup site (#2367). This function is only ever reached
    // from revalidate_stream — the per-tick liveness re-check of an ALREADY
    // authenticated stream — never from session synthesis or an on-behalf-of
    // target check, both of which call get_for_auth and read through to
    // Postgres every time (which is why this method is private).
    const auto engine = engine_principal_store_->get_for_auth_revalidate(token.principal_id);
    switch (engine.status) {
    case EngineLookupStatus::Active:
        // Propagate WHERE the answer came from, not just what it was. A cached
        // Active reported as plain kValid would reset the pump's grace clock,
        // making cache residency and the grace window additive — the stream
        // rides the cache, then gets a full FRESH grace window once it expires.
        // kValidStale keeps the pump measuring from the last AUTHORITATIVE
        // confirmation, so total survival stays bounded by the grace window.
        return engine.from_cache ? R::kValidStale : R::kValid;
    case EngineLookupStatus::MissingOrRevoked:
        // Terminal: the credential's backing principal is dead. Cut the stream now —
        // this is the revocation path the per-tick re-validation exists for.
        return R::kRevoked;
    case EngineLookupStatus::StoreUnreachable:
        // We asked and did not get an answer. Indeterminate, NOT revoked: the stream
        // rides out its bounded grace window rather than every engine stream on the
        // fleet dying together on a store blip (Decision 15(i), CH-4).
        return R::kIndeterminate;
    }
    return R::kRevoked; // unreachable — fail closed on a future enum value
}

auth::CredentialCheck AuthRoutes::revalidate_stream(const httplib::Request& req,
                                                    const std::string& expected_principal) {
    using R = auth::CredentialCheck;

    // The invariant: a stream lives iff a FRESH request carrying these same headers
    // would still authenticate as `expected_principal`. So this must mirror
    // resolve_session's precedence EXACTLY — including its fall-through. An earlier
    // version returned kRevoked as soon as a cookie failed, which killed (every 3 s,
    // in a reconnect loop) a perfectly good token-authenticated stream that happened
    // to also carry a stale cookie from a browser jar or a cookie-injecting proxy.
    // It failed closed, but it was still wrong.

    // 1. Session cookie. AuthManager's session table is in-memory, so a "no" here is
    //    always DEFINITIVE — there is no backend that could be unavailable.
    const auto cookie = extract_session_cookie(req);
    if (cookie.size() > auth::kMaxSessionTokenLength) {
        // resolve_session hard-rejects an oversized cookie rather than falling through,
        // so a fresh request carrying one would 401. The stream must die for the same
        // reason, or the "lives iff a fresh request would authenticate" invariant is a
        // fiction.
        return R::kRevoked;
    }
    if (!cookie.empty()) {
        if (auto session = auth_mgr_.validate_session(cookie)) {
            // A credential that now resolves to a DIFFERENT principal is a rebind, and
            // a rebind revokes the stream's authority: the stream carries the original
            // principal's messages and must not survive the change.
            if (session->username == expected_principal)
                return R::kValid;
            return R::kRevoked;
        }
        // Cookie present but dead — fall through to the token headers, exactly as
        // resolve_session does.
    }

    // 2. Authorization: Bearer <token>, then 3. X-Yuzu-Token — resolve_session's order.
    // Both are tried: a request may carry a dead Bearer and a live X-Yuzu-Token.
    std::array<std::string, 2> candidates{};
    if (const auto header = req.get_header_value("Authorization");
        header.size() > 7 && header.substr(0, 7) == "Bearer ") {
        candidates[0] = header.substr(7);
    }
    candidates[1] = req.get_header_value("X-Yuzu-Token");

    bool store_unavailable = false;
    for (const auto& raw : candidates) {
        if (raw.empty() || raw.size() > auth::kMaxApiTokenLength || !api_token_store_)
            continue;
        const auto checked = api_token_store_->validate_token_checked(raw);
        switch (checked.status) {
        case ApiTokenStore::TokenCheck::kValid:
            if (checked.token && checked.token->principal_id == expected_principal) {
                // A live token row is NOT sufficient. synthesize_token_session applies two
                // further gates before it will mint a session, and the "a stream lives iff
                // a fresh request would still authenticate" invariant is only true if this
                // applies them too. Without them a DELETED OR REVOKED ENGINE PRINCIPAL kept
                // its live MCP stream indefinitely — every fresh request 401'd, while the
                // stream slid its own idle TTL forward on each tick and never expired.
                // Returned verbatim, including kValidStale (#2367): the engine
                // gate is the only staleness this function models today, and
                // flattening it to kValid here would undo the whole point of
                // the distinction. NOTE the token half above is NOT modelled —
                // `validate_token_checked` is served from its own 60 s cache
                // and reports a hit as plain kValid, so a token-authenticated
                // stream still carries the additive window this closes for
                // engine principals. Pre-existing; tracked as #2447.
                return engine_credential_state(*checked.token);
            }
            break; // a valid token for SOMEONE ELSE is not authority for this stream
        case ApiTokenStore::TokenCheck::kUnavailable:
            // The store could not answer. That is NOT evidence of revocation — remember
            // it, but keep looking: another credential on the request may still say yes.
            store_unavailable = true;
            break;
        case ApiTokenStore::TokenCheck::kInvalid:
            break; // definitively not a credential — try the next one
        }
    }

    // Nothing on this request authenticates as the stream's principal. If the store was
    // unreachable while we looked, we genuinely do not KNOW — say so, and let the pump
    // ride out its bounded grace window rather than cutting every stream on the fleet
    // at the same instant (Decision 15(i), CH-4).
    return store_unavailable ? R::kIndeterminate : R::kRevoked;
}

std::optional<auth::Session> AuthRoutes::require_auth(const httplib::Request& req,
                                                      httplib::Response& res) {
    if (auto session = resolve_session(req))
        return session;

    res.status = 401;
    res.set_content(detail::a4_denial(res, 401, "unauthorized"), "application/json");
    return std::nullopt;
}

bool AuthRoutes::require_admin(const httplib::Request& req, httplib::Response& res) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    // Service-scoped tokens are limited to ITServiceOwner permissions for one named
    // service; they must never reach admin routes regardless of the creator's role.
    // MCP tokens are for fleet management (queries, instruction execution) and must
    // not be used to administer the server itself (settings, users, TLS, OIDC).
    // See docs/mcp-server.md and docs/auth-architecture.md (#520).
    if (!session->token_scope_service.empty()) {
        audit_log(req, "auth.admin_required", "denied", "", "",
                  "service-scoped token blocked from admin route");
        res.status = 403;
        // A4 unified envelope (#1470). require_admin gates a whole route, not a
        // single securable:operation, so no `permission` field is emitted; the
        // correlation_id ties the 403 to the auth.admin_required audit row.
        res.set_content(
            detail::a4_denial(res, 403, "service-scoped tokens cannot perform admin operations"),
            "application/json");
        return false;
    }
    if (!session->mcp_tier.empty()) {
        audit_log(req, "auth.admin_required", "denied", "", "",
                  "MCP token blocked from admin route");
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "MCP tokens cannot perform admin operations"),
                        "application/json");
        return false;
    }

    // effective_role(), not the raw role, so an active JIT admin elevation
    // (POST /api/v1/elevate) is treated as admin for its window and auto-reverts.
    // Only interactive cookie sessions can be elevated — the MCP/service-token
    // guards above already rejected those credentials, and elevate_session never
    // runs for them.
    if (auth::effective_role(*session) != auth::Role::admin) {
        // SOC 2 CC7.2: every privileged-endpoint denial must surface in
        // the audit chain, not just the request log. Emitting here closes
        // the gap for every caller in one place rather than threading an
        // audit_fn through dozens of route registrations (governance PR4).
        audit_log(req, "auth.admin_required", "denied", "endpoint", req.path);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "admin role required"), "application/json");
        return false;
    }
    return true;
}

bool AuthRoutes::service_scope_admits(std::string_view securable_type,
                                      std::string_view operation) const {
    if (service_scope_global_safe_override_for_test_) {
        for (const auto& pair : *service_scope_global_safe_override_for_test_) {
            if (pair.securable_type == securable_type && pair.operation == operation)
                return true;
        }
        return false;
    }
    return authz::service_scope_global_safe(securable_type, operation);
}

bool AuthRoutes::require_permission(const httplib::Request& req, httplib::Response& res,
                                    const std::string& securable_type,
                                    const std::string& operation) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    // JIT admin elevation: an active elevation grants full admin for its window,
    // so it satisfies any securable:operation (mirrors require_admin gating on
    // effective_role). Only interactive cookie sessions can be elevated —
    // elevate_session never runs for MCP/service-scoped tokens (which are
    // synthesized per-request and carry no elevated_until), so this short-circuit
    // cannot be reached by them today. Auditing is on the elevation lifecycle
    // (role.elevation.granted/expired), not per privileged action.
    //
    // Defense-in-depth (#2298 PR 3): the `token_scope_service.empty()` guard
    // is currently redundant with the invariant above, not load-bearing — kept
    // so this short-circuit can never be the thing that lets a service-scoped
    // token bypass the default-deny flip below, if that invariant ever
    // changes. Do NOT read its presence as evidence elevation is reachable
    // for service tokens today; it is not.
    if (auth::is_elevated(*session) && session->token_scope_service.empty())
        return true;

    // Engine principals have NO legacy or service-scoped authority — their only
    // authority is an explicit RBAC assignment (design §4.2 default-deny). The
    // pre-RBAC legacy fallback below would otherwise hand an engine credential
    // fleet-wide Read the moment RBAC is off (the default). Resolve engine
    // sessions here, RBAC-only, or deny.
    if (session->principal_kind == "engine") {
        if (!rbac_store_ || !rbac_store_->is_open()) {
            // Cannot evaluate authority — fail closed, 503.
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "engine principal denied: RBAC store unavailable");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                              detail::A4ErrorOpts{.permission = securable_type + ":" +
                                                                        operation}),
                            "application/json");
            return false;
        }
        if (!rbac_store_->is_rbac_enabled() ||
            !rbac_store_->check_permission(session->username, securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "engine principal denied " + securable_type + ":" + operation);
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        // Belt-and-braces (#2298 PR 3): engine-token mint already rejects a
        // non-empty `scope_service` (`api_token_store.cpp::validate_engine_mint`),
        // so this guards a corrupted/constraint-bypassed row only, not a live
        // path. An engine session's own direct RBAC grant is a DIFFERENT
        // authority than ITServiceOwner and is not exempt from the same
        // default-deny consult the service branch applies below — a
        // corrupted row must not use the engine branch as a side door around
        // the seeded-empty allow-list.
        if (!session->token_scope_service.empty() &&
            !service_scope_admits(securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "engine principal denied: corrupted scope_service on engine session "
                      "blocked by service-scope default-deny");
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            // No `.permission` field: holding `perm` alone would not admit
            // this session (compile-time-empty allow-list — routed-concern
            // "MUST NOT name a permission that wouldn't actually admit").
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm),
                            "application/json");
            return false;
        }
        return true;
    }

    // MCP-tier tokens: enforce the tier policy (readonly/operator/supervised) then
    // fall through to the standard RBAC/role check using the creator's actual role.
    // The tier is the primary MCP access control boundary; RBAC is a secondary layer.
    // Tier enforcement applies on all transports (MCP JSON-RPC and REST API) so
    // a token cannot bypass the tier by switching endpoints.
    if (!session->mcp_tier.empty()) {
        if (!mcp::tier_allows(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' does not allow " +
                          securable_type + ":" + operation);
            res.status = 403;
            // A4 unified envelope (#1470) — the kPermissionDenied specialisation
            // names the missing grant in the structured `permission` field.
            const std::string perm = securable_type + ":" + operation;
            res.set_content(
                detail::a4_denial(res, 403, "MCP token tier does not allow " + perm,
                                  detail::A4ErrorOpts{.permission = perm}),
                "application/json");
            return false;
        }
        // Approval-gated operations (supervised tier on destructive ops).
        // On the MCP JSON-RPC transport (`/mcp/v1/`) the C8 gate in
        // mcp_server.cpp is the AUTHORITATIVE approval gate: it mints a ticket,
        // and on a recall it verifies + consumes a valid approval before the
        // per-tool handler ever calls this function (#289 ticket-then-recall).
        // Re-denying here would break that recall (consume-then-deny) — so skip
        // it on the MCP endpoint. Keep the denial for EVERY OTHER transport: a
        // REST route hit by an MCP token must not bypass the ticket flow (#520).
        if (req.path != "/mcp/v1/" &&
            mcp::requires_approval(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.approval_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' requires approval for " +
                          securable_type + ":" + operation + " on a non-MCP transport");
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            res.set_content(
                detail::a4_denial(
                    res, 403,
                    "operation requires approval for this MCP tier on this transport",
                    detail::A4ErrorOpts{.remediation = "this operation is approval-gated for the "
                                               "supervised MCP tier; use the MCP ticket-then-recall "
                                               "flow (POST /mcp/v1/) or the dashboard",
                                .permission = perm}),
                "application/json");
            return false;
        }
    }

    // Service-scoped tokens (PR 3 — the flip, #2298 durable fix): ITServiceOwner
    // remains the AUTHORITY CEILING (a service token can never exceed what that
    // role grants), but no longer the sole gate. A pair also has to clear the
    // seeded-EMPTY `kServiceScopeGlobalSafe` allow-list to be exercised
    // fleet-wide/unconfined — everything else 403s by default now, inverting
    // the old "ITServiceOwner holds it -> admit" shape. This closes the ~100
    // instances where that admit reached fleet-wide data with no per-agent
    // narrowing at all (`docs/adr/1006-service-scope-default-deny.md`). A
    // route that legitimately needs to serve service tokens migrates onto
    // `require_fleet_read`/`confine_agent_target` (Phase 2, metric-prioritized
    // below) instead of growing this allow-list.
    if (!session->token_scope_service.empty()) {
        const std::string perm = securable_type + ":" + operation;
        // #1717: gate on `rbac_enforcement_in_effect`, not raw
        // `is_rbac_enabled()` (same standardization as the legacy branch
        // below and `require_scoped_permission`'s service branch). A null
        // store or a genuinely-disabled one still denies here; a degraded
        // view (open, but a stale cached "disabled" that never observed a
        // real toggle) is treated as still-enforced and falls through to
        // fail closed via `check_role_has_permission` on that same handle
        // instead — deny-on-degrade either way, just a more accurate reason.
        if (!rbac_store_ || !rbac_enforcement_in_effect(rbac_store_)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "service-scoped token blocked: RBAC not enabled");
            res.status = 403;
            // No `.permission`: granting `perm` does not fix "RBAC disabled".
            res.set_content(detail::a4_denial(res, 403,
                                              "service-scoped tokens require RBAC to be enabled"),
                            "application/json");
            return false;
        }
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "service-scoped token blocked: lacks ITServiceOwner permission");
            res.status = 403;
            // Post-flip, an ITServiceOwner grant is necessary but no longer
            // sufficient (the allow-list check below still applies) — the
            // message says so and `.permission` is omitted rather than
            // implying this single grant would admit the caller.
            std::string msg = "service-scoped token does not grant " + perm +
                              " (requires ITServiceOwner AND an explicit service-scope "
                              "allow-list entry)";
            res.set_content(detail::a4_denial(res, 403, msg), "application/json");
            return false;
        }
        if (!service_scope_admits(securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "service-scoped token blocked: default-deny (" + perm +
                          " not on the service-scope global-safe allow-list)");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_service_scope_default_denied_total",
                           {{"permission", perm},
                            {"path_class", std::string(resolve_body_cap(req.method, req.path)
                                                            .path_class)}})
                    .increment();
            }
            res.status = 403;
            // No `.permission`: the allow-list is compile-time-empty, so no
            // RBAC grant admits this caller (routed-concern MUST — a blanket
            // deny must not name a permission that wouldn't actually admit).
            std::string msg = "service-scoped token does not grant " + perm +
                              " (not on the service-scope global-safe allow-list; this route "
                              "needs an explicit confined path via require_fleet_read/"
                              "confine_agent_target)";
            res.set_content(detail::a4_denial(res, 403, msg), "application/json");
            return false;
        }
        return true;
    }

    // #1717 (ADR-0017 ship-now HIGH): gate on `rbac_enforcement_in_effect`, NOT
    // raw `is_rbac_enabled`. A corrupt/load-failed rbac.db (`is_open()==false`)
    // then ENTERS this branch and fails CLOSED via `check_permission` on the dead
    // handle (`db_==nullptr` → false → 403), instead of skipping RBAC and falling
    // through to the legacy Read-allow below — a full-fleet fail-OPEN disclosure to
    // any authenticated principal. Behaviour-neutral for fresh installs (open db +
    // enabled=false → `rbac_enforcement_in_effect` false → legacy preserved) and for
    // a wholly unwired store (`rbac_store_==nullptr` → short-circuits to legacy).
    // This is the SAME predicate the ADR-0017 per-row scope filters key on, so the
    // gate and the filter can never disagree on a corrupt store.
    if (rbac_store_ && rbac_enforcement_in_effect(rbac_store_)) {
        if (!rbac_store_->check_permission(session->username, securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "RBAC denied " + securable_type + ":" + operation);
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        return true;
    }

    // Legacy fallback: write/delete/execute/approve require admin (effective_role
    // so an elevation still satisfies it as defense-in-depth, though the
    // is_elevated short-circuit above already returned for elevated sessions).
    // #2376 topology floor: a handful of Reads are authorization TOPOLOGY
    // itself (access-review export, RBAC role graph, engine-principal grant
    // graph) and must not fall through the generic "Read is always allowed"
    // legacy rule below — see authz_topology_floor.hpp for the rationale and
    // why the set is fixed, not configurable.
    //
    // NOTE: an MCP-tier token that reaches this point carries its CREATOR's
    // real legacy role (see the mcp_tier branch above / require_auth) —
    // so an admin's MCP token passes the floor here and a non-admin's does
    // not. That is intended, not a gap to "fix".
    const bool floored = topology_floor_applies(securable_type, operation);
    // #2963: a pair on the legacy self-service allowlist (currently just
    // ApiToken:Rotate) skips the admin-role requirement here — never the
    // floor, which stays checked unconditionally above/independently of
    // this. See legacy_self_service_allow.hpp for why this is safe (the
    // downstream store enforces ownership; this gate only decides "may
    // attempt").
    const bool self_service_exempt =
        !floored && legacy_self_service_allow(securable_type, operation);
    if ((operation != "Read" || floored) && !self_service_exempt &&
        auth::effective_role(*session) != auth::Role::admin) {
        const std::string reason =
            (floored ? std::string("topology floor: non-admin role denied ")
                     : std::string("non-admin role denied ")) +
            securable_type + ":" + operation +
            (session->mcp_tier.empty() ? "" : " (mcp_tier=" + session->mcp_tier + ")");
        audit_log(req, "auth.permission_required", "denied", "", "", reason);
        if (floored) {
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_topology_floor_denied_total",
                           {{"permission", securable_type + ":" + operation}})
                    .increment();
            }
        }
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "admin role required",
                                          detail::A4ErrorOpts{.permission = securable_type + ":" +
                                                                    operation}),
                        "application/json");
        return false;
    }
    return true;
}

bool AuthRoutes::require_scoped_permission(const httplib::Request& req, httplib::Response& res,
                                           const std::string& securable_type,
                                           const std::string& operation,
                                           const std::string& agent_id) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    // JIT admin elevation grants full admin (across all management groups) for
    // its window — cookie-session-only, so unreachable by MCP/service tokens.
    //
    // Defense-in-depth (#2298 PR 3, mirrors require_permission's identical
    // guard above): the `token_scope_service.empty()` check is currently
    // redundant with that same cookie-session-only invariant, not
    // load-bearing — kept so this short-circuit can never be the thing that
    // lets a service-scoped token bypass the default-deny flip below, if
    // that invariant ever changes. Do NOT read its presence as evidence
    // elevation is reachable for service tokens today; it is not.
    if (auth::is_elevated(*session) && session->token_scope_service.empty())
        return true;

    // Engine principals have NO legacy or service-scoped authority — their only
    // authority is an explicit RBAC assignment (design §4.2 default-deny). The
    // pre-RBAC legacy fallback below would otherwise hand an engine credential
    // fleet-wide Read the moment RBAC is off (the default). Resolve engine
    // sessions here, RBAC-only, or deny.
    if (session->principal_kind == "engine") {
        if (!rbac_store_ || !rbac_store_->is_open()) {
            // Cannot evaluate authority — fail closed, 503.
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                      "engine principal denied: RBAC store unavailable");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                              detail::A4ErrorOpts{.permission = securable_type + ":" +
                                                                        operation}),
                            "application/json");
            return false;
        }
        if (!rbac_store_->is_rbac_enabled() ||
            !rbac_store_->check_scoped_permission(session->username, securable_type, operation,
                                                  agent_id, mgmt_group_store_)) {
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                      "engine principal denied " + securable_type + ":" + operation);
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        // Belt-and-braces (#2298 PR 3, mirrors require_permission's identical
        // guard): engine-token mint already rejects a non-empty
        // `scope_service` (`api_token_store.cpp::validate_engine_mint`), so
        // this guards a corrupted/constraint-bypassed row only, not a live
        // path — fjarvis (PR review) found this sibling function had the
        // guard applied to only one of the two engine branches. A corrupted
        // row must not use the engine branch as a side door around the
        // seeded-empty allow-list.
        if (!session->token_scope_service.empty() &&
            !service_scope_admits(securable_type, operation)) {
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                      "engine principal denied: corrupted scope_service on engine session "
                      "blocked by service-scope default-deny");
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            // No `.permission` field: holding `perm` alone would not admit
            // this session (compile-time-empty allow-list — routed-concern
            // "MUST NOT name a permission that wouldn't actually admit").
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm),
                            "application/json");
            return false;
        }
        return true;
    }

    // MCP-tier tokens: enforce the tier policy then fall through to the standard
    // RBAC/role check using the creator's actual role. Approval-gated operations
    // on a non-MCP transport are denied here; on `/mcp/v1/` the ticket-then-recall
    // flow in mcp_server.cpp is the authoritative approval gate (see guard below,
    // #289/#520).
    if (!session->mcp_tier.empty()) {
        const std::string perm = securable_type + ":" + operation;
        if (!mcp::tier_allows(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' does not allow " +
                          securable_type + ":" + operation);
            res.status = 403;
            res.set_content(detail::a4_denial(res, 403, "MCP token tier does not allow " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        // On the MCP JSON-RPC transport (`/mcp/v1/`) the C8 gate in
        // mcp_server.cpp is the authoritative approval gate (ticket-then-recall,
        // #289) — skip the denial there so a recall isn't consume-then-denied.
        // Enforced on every other transport so a REST route hit by an MCP token
        // cannot bypass the ticket flow (#520). NOTE (updated K-06/CDX-R4-09):
        // the MCP set_tag/delete_tag write tools NOW route through
        // require_scoped_permission (mcp_server.cpp), so this `req.path !=
        // "/mcp/v1/"` skip is LOAD-BEARING for them — it is what keeps an
        // approval-gated tag delete on the MCP transport from being
        // consume-then-denied. Do not remove it as "dead defense-in-depth".
        // Mirrors require_permission exactly (gov: architect/consistency/security).
        if (req.path != "/mcp/v1/" &&
            mcp::requires_approval(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.approval_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' requires approval for " +
                          securable_type + ":" + operation + " on a non-MCP transport");
            res.status = 403;
            res.set_content(
                detail::a4_denial(
                    res, 403,
                    "operation requires approval for this MCP tier on this transport",
                    detail::A4ErrorOpts{.remediation = "this operation is approval-gated for the "
                                               "supervised MCP tier; use the MCP ticket-then-recall "
                                               "flow (POST /mcp/v1/) or the dashboard",
                                .permission = perm}),
                "application/json");
            return false;
        }
    }

    // Service-scoped tokens: verify the target agent belongs to the token's service,
    // and that the ITServiceOwner role grants the required permission.
    if (!session->token_scope_service.empty()) {
        const std::string perm = securable_type + ":" + operation;
        // #1717: gate on `rbac_enforcement_in_effect`, not raw
        // `is_rbac_enabled()` — same standardization as `require_permission`'s
        // service branch (#2298 PR 3), so a degraded/stale-cached store
        // reads identically on both functions instead of diverging.
        if (!rbac_store_ || !rbac_enforcement_in_effect(rbac_store_)) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: RBAC not enabled");
            res.status = 403;
            // No `.permission`: granting `perm` does not fix "RBAC disabled".
            res.set_content(detail::a4_denial(res, 403,
                                              "service-scoped tokens require RBAC to be enabled"),
                            "application/json");
            return false;
        }
        // Check that the ITServiceOwner role grants this permission type
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: lacks ITServiceOwner permission");
            res.status = 403;
            // Post-flip, an ITServiceOwner grant is necessary but no longer
            // sufficient (the target agent's service tag must still match
            // below) — omit `.permission` rather than imply this single
            // grant would admit the caller.
            std::string msg = "service-scoped token does not grant " + perm +
                              " (requires ITServiceOwner AND the target agent's service tag "
                              "to match the token's scope)";
            res.set_content(detail::a4_denial(res, 403, msg), "application/json");
            return false;
        }
        // Verify the target agent's service tag matches the token's scope
        if (!tag_store_) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: tag store unavailable");
            res.status = 503;
            // Transient store outage → retryable; no permission field on a 503.
            res.set_content(detail::a4_denial(res, 503, "tag store unavailable, cannot verify scope",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000}),
                            "application/json");
            return false;
        }
        // #2298 PR 3 (§3b): an empty agent_id used to skip the ONLY
        // comparison that could deny and fall through to an unconditional
        // `return true` below — the exact "allow everything" degenerate
        // `confine_agent_target` (authz_gates.cpp) was built to not repeat
        // (#2437/#2500 omitted-vs-empty rule: an empty agent_id is a caller
        // bug, never "no target to check"). Verified during planning: every
        // one of this function's ~18 call sites already guards
        // `agent_id.empty()` before reaching it, so this bug was latent, not
        // live — this 400 closes the function's own degenerate shape without
        // an admit->deny regression on any real caller. Checked FIRST, before
        // any tag-store access, so a caller bug never reaches the (unrelated)
        // degraded-store handling below.
        if (agent_id.empty()) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: empty agent_id");
            res.status = 400;
            res.set_content(detail::a4_denial(res, 400, "agent_id is required",
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        // ADR-0050 typed read: a degraded store is a 503 (retryable),
        // never conflated with "agent has no service tag" — the
        // pre-migration read collapsed both to "", which happened to
        // deny (fail-closed) but audited the outage as a scope MISMATCH,
        // hiding the real cause from the operator.
        auto service_tag = tag_store_->get_tag(agent_id, std::string(authz::kServiceTagKey));
        if (!service_tag) {
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id, "",
                      "service-scoped token blocked: tag store degraded");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503,
                                              "tag store unavailable, cannot verify scope",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000}),
                            "application/json");
            return false;
        }
        const std::string agent_service = service_tag->value_or(std::string{});
        if (agent_service != session->token_scope_service) {
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                      "agent service '" + agent_service + "' does not match token scope '" +
                          session->token_scope_service + "'");
            res.status = 403;
            // Was the third denial shape ({"error":"forbidden","detail":...});
            // now the unified A4 envelope like every other gate (#1470).
            res.set_content(detail::a4_denial(res, 403,
                                              "agent is not in service '" +
                                                  session->token_scope_service + "'",
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        return true;
    }

    // #1717 (ADR-0017 ship-now HIGH): gate on `rbac_enforcement_in_effect`, NOT
    // raw `is_rbac_enabled` — same fail-closed-on-corrupt reasoning as
    // `require_permission` above. A corrupt rbac.db enters here and denies via
    // `check_scoped_permission` on the dead handle rather than falling through to
    // the legacy Read-allow.
    if (rbac_store_ && rbac_enforcement_in_effect(rbac_store_)) {
        if (!rbac_store_->check_scoped_permission(session->username, securable_type, operation,
                                                  agent_id, mgmt_group_store_)) {
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                      "RBAC denied " + securable_type + ":" + operation);
            res.status = 403;
            const std::string perm = securable_type + ":" + operation;
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return false;
        }
        return true;
    }

    // Legacy fallback: write/delete/execute/approve require admin (effective_role
    // — defense-in-depth; the is_elevated short-circuit above already returned for
    // elevated sessions).
    // #2376 topology floor: mirrors require_permission's floor above. Wave 7
    // PR7b (app_usage) is the first floored (securable, operation) pair to
    // reach this scoped variant — `Forensics:Read`, routed here via
    // `app_usage_routes.cpp`'s scoped gate (see the `{"Forensics", "Read"}`
    // entry in authz_topology_floor.hpp). It was floored defensively before
    // that, so a FUTURE scoped topology read cannot silently bypass the
    // floor — flooring only one of the two structurally identical legacy
    // branches is the "second copy" defect this repo keeps re-learning. See
    // authz_topology_floor.hpp for the rationale.
    const bool floored = topology_floor_applies(securable_type, operation);
    // #2963: mirrors require_permission's exemption above — no floored
    // (securable, operation) pair reaches this scoped variant today, but
    // it is checked anyway so a future scoped self-service op cannot
    // silently fall on the wrong side of this (same "second copy" lesson
    // as the topology floor comment above).
    const bool self_service_exempt =
        !floored && legacy_self_service_allow(securable_type, operation);
    if ((operation != "Read" || floored) && !self_service_exempt &&
        auth::effective_role(*session) != auth::Role::admin) {
        const std::string reason =
            (floored ? std::string("topology floor: non-admin role denied ")
                     : std::string("non-admin role denied ")) +
            securable_type + ":" + operation +
            (session->mcp_tier.empty() ? "" : " (mcp_tier=" + session->mcp_tier + ")");
        audit_log(req, "auth.scoped_permission_required", "denied", agent_id, reason);
        if (floored) {
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_topology_floor_denied_total",
                           {{"permission", securable_type + ":" + operation}})
                    .increment();
            }
        }
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "admin role required",
                                          detail::A4ErrorOpts{.permission = securable_type + ":" +
                                                                    operation}),
                        "application/json");
        return false;
    }
    return true;
}

ListReadGate AuthRoutes::require_list_read(const httplib::Request& req, httplib::Response& res,
                                           const std::string& securable_type,
                                           const std::string& operation) {
    ListReadGate gate;
    const std::string perm = securable_type + ":" + operation;

    auto session = require_auth(req, res);
    if (!session)
        return gate;
    gate.session = *session;

    // Structurally Read-only: the MCP approval-ticket branch never applies to
    // this gate (mcp::requires_approval only fires for Write/Delete/Execute,
    // mcp_policy.hpp), and this prevents a future caller from accidentally
    // routing a mutation through a primitive whose legacy-open branch can
    // return an unfiltered admit.
    if (operation != "Read") {
        audit_log(req, "auth.permission_required", "denied", "", "",
                  "list-read gate accepts Read operations only: " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "list-read gate accepts Read operations only",
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return gate;
    }

    // JIT admin elevation: same semantics as require_permission — full admin
    // for the elevation window, no underlying grant needed. Do NOT call
    // authorize_list_read here: it has no elevation concept, so an elevated
    // session with zero RBAC grants would otherwise be denied (the
    // regression the first #3038 fix attempt shipped, closed here).
    if (auth::is_elevated(*session)) {
        gate.admitted = true;
        return gate; // scope stays nullopt: unfiltered
    }

    // Engine principals have NO legacy or service-scoped authority — their
    // only authority is an explicit RBAC assignment (design §4.2
    // default-deny). authorize_list_read's own legacy-open branch would
    // otherwise hand an engine credential fleet-wide read the moment RBAC is
    // disabled; resolve engine sessions here, RBAC-only, or deny.
    if (session->principal_kind == "engine") {
        if (!rbac_store_ || !rbac_store_->is_open()) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "engine principal denied: RBAC store unavailable");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return gate;
        }
        if (!rbac_store_->is_rbac_enabled() ||
            !rbac_store_->check_permission(session->username, securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "engine principal denied " + perm);
            res.status = 403;
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return gate;
        }
        gate.admitted = true; // current engine grants are fleet-wide only
        return gate;
    }

    // MCP-tier tokens: tier policy precedes RBAC (matches require_permission).
    // Falls through on allow — an allowed MCP token continues below with its
    // creator's role/authority.
    if (!session->mcp_tier.empty() &&
        !mcp::tier_allows(session->mcp_tier, securable_type, operation)) {
        audit_log(req, "auth.permission_required", "denied", "", "",
                  "MCP token tier '" + session->mcp_tier + "' does not allow " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "MCP token tier does not allow " + perm,
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return gate;
    }

    // This fleet-wide list-read aggregate deliberately refuses service-scoped
    // credentials outright — unlike require_permission's service-scoped
    // branch (which checks the ITServiceOwner role and, for
    // require_scoped_permission, the target agent's own service tag), a
    // flat list-read gate has no single agent_id to scope the token's
    // service against, so admitting it would hand a service-scoped token the
    // WHOLE fleet's data.
    if (!session->token_scope_service.empty()) {
        audit_log(req, "auth.permission_required", "denied", "", "",
                  "service-scoped token '" + session->token_scope_service +
                      "' cannot read the fleet-wide list-read aggregate: " + perm);
        res.status = 403;
        res.set_content(
            detail::a4_denial(res, 403,
                              "service-scoped tokens cannot read the fleet-wide status rollup",
                              detail::A4ErrorOpts{.permission = perm}),
            "application/json");
        return gate;
    }

    // Wholly unwired RBAC subsystem: exact current legacy semantics (mirrors
    // require_permission's rbac_store_==nullptr short-circuit to legacy —
    // authorize_list_read cannot be called on a null store).
    if (!rbac_store_) {
        gate.admitted = true;
        return gate;
    }

    auto decision = rbac_store_->authorize_list_read(session->username, securable_type,
                                                      operation, mgmt_group_store_);
    switch (decision.decision) {
    case ListReadDecision::DenyAll:
        audit_log(req, "auth.permission_required", "denied", "", "",
                  "RBAC denied list read " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return gate;
    case ListReadDecision::AdmitAll:
        gate.admitted = true;
        return gate; // scope stays nullopt: unfiltered (global grant, or legacy-open)
    case ListReadDecision::AdmitScoped:
        gate.admitted = true;
        gate.scope = std::move(decision.visible_agents); // engaged even when empty (INV-2)
        return gate;
    }
    return gate; // unreachable — fail-closed default (admitted stays false)
}

std::string AuthRoutes::session_cookie_attrs() const {
    std::string attrs = "; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800";
    if (cfg_.https_enabled) {
        attrs += "; Secure";
    }
    return attrs;
}

AuditEvent AuthRoutes::make_audit_event(const httplib::Request& req, const std::string& action,
                                        const std::string& result) {
    AuditEvent event;
    event.action = action;
    event.result = result;
    event.source_ip = req.remote_addr;
    event.user_agent = req.get_header_value("User-Agent");
    // Actor class (ADR-1005 Phase 3a) — by credential presentation, same basis
    // principal_class_of already uses for the HTTP request metric.
    event.principal_class = std::string(principal_class_of(req));

    // Resolve principal via cookie / Bearer token / X-Yuzu-Token (same as require_auth).
    // Without this, audit rows for API-token-authenticated requests (REST API automation
    // and every MCP tool call) would have an empty `principal`, breaking the audit trail.
    if (auto session = resolve_session(req)) {
        event.principal = session->username;
        // effective_role so an action taken under an active JIT elevation is
        // audited as `admin` (the role it was AUTHORIZED as), not the base role —
        // SOC 2 evidence-integrity (#1748 H1). A no-op for non-elevated sessions.
        event.principal_role = auth::role_to_string(auth::effective_role(*session));
        event.session_id = extract_session_cookie(req);
        // principal_class_of(req) above can only distinguish by credential
        // presentation (bearer token → "agent"), which mislabels an engine
        // principal's bearer-token requests. Re-stamp from the resolved
        // session's persisted principal_kind so engine-principal actions are
        // audited truthfully as "engine" (design §6 / adr-1005-execution-plan
        // Decision 9 — the AuditStore column reports it now; the HTTP metric
        // is deferred to 4.5).
        if (session->principal_kind == "engine") {
            event.principal_class = "engine";
        }
    }
    return event;
}

void AuthRoutes::reap_mfa_pending_locked() {
    auto now = std::chrono::steady_clock::now();
    std::erase_if(mfa_pending_, [&](const auto& p) { return now > p.second.expires_at; });
}

bool AuthRoutes::audit_log(const httplib::Request& req, const std::string& action,
                           const std::string& result, const std::string& target_type,
                           const std::string& target_id, const std::string& detail) {
    if (!audit_store_)
        return true; // audit-off deployment — not a failure relative to config
    auto event = make_audit_event(req, action, result);
    event.target_type = target_type;
    event.target_id = target_id;
    event.detail = detail;
    auto ok = audit_store_->log(event);
    if (!ok) {
        // SOC 2 CC7.2 — surface audit-write failures via spdlog so on-call
        // has a signal short of the row-count metric. The wrapper still
        // returns false so the caller can decide whether to abort the
        // surrounding operation; most call sites legitimately fire-and-
        // forget the return value (matches the historical contract).
        spdlog::warn("audit_log: AuditStore::log failed for action='{}' target_type='{}' "
                     "target_id='{}'",
                     action, target_type, target_id);
    }
    return ok;
}

bool AuthRoutes::audit_log_for_principal(const httplib::Request& req, const std::string& action,
                                         const std::string& result, const std::string& principal,
                                         const std::string& principal_role,
                                         const std::string& target_type,
                                         const std::string& target_id,
                                         const std::string& detail,
                                         const std::string& principal_class_override) {
    if (!audit_store_)
        return true;
    AuditEvent event;
    event.action = action;
    event.result = result;
    event.source_ip = req.remote_addr;
    event.user_agent = req.get_header_value("User-Agent");
    event.principal = principal;
    event.principal_role = principal_role;
    event.target_type = target_type;
    event.target_id = target_id;
    event.detail = detail;
    // Actor class (ADR-1005 Phase 3a) — same basis as make_audit_event; this
    // constructor exists precisely for the pre-session sites (login/MFA/OIDC
    // callback), so the request itself is still the only signal available.
    event.principal_class = principal_class_override.empty()
                                ? std::string(principal_class_of(req))
                                : principal_class_override;
    // Stamped like make_audit_event so a row written by this path carries the same
    // session correlator. Empty at the pre-session login sites, which is correct there.
    event.session_id = extract_session_cookie(req);
    auto ok = audit_store_->log(event);
    if (!ok) {
        spdlog::warn("audit_log_for_principal: AuditStore::log failed for action='{}' "
                     "principal='{}' target_id='{}'",
                     action, principal, target_id);
    }
    return ok;
}

bool AuthRoutes::deny_service_scoped_session(const httplib::Request& req, httplib::Response& res,
                                             const std::string& action,
                                             const std::string& message,
                                             const std::string& target_type,
                                             const std::string& target_id,
                                             const std::string& permission) {
    auto session = require_auth(req, res);
    if (!session)
        return true; // require_auth already wrote 401/redirect; caller returns.
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after: a throwing audit sink must not be
    // able to suppress the 403 (mirrors the per-file deny_service_scoped_*
    // family's ordering — see this method's declaration comment).
    res.status = 403;
    res.set_content(
        detail::a4_denial(res, 403, message, detail::A4ErrorOpts{.permission = permission}),
        "application/json");
    // `audit_log` calls into a concrete `AuditStore*`, not an injected
    // callback, so it cannot propagate a caller-supplied exception the way
    // the per-file `deny_service_scoped_*` family's `audit_fn`/`audit_fn_`
    // parameters could — but this try/catch matches their shape anyway
    // (Gate 4/consistency-auditor: a family that looks identical everywhere
    // is cheaper to reason about than one exception debated case-by-case).
    try {
        audit_log(req, action, "denied", target_type, target_id,
                 message + " (path=" + req.path + ")");
    } catch (const std::exception& e) {
        spdlog::warn("deny_service_scoped_session: audit_log threw: {}", e.what());
    } catch (...) {
        spdlog::warn("deny_service_scoped_session: audit_log threw (non-std)");
    }
    return true;
}

bool AuthRoutes::deny_service_scoped_service_tag_mutation(const httplib::Request& req,
                                                            httplib::Response& res,
                                                            const std::string& action,
                                                            const std::string& agent_id,
                                                            const std::string& key) {
    auto session = require_auth(req, res);
    if (!session)
        return true; // require_auth already wrote 401/redirect; caller returns.
    if (authz::service_scope_may_mutate_tag_key(session->token_scope_service, key))
        return false;
    // Write the 403 FIRST, audit after — same throw-safety ordering as
    // deny_service_scoped_session immediately above.
    res.status = 403;
    res.set_content(
        detail::a4_denial(res, 403,
                          authz::kServiceTagMutationDeniedMessage),
        "application/json");
    try {
        // Gate 4/#3289 hardening round: target_type="Tag" matches REST v1's
        // convention for this identical logical event (a denied tag
        // mutation) — not "Agent", which matched neither REST's nor any
        // other surface's convention. This does NOT resolve the separate,
        // pre-existing mismatch against server.cpp's own tag.set/tag.delete
        // success/failure rows, which use lowercase "tag" — this caller
        // (server.cpp, via the legacy dashboard routes) is a DIFFERENT file
        // from where this comment lives; see the routed-concern row for the
        // tracked residual.
        audit_log(req, action, "denied", "Tag", agent_id + ":" + key,
                 "service-scoped token blocked: cannot mutate the service tag (path=" +
                     req.path + ")");
    } catch (const std::exception& e) {
        spdlog::warn("deny_service_scoped_service_tag_mutation: audit_log threw: {}", e.what());
    } catch (...) {
        spdlog::warn("deny_service_scoped_service_tag_mutation: audit_log threw (non-std)");
    }
    return true;
}

void AuthRoutes::emit_event(const std::string& event_type, const httplib::Request& req,
                            const nlohmann::json& attrs, const nlohmann::json& payload_data,
                            Severity sev) {
    if (!analytics_store_)
        return;
    AnalyticsEvent ae;
    ae.event_type = event_type;
    ae.severity = sev;
    ae.attributes = attrs;
    ae.payload = payload_data;

    if (auto session = resolve_session(req)) {
        ae.principal = session->username;
        // effective_role: an elevated session's analytics row reflects admin too
        // (#1748 H1/L4). No-op when not elevated.
        ae.principal_role = auth::role_to_string(auth::effective_role(*session));
        // HASHED, never the raw cookie (ADR-0049 governance Gate 2, 2026-08-16):
        // this value is durably persisted into AnalyticsEventStore (unbounded
        // retention on Postgres, ADR-0049) and readable by anyone holding the
        // broad Infrastructure:Read permission via /api/analytics/recent — the
        // live bearer token is exactly what validate_session() accepts, so
        // storing it raw would let any Infrastructure:Read holder hijack the
        // session (including an elevated admin's, via role.elevation.granted
        // events). The hash still correlates events from the same session
        // (same cookie -> same hash) without being a redeemable credential.
        // Guard on the COOKIE, not just the session (governance Gate 3
        // cpp-expert finding, 2026-08-16): resolve_session() also succeeds
        // for Bearer/X-Yuzu-Token auth, which carries no cookie —
        // extract_session_cookie returns "", and sha256_hex("") is a FIXED
        // constant. Hashing unconditionally would give every token-
        // authenticated row the SAME non-empty session_id, falsely
        // correlating unrelated principals as "the same session" — a
        // regression the pre-hash code didn't have (empty stayed
        // distinguishably empty). Only hash a real cookie; leave
        // session_id at its default-empty value otherwise.
        //
        // Fail-soft parity (governance Gate 3 cpp-safety finding,
        // 2026-08-16): sha256_hex can throw on an internal EVP failure
        // (OOM-class, rare) — this whole function exists so a dropped
        // analytics event never fails the operation that emitted it.
        // Degrades to an empty session_id, not a failed request.
        if (auto cookie = extract_session_cookie(req); !cookie.empty()) {
            try {
                ae.session_id = auth::AuthManager::sha256_hex(cookie);
            } catch (const std::exception& e) {
                spdlog::debug("AuthRoutes::emit_event: session_id hash failed: {}", e.what());
            }
        }
    }
    analytics_store_->emit(std::move(ae));
}

// Pick the striped login mutex for a username (account-lockout race close).
// Any hash is fine — same-stripe collisions across distinct usernames just
// serialize harmlessly. See the header for the full rationale.
std::mutex& AuthRoutes::login_lock_for(const std::string& username) {
    return login_locks_[std::hash<std::string>{}(username) % login_locks_.size()];
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void AuthRoutes::register_routes(httplib::Server& svr) {
    // Production shim — wrap the real server in an HttplibRouteSink and
    // delegate to the sink-based overload. Same handlers, same lambdas,
    // same observable behaviour. Test code calls the sink overload
    // directly with a TestRouteSink.
    HttplibRouteSink sink(svr);
    register_routes(sink);
}

void AuthRoutes::register_routes(HttpRouteSink& sink) {
    // -- Login page -----------------------------------------------------------
    sink.Get("/login", [this](const httplib::Request& req, httplib::Response& res) {
        std::string html(kLoginHtml);
        // Inject OIDC enablement flag into the page
        std::shared_lock oidc_lock(oidc_mu_);
        if (oidc_provider_ && oidc_provider_->is_enabled()) {
            auto pos = html.find("/*OIDC_CONFIG*/");
            if (pos != std::string::npos)
                html.replace(pos, 15, "window.OIDC_ENABLED=true;");
        }
        res.set_content(html, "text/html; charset=utf-8");
    });

    sink.Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
        auto username = extract_form_value(req.body, "username");
        auto password = extract_form_value(req.body, "password");

        // The configured break-glass account is EXEMPT from failed-login lockout
        // while in hardened mode (governance Hermes-F / UP-13 / security-LOW): the
        // lockout pre-check runs first, so without this an attacker who learns the
        // break-glass username could spray wrong passwords to keep `locked_until`
        // armed and render the escape hatch unreachable during the exact IdP
        // outage it exists for — a denial of *availability* of the recovery path.
        // The exemption is safe because (a) the account still requires a second
        // factor (MFA is mandatory, enforced fail-closed at boot + login), so a
        // guessed password alone grants nothing; (b) while UN-armed the password
        // is never even evaluated (the sso-only gate rejects before
        // verify_password), so brute-force is only possible inside the operator's
        // own armed window; and (c) per-IP `login_rate_limit` still throttles.
        // Every wrong-password attempt is still audited as `auth.login_failed`,
        // so brute-force activity remains visible — we drop the *lock*, not the
        // evidence. Scoped to sso-only so the account keeps normal lockout in
        // standard mode.
        const bool break_glass_lockout_exempt = cfg_.auth_mode == "sso-only" &&
                                                !cfg_.break_glass_user.empty() &&
                                                username == cfg_.break_glass_user;

        // Serialize concurrent attempts for THIS username across the whole
        // lockout-critical section below (pre-check → verify_password →
        // record/clear), so a synchronized burst cannot all pass the stale
        // pre-check and verify more than `threshold` passwords before the lock
        // arms (adversarial C1). Held only when lockout is enabled; released
        // explicitly before the MFA branching, which does not touch lockout
        // state. Striped per-username (login_lock_for) so unrelated usernames
        // log in fully in parallel — only a burst against one account is
        // serialized, which is the intended throttle.
        std::unique_lock<std::mutex> login_lk;
        if (cfg_.auth_lockout_threshold > 0) {
            login_lk = std::unique_lock<std::mutex>(login_lock_for(username));
        }

        // ── Account-lockout pre-check (SOC 2 CC6.3) ──────────────────────
        // Brute-force / credential-stuffing guard. When the account is
        // currently locked we reject with the SAME generic 401 as a bad
        // password (no Retry-After, no "locked" wording) so the response is
        // not a username-enumeration / lock-state oracle, and we skip
        // verify_password entirely — the ~100 ms PBKDF2 is never burned on a
        // locked account (a free anti-DoS win). The lock is observable only
        // server-side via the audit row + metric below. Fail-open on a read
        // error: lockout protects against *wrong* passwords, so a transient
        // auth.db read failure must not wedge logins — verify_password is
        // still the real credential gate. prior_failed_count is captured so
        // the success path knows whether to emit a "cleared" audit.
        int prior_failed_count = 0;
        // Set when the lockout pre-check read itself fails (fail-open path): we
        // then cannot know the user's prior failure count, so on a subsequent
        // successful login we clear defensively rather than leave a stale
        // counter that could lock a legitimate user on their very next slip
        // (Hermes cyber-review F4).
        bool lockout_read_failed = false;
        if (cfg_.auth_lockout_threshold > 0 && !break_glass_lockout_exempt) {
            if (auto* db = auth_mgr_.auth_db_ptr()) {
                if (auto st = db->lockout_status(username)) {
                    prior_failed_count = st->failed_count;
                    if (st->locked) {
                        res.status = 401;
                        res.set_content(detail::a4_error(res, "Invalid username or password"),
                                        "application/json");
                        // Metric + a rate-limited log line ONLY — deliberately
                        // no audit row AND no analytics event per blocked
                        // attempt. Under a sustained brute-force against a
                        // locked account, an `emit_event` per attempt would
                        // amplify the analytics/SSE pipeline exactly the way a
                        // per-attempt audit row would amplify the audit log
                        // (governance UP-15). The aggregate signal is the
                        // counter; the once-per-lock `auth.lockout.applied`
                        // audit row is the durable evidence; the source IP for
                        // forensics is in the spdlog line below (bounded by the
                        // 10/s/IP login rate-limiter).
                        if (auto* m = auth_mgr_.metrics_registry()) {
                            m->counter("yuzu_auth_lockout_blocked_total").increment();
                        }
                        spdlog::warn("Login blocked: account '{}' is locked (source {})", username,
                                     req.remote_addr);
                        return;
                    }
                } else {
                    // Fail-open: lockout protects against *wrong* passwords, so
                    // a transient auth.db read error must not wedge logins —
                    // verify_password remains the real credential gate. Make the
                    // degradation observable (was silent) and remember it so the
                    // success path below clears the counter defensively.
                    lockout_read_failed = true;
                    spdlog::warn("lockout_status read failed for '{}' (error={}) — pre-check "
                                 "fail-open; brute-force throttle degraded for this attempt",
                                 username, static_cast<int>(st.error()));
                }
            }
        }

        // ── Hardened mode: local-password login disabled (SOC 2 CC6.3) ───
        // Under --auth-mode=sso-only the local-password path is closed
        // fleet-wide; only SSO (OIDC /auth/callback or SAML /saml/acs, both
        // untouched) mints a session. The single configured break-glass account is exempt ONLY
        // while armed — an out-of-band host operator ran --break-glass-arm
        // within the window. A non-exempt or un-armed attempt is rejected with
        // the SAME generic 401 as a bad password (no "disabled"/"sso-only"
        // wording, no Retry-After), so the response BODY/STATUS/HEADERS carry no
        // enumeration/mode/arm-state oracle, and verify_password (PBKDF2) is
        // skipped. The one residue is response TIMING: an armed break-glass user
        // runs PBKDF2 (slow) while every other username short-circuits (fast),
        // so timing can reveal that the break-glass account is currently armed
        // (and, separately, that the deployment is in sso-only mode) —
        // identical in kind to the lockout pre-check's accepted timing residue,
        // and it discloses at most "armed"/"mode", never a credential (the
        // attacker still needs the password AND a second factor). A constant-time
        // floor (dummy PBKDF2 / sleep on the reject path) was DELIBERATELY NOT
        // added: it would re-introduce exactly the PBKDF2-cost amplification DoS
        // the skip exists to avoid — every sprayed sso-only reject would burn
        // ~100 ms of server CPU — for a residue that leaks only operational
        // state, never a secret. Same trade-off the shipped lockout pre-check
        // already makes (see docs/auth-architecture.md "Account lockout").
        bool break_glass_login = false;
        if (cfg_.auth_mode == "sso-only") {
            if (!cfg_.break_glass_user.empty() && username == cfg_.break_glass_user) {
                if (auto* db = auth_mgr_.auth_db_ptr()) {
                    // Fail CLOSED on a read error: unlike lockout (which guards
                    // against wrong passwords and so fails open), this gate is
                    // the credential path itself — a transient read error must
                    // not become a free pass to the disabled local-login path.
                    if (auto bg = db->break_glass_status(username); bg && bg->armed) {
                        break_glass_login = true;
                    }
                }
            }
            if (!break_glass_login) {
                res.status = 401;
                res.set_content(detail::a4_error(res, "Invalid username or password"),
                                "application/json");
                // Governance UP-2: metric + rate-limited log, NOT a per-attempt
                // audit row. sso-only rejects EVERY local login and this path
                // never feeds lockout, so a per-attempt `audit_log` would let a
                // credential-stuffing spray grow audit.db without bound — the
                // exact amplification the lockout *blocked* path deliberately
                // avoids (metric-only there too). CC6.3 evidence is the boot
                // posture banner + this counter. The bounded {target} label
                // (break_glass|other — cardinality 2) flags probing of the
                // break-glass account itself for SIEM alerting without a row per
                // attempt. The per-IP login_rate_limit bounds the log rate.
                const bool probed_break_glass =
                    !cfg_.break_glass_user.empty() && username == cfg_.break_glass_user;
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_local_disabled_total",
                               {{"target", probed_break_glass ? "break_glass" : "other"}})
                        .increment();
                }
                spdlog::warn("Local-password login blocked (auth-mode=sso-only){} from source {}",
                             probed_break_glass ? " [break-glass account, not armed]" : "",
                             req.remote_addr);
                return;
            }
            // break_glass_login stays true → the success audit + metric + warn
            // fire only AFTER verify_password below confirms the credential, so a
            // wrong-password attempt against the armed account audits as a normal
            // auth.login_failed (and counts toward lockout), never a spurious
            // "ok" break-glass row.
        }

        auto role_opt = auth_mgr_.verify_password(username, password);
        if (!role_opt) {
            res.status = 401;
            res.set_content(detail::a4_error(res, "Invalid username or password"),
                            "application/json");
            audit_log(req, "auth.login_failed", "error", "User", username);
            emit_event("auth.login_failed", req,
                       {{"source_ip", req.remote_addr}, {"username", username}}, {},
                       Severity::kWarn);
            // Record the failed attempt for lockout accounting. Only the
            // threshold-crossing failure emits an audit row — subsequent
            // blocked attempts are counted via the metric above, NOT audited.
            // record_failed_login is a no-op for unknown / malformed
            // usernames, so it never creates a row for a non-existent account
            // (anti-enumeration + no storage growth). Skipped for the
            // lockout-exempt break-glass account (the wrong attempt is still
            // audited as auth.login_failed above — evidence kept, lock dropped).
            if (cfg_.auth_lockout_threshold > 0 && !break_glass_lockout_exempt) {
                if (auto* db = auth_mgr_.auth_db_ptr()) {
                    auto rec = db->record_failed_login(username, cfg_.auth_lockout_threshold,
                                                       cfg_.auth_lockout_window_secs);
                    if (rec && rec->just_locked) {
                        // result uses the canonical ok|denied|error envelope
                        // vocabulary (the lock was applied successfully); the
                        // warning *severity* is carried by the emit_event +
                        // metric, not the audit result token. The applied row
                        // is the primary CC6.3 lock evidence, so a lost write
                        // is surfaced (governance UP-14 / compliance SHOULD-1).
                        if (!audit_log_for_principal(
                                req, "auth.lockout.applied", "ok", username, "", "User", username,
                                "threshold=" + std::to_string(cfg_.auth_lockout_threshold) +
                                    " window_secs=" +
                                    std::to_string(cfg_.auth_lockout_window_secs))) {
                            spdlog::error("audit emission FAILED for auth.lockout.applied user='{}' "
                                          "— CC6.3 lock-event evidence lost",
                                          username);
                        }
                        emit_event("auth.lockout.applied", req,
                                   {{"source_ip", req.remote_addr}, {"username", username}}, {},
                                   Severity::kWarn);
                        if (auto* m = auth_mgr_.metrics_registry()) {
                            m->counter("yuzu_auth_lockout_applied_total").increment();
                        }
                        spdlog::warn("Account '{}' locked after {} failed login attempts", username,
                                     cfg_.auth_lockout_threshold);
                    } else if (!rec) {
                        spdlog::warn("record_failed_login failed for '{}': error={}", username,
                                     static_cast<int>(rec.error()));
                        if (is_store_unavailable(rec.error())) {
                            // ★ Hermes p2 MEDIUM: the lockout counter could not
                            // be persisted (PG outage) — refuse fail-closed with
                            // a 503 rather than return the already-built 401,
                            // which would be an UNcounted attempt and let a
                            // password-spray brute-force unlimited tries while
                            // the store is degraded.
                            res.status = 503;
                            // #2396: honest backoff hint on a transient
                            // store-unavailable 503 (header + A4-style body
                            // field), and a reason-labelled degrade counter so
                            // a retry-storm is distinguishable from a uniform
                            // outage. Does NOT change the fail-closed decision.
                            res.set_header("Retry-After", "2");
                            res.set_content(
                                detail::a4_error(res, "authentication store is temporarily unavailable",
                                                 {.retry_after_ms = 2000}),
                                "application/json");
                            if (auto* m = auth_mgr_.metrics_registry()) {
                                // Both counters, matching the mfa_status / mfa_init
                                // sites: the coarse route-level total (every
                                // store-unavailable login 503) AND the reason
                                // split. #2396 adv-review CDX-P1-01 — the coarse
                                // series must move at every login-path 503 so an
                                // alert on it does not undercount an outage.
                                m->counter("yuzu_auth_secret_unavailable_total",
                                           {{"route", "login"}})
                                    .increment();
                                m->counter(
                                     "yuzu_auth_read_degrade_total",
                                     {{"route", "login"}, {"reason", degrade_reason(rec.error())}})
                                    .increment();
                            }
                        }
                    }
                }
            }
            return;
        }

        // (Break-glass success evidence is emitted further down, AFTER the UP-1
        // hard-deny — so an un-enrolled armed break-glass user that proved its
        // password gets ONLY the `auth.breakglass.denied` row, never a
        // contradictory `login`-then-`denied` pair.)

        // Password verified — reset the lockout counter (the brute-force
        // window is per-consecutive-failure, so any success clears it). Done
        // here, before the MFA branching below, so it covers all three
        // success exits (no-MFA mint, MFA challenge, enforced enrollment).
        // Clear when there was a known non-zero counter, OR when the pre-check
        // read failed and the count is unknown (F4 — never leave a stale
        // counter behind a successful login). Only routine logins with a known
        // zero counter skip the write, so they don't spam the audit log.
        if (cfg_.auth_lockout_threshold > 0 && (prior_failed_count > 0 || lockout_read_failed)) {
            if (auto* db = auth_mgr_.auth_db_ptr()) {
                if (auto cl = db->clear_failed_logins(username); !cl) {
                    spdlog::warn("clear_failed_logins failed for '{}': error={}", username,
                                 static_cast<int>(cl.error()));
                } else {
                    if (!audit_log_for_principal(req, "auth.lockout.cleared", "ok", username,
                                                 auth::role_to_string(*role_opt), "User", username,
                                                 "reset_on_successful_login")) {
                        spdlog::warn("audit emission failed for auth.lockout.cleared user='{}'",
                                     username);
                    }
                    emit_event("auth.lockout.cleared", req,
                               {{"source_ip", req.remote_addr}, {"username", username}});
                }
            }
        }

        // Lockout-critical section complete (password verified, counter
        // cleared). Release the per-username lock BEFORE the MFA branching so a
        // TOTP challenge for this user doesn't hold the stripe across the rest
        // of the flow — MFA state has its own (`mfa_pending_mu_`) guard.
        if (login_lk.owns_lock())
            login_lk.unlock();

        // Decide whether this user must complete a TOTP challenge before we
        // mint a real session. ★ SECURITY (architect BLOCK, Postgres
        // migration): `mfa_status` is now TRI-STATE — a store/decrypt
        // failure (`SecretUnavailable`/`QueryFailed`) MUST NEVER collapse to
        // "not enrolled". Doing so would let a PG/KEK outage silently strip
        // an enrolled privileged account of its second factor and fall
        // through to the password-only session mint below. Only a genuine
        // `Ok{enrolled=false}` may skip MFA; every error arm fails CLOSED
        // (503, no session minted) here — if AuthDB itself is not
        // configured at all (db == nullptr; legacy/degraded deployments),
        // that is unchanged fail-open-to-not-enrolled, matching every other
        // "AuthDB unavailable" site in this file (there is no store to be
        // wrong about).
        bool mfa_enrolled = false;
        if (auto* db = auth_mgr_.auth_db_ptr()) {
            auto status = db->mfa_status(username);
            if (status) {
                mfa_enrolled = status->enrolled;
            } else {
                res.status = 503;
                res.set_header("Retry-After", "2"); // #2396 honest backoff hint
                res.set_content(
                    detail::a4_error(res, "authentication store is temporarily unavailable",
                                     {.retry_after_ms = 2000}),
                    "application/json");
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_secret_unavailable_total", {{"route", "login"}})
                        .increment();
                    // #2396: reason-labelled sibling of the counter above so a
                    // transient pool-acquire retry-storm is distinguishable
                    // from a uniform secret/query outage (#2401). Gated on
                    // is_store_unavailable so a non-store error reaching this
                    // fail-closed else (e.g. a UserNotFound row-vanished race)
                    // is never mislabelled with a store-degrade reason.
                    if (is_store_unavailable(status.error())) {
                        m->counter("yuzu_auth_read_degrade_total",
                                   {{"route", "login"}, {"reason", degrade_reason(status.error())}})
                            .increment();
                    }
                }
                audit_log_for_principal(
                    req, "mfa.status.unavailable", "error", username,
                    auth::role_to_string(*role_opt), "User", username,
                    status.error() == AuthDBError::SecretUnavailable
                        ? "mfa_status: secret unavailable (fail-closed, no session minted)"
                        : "mfa_status: query failed (fail-closed, no session minted)");
                emit_event("mfa.status.unavailable", req,
                           {{"source_ip", req.remote_addr}, {"username", username}}, {},
                           Severity::kCritical);
                spdlog::error("mfa_status failed for '{}' (error={}) — refusing login "
                              "(fail-closed, architect BLOCK)",
                              username, static_cast<int>(status.error()));
                return;
            }
        }

        // Governance UP-1 (BLOCKING fix). A break-glass login requires an
        // EXISTING enrolled second factor. The boot guard refuses to start
        // sso-only with an MFA-less break-glass user, so this only trips in the
        // narrow race where MFA was cleared out-of-band (e.g. --mfa-reset) after
        // boot. HARD-DENY here rather than fall through to the enrollment branch
        // below: enrollment would reveal a fresh provisional TOTP secret to
        // whoever proved the password and let them self-enrol and complete the
        // login — i.e. a password-only adversary would break the glass with no
        // real second factor, defeating CC6.6. Fail closed; re-enrolment of the
        // break-glass account is a deliberate out-of-band operation.
        if (break_glass_login && !mfa_enrolled) {
            res.status = 403;
            // A4 error envelope (review #1735 MEDIUM): correlation_id so an
            // agentic worker can tie this 403 to its auth.breakglass.denied audit
            // row, plus a remediation hint. Uses the canonical detail::error_json_a4
            // (the local a4_denial omits the remediation field). No retry_after_ms
            // — re-enrolling a second factor is a manual out-of-band operation,
            // not a timed backoff. (Unlike the sso-only LOCAL-disabled 401, this
            // 403 is already a distinct status, so enriching it is not an
            // enumeration oracle.)
            std::string cid = res.get_header_value("X-Correlation-Id");
            if (cid.empty()) {
                cid = detail::make_correlation_id();
                res.set_header("X-Correlation-Id", cid);
            }
            res.set_content(
                detail::error_json_a4(
                    403, "break-glass account requires an enrolled second factor", cid,
                    "the break-glass account has no enrolled second factor, and no admin can "
                    "enroll it on its behalf. Recover by restarting with --auth-mode=standard, "
                    "enrolling as the break-glass account, then restoring sso-only; standard "
                    "mode re-enables local-password login for every account. Full sequence: "
                    "docs/ops-runbooks/auth-db-recovery.md (break-glass section)"),
                "application/json");
            audit_log_for_principal(
                req, "auth.breakglass.denied", "denied", username,
                auth::role_to_string(*role_opt), "User", username,
                "break-glass login refused: no MFA enrolled (enrollment not offered — see the "
                "break-glass section of docs/ops-runbooks/auth-db-recovery.md)");
            emit_event("auth.breakglass.denied", req,
                       {{"source_ip", req.remote_addr}, {"username", username}}, {},
                       Severity::kCritical);
            spdlog::error("BREAK-GLASS login DENIED for '{}' (source {}): no MFA enrolled — "
                          "refusing to offer enrollment (would defeat the second factor). "
                          "Re-enroll it per the break-glass section of "
                          "docs/ops-runbooks/auth-db-recovery.md.",
                          username, req.remote_addr);
            return;
        }

        // Break-glass password accepted AND an enrolled second factor exists
        // (the UP-1 hard-deny above returned otherwise). Loud + audited evidence
        // (SOC 2 CC6.6): a CRITICAL row + metric + log so an auditor/SIEM sees
        // every break-glass use. `result=ok` here means "password accepted" —
        // the `detail` is explicit that no session is minted yet (the mandatory
        // TOTP challenge below still runs); correlate with the subsequent
        // `auth.login` mint by principal + time.
        if (break_glass_login) {
            audit_log_for_principal(req, "auth.breakglass.login", "ok", username,
                                    auth::role_to_string(*role_opt), "User", username,
                                    "break-glass password accepted under auth-mode=sso-only; "
                                    "second factor still required before a session is minted");
            emit_event("auth.breakglass.login", req,
                       {{"source_ip", req.remote_addr}, {"username", username}}, {},
                       Severity::kCritical);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_break_glass_login_total").increment();
            }
            spdlog::warn("BREAK-GLASS login proceeding for '{}' (source {}) under "
                         "auth-mode=sso-only — a second factor is still required",
                         username, req.remote_addr);
        }

        // PR3 enforcement (SOC 2 CC6.6). Under `required` (every role) or
        // `admin-only` (admins only), a user without MFA must enrol before
        // a session is minted. Reuse PR1's pending-token machinery: issue
        // a provisional TOTP secret + an enrollment-pending token and let
        // POST /login/mfa/enroll confirm the first code and complete the
        // login. No new session concept; an un-enrolled enforced user
        // never holds a cookie until they finish enrolling. (A break-glass
        // user reaching here is necessarily already enrolled — the hard-deny
        // above handled the un-enrolled case — so it falls through to the
        // enrolled TOTP challenge, never this enrollment branch.)
        const bool mfa_enforced = mfa_enforcement_protects(cfg_.mfa_enforcement, *role_opt);
        if (!mfa_enrolled && mfa_enforced) {
            auto* db = auth_mgr_.auth_db_ptr();
            if (!db) {
                // Enforcement is configured but the store that holds TOTP
                // secrets is unavailable, so MFA can be neither enrolled
                // nor verified. Fail CLOSED — minting an unprotected
                // session here would silently defeat the control the
                // operator explicitly enabled.
                res.status = 503;
                res.set_content(
                    detail::a4_error(
                        res, "MFA enrollment is required but the authentication store is unavailable"),
                    "application/json");
                audit_log_for_principal(req, "mfa.enroll.required", "error", username,
                                        auth::role_to_string(*role_opt), "User", username,
                                        "auth_db unavailable (fail-closed)");
                spdlog::error(
                    "MFA enforcement={} but auth_db unavailable — refusing login for '{}'",
                    cfg_.mfa_enforcement, username);
                return;
            }
            auto init = db->mfa_init_enrollment(username, "Yuzu");
            if (!init) {
                // ★ SECURITY (architect BLOCK): a decrypt/store failure while
                // (re-)revealing a provisional secret is 503, fail-closed —
                // never a generic 500 that could be confused with a
                // harmless one-off. No session is minted either way.
                const bool store_unavailable = is_store_unavailable(init.error());
                res.status = store_unavailable ? 503 : 500;
                if (store_unavailable)
                    res.set_header("Retry-After", "2"); // #2396 honest backoff hint (503 only)
                res.set_content(
                    store_unavailable
                        ? detail::a4_error(res, "authentication store is temporarily unavailable",
                                           {.retry_after_ms = 2000})
                        : detail::a4_error(res, "Could not initiate MFA enrollment"),
                    "application/json");
                if (store_unavailable) {
                    if (auto* m = auth_mgr_.metrics_registry()) {
                        m->counter("yuzu_auth_secret_unavailable_total", {{"route", "login"}})
                            .increment();
                        // #2396 reason-labelled sibling (#2401).
                        m->counter(
                             "yuzu_auth_read_degrade_total",
                             {{"route", "login"}, {"reason", degrade_reason(init.error())}})
                            .increment();
                    }
                }
                audit_log_for_principal(req, "mfa.enroll.required", "error", username,
                                        auth::role_to_string(*role_opt), "User", username,
                                        store_unavailable
                                            ? "mfa_init_enrollment: secret/store unavailable "
                                              "(fail-closed)"
                                            : "mfa_init_enrollment failed");
                return;
            }
            auto pending_token =
                auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
            bool at_capacity = false;
            {
                std::lock_guard lock(mfa_pending_mu_);
                reap_mfa_pending_locked();
                if (mfa_pending_.size() >= mfa_pending_cap_) {
                    at_capacity = true; // load-shed (Hermes H-2)
                } else {
                    MfaPending entry;
                    entry.username = username;
                    entry.role = *role_opt;
                    entry.kind = PendingKind::enrollment;
                    entry.expires_at = std::chrono::steady_clock::now() +
                                       std::chrono::seconds(cfg_.mfa_login_pending_secs);
                    mfa_pending_[pending_token] = std::move(entry);
                }
            }
            if (at_capacity) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res, "too many pending authentications, retry shortly"),
                    "application/json");
                // Observable load-shed (governance sec-MED / UP-D3): a
                // counter for alerting + a (per-event, not audit) warn.
                // Deliberately NOT an audit row — a flood would amplify
                // audit writes; the counter is the aggregated signal.
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_mfa_pending_load_shed_total", {{"kind", "enrollment"}})
                        .increment();
                }
                spdlog::warn("MFA pending-token map at capacity ({}) — shedding enrollment "
                             "challenge for source {}",
                             mfa_pending_cap_, req.remote_addr);
                return;
            }
            res.status = 202;
            // The provisional secret is revealed exactly once here — the
            // caller already proved the password, the same trust level as
            // the Settings-page enrollment reveal. POST /login/mfa/enroll
            // never re-reveals it on a failed confirm.
            nlohmann::json body = {{"status", "mfa_enrollment_required"},
                                   {"mfa_pending_token", pending_token},
                                   {"otpauth_uri", init->otpauth_uri},
                                   {"secret_base32", init->secret_base32},
                                   // Server-rendered inline SVG QR (#1232). May be
                                   // "" on encode failure → the form falls back to
                                   // the textual secret.
                                   {"qr_svg", otpauth_qr_svg(init->otpauth_uri)},
                                   {"expires_in", cfg_.mfa_login_pending_secs}};
            res.set_content(body.dump(), "application/json");
            audit_log_for_principal(req, "mfa.enroll.required", "ok", username,
                                    auth::role_to_string(*role_opt), "User", username,
                                    "enforcement=" + cfg_.mfa_enforcement);
            emit_event("mfa.enroll.required", req,
                       {{"source_ip", req.remote_addr}, {"username", username}});
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_challenges_issued_total").increment();
                std::lock_guard lock(mfa_pending_mu_);
                m->gauge("yuzu_auth_mfa_pending_tokens")
                    .set(static_cast<double>(mfa_pending_.size()));
            }
            return;
        }

        if (!mfa_enrolled) {
            auto token = auth_mgr_.create_local_session(username, *role_opt, false);
            if (token.empty()) {
                // #4107 Gate 8 finding (security-guardian): create_local_
                // session's empty-token sentinel (durable-persist failure,
                // OR - since this branch's #4107 fix - a post-mint role-
                // recheck denial) was previously UNCHECKED here: the route
                // still set a garbage Set-Cookie, reported 200 "ok", and
                // audited a fictional successful admin-role login. Neither
                // failure mode is distinguishable from the caller side
                // without a structural return-type change (tracked as a
                // follow-up) - the audit reason below deliberately does NOT
                // assert which of the two fired (cpp-expert Gate 8: an
                // earlier draft asserted post_mint_recheck=true
                // unconditionally, which is false audit evidence on an
                // ordinary persist failure). Same 401 body as this route's
                // other failure branches (no oracle on which credential/
                // state step failed).
                res.status = 401;
                res.set_content(detail::a4_error(res, "Invalid username or password"),
                                "application/json");
                audit_log_for_principal(req, "auth.login", "failure", username,
                                        auth::role_to_string(*role_opt), "User", username,
                                        "reason=session_mint_failed;cause=undifferentiated");
                emit_event("auth.login", req,
                           {{"source_ip", req.remote_addr},
                            {"username", username},
                            {"auth_method", "password"},
                            {"user_agent", req.get_header_value("User-Agent")}},
                           {}, Severity::kWarn);
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_login_session_mint_denied_total").increment();
                }
                return;
            }
            res.set_header("Set-Cookie", "yuzu_session=" + token + session_cookie_attrs());
            res.set_content(R"({"status":"ok"})", "application/json");
            // Mint-time audit row uses the explicit-principal helper —
            // request has no session cookie yet so the default
            // resolve_session-based path would leave `principal` empty
            // (consistency B3). target_type follows the
            // observability-conventions.md PascalCase convention; result
            // uses the spec's "ok"/"error" vocabulary.
            audit_log_for_principal(req, "auth.login", "ok", username,
                                    auth::role_to_string(*role_opt), "User", username);
            emit_event("auth.login", req,
                       {{"source_ip", req.remote_addr},
                        {"username", username},
                        {"auth_method", "password"},
                        {"user_agent", req.get_header_value("User-Agent")}});
            return;
        }

        // User has TOTP enrolled — issue an opaque short-lived pending
        // token and require POST /login/mfa to complete.
        auto pending_token =
            auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
        bool challenge_at_capacity = false;
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            if (mfa_pending_.size() >= mfa_pending_cap_) {
                challenge_at_capacity = true; // load-shed (Hermes H-2)
            } else {
                MfaPending entry;
                entry.username = username;
                entry.role = *role_opt;
                entry.expires_at = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(cfg_.mfa_login_pending_secs);
                mfa_pending_[pending_token] = std::move(entry);
            }
        }
        if (challenge_at_capacity) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "too many pending authentications, retry shortly"),
                "application/json");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_pending_load_shed_total", {{"kind", "challenge"}})
                    .increment();
            }
            spdlog::warn("MFA pending-token map at capacity ({}) — shedding login challenge for "
                         "source {}",
                         mfa_pending_cap_, req.remote_addr);
            return;
        }
        res.status = 202;
        nlohmann::json body = {{"status", "mfa_required"},
                               {"mfa_pending_token", pending_token},
                               {"expires_in", cfg_.mfa_login_pending_secs}};
        res.set_content(body.dump(), "application/json");
        audit_log_for_principal(req, "mfa.login.required", "ok", username,
                                auth::role_to_string(*role_opt), "User", username);
        emit_event("mfa.login.required", req,
                   {{"source_ip", req.remote_addr}, {"username", username}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_challenges_issued_total").increment();
            std::lock_guard lock(mfa_pending_mu_);
            m->gauge("yuzu_auth_mfa_pending_tokens")
                .set(static_cast<double>(mfa_pending_.size()));
        }
    });

    sink.Post("/login/mfa", [this](const httplib::Request& req, httplib::Response& res) {
        // Single error message regardless of failure mode (token-invalid
        // vs code-rejected vs attempts-exhausted) — distinguishing them
        // on the wire gives an attacker a token-validity oracle. The
        // discriminator lives in the audit `detail` column only
        // (Gate 4 consistency N1 + security oracle). `kFailureBody(res)`
        // (not a compile-time constant) so each 401 mints its own
        // correlation id.
        auto kFailureBody = [](httplib::Response& r) {
            return detail::a4_error(r, "Invalid verification code");
        };

        auto pending = extract_form_value(req.body, "mfa_pending_token");
        auto code = extract_form_value(req.body, "code");

        // Look up + atomically take ownership of the entry under the
        // lock — without the move, two concurrent submits with the same
        // pending token + same valid code would both succeed and mint
        // two sessions (Gate 4 happy-path B2). We extract the entry
        // here, work without the lock, and on terminal failure we
        // re-insert with the attempts counter bumped.
        MfaPending entry;
        bool found = false;
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            auto it = mfa_pending_.find(pending);
            if (it != mfa_pending_.end()) {
                entry = std::move(it->second);
                mfa_pending_.erase(it);
                found = true;
            }
        }
        if (!found) {
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log(req, "mfa.login.failed", "error", "User", "",
                      "pending token invalid or expired");
            emit_event("mfa.login.failed", req,
                       {{"source_ip", req.remote_addr}, {"reason", "pending_invalid"}}, {},
                       Severity::kWarn);
            return;
        }

        // Reject an enrollment-bootstrap token replayed here. The user is
        // still provisional so mfa_verify_login_code would fail regardless,
        // but an explicit guard keeps the failure audit unambiguous and
        // closes the wrong-endpoint path deterministically. The entry was
        // already consumed at lookup time, so this is terminal.
        if (entry.kind == PendingKind::enrollment) {
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "enrollment token used at login-challenge endpoint");
            return;
        }

        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "auth_db unavailable");
            return;
        }

        bool matched = false;
        bool used_recovery = false;
        bool store_unavailable = false;
        // Strict shape gate (Gate 4 consistency N2 + unhappy UP-14/UP-20):
        //   - TOTP: exactly 6 ASCII digits
        //   - Recovery: any other shape goes through normalisation +
        //     base32 alphabet check at the store layer
        // Pre-PR1's heuristic admitted 7-digit numeric noise into the
        // recovery PBKDF2 scan (~10 ms CPU each) which compounded UP-11
        // into a sustained DoS vector.
        bool is_totp = code.size() == 6;
        if (is_totp) {
            for (char c : code) {
                if (c < '0' || c > '9') {
                    is_totp = false;
                    break;
                }
            }
        }
        if (is_totp) {
            auto r = db->mfa_verify_login_code(entry.username, code);
            if (r) {
                matched = *r;
            } else if (is_store_unavailable(r.error())) {
                // ★ SECURITY (architect BLOCK): a decrypt/store failure must
                // NEVER be treated as "wrong code" — that would silently
                // burn one of the user's limited attempts against a
                // transient outage, and (more importantly) is exactly the
                // class of error `AuthDBError::SecretUnavailable` exists to
                // distinguish from a genuine mismatch. `matched` stays
                // false either way (no session is minted), but this takes
                // a dedicated fail-closed 503 path below rather than the
                // uniform 401 "wrong code" body.
                store_unavailable = true;
            }
        } else {
            auto r = db->mfa_consume_recovery_code(entry.username, code);
            if (r && *r) {
                matched = true;
                used_recovery = true;
            } else if (!r && is_store_unavailable(r.error())) {
                store_unavailable = true; // outage → 503, never a burned attempt
            }
        }

        if (store_unavailable) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "authentication store is temporarily unavailable"),
                            "application/json");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_verify"}})
                    .increment();
            }
            audit_log_for_principal(req, "mfa.login.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "mfa_verify_login_code: secret/store unavailable "
                                    "(fail-closed, no session minted)");
            emit_event("mfa.login.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", entry.username},
                        {"reason", "store_unavailable"}},
                       {}, Severity::kCritical);
            return;
        }

        if (!matched) {
            // Bump attempts counter and re-insert if still under the cap.
            // Once exhausted the entry stays erased and the operator must
            // start over from /login (rate-limit gap closure for H1+UP-11).
            // Capture identity BEFORE the move-back — reading entry.username
            // after `std::move(entry)` would emit a CC6.6 audit row with an
            // empty principal (governance safety-B1).
            const std::string uname = entry.username;
            const auto urole = entry.role;
            entry.attempts += 1;
            bool exhausted = entry.attempts >= kMfaMaxAttemptsPerPending;
            // Only re-insert if the entry is under the cap AND still within
            // its TTL — re-inserting an already-expired entry would
            // resurrect a token past its deadline for one more attempt
            // window until the next reap (governance UP-13).
            const bool reinsert =
                !exhausted && std::chrono::steady_clock::now() < entry.expires_at;
            std::size_t pending_size = 0;
            {
                std::lock_guard lock(mfa_pending_mu_);
                if (reinsert) {
                    mfa_pending_[pending] = std::move(entry);
                }
                pending_size = mfa_pending_.size();
            }
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", uname,
                                    auth::role_to_string(urole), "User", uname,
                                    exhausted ? "attempts exhausted"
                                              : (is_totp ? "totp code rejected"
                                                         : "recovery code rejected"));
            emit_event("mfa.login.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", uname},
                        {"method", is_totp ? "totp" : "recovery"},
                        {"attempts_exhausted", exhausted}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_logins_total",
                           {{"method", is_totp ? "totp" : "recovery"},
                            {"result", exhausted ? "exhausted" : "failure"}})
                    .increment();
                m->gauge("yuzu_auth_mfa_pending_tokens")
                    .set(static_cast<double>(pending_size));
            }
            return;
        }

        // Terminal success — entry was already erased atomically at
        // lookup time. The TOTP/recovery code has already been verified
        // (and, for recovery, irreversibly consumed in AuthDB) above —
        // that DB-committed state change is real regardless of what the
        // session mint below does, so its audit row is emitted here,
        // unconditionally, rather than after the mint (#4107 Gate 8,
        // security-guardian: a denied mint used to silently drop this
        // TRUE row along with the false auth.login "ok" it was
        // previously bundled with).
        if (used_recovery) {
            audit_log_for_principal(req, "mfa.recovery_code.used", "ok", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "method=recovery");
        } else {
            audit_log_for_principal(req, "mfa.login.verified", "ok", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username);
        }
        emit_event(used_recovery ? "mfa.recovery_code.used" : "mfa.login.verified", req,
                   {{"source_ip", req.remote_addr},
                    {"username", entry.username},
                    {"auth_method", used_recovery ? "password+recovery" : "password+totp"}});
        // Mint the real session marked as MFA-verified.
        auto token = auth_mgr_.create_local_session(entry.username, entry.role, true);
        if (token.empty()) {
            // #4107 Gate 8 finding (security-guardian) - see the plain-
            // password-login call site's identical comment above (also
            // covers why the audit reason below doesn't assert
            // post_mint_recheck=true - cpp-expert Gate 8).
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "auth.login", "failure", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "reason=session_mint_failed;cause=undifferentiated;method=" +
                                        std::string(used_recovery ? "password+recovery"
                                                                   : "password+totp"));
            emit_event("auth.login", req,
                       {{"source_ip", req.remote_addr},
                        {"username", entry.username},
                        {"auth_method", used_recovery ? "password+recovery" : "password+totp"}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_login_session_mint_denied_total").increment();
            }
            return;
        }
        res.set_header("Set-Cookie", "yuzu_session=" + token + session_cookie_attrs());
        res.set_content(R"({"status":"ok"})", "application/json");
        // Canonical auth.login row so SIEM queries that key on it for
        // session-creation parity across password, OIDC, and MFA paths
        // stay correct (Gate 4 architect S2 + happy-path S1 + S2).
        audit_log_for_principal(req, "auth.login", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username,
                                used_recovery ? "method=password+recovery"
                                              : "method=password+totp");
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_logins_total",
                       {{"method", used_recovery ? "recovery" : "totp"},
                        {"result", "success"}})
                .increment();
            std::lock_guard lock(mfa_pending_mu_);
            m->gauge("yuzu_auth_mfa_pending_tokens")
                .set(static_cast<double>(mfa_pending_.size()));
        }
    });

    // -- MFA enrollment bootstrap (PR3) ---------------------------------------
    //
    // POST /login/mfa/enroll — completes a login that /login blocked
    // because `mfa_enforcement` required MFA and the user had none. /login
    // issued a provisional TOTP secret + an enrollment-pending token; this
    // endpoint confirms the first code against that provisional secret,
    // promotes it to enrolled, mints the (MFA-verified) session, and
    // returns the one-time recovery codes for the browser to display.
    //
    // Only a 6-digit TOTP code is accepted — recovery codes don't exist
    // until enrollment completes, and the strict shape gate keeps the
    // PBKDF2 DoS surface closed (same posture as /login/mfa). Shares the
    // `is_login` rate-limit predicate so the provisional secret can't be
    // brute-forced. Uniform 401 body on every failure mode.
    sink.Post("/login/mfa/enroll", [this](const httplib::Request& req, httplib::Response& res) {
        auto kFailureBody = [](httplib::Response& r) {
            return detail::a4_error(r, "Invalid verification code");
        };

        auto pending = extract_form_value(req.body, "mfa_pending_token");
        auto code = extract_form_value(req.body, "code");

        // Atomically take ownership of the entry (see /login/mfa rationale —
        // without the move two concurrent confirms could both mint).
        MfaPending entry;
        bool found = false;
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            auto it = mfa_pending_.find(pending);
            if (it != mfa_pending_.end()) {
                entry = std::move(it->second);
                mfa_pending_.erase(it);
                found = true;
            }
        }
        if (!found) {
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log(req, "mfa.enroll.failed", "error", "User", "",
                      "pending token invalid or expired");
            return;
        }

        // Reject a login-challenge token replayed at the enrollment
        // endpoint — the inverse of the guard in /login/mfa.
        if (entry.kind != PendingKind::enrollment) {
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.enroll.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "login-challenge token used at enrollment endpoint");
            return;
        }

        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            // Uniform 401 (NOT 503) on db-null: matches the /login/mfa
            // sibling and avoids leaking "this pending token is valid" via
            // a distinct status during a store outage (Hermes L-1). The
            // real reason is in the audit detail only.
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.enroll.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "auth_db unavailable");
            return;
        }

        // Strict shape gate: exactly 6 ASCII digits.
        bool is_totp = code.size() == 6;
        if (is_totp) {
            for (char c : code) {
                if (c < '0' || c > '9') {
                    is_totp = false;
                    break;
                }
            }
        }

        std::vector<std::string> recovery_codes;
        bool verified = false;
        bool store_unavailable = false;
        bool already_enrolled = false;
        if (is_totp) {
            auto r = db->mfa_verify_enrollment(entry.username, code);
            if (r) {
                recovery_codes = std::move(*r);
                verified = true;
            } else if (r.error() == AuthDBError::MfaAlreadyEnrolled) {
                // The account is already enrolled — a concurrent verify won the
                // race (or it was enrolled before this pending token committed).
                // NOT a wrong code and NOT an outage — handled distinctly below so
                // it neither burns a pending attempt nor emits a false
                // store-unavailable signal (#3777, CC7.2). (A bare disable+re-init
                // WITHOUT a subsequent winning verify leaves mfa_enrolled_at NULL,
                // so it does NOT reach here — it stays fail-closed WriteFailed→503.)
                already_enrolled = true;
            } else if (is_store_unavailable(r.error())) {
                // ★ SECURITY (architect BLOCK): a decrypt/store failure must
                // NEVER be treated as "wrong code" here either — same
                // reasoning as /login/mfa. No session is minted regardless;
                // this only routes to a distinct fail-closed 503 below
                // instead of burning an attempt on a transient outage.
                store_unavailable = true;
            }
        }

        if (already_enrolled) {
            // Distinct benign outcome: audit as a race (not a rejected code) and
            // tell the caller the true state. No session is minted (as on every
            // non-success path here); the operator simply completes login
            // normally, now enrolled. The pending entry was already move-erased on
            // take-ownership above (a verify consumes its token), so there is
            // nothing further to drop — unlike the wrong-code path, this branch
            // never re-inserts it, so the one-shot token is spent.
            audit_log_for_principal(req, "mfa.enroll.race", "ok", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "already enrolled by a concurrent verify; no duplicate "
                                    "enrollment");
            res.status = 409;
            res.set_content(detail::a4_error(res, "MFA is already enrolled on this account"),
                            "application/json");
            return;
        }

        if (store_unavailable) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "authentication store is temporarily unavailable"),
                            "application/json");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_enroll"}})
                    .increment();
            }
            audit_log_for_principal(req, "mfa.enroll.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "mfa_verify_enrollment: secret/store unavailable "
                                    "(fail-closed, no session minted)");
            emit_event("mfa.enroll.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", entry.username},
                        {"reason", "store_unavailable"}},
                       {}, Severity::kCritical);
            return;
        }

        if (!verified) {
            // Bump attempts; re-insert if still under the cap. The
            // provisional secret persists in the DB across retries (it is
            // NOT re-revealed) so the operator keeps the QR they already
            // scanned; only the next 30s code is needed.
            //
            // Capture identity BEFORE the move-back — reading entry.username
            // after `std::move(entry)` would emit a CC6.6 audit row with an
            // empty principal (governance safety-B1). Snapshot the pending
            // count under the same lock and publish metrics OUTSIDE it, so
            // mfa_pending_mu_ is never held across the metrics-registry lock
            // (lock-discipline parity with /login/mfa; cpp-safety SHOULD).
            const std::string uname = entry.username;
            const auto urole = entry.role;
            entry.attempts += 1;
            bool exhausted = entry.attempts >= kMfaMaxAttemptsPerPending;
            // Re-insert only if under the cap AND still within TTL (UP-13).
            const bool reinsert =
                !exhausted && std::chrono::steady_clock::now() < entry.expires_at;
            std::size_t pending_size = 0;
            {
                std::lock_guard lock(mfa_pending_mu_);
                if (reinsert) {
                    mfa_pending_[pending] = std::move(entry);
                }
                pending_size = mfa_pending_.size();
            }
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(
                req, "mfa.enroll.failed", "error", uname, auth::role_to_string(urole), "User",
                uname,
                exhausted ? "attempts exhausted"
                          : (is_totp ? "totp code rejected" : "malformed code"));
            emit_event("mfa.enroll.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", uname},
                        {"method", "enroll"},
                        {"attempts_exhausted", exhausted}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                // Failure-counter parity with /login/mfa so enrollment
                // brute-force / storm is alertable (cons-S2 / sre).
                m->counter("yuzu_auth_mfa_logins_total",
                           {{"method", "enroll"},
                            {"result", exhausted ? "exhausted" : "failure"}})
                    .increment();
                m->gauge("yuzu_auth_mfa_pending_tokens")
                    .set(static_cast<double>(pending_size));
            }
            return;
        }

        // Enrollment confirmed - TOTP secret is already durably promoted
        // to enrolled and the recovery codes already generated server-
        // side, regardless of what the session mint below does, so their
        // audit rows fire here, unconditionally (#4107 Gate 8, security-
        // guardian: a denied mint used to silently drop these TRUE rows
        // along with the false auth.login "ok" they were previously
        // bundled with). The recovery codes' one-time VALUE reveal to the
        // client stays gated on a successful mint below - only the fact
        // that they were generated is unconditional.
        audit_log_for_principal(req, "mfa.enroll.verified", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username,
                                "enforcement bootstrap");
        audit_log_for_principal(req, "mfa.recovery_codes.generated", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username);
        emit_event("mfa.enroll.verified", req,
                   {{"source_ip", req.remote_addr}, {"username", entry.username}});
        // Mint the MFA-verified session and return the recovery codes for
        // the one-time reveal.
        auto token = auth_mgr_.create_local_session(entry.username, entry.role, true);
        if (token.empty()) {
            // #4107 Gate 8 finding (security-guardian) - see the plain-
            // password-login call site's identical comment. Enrollment
            // itself already committed (TOTP confirmed, recovery codes
            // generated) - only the SESSION mint is denied here, which is
            // correct and safe: the account's role changed (or the store
            // degraded) during this flow, so no session should be handed
            // out regardless of enrollment status. The recovery-codes
            // one-time reveal is correctly withheld on this path too.
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "auth.login", "failure", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "reason=session_mint_failed;cause=undifferentiated;"
                                    "method=password+totp-enroll");
            emit_event("auth.login", req,
                       {{"source_ip", req.remote_addr}, {"username", entry.username}}, {},
                       Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_login_session_mint_denied_total").increment();
            }
            return;
        }
        res.set_header("Set-Cookie", "yuzu_session=" + token + session_cookie_attrs());
        nlohmann::json body = {{"status", "ok"}, {"recovery_codes", recovery_codes}};
        res.set_content(body.dump(), "application/json");
        // Canonical auth.login row (session-creation parity with the
        // password / OIDC / login-challenge paths).
        audit_log_for_principal(req, "auth.login", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username,
                                "method=password+totp-enroll");
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_logins_total", {{"method", "enroll"}, {"result", "success"}})
                .increment();
            std::lock_guard lock(mfa_pending_mu_);
            m->gauge("yuzu_auth_mfa_pending_tokens")
                .set(static_cast<double>(mfa_pending_.size()));
        }
    });

    // -- MFA step-up (PR2) ----------------------------------------------------
    //
    // POST /login/mfa/stepup — re-prove MFA for an existing session so the
    // session's mfa_verified_at refreshes and the high-risk REST/Settings
    // gate at `mfa_step_up.hpp` lets the next mutation through. The endpoint
    // is rate-limited at the server pre-routing layer (`is_login`
    // predicate widened to include this path) so a malicious operator with
    // a valid session cannot pound the TOTP space to brute-force the secret.
    //
    // Failure-mode taxonomy mirrors POST /login/mfa: uniform 401 body
    // regardless of whether the session was missing/stale, the code shape
    // was wrong, or the code mismatched. Discriminator lives in the audit
    // detail only (token-validity oracle defence). API-token principals
    // hit this endpoint with auth_source != "local"/"oidc" — they get a
    // 400 (session step-up is the wrong tool for token rotation).
    sink.Post("/login/mfa/stepup", [this](const httplib::Request& req, httplib::Response& res) {
        auto kFailureBody = [](httplib::Response& r) {
            return detail::a4_error(r, "MFA step-up failed");
        };

        auto session = require_auth(req, res);
        if (!session)
            return;

        // Only LOCAL sessions can step up here: this endpoint verifies a
        // TOTP / recovery code against a local `users` row. Three other
        // principal kinds reach this code and must be rejected with a
        // precise remediation rather than a misleading 401:
        //   - bearer (api_token/mcp_token): no session to step up; re-issue
        //     the token.
        //   - OIDC: no local secret exists (create_oidc_session never
        //     writes a users row), so mfa_verify_login_code would always
        //     fail. The step-up gate already routes OIDC callers to
        //     /auth/oidc/start; this 400 keeps the endpoint contract honest
        //     instead of silently dead-ending them on a 401 (governance
        //     cons-B1). Audit + correlation_id keep both branches traceable.
        //   - SAML: no local secret exists (create_saml_session never
        //     writes a users row); MFA attestation for SAML is deferred to
        //     a future release. Return a clear denial rather than the
        //     misleading API-token message (governance R12).
        //
        // A fourth kind, `engine_token` (design doc §6), also reaches this
        // code: `is_oidc`/`is_saml` are both false for it, so it falls into
        // the same "bearer credential cannot step up" branch as api_token/
        // mcp_token below — a 400, never a session mutation. Correct posture:
        // an engine session has no local secret and no MFA-enrolled user to
        // step up (§9), so denial here is intended, not an accidental
        // fallthrough.
        if (session->auth_source != "local") {
            const bool is_oidc = session->auth_source == "oidc";
            const bool is_saml = session->auth_source == "saml";
            const auto cid = detail::make_correlation_id();
            res.status = 400;
            const char* msg =
                is_oidc ? "OIDC sessions re-prove MFA by re-authenticating with the "
                          "identity provider — start a new SSO sign-in at /auth/oidc/start, "
                          "not local step-up"
                : is_saml ? "MFA step-up is not available for SAML sessions in this release — "
                            "re-authenticate via SAML at /auth/saml/start"
                : "step-up is for session-cookie callers only — re-issue the API "
                  "token to refresh MFA proof";
            nlohmann::json envelope = {
                {"error",
                 {{"code", 400},
                  {"message", msg},
                  {"correlation_id", cid}}},
                {"meta", {{"api_version", "v1"}}}};
            res.set_content(envelope.dump(), "application/json");
            const char* audit_detail =
                is_oidc ? "oidc session cannot local step up (re-SSO)"
                : is_saml ? "saml session cannot local step up (no mfa this release)"
                : "bearer credential cannot step up";
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username,
                                    std::string(audit_detail) +
                                        " (auth_source=" + session->auth_source + ")");
            return;
        }

        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "auth_db unavailable"), "application/json");
            return;
        }

        auto code = extract_form_value(req.body, "code");
        if (code.empty()) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "missing code"), "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username, "missing code");
            return;
        }

        // Strict shape gate (same as /login/mfa): 6 ASCII digits → TOTP,
        // anything else → recovery code path. Defeats the CPU-DoS shape
        // oracle that a 7-digit numeric noise would otherwise trip.
        bool is_totp = code.size() == 6;
        if (is_totp) {
            for (char c : code) {
                if (c < '0' || c > '9') {
                    is_totp = false;
                    break;
                }
            }
        }
        bool matched = false;
        bool used_recovery = false;
        bool store_unavailable = false;
        if (is_totp) {
            auto r = db->mfa_verify_login_code(session->username, code);
            if (r) {
                matched = *r;
            } else if (is_store_unavailable(r.error())) {
                // ★ SECURITY (architect BLOCK): never collapse a decrypt/
                // store failure into "wrong code" — no session mutation
                // happens either way, but the caller (and audit trail)
                // deserves a distinct fail-closed signal.
                store_unavailable = true;
            }
        } else {
            auto r = db->mfa_consume_recovery_code(session->username, code);
            if (r && *r) {
                matched = true;
                used_recovery = true;
            } else if (!r && is_store_unavailable(r.error())) {
                store_unavailable = true; // outage → 503, never a burned attempt
            }
        }

        if (store_unavailable) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "authentication store is temporarily unavailable"),
                            "application/json");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
                    .increment();
            }
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username,
                                    "mfa_verify_login_code: secret/store unavailable "
                                    "(fail-closed)");
            emit_event("mfa.step_up.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", session->username},
                        {"reason", "store_unavailable"}},
                       {}, Severity::kCritical);
            return;
        }

        if (!matched) {
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username,
                                    is_totp ? "totp code rejected" : "recovery code rejected");
            emit_event("mfa.step_up.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", session->username},
                        {"method", is_totp ? "totp" : "recovery"}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_step_up_total",
                           {{"method", is_totp ? "totp" : "recovery"}, {"result", "failure"}})
                    .increment();
            }
            return;
        }

        // Success — stamp `mfa_verified_at = system_clock::now()` on the
        // existing session row (wall-clock since HA WS-1/1a). The cookie itself
        // does NOT rotate — the
        // step-up refreshes a session attribute, it does not mint a new
        // session (which would break in-flight HTMX requests from the
        // same browser tab).
        auto token = extract_session_cookie(req);
        if (!auth_mgr_.mark_session_mfa_verified(token)) {
            // Defensive — require_auth succeeded so the token resolves to
            // a session; if mark_session_mfa_verified can't find it, the
            // session was concurrently invalidated. Fail closed.
            res.status = 401;
            res.set_content(kFailureBody(res), "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username, "session vanished during step-up");
            return;
        }
        res.set_content(R"({"status":"ok"})", "application/json");
        audit_log_for_principal(req, "mfa.step_up.passed", "ok", session->username,
                                auth::role_to_string(session->role), "User", session->username,
                                used_recovery ? "method=recovery" : "method=totp");
        emit_event("mfa.step_up.passed", req,
                   {{"source_ip", req.remote_addr},
                    {"username", session->username},
                    {"method", used_recovery ? "recovery" : "totp"}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_step_up_total",
                       {{"method", used_recovery ? "recovery" : "totp"}, {"result", "success"}})
                .increment();
        }
    });

    // -- Logout ---------------------------------------------------------------
    sink.Post("/logout", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = extract_session_cookie(req);
        // db_persisted=false ⇒ the durable session row was NOT deleted (store
        // error); the cookie can still rehydrate a valid session on another
        // replica / if copied, so logout is only PARTIAL — do not audit/report a
        // clean success (adversarial-round blocker #3). The local cache is erased
        // and the client cookie is cleared regardless (this browser is logged
        // out), but ops + API callers are told the durable delete failed so it
        // can be retried; the degrade metric was already incremented in
        // invalidate_session.
        const bool db_persisted = token.empty() ? true : auth_mgr_.invalidate_session(token);
        audit_log(req, "auth.logout", db_persisted ? "success" : "partial", /*target_type=*/{},
                  /*target_id=*/{}, db_persisted ? "" : "db_error=true");
        emit_event("auth.logout", req);
        const bool is_htmx = !req.get_header_value("HX-Request").empty();
        if (!db_persisted) {
            // FAIL CLOSED (adversarial-round #2, C2): the durable row was NOT
            // deleted, so the session is still valid (it rehydrates on any cache
            // miss / on another replica / from a copied cookie). Do NOT clear the
            // cookie — that would look like a clean logout AND destroy the only
            // credential a retry needs — and do NOT redirect an HTMX client to
            // /login. Return a visible error on BOTH surfaces so the human/API
            // caller knows logout is incomplete and retries (the durable delete
            // is idempotent). The degrade metric already fired in
            // invalidate_session; ops sees the `partial` audit row.
            res.status = 503;
            if (is_htmx)
                res.set_content("<div class=\"error\">Logout could not be completed (the session "
                                "store is unavailable). You are still signed in — please retry.</div>",
                                "text/html");
            else
                res.set_content(
                    R"({"status":"partial","detail":"the durable session could not be deleted; you are still signed in, retry to complete logout"})",
                    "application/json");
            return;
        }
        // Success — the durable row is gone; clear the cookie and finish.
        res.set_header("Set-Cookie", "yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
        if (is_htmx) {
            res.set_header("HX-Redirect", "/login");
            res.set_content("", "text/plain");
        } else {
            res.set_content(R"({"status":"ok"})", "application/json");
        }
    });

    // -- OIDC SSO endpoints ---------------------------------------------------
    sink.Get("/auth/oidc/start", [this](const httplib::Request& req, httplib::Response& res) {
        std::shared_lock oidc_lock(oidc_mu_);
        if (!oidc_provider_ || !oidc_provider_->is_enabled()) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "OIDC not configured"), "application/json");
            return;
        }
        // Use the configured redirect URI only — never derive from the
        // Host header, which can be manipulated for phishing attacks (M3).
        if (cfg_.oidc_redirect_uri.empty()) {
            res.status = 500;
            res.set_content(
                detail::a4_error(res, "OIDC redirect_uri not configured — set "
                                       "--oidc-redirect-uri or YUZU_OIDC_REDIRECT_URI"),
                "application/json");
            spdlog::error("OIDC auth flow blocked: redirect_uri not configured");
            return;
        }
        auto auth_url = oidc_provider_->start_auth_flow(cfg_.oidc_redirect_uri);
        res.set_redirect(auth_url);
    });

    sink.Get("/auth/callback", [this](const httplib::Request& req, httplib::Response& res) {
        std::shared_lock oidc_lock(oidc_mu_);
        if (!oidc_provider_) {
            res.status = 404;
            res.set_content("OIDC not configured", "text/plain");
            return;
        }

        // Check for error response from IdP
        auto error = req.get_param_value("error");
        if (!error.empty()) {
            auto desc = req.get_param_value("error_description");
            spdlog::warn("OIDC error from IdP: {} - {}", error, desc);
            // cons-S1: mirror the SAML ACS early-error branches — emit an
            // audit row, not just a metric bump, so an IdP-side denial shows
            // up in Yuzu's own audit trail.
            audit_log(req, "auth.oidc_login_failed", "error", {}, {}, "idp error: " + error);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_redirect("/login?error=sso_denied");
            return;
        }

        auto code = req.get_param_value("code");
        auto state = req.get_param_value("state");

        if (code.empty() || state.empty()) {
            // cons-S1: mirror the SAML ACS early-error branches — emit an
            // audit row, not just a metric bump.
            audit_log(req, "auth.oidc_login_failed", "error", {}, {}, "missing code or state");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_redirect("/login?error=sso_invalid");
            return;
        }

        auto result = oidc_provider_->handle_callback(code, state);
        if (!result) {
            // No display=/email= detail here — handle_callback failed before
            // claims were extracted (token exchange, signature, or
            // validate_claims rejection incl. the #1837 governance sub/iss
            // checks), so there is no human name to carry. Every OTHER
            // auth.oidc_login_failed / auth.sso_group_provision emission
            // below this point (claims successfully parsed) DOES carry it.
            spdlog::warn("OIDC callback failed: {}", result.error());
            audit_log(req, "auth.oidc_login_failed", "failure");
            emit_event("auth.oidc_login_failed", req,
                       {{"source_ip", req.remote_addr}, {"error", result.error()}}, {},
                       Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_redirect("/login?error=sso_failed");
            return;
        }

        auto& claims = result.value();
        auto email = claims.email.empty() ? claims.preferred_username : claims.email;
        auto display = claims.name.empty() ? email : claims.name;
        // #1837 — the STABLE authorization principal, not the mutable
        // display name: `sub` is only guaranteed unique per-issuer (RFC
        // 7519), so it must be scoped by `iss`. Two SSO users who happen to
        // share a display name (or one whose display name later changes)
        // must never collide onto — or silently migrate onto — the same
        // principal, which #1832's RBAC reconcile would otherwise make
        // destructive (one user's login deleting the other's group
        // memberships). ADR-2001 §5 — built through the single shared
        // helper, which is also what AuthManager::create_oidc_session uses,
        // so the two mint sites cannot drift apart.
        const std::string username = oidc::oidc_principal_id(claims.iss, claims.sub);
        auto admin_gid = oidc_provider_ ? cfg_.oidc_admin_group : std::string{};

        // ADR-2001 §4 — the SAME externalId candidate value link formation
        // uses below (`link_oidc_login_to_scim`) — computed once here so the
        // deny-at-login backstop's reprovision check (governance U1) and
        // link formation can never drift onto different values.
        const std::string link_claim_value =
            cfg_.oidc_scim_link_claim == "oid" ? claims.oid : claims.sub;

        // ADR-2001 §4 — deny-at-login backstop, PRIMARY check. Runs before
        // every mutation below (group reconcile, session mint,
        // provision_sso_identity, the ADR-2001 §2 link/observation writes,
        // MFA amr seeding) so a denied login leaves no side effect behind —
        // a deprovisioned SCIM user must not be able to re-authenticate and
        // mint a fresh session just by round-tripping the IdP again.
        // `oidc_login_denied_deprovisioned` is fail-CLOSED: a ScimStore that
        // cannot answer denies, exactly like a resolved-inactive link or a
        // genuinely-orphaned (not re-provisioned) one. Emits the
        // BYTE-IDENTICAL `sso_failed` redirect the token-exchange-failure
        // branch above uses — no "deprovisioned"/oracle wording reaches the
        // browser; the reason (and, when known, the driving scim_id —
        // server-generated CSPRNG hex, never IdP input, so no
        // sanitize_detail_value needed) lives only in the server-side audit
        // row. Governance U6 fix: a store-unavailable DENY (`scim_id`
        // absent) is audited as `scim_store_unavailable`, never as
        // `linked_scim_resource_inactive` — the latter is fictional CC6.8
        // evidence when the store simply couldn't be asked.
        if (auto decision = oidc::oidc_login_denied_deprovisioned(scim_store_, claims.iss,
                                                                   claims.sub, link_claim_value);
            decision.denied) {
            spdlog::warn("OIDC login denied for '{}': linked SCIM resource is deprovisioned",
                        username);
            std::string deny_detail = decision.scim_id
                                          ? "reason=linked_scim_resource_inactive;scim_id=" +
                                                *decision.scim_id
                                          : "reason=scim_store_unavailable";
            audit_log_for_principal(req, "auth.oidc.deprovisioned_denied", "failure", username,
                                    "user", "User", username, deny_detail);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_oidc_deprovisioned_denied_total").increment();
                // #3069 split: the total above conflates a genuine
                // deprovision deny with a store-unavailable fail-closed
                // deny, which lets a Postgres outage inflate the counter
                // operators alert on. `decision.scim_id` is the SAME
                // predicate the audit `reason=` string above already
                // switches on — absent means the store couldn't be asked
                // (`scim_store_unavailable`), never a genuine deny.
                record_deprovision_deny_split(
                    m, "yuzu_auth_oidc_deprovisioned_denied_genuine_total",
                    "yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total",
                    decision.scim_id.has_value());
                // Also bump the established general OIDC login counter so
                // dashboards keyed on it don't undercount during a deny
                // episode — every other /auth/callback failure path bumps
                // this series too.
                m->counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_redirect("/login?error=sso_failed");
            return;
        }

        // #1832 — reconcile IdP group memberships into the RBAC store BEFORE
        // minting a session, so a provisioning failure denies the login
        // outright (fail-closed) instead of granting a session under
        // stale/unreconciled roles. `reconcile_idp_memberships` writes
        // NAMESPACED group names (`entra:<gid>`, via
        // `RbacStore::namespaced_group_name`) — the confused-deputy fix: a
        // locally-created group can never collide with (or be impersonated
        // by) a same-named IdP group. It also DELETEs any of this user's
        // 'entra'-sourced memberships that were NOT re-asserted this login,
        // which is the deprovisioning-bypass fix — IdP-side group removal
        // now takes effect on the user's next SSO login instead of
        // accumulating forever. Local memberships are never touched.
        //
        // UP-1 hardening: reconciliation only runs when
        // `groups_claim_reconcilable(claims)` is true — i.e. the token
        // actually carried a `groups` key AND it was not replaced by an
        // Entra group-overage pointer. A user in >200 Entra groups gets
        // NEITHER of those, and treating the resulting empty `claims.groups`
        // as "this user is in zero groups" would DELETE every one of their
        // existing entra:-owned memberships on this login — silent mass
        // deprovisioning of a legitimate, heavily-grouped user. That case is
        // SKIPPED entirely (existing memberships left untouched; the login
        // itself still proceeds — this is fail-OPEN on membership, never on
        // authentication). See `docs/user-manual/authentication.md` "RBAC
        // Group Provisioning" (the real heading — keep this anchor in sync).
        if (rbac_store_) {
            if (!oidc::groups_claim_reconcilable(claims)) {
                const std::string reason =
                    claims.groups_overage ? "groups_overage" : "groups_absent";
                spdlog::info("OIDC group provisioning skipped for '{}': reason={}", username,
                            reason);
                audit_log_for_principal(
                    req, "auth.sso_group_provision", "skipped", username, "user", "", "",
                    "reason=" + reason + ";source=entra" +
                        ";display=" + detail::sanitize_detail_value(display) +
                        ";email=" + detail::sanitize_detail_value(email));
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_sso_group_provision_total",
                              {{"source", "entra"}, {"result", "skipped"}})
                        .increment();
                }
            } else if (claims.groups.size() > RbacStore::kMaxIdpGroupsPerLogin) {
                spdlog::warn(
                    "OIDC group provisioning denied for '{}': {} asserted groups exceeds cap {}",
                    username, claims.groups.size(), RbacStore::kMaxIdpGroupsPerLogin);
                audit_log_for_principal(
                    req, "auth.sso_group_provision", "error", username, "user", "", "",
                    "reason=group_count_exceeded;count=" +
                        std::to_string(claims.groups.size()) + ";source=entra" +
                        ";display=" + detail::sanitize_detail_value(display) +
                        ";email=" + detail::sanitize_detail_value(email));
                // cons-S2 — also emit the same failed-OIDC-login signal the
                // sibling token-exchange-failure branch emits above, so a
                // SIEM query counting failed OIDC logins by
                // `auth.oidc_login_failed` doesn't miss a provisioning-denied
                // login (this branch denies the login just as surely).
                audit_log_for_principal(
                    req, "auth.oidc_login_failed", "error", username, "user", "", "",
                    std::string("reason=group_count_exceeded") +
                        ";display=" + detail::sanitize_detail_value(display) +
                        ";email=" + detail::sanitize_detail_value(email));
                emit_event("auth.oidc_login_failed", req,
                          {{"source_ip", req.remote_addr},
                           {"username", username},
                           {"error", "group_count_exceeded"}},
                          {}, Severity::kWarn);
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_sso_group_provision_total",
                              {{"source", "entra"}, {"result", "error"}})
                        .increment();
                }
                res.set_redirect("/login?error=sso_failed");
                return;
            } else {
                std::vector<std::pair<std::string, std::string>> asserted;
                asserted.reserve(claims.groups.size());
                for (const auto& gid : claims.groups)
                    asserted.emplace_back(gid, gid);

                auto reconciled =
                    rbac_store_->reconcile_idp_memberships(username, "entra", asserted);
                if (!reconciled) {
                    spdlog::warn("OIDC group provisioning failed for '{}': {}", username,
                                reconciled.error());
                    audit_log_for_principal(
                        req, "auth.sso_group_provision", "error", username, "user", "", "",
                        "reason=" + reconciled.error() + ";source=entra" +
                            ";display=" + detail::sanitize_detail_value(display) +
                            ";email=" + detail::sanitize_detail_value(email));
                    // cons-S2 — see the over-cap branch above.
                    audit_log_for_principal(
                        req, "auth.oidc_login_failed", "error", username, "user", "", "",
                        "reason=" + reconciled.error() +
                            ";display=" + detail::sanitize_detail_value(display) +
                            ";email=" + detail::sanitize_detail_value(email));
                    emit_event("auth.oidc_login_failed", req,
                              {{"source_ip", req.remote_addr},
                               {"username", username},
                               {"error", reconciled.error()}},
                              {}, Severity::kWarn);
                    if (auto* m = auth_mgr_.metrics_registry()) {
                        m->counter("yuzu_auth_sso_group_provision_total",
                                  {{"source", "entra"}, {"result", "error"}})
                            .increment();
                    }
                    res.set_redirect("/login?error=sso_failed");
                    return;
                }

                // cons-S3 — a no-op reconcile (nothing added or removed; the
                // asserted set exactly matched what was already on record)
                // writes no provisioning audit row. Every login after the
                // first steady-state one is typically a no-op; auditing each
                // would swamp the log with rows carrying no new information.
                if (reconciled->added + reconciled->removed > 0) {
                    audit_log_for_principal(
                        req, "auth.sso_group_provision", "ok", username, "user", "", "",
                        "source=entra;added=" + std::to_string(reconciled->added) +
                            ";removed=" + std::to_string(reconciled->removed) +
                            ";display=" + detail::sanitize_detail_value(display) +
                            ";email=" + detail::sanitize_detail_value(email));
                }
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_sso_group_provision_total",
                              {{"source", "entra"}, {"result", "ok"}})
                        .increment();
                }
            }
        }

        // PR3 / SOC 2 CC6.6 — seed the session's MFA-verified timestamp
        // when the IdP `amr` claim attests a multi-factor login. The
        // step-up gate (mfa_step_up.cpp) consumes this so an MFA'd SSO
        // session clears high-risk endpoints without a redundant local
        // prompt, while a single-factor SSO login is gated. Anchor the
        // proof to the IdP-asserted `iat` so a stale assertion still
        // re-prompts: a token issued `age` ago is treated as proven `age`
        // ago. Since HA WS-1/1a the proof timestamp IS wall-clock
        // (`system_clock`, durable rows, ADR-2002 §4), so `iat` seeds it
        // directly — the former steady-clock age-projection is gone. The
        // NTP-step resistance hard-invariant #5 asked for is now provided by
        // the short step-up window plus mfa_step_up.cpp's fail-closed guard
        // on a future-dated proof. A future `iat` (IdP clock ahead of ours)
        // is clamped to "now" so it can only ever shorten the window, never
        // extend it. `iat<=0` (missing/0) is NOT seeded — fabricating a fresh
        // window from a timestampless assertion would let a replayed
        // amr-without-iat token look fresh (governance UP-9); an un-seeded
        // OIDC session simply passes the step-up gate like any non-MFA SSO
        // identity.
        const bool amr_mfa_asserted = amr_asserts_mfa(claims.amr);
        std::chrono::system_clock::time_point mfa_at{};
        if (amr_mfa_asserted && claims.iat > 0) {
            const auto asserted =
                std::chrono::system_clock::from_time_t(static_cast<std::time_t>(claims.iat));
            const auto now = std::chrono::system_clock::now();
            mfa_at = (asserted > now) ? now : asserted; // clamp a future iat to "now"
        }

        auto session_token = auth_mgr_.create_oidc_session(display, email, claims.sub, claims.iss,
                                                           claims.groups, admin_gid, mfa_at);

        // #1852 — auto-provision a durable auth.db row for this stable
        // principal so JIT admin elevation has something to key on
        // (elevation_eligible / role survive across logins). Deliberately
        // called HERE, outside `create_oidc_session` — that method holds
        // `mu_` for the in-memory session map, and this performs
        // independent auth.db I/O that must not serialize behind it.
        // Fail-soft: a provisioning error is logged and swallowed by
        // `provision_sso_identity` itself; the session minted above is
        // never un-minted because of it (a login must not fail here).
        auth_mgr_.provision_sso_identity(username, claims.iss, claims.sub, display);

        // ADR-2001 §2/D2 — form a durable SCIM identity link (if the
        // configured link-claim value matches EXACTLY ONE active SCIM
        // resource) and ALWAYS record a login observation for EACH
        // candidate claim (sub AND oid — governance Gate 7 BLOCKING fix, the
        // D2 tripwire), regardless of whether a link formed. Goes through
        // ScimStore's own leased accessors — no AuthManager::mu_ is held
        // here (both create_oidc_session above and provision_sso_identity
        // have already returned, releasing their own internal locks).
        // `link_oidc_login_to_scim` is fail-OPEN by construction (never
        // throws, never returns an error to check) — it must never fail
        // this login, which has already succeeded above. A missing link is
        // instead caught later by the D2 detector (`observation_matches`)
        // against the observations written here.
        //
        // `--oidc-scim-link-claim` (default "sub"; allow-list {sub, oid}
        // enforced fail-closed at boot, main.cpp) selects which validated
        // claim value is the SCIM externalId join key for LINK FORMATION
        // only. `claims.oid` is parsed unconditionally by
        // OidcProvider::parse_id_token but validated sub-equivalently by
        // validate_claims ONLY when it is the configured link claim — safe
        // to pass through unconditionally here because
        // `link_oidc_login_to_scim` re-sanitizes every candidate claim
        // before trusting it into a durable observation row.
        oidc::link_oidc_login_to_scim(scim_store_, claims.iss, claims.sub, claims.oid,
                                      link_claim_value, auth_mgr_.metrics_registry());

        // ADR-2001 §4 — deny-at-login backstop, POST-MINT RE-CHECK (the
        // codex-caught check-then-mint race, user-approved). The primary
        // check above ran before this login's own mint; a concurrent SCIM
        // deactivate/DELETE could have landed in the window between that
        // check and `create_oidc_session` above. Re-resolve the SAME
        // decision via the SAME helper (same `link_claim_value`, so the
        // governance U1 reprovision check stays consistent between the two
        // calls) and, if it has now flipped to DENY, invalidate the session
        // just minted rather than hand it out — this self-heals the race
        // without holding a cross-store lock over the mint (which would
        // violate the no-lease-across-sibling-store discipline, ADR-2001
        // §3). Runs BEFORE the Set-Cookie header below so a denied login
        // never reaches the browser with a live cookie.
        if (auto decision = oidc::oidc_login_denied_deprovisioned(scim_store_, claims.iss,
                                                                   claims.sub, link_claim_value);
            decision.denied) {
            spdlog::warn("OIDC login denied for '{}' on post-mint re-check: linked SCIM resource "
                        "is deprovisioned (concurrent deprovision race)",
                        username);
            auto revoke_result = auth_mgr_.invalidate_user_sessions(username);
            // Governance U6 fix: a store-unavailable DENY (`scim_id` absent)
            // is audited as `scim_store_unavailable`, never as
            // `linked_scim_resource_inactive` (fictional CC6.8 evidence on a
            // mere outage) — mirrors the primary check's reason string.
            std::string recheck_detail = decision.scim_id
                                             ? "reason=linked_scim_resource_inactive;scim_id=" +
                                                   *decision.scim_id
                                             : "reason=scim_store_unavailable";
            recheck_detail += ";post_mint_recheck=true;sessions_invalidated=" +
                              std::to_string(revoke_result.count);
            if (!revoke_result.db_persisted) {
                // RevokeResult's contract (auth.hpp): a "success" audit row
                // that hides a DB persistence failure produces fictional
                // CC6.3/CC6.6 evidence — surface it in the row itself.
                recheck_detail += ";db_persisted=false";
            }
            audit_log_for_principal(req, "auth.oidc.deprovisioned_denied", "failure", username,
                                    "user", "User", username, recheck_detail);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_oidc_deprovisioned_denied_total").increment();
                // #3069 split — see the primary check above; same
                // `decision.scim_id` predicate the recheck's `reason=`
                // string already switches on.
                record_deprovision_deny_split(
                    m, "yuzu_auth_oidc_deprovisioned_denied_genuine_total",
                    "yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total",
                    decision.scim_id.has_value());
                // Also bump the established general OIDC login counter — see
                // the primary check above.
                m->counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_redirect("/login?error=sso_failed");
            return;
        }

        res.set_header("Set-Cookie", "yuzu_session=" + session_token + session_cookie_attrs());

        // Explicit-principal audit row — request lands at /auth/callback
        // with no session cookie yet, so the default resolve_session
        // path would leave principal empty (Gate 4 consistency B3). Use
        // the STABLE `username` (#1837: "oidc:<iss>#<sub>") as the
        // canonical audit principal — never the mutable display name, or
        // an IdP-side rename would sever the audit trail's identity
        // linkage across logins. Role is resolved from the freshly-minted
        // session — for the audit row we re-validate to capture the
        // role the user actually holds (group-mapping may have made
        // them admin).
        auto effective_role = auth_mgr_.validate_session(session_token)
                                  .transform([](const auth::Session& s) {
                                      return auth::role_to_string(s.role);
                                  })
                                  .value_or(std::string{"user"});
        // Record whether the IdP attested MFA (the `amr` decision) in the
        // audit detail so the CC6.6 "was this privileged SSO login MFA-
        // verified" question is answerable from Yuzu's own chain without
        // cross-referencing IdP logs (governance compliance-S2). Also carry
        // the human-readable `display`/`email` in the detail string (never
        // in the principal field) so a SIEM operator can see both the
        // stable identity and a readable name for the same row.
        // #1830.2: when the login resolved to admin, also name the granting
        // group — mirrors the SAML admin audit detail so a reviewer can see
        // WHY this OIDC login is admin without cross-referencing boot flags.
        // cons-N1: leading "auth_source=oidc;" mirrors SAML's leading
        // "auth_source=saml;" token.
        //
        // `display`/`email` are IdP-supplied — `detail::sanitize_detail_value()`
        // is applied to prevent `;`/`=`/newlines/control bytes/markup from
        // corrupting this flat "k=v;k=v" detail string's SIEM parsing or
        // causing stored XSS if rendered unescaped. The stable `username`
        // principal (`oidc:<iss>#<sub>`) is NOT sanitized here — it is the
        // audit KEY, not a detail value, and is never embedded in `detail`.
        auto oidc_audit_detail = std::string("auth_source=oidc;amr_mfa_asserted=") +
                                 (amr_mfa_asserted ? "true" : "false") +
                                 ";display=" + detail::sanitize_detail_value(display) +
                                 ";email=" + detail::sanitize_detail_value(email);
        if (effective_role == auth::role_to_string(auth::Role::admin)) {
            oidc_audit_detail += ";admin_group=" + admin_gid;
        }
        audit_log_for_principal(
            req, "auth.oidc_login", "ok", username, effective_role, "User", username,
            oidc_audit_detail);
        emit_event("auth.oidc_login", req,
                   {{"source_ip", req.remote_addr},
                    {"username", username},
                    {"auth_method", "oidc"},
                    {"amr_mfa_asserted", amr_mfa_asserted},
                    {"oidc_sub", detail::sanitize_detail_value(claims.sub)},
                    {"email", detail::sanitize_detail_value(email)},
                    {"name", detail::sanitize_detail_value(claims.name)}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            // #1828.2: mirror the SAML login counter — role sourced from the
            // same effective_role already resolved for the audit row above.
            m->counter("yuzu_auth_oidc_login_total", {{"result", "ok"}, {"role", effective_role}})
                .increment();
        }

        res.set_redirect("/");
    });

    // -- SAML 2.0 SSO endpoints ------------------------------------------------
    //
    // N4 safety: SamlProvider::is_enabled() returns false on Windows and whenever
    // the required config is incomplete — both routes fail-closed to 404.
    //
    // RelayState open-redirect safety: only same-origin relative paths are
    // accepted (starts with '/' but NOT '//').  All other values fall back to '/'.

    sink.Get("/auth/saml/start", [this](const httplib::Request& req, httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        if (!saml_provider_ || !saml_provider_->is_enabled()) {
            res.status = 404;
            res.set_content(detail::error_json_a4(404, "SAML not configured", cid),
                            "application/json");
            return;
        }

        // Optional RelayState (return-to path passed through the IdP round-trip).
        // The redirect target is validated in /saml/acs — here we pass it verbatim
        // to the AuthnRequest and it bounces back as the POST body RelayState.
        auto relay_state = req.get_param_value("RelayState");
        // build_authn_request can throw under crypto/allocation failure (deflate,
        // RNG, SHA-256); catch so we return a clean A4 500 rather than an
        // uncaught exception that httplib would surface as a non-A4 500.
        std::string authn_url;
        std::string authn_cookie_secret;
        try {
            auto authn = saml_provider_->build_authn_request(relay_state);
            authn_url           = authn.url;
            authn_cookie_secret = authn.cookie_secret;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(detail::error_json_a4(500, "Failed to build SAML AuthnRequest", cid),
                            "application/json");
            spdlog::error("SAML /auth/saml/start: build_authn_request threw: {}", e.what());
            // Count SP-initiated failures the same way the ACS paths do, so the
            // signing-failure leg is not the one SAML-login failure mode absent
            // from yuzu_auth_saml_login_total.
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            return;
        }
        if (authn_url.empty()) {
            res.status = 500;
            res.set_content(detail::error_json_a4(500, "Failed to build SAML AuthnRequest", cid),
                            "application/json");
            // An empty URL is the per-request signing-failure signal
            // (build_authn_request returns {} rather than emit an unsigned
            // redirect once an SP signing key is configured).
            spdlog::error("SAML /auth/saml/start: build_authn_request returned empty URL");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            return;
        }
        // Set the browser-binding cookie so the ACS can verify this browser
        // initiated the login.  __Host- prefix enforces host-lock + Secure +
        // Path=/ (cannot be set with a Domain attribute).  SameSite=None is
        // REQUIRED because the IdP delivers the assertion via a cross-site POST
        // directly to /saml/acs; Lax would suppress the cookie on that POST.
        // Max-Age=600 matches kRequestTtl (10 minutes) so the cookie expires
        // when the pending request does.
        res.set_header("Set-Cookie",
            "__Host-yuzu_saml_bind=" + authn_cookie_secret +
            "; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=600");
        res.set_redirect(authn_url);
    });

    sink.Post("/saml/acs", [this](const httplib::Request& req, httplib::Response& res) {
        if (!saml_provider_ || !saml_provider_->is_enabled()) {
            res.status = 404;
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            res.set_content(detail::error_json_a4(404, "SAML not configured", cid),
                            "application/json");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            return;
        }

        // Clear-cookie string used on both success and failure paths.
        // Expiring the __Host- cookie immediately after use is defence-in-depth:
        // even if an attacker extracts it, it is single-use (validated_response
        // erases the pending entry on any match or mismatch).
        static const std::string kBindCookieClear =
            "__Host-yuzu_saml_bind=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0";

        // ── Forced-login CSRF guard: browser-binding cookie must be present ────
        // The binding cookie is set by GET /auth/saml/start and is HttpOnly +
        // SameSite=None + __Host-.  A CSRF-injected ACS POST from a victim's
        // browser will NOT carry this cookie (the victim never initiated a login),
        // so absence is an unambiguous forced-login attempt.
        // Use find_cookie_value (boundary-aware) so a cookie named
        // "foo__Host-yuzu_saml_bind" cannot shadow our binding cookie.
        std::string binding_cookie;
        {
            const auto cookie_hdr = req.get_header_value("Cookie");
            binding_cookie = find_cookie_value(cookie_hdr, "__Host-yuzu_saml_bind");
        }
        if (binding_cookie.empty()) {
            spdlog::warn("SAML ACS: missing binding cookie — forced-login attempt rejected");
            audit_log(req, "auth.saml_login_failed", "error", {}, {},
                      "missing binding cookie");
            emit_event("auth.saml_login_failed", req,
                       {{"source_ip", req.remote_addr},
                        {"error", "missing binding cookie"}}, {},
                       Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            // Clear any stale binding cookie (belt-and-suspenders: may be absent,
            // but Max-Age=0 on a non-existent cookie is a harmless no-op per RFC 6265).
            res.set_header("Set-Cookie", kBindCookieClear);
            res.set_redirect("/login?error=saml");
            return;
        }

        // Reject oversized POST bodies before any parsing — 1 MiB cap (N5: DoS guard).
        // A legitimate SAML Response with a signed assertion is well under 64 KiB;
        // 1 MiB gives generous headroom while preventing a plaintext amplification attack
        // via an enormous fake SAMLResponse field.
        static constexpr std::size_t kSamlMaxBodyBytes = 1048576; // 1 MiB
        if (req.body.size() > kSamlMaxBodyBytes) {
            spdlog::warn("SAML ACS: oversized POST body ({} bytes) rejected", req.body.size());
            audit_log(req, "auth.saml_login_failed", "error", {}, {}, "oversize");
            emit_event("auth.saml_login_failed", req,
                       {{"source_ip", req.remote_addr}, {"error", "oversize"}}, {},
                       Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_header("Set-Cookie", kBindCookieClear);
            res.set_redirect("/login?error=saml");
            return;
        }

        // HTTP-POST binding: SAMLResponse and RelayState are form fields.
        auto saml_response_b64 = extract_form_value(req.body, "SAMLResponse");
        auto relay_state       = extract_form_value(req.body, "RelayState");

        if (saml_response_b64.empty()) {
            audit_log(req, "auth.saml_login_failed", "error", {}, {}, "missing SAMLResponse");
            emit_event("auth.saml_login_failed", req,
                       {{"source_ip", req.remote_addr}, {"error", "missing SAMLResponse"}}, {},
                       Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_header("Set-Cookie", kBindCookieClear);
            res.set_redirect("/login?error=saml");
            return;
        }

        // validate_response verifies cryptographic signature + conditions +
        // InResponseTo + browser-binding (SHA-256(cookie) == stored hash).
        // Both validate_response and create_saml_session can throw under
        // crypto/allocation/DB failure; catch so an exception yields the same
        // clean redirect-to-login as an ordinary validation failure rather than
        // an uncaught exception surfacing as a non-A4 500.
        std::string saml_name_id;
        std::string saml_principal; // ADR-2001 PR4a stable principal — saml::saml_principal_id
        std::string session_token;
        // cons-NICE: mirror the OIDC call site's provider-presence ternary
        // (defense-in-depth — saml_provider_ is always non-null on this
        // handler's path since routes 404 without it, but this keeps the two
        // call sites structurally identical for future refactors). Hoisted
        // outside the try block so the post-login audit row (comp-S1 / UP-5,
        // below) can also reference it.
        auto saml_admin_gid = saml_provider_ ? cfg_.saml_admin_group : std::string{};
        // ADR-2001 PR4a — the operator-configured, boot-validated IdP
        // entityID (already verified by validate_response below to equal
        // the assertion's signed <saml:Issuer>). This is the single-IdP
        // precondition the SAML principal/link design relies on.
        const std::string& saml_entity_id = cfg_.saml_idp_entity_id;
        try {
            auto result = saml_provider_->validate_response(saml_response_b64, binding_cookie);
            if (!result) {
                spdlog::warn("SAML ACS validation failed: {}", result.error());
                audit_log(req, "auth.saml_login_failed", "error", {}, {}, result.error());
                emit_event("auth.saml_login_failed", req,
                           {{"source_ip", req.remote_addr}, {"error", result.error()}}, {},
                           Severity::kWarn);
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
                }
                res.set_header("Set-Cookie", kBindCookieClear);
                res.set_redirect("/login?error=saml");
                return;
            }
            saml_name_id  = result.value().name_id;
            // Namespace hygiene: a malicious/misconfigured IdP could assert a
            // NameID inside the reserved `engine:` namespace. It would NOT
            // bypass RBAC (the engine gate keys on principal_kind, not the
            // prefix — this SAML session is principal_kind="human"), but it
            // would pollute the reserved namespace and mislead audit logs with
            // an engine-looking human session. Reject before minting.
            if (saml_name_id.starts_with("engine:")) {
                spdlog::warn("SAML login rejected: NameID is in the reserved 'engine:' namespace");
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}})
                        .increment();
                }
                res.set_header("Set-Cookie", kBindCookieClear);
                res.set_redirect("/login?error=saml");
                return;
            }

            // ADR-2001 PR4a — sanitise both NameID and entity_id BEFORE
            // either enters the stable principal (the durable RBAC/session
            // key) or the saml_identity_links store, mirroring
            // OidcProvider::validate_claims' sub/oid rule exactly. A
            // malformed value fails the login outright (fail-closed) rather
            // than being sanitised-and-continued — same posture OIDC takes
            // for the same class of durable-join-key input.
            if (!saml::is_valid_saml_component(saml_name_id) ||
                !saml::is_valid_saml_component(saml_entity_id)) {
                spdlog::warn("SAML login rejected: NameID or entity_id failed sanitation");
                audit_log(req, "auth.saml_login_failed", "error", {}, {},
                          "NameID or entity_id failed sanitation");
                emit_event("auth.saml_login_failed", req,
                           {{"source_ip", req.remote_addr},
                            {"error", "NameID or entity_id failed sanitation"}},
                           {}, Severity::kWarn);
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}})
                        .increment();
                }
                res.set_header("Set-Cookie", kBindCookieClear);
                res.set_redirect("/login?error=saml");
                return;
            }

            saml_principal = saml::saml_principal_id(saml_entity_id, saml_name_id);

            // ADR-2001 §4 (PR4b) — deny-at-login backstop, PRIMARY check.
            // Runs before every mutation below (link formation, session
            // mint) so a denied login leaves no side effect behind — a
            // deprovisioned SCIM user must not be able to re-authenticate
            // and mint a fresh session just by round-tripping the IdP
            // again. `saml_login_denied_deprovisioned` is fail-CLOSED: a
            // ScimStore that cannot answer denies, exactly like a
            // resolved-inactive link or a genuinely-orphaned (not
            // re-provisioned) one. Emits the BYTE-IDENTICAL
            // `/login?error=saml` redirect every other SAML failure branch
            // above uses — no "deprovisioned"/oracle wording reaches the
            // browser; the reason (and, when known, the driving scim_id —
            // server-generated CSPRNG hex, never IdP input, so no
            // sanitize_detail_value needed) lives only in the server-side
            // audit row. Mirrors the OIDC primary check's U6 fix: a
            // store-unavailable DENY (`scim_id` absent) is audited as
            // `scim_store_unavailable`, never as
            // `linked_scim_resource_inactive` — the latter is fictional
            // CC6.8 evidence when the store simply couldn't be asked.
            if (auto decision =
                    saml::saml_login_denied_deprovisioned(scim_store_, saml_entity_id, saml_name_id);
                decision.denied) {
                spdlog::warn("SAML login denied for '{}': linked SCIM resource is deprovisioned",
                            saml_principal);
                std::string deny_detail = decision.scim_id
                                              ? "reason=linked_scim_resource_inactive;scim_id=" +
                                                    *decision.scim_id
                                              : "reason=scim_store_unavailable";
                audit_log_for_principal(req, "auth.saml.deprovisioned_denied", "failure",
                                        saml_principal, "user", "User", saml_principal,
                                        deny_detail);
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_saml_deprovisioned_denied_total").increment();
                    // #3069 split: same predicate the audit `reason=`
                    // string above already switches on — see the OIDC
                    // primary check for the full rationale.
                    record_deprovision_deny_split(
                        m, "yuzu_auth_saml_deprovisioned_denied_genuine_total",
                        "yuzu_auth_saml_deprovisioned_denied_store_unavailable_total",
                        decision.scim_id.has_value());
                    // Also bump the established general SAML login counter
                    // so dashboards keyed on it don't undercount during a
                    // deny episode — every other /saml/acs failure path
                    // bumps this series too.
                    m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
                }
                res.set_header("Set-Cookie", kBindCookieClear);
                res.set_redirect("/login?error=saml");
                return;
            }

            // SAML fine-grained RBAC — parity with the OIDC block above
            // (`#1832`, ~2531-2634): reconcile the configured
            // `--saml-group-attribute`'s asserted values into the RBAC store
            // under source "saml" BEFORE minting the session, so a
            // provisioning failure denies the login outright (fail-closed)
            // instead of granting a session under stale/unreconciled roles.
            // Runs AFTER the PR4b primary deny check and BEFORE both link
            // formation and create_saml_session, so a reconcile-deny leaves
            // no link-write or session side effect behind.
            //
            // Only runs when `rbac_store_` is present AND a group attribute
            // is configured — otherwise this is a no-op and the coarse
            // `--saml-admin-group` role (create_saml_session, below) is the
            // only mechanism in play, exactly as before this change.
            //
            // SAML cannot distinguish "group attribute absent from the
            // assertion" from "attribute present, zero values" — both yield
            // an empty `result.value().groups`. Unlike OIDC (which has an
            // explicit `groups_claim_reconcilable` signal from the token),
            // reconciling an empty SAML group set would DELETE every one of
            // this user's `saml:`-sourced memberships (deprovision-to-zero),
            // so an empty asserted set is SKIPPED entirely — the SCIM
            // deprovision chokepoint (PR4a/PR4b above) remains the only full
            // deprovisioning path here.
            if (rbac_store_ && !cfg_.saml_group_attribute.empty()) {
                const auto& asserted_groups = result.value().groups;
                if (asserted_groups.empty()) {
                    spdlog::info("SAML group provisioning skipped for '{}': no groups asserted",
                                saml_principal);
                    audit_log_for_principal(
                        req, "auth.sso_group_provision", "skipped", saml_principal, "user", "User",
                        saml_principal, "reason=groups_absent;source=saml");
                    if (auto* m = auth_mgr_.metrics_registry()) {
                        m->counter("yuzu_auth_sso_group_provision_total",
                                  {{"source", "saml"}, {"result", "skipped"}})
                            .increment();
                    }
                } else if (result.value().group_cap_truncated) {
                    // Fail-closed: the verifier's `groups` vector is already
                    // a TRUNCATED view once the assertion carried more than
                    // `saml::kMaxGroupValues` (200) values — reconciling it
                    // would false-deprovision every membership beyond the
                    // cap. Deny the login instead, mirroring OIDC's
                    // group_count_exceeded branch.
                    spdlog::warn(
                        "SAML group provisioning denied for '{}': asserted groups exceeded cap {}",
                        saml_principal, saml::kMaxGroupValues);
                    audit_log_for_principal(
                        req, "auth.sso_group_provision", "error", saml_principal, "user", "User",
                        saml_principal, "reason=group_count_exceeded;source=saml");
                    audit_log_for_principal(
                        req, "auth.saml_login_failed", "error", saml_principal, "user", "User",
                        saml_principal, "reason=group_count_exceeded");
                    emit_event("auth.saml_login_failed", req,
                              {{"source_ip", req.remote_addr},
                               {"username", saml_principal},
                               {"error", "group_count_exceeded"}},
                              {}, Severity::kWarn);
                    if (auto* m = auth_mgr_.metrics_registry()) {
                        m->counter("yuzu_saml_group_cap_truncated_total").increment();
                        m->counter("yuzu_auth_sso_group_provision_total",
                                  {{"source", "saml"}, {"result", "error"}})
                            .increment();
                        m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
                    }
                    res.set_header("Set-Cookie", kBindCookieClear);
                    res.set_redirect("/login?error=saml");
                    return;
                } else {
                    std::vector<std::pair<std::string, std::string>> asserted;
                    asserted.reserve(asserted_groups.size());
                    for (const auto& gid : asserted_groups)
                        asserted.emplace_back(gid, gid);

                    auto reconciled =
                        rbac_store_->reconcile_idp_memberships(saml_principal, "saml", asserted);
                    if (!reconciled) {
                        spdlog::warn("SAML group provisioning failed for '{}': {}", saml_principal,
                                    reconciled.error());
                        audit_log_for_principal(
                            req, "auth.sso_group_provision", "error", saml_principal, "user",
                            "User", saml_principal,
                            "reason=" + reconciled.error() + ";source=saml");
                        audit_log_for_principal(
                            req, "auth.saml_login_failed", "error", saml_principal, "user", "User",
                            saml_principal, "reason=" + reconciled.error());
                        emit_event("auth.saml_login_failed", req,
                                  {{"source_ip", req.remote_addr},
                                   {"username", saml_principal},
                                   {"error", reconciled.error()}},
                                  {}, Severity::kWarn);
                        if (auto* m = auth_mgr_.metrics_registry()) {
                            m->counter("yuzu_auth_sso_group_provision_total",
                                      {{"source", "saml"}, {"result", "error"}})
                                .increment();
                            m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
                        }
                        res.set_header("Set-Cookie", kBindCookieClear);
                        res.set_redirect("/login?error=saml");
                        return;
                    }

                    // Mirrors OIDC's cons-S3: a no-op reconcile (nothing
                    // added or removed) writes no provisioning audit row —
                    // every login after the first steady-state one is
                    // typically a no-op.
                    if (reconciled->added + reconciled->removed > 0) {
                        audit_log_for_principal(
                            req, "auth.sso_group_provision", "ok", saml_principal, "user", "User",
                            saml_principal,
                            "source=saml;added=" + std::to_string(reconciled->added) +
                                ";removed=" + std::to_string(reconciled->removed));
                    }
                    if (auto* m = auth_mgr_.metrics_registry()) {
                        m->counter("yuzu_auth_sso_group_provision_total",
                                  {{"source", "saml"}, {"result", "ok"}})
                            .increment();
                    }
                }
            }

            // ADR-2001 PR4a — form a durable SCIM<->SAML identity link when
            // the NameID Format is stable (see saml_scim_link.hpp), BEFORE
            // minting the session. Fail-OPEN: never fails this login. No
            // AuthManager::mu_ is held across this ScimStore call (mint
            // happens next, after this returns).
            //
            // ADR-2001 #3072 — the typed outcome drives per-outcome
            // observability ONLY; every branch below still falls through to
            // create_saml_session — this is OBSERVE-AND-PROCEED, never a
            // deny (the PR4b deny-at-login backstop above is the only
            // SAML-side path that can refuse the login). `linked`/
            // `not_linkable`/`link_write_error` keep the pre-#3072 behaviour
            // (no new login-time audit row; `link_write_error` still bumps
            // the existing yuzu_scim_saml_link_write_failures_total inside
            // link_saml_login_to_scim itself).
            auto link_outcome =
                saml::link_saml_login_to_scim(scim_store_, saml_entity_id, saml_name_id,
                                              result.value().name_id_format,
                                              auth_mgr_.metrics_registry());
            switch (link_outcome) {
            case saml::SamlScimLinkOutcome::no_active_match:
                audit_log_for_principal(
                    req, "auth.saml.link_unmatched", "failure", saml_principal, "user", "User",
                    saml_principal,
                    "reason=no_active_external_id_match;name_id_format=" +
                        detail::sanitize_detail_value(result.value().name_id_format));
                if (auto* m = auth_mgr_.metrics_registry())
                    m->counter("yuzu_scim_saml_link_unmatched_total").increment();
                break;
            case saml::SamlScimLinkOutcome::ambiguous_match:
                // A SEPARATE counter from the plain-unmatched case above —
                // an ambiguous externalId (more than one active SCIM
                // resource sharing it) is a distinct, more actionable
                // misconfiguration than ordinary IdP/SCIM drift and must
                // stay distinguishable in metrics (task spec).
                audit_log_for_principal(
                    req, "auth.saml.link_unmatched", "failure", saml_principal, "user", "User",
                    saml_principal,
                    "reason=ambiguous_active_external_id_match;name_id_format=" +
                        detail::sanitize_detail_value(result.value().name_id_format));
                if (auto* m = auth_mgr_.metrics_registry())
                    m->counter("yuzu_scim_saml_link_ambiguous_total").increment();
                break;
            case saml::SamlScimLinkOutcome::lookup_store_error:
                audit_log_for_principal(req, "auth.saml.link_lookup_failed", "failure",
                                        saml_principal, "user", "User", saml_principal,
                                        "reason=scim_store_unavailable");
                if (auto* m = auth_mgr_.metrics_registry())
                    m->counter("yuzu_scim_saml_link_lookup_failures_total").increment();
                break;
            case saml::SamlScimLinkOutcome::linked:
            case saml::SamlScimLinkOutcome::not_linkable:
            case saml::SamlScimLinkOutcome::link_write_error:
                break; // existing behaviour — no new login-time audit row
            }

            session_token = auth_mgr_.create_saml_session(
                saml_name_id, saml_entity_id, result.value().groups, saml_admin_gid,
                result.value().display_name, result.value().email);

            // ADR-2001 §4 (PR4b) — deny-at-login backstop, POST-MINT
            // RE-CHECK (the codex-caught check-then-mint race, mirrors the
            // OIDC side). The primary check above ran before this login's
            // own mint; a concurrent SCIM deactivate/DELETE could have
            // landed in the window between that check and
            // `create_saml_session` above. Re-resolve the SAME decision via
            // the SAME helper and, if it has now flipped to DENY,
            // invalidate the session just minted rather than hand it out —
            // this self-heals the race without holding a cross-store lock
            // over the mint. Runs BEFORE the Set-Cookie header below so a
            // denied login never reaches the browser with a live cookie.
            // `saml_principal` is exactly the `username` `create_saml_session`
            // minted the session under (`saml::saml_principal_id(entity_id,
            // name_id)` — see `AuthManager::create_saml_session`), so it is
            // the correct key to invalidate.
            if (auto decision =
                    saml::saml_login_denied_deprovisioned(scim_store_, saml_entity_id, saml_name_id);
                decision.denied) {
                spdlog::warn("SAML login denied for '{}' on post-mint re-check: linked SCIM "
                            "resource is deprovisioned (concurrent deprovision race)",
                            saml_principal);
                auto revoke_result = auth_mgr_.invalidate_user_sessions(saml_principal);
                // Mirrors the OIDC side's U6 fix: a store-unavailable DENY
                // (`scim_id` absent) is audited as `scim_store_unavailable`,
                // never as `linked_scim_resource_inactive` (fictional
                // CC6.8 evidence on a mere outage) — mirrors the primary
                // check's reason string.
                std::string recheck_detail = decision.scim_id
                                                 ? "reason=linked_scim_resource_inactive;scim_id=" +
                                                       *decision.scim_id
                                                 : "reason=scim_store_unavailable";
                recheck_detail += ";post_mint_recheck=true;sessions_invalidated=" +
                                  std::to_string(revoke_result.count);
                if (!revoke_result.db_persisted) {
                    // RevokeResult's contract (auth.hpp): a "success" audit
                    // row that hides a DB persistence failure produces
                    // fictional CC6.3/CC6.6 evidence — surface it in the
                    // row itself.
                    recheck_detail += ";db_persisted=false";
                }
                audit_log_for_principal(req, "auth.saml.deprovisioned_denied", "failure",
                                        saml_principal, "user", "User", saml_principal,
                                        recheck_detail);
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_saml_deprovisioned_denied_total").increment();
                    // #3069 split — see the primary check above; same
                    // `decision.scim_id` predicate the recheck's `reason=`
                    // string already switches on.
                    record_deprovision_deny_split(
                        m, "yuzu_auth_saml_deprovisioned_denied_genuine_total",
                        "yuzu_auth_saml_deprovisioned_denied_store_unavailable_total",
                        decision.scim_id.has_value());
                    // Also bump the established general SAML login counter
                    // — see the primary check above.
                    m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
                }
                res.set_header("Set-Cookie", kBindCookieClear);
                res.set_redirect("/login?error=saml");
                return;
            }

            // #1828.3: the verifier flags (rather than logs or increments
            // directly — it has no metrics handle) when the assertion's
            // group-attribute values exceeded the `saml::kMaxGroupValues`
            // (200) cap. Bump the counter here, once per login, not a
            // per-value/per-login log line (anti-flood — same rationale as
            // the sibling metric-only signals in
            // docs/observability-conventions.md). Reached ONLY when the
            // fine-grained reconcile block above did NOT already deny this
            // login for the same reason (`rbac_store_` absent, or
            // `--saml-group-attribute` unconfigured) — a truncated assertion
            // under an active reconcile is denied before session mint and
            // never reaches this point.
            if (result.value().group_cap_truncated) {
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_saml_group_cap_truncated_total").increment();
                }
            }
        } catch (const std::exception& e) {
            spdlog::error("SAML ACS: internal error during validation/session: {}", e.what());
            audit_log(req, "auth.saml_login_failed", "error", {}, {}, "internal error");
            emit_event("auth.saml_login_failed", req,
                       {{"source_ip", req.remote_addr}, {"error", "internal error"}}, {},
                       Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}).increment();
            }
            res.set_header("Set-Cookie", kBindCookieClear);
            res.set_redirect("/login?error=saml");
            return;
        }

        // Clear the binding cookie now that the round-trip is complete.
        res.set_header("Set-Cookie", kBindCookieClear);
        res.set_header("Set-Cookie", "yuzu_session=" + session_token + session_cookie_attrs());

        // Explicit-principal audit row — request lands at /saml/acs with no session
        // cookie yet, so the default resolve_session path would leave principal empty
        // (same rationale as the OIDC /auth/callback audit, Gate 4 consistency B3).
        // Re-validate the freshly-minted session (mirrors the OIDC /auth/callback
        // pattern) to capture the RESOLVED role — group-mapping may have made this
        // login an admin — rather than hard-coding "user" and hiding an admin SAML
        // login from the audit trail.
        auto saml_effective_role = auth_mgr_.validate_session(session_token)
                                       .transform([](const auth::Session& s) {
                                           return auth::role_to_string(s.role);
                                       })
                                       .value_or(std::string{"user"});
        // comp-S1 / UP-5: when the login resolved to admin, name the granting
        // group in the audit detail so a reviewer can see WHY this SAML login
        // is admin without cross-referencing boot flags. Matching is exact
        // against the single configured saml_admin_gid, so there is exactly
        // one candidate group to log — no ambiguity about which of possibly
        // several assertion groups triggered the promotion.
        // ADR-2001 PR4a — mirror the OIDC audit pattern exactly (auth.oidc_
        // login above): the STABLE `saml_principal` is the audit KEY
        // (never sanitized — it is not a detail value), the raw NameID is
        // carried in `detail` via sanitize_detail_value (a control/newline
        // byte there is an audit-log injection/readability hazard, same
        // rationale as OIDC's display/email handling).
        auto saml_audit_detail =
            std::string("auth_source=saml;name_id=") + detail::sanitize_detail_value(saml_name_id);
        if (saml_effective_role == auth::role_to_string(auth::Role::admin)) {
            saml_audit_detail += ";admin_group=" + saml_admin_gid;
        }
        audit_log_for_principal(req, "auth.saml_login", "ok", saml_principal, saml_effective_role,
                                "User", saml_principal, saml_audit_detail);
        emit_event("auth.saml_login", req,
                   {{"source_ip", req.remote_addr},
                    {"username", saml_principal},
                    {"auth_method", "saml"},
                    {"name_id", detail::sanitize_detail_value(saml_name_id)}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            // #1828.1: role label lets a SIEM/Grafana query distinguish admin
            // vs user SSO logins without joining against the audit store —
            // sourced from the same saml_effective_role already resolved for
            // the audit row above, never re-derived.
            m->counter("yuzu_auth_saml_login_total",
                       {{"result", "ok"}, {"role", saml_effective_role}})
                .increment();
        }

        // RelayState open-redirect safety: only accept same-origin relative paths.
        // Reject:
        //   - protocol-relative paths  ("//evil.com")
        //   - backslash-second-char    ("/\evil.com" — browsers normalize '\' → '/')
        //   - values containing '\'    (anywhere — same normalization risk)
        //   - values containing control characters (tab, newline, CR, <0x20 — header injection)
        //   - any byte ≥ 0x80 (non-ASCII — kills fullwidth/Unicode slash lookalikes
        //     such as U+FF0F FULLWIDTH SOLIDUS which browsers may canonicalize to '/')
        //   - any ".." path segment (H-D: url_decode runs before this check, so
        //     "/%2e%2e/admin" → "/../admin" → rejected here)
        auto is_safe_relay_state = [](const std::string& rs) -> bool {
            if (rs.empty() || rs[0] != '/') return false;
            if (rs.size() >= 2 && (rs[1] == '/' || rs[1] == '\\')) return false;
            for (unsigned char c : rs) {
                if (c < 0x20 || c >= 0x80 || c == '\\') return false;
            }
            // Reject any ".." path segment (prevents path traversal after url_decode).
            {
                std::size_t p = 1; // skip leading '/'
                while (p <= rs.size()) {
                    const auto slash = rs.find('/', p);
                    const auto seg_end = (slash == std::string::npos) ? rs.size() : slash;
                    if (rs.compare(p, seg_end - p, "..") == 0) return false;
                    if (slash == std::string::npos) break;
                    p = slash + 1;
                }
            }
            return true;
        };
        auto target = is_safe_relay_state(relay_state) ? relay_state : std::string{"/"};
        res.set_redirect(target);
    });

    // ── JIT admin elevation (SOC 2 CC6.3/CC6.6) — /auth-and-authz P1 #9 ───────
    // A pre-authorized (users.elevation_eligible) operator activates a
    // time-boxed, justified, MFA-gated admin elevation on their COOKIE session;
    // effective_role() then treats the session as admin for the window and it
    // auto-reverts. See docs/auth-architecture.md "JIT admin elevation".

    // Shared step-up gate: elevating to admin and granting eligibility are both
    // high-risk and require a fresh MFA proof (reuses require_mfa_step_up).
    // window_secs lets the elevation path force a positive step-up window even
    // when the operator has globally disabled step-up (--mfa-step-up-window-secs
    // <= 0): elevation is the privilege boundary, so it ALWAYS requires a fresh
    // proof, never honouring that escape hatch (Hermes pass-1 #3).
    auto elevation_step_up = [this](const httplib::Request& req, httplib::Response& res,
                                    const auth::Session& session, const std::string& label,
                                    int window_secs) -> bool {
        auto* db = auth_mgr_.auth_db_ptr();
        if (!db)
            return true; // legacy config-file-only: step-up needs auth.db (fail-open, as elsewhere)
        return require_mfa_step_up(
            req, res, session, *db, window_secs,
            [this](const httplib::Request& r, const std::string& a, const std::string& rs,
                   const std::string& tt, const std::string& ti, const std::string& d) {
                return audit_log(r, a, rs, tt, ti, d);
            },
            label, cfg_.mfa_enforcement, auth_mgr_.metrics_registry());
    };
    // Step-up window for the elevation surfaces: the global window when it is
    // positive, else 300 s. So disabling the global gate (<= 0) does not disable
    // it here, and the privilege boundary keeps a fresh-proof check. A positive
    // window below 300 is used as-is; this substitutes, it does not floor.
    const int kElevationStepUpWindow =
        cfg_.mfa_step_up_window_secs > 0 ? cfg_.mfa_step_up_window_secs : 300;

    // POST /api/v1/users/<name>/elevation-eligibility — admin grants/revokes who
    // may elevate. Body: {"eligible": <bool>}. Admin + step-up gated.
    //
    // Registered on TWO route forms (both bound to the same handler below):
    //   - /api/v1/users/([^/]+)/elevation-eligibility  — path-segment form, for
    //     local usernames.
    //   - /api/v1/users/elevation-eligibility?username=<principal> — query form,
    //     REQUIRED for a durable SSO principal (`oidc:<iss>#<sub>`). httplib
    //     percent-decodes the path (%2F -> '/', %23 -> '#') and strips the
    //     literal '#' fragment BEFORE route-regex matching, so a `([^/]+)`
    //     path segment can never carry the '/' and '#' an SSO principal
    //     contains — that route 404s for every real IdP identity. The query
    //     form mirrors the proven `DELETE /api/v1/sessions?username=` pattern.
    auto set_elevation_eligibility = [this, elevation_step_up, kElevationStepUpWindow](
                                         const httplib::Request& req, httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        // Inline A4 admin gate (#1748 H3): a new REST route must carry the
        // A4 envelope on its denial path, not require_admin's legacy
        // {"error":{code,message}} body. Replicates require_admin's
        // token-type guards + role check, but gates on effective_role
        // (so an active elevation passes) and audits `auth.admin_required`.
        auto session = resolve_session(req);
        if (!session) {
            res.status = 401;
            res.set_content(detail::a4_denial(res, 401, "unauthorized"), "application/json");
            return;
        }
        if (!session->token_scope_service.empty() || !session->mcp_tier.empty()) {
            audit_log(req, "auth.admin_required", "denied", "endpoint", req.path,
                      "non-interactive token blocked from admin route");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "non-interactive tokens cannot "
                                                       "perform admin operations",
                                                  cid),
                            "application/json");
            return;
        }
        if (auth::effective_role(*session) != auth::Role::admin) {
            audit_log(req, "auth.admin_required", "denied", "endpoint", req.path);
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "admin role required", cid,
                                                  "elevate via POST /api/v1/elevate, or use "
                                                  "an admin account"),
                            "application/json");
            return;
        }
        if (!elevation_step_up(req, res, *session,
                               "POST /api/v1/users/{name}/elevation-eligibility",
                               kElevationStepUpWindow))
            return;
        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 503;
            res.set_content(detail::error_json_a4(503, "JIT elevation requires the "
                                                       "persistent auth store",
                                                  cid, "start the server with --data-dir"),
                            "application/json");
            return;
        }
        // Path-segment form (local usernames) OR query form (SSO
        // principals — see the route-registration comment above for
        // why a path segment can't carry the '/' and '#' of an
        // `oidc:<iss>#<sub>` principal).
        const std::string target = (req.matches.size() > 1 && req.matches[1].matched)
                                        ? req.matches[1].str()
                                        : req.get_param_value("username");
        // #1852 — `target` may be a durable SSO principal
        // (`oidc:<iss>#<sub>`); an admin must be able to grant
        // elevation eligibility to an SSO operator, not just a
        // local account. `is_valid_principal` is a strict
        // superset of `is_valid_username`, so local-target
        // behaviour is unchanged.
        if (target.empty() || !is_valid_principal(target)) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "invalid username format", cid,
                                                  "username must match the allowed format"),
                            "application/json");
            return;
        }
        // Block self-grant (review UP-6 / security-LOW): an operator —
        // including one acting under an active elevation — must not set
        // their OWN eligibility, which would let a temporary admin
        // window manufacture a durable self-elevation right. Eligibility
        // is always granted by another admin.
        if (target == session->username) {
            audit_log(req, "user.elevation_eligibility.set", "denied", "User", target,
                      "self_grant_blocked");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "cannot change your own elevation "
                                                       "eligibility",
                                                  cid, "another administrator must set it"),
                            "application/json");
            return;
        }
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (!body.is_object() || !body.contains("eligible") ||
            !body["eligible"].is_boolean()) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "body must be {\"eligible\": bool}",
                                                  cid),
                            "application/json");
            return;
        }
        const bool eligible = body["eligible"].get<bool>();
        if (auto r = db->set_elevation_eligible(target, eligible); !r) {
            const auto err = r.error();
            const int code = err == AuthDBError::UserNotFound ? 404 : 500;
            audit_log(req, "user.elevation_eligibility.set", "error", "User", target,
                      "store error");
            res.status = code;
            res.set_content(detail::error_json_a4(code,
                                                  code == 404 ? "user not found"
                                                              : "failed to update",
                                                  cid),
                            "application/json");
            return;
        }
        // Revoking eligibility must terminate any in-flight elevation
        // immediately (governance UP-1) — symmetric with the session
        // wipe on demote/delete, so an incident-response "revoke now"
        // actually drops the operator's admin access rather than
        // leaving it standing for up to the window.
        int cleared = 0;
        if (!eligible) {
            auto rv = auth_mgr_.revoke_user_elevations(target);
            if (!rv) {
                // The eligibility flag persisted, but clearing the in-flight
                // elevation failed durably — the "revoke now" is NOT complete, an
                // active admin elevation may still be live. Fail CLOSED (503 +
                // error audit) rather than a false "ok" that tells an incident
                // responder the access was dropped (adversarial C2). The
                // eligibility flip is durable, so a retry re-runs only the clear.
                spdlog::error("elevation-eligibility: durable elevation clear failed for '{}': {}",
                              target, rv.error());
                audit_log(req, "user.elevation_eligibility.set", "error", "User", target,
                          "eligible=false elevation_clear_failed=true detail=" + rv.error());
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503,
                                          "eligibility updated but active elevations could not be "
                                          "cleared; retry to complete the revocation",
                                          cid),
                    "application/json");
                return;
            }
            cleared = *rv;
        }
        audit_log(req, "user.elevation_eligibility.set", "ok", "User", target,
                  std::string(eligible ? "eligible=true" : "eligible=false") +
                      (cleared > 0 ? " elevations_cleared=" + std::to_string(cleared) : ""));
        res.set_content(R"({"status":"ok"})", "application/json");
    };
    // Path form: local usernames.
    sink.Post(R"(/api/v1/users/([^/]+)/elevation-eligibility)", set_elevation_eligibility);
    // Query form: required for SSO principals (`?username=oidc:<iss>#<sub>`,
    // percent-encoded). The two patterns don't collide — this fixed path has
    // exactly two segments after /api/v1/users, the path-param pattern
    // requires three.
    sink.Post(R"(/api/v1/users/elevation-eligibility)", set_elevation_eligibility);

    // POST /api/v1/elevate — activate a time-boxed admin elevation on THIS cookie
    // session. Body: {"justification": <str, required>, "duration_secs": <int>}.
    sink.Post("/api/v1/elevate", [this, elevation_step_up,
                                   kElevationStepUpWindow](const httplib::Request& req,
                                                           httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        // Elevation is COOKIE-session only — an API/MCP token cannot elevate
        // (it carries no cookie, and elevate_session keys on the cookie token).
        auto token = extract_session_cookie(req);
        if (token.empty()) {
            res.status = 401;
            res.set_content(detail::error_json_a4(401, "elevation requires an interactive session",
                                                  cid, "sign in to the dashboard, then elevate"),
                            "application/json");
            return;
        }
        auto session = auth_mgr_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(detail::a4_denial(res, 401, "unauthorized"), "application/json");
            return;
        }
        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 503;
            res.set_content(detail::error_json_a4(503, "JIT elevation requires the persistent auth "
                                                       "store",
                                                  cid, "start the server with --data-dir"),
                            "application/json");
            return;
        }
        // Eligibility (fail-closed): a store read error denies.
        auto elig = db->is_elevation_eligible(session->username);
        if (!elig || !*elig) {
            audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                    auth::role_to_string(session->role), "User", session->username,
                                    elig ? "not eligible" : "eligibility read failed");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "not authorized to elevate", cid,
                                                  "ask an administrator to grant you elevation "
                                                  "eligibility"),
                            "application/json");
            return;
        }
        // governance round (UP-6/UP-7/cons-N2) — source-scope the eligibility
        // grant: `is_elevation_eligible` above keyed on the raw principal
        // STRING alone, so a session whose principal happens to collide
        // with an eligible row's username (a crafted SAML NameID equal to
        // `oidc:<iss>#<sub>`, or a legacy `identity_source='local'` row
        // literally named `oidc:x#y` that somehow has
        // `elevation_eligible=1`) would otherwise borrow that row's grant.
        // Require the row's `identity_source` to MATCH the session's own
        // `auth_source`: an OIDC session may only elevate an
        // `identity_source='oidc'` row; every other session (local,
        // and — until SAML provisioning exists — saml) requires
        // `identity_source='local'`. Read fresh via `get_user` rather than
        // trusting anything cached on `session` (SQLite is the source of
        // truth for identity_source).
        auto row = db->get_user(session->username);
        if (!row) {
            audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                    auth::role_to_string(session->role), "User", session->username,
                                    "identity-source lookup failed");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "not authorized to elevate", cid), "application/json");
            return;
        }
        // The eligible row's `identity_source` must equal the session's own
        // `auth_source` — a DIRECT mapping (`local`↔`local`, `oidc`↔`oidc`,
        // `saml`↔`saml`), NOT "oidc-or-else-local". A SAML session therefore
        // expects `identity_source=="saml"`, which no row carries today (SAML
        // is not provisioned — #1852 fast-follow), so SAML is fail-closed at
        // this gate; and a SAML NameID crafted to collide with a `local` (or
        // `oidc`) row can no longer satisfy it. This keeps the guard correct
        // when SAML provisioning + SAML-MFA land, without a rework (Hermes
        // cyber-review finding, #1852 hardening).
        //
        // An `engine_token` session (design doc §6/§9) never reaches this
        // comparison at all: `POST /api/v1/elevate` is COOKIE-session only
        // (see the `extract_session_cookie`/`validate_session` gate above —
        // an engine session is synthesized fresh per bearer request and is
        // never placed in the cookie `sessions_` map). If that structural
        // gate were ever bypassed, `db->get_user(session->username)` for an
        // `engine:<slug>` username would still fail (`!row`, no `users` row)
        // and deny at the branch above. Belt-and-braces default-deny, both
        // intended.
        const std::string& expected_identity_source = session->auth_source;
        if (row->identity_source != expected_identity_source) {
            audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                    auth::role_to_string(session->role), "User", session->username,
                                    "identity-source mismatch");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "not authorized to elevate", cid), "application/json");
            return;
        }
        // MFA is MANDATORY to elevate (review #JIT security-F1). Elevation is the
        // privilege-crossing boundary (non-admin → full admin), so — UNLIKE the
        // other step-up sites where the actor is already admin — a second factor
        // is required unconditionally, NOT gated on --mfa-enforcement.
        //
        // OIDC-amr follow-up (docs/security-reviews/jit-elevation-2026-06-30.md):
        // an OIDC session whose IdP login attested MFA via the `amr` claim
        // already carries a seeded `Session::mfa_verified_at` (set at
        // /auth/callback via amr_asserts_mfa). That proof satisfies "a second
        // factor" in place of local TOTP enrollment.
        //
        // LOAD-BEARING: the two identity sources are handled by DISJOINT
        // branches, not a single "skip the local check" flag. An OIDC session
        // must NEVER fall through to the local `mfa_status` lookup — a local
        // *namesake* account (same username, different identity) might be
        // TOTP-enrolled, and passing that check for an OIDC caller would grant
        // elevation on a factor the OIDC caller never actually presented
        // (security-F1 / hardening-round S-2). This seam is the ONLY place
        // that unconditionally blocks a single-factor (no-amr) OIDC session
        // from elevating — require_mfa_step_up's own no-proof-OIDC branch can
        // PASS a request through when --mfa-enforcement doesn't protect the
        // role (e.g. "optional"), so the decision must not be deferred there.
        //
        // As with the identity-source comparison above, an `engine_token`
        // session cannot reach this code (cookie-session-only route,
        // enforced structurally, plus the `!row` deny two branches up). Were
        // it ever to arrive here, `session->auth_source == "oidc"` is false
        // for "engine_token", so it takes the local-session `else` branch
        // below (line ~2840), which requires local TOTP enrollment the
        // engine principal's non-existent `users` row can never satisfy —
        // denied either way.
        const bool oidc_amr_proof = session->auth_source == "oidc" &&
                                    session->mfa_verified_at.time_since_epoch().count() != 0;
        const bool oidc_amr_elevation = cfg_.jit_oidc_amr_elevation && oidc_amr_proof;
        if (session->auth_source == "oidc") {
            // An OIDC session's ONLY acceptable second factor is a seeded amr
            // proof (IdP-attested MFA) with the toggle on. There is no way for
            // an OIDC session to present a local TOTP step-up (its step-up is
            // re-SSO, not a TOTP code), so toggle-off means OIDC sessions
            // cannot elevate at all, not "fall back to local TOTP".
            if (!oidc_amr_elevation) {
                const char* reason =
                    cfg_.jit_oidc_amr_elevation
                        ? "no MFA in SSO login (the IdP did not assert amr MFA) — "
                          "re-authenticate via your IdP with MFA"
                        : "OIDC-amr elevation is disabled (--no-jit-oidc-amr-elevation); "
                          "elevate from a local session with TOTP";
                audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                        auth::role_to_string(session->role), "User", session->username,
                                        reason);
                res.status = 403;
                res.set_content(detail::error_json_a4(403, "elevation requires a second factor", cid,
                                                      reason),
                                "application/json");
                return;
            }
            // Fall through to elevation_step_up below (freshness check on the
            // amr-seeded proof).
        } else {
            // Local session: mandatory local TOTP enrollment (unchanged). An
            // eligible operator with no TOTP enrolled is refused here
            // (require_mfa_step_up would otherwise pass them through under the
            // default optional mode). ★ SECURITY (architect BLOCK): a
            // store/decrypt failure (SecretUnavailable/QueryFailed) is
            // ALREADY a deny here (elevation is refused either way, never
            // granted on error) — but it must be a distinct fail-closed 503,
            // not conflated with the genuine "not enrolled, go enroll" 403,
            // so an operator/SIEM can tell "MFA store is down" from
            // "this account has no MFA".
            auto st = db->mfa_status(session->username);
            if (!st && is_store_unavailable(st.error())) {
                audit_log_for_principal(req, "role.elevation.denied", "error", session->username,
                                        auth::role_to_string(session->role), "User", session->username,
                                        "mfa_status: secret/store unavailable (fail-closed)");
                res.status = 503;
                res.set_content(detail::error_json_a4(503, "authentication store is temporarily "
                                                           "unavailable",
                                                      cid),
                                "application/json");
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_secret_unavailable_total", {{"route", "elevate"}})
                        .increment();
                }
                return;
            }
            if (!st || !st->enrolled) {
                audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                        auth::role_to_string(session->role), "User", session->username,
                                        "no MFA enrolled (a second factor is required to elevate)");
                res.status = 403;
                res.set_content(detail::error_json_a4(403, "elevation requires an enrolled second factor",
                                                      cid, "enroll MFA (Settings -> Multi-Factor "
                                                           "Authentication) before you can elevate"),
                                "application/json");
                return;
            }
        }
        // High-risk: require a fresh MFA proof (step-up) before granting admin.
        // kElevationStepUpWindow (the global window when positive, else 300 s) so
        // a globally-disabled gate can't skip the proof for the privilege boundary.
        if (!elevation_step_up(req, res, *session, "POST /api/v1/elevate",
                               kElevationStepUpWindow)) {
            // The shared gate set the 401 challenge + audited mfa.step_up; add the
            // elevation-specific denial so the role.elevation.* trail is complete
            // (Hermes pass-1 #4).
            audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                    auth::role_to_string(session->role), "User", session->username,
                                    "mfa_step_up_refused");
            return;
        }
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        // Type-guard the fields: a present-but-wrong-type value would otherwise
        // throw nlohmann type_error.302 → httplib 500 (review UP-2/cpp-safety).
        if (body.is_object() &&
            ((body.contains("justification") && !body["justification"].is_string()) ||
             (body.contains("duration_secs") && !body["duration_secs"].is_number_integer()))) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "justification must be a string and "
                                                       "duration_secs an integer",
                                                  cid),
                            "application/json");
            return;
        }
        std::string justification =
            body.is_object() ? body.value("justification", std::string{}) : std::string{};
        // Justification is mandatory (the auditable reason). Sanitise control
        // bytes incl. DEL (anti log-injection) and cap length (anti audit-row
        // bloat).
        for (char& c : justification)
            if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) == 0x7F)
                c = ' ';
        // trim surrounding whitespace for the empty-check
        auto first = justification.find_first_not_of(' ');
        if (first == std::string::npos) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "justification is required", cid,
                                                  "include a non-empty \"justification\""),
                            "application/json");
            return;
        }
        if (justification.size() > kMaxJustificationLength) {
            justification.resize(kMaxJustificationLength);
            // Back up to a UTF-8 code-point boundary so the audit detail never
            // ends mid-sequence (#1748 L2). Walk back over continuation bytes
            // (0x80-0xBF) to the lead byte; if the lead byte's declared length
            // overruns the truncated end, drop that partial code point.
            std::size_t i = justification.size();
            while (i > 0 && (static_cast<unsigned char>(justification[i - 1]) & 0xC0) == 0x80)
                --i;
            if (i > 0) {
                const unsigned char lead = static_cast<unsigned char>(justification[i - 1]);
                const std::size_t seq_len =
                    lead < 0x80 ? 1 : lead < 0xE0 ? 2 : lead < 0xF0 ? 3 : 4;
                if (justification.size() - (i - 1) < seq_len)
                    justification.resize(i - 1);
            }
        }
        // Read as int64 first: a JSON integer > INT_MAX passes is_number_integer()
        // but get<int>() would THROW (→ 500). Range-check in 64-bit, then narrow
        // (Hermes pass-1 #1).
        std::int64_t raw_duration = body.is_object() ? body.value("duration_secs", std::int64_t{0})
                                                     : std::int64_t{0};
        // An explicit NEGATIVE duration is a client error, not "give me the max"
        // (review UP-5 least-privilege). Absent or 0 defaults to the cap.
        if (raw_duration < 0) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "duration_secs must be positive", cid),
                            "application/json");
            return;
        }
        int duration = (raw_duration == 0 || raw_duration > cfg_.jit_max_elevation_secs)
                           ? cfg_.jit_max_elevation_secs // unspecified → cap; over-cap → clamp
                           : static_cast<int>(raw_duration);
        // TOCTOU re-check (Hermes pass-1 #2 / unhappy-path UP-1): eligibility was
        // read before the human-time MFA step-up. Re-verify it immediately before
        // granting so an admin who revoked eligibility mid-step-up wins the race.
        if (auto re = db->is_elevation_eligible(session->username); !re || !*re) {
            audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                    auth::role_to_string(session->role), "User", session->username,
                                    "eligibility revoked during step-up");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "not authorized to elevate", cid), "application/json");
            return;
        }
        auto until = auth_mgr_.elevate_session(token, std::chrono::seconds(duration));
        if (!until) {
            res.status = 401; // session vanished between validate and elevate
            res.set_content(detail::a4_denial(res, 401, "unauthorized"), "application/json");
            return;
        }
        // `until` may be CLAMPED to the session's own absolute expiry
        // (follow-up B, security review 2026-06-30) — report the TRUE
        // remaining time, not the requested/capped `duration`. A live window
        // is CEIL'd (never floor/truncated) — duration_cast truncates toward
        // zero, so a genuinely-live sub-second remainder (e.g. duration_secs:1
        // re-sampled a moment later) would falsely report 0 across all three
        // channels (HIGH, adversarial review). Only a non-live/edge window
        // (until <= now) floors to 0.
        const auto elevate_now = std::chrono::system_clock::now();
        auto remaining = (*until > elevate_now)
                              ? std::chrono::ceil<std::chrono::seconds>(*until - elevate_now)
                              : std::chrono::seconds(0);
        // `*until` is an absolute wall-clock instant since HA WS-1/1a (durable
        // session, ADR-2002 §4), so it reports directly — no steady→system
        // projection needed. iso8601_utc formats the true (post-clamp) expiry.
        const std::string expires_at_str = iso8601_utc(*until);
        // FAIL-CLOSED on the mandatory grant audit (review UP-3): a privileged
        // activation must never stand without a durable record. If the audit row
        // can't persist, ROLL BACK the elevation (compensating revoke, mirrors
        // the break-glass arm) and 500 with Sec-Audit-Failed — rather than leave
        // a silent admin window.
        // Stamp the factor source (oidc_amr vs local_totp, PR #1799) so access
        // reviews can tell an IdP-MFA'd elevation apart from a locally-enrolled
        // one, and carry the TRUE post-clamp window + absolute expires_at (PR
        // #1792). duration_secs is remaining.count() — the post-clamp value the
        // analytics event and JSON response also use — NOT the requested/capped
        // `duration`, so all three channels agree even when the window was
        // clamped to the session's own absolute expiry (evidence integrity,
        // docs/auth-architecture.md:238-240).
        //
        // Field ordering is load-bearing: BOTH machine-parsed tokens (`mfa=` and
        // `expires_at=`) precede the operator free-text `justification=` (only
        // control-bytes sanitised), so a crafted justification (e.g.
        // "x mfa=local_totp") cannot forge either token that access reviews and
        // tests grep for (hardening-round consistency S-3).
        const char* mfa_factor_label = oidc_amr_elevation ? "oidc_amr" : "local_totp";
        if (!audit_log_for_principal(req, "role.elevation.granted", "ok", session->username, "admin",
                                     "User", session->username,
                                     "duration_secs=" + std::to_string(remaining.count()) +
                                         " mfa=" + mfa_factor_label +
                                         " expires_at=" + expires_at_str +
                                         " justification=" + justification)) {
            auto rollback = auth_mgr_.revoke_elevation(token); // un-elevate — no record, no grant
            if (!rollback) {
                // The compensating revoke itself failed durably: the elevation is
                // LIVE AND UNRECORDED — the worst state. Do not claim "not
                // granted"; escalate loudly (CRITICAL) so an operator manually
                // revokes, and still fail the request (adversarial C2).
                spdlog::critical("role.elevation.granted audit FAILED for '{}' AND the compensating "
                                 "revoke ALSO FAILED ({}) — elevation is LIVE and UNRECORDED; "
                                 "manual revocation required",
                                 session->username, rollback.error());
                res.status = 500;
                res.set_header("Sec-Audit-Failed", "true");
                res.set_content(
                    detail::error_json_a4(500,
                                          "elevation could neither be recorded nor rolled back; it "
                                          "may be active — revoke it manually and check the stores",
                                          cid, "revoke manually; check the audit + session stores"),
                    "application/json");
                return;
            }
            spdlog::error("role.elevation.granted audit FAILED for '{}' — elevation rolled back",
                          session->username);
            res.status = 500;
            res.set_header("Sec-Audit-Failed", "true");
            res.set_content(detail::error_json_a4(500, "could not record the elevation; not granted",
                                                  cid, "retry; if it persists, check the audit store"),
                            "application/json");
            return;
        }
        // duration_secs here is remaining.count() (the true post-clamp value),
        // not the requested/capped `duration` — matches the audit row and the
        // JSON response so all three channels agree (governance hardening
        // round, consistency). With the ceil above, a live window is always
        // >= 1 (never truncated to 0); only the dead-window edge case is 0.
        // expires_at is carried too (L2, adversarial review) so this channel
        // matches the audit row and the JSON response (docs/auth-architecture.md:238-240).
        emit_event("role.elevation.granted", req,
                   {{"username", session->username},
                    {"duration_secs", std::to_string(remaining.count())},
                    {"expires_at", expires_at_str}},
                   {}, Severity::kWarn);
        nlohmann::json out = {
            {"status", "ok"}, {"expires_in", remaining.count()}, {"expires_at", expires_at_str}};
        res.set_content(out.dump(), "application/json");
    });

    // POST /api/v1/elevate/revoke — manual step-down (clear an active elevation).
    sink.Post("/api/v1/elevate/revoke",
              [this](const httplib::Request& req, httplib::Response& res) {
                  res.set_header("X-Correlation-Id", detail::make_correlation_id());
                  auto token = extract_session_cookie(req);
                  if (token.empty()) {
                      res.status = 401;
                      res.set_content(detail::a4_denial(res, 401, "unauthorized"), "application/json");
                      return;
                  }
                  auto session = auth_mgr_.validate_session(token);
                  if (!session) {
                      res.status = 401;
                      res.set_content(detail::a4_denial(res, 401, "unauthorized"), "application/json");
                      return;
                  }
                  auto rev = auth_mgr_.revoke_elevation(token);
                  if (!rev) {
                      // Durable clear failed — the elevation may still be LIVE.
                      // Fail CLOSED (503 + error audit) rather than auditing a
                      // false `role.elevation.revoked ok` (adversarial C2).
                      spdlog::error("elevate/revoke: durable clear failed for '{}': {}",
                                    session->username, rev.error());
                      audit_log_for_principal(req, "role.elevation.revoked", "error",
                                              session->username,
                                              auth::role_to_string(session->role), "User",
                                              session->username,
                                              "durable_clear_failed=true detail=" + rev.error());
                      res.status = 503;
                      res.set_content(
                          detail::a4_denial(res, 503, "could not revoke the elevation; retry"),
                          "application/json");
                      return;
                  }
                  const bool was_elevated = *rev;
                  audit_log_for_principal(req, "role.elevation.revoked", "ok", session->username,
                                          auth::role_to_string(session->role), "User",
                                          session->username,
                                          was_elevated ? "was_elevated=true" : "was_elevated=false");
                  res.set_content(R"({"status":"ok"})", "application/json");
              });
}

} // namespace yuzu::server
