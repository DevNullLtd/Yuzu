#pragma once

/**
 * saml_provider.hpp — SAML 2.0 SP core verifier library
 *
 * Thread-safe. On Windows, all methods are stubs that return disabled/error
 * (Non-Negotiable #4 — never return success-without-verify on any platform).
 *
 * Security invariants enforced by this library (all 4 non-negotiables):
 *   N1: Signature verified against PINNED IdP cert only. In-document KeyInfo
 *       is IGNORED entirely (dsigCtx->signKey set directly before verify —
 *       bypasses key discovery from the document).
 *   N2: XSW (signature-wrapping) binding: document must contain exactly one
 *       <saml:Assertion>; the verified Reference URI must be "#<that assertion's
 *       ID>"; NameID/Conditions are read ONLY from the verified assertion node.
 *   N3: Full condition validation: Status/Success, NotBefore/NotOnOrAfter,
 *       AudienceRestriction, SubjectConfirmationData Recipient + NotOnOrAfter +
 *       InResponseTo (tracked, consumed on use, replay-protected).
 *   N4: Windows compile-time stubs — is_enabled()→false,
 *       validate_response()→std::unexpected, build_authn_request()→"".
 */

#include <openssl/evp.h> // EVP_PKEY — OpenSSL is a mandatory dep on every platform (CLAUDE.md)

#include <chrono>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::saml {

/// DoS guard on <AttributeStatement> parsing: at most this many group values
/// are extracted from the configured group_attribute, across however many
/// <Attribute Name="..."> elements carry that Name. Parsing stops once the
/// cap is reached — remaining values (and remaining Attribute elements) are
/// silently ignored rather than rejecting the whole assertion. Aligned with
/// `RbacStore::kMaxIdpGroupsPerLogin` (200) — SAML fine-grained RBAC
/// reconciles `groups` into the RBAC store the same way OIDC does, and the
/// two caps must agree or a SAML assertion could pass this parser only to
/// be rejected (or worse, silently under-reconciled) at the RBAC boundary.
/// `group_cap_truncated` (below) trips once an assertion carries more than
/// 200 non-empty group values; the ACS route (auth_routes.cpp) DENIES the
/// login in that case rather than reconciling a truncated (i.e. incomplete)
/// membership set. Raising this from 64 to 200 also improves the coarse
/// `--saml-admin-group` path: an admin group asserted at position 65-200
/// was previously silently missed.
inline constexpr std::size_t kMaxGroupValues = 200;

/// Configuration for the SAML 2.0 SP. All string fields are UTF-8.
struct SamlConfig {
    std::string idp_entity_id;  ///< IdP entityID — must match Issuer in assertions
    std::string idp_sso_url;    ///< IdP SSO endpoint for HTTP-Redirect binding
    std::string sp_entity_id;   ///< SP entityID — used as Audience in assertions
    std::string sp_acs_url;     ///< SP Assertion Consumer Service URL
    std::string idp_cert_pem;   ///< PEM-encoded IdP signing certificate (PINNED KEY — N1)
    bool        enabled{false};

    /// Name of the `<Attribute Name="...">` inside `<AttributeStatement>` whose
    /// `<AttributeValue>` children are group identifiers (e.g. the Entra
    /// `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` claim
    /// URI). Empty (default) disables attribute parsing entirely — a SAML
    /// deployment that never configures this behaves exactly like the thin
    /// slice (SamlAssertion::groups always empty).
    std::string group_attribute;

    /// Name of the `<Attribute Name="...">` whose first `<AttributeValue>` is
    /// the user's human display name (e.g. Entra's
    /// `http://schemas.microsoft.com/identity/claims/displayname` or the SAML
    /// 2.0 `urn:oid:2.16.840.1.113730.3.1.241`). Empty (default) disables
    /// display-name parsing — `SamlAssertion::display_name` stays empty and the
    /// session display falls back to the raw NameID, exactly as before. Purely
    /// session-enrichment (dashboard/audit rendering); NEVER an identity or
    /// authz input — see `saml_principal_id` (identity stays NameID-only).
    std::string name_attribute;

    /// Name of the `<Attribute Name="...">` whose first `<AttributeValue>` is
    /// the user's email (e.g. Entra's
    /// `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`).
    /// Empty (default) disables email parsing. Same session-enrichment-only
    /// contract as `name_attribute`: it feeds the session display fallback and
    /// a log line, is NEVER stored as a durable session field, and NEVER
    /// participates in identity/SCIM linkage (mirrors the OIDC email posture,
    /// `create_oidc_session`).
    std::string email_attribute;

    /// PEM-encoded SP AuthnRequest signing private key (RSA only). TRANSIT
    /// field only — server.cpp reads the key file and populates this; the
    /// SamlProvider constructor parses it once, retains the owned EVP_PKEY,
    /// and clears this member. Empty (default) means AuthnRequests are
    /// unsigned (backward-compatible).
    std::string sp_signing_key_pem;
};

/// Claims extracted from a verified SAML assertion.
struct SamlAssertion {
    std::string name_id;

    /// ADR-2001 PR4a — the verified `<saml:NameID Format="...">` attribute,
    /// read from the SAME XSW-verified assertion node as `name_id` (never a
    /// second document-wide search — N2 parity). Empty when the assertion's
    /// NameID carries no Format attribute at all. Consumed by
    /// `saml_scim_link.hpp`'s `is_linkable_name_id_format` to decide whether
    /// this NameID is a safe SCIM-externalId join key: only a STABLE format
    /// (persistent, or the 1.1 emailAddress format) is; a `transient` (or
    /// missing/empty) Format NameID is re-minted per login and must never be
    /// trusted into a durable link. This field is purely descriptive — the
    /// verifier itself never rejects a login based on Format; that decision
    /// is entirely the login-site linking orchestration's.
    std::string name_id_format;

    /// Group identifiers extracted from the configured `group_attribute`'s
    /// `<AttributeValue>` children. Always empty when `SamlConfig::group_attribute`
    /// is empty. Bounded to at most kMaxGroupValues entries (DoS guard).
    /// Read from the SAME XSW-verified assertion node as name_id — never a
    /// second document-wide search (see validate_response N2 discussion).
    std::vector<std::string> groups;

    /// #1828.3: true when the assertion carried at least one more non-empty
    /// group value beyond the kMaxGroupValues cap (i.e. `groups` is a
    /// truncated view of the assertion's actual group membership). The
    /// verifier (this class) has no metrics handle, so it surfaces the
    /// signal as a flag here rather than incrementing a counter directly —
    /// the ACS route (auth_routes.cpp) bumps
    /// `yuzu_saml_group_cap_truncated_total` when this is true. Deliberately
    /// NOT a per-login audit/log line (would spam on a chatty IdP); a
    /// counter is the anti-flood-safe signal, same rationale as the sibling
    /// `_blocked_total`/`_local_disabled_total` metric-only signals
    /// documented in docs/observability-conventions.md.
    bool group_cap_truncated{false};

    /// The first `<AttributeValue>` of the configured `name_attribute`, read
    /// from the SAME XSW-verified assertion node as `name_id` (N2 parity —
    /// never a second document-wide search). Empty when `name_attribute` is
    /// unset or the assertion carries no such attribute/value. PURELY
    /// descriptive session-enrichment: the login site uses it (with `email`)
    /// only to render `Session::display_name`; it is NEVER an identity, authz,
    /// or SCIM-linkage input (identity remains NameID-only, `saml_principal.hpp`).
    std::string display_name;

    /// The first `<AttributeValue>` of the configured `email_attribute`, read
    /// from the SAME XSW-verified assertion node. Empty when unset/absent.
    /// Session-enrichment only, same contract as `display_name`: a display
    /// fallback + a log line, never a durable session field and never an
    /// identity/linkage input.
    std::string email;
};

/// SAML 2.0 SP verifier — pure library, no HTTP routes, no session minting.
///
/// Construct at startup (before request threads spin up) — the underlying
/// xmlsec1 global init is not thread-safe; after first construction it is
/// idempotent.
class SamlProvider {
public:
    explicit SamlProvider(SamlConfig config);
    ~SamlProvider();

    // Non-copyable, non-movable (mutex + xmlsec state)
    SamlProvider(const SamlProvider&) = delete;
    SamlProvider& operator=(const SamlProvider&) = delete;

    /// Returns true only when enabled flag is set AND idp_cert_pem is non-empty.
    bool is_enabled() const;

    /// Result of build_authn_request.
    /// Both fields are empty strings when the provider is not enabled.
    struct AuthnRequestResult {
        std::string url;            ///< Full IdP redirect URL
        std::string cookie_secret;  ///< 32-byte CSPRNG secret (hex) for the binding cookie
    };

    /// Build an AuthnRequest redirect URL (HTTP-Redirect binding).
    /// Generates a random request ID and a CSPRNG binding secret, stores
    /// SHA-256(secret) alongside the expiry for InResponseTo validation,
    /// raw-DEFLATEs the XML, base64-encodes, URL-encodes, and appends relay_state.
    /// Note: AuthnRequest signing is a follow-up (not required for basic interop).
    /// @returns AuthnRequestResult with url + cookie_secret; both empty if not enabled.
    AuthnRequestResult build_authn_request(const std::string& relay_state);

    /// Validate a base64-encoded SAMLResponse (POST binding).
    /// Performs all four non-negotiable security checks plus browser-binding
    /// verification: SHA-256(cookie_secret) must match the hash stored when
    /// the corresponding AuthnRequest was issued.
    /// @param saml_response_b64  Base64-encoded SAMLResponse POST parameter.
    /// @param cookie_secret      Raw binding secret from the __Host-yuzu_saml_bind cookie.
    std::expected<SamlAssertion, std::string> validate_response(
        const std::string& saml_response_b64,
        const std::string& cookie_secret);

    /// Purge expired pending AuthnRequest IDs (call periodically).
    void cleanup_expired_states();

    /// True when SamlConfig::sp_signing_key_pem was non-empty but failed to
    /// parse as a usable SP signing key (malformed PEM, or a non-RSA key —
    /// EC/RSA-PSS are rejected). Callers (server.cpp) use this to disable
    /// SAML LOUDLY on a misconfigured key rather than silently falling back
    /// to unsigned AuthnRequests. Always false on Windows and when
    /// sp_signing_key_pem was empty.
    bool signing_configured_but_broken() const;

    /// Human-readable reason signing_configured_but_broken() is true.
    /// Empty when signing_configured_but_broken() is false. Never contains
    /// the PEM bytes.
    const std::string& signing_init_error() const;

private:
    void cleanup_expired_states_locked(); ///< Must be called with mu_ held.

    SamlConfig config_;
    mutable std::mutex mu_;

    /// Tracks issued AuthnRequest IDs → (expiry, binding_hash).
    /// binding_hash = SHA-256(cookie_secret) stored at request-issue time.
    /// Consumed on use (replay prevention).  Atomic under mu_ with validate_response.
    struct PendingRequest {
        std::chrono::steady_clock::time_point expiry;
        std::string binding_hash; ///< hex-encoded SHA-256 of the binding cookie secret
    };
    std::unordered_map<std::string, PendingRequest> pending_requests_;

    static constexpr auto kRequestTtl          = std::chrono::minutes(10);
    static constexpr std::size_t kMaxPendingRequests = 1000;

    /// Owned SP AuthnRequest signing key, parsed once at construction from
    /// SamlConfig::sp_signing_key_pem. Null when signing is not configured,
    /// or when signing_init_failed_ is true (a malformed/non-RSA key is
    /// never retained — see signing_configured_but_broken()).
    std::shared_ptr<EVP_PKEY> sp_signing_key_;
    bool        signing_init_failed_{false};
    std::string signing_init_error_;
};

} // namespace yuzu::server::saml
