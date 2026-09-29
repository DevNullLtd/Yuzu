#pragma once

#include <chrono>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// OpenSSL is an unconditional server dependency on every platform (vcpkg.json;
// server/core/meson.build hard-errors without it). JWT/JWKS RSA verification
// therefore uses the same OpenSSL EVP path everywhere — see verify_jwt_signature
// (#1856/#1782: the old Windows build stubbed verification out and returned
// success without checking the signature, accepting forged tokens).
//
// <openssl/evp.h> alone is safe to expose from this header: it declares none of
// the wincrypt.h-shadowed symbols (X509_NAME, OCSP_*, PKCS7_*), so a Windows
// consumer that includes <windows.h> before this header does not hit the macro
// clash. If a future edit adds <openssl/x509.h> (etc.) here, that guarantee
// breaks — such includers would then need OpenSSL-before-windows.h ordering.
#include <openssl/evp.h>

namespace yuzu::server::oidc {

struct OidcConfig {
    std::string issuer;
    std::string client_id;
    std::string client_secret; // Required for web platform (Entra confidential client)
    std::string redirect_uri;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string jwks_uri;        // JWKS endpoint for JWT signature verification
    std::string exchange_script; // Path to oidc_token_exchange.py
    std::string admin_group_id;  // Entra group ID that maps to admin role
    bool skip_tls_verify{false}; // Disable TLS cert verification (insecure, dev only)
    // ADR-2001 §1 — which claim `validate_claims` treats as the SCIM link
    // key (`"sub"` default or `"oid"`), threaded from
    // Config::oidc_scim_link_claim. Only `"oid"` changes validate_claims'
    // behaviour: it gates whether a missing/malformed `oid` claim fails the
    // login (sub-equivalent fail-closed validation applies only when `oid`
    // IS the configured link claim — see `IdTokenClaims::oid`).
    std::string scim_link_claim{"sub"};

    bool is_enabled() const { return !issuer.empty() && !client_id.empty(); }
};

struct PkceChallenge {
    std::string code_verifier;
    std::string code_challenge;
    std::string state;
    std::string nonce;
    std::string redirect_uri; // The exact redirect_uri used for this flow
    std::chrono::steady_clock::time_point expires_at;
};

struct IdTokenClaims {
    std::string sub;
    /// Entra/Azure AD object id (ADR-2001 §1). Entra's `externalId` on the
    /// SCIM side rides this claim, not `sub` — so this is the second
    /// allowed value for `--oidc-scim-link-claim`. Validated with the SAME
    /// fail-closed rules as `sub` (see `validate_claims`) ONLY when the
    /// operator selected `oid` as the link claim — a missing/malformed
    /// `oid` must not fail a login under the default `sub` link-claim
    /// configuration. Empty when the IdP omits the claim (Okta typically
    /// does).
    std::string oid;
    std::string email;
    std::string preferred_username;
    std::string name;
    std::string iss;
    std::string aud;
    std::string nonce;
    int64_t exp{0};
    int64_t iat{0};
    int64_t nbf{0}; // not-before (RFC 7519 §4.1.5); 0 = absent
    std::vector<std::string> groups; // Entra security group object IDs
    /// True iff the token payload actually contained a `groups` key (even an
    /// empty array). Distinguishes "IdP asserted zero groups" (a genuine
    /// deprovisioning event) from "IdP omitted the claim" — Entra drops
    /// `groups` entirely once a user belongs to more groups than fit in the
    /// token and sends a `_claim_names`/`_claim_sources` overage pointer
    /// instead (see `groups_overage`). `reconcile_idp_memberships` MUST NOT
    /// run against an empty `groups` vector unless this is true, or a
    /// heavily-grouped legitimate user gets every IdP-sourced RBAC
    /// membership silently deleted on next login (governance UP-1).
    bool groups_claim_present{false};
    /// True when the token carries Entra/Graph group-overage indicators — a
    /// `_claim_names` object with a `"groups"` entry and/or a
    /// `_claim_sources` object — meaning the IdP could NOT fit the user's
    /// full group membership in the token. `claims.groups` is therefore
    /// partial/absent, never authoritative, for this login.
    bool groups_overage{false};
    /// RFC 8176 Authentication Method Reference values asserted by the IdP
    /// (Entra adds the non-standard "mfa" value). Parsed so /auth/callback
    /// can seed the session's MFA-verified timestamp when the IdP attests a
    /// multi-factor login. Empty when the IdP omits the claim.
    std::vector<std::string> amr;
};

/// True when `claims.groups` is safe to reconcile against the RBAC store as
/// the user's COMPLETE asserted group set for this login (upsert asserted +
/// DELETE everything else under that source). False when the IdP omitted the
/// `groups` claim or replaced it with an overage pointer — in either case the
/// caller must SKIP reconciliation entirely (leave existing memberships
/// untouched) rather than treat an unreadable claim as "the user is in zero
/// groups". Mirrors the `amr_asserts_mfa` free-function pattern
/// (`mfa_step_up.hpp`) so the decision is unit-testable without a live route
/// harness. Governance UP-1 (#1832 hardening round).
[[nodiscard]] bool groups_claim_reconcilable(const IdTokenClaims& claims);

/// Cached JWK public key for JWT signature verification.
struct CachedJwk {
    std::string kid;
    std::string alg;
    std::shared_ptr<EVP_PKEY> pkey; // shared_ptr with custom deleter for RAII
};

class OidcProvider {
public:
    explicit OidcProvider(OidcConfig config);

    bool is_enabled() const;

    /// Generate PKCE params, store them, return authorization URL for redirect.
    /// @param request_redirect_uri If non-empty, overrides the configured redirect_uri
    ///        (derived from the request Host header for multi-origin support).
    std::string start_auth_flow(const std::string& request_redirect_uri = {});

    /// Exchange authorization code for tokens, validate ID token, return claims.
    std::expected<IdTokenClaims, std::string> handle_callback(const std::string& code,
                                                              const std::string& state);

    /// Remove expired PKCE states.
    void cleanup_expired_states();

    // ── Exposed for unit testing ──────────────────────────────────────────
    static std::string base64url_encode(const std::vector<uint8_t>& data);
    static std::string base64url_decode(const std::string& input);
    static std::string generate_code_verifier();
    static std::string compute_code_challenge(const std::string& verifier);
    static std::expected<IdTokenClaims, std::string> parse_id_token(const std::string& jwt);

    /// Test-only seam (#1856): inject an RSA verifying key into the JWKS cache
    /// directly, bypassing the network fetch, so verify_jwt_signature can be
    /// exercised end-to-end (jwk_to_pkey + EVP_DigestVerify) without a live IdP.
    /// `n_b64url`/`e_b64url` are the base64url RSA modulus/exponent (JWK form).
    /// Returns false if the key material does not parse. NOT for production use —
    /// this mutates the trusted signing-key cache and has no production callers.
    bool add_test_jwks_key(const std::string& kid, const std::string& n_b64url,
                           const std::string& e_b64url);

    std::expected<void, std::string> validate_claims(const IdTokenClaims& claims,
                                                     const std::string& expected_nonce) const;

    /// Verify JWT signature against cached JWKS keys. Returns error string on failure.
    std::expected<void, std::string> verify_jwt_signature(const std::string& jwt);

private:
    static std::string url_encode(const std::string& value);

    std::expected<std::string, std::string> exchange_code(const std::string& code,
                                                          const std::string& code_verifier,
                                                          const std::string& redirect_uri);

    /// Cleanup expired pending challenges (must hold mu_).
    void cleanup_expired_states_locked();

    /// Fetch and cache JWKS from the IdP's jwks_uri endpoint.
    void fetch_jwks();

    OidcConfig config_;
    std::string exchange_script_path_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, PkceChallenge> pending_challenges_;

    // JWKS cache for JWT signature verification (G2-SEC-A1-001)
    mutable std::mutex jwks_mu_;
    std::vector<CachedJwk> jwks_cache_;
    std::chrono::steady_clock::time_point jwks_fetched_at_;
    static constexpr auto kJwksCacheTtl = std::chrono::hours(1);

    static constexpr auto kChallengeTtl = std::chrono::minutes(10);
};

} // namespace yuzu::server::oidc
