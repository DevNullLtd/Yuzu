#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
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
    // The three endpoints normally stay EMPTY and are read from the issuer's OIDC Discovery
    // document the first time a login needs them (see OidcProvider::ensure_discovered). A
    // non-empty value is authoritative for that ONE field: it is used as given and discovery is
    // not consulted for it. Today that is a test seam; it is also the hook for a future operator
    // override flag (e.g. --oidc-jwks-uri). Production construction sites must NOT derive these
    // from the issuer: an IdP whose endpoints are not the derived ones then 404s, and a
    // pre-set authorization_endpoint used to skip discovery and leave jwks_uri empty (#5692).
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string jwks_uri;        // JWKS endpoint for JWT signature verification
    std::string admin_group_id;  // Entra group ID that maps to admin role
    bool skip_tls_verify{false}; // Disable TLS cert verification (insecure, dev only)
    // Egress policy (oidc_egress_policy.hpp): when false, the server refuses to connect to a
    // loopback, RFC 1918, carrier-grade NAT, unique-local or other non-global address for any
    // OIDC fetch. Link-local, cloud-metadata, multicast and unspecified addresses are refused
    // either way. Set ONLY from the process operator's `--oidc-allow-private-networks`; never
    // from the Settings form or a REST body (an admin who could set it could aim the server at
    // the internal network).
    bool allow_private_networks{false};
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
    std::string binding_hash; // hex SHA-256 of the initiating browser's binding secret
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

    /// The error `handle_callback` returns when the callback does not come from the browser
    /// that started the flow. A FIXED token: the route audits it as
    /// `reason=browser_binding_mismatch` and tests compare against it, so it never carries
    /// caller-controlled text.
    static constexpr const char* kBrowserBindingMismatch = "browser binding check failed";

    /// The error `handle_callback` returns when the binding digest could not be computed (a
    /// crypto-provider failure). Fail-closed like a mismatch and, like it, non-consuming, but a
    /// distinct FIXED token so the audit trail tells a platform fault from a refused cookie.
    static constexpr const char* kBrowserBindingUnavailable = "browser binding unavailable";

    /// The error `handle_callback` returns when `state` names no pending flow (never issued,
    /// already consumed, or swept). A FIXED token.
    static constexpr const char* kUnknownState = "unknown or expired state parameter";

    /// The error `handle_callback` returns when the IdP's discovery document could not be fetched
    /// or failed validation (issuer mismatch, a relative or scheme-downgraded endpoint, a
    /// missing field). A FIXED token; the cause is in the server log, never in the answer.
    static constexpr const char* kDiscoveryUnavailable = "OIDC discovery unavailable";

    /// The error `handle_callback` returns when no signing key could be obtained because the
    /// JWKS fetch failed. A FIXED token.
    static constexpr const char* kJwksUnavailable = "JWKS signing keys unavailable";

    /// The error `handle_callback` returns when something unexpected was thrown while processing
    /// the IdP's response (the backstop behind the per-claim type guards). A FIXED token: the
    /// route forwards the error into an audit event, so it never carries exception text.
    static constexpr const char* kCallbackInternalError = "OIDC callback processing failed";

    /// The fixed reason in the error of a request the egress policy refused (the full text is
    /// "request failed: " + this on the GET paths, "token endpoint request failed: " + this on the
    /// token POST). Never carries the resolved address.
    static constexpr const char* kEgressRefused = "address not permitted by the OIDC egress policy";

    /// The bounds on every IdP GET (discovery, JWKS, Test Connection), pinned by name in
    /// tests/unit/server/test_oidc_provider.cpp so a silent edit fails a test: the
    /// connect/read/write timeout PER OPERATION, the whole-request bound as a multiple of it
    /// (10 s by default), and the window during which a failed discovery is not retried.
    static constexpr int kHttpOperationTimeoutMs = 5000;
    static constexpr int kHttpTotalBoundMultiplier = 2;
    static constexpr int kDiscoveryNegativeCacheMs = 30000;

    /// What `start_auth_flow` hands the route: the IdP redirect and the initiating-browser
    /// binding secret. The route sets the secret as a cookie on the SAME response and requires
    /// it back at the callback; the provider retains only its SHA-256, so the secret is never
    /// in the redirect URL and never stored.
    struct AuthFlowStart {
        std::string url;            ///< authorization URL for the redirect
        std::string binding_secret; ///< 32-byte CSPRNG secret (64 hex chars) for the binding cookie
    };

    /// Generate PKCE params and a browser-binding secret, store them, return the
    /// authorization URL and the secret. THROWS (std::runtime_error) if the platform CSPRNG
    /// or SHA-256 fails, or if the authorization endpoint cannot be discovered
    /// (`kDiscoveryUnavailable`; there is NO fallback to a derived URL); nothing is stored in
    /// either case.
    /// @param request_redirect_uri If non-empty, overrides the configured redirect_uri. The
    ///        production route passes the configured value (`cfg_.oidc_redirect_uri`) and never
    ///        derives one from the request Host header; when the operator sets none, startup
    ///        fills a `http(s)://localhost:<port>/auth/callback` default (main.cpp).
    AuthFlowStart start_auth_flow(const std::string& request_redirect_uri = {});

    /// Exchange authorization code for tokens, validate ID token, return claims.
    ///
    /// `binding_secret` is the value of the binding cookie the CALLING browser presented. The
    /// flow proceeds only if SHA-256(binding_secret) equals the hash stored at
    /// `start_auth_flow` (constant-time compare); an empty or wrong secret is refused with
    /// `kBrowserBindingMismatch`, and a digest failure with `kBrowserBindingUnavailable`. The
    /// check runs BEFORE the pending flow is consumed and either refusal leaves the pending flow
    /// available to the initiating browser. The flow is consumed (single use) only once the
    /// binding matched.
    ///
    /// `binding_verified`, when non-null, is set false on entry and true ONLY once the presented
    /// secret matched. It is the sole signal that the calling browser's cookie proved a
    /// pending flow (and so is spent); an unknown or expired state, a mismatch and a digest
    /// failure leave it false.
    /// Every failure after the match (token exchange, signature, claims) leaves it true.
    std::expected<IdTokenClaims, std::string> handle_callback(const std::string& code,
                                                              const std::string& state,
                                                              const std::string& binding_secret,
                                                              bool* binding_verified = nullptr);

    /// Remove expired PKCE states.
    void cleanup_expired_states();

    // ── Exposed for unit testing ──────────────────────────────────────────
    static std::string base64url_encode(const std::vector<uint8_t>& data);
    static std::string base64url_decode(const std::string& input);
    static std::string generate_code_verifier();
    /// THROWS std::runtime_error if SHA-256 fails (like `start_auth_flow`).
    static std::string compute_code_challenge(const std::string& verifier);
    static std::expected<IdTokenClaims, std::string> parse_id_token(const std::string& jwt);

    /// Test-only seams for the binding digest. `set_binding_digest_failure_for_test(true)` makes
    /// this instance's binding SHA-256 fail exactly as a broken crypto provider would;
    /// `add_test_pending_flow` plants a pending flow with a chosen binding hash (hex), bypassing
    /// `start_auth_flow`, so the stored-hash validation can be driven with a value no honest
    /// flow stores. TEST-ONLY: none of the six test seams in this block (these two,
    /// `set_http_timeouts_for_test`, `set_discovery_negative_cache_for_test`,
    /// `set_resolver_for_test` and `pending_flow_count_for_test`) has a production caller, and
    /// tests/unit/server/ test_oidc_provider.cpp pins (source scan) that no other file in
    /// server/core/src references them.
    void set_binding_digest_failure_for_test(bool fail);
    void add_test_pending_flow(const std::string& state, std::string binding_hash);
    /// Test-only seam: replaces the 5 s per-operation connect/read/write timeouts of every IdP
    /// GET this instance makes (and so the total bound, which is twice this value), so a
    /// slow-IdP test never waits for a real timeout. Same source-scan pin.
    void set_http_timeouts_for_test(int ms);
    /// Test-only seam: replaces the name resolver the egress policy uses (the OS resolver
    /// otherwise) with `resolver`, which returns the numeric addresses a host name should resolve
    /// to. The addresses go through the same classification and pinning, so a test can give a
    /// name any answer (public, private, link-local, a mixed list) without DNS or an IdP on that
    /// address; the connect still goes to the PINNED address, so a test can also prove a request
    /// does not follow a second, different lookup. An empty function restores the OS resolver.
    /// Process-wide: a test must restore it. Same source-scan pin.
    using ResolverForTest = std::function<std::vector<std::string>(const std::string& host)>;
    static void set_resolver_for_test(ResolverForTest resolver);
    /// Test-only seam: replaces the 30 s window during which a failed discovery is not retried
    /// (0 = retry on the next call) and clears any window already running. Same source-scan pin.
    void set_discovery_negative_cache_for_test(int ms);
    /// Test-only seam: how many authorization flows are pending (a failed start must leave 0
    /// and a refused callback leaves the count unchanged). Same source-scan pin.
    std::size_t pending_flow_count_for_test() const;

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

    /// The three endpoints of a validated discovery document.
    struct DiscoveryDocument {
        std::string authorization_endpoint;
        std::string token_endpoint;
        std::string jwks_uri;
    };

    /// Fetch `{issuer}/.well-known/openid-configuration` (one trailing slash on `issuer` is
    /// tolerated) and validate it: `issuer` must equal the argument byte for byte (OIDC Discovery
    /// 4.3, the mix-up defense); all three endpoints must be present (even the ones the current
    /// caller does not need), absolute, free of spaces, control characters and the Unicode line
    /// breaks NEL/U+2028/U+2029, at most 2048 bytes, with a well-formed `host[:port]` authority
    /// (no userinfo, a port of 1..65535, a bracketed IPv6 host of hex digits and ':' only), and
    /// carry the
    /// ISSUER'S scheme (an https issuer can never be downgraded to http endpoints). An issuer
    /// longer than 2048 bytes, or holding a space, control character or Unicode line break, is
    /// refused before any request. Hosts are not restricted by NAME (Google serves jwks_uri from
    /// another host); the egress policy (`oidc_egress_policy.hpp`) restricts them by resolved
    /// ADDRESS, see `http_get_bounded`. The error text is for the operator-facing Test
    /// Connection and the log, not for the login answer; IdP-controlled text in it is
    /// neutralized for the log.
    /// Shared by the login path (ensure_discovered) and Test Connection so the button validates
    /// exactly what a login will.
    [[nodiscard]] static std::expected<DiscoveryDocument, std::string>
    fetch_discovery_document(const std::string& issuer, bool skip_tls_verify,
                             bool allow_private_networks, int timeout_ms = kHttpOperationTimeoutMs);

    /// The validation half of `fetch_discovery_document`, on an already fetched body. Pure: no
    /// network. Public so the scheme rules can be pinned for an https issuer without a TLS IdP.
    [[nodiscard]] static std::expected<DiscoveryDocument, std::string>
    parse_discovery_document(const std::string& body, const std::string& issuer);

    /// The one bounded GET used for discovery, the JWKS and Test Connection. `timeout_ms`
    /// (5 s by default) is the connect/read/write timeout PER OPERATION. The whole request is
    /// also bounded at TWICE that (10 s by default), measured from the start of the request and
    /// covering the connect and the response; on Linux/macOS a deadline watchdog extends the same
    /// bound to the TLS handshake, which httplib's own total bound does not cover (a server that
    /// drips handshake bytes would otherwise hold the call). On Windows the handshake phase has
    /// no total bound. The watchdog reserves a spare descriptor first; when none is available the
    /// call fails closed ("request failed: no file descriptor available") before any socket is
    /// opened. A 256 KiB body cap, redirects NOT followed (a 3xx is a failure), TLS verification
    /// honored. The URL's authority must be a well-formed `host[:port]` (see
    /// `fetch_discovery_document`). Returns the body of a 200 response.
    ///
    /// EGRESS POLICY. Before any socket exists the host is resolved here (IP literals are
    /// classified directly, no DNS), EVERY resolved address is classified by its bytes, and the
    /// connect is PINNED to the first permitted address (httplib `set_hostname_addr_map`; TLS
    /// server-name indication and certificate verification still use the host name). Link-local
    /// (cloud metadata included), unspecified, multicast and reserved addresses are always
    /// refused; loopback, RFC 1918, carrier-grade NAT and unique-local ones are refused unless
    /// `allow_private_networks` (the operator's `--oidc-allow-private-networks`). A refusal is the
    /// fixed `kEgressRefused` text and names no address. Name resolution is inside the total
    /// bound. Only the first permitted address is tried (no fallback to the others).
    [[nodiscard]] static std::expected<std::string, std::string>
    http_get_bounded(const std::string& url, bool skip_tls_verify, bool allow_private_networks,
                     int timeout_ms = kHttpOperationTimeoutMs);

    /// Parse a JWKS document into verifying keys (RSA, `use` absent or "sig"; others skipped).
    [[nodiscard]] static std::expected<std::vector<CachedJwk>, std::string>
    parse_jwks(const std::string& body);

private:
    /// Which endpoint a caller needs from `ensure_discovered`.
    enum class Need { Authorize, Token, Jwks };

    /// The endpoint for `need`, BY VALUE. A non-empty OidcConfig field is authoritative and
    /// returned as is (no network). Otherwise the discovery document is fetched once and cached
    /// for the provider's lifetime (a Settings save or a restart rebuilds the provider, so an IdP
    /// that moves jwks_uri needs one of those). Exactly ONE thread fetches at a time: it marks the
    /// fetch in flight under `discovery_mu_` and releases the mutex for the network round trip, so
    /// every other caller that needs discovery while it runs fails FAST with
    /// `kDiscoveryUnavailable` (it neither waits for the fetch nor starts a second one, and it
    /// does not start the 30 s window; the next call after the fetch finishes sees the result).
    /// A failed attempt is remembered for 30 s so a dead IdP is not hammered. Validate-only
    /// providers (empty redirect_uri) never fetch. The in-flight mark is cleared by an RAII guard
    /// on every exit (including an exception unwinding out of the fetch or its logging), in the
    /// same critical section that stores the result. A configured endpoint holding a space,
    /// control character or Unicode line break is refused like a discovered one. Fails CLOSED with
    /// `kDiscoveryUnavailable`; there is no fallback to derived endpoints. Nothing reads the
    /// config_ endpoint fields except through here. Lock order: `discovery_mu_` is never taken
    /// while holding `mu_` or `jwks_mu_` and is never held across network I/O. Future order, if the
    /// JWKS fetch is ever made single-flight under its own mutex (#1900): that fetch mutex first,
    /// then `discovery_mu_`.
    std::expected<std::string, std::string> ensure_discovered(Need need);

    static std::string url_encode(const std::string& value);

    std::expected<std::string, std::string> exchange_code(const std::string& code,
                                                          const std::string& code_verifier,
                                                          const std::string& redirect_uri);

    /// Hex SHA-256 of a binding secret. Throws on a digest failure.
    std::string binding_digest(const std::string& secret) const;

    /// Cleanup expired pending challenges (must hold mu_).
    void cleanup_expired_states_locked();

    /// Fetch and cache JWKS from the IdP's jwks_uri endpoint. True when a key set was stored.
    /// Stamps `jwks_fetched_at_` on EVERY attempt, so while the cache holds keys a failing IdP is
    /// retried once per cache TTL rather than once per login. An EMPTY cache and every kid miss
    /// still refetch on every call (#1900). Cached keys are trusted until the next SUCCESSFUL
    /// fetch replaces them (this was already so before discovery): a retired key therefore keeps
    /// verifying while jwks_uri stays unreachable (tracked under #1900/#1901).
    bool fetch_jwks();

    OidcConfig config_;
    std::atomic<int> http_timeout_ms_{kHttpOperationTimeoutMs}; // test seam only
    mutable std::mutex mu_;

    // Lazy discovery (ensure_discovered). Guards the four members below.
    std::mutex discovery_mu_;
    std::optional<DiscoveryDocument> discovered_;
    bool discovery_in_flight_{false}; // one fetcher at a time; the others fail fast
    std::chrono::steady_clock::time_point discovery_retry_after_{};
    // kDiscoveryNegativeCacheMs by default; see set_discovery_negative_cache_for_test.
    std::chrono::milliseconds discovery_retry_window_{kDiscoveryNegativeCacheMs};
    std::unordered_map<std::string, PkceChallenge> pending_challenges_;
    std::atomic<bool> binding_digest_forced_failure_{false}; // test seam only

    // JWKS cache for JWT signature verification (G2-SEC-A1-001)
    mutable std::mutex jwks_mu_;
    std::vector<CachedJwk> jwks_cache_;
    std::chrono::steady_clock::time_point jwks_fetched_at_;
    static constexpr auto kJwksCacheTtl = std::chrono::hours(1);

    static constexpr auto kChallengeTtl = std::chrono::minutes(10);
};

} // namespace yuzu::server::oidc
