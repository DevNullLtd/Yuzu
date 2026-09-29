/**
 * test_oidc_provider.cpp — Unit tests for OidcProvider
 *
 * Covers: base64url encode/decode, PKCE code_verifier/code_challenge,
 * JWT parsing, claim validation, auth flow URL generation, state lifecycle.
 */

#include "oidc_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h> // EVP_RSA_gen

#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace yuzu::server::oidc;

// ── Base64URL ────────────────────────────────────────────────────────────────

TEST_CASE("OIDC: base64url encode/decode roundtrip", "[oidc]") {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x7F};
    auto encoded = OidcProvider::base64url_encode(data);

    // Must not contain +, /, or =
    CHECK(encoded.find('+') == std::string::npos);
    CHECK(encoded.find('/') == std::string::npos);
    CHECK(encoded.find('=') == std::string::npos);

    auto decoded = OidcProvider::base64url_decode(encoded);
    REQUIRE(decoded.size() == data.size());
    for (size_t i = 0; i < data.size(); ++i)
        CHECK(static_cast<uint8_t>(decoded[i]) == data[i]);
}

TEST_CASE("OIDC: base64url decode without padding", "[oidc]") {
    // "Hello" in base64url is "SGVsbG8" (no padding)
    auto decoded = OidcProvider::base64url_decode("SGVsbG8");
    CHECK(decoded == "Hello");
}

TEST_CASE("OIDC: base64url encode empty input", "[oidc]") {
    auto encoded = OidcProvider::base64url_encode({});
    CHECK(encoded.empty());
    auto decoded = OidcProvider::base64url_decode("");
    CHECK(decoded.empty());
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

TEST_CASE("OIDC: code_verifier length", "[oidc]") {
    auto verifier = OidcProvider::generate_code_verifier();
    // 32 bytes -> 43 base64url characters (no padding)
    CHECK(verifier.size() == 43);
    // Must only contain unreserved characters
    for (char c : verifier) {
        CHECK((std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_'));
    }
}

TEST_CASE("OIDC: code_challenge is deterministic for same verifier", "[oidc]") {
    auto verifier = OidcProvider::generate_code_verifier();
    auto c1 = OidcProvider::compute_code_challenge(verifier);
    auto c2 = OidcProvider::compute_code_challenge(verifier);
    CHECK(c1 == c2);
}

TEST_CASE("OIDC: code_challenge differs for different verifiers", "[oidc]") {
    auto v1 = OidcProvider::generate_code_verifier();
    auto v2 = OidcProvider::generate_code_verifier();
    // Two random verifiers should produce different challenges
    CHECK(v1 != v2);
    CHECK(OidcProvider::compute_code_challenge(v1) != OidcProvider::compute_code_challenge(v2));
}

TEST_CASE("OIDC: code_challenge against RFC 7636 Appendix B", "[oidc]") {
    // RFC 7636 test vector:
    //   code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    //   code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    auto challenge =
        OidcProvider::compute_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    CHECK(challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

// ── JWT parsing ──────────────────────────────────────────────────────────────

static std::string make_test_jwt(const std::string& payload_json) {
    // Encode a minimal JWT: header.payload.signature (fake signature)
    auto encode_part = [](const std::string& s) {
        std::vector<uint8_t> bytes(s.begin(), s.end());
        return OidcProvider::base64url_encode(bytes);
    };
    auto header = R"({"alg":"RS256","typ":"JWT"})";
    return encode_part(header) + "." + encode_part(payload_json) + ".fakesignature";
}

TEST_CASE("OIDC: parse valid ID token", "[oidc]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "email": "alice@example.com",
        "preferred_username": "alice",
        "name": "Alice Operator",
        "iss": "https://login.microsoftonline.com/tenant/v2.0",
        "aud": "my-client-id",
        "nonce": "abc123",
        "exp": 9999999999,
        "iat": 1700000000
    })");

    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->sub == "user123");
    CHECK(result->email == "alice@example.com");
    CHECK(result->preferred_username == "alice");
    CHECK(result->name == "Alice Operator");
    CHECK(result->iss == "https://login.microsoftonline.com/tenant/v2.0");
    CHECK(result->aud == "my-client-id");
    CHECK(result->nonce == "abc123");
    CHECK(result->exp == 9999999999);
    CHECK(result->iat == 1700000000);
}

TEST_CASE("OIDC: parse ID token with amr array (PR3)", "[oidc][amr]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "amr": ["pwd", "mfa"]
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    REQUIRE(result->amr.size() == 2);
    CHECK(result->amr[0] == "pwd");
    CHECK(result->amr[1] == "mfa");
}

TEST_CASE("OIDC: parse ID token with amr as a lone string (non-conformant IdP)", "[oidc][amr]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "amr": "mfa"
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    REQUIRE(result->amr.size() == 1);
    CHECK(result->amr[0] == "mfa");
}

TEST_CASE("OIDC: amr absent leaves the vector empty", "[oidc][amr]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->amr.empty());
}

// ── groups claim / group-overage (UP-1) ─────────────────────────────────────

TEST_CASE("OIDC: groups claim present and non-empty", "[oidc][groups]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "groups": ["g1", "g2"]
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->groups_claim_present);
    CHECK_FALSE(result->groups_overage);
    REQUIRE(result->groups.size() == 2);
    CHECK(groups_claim_reconcilable(*result));
}

TEST_CASE("OIDC: groups claim present but empty — genuine deprovisioning assertion",
         "[oidc][groups]") {
    // Distinct from "claim absent": the IdP explicitly asserts the user is
    // in ZERO groups (e.g. every group membership was removed). This MUST
    // be reconcilable — it's what makes deprovisioning propagate.
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "groups": []
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->groups_claim_present);
    CHECK_FALSE(result->groups_overage);
    CHECK(result->groups.empty());
    CHECK(groups_claim_reconcilable(*result));
}

TEST_CASE("OIDC: groups claim absent (no overage pointer either)", "[oidc][groups]") {
    // A plain IdP that simply never emits a `groups` claim — not the same as
    // the Entra overage case, but must be treated identically by the
    // caller: unreconcilable (don't run a destructive reconcile against an
    // absent claim).
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->groups_claim_present);
    CHECK_FALSE(result->groups_overage);
    CHECK(result->groups.empty());
    CHECK_FALSE(groups_claim_reconcilable(*result));
}

TEST_CASE("OIDC: Entra group overage via _claim_names/_claim_sources (UP-1)",
         "[oidc][groups]") {
    // Real Entra shape: `groups` is OMITTED and replaced by an indirection
    // pointer once the user is in more groups than fit in the token.
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "_claim_names": {"groups": "src1"},
        "_claim_sources": {
            "src1": {
                "endpoint": "https://graph.microsoft.com/v1.0/users/user123/getMemberObjects"
            }
        }
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->groups_claim_present);
    CHECK(result->groups_overage);
    CHECK(result->groups.empty());
    CHECK_FALSE(groups_claim_reconcilable(*result));
}

TEST_CASE("OIDC: non-groups overage does NOT flag groups overage (precision)",
         "[oidc][groups]") {
    // A `_claim_sources` / `_claim_names` naming some OTHER overaged claim
    // (here `roles`) must NOT suppress a genuine groups deprovision: an
    // authoritative, present `groups` array alongside a roles-overage pointer
    // is still reconcilable. Keying overage on `_claim_names.groups` avoids the
    // over-conservative skip flagged in the #1832 hardening security re-review.
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "groups": ["gid-a"],
        "_claim_names": {"roles": "src1"},
        "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/..."}}
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->groups_claim_present);
    CHECK_FALSE(result->groups_overage);
    CHECK(groups_claim_reconcilable(*result));  // groups authoritative -> reconcile runs
}

TEST_CASE("OIDC: an unrelated _claim_names entry does not flag groups overage",
         "[oidc][groups]") {
    // Only a `groups` key inside `_claim_names` counts — some IdPs use the
    // same indirection mechanism for other overaged claims (e.g. `roles`).
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "groups": ["g1"],
        "_claim_names": {"roles": "src1"}
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->groups_claim_present);
    CHECK_FALSE(result->groups_overage);
    CHECK(groups_claim_reconcilable(*result));
}

TEST_CASE("OIDC: malformed iat/exp/sub do not throw (sec-M1 type-guard)", "[oidc][amr]") {
    // A signature-valid token whose iat is a JSON string, or sub is a
    // number, must NOT throw an uncaught nlohmann type_error out of
    // parse_id_token (PR3 makes iat load-bearing → a throw would 500 the
    // /auth/callback). Type-guarded extraction leaves the bad field at its
    // default instead.
    auto jwt = make_test_jwt(R"({
        "sub": 12345,
        "iss": "https://issuer",
        "nonce": "n",
        "exp": "not-a-number",
        "iat": "also-not-a-number",
        "amr": ["mfa"]
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value()); // did not throw
    CHECK(result->sub.empty());  // numeric sub → guarded out
    CHECK(result->iat == 0);     // string iat → left at default
    CHECK(result->exp == 0);
    REQUIRE(result->amr.size() == 1); // valid claims still parsed
    CHECK(result->amr[0] == "mfa");
}

TEST_CASE("OIDC: float-encoded iat is accepted (sec-M1)", "[oidc][amr]") {
    // Some IdPs emit iat as 1700000000.0. The double-cast extraction keeps
    // it usable instead of throwing on get<int64_t>().
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999,
        "iat": 1700000000.0
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->iat == 1700000000);
}

TEST_CASE("OIDC: parse ID token with aud as array", "[oidc]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "aud": ["client-a", "client-b"],
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->aud == "client-a");
}

TEST_CASE("OIDC: parse malformed JWT — no dots", "[oidc]") {
    auto result = OidcProvider::parse_id_token("nodots");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("no dots") != std::string::npos);
}

TEST_CASE("OIDC: parse malformed JWT — one dot", "[oidc]") {
    auto result = OidcProvider::parse_id_token("one.dot");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("only one dot") != std::string::npos);
}

TEST_CASE("OIDC: parse malformed JWT — invalid base64url payload", "[oidc]") {
    auto result = OidcProvider::parse_id_token("header.!!!invalid!!!.sig");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("parse error") != std::string::npos);
}

// ── Claim validation ─────────────────────────────────────────────────────────

TEST_CASE("OIDC: validate_claims — valid", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "test-nonce";
    claims.exp = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count() +
                 3600;

    auto result = provider.validate_claims(claims, "test-nonce");
    CHECK(result.has_value());
}

TEST_CASE("OIDC: validate_claims — missing exp is rejected (Gate 8)", "[oidc]") {
    // OIDC Core requires exp. A token with no exp (claims.exp left at 0 by
    // the parser, e.g. missing or non-numeric) must be rejected, not
    // treated as never-expiring.
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "test-nonce";
    claims.exp = 0; // missing/invalid

    auto result = provider.validate_claims(claims, "test-nonce");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("exp") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — future iat is rejected (Hermes A1)", "[oidc][amr]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = now + 3600;
    claims.iat = now + 7200; // 2h in the future, well past clock skew

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("future") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — iat within clock-skew window is accepted (UP-D4)",
          "[oidc][amr]") {
    // The future-iat rejection uses a generous 300 s skew so honest IdP/
    // server NTP drift does not cause a total SSO outage. A token issued
    // ~a minute "ahead" must still be accepted.
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = now + 3600;
    claims.iat = now + 120; // 2 min ahead — within the 300 s tolerance

    CHECK(provider.validate_claims(claims, "n").has_value());
}

TEST_CASE("OIDC: validate_claims — nbf in the past is accepted", "[oidc][amr]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = now + 3600;
    claims.iat = now;
    claims.nbf = now - 60; // already valid

    CHECK(provider.validate_claims(claims, "n").has_value());
}

TEST_CASE("OIDC: validate_claims — nbf in the future is rejected (Hermes A3)", "[oidc][amr]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = now + 3600;
    claims.iat = now;
    claims.nbf = now + 1800; // not valid for another 30 min

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("nbf") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — wrong issuer", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://expected";
    cfg.client_id = "c";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://wrong";
    claims.aud = "c";
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("iss mismatch") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — wrong audience", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "expected";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://iss";
    claims.aud = "wrong";
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("aud mismatch") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — expired token", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://iss";
    claims.aud = "c";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = 1000000000; // long expired

    auto result = provider.validate_claims(claims, "n");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("expired") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — wrong nonce", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://iss";
    claims.aud = "c";
    claims.sub = "user-123";
    claims.nonce = "actual";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "expected");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("nonce mismatch") != std::string::npos);
}

// ── sub validation (#1837 governance follow-up) ─────────────────────────────
//
// `sub` is the authorization-load-bearing half of the stable RBAC principal
// `oidc:<iss>#<sub>` (auth_routes.cpp /auth/callback). A degenerate/hostile
// `sub` must never reach that construction — validate_claims is the single
// chokepoint that already rejects iss/aud/exp/nonce mismatches, so the sub
// checks live there too (fail-closed: no session minted).

TEST_CASE("OIDC: validate_claims — missing sub is rejected", "[oidc][sub]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.nonce = "n";
    claims.exp = 9999999999;
    // claims.sub left at its default-constructed empty string — mirrors
    // parse_id_token's behaviour when the IdP token omits `sub` or sends a
    // non-string value.

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("sub") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — sub containing a control/newline char is rejected",
          "[oidc][sub]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user\n123"; // would corrupt the audit `principal` column
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("sub") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — over-length sub is rejected", "[oidc][sub]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = std::string(256, 'a'); // 1 over the 255-char cap
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("sub") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — a 255-char sub is accepted (boundary)", "[oidc][sub]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = std::string(255, 'a'); // exactly the cap
    claims.nonce = "n";
    claims.exp = 9999999999;

    CHECK(provider.validate_claims(claims, "n").has_value());
}

TEST_CASE("OIDC: validate_claims — two tokens with empty sub are BOTH rejected, "
          "never collapsed onto the same principal",
          "[oidc][sub]") {
    // Regression guard for the exact hazard this validation closes: before
    // this check, two distinct users whose IdP omitted `sub` would both
    // build the principal `oidc:<iss>#` and collapse onto one RBAC identity.
    // Now neither login succeeds — there is no session to collapse.
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims_a;
    claims_a.iss = "https://issuer";
    claims_a.aud = "my-client";
    claims_a.nonce = "n";
    claims_a.exp = 9999999999;
    // sub left empty — "user A"

    IdTokenClaims claims_b = claims_a; // sub left empty — "user B" too

    CHECK_FALSE(provider.validate_claims(claims_a, "n").has_value());
    CHECK_FALSE(provider.validate_claims(claims_b, "n").has_value());
}

// ── oid validation (ADR-2001 §1) ────────────────────────────────────────────
//
// `oid` mirrors `sub`'s sub-equivalent fail-closed validation EXACTLY, but
// ONLY when the operator selected `oid` as the SCIM link claim
// (`--oidc-scim-link-claim`, `OidcConfig::scim_link_claim`) — the default
// `sub` link claim must not fail a login over a missing/malformed `oid`
// that most IdPs (Okta) never send.

TEST_CASE("OIDC: validate_claims — missing oid is rejected when oid is the link claim",
          "[oidc][oid]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    cfg.scim_link_claim = "oid";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = 9999999999;
    // claims.oid left at its default-constructed empty string.

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("oid") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — missing oid does NOT fail login when sub is the link claim",
          "[oidc][oid]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    cfg.scim_link_claim = "sub"; // default
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = 9999999999;
    // claims.oid left empty — Okta typically never sends this claim.

    CHECK(provider.validate_claims(claims, "n").has_value());
}

TEST_CASE("OIDC: validate_claims — oid containing a control/newline char is rejected when "
          "oid is the link claim",
          "[oidc][oid]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    cfg.scim_link_claim = "oid";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.oid = "aad-obj\n456"; // would corrupt a durable join key
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("oid") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — over-length oid is rejected when oid is the link claim",
          "[oidc][oid]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    cfg.scim_link_claim = "oid";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.oid = std::string(256, 'a'); // 1 over the 255-char cap
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("oid") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — a 255-char oid is accepted (boundary) when oid is the "
          "link claim",
          "[oidc][oid]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    cfg.scim_link_claim = "oid";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.oid = std::string(255, 'a'); // exactly the cap
    claims.nonce = "n";
    claims.exp = 9999999999;

    CHECK(provider.validate_claims(claims, "n").has_value());
}

TEST_CASE("OIDC: validate_claims — a valid oid is accepted when oid is the link claim",
          "[oidc][oid]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    cfg.scim_link_claim = "oid";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.sub = "user-123";
    claims.oid = "aad-object-id-456";
    claims.nonce = "n";
    claims.exp = 9999999999;

    CHECK(provider.validate_claims(claims, "n").has_value());
}

// ── Auth flow ────────────────────────────────────────────────────────────────

TEST_CASE("OIDC: start_auth_flow generates valid URL", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://login.example.com/tenant/v2.0";
    cfg.client_id = "test-client-id";
    cfg.redirect_uri = "http://localhost:8443/auth/callback";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = cfg.issuer + "/token";
    OidcProvider provider(std::move(cfg));

    auto url = provider.start_auth_flow();

    CHECK(url.starts_with("https://login.example.com/tenant/v2.0/authorize?"));
    CHECK(url.find("client_id=test-client-id") != std::string::npos);
    CHECK(url.find("response_type=code") != std::string::npos);
    CHECK(url.find("code_challenge=") != std::string::npos);
    CHECK(url.find("code_challenge_method=S256") != std::string::npos);
    CHECK(url.find("state=") != std::string::npos);
    CHECK(url.find("nonce=") != std::string::npos);
    CHECK(url.find("redirect_uri=") != std::string::npos);
}

TEST_CASE("OIDC: cleanup_expired_states removes old entries", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = cfg.issuer + "/token";
    OidcProvider provider(std::move(cfg));

    // Start a flow to create a pending challenge
    auto url = provider.start_auth_flow();
    (void)url;

    // Cleanup should not remove it (not yet expired)
    provider.cleanup_expired_states();

    // Try handle_callback with a bogus state — should fail with "unknown"
    auto result = provider.handle_callback("fakecode", "bogus-state");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("unknown") != std::string::npos);
}

TEST_CASE("OIDC: handle_callback with unknown state fails", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = cfg.issuer + "/token";
    OidcProvider provider(std::move(cfg));

    auto result = provider.handle_callback("code", "nonexistent-state");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("unknown") != std::string::npos);
}

// ── JWT signature verification (#1856 / #1782) ───────────────────────────────
//
// Regression guard for the CRITICAL fail-open where the Windows build stubbed
// verify_jwt_signature to `return {}` (success) WITHOUT checking the signature,
// accepting any forged RS256/384/512 token. The fix routes every platform
// through the same OpenSSL EVP path. These cases assert the load-bearing
// property the stub violated: verification must FAIL when it cannot actually
// verify — never silently succeed. (They run identically on Windows now.)

// Build a JWT with a caller-chosen header so we can exercise the alg guards.
static std::string make_jwt_with_header(const std::string& header_json,
                                        const std::string& payload_json) {
    auto encode_part = [](const std::string& s) {
        std::vector<uint8_t> bytes(s.begin(), s.end());
        return OidcProvider::base64url_encode(bytes);
    };
    return encode_part(header_json) + "." + encode_part(payload_json) + ".c2ln";
}

TEST_CASE("OIDC: verify_jwt_signature fails closed when no signing key is available",
          "[oidc][jwt][security]") {
    // A structurally valid RS256 token, but the provider has no jwks_uri, so the
    // JWKS cache stays empty and no key can be found. Pre-fix, the Windows build
    // returned success here (forged-token acceptance); it must now be rejected.
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    // No jwks_uri, no redirect_uri → construction skips discovery/fetch.
    OidcProvider provider(std::move(cfg));

    auto jwt = make_jwt_with_header(R"({"alg":"RS256","kid":"nope","typ":"JWT"})",
                                    R"({"sub":"attacker","exp":9999999999})");

    auto result = provider.verify_jwt_signature(jwt);
    REQUIRE_FALSE(result.has_value()); // MUST NOT fail open
    CHECK(result.error().find("JWKS key") != std::string::npos);
}

TEST_CASE("OIDC: verify_jwt_signature rejects alg:none", "[oidc][jwt][security]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto jwt = make_jwt_with_header(R"({"alg":"none","typ":"JWT"})",
                                    R"({"sub":"attacker","exp":9999999999})");

    auto result = provider.verify_jwt_signature(jwt);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("none") != std::string::npos);
}

TEST_CASE("OIDC: verify_jwt_signature rejects unsupported alg (HS256 confusion)",
          "[oidc][jwt][security]") {
    // Reject symmetric/unsupported algorithms outright — an RS→HS key-confusion
    // token must never reach the RSA verification path.
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto jwt = make_jwt_with_header(R"({"alg":"HS256","typ":"JWT"})",
                                    R"({"sub":"attacker","exp":9999999999})");

    auto result = provider.verify_jwt_signature(jwt);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("unsupported") != std::string::npos);
}

// Generate an RSA keypair, register its public half in `provider` as a JWKS key
// under `kid`, and return a genuinely RS256-signed JWT over `payload_json`.
// Drives the SAME jwk_to_pkey + EVP path that production uses. Returns "" on any
// OpenSSL failure (the caller REQUIREs non-empty). Uses only non-deprecated
// OpenSSL 3.0 EVP APIs, so it needs no deprecation pragmas.
static std::string sign_and_register_rs256(OidcProvider& provider, const std::string& kid,
                                           const std::string& payload_json) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk(EVP_RSA_gen(2048), EVP_PKEY_free);
    if (!pk)
        return "";

    // Modulus/exponent → base64url for the JWK the provider will cache.
    BIGNUM* raw_n = nullptr;
    BIGNUM* raw_e = nullptr;
    if (EVP_PKEY_get_bn_param(pk.get(), "n", &raw_n) != 1 ||
        EVP_PKEY_get_bn_param(pk.get(), "e", &raw_e) != 1) {
        BN_free(raw_n);
        BN_free(raw_e);
        return "";
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_n(raw_n, BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_e(raw_e, BN_free);

    auto bn_to_b64url = [](const BIGNUM* bn) {
        std::vector<uint8_t> buf(static_cast<size_t>(BN_num_bytes(bn)));
        BN_bn2bin(bn, buf.data());
        return OidcProvider::base64url_encode(buf);
    };
    if (!provider.add_test_jwks_key(kid, bn_to_b64url(bn_n.get()), bn_to_b64url(bn_e.get())))
        return "";

    auto b64 = [](const std::string& s) {
        return OidcProvider::base64url_encode(std::vector<uint8_t>(s.begin(), s.end()));
    };
    std::string header = R"({"alg":"RS256","kid":")" + kid + R"(","typ":"JWT"})";
    std::string signing_input = b64(header) + "." + b64(payload_json);

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md || EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, pk.get()) != 1)
        return "";
    const auto* in = reinterpret_cast<const unsigned char*>(signing_input.data());
    size_t sig_len = 0;
    if (EVP_DigestSign(md.get(), nullptr, &sig_len, in, signing_input.size()) != 1)
        return "";
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md.get(), sig.data(), &sig_len, in, signing_input.size()) != 1)
        return "";
    sig.resize(sig_len);

    return signing_input + "." + OidcProvider::base64url_encode(sig);
}

TEST_CASE("OIDC: verify_jwt_signature accepts a valid RS256 signature and rejects tampering",
          "[oidc][jwt][security]") {
    // The load-bearing crypto round-trip: a token genuinely signed by the
    // private key whose public half is cached MUST verify, and the same token
    // with one flipped signature byte MUST be rejected. This exercises the real
    // jwk_to_pkey + EVP_DigestVerify path the #1856 fix now runs on every
    // platform — the earlier rejection-only tests never reach EVP.
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    auto jwt = sign_and_register_rs256(provider, "test-kid-1",
                                       R"({"sub":"alice","exp":9999999999})");
    REQUIRE_FALSE(jwt.empty()); // OpenSSL keygen/sign succeeded

    // Positive: genuine signature over the cached key verifies.
    auto ok = provider.verify_jwt_signature(jwt);
    CHECK(ok.has_value());

    // Negative: corrupt the first signature byte (top 6 bits of sig[0]) so the
    // decoded signature is definitively different → EVP must reject it.
    auto dot2 = jwt.rfind('.');
    REQUIRE(dot2 != std::string::npos);
    std::string forged = jwt;
    forged[dot2 + 1] = (forged[dot2 + 1] == 'A') ? 'B' : 'A';
    REQUIRE(forged != jwt);

    auto bad = provider.verify_jwt_signature(forged);
    REQUIRE_FALSE(bad.has_value()); // MUST NOT fail open
    CHECK(bad.error().find("forged") != std::string::npos);
}
