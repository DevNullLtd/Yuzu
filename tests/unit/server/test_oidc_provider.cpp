/**
 * test_oidc_provider.cpp — Unit tests for OidcProvider
 *
 * Covers: base64url encode/decode, PKCE code_verifier/code_challenge,
 * JWT parsing, claim validation, auth flow URL generation, state lifecycle.
 */

#include "oidc_provider.hpp"
#include "test_oidc_mock_idp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h> // EVP_RSA_gen

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace yuzu::server::oidc;

namespace {
// Joins its threads on scope exit after setting `abort` first, so a worker spinning on a
// barrier that a failed spawn (or a failing REQUIRE) left short cannot strand the join. Stands
// in for std::jthread/std::stop_token, which Apple Clang 15 (the documented floor) lacks.
class ScopedThreads {
public:
    ScopedThreads() = default;
    ScopedThreads(const ScopedThreads&) = delete;
    ScopedThreads& operator=(const ScopedThreads&) = delete;
    ~ScopedThreads() {
        abort_.store(true);
        join_all();
    }
    template <class F> void spawn(F&& f) { threads_.emplace_back(std::forward<F>(f)); }
    /// The flag a worker's barrier checks (`while (ready < n && !aborted())`).
    bool aborted() const { return abort_.load(); }
    /// The normal path: wait for every worker WITHOUT aborting any.
    void join_all() {
        for (auto& t : threads_)
            if (t.joinable())
                t.join();
    }

private:
    std::atomic<bool> abort_{false};
    std::vector<std::thread> threads_;
};
} // namespace

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

    const auto url = provider.start_auth_flow().url;

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
    const auto flow = provider.start_auth_flow();
    (void)flow;

    // Cleanup should not remove it (not yet expired)
    provider.cleanup_expired_states();

    // Try handle_callback with a bogus state — should fail with "unknown"
    auto result = provider.handle_callback("fakecode", "bogus-state", "any-secret");
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

    auto result = provider.handle_callback("code", "nonexistent-state", "any-secret");
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
    // No jwks_uri, no redirect_uri → validate-only: nothing is ever discovered or fetched.
    OidcProvider provider(std::move(cfg));

    auto jwt = make_jwt_with_header(R"({"alg":"RS256","kid":"nope","typ":"JWT"})",
                                    R"({"sub":"attacker","exp":9999999999})");

    auto result = provider.verify_jwt_signature(jwt);
    REQUIRE_FALSE(result.has_value()); // MUST NOT fail open
    CHECK(result.error() == OidcProvider::kJwksUnavailable);
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

// ── Initiating-browser binding ───────────────────────────────────────────────
//
// The callback must come from the browser that started the flow. These cases drive the provider
// with two "browsers" (two binding secrets) against one pending flow. A refusal must not consume
// the flow (the legitimate browser can still finish), and the check runs before any token
// exchange. Cases that reach the real httplib token client (even a refused connection) are
// compiled out under ThreadSanitizer: that client's glibc getaddrinfo_a worker thread crashes
// inside TSan's allocator (#438 class), so under TSan only the cases that reach no network run.

namespace {

OidcConfig binding_cfg(const std::string& token_endpoint = "http://127.0.0.1:1/token") {
    OidcConfig cfg;
    cfg.issuer = "https://idp.example.test";
    cfg.client_id = "yuzu-test-client";
    cfg.redirect_uri = "http://localhost:8443/auth/callback";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = token_endpoint;                    // :1 = connection refused, instantly
    // Explicit, and refused instantly: were the per-field rule ever to regress, the flow fails
    // here instead of reaching a real discovery fetch.
    cfg.jwks_uri = "http://127.0.0.1:1/jwks";
    return cfg;
}

bool is_lower_hex_64(const std::string& s) {
    if (s.size() != 64)
        return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

std::string state_of(const OidcProvider::AuthFlowStart& flow) {
    return yuzu::server::test::url_query_param(flow.url, "state");
}

/// Makes this provider's binding SHA-256 fail (the broken-crypto-provider branch) and always
/// restores it, even if an assertion throws.
struct DigestFailure {
    explicit DigestFailure(OidcProvider& p) : p_(p) { p_.set_binding_digest_failure_for_test(true); }
    ~DigestFailure() { p_.set_binding_digest_failure_for_test(false); }
    DigestFailure(const DigestFailure&) = delete;
    DigestFailure& operator=(const DigestFailure&) = delete;
    OidcProvider& p_;
};

} // namespace

TEST_CASE("OIDC binding: start_auth_flow returns a fresh 256-bit secret that is not in the URL",
          "[oidc][oidc_binding]") {
    OidcProvider provider(binding_cfg());
    const auto a = provider.start_auth_flow();
    const auto b = provider.start_auth_flow();
    CHECK(is_lower_hex_64(a.binding_secret));
    CHECK(is_lower_hex_64(b.binding_secret));
    CHECK(a.binding_secret != b.binding_secret);
    // The secret travels only as a cookie: never through the IdP, never in a URL.
    CHECK(a.url.find(a.binding_secret) == std::string::npos);
    CHECK(b.url.find(b.binding_secret) == std::string::npos);
    // ...and it is independent of state and nonce.
    CHECK(state_of(a) != a.binding_secret);
    CHECK(yuzu::server::test::url_query_param(a.url, "nonce") != a.binding_secret);
}

TEST_CASE("OIDC binding: a callback from another browser is refused and the flow stays pending",
          "[oidc][oidc_binding]") {
    OidcProvider provider(binding_cfg());
    const auto flow = provider.start_auth_flow();
    const auto state = state_of(flow);
    REQUIRE_FALSE(state.empty());

    // Browser B presents the flow's state with its own secret.
    for (int i = 0; i < 3; ++i) {
        bool verified = true;
        auto b = provider.handle_callback("code", state, std::string(64, 'b'), &verified);
        REQUIRE_FALSE(b.has_value());
        CHECK(b.error() == OidcProvider::kBrowserBindingMismatch);
        CHECK_FALSE(verified);
    }
    // Every refusal left the flow in place: it is still "pending" (a mismatch, not "unknown").
    auto again = provider.handle_callback("code", state, std::string(64, 'c'));
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error() == OidcProvider::kBrowserBindingMismatch);
}

TEST_CASE("OIDC binding: an empty or near-miss secret never matches", "[oidc][oidc_binding]") {
    OidcProvider provider(binding_cfg());
    const auto flow = provider.start_auth_flow();
    const auto state = state_of(flow);
    std::string flipped = flow.binding_secret;
    flipped[0] = flipped[0] == 'a' ? 'b' : 'a';
    std::string truncated = flow.binding_secret.substr(0, 63);
    std::string extended = flow.binding_secret + "0";
    for (const std::string& bad :
         {std::string{}, std::string(64, '0'), std::string("x"), flipped, truncated, extended}) {
        CAPTURE(bad);
        bool verified = true;
        auto r = provider.handle_callback("code", state, bad, &verified);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == OidcProvider::kBrowserBindingMismatch);
        CHECK_FALSE(verified);
    }
}

TEST_CASE("OIDC binding: a stored hash that is empty is never honoured", "[oidc][oidc_binding]") {
    OidcProvider provider(binding_cfg());
    provider.add_test_pending_flow("unbound-state", std::string{});
    for (const std::string& secret : {std::string{}, std::string("anything")}) {
        auto r = provider.handle_callback("code", "unbound-state", secret);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == OidcProvider::kBrowserBindingMismatch);
    }
}

TEST_CASE("OIDC binding: an unknown state is reported as unknown whatever the secret",
          "[oidc][oidc_binding]") {
    OidcProvider provider(binding_cfg());
    const auto flow = provider.start_auth_flow();
    bool verified = true;
    auto r = provider.handle_callback("code", "never-issued", flow.binding_secret, &verified);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kUnknownState);
    CHECK_FALSE(verified);
    // The refused attempts did not disturb the real pending flow.
    auto still = provider.handle_callback("code", state_of(flow), std::string(64, 'e'));
    REQUIRE_FALSE(still.has_value());
    CHECK(still.error() == OidcProvider::kBrowserBindingMismatch);
}

TEST_CASE("OIDC binding: a digest failure at start throws and a flow starts again afterwards",
          "[oidc][oidc_binding][oidc_hash_failure]") {
    // The seam fires in binding_digest, before sha256_raw runs, so this covers the caller's
    // fail-closed handling (a digest failure throws, as random_bytes() does). The failure of
    // each digest stage is covered separately in test_sha256_steps.cpp; the real OpenSSL and CNG
    // calls themselves cannot be made to fail from a test.
    OidcProvider provider(binding_cfg());
    {
        DigestFailure fail(provider);
        CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    }
    const auto flow = provider.start_auth_flow();
    CHECK(is_lower_hex_64(flow.binding_secret));
    CHECK(OidcProvider::compute_code_challenge("verifier-one") !=
          OidcProvider::compute_code_challenge("verifier-two"));
}

TEST_CASE("OIDC binding: a digest failure while checking the binding refuses and keeps the flow",
          "[oidc][oidc_binding][oidc_hash_failure]") {
    OidcProvider provider(binding_cfg());
    const auto flow = provider.start_auth_flow();
    const auto state = state_of(flow);
    {
        DigestFailure fail(provider);
        bool verified = true;
        // Even the CORRECT secret is refused when the digest cannot be computed: fail closed,
        // no exception escapes.
        auto r = provider.handle_callback("code", state, flow.binding_secret, &verified);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == OidcProvider::kBrowserBindingUnavailable);
        CHECK_FALSE(verified);
    }
    // The refusal did not consume the flow.
    auto after = provider.handle_callback("code", state, std::string(64, 'e'));
    REQUIRE_FALSE(after.has_value());
    CHECK(after.error() == OidcProvider::kBrowserBindingMismatch);
}

#ifndef YUZU_OIDC_MOCK_IDP_TSAN
// These cases reach exchange_code's token client (a loopback MockIdp, or a refused connection),
// so they are compiled out under ThreadSanitizer (see the section comment above).

TEST_CASE("OIDC binding: the matching secret passes the gate and the flow is single-use",
          "[oidc][oidc_binding]") {
    OidcProvider provider(binding_cfg()); // token endpoint refuses the connection instantly
    const auto flow = provider.start_auth_flow();
    const auto state = state_of(flow);
    bool verified = false;
    auto first = provider.handle_callback("code", state, flow.binding_secret, &verified);
    REQUIRE_FALSE(first.has_value());
    CHECK(verified); // a failure AFTER the match leaves the binding cookie spent
    // Past the binding gate: the failure is the token exchange, not the binding.
    CHECK(first.error() != OidcProvider::kBrowserBindingMismatch);
    CHECK(first.error().find("token endpoint") != std::string::npos);
    // Replay: consumed.
    auto replay = provider.handle_callback("code", state, flow.binding_secret);
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error() == OidcProvider::kUnknownState);
}

TEST_CASE("OIDC binding: end to end against a loopback IdP, a refusal never reaches the IdP and "
          "does not block the legitimate browser",
          "[oidc][oidc_binding]") {
    yuzu::server::test::MockIdp idp;
    const auto cfg = binding_cfg(idp.token_endpoint());
    OidcProvider provider(cfg);
    const auto flow = provider.start_auth_flow();
    const auto state = state_of(flow);
    const auto nonce = yuzu::server::test::url_query_param(flow.url, "nonce");
    REQUIRE_FALSE(nonce.empty());
    const auto jwt = yuzu::server::test::sign_and_register_rs256(
        provider, "kid-1", yuzu::server::test::id_token_payload(cfg, nonce));
    REQUIRE_FALSE(jwt.empty());
    idp.set_id_token(jwt);

    // A different browser: refused BEFORE any exchange,
    // with no secret and with a wrong one.
    for (const std::string& wrong : {std::string{}, std::string(64, 'e')}) {
        auto b = provider.handle_callback("other-code", state, wrong);
        REQUIRE_FALSE(b.has_value());
        CHECK(b.error() == OidcProvider::kBrowserBindingMismatch);
        CHECK(idp.token_calls.load() == 0);
    }

    // The initiating browser still completes the SAME flow.
    bool verified = false;
    auto a = provider.handle_callback("good-code", state, flow.binding_secret, &verified);
    REQUIRE(a.has_value());
    CHECK(verified);
    CHECK(a->sub == "alice-sub");
    CHECK(idp.token_calls.load() == 1);

    // Replay of the completed callback: refused, no second exchange.
    auto replay = provider.handle_callback("good-code", state, flow.binding_secret);
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error() == OidcProvider::kUnknownState);
    CHECK(idp.token_calls.load() == 1);
}
#endif // !YUZU_OIDC_MOCK_IDP_TSAN

// ── Discovery (#5692) ────────────────────────────────────────────────────────
//
// The provider reads the authorization/token/JWKS endpoints from the issuer's discovery document
// the first time a login needs them. Each case drives the real provider against a loopback
// MockIdp and counts the requests the IdP actually saw. Under ThreadSanitizer they are compiled
// out with the other cases that need an httplib acceptor thread (#438).

#ifndef YUZU_OIDC_MOCK_IDP_TSAN
namespace {

using yuzu::server::test::MockIdp;

OidcConfig discovery_cfg(const MockIdp& idp) {
    OidcConfig cfg;
    cfg.issuer = idp.base();
    cfg.client_id = "yuzu-test-client";
    cfg.redirect_uri = "http://localhost:8443/auth/callback";
    return cfg; // NO endpoints: every one comes from the discovery document
}

std::string signed_token(const OidcConfig& cfg, const std::string& kid,
                         const std::string& nonce = "n") {
    return yuzu::server::test::rs256_sign(kid,
                                          yuzu::server::test::id_token_payload(cfg, nonce));
}

} // namespace

TEST_CASE("OIDC discovery: all three endpoints come from the document and a full login works",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    OidcProvider provider(cfg);
    CHECK(idp.discovery_calls.load() == 0); // construction does no network

    const auto flow = provider.start_auth_flow();
    CHECK(flow.url.starts_with(idp.base() + "/authorize?"));
    const auto redirect = idp.follow_authorize(flow.url);
    REQUIRE(redirect.starts_with(cfg.redirect_uri + "?code=the-code&state="));

    auto claims = provider.handle_callback("the-code", yuzu::server::test::url_query_param(flow.url, "state"),
                                           flow.binding_secret);
    REQUIRE(claims.has_value()); // token endpoint AND jwks_uri were discovered
    CHECK(claims->sub == "alice-sub");
    CHECK(idp.discovery_calls.load() == 1); // one document, shared by all three needs
    CHECK(idp.token_calls.load() == 1);
    CHECK(idp.jwks_calls.load() == 1);
}

TEST_CASE("OIDC discovery: an explicitly configured field is authoritative and is never discovered",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    auto cfg = discovery_cfg(idp);
    cfg.authorization_endpoint = idp.base() + "/explicit-authorize";
    cfg.token_endpoint = idp.token_endpoint();
    cfg.jwks_uri = idp.base() + "/jwks";
    OidcProvider provider(cfg);

    const auto flow = provider.start_auth_flow();
    CHECK(flow.url.starts_with(idp.base() + "/explicit-authorize?"));
    auto jwt = signed_token(cfg, "mock-kid-1");
    REQUIRE(provider.verify_jwt_signature(jwt).has_value());
    CHECK(idp.discovery_calls.load() == 0); // zero GETs for the document

    SECTION("a partly explicit config discovers only the fields it lacks") {
        auto partial = discovery_cfg(idp);
        partial.authorization_endpoint = idp.base() + "/explicit-authorize";
        OidcProvider p2(partial);
        (void)p2.start_auth_flow();
        CHECK(idp.discovery_calls.load() == 0); // the one field the start needs was explicit
        REQUIRE(p2.verify_jwt_signature(jwt).has_value());
        CHECK(idp.discovery_calls.load() == 1); // jwks_uri was not
        CHECK(p2.start_auth_flow().url.starts_with(idp.base() + "/explicit-authorize?"));
    }
}

TEST_CASE("OIDC discovery: a validate-only provider (no redirect_uri) never touches the network",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    auto cfg = discovery_cfg(idp);
    cfg.redirect_uri.clear();
    OidcProvider provider(cfg);
    auto r = provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kJwksUnavailable);
    CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    CHECK(idp.discovery_calls.load() == 0);
    CHECK(idp.jwks_calls.load() == 0);
}

TEST_CASE("OIDC discovery: every defective document fails closed at start with the fixed token "
          "and stores no flow",
          "[oidc][oidc_discovery][security]") {
    struct Case {
        const char* name;
        std::function<void(MockIdp&)> knob;
        const char* detail; // a fragment of the operator-facing reason
    };
    const std::string big_doc_issuer = "https://elsewhere.example.test";
    const Case cases[] = {
        {"issuer mismatch", [&](MockIdp& m) { m.discovery_issuer = big_doc_issuer; },
         "issuer mismatch"},
        {"404", [](MockIdp& m) { m.discovery_status = 404; }, "HTTP 404"},
        {"500", [](MockIdp& m) { m.discovery_status = 500; }, "HTTP 500"},
        {"oversize body", [](MockIdp& m) { m.discovery_pad = 300 * 1024; }, "request failed"},
        {"redirect", [](MockIdp& m) { m.discovery_redirect = "/elsewhere"; }, "HTTP 302"},
        {"missing jwks_uri",
         [](MockIdp& m) {
             m.discovery_body = R"({"issuer":"ISS","authorization_endpoint":"ISS/a","token_endpoint":"ISS/t"})";
         },
         "no jwks_uri"},
        {"missing token_endpoint (start only needs the authorization endpoint)",
         [](MockIdp& m) {
             m.discovery_body = R"({"issuer":"ISS","authorization_endpoint":"ISS/a","jwks_uri":"ISS/j"})";
         },
         "no token_endpoint"},
        {"https endpoints under an http issuer",
         [](MockIdp& m) {
             m.discovery_body = R"({"issuer":"ISS","authorization_endpoint":"https://x.test/a","token_endpoint":"ISS/t","jwks_uri":"ISS/j"})";
         },
         "authorization_endpoint is not an absolute http URL"},
        {"relative endpoint",
         [](MockIdp& m) {
             m.discovery_body = R"({"issuer":"ISS","authorization_endpoint":"/a","token_endpoint":"ISS/t","jwks_uri":"ISS/j"})";
         },
         "authorization_endpoint is not an absolute http URL"},
    };
    for (const auto& c : cases) {
        CAPTURE(c.name);
        MockIdp idp;
        idp.with([&](MockIdp& m) {
            c.knob(m);
            // The placeholder ISS stands for this server's own base URL (known only after bind).
            for (std::size_t at; (at = m.discovery_body.find("ISS")) != std::string::npos;)
                m.discovery_body.replace(at, 3, m.base());
        });
        // The operator-facing validator (also behind Test Connection) says why.
        auto doc = OidcProvider::fetch_discovery_document(idp.base(), false);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(c.detail) != std::string::npos);
        // The login path gives only the fixed token, and stores nothing.
        OidcProvider provider(discovery_cfg(idp));
        try {
            (void)provider.start_auth_flow();
            FAIL("start_auth_flow must throw");
        } catch (const std::runtime_error& e) {
            CHECK(std::string(e.what()) == OidcProvider::kDiscoveryUnavailable);
        }
        CHECK(provider.pending_flow_count_for_test() == 0);
    }
}

TEST_CASE("OIDC discovery: a document missing a field this caller does not need is still refused",
          "[oidc][oidc_discovery][security]") {
    MockIdp idp;
    idp.with([](MockIdp& m) {
        // jwks_uri is present and is all this caller needs; token_endpoint is missing.
        m.discovery_body = R"({"issuer":"ISS","authorization_endpoint":"ISS/authorize","jwks_uri":"ISS/jwks"})";
        for (std::size_t at; (at = m.discovery_body.find("ISS")) != std::string::npos;)
            m.discovery_body.replace(at, 3, m.base());
    });
    auto cfg = discovery_cfg(idp);
    cfg.authorization_endpoint = idp.base() + "/authorize";
    OidcProvider provider(cfg);
    auto r = provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kJwksUnavailable);
    CHECK(idp.jwks_calls.load() == 0);
}

TEST_CASE("OIDC discovery: the negative cache expires - a failed attempt is retried once its window "
          "ends, and a recovered IdP is then cached",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_status = 500; });
    OidcProvider provider(discovery_cfg(idp));
    provider.set_discovery_negative_cache_for_test(0); // the window has already ended
    CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    CHECK(idp.discovery_calls.load() == 2);

    idp.with([](MockIdp& m) { m.discovery_status = 200; }); // the IdP recovers
    CHECK_NOTHROW(provider.start_auth_flow());
    CHECK(idp.discovery_calls.load() == 3);
    CHECK_NOTHROW(provider.start_auth_flow()); // the positive result is cached
    CHECK(idp.discovery_calls.load() == 3);
}

TEST_CASE("OIDC discovery: a failing JWKS refetch keeps the keys already cached",
          "[oidc][oidc_discovery][jwt]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    OidcProvider provider(cfg);
    REQUIRE(provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1")).has_value());
    idp.with([](MockIdp& m) { m.jwks_status = 503; }); // an outage begins
    (void)provider.verify_jwt_signature(signed_token(cfg, "never-published")); // failed refetch
    CHECK(idp.jwks_calls.load() == 2);
    // The failed attempt neither emptied the cache nor forces another fetch: known keys verify.
    CHECK(provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1")).has_value());
    CHECK(idp.jwks_calls.load() == 2);
}

TEST_CASE("OIDC discovery: a failed attempt is remembered, two logins inside the window cost ONE GET",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_status = 500; });
    OidcProvider provider(discovery_cfg(idp));
    CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    CHECK(idp.discovery_calls.load() == 1);
}

TEST_CASE("OIDC discovery: a slow IdP is cut off by the timeout seam, not a real 5 s wait",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_delay_ms = 150; });
    OidcProvider provider(discovery_cfg(idp));
    provider.set_http_timeouts_for_test(30);
    CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
    CHECK(provider.pending_flow_count_for_test() == 0);
}

TEST_CASE("OIDC discovery: concurrent logins share ONE discovery fetch (single-flight)",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_delay_ms = 60; }); // keep the first fetch in flight
    auto cfg = discovery_cfg(idp);
    cfg.authorization_endpoint = idp.base() + "/authorize"; // only jwks_uri is discovered
    cfg.token_endpoint = idp.token_endpoint();
    OidcProvider provider(cfg);
    const auto jwt = signed_token(cfg, "mock-kid-1");

    constexpr int kThreads = 8;
    std::atomic<int> ready{0};
    std::atomic<int> ok{0};
    std::atomic<int> refused{0};
    {
        ScopedThreads threads;
        for (int i = 0; i < kThreads; ++i)
            threads.spawn([&] {
                ready.fetch_add(1);
                // Abortable barrier: a failed spawn in this scope must not strand a waiter.
                while (ready.load() < kThreads && !threads.aborted())
                    std::this_thread::yield();
                if (threads.aborted())
                    return;
                auto r = provider.verify_jwt_signature(jwt);
                if (r.has_value())
                    ok.fetch_add(1);
                else if (r.error() == OidcProvider::kJwksUnavailable)
                    refused.fetch_add(1);
            });
        // Join before the guard's abort: the abort path is only for an exception unwinding here.
        threads.join_all();
    }
    // Exactly one fetch ran. A caller that arrived while it was in flight was refused with the
    // fixed token (it does not queue behind the fetch); the one that fetched succeeded.
    CHECK(idp.discovery_calls.load() == 1);
    CHECK(ok.load() >= 1);
    CHECK(ok.load() + refused.load() == kThreads);
    // Once the fetch is done the result is cached: every later caller succeeds, no new GET.
    CHECK(provider.verify_jwt_signature(jwt).has_value());
    CHECK(idp.discovery_calls.load() == 1);
}

TEST_CASE("OIDC discovery: a caller arriving mid-fetch fails fast instead of waiting for it",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    idp.hold_discovery(); // the first fetch stays in flight until THIS thread releases it
    OidcProvider provider(discovery_cfg(idp));

    std::atomic<bool> first_done{false};
    std::atomic<bool> first_ok{false};
    ScopedThreads threads;
    // Declared after `threads`, so it runs first on any exit: a failing REQUIRE must not leave
    // the held fetch blocking the join.
    struct ReleaseOnExit {
        MockIdp& idp;
        ~ReleaseOnExit() { idp.release_discovery(); }
    } release_on_exit{idp};
    threads.spawn([&] {
        try {
            first_ok.store(!provider.start_auth_flow().url.empty());
        } catch (const std::exception&) {}
        first_done.store(true);
    });
    // The mock counts a discovery GET the moment it arrives, so this is the in-flight signal.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (idp.discovery_calls.load() < 1 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    REQUIRE(idp.discovery_calls.load() == 1);

    try {
        (void)provider.start_auth_flow();
        FAIL("a caller arriving mid-fetch must be refused");
    } catch (const std::runtime_error& e) {
        CHECK(std::string(e.what()) == OidcProvider::kDiscoveryUnavailable);
    }
    // Refused while the first fetch was STILL running: the latch holds it, so it cannot have
    // finished however the threads were scheduled. No second GET was started.
    CHECK_FALSE(first_done.load());
    CHECK(idp.discovery_calls.load() == 1);
    idp.release_discovery();
    threads.join_all();
    CHECK(first_ok.load());
    // The refusal did not start a retry window: the next call sees the cached result.
    CHECK_NOTHROW(provider.start_auth_flow());
    CHECK(idp.discovery_calls.load() == 1);
}

TEST_CASE("OIDC discovery: signature checks use the discovered JWKS - an unknown kid refetches once, "
          "and a rotated kid then verifies",
          "[oidc][oidc_discovery][jwt]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    OidcProvider provider(cfg);

    REQUIRE(provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1")).has_value());
    CHECK(idp.jwks_calls.load() == 1);

    // A kid the IdP never published costs exactly ONE refetch. (Whether such a token is then
    // refused is #1901's front()-fallback question and is deliberately not pinned here.)
    (void)provider.verify_jwt_signature(signed_token(cfg, "never-published"));
    CHECK(idp.jwks_calls.load() == 2);

    // Rotation: the IdP now publishes kid-2; the first token under it triggers ONE refetch.
    idp.with([](MockIdp& m) { m.token_kid = "mock-kid-2"; });
    REQUIRE(provider.verify_jwt_signature(signed_token(cfg, "mock-kid-2")).has_value());
    CHECK(idp.jwks_calls.load() == 3);
    CHECK(idp.discovery_calls.load() == 1);
}

TEST_CASE("OIDC discovery: a JWKS that cannot be fetched is the fixed jwks token, never a pass",
          "[oidc][oidc_discovery][jwt][security]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    OidcProvider provider(cfg);
    idp.with([](MockIdp& m) { m.jwks_status = 500; });
    auto r = provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kJwksUnavailable);
}

TEST_CASE("OIDC discovery: a token for another audience is refused after a discovered login",
          "[oidc][oidc_discovery][security]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    idp.with([](MockIdp& m) { m.token_client_id = "some-other-client"; });
    OidcProvider provider(cfg);
    const auto flow = provider.start_auth_flow();
    REQUIRE_FALSE(idp.follow_authorize(flow.url).empty());
    auto r = provider.handle_callback("the-code", yuzu::server::test::url_query_param(flow.url, "state"),
                                      flow.binding_secret);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("aud mismatch") != std::string::npos);
}

TEST_CASE("OIDC discovery: discovery down at the callback is the fixed token and the flow is spent",
          "[oidc][oidc_discovery][security]") {
    MockIdp idp;
    auto cfg = discovery_cfg(idp);
    cfg.authorization_endpoint = idp.base() + "/authorize"; // the start does not need discovery
    idp.with([](MockIdp& m) { m.discovery_status = 503; });
    OidcProvider provider(cfg);
    const auto flow = provider.start_auth_flow();
    bool verified = false;
    auto r = provider.handle_callback("the-code", yuzu::server::test::url_query_param(flow.url, "state"),
                                      flow.binding_secret, &verified);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kDiscoveryUnavailable);
    CHECK(verified);
    CHECK(idp.token_calls.load() == 0);
    CHECK(provider.pending_flow_count_for_test() == 0); // the flow is spent
}

TEST_CASE("OIDC discovery: a JWKS that cannot be fetched at the callback is the fixed jwks token",
          "[oidc][oidc_discovery][security]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    OidcProvider provider(cfg);
    const auto flow = provider.start_auth_flow();
    REQUIRE_FALSE(idp.follow_authorize(flow.url).empty());
    idp.with([](MockIdp& m) { m.jwks_status = 500; });
    auto r = provider.handle_callback(
        "the-code", yuzu::server::test::url_query_param(flow.url, "state"), flow.binding_secret);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kJwksUnavailable);
    CHECK(idp.token_calls.load() == 1); // the code was exchanged; the signature check failed closed
}

// A server that sends one byte just inside every per-operation timeout defeats connect/read/write
// timeouts alone. Each GET also has a TOTAL bound of twice the per-operation timeout, so the
// answer is bounded however slowly the body arrives.
TEST_CASE("OIDC discovery: a trickling discovery document is cut at the total bound",
          "[oidc][oidc_discovery][security]") {
    MockIdp idp;
    idp.with([](MockIdp& m) {
        m.trickle_discovery = true;
        m.trickle_interval_ms = 40; // well inside the 250 ms read timeout below
        m.trickle_chunks = 100;     // 4 s of trickle if nothing cuts it
    });
    OidcProvider provider(discovery_cfg(idp));
    provider.set_http_timeouts_for_test(250); // so the total bound is 500 ms
    const auto begin = std::chrono::steady_clock::now();
    try {
        (void)provider.start_auth_flow();
        FAIL("a trickled document must not yield an authorization URL");
    } catch (const std::runtime_error& e) {
        CHECK(std::string(e.what()) == OidcProvider::kDiscoveryUnavailable);
    }
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    CHECK(elapsed >= std::chrono::milliseconds(450)); // it ran to the bound, not a quick error
    CHECK(elapsed < std::chrono::milliseconds(2000)); // and was cut there, not at 4 s
    CHECK(provider.pending_flow_count_for_test() == 0);
}

TEST_CASE("OIDC discovery: a trickling JWKS is cut at the total bound",
          "[oidc][oidc_discovery][security]") {
    MockIdp idp;
    const auto cfg = discovery_cfg(idp);
    OidcProvider provider(cfg);
    REQUIRE_NOTHROW(provider.start_auth_flow()); // discovery cached with the normal timeouts
    idp.with([](MockIdp& m) {
        m.trickle_jwks = true;
        m.trickle_interval_ms = 40;
        m.trickle_chunks = 100;
    });
    provider.set_http_timeouts_for_test(250);
    const auto begin = std::chrono::steady_clock::now();
    auto r = provider.verify_jwt_signature(signed_token(cfg, "mock-kid-1"));
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == OidcProvider::kJwksUnavailable);
    CHECK(elapsed >= std::chrono::milliseconds(450));
    CHECK(elapsed < std::chrono::milliseconds(2000));
}

TEST_CASE("OIDC discovery: a discovered endpoint with an absurd host is refused and the process "
          "survives",
          "[oidc][oidc_discovery][security]") {
    // 200 KB of host in each endpoint, served by a real IdP: the document fits the body cap, and
    // reaching httplib::Client's constructor with it would overflow the stack in its URL regex.
    const std::string huge(200 * 1024, 'a');
    for (const char* field : {"authorization_endpoint", "token_endpoint", "jwks_uri"}) {
        CAPTURE(field);
        MockIdp idp;
        idp.with([&](MockIdp& m) {
            nlohmann::json doc = {{"issuer", m.base()},
                                  {"authorization_endpoint", m.base() + "/authorize"},
                                  {"token_endpoint", m.base() + "/token"},
                                  {"jwks_uri", m.base() + "/jwks"}};
            doc[field] = "http://" + huge + "/x";
            m.discovery_body = doc.dump();
        });
        OidcProvider provider(discovery_cfg(idp));
        CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
        auto r = provider.verify_jwt_signature(signed_token(discovery_cfg(idp), "mock-kid-1"));
        CHECK_FALSE(r.has_value());
        CHECK(idp.jwks_calls.load() == 0);
    }
}

TEST_CASE("OIDC discovery: an issuer with a trailing slash builds one slash into the URL and "
          "matches a slash-bearing document issuer",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_issuer = m.base() + "/"; });
    auto cfg = discovery_cfg(idp);
    cfg.issuer = idp.base() + "/";
    OidcProvider provider(cfg);
    const auto flow = provider.start_auth_flow();
    CHECK(flow.url.starts_with(idp.base() + "/authorize?"));
    CHECK(idp.discovery_calls.load() == 1);
    CHECK(idp.discovery_path() == "/.well-known/openid-configuration"); // no double slash

    // The configured issuer must equal the document's byte for byte: without the slash it does not.
    OidcProvider other(discovery_cfg(idp)); // issuer WITHOUT the slash
    CHECK_THROWS_AS(other.start_auth_flow(), std::runtime_error);
}

TEST_CASE("OIDC discovery: an issuer with a path prefix is fetched under that prefix",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    for (const char* prefix : {"/realms/yuzu", "/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"}) {
        CAPTURE(prefix);
        const std::string issuer = idp.base() + prefix;
        idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });
        auto doc = OidcProvider::fetch_discovery_document(issuer, false);
        REQUIRE(doc.has_value());
        CHECK(idp.discovery_path() == std::string(prefix) + "/.well-known/openid-configuration");
        CHECK(doc->jwks_uri == idp.base() + "/jwks");
    }
}

TEST_CASE("OIDC http_get_bounded: a query on a bare-host URL is part of the path, not the host",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    // `http://127.0.0.1:<port>?x=1` is the authority `127.0.0.1:<port>` and the path "/?x=1".
    auto r = OidcProvider::http_get_bounded(idp.base() + "?x=1", false);
    REQUIRE(r.has_value());
    CHECK(*r == "root");
    CHECK(idp.root_target() == "/?x=1");
}

TEST_CASE("OIDC http_get_bounded: a #fragment is never put on the request line",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    // RFC 3986 3.5: the fragment is client-side only. A bare host with a fragment is the origin
    // and the path "/"; a path with a query and a fragment keeps the query only.
    auto bare = OidcProvider::http_get_bounded(idp.base() + "#frag", false);
    REQUIRE(bare.has_value());
    CHECK(idp.root_target() == "/");
    auto with_query = OidcProvider::http_get_bounded(idp.base() + "?a=b#frag?c", false);
    REQUIRE(with_query.has_value());
    CHECK(idp.root_target() == "/?a=b");
    auto jwks = OidcProvider::http_get_bounded(idp.base() + "/jwks#x", false);
    REQUIRE(jwks.has_value()); // the route is "/jwks": "/jwks#x" would not match it
    CHECK(idp.jwks_calls.load() == 1);
}

#ifndef _WIN32
// ── The total bound covers the TLS handshake (#5692, Gate 8) ─────────────────
//
// httplib's set_max_timeout only guards reads and writes on an established stream, so a server
// that accepts the TCP connection and drips TLS handshake bytes, each inside the per-operation
// timeout, used to hold a fetch for as long as it liked. `TlsDripServer` is a raw TCP acceptor (no
// certificate is needed: the handshake never completes) that sends a TLS record header declaring a
// body that never finishes, then one byte per `interval_ms`. Pacing and shutdown are
// condition-variable driven; the acceptor wakes on a self-pipe, so the destructor never waits out
// an interval or an accept().
class TlsDripServer {
public:
    explicit TlsDripServer(int interval_ms = 300) : interval_ms_(interval_ms) {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(listen_fd_ >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        REQUIRE(::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(listen_fd_, 8) == 0);
        socklen_t len = sizeof(addr);
        REQUIRE(::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
        port_ = ntohs(addr.sin_port);
        REQUIRE(::pipe(wake_) == 0);
        thread_ = std::thread([this] { run(); });
    }
    ~TlsDripServer() {
        release();
        const char b = 1;
        (void)::write(wake_[1], &b, 1);
        thread_.join();
        ::close(wake_[0]);
        ::close(wake_[1]);
        ::close(listen_fd_);
    }
    TlsDripServer(const TlsDripServer&) = delete;
    TlsDripServer& operator=(const TlsDripServer&) = delete;

    /// Stop dripping and hang up on the current connection (so a stuck client sees EOF).
    void release() {
        {
            std::lock_guard lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
    }

    int port() const { return port_; }
    std::string base() const { return "https://127.0.0.1:" + std::to_string(port_); }
    int accepted() const { return accepted_.load(); }

private:
    void run() {
        for (;;) {
            pollfd fds[2] = {{listen_fd_, POLLIN, 0}, {wake_[0], POLLIN, 0}};
            if (::poll(fds, 2, -1) < 0 && errno != EINTR)
                return;
            if (fds[1].revents != 0)
                return;
            if ((fds[0].revents & POLLIN) == 0)
                continue;
            const int conn = ::accept(listen_fd_, nullptr, nullptr);
            if (conn < 0)
                continue;
            accepted_.fetch_add(1);
            drip(conn);
            ::close(conn);
        }
    }
    // A TLS handshake record header (type 22, version 3.3) declaring 16 KiB, then one byte per
    // interval until the client hangs up or the server stops.
    void drip(int conn) {
#ifdef SO_NOSIGPIPE
        const int one = 1;
        ::setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#ifdef MSG_NOSIGNAL
        constexpr int kFlags = MSG_NOSIGNAL;
#else
        constexpr int kFlags = 0;
#endif
        static constexpr unsigned char header[5] = {0x16, 0x03, 0x03, 0x40, 0x00};
        if (::send(conn, header, sizeof(header), kFlags) < 0)
            return;
        for (;;) {
            std::unique_lock lk(mu_);
            if (cv_.wait_for(lk, std::chrono::milliseconds(interval_ms_), [this] { return stop_; }))
                return;
            lk.unlock();
            const unsigned char b = 0;
            if (::send(conn, &b, 1, kFlags) < 0)
                return;
        }
    }

    const int interval_ms_;
    int listen_fd_{-1};
    int wake_[2]{-1, -1};
    int port_{0};
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_{false};
    std::atomic<int> accepted_{0};
    std::thread thread_;
};

namespace {
// Runs `fn` on its own thread and waits for it for at most `limit`. If it overruns, the test
// fails (the red evidence on a build without the bound) instead of hanging the suite; `stop` is
// then called to release whatever `fn` is stuck on, and the thread is joined.
template <class Fn, class Stop>
bool finished_within(std::chrono::milliseconds limit, Fn&& fn, Stop&& stop) {
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    std::thread t([&] {
        fn();
        {
            std::lock_guard lk(m);
            done = true;
        }
        cv.notify_all();
    });
    bool finished;
    {
        std::unique_lock lk(m);
        finished = cv.wait_for(lk, limit, [&] { return done; });
    }
    if (!finished)
        stop();
    t.join();
    return finished;
}
} // namespace

TEST_CASE("OIDC discovery: an https server dripping TLS handshake bytes cannot hold a fetch past "
          "the total bound",
          "[oidc][oidc_discovery][security]") {
    TlsDripServer drip;
    // The per-operation timeout is 1 s and the drip is one byte per 300 ms, so the handshake
    // never trips a read timeout: only the total bound (2 s) can end it.
    std::expected<OidcProvider::DiscoveryDocument, std::string> doc;
    const auto begin = std::chrono::steady_clock::now();
    const bool in_time = finished_within(
        std::chrono::seconds(8),
        [&] { doc = OidcProvider::fetch_discovery_document(drip.base(), true, 1000); },
        [&] { drip.release(); });
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    CHECK(in_time); // false = the fetch outlived the bound by 6 s: the unbounded handshake
    CHECK_FALSE(doc.has_value());
    CHECK(elapsed >= std::chrono::seconds(1));
    CHECK(elapsed < std::chrono::seconds(3));
    CHECK(drip.accepted() >= 1);
}

TEST_CASE("OIDC discovery: the JWKS fetch is bounded the same way against a dripping https server",
          "[oidc][oidc_discovery][security]") {
    TlsDripServer drip;
    OidcConfig cfg;
    cfg.issuer = drip.base();
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    cfg.jwks_uri = drip.base() + "/jwks"; // explicit: the JWKS fetch is the one under test
    cfg.skip_tls_verify = true;
    OidcProvider provider(cfg);
    provider.set_http_timeouts_for_test(1000);
    const auto header = OidcProvider::base64url_encode(std::vector<uint8_t>{
        '{', '"', 'a', 'l', 'g', '"', ':', '"', 'R', 'S', '2', '5', '6', '"', '}'});
    const std::string jwt = header + ".e30.c2ln";

    std::expected<void, std::string> verdict;
    const auto begin = std::chrono::steady_clock::now();
    const bool in_time = finished_within(
        std::chrono::seconds(8), [&] { verdict = provider.verify_jwt_signature(jwt); },
        [&] { drip.release(); });
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    CHECK(in_time);
    REQUIRE_FALSE(verdict.has_value());
    CHECK(verdict.error() == OidcProvider::kJwksUnavailable);
    CHECK(elapsed >= std::chrono::seconds(1));
    CHECK(elapsed < std::chrono::seconds(3));
}

TEST_CASE("OIDC http_get_bounded: the watchdog does not cut a fast or a merely slow fetch",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    SECTION("a fast fetch succeeds, and returns at once (the watchdog is woken, not waited for)") {
        const auto begin = std::chrono::steady_clock::now();
        auto r = OidcProvider::http_get_bounded(idp.base() + "/jwks", false, 5000);
        const auto elapsed = std::chrono::steady_clock::now() - begin;
        REQUIRE(r.has_value());
        CHECK(elapsed < std::chrono::seconds(2)); // the bound here is 10 s
    }
    SECTION("a response that takes a third of the per-operation timeout is not shut down") {
        idp.with([](MockIdp& m) { m.discovery_delay_ms = 300; });
        auto doc = OidcProvider::fetch_discovery_document(idp.base(), false, 1000);
        REQUIRE(doc.has_value());
    }
}

#ifdef __linux__
namespace {
std::size_t open_fd_count() {
    std::size_t n = 0;
    for ([[maybe_unused]] const auto& e : std::filesystem::directory_iterator("/proc/self/fd"))
        ++n;
    return n;
}
} // namespace

TEST_CASE("OIDC http_get_bounded: fifty fetches leave the open descriptor count unchanged",
          "[oidc][oidc_discovery]") {
    MockIdp idp;
    // One fetch first, so lazily opened descriptors (resolver, locale, TLS) are already open.
    REQUIRE(OidcProvider::http_get_bounded(idp.base() + "/jwks", false, 2000).has_value());
    const auto before = open_fd_count();
    for (int i = 0; i < 50; ++i)
        REQUIRE(OidcProvider::http_get_bounded(idp.base() + "/jwks", false, 2000).has_value());
    // A refused connection and a failed (404) answer take the early-exit paths.
    for (int i = 0; i < 10; ++i) {
        CHECK_FALSE(OidcProvider::http_get_bounded("http://127.0.0.1:1/x", false, 2000));
        CHECK_FALSE(OidcProvider::http_get_bounded(idp.base() + "/nope", false, 2000));
    }
    const auto after = open_fd_count();
    CHECK(after == before);
}
#endif // __linux__
#endif // !_WIN32
#endif // !YUZU_OIDC_MOCK_IDP_TSAN

TEST_CASE("OIDC discovery: a refused connection fails closed", "[oidc][oidc_discovery][security]") {
    OidcConfig cfg;
    cfg.issuer = "http://127.0.0.1:1"; // connection refused, instantly
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    OidcProvider provider(cfg);
    try {
        (void)provider.start_auth_flow();
        FAIL("start_auth_flow must throw");
    } catch (const std::runtime_error& e) {
        CHECK(std::string(e.what()) == OidcProvider::kDiscoveryUnavailable);
    }
    CHECK(provider.pending_flow_count_for_test() == 0);
}

// These need no acceptor (a refused loopback port, or no network at all), so they also run under
// ThreadSanitizer, which is where the locking around the lazy discovery is exercised.
TEST_CASE("OIDC discovery: concurrent starts, signature checks and seam calls against a dead IdP "
          "all get the fixed errors",
          "[oidc][oidc_discovery][security]") {
    OidcConfig cfg;
    cfg.issuer = "http://127.0.0.1:1"; // connection refused, instantly
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    OidcProvider provider(cfg);
    provider.set_discovery_negative_cache_for_test(0); // every call really tries
    const auto header = OidcProvider::base64url_encode(std::vector<uint8_t>{
        '{', '"', 'a', 'l', 'g', '"', ':', '"', 'R', 'S', '2', '5', '6', '"', '}'});
    const std::string jwt = header + ".e30.c2ln";

    constexpr int kThreads = 8;
    constexpr int kRounds = 20;
    std::atomic<int> ready{0};
    std::atomic<int> bad{0};
    {
        ScopedThreads threads;
        for (int i = 0; i < kThreads; ++i)
            threads.spawn([&, i] {
                ready.fetch_add(1);
                while (ready.load() < kThreads && !threads.aborted())
                    std::this_thread::yield();
                for (int round = 0; round < kRounds && !threads.aborted(); ++round) {
                    try {
                        (void)provider.start_auth_flow();
                        bad.fetch_add(1); // must have thrown
                    } catch (const std::runtime_error& e) {
                        if (std::string(e.what()) != OidcProvider::kDiscoveryUnavailable)
                            bad.fetch_add(1);
                    }
                    auto r = provider.verify_jwt_signature(jwt);
                    if (r.has_value() || r.error() != OidcProvider::kJwksUnavailable)
                        bad.fetch_add(1);
                    // The seams take the same locks the calls above do.
                    if (i % 2 == 0) {
                        provider.set_discovery_negative_cache_for_test(0);
                        provider.set_http_timeouts_for_test(500 + round);
                    }
                    (void)provider.pending_flow_count_for_test();
                }
            });
        threads.join_all(); // before the guard's abort, which is only for an unwinding exception
    }
    CHECK(bad.load() == 0);
    CHECK(provider.pending_flow_count_for_test() == 0);
}

namespace {
// A discovery document for issuer `https://idp.test` with one endpoint replaced.
std::string doc_with(const char* field, const std::string& value) {
    nlohmann::json doc = {{"issuer", "https://idp.test"},
                          {"authorization_endpoint", "https://idp.test/a"},
                          {"token_endpoint", "https://idp.test/t"},
                          {"jwks_uri", "https://idp.test/j"}};
    doc[field] = value;
    return doc.dump();
}
} // namespace

TEST_CASE("OIDC discovery: an endpoint authority must be a well-formed host[:port]",
          "[oidc][oidc_discovery][security]") {
    const std::string iss = "https://idp.test";
    const auto accepted = [&](const std::string& value) {
        return OidcProvider::parse_discovery_document(doc_with("jwks_uri", value), iss).has_value();
    };
    const std::string huge(200 * 1024, 'a'); // a host this long overflows httplib's URL regex
    for (const char* field : {"authorization_endpoint", "token_endpoint", "jwks_uri"}) {
        CAPTURE(field);
        CHECK_FALSE(
            OidcProvider::parse_discovery_document(doc_with(field, "https://" + huge + "/x"), iss));
        CHECK_FALSE(OidcProvider::parse_discovery_document(
            doc_with(field, "https://" + std::string(254, 'a') + "/x"), iss)); // host > 253
    }
    CHECK(accepted("https://" + std::string(253, 'a') + "/x"));
    CHECK(accepted("https://idp.test:65535/x"));
    CHECK(accepted("https://idp.test:1/x"));
    CHECK(accepted("https://[::1]:8443/x"));
    CHECK(accepted("https://[2001:db8::1]/x"));
    CHECK(accepted("https://idp.test?x=1")); // authority ends at '?': the path is "/?x=1"
    CHECK(accepted("https://idp.test#frag"));
    CHECK_FALSE(accepted("https://idp.test:99999999999/x")); // does not fit an int
    CHECK_FALSE(accepted("https://idp.test:65536/x"));
    CHECK_FALSE(accepted("https://idp.test:100000/x")); // six digits
    CHECK_FALSE(accepted("https://idp.test:/x"));       // empty port
    CHECK_FALSE(accepted("https://idp.test:80a/x"));
    CHECK_FALSE(accepted("https://idp.test:80:81/x"));
    CHECK_FALSE(accepted("https://user:pw@idp.test/x")); // userinfo
    CHECK_FALSE(accepted("https://idp.test@evil.test/x"));
    CHECK_FALSE(accepted("https://idp.test\\evil.test/x")); // backslash
    CHECK_FALSE(accepted("https://:443/x"));                // empty host
    CHECK_FALSE(accepted("https://?x"));
    CHECK_FALSE(accepted("https://[::1/x")); // unterminated bracket
    CHECK_FALSE(accepted("https://[::1]x/x"));
    CHECK_FALSE(accepted("https://[zz]/x"));
    CHECK_FALSE(accepted("https://[]/x"));
    // The bracketed form is hex digits and ':' only, as httplib's regex is: a dotted IPv4-mapped
    // form would pass here and then be treated as a plain-http host name by httplib.
    CHECK_FALSE(accepted("https://[::ffff:1.2.3.4]/x"));
    CHECK_FALSE(accepted("https://[::ffff:1.2.3.4]:8443/x"));
    CHECK(accepted("https://[::ffff:102:304]/x"));
    // Port 0 names no listener; "00000" is the same value.
    CHECK_FALSE(accepted("https://idp.test:0/x"));
    CHECK_FALSE(accepted("https://idp.test:00000/x"));
    CHECK_FALSE(accepted("https://[::1]:0/x"));
    CHECK(accepted("https://idp.test:00080/x")); // leading zeros, still 80
}

TEST_CASE("OIDC discovery: an endpoint over 2048 bytes is refused, 2048 is accepted",
          "[oidc][oidc_discovery][security]") {
    const std::string iss = "https://idp.test";
    const std::string prefix = "https://idp.test/";
    const auto accepted = [&](std::size_t total) {
        return OidcProvider::parse_discovery_document(
                   doc_with("jwks_uri", prefix + std::string(total - prefix.size(), 'p')), iss)
            .has_value();
    };
    CHECK(accepted(2048));
    CHECK_FALSE(accepted(2049));
    CHECK_FALSE(accepted(4096));
}

TEST_CASE("OIDC discovery: an issuer that is too long or has no host is refused before any "
          "request",
          "[oidc][oidc_discovery][security]") {
    // Nothing listens anywhere: these must fail on the issuer alone, and never reach the client.
    CHECK_FALSE(
        OidcProvider::fetch_discovery_document("https://" + std::string(50000, 'a'), false));
    const auto too_long = "https://" + std::string(2048 - 8 + 1, 'a');
    REQUIRE(too_long.size() == 2049);
    auto r = OidcProvider::fetch_discovery_document(too_long, false);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("2048") != std::string::npos);
    for (const char* issuer : {"https://", "http://", "https:///x", "https://?x", "https://:443",
                               "https://user@idp.test"}) {
        CAPTURE(issuer);
        CHECK_FALSE(OidcProvider::fetch_discovery_document(issuer, false));
        CHECK_FALSE(OidcProvider::parse_discovery_document(
            doc_with("jwks_uri", "https://idp.test/j"), issuer));
    }
}

TEST_CASE("OIDC discovery: a URL with an absurd authority never reaches the HTTP client",
          "[oidc][oidc_discovery][security]") {
    const auto r =
        OidcProvider::http_get_bounded("https://" + std::string(200 * 1024, 'a') + "/x", false);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "not an http or https URL");
    CHECK_FALSE(OidcProvider::http_get_bounded("https://h:99999999999/x", false));
}

#ifndef _WIN32
// Windows posts the token request through WinHTTP, which has no httplib URL regex to overflow.
TEST_CASE("OIDC token exchange: a configured token endpoint with an impossible port is a failed "
          "callback, not a throw",
          "[oidc][oidc_discovery][security]") {
    for (const char* endpoint : {"https://idp.test:99999999999/token",
                                 "https://user@idp.test/token", "ftp://idp.test/t"}) {
        CAPTURE(endpoint);
        OidcConfig cfg;
        cfg.issuer = "https://idp.test";
        cfg.client_id = "c";
        cfg.redirect_uri = "http://localhost/cb";
        cfg.authorization_endpoint = "https://idp.test/authorize"; // the start needs no network
        cfg.token_endpoint = endpoint;
        OidcProvider provider(cfg);
        const auto flow = provider.start_auth_flow();
        auto r = provider.handle_callback(
            "code", yuzu::server::test::url_query_param(flow.url, "state"), flow.binding_secret);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("token endpoint") != std::string::npos);
    }
}
#endif

TEST_CASE("OIDC discovery: the discovery document's body-level defects are named and bounded",
          "[oidc][oidc_discovery][security]") {
    const std::string iss = "https://idp.test";
    const auto err = [&](const std::string& body) {
        auto r = OidcProvider::parse_discovery_document(body, iss);
        REQUIRE_FALSE(r.has_value());
        return r.error();
    };
    CHECK(err("").find("not valid JSON") != std::string::npos);
    CHECK(err("not json").find("not valid JSON") != std::string::npos);
    CHECK(err("[]").find("not a JSON object") != std::string::npos);
    CHECK(err("\"x\"").find("not a JSON object") != std::string::npos);
    CHECK(err("5").find("not a JSON object") != std::string::npos);
    CHECK(err(R"({"issuer":5})").find("issuer mismatch") != std::string::npos);
    CHECK(err(R"({"authorization_endpoint":"https://idp.test/a"})").find("issuer mismatch") !=
          std::string::npos); // no issuer at all
    nlohmann::json numeric = {{"issuer", iss},
                              {"authorization_endpoint", "https://idp.test/a"},
                              {"token_endpoint", "https://idp.test/t"},
                              {"jwks_uri", 5}};
    CHECK(err(numeric.dump()).find("no jwks_uri") != std::string::npos);

    SECTION("a 10 KB issuer with control bytes is bounded and neutralized in the error") {
        const std::string hostile = std::string("evil\r\nX: y\x01") + std::string(10 * 1024, 'z');
        nlohmann::json doc = {{"issuer", hostile}};
        const auto e = err(doc.dump());
        CHECK(e.size() < 400);
        for (const unsigned char c : e)
            CHECK((c >= 0x20 && c != 0x7f));
        // CR, LF, the space and the SOH byte each became '_': nothing raw reached the text.
        CHECK(e.find("evil__X:_y_") != std::string::npos);
    }
    SECTION("the cut never splits a UTF-8 sequence") {
        // 199 ASCII bytes then 2-byte characters: a byte cut at 200 would end mid-character.
        const std::string issuer = std::string(199, 'a') + "\xC3\xA9\xC3\xA9\xC3\xA9";
        nlohmann::json doc = {{"issuer", issuer}};
        const auto e = err(doc.dump());
        CHECK(e.find(std::string(199, 'a') + "\"") != std::string::npos); // cut before the first
        CHECK(e.find('\xC3') == std::string::npos);
    }
}

TEST_CASE("OIDC discovery: a control byte alone makes an endpoint unacceptable",
          "[oidc][oidc_discovery][security]") {
    const std::string iss = "https://idp.test";
    for (const char c : {'\r', '\n', '\t', '\x7f', '\x01', ' '}) {
        CAPTURE(static_cast<int>(c));
        CHECK_FALSE(OidcProvider::parse_discovery_document(
            doc_with("token_endpoint", std::string("https://idp.test/t") + c + "x"), iss));
    }
}

TEST_CASE("OIDC discovery: the Unicode line breaks NEL, U+2028 and U+2029 make an endpoint "
          "unacceptable",
          "[oidc][oidc_discovery][security]") {
    const std::string iss = "https://idp.test";
    for (const char* sep : {"\xC2\x85", "\xE2\x80\xA8", "\xE2\x80\xA9"}) {
        for (const char* field : {"authorization_endpoint", "token_endpoint", "jwks_uri"}) {
            CAPTURE(field, sep);
            CHECK_FALSE(OidcProvider::parse_discovery_document(
                doc_with(field, std::string("https://idp.test/p") + sep + "q"), iss));
        }
    }
    // Neighbouring code points that are NOT line breaks stay legal (U+00E9, U+2027, U+202A).
    for (const char* ok : {"\xC3\xA9", "\xE2\x80\xA7", "\xE2\x80\xAA", "\xC2\x84"}) {
        CAPTURE(ok);
        CHECK(OidcProvider::parse_discovery_document(
                  doc_with("jwks_uri", std::string("https://idp.test/p") + ok + "q"), iss)
                  .has_value());
    }
}

TEST_CASE("OIDC discovery: a configured issuer with a space or control byte is refused before any "
          "request",
          "[oidc][oidc_discovery][security]") {
    // Nothing listens anywhere: each must fail on the issuer's bytes alone.
    for (const std::string issuer :
         {std::string("https://idp.test\nX-Evil: 1"), std::string("https://idp.test\r\nx"),
          std::string("https://idp .test"), std::string("https://idp.test\x7f"),
          std::string("https://idp.test/realm\xE2\x80\xA8"),
          std::string("https://idp.test/realm\xC2\x85"),
          std::string("https://idp.test/realm\xE2\x80\xA9")}) {
        CAPTURE(issuer);
        auto r = OidcProvider::fetch_discovery_document(issuer, false);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("space or control") != std::string::npos);
    }
}

TEST_CASE("OIDC discovery: a configured endpoint with a space or control byte is refused, not sent",
          "[oidc][oidc_discovery][security]") {
    OidcConfig cfg;
    cfg.issuer = "https://idp.test";
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    cfg.authorization_endpoint = "https://idp.test/a b";
    OidcProvider provider(cfg);
    try {
        (void)provider.start_auth_flow();
        FAIL("a configured endpoint holding a space must be refused");
    } catch (const std::runtime_error& e) {
        CHECK(std::string(e.what()) == OidcProvider::kDiscoveryUnavailable);
    }
    CHECK(provider.pending_flow_count_for_test() == 0);

    cfg.authorization_endpoint = "https://idp.test/a\xE2\x80\xA8";
    OidcProvider separator(cfg);
    CHECK_THROWS_AS(separator.start_auth_flow(), std::runtime_error);
}

// The scheme rules for an HTTPS issuer cannot be driven through a loopback MockIdp (it has no
// TLS), so the validation half of discovery is pinned directly on a document body.
TEST_CASE("OIDC discovery: endpoints must be absolute and carry the issuer's own scheme",
          "[oidc][oidc_discovery][security]") {
    const auto doc = [](const std::string& iss, const std::string& auth) {
        return R"({"issuer":")" + iss + R"(","authorization_endpoint":")" + auth +
               R"(","token_endpoint":")" + iss + R"(/t","jwks_uri":")" + iss + R"(/j"})";
    };
    const std::string https = "https://idp.test/realm";
    const std::string http = "http://idp.test/realm";
    CHECK(OidcProvider::parse_discovery_document(doc(https, "https://idp.test/a"), https).has_value());
    CHECK(OidcProvider::parse_discovery_document(doc(http, "http://idp.test/a"), http).has_value());
    // Google-style: another host is fine, the scheme is what is pinned.
    CHECK(OidcProvider::parse_discovery_document(doc(https, "https://auth.other.test/a"), https)
              .has_value());
    // A downgrade (https issuer, http endpoint) and an upgrade (http issuer, https endpoint).
    CHECK_FALSE(OidcProvider::parse_discovery_document(doc(https, "http://idp.test/a"), https));
    CHECK_FALSE(OidcProvider::parse_discovery_document(doc(http, "https://idp.test/a"), http));
    // Relative, empty, scheme-less, no host, scheme in another case, embedded space/CR/LF.
    for (const char* bad : {"/a", "", "idp.test/a", "https:///a", "HTTPS://idp.test/a",
                            "https://idp.test/a b", "https://idp.test/a\\r\\nX: y"})
        CHECK_FALSE(OidcProvider::parse_discovery_document(doc(https, bad), https));
    // The issuer itself must be http or https (HTTPS:// is not recognized: byte-exact on purpose).
    CHECK_FALSE(OidcProvider::parse_discovery_document(doc("HTTPS://idp.test", "HTTPS://idp.test/a"),
                                                       "HTTPS://idp.test"));
}

TEST_CASE("OIDC test seams: no production file references set_binding_digest_failure_for_test, "
          "add_test_pending_flow, set_http_timeouts_for_test, "
          "set_discovery_negative_cache_for_test or pending_flow_count_for_test "
          "(source pin)",
          "[oidc][oidc_binding][source_pin]") {
    // The seams are public members of the production class and the first makes the binding
    // digest fail. Their only legitimate callers are tests; any file under server/core/src other
    // than the provider's own two that names them fails this pin.
    namespace fs = std::filesystem;
    static constexpr const char* kSeams[] = {"set_binding_digest_failure_for_test",
                                             "add_test_pending_flow",
                                             "set_http_timeouts_for_test",
                                             "set_discovery_negative_cache_for_test",
                                             "pending_flow_count_for_test"};
    std::size_t scanned = 0;
    const fs::path src_dir = fs::path(YUZU_SERVER_SRC_DIR);
    // The public headers live beside src/ (server/core/include/yuzu/server/).
    const fs::path include_dir = src_dir.parent_path() / "include" / "yuzu" / "server";
    const fs::path own_cpp = src_dir / "oidc_provider.cpp";
    const fs::path own_hpp = src_dir / "oidc_provider.hpp";
    std::vector<fs::path> files;
    for (const auto& root : {src_dir, include_dir}) {
        REQUIRE(fs::is_directory(root));
        for (const auto& e : fs::recursive_directory_iterator(root)) {
            if (!e.is_regular_file())
                continue;
            const auto ext = e.path().extension();
            if (ext == ".cpp" || ext == ".hpp" || ext == ".h" || ext == ".cc" || ext == ".inc")
                files.push_back(e.path());
        }
    }
    for (const auto& path : files) {
        ++scanned;
        // Exempt the provider's own two files by FULL path, not by basename.
        if (fs::equivalent(path, own_cpp) || fs::equivalent(path, own_hpp))
            continue;
        const auto name = path.filename().string();
        std::ifstream in(path, std::ios::binary);
        REQUIRE(in.is_open());
        std::ostringstream ss;
        ss << in.rdbuf();
        const auto text = ss.str();
        for (const char* seam : kSeams) {
            INFO(name << " references " << seam);
            CHECK(text.find(seam) == std::string::npos);
        }
    }
    CHECK(scanned > 100); // non-vacuity
}

TEST_CASE("OIDC discovery: the in-flight mark is set once, cleared only by an RAII guard created "
          "straight after it (source pin)",
          "[oidc][oidc_discovery][source_pin]") {
    // A throw between the mark and a manual clear (an allocation failure in a handler, say)
    // would leave every later caller failing fast until a Settings save. The handler path cannot
    // be driven from a test, so pin the shape that makes it safe by construction: ONE set, ONE
    // clear, the clear inside the guard's destructor, the guard declared right after the set.
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "oidc_provider.cpp",
                     std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    const auto text = ss.str();
    const auto count = [&](const std::string& needle) {
        std::size_t n = 0;
        for (auto pos = text.find(needle); pos != std::string::npos;
             pos = text.find(needle, pos + 1))
            ++n;
        return n;
    };
    CHECK(count("discovery_in_flight_ = true;") == 1);
    CHECK(count("discovery_in_flight_ = false;") == 0); // the guard clears it through a reference
    CHECK(count("flag = false;") == 1);
    const auto set_at = text.find("discovery_in_flight_ = true;");
    const auto guard_at = text.find("} in_flight_guard{lock, discovery_in_flight_};");
    REQUIRE(set_at != std::string::npos);
    REQUIRE(guard_at != std::string::npos);
    CHECK(guard_at > set_at);
    // Nothing that can throw between the set and the guard: only the guard's own definition.
    const auto between = text.substr(set_at, guard_at - set_at);
    CHECK(between.find("spdlog") == std::string::npos);
    CHECK(between.find("fetch_") == std::string::npos);
}
