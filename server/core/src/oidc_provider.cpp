#include "oidc_provider.hpp"
#include "oidc_vetted_host.hpp"

#include "evp_raii.hpp"
#include "oidc_abandoned_ledger.hpp"
#include "oidc_egress_policy.hpp"
#include "sha256_steps.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <cstdint>
#include <cstdio>
#include <array>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <typeinfo>
#include <utility>

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// OpenSSL is an unconditional server dependency on every platform (vcpkg.json;
// server/core/meson.build). RSA JWKS parsing and JWT signature verification use
// the OpenSSL EVP path on all platforms, including Windows (#1856/#1782). Include
// the OpenSSL headers before <windows.h> so OpenSSL's X509_NAME type is declared
// before wincrypt.h (pulled by windows.h) redefines X509_NAME as a macro.
#include <openssl/bn.h>
#include <openssl/crypto.h> // CRYPTO_memcmp: constant-time binding-hash compare
#include <openssl/evp.h>
#include <openssl/rand.h> // RAND_bytes — non-Windows random_bytes() only (Windows uses BCryptGenRandom)
#include <openssl/rsa.h>

#ifdef _WIN32
// clang-format off
#include <winsock2.h> // WSADuplicateSocketW / WSASocketW for RequestDeadlineWatchdog
#include <ws2tcpip.h> // GetAddrInfoExW / FreeAddrInfoExW for the egress resolver
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#endif

namespace yuzu::server::oidc {

// ── Base64 for HTTP Basic auth ───────────────────────────────────────────────

static std::string base64_encode(const std::string& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < input.size(); i += 3) {
        uint32_t n = static_cast<uint8_t>(input[i]) << 16;
        if (i + 1 < input.size())
            n |= static_cast<uint8_t>(input[i + 1]) << 8;
        if (i + 2 < input.size())
            n |= static_cast<uint8_t>(input[i + 2]);
        out += kAlphabet[(n >> 18) & 0x3F];
        out += kAlphabet[(n >> 12) & 0x3F];
        out += (i + 1 < input.size()) ? kAlphabet[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < input.size()) ? kAlphabet[n & 0x3F] : '=';
    }
    return out;
}

// ── Platform crypto (file-local) ─────────────────────────────────────────────

static std::vector<uint8_t> random_bytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    auto status = BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(n),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("BCryptGenRandom failed");
#else
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
#endif
    return buf;
}

static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    std::string out;
    out.reserve(v.size() * 2);
    for (auto b : v) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        out.append(buf, 2);
    }
    return out;
}

#ifdef _WIN32
namespace {
// File-local RAII owners for the two CNG handles CngSha256Ops opens: one owner per handle,
// released exactly once on every path including a throw.
class BcryptAlgHandle {
public:
    BcryptAlgHandle() = default;
    BcryptAlgHandle(const BcryptAlgHandle&) = delete;
    BcryptAlgHandle& operator=(const BcryptAlgHandle&) = delete;
    ~BcryptAlgHandle() {
        if (h_)
            BCryptCloseAlgorithmProvider(h_, 0);
    }
    BCRYPT_ALG_HANDLE* out() { return &h_; }
    BCRYPT_ALG_HANDLE get() const { return h_; }

private:
    BCRYPT_ALG_HANDLE h_ = nullptr;
};

class BcryptHashHandle {
public:
    BcryptHashHandle() = default;
    BcryptHashHandle(const BcryptHashHandle&) = delete;
    BcryptHashHandle& operator=(const BcryptHashHandle&) = delete;
    ~BcryptHashHandle() {
        if (h_)
            BCryptDestroyHash(h_);
    }
    BCRYPT_HASH_HANDLE* out() { return &h_; }
    BCRYPT_HASH_HANDLE get() const { return h_; }

private:
    BCRYPT_HASH_HANDLE h_ = nullptr;
};
} // namespace
#endif

namespace {
#ifdef _WIN32
// CNG stages for sha256_via_ops. `alg_` is declared before `hh_`, so the hash handle is
// destroyed first and the provider handle last, on success and on a throw alike.
class CngSha256Ops {
public:
    bool open() {
        return BCRYPT_SUCCESS(
            BCryptOpenAlgorithmProvider(alg_.out(), BCRYPT_SHA256_ALGORITHM, nullptr, 0));
    }
    bool create() {
        return BCRYPT_SUCCESS(BCryptCreateHash(alg_.get(), hh_.out(), nullptr, 0, nullptr, 0, 0));
    }
    bool update(const std::string& input) {
        // PUCHAR is a signature artefact: BCryptHashData only reads the input buffer.
        return BCRYPT_SUCCESS(
            BCryptHashData(hh_.get(), reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                           static_cast<ULONG>(input.size()), 0));
    }
    bool finish(std::vector<uint8_t>& out) {
        return BCRYPT_SUCCESS(
            BCryptFinishHash(hh_.get(), out.data(), static_cast<ULONG>(out.size()), 0));
    }

private:
    BcryptAlgHandle alg_;
    BcryptHashHandle hh_;
};
#else
// OpenSSL EVP stages for sha256_via_ops. `ctx_` is the single owner of the digest context.
class OpenSslSha256Ops {
public:
    bool open() {
        ctx_.reset(EVP_MD_CTX_new());
        return ctx_ != nullptr;
    }
    bool create() { return EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) == 1; }
    bool update(const std::string& input) {
        return EVP_DigestUpdate(ctx_.get(), input.data(), input.size()) == 1;
    }
    bool finish(std::vector<uint8_t>& out) {
        return EVP_DigestFinal_ex(ctx_.get(), out.data(), nullptr) == 1;
    }

private:
    EvpMdCtxPtr ctx_;
};
#endif
} // namespace

/// SHA-256 of `input`. THROWS (std::runtime_error, like `random_bytes` above) on ANY provider
/// failure, so a failed digest is reported, never returned as a value. The stage sequencing and
/// the throw live in `detail::sha256_via_ops` (sha256_steps.hpp), which a unit test drives with a
/// fake `Ops`.
static std::vector<uint8_t> sha256_raw(const std::string& input) {
#ifdef _WIN32
    CngSha256Ops ops;
#else
    OpenSslSha256Ops ops;
#endif
    return detail::sha256_via_ops(ops, input);
}

std::string OidcProvider::binding_digest(const std::string& secret) const {
    if (binding_digest_forced_failure_.load()) // test seam: the branch a provider failure takes
        throw std::runtime_error("SHA-256 failed");
    return bytes_to_hex(sha256_raw(secret));
}

void OidcProvider::set_binding_digest_failure_for_test(bool fail) {
    binding_digest_forced_failure_.store(fail);
}

void OidcProvider::add_test_pending_flow(const std::string& state, std::string binding_hash) {
    PkceChallenge pkce;
    pkce.code_verifier = "test-verifier";
    pkce.state = state;
    pkce.nonce = "test-nonce";
    pkce.binding_hash = std::move(binding_hash);
    pkce.redirect_uri = config_.redirect_uri;
    pkce.expires_at = std::chrono::steady_clock::now() + kChallengeTtl;
    std::lock_guard lock(mu_);
    pending_challenges_[state] = std::move(pkce);
}

// ── Base64URL ────────────────────────────────────────────────────────────────

std::string OidcProvider::base64url_encode(const std::vector<uint8_t>& data) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);

    for (std::size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size())
            n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size())
            n |= static_cast<uint32_t>(data[i + 2]);

        out += kAlphabet[(n >> 18) & 0x3F];
        out += kAlphabet[(n >> 12) & 0x3F];
        if (i + 1 < data.size())
            out += kAlphabet[(n >> 6) & 0x3F];
        if (i + 2 < data.size())
            out += kAlphabet[n & 0x3F];
    }
    // No padding (JWT convention)
    return out;
}

std::string OidcProvider::base64url_decode(const std::string& input) {
    // Convert base64url to standard base64 and decode
    std::string b64 = input;
    for (auto& c : b64) {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }
    // Add padding
    while (b64.size() % 4 != 0)
        b64 += '=';

    // Standard base64 decode
    static constexpr unsigned char kTable[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62,
        64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};

    std::string out;
    out.reserve(b64.size() * 3 / 4);
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : b64) {
        if (kTable[c] == 64)
            continue;
        val = (val << 6) | kTable[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// ── URL encoding ─────────────────────────────────────────────────────────────

std::string OidcProvider::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' ||
            c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return escaped.str();
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

std::string OidcProvider::generate_code_verifier() {
    auto bytes = random_bytes(32);
    return base64url_encode(bytes);
}

std::string OidcProvider::compute_code_challenge(const std::string& verifier) {
    auto hash = sha256_raw(verifier);
    return base64url_encode(hash);
}

// ── JWT parsing ──────────────────────────────────────────────────────────────

std::expected<IdTokenClaims, std::string> OidcProvider::parse_id_token(const std::string& jwt) {
    // Split on '.'
    auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos)
        return std::unexpected("invalid JWT: no dots");

    auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos)
        return std::unexpected("invalid JWT: only one dot");

    auto payload_b64 = jwt.substr(dot1 + 1, dot2 - dot1 - 1);
    auto payload_json = base64url_decode(payload_b64);

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(payload_json);
    } catch (const nlohmann::json::parse_error& e) {
        // The parser's text quotes the bytes it was reading (IdP-controlled): neutralize here, at
        // the point the string is built, so every sink that logs it is safe.
        return std::unexpected(std::string("JWT payload parse error: ") +
                               ::yuzu::log_key_token(e.what()));
    }

    // Every claim is read through a type guard. A signature-valid token
    // (attacker-controlled or merely non-conformant IdP) whose `sub` is a
    // number, or whose `iat` is a JSON string/float, must NOT throw an
    // uncaught nlohmann type_error out of parse_id_token — PR3 makes `iat`
    // load-bearing (it seeds the MFA step-up window), elevating a former
    // "noise" throw into a /auth/callback 500 (governance sec-M1 +
    // happy-path). Numeric claims are read via get<double>() + cast so a
    // float-encoded `iat`/`exp` (some IdPs emit `1700000000.0`) survives.
    IdTokenClaims claims;
    if (j.contains("sub") && j["sub"].is_string())
        claims.sub = j["sub"].get<std::string>();
    // ADR-2001 §1 — Entra's `oid` claim (the AAD object id). Not parsed
    // before this ADR; see `IdTokenClaims::oid`.
    if (j.contains("oid") && j["oid"].is_string())
        claims.oid = j["oid"].get<std::string>();
    if (j.contains("email") && j["email"].is_string())
        claims.email = j["email"].get<std::string>();
    if (j.contains("preferred_username") && j["preferred_username"].is_string())
        claims.preferred_username = j["preferred_username"].get<std::string>();
    if (j.contains("name") && j["name"].is_string())
        claims.name = j["name"].get<std::string>();
    if (j.contains("iss") && j["iss"].is_string())
        claims.iss = j["iss"].get<std::string>();
    if (j.contains("nonce") && j["nonce"].is_string())
        claims.nonce = j["nonce"].get<std::string>();
    // Clamp before the double→int64 cast: an out-of-range float (a
    // misconfigured/hostile IdP emitting `1e300`) would be UB on the cast.
    // In-range positive values only; anything else leaves the field at 0
    // (treated as missing — for `iat` that means "not seeded", for `exp`
    // it falls to the existing missing-exp path). Practically unreachable
    // on a signature-valid token; defense-in-depth (Gate 8 INFO).
    constexpr double kMaxEpoch = 9.0e18; // < int64 max (~9.22e18)
    if (j.contains("exp") && j["exp"].is_number()) {
        double v = j["exp"].get<double>();
        if (v > 0.0 && v < kMaxEpoch)
            claims.exp = static_cast<int64_t>(v);
    }
    if (j.contains("iat") && j["iat"].is_number()) {
        double v = j["iat"].get<double>();
        if (v > 0.0 && v < kMaxEpoch)
            claims.iat = static_cast<int64_t>(v);
    }
    if (j.contains("nbf") && j["nbf"].is_number()) {
        double v = j["nbf"].get<double>();
        if (v > 0.0 && v < kMaxEpoch)
            claims.nbf = static_cast<int64_t>(v);
    }

    // aud can be a string or array. An array is read through its first element only when that
    // element is a string; any other shape (empty, non-string first element, object) leaves
    // `aud` empty, which validate_claims refuses, rather than throwing.
    if (j.contains("aud")) {
        if (j["aud"].is_string()) {
            claims.aud = j["aud"].get<std::string>();
        } else if (j["aud"].is_array() && !j["aud"].empty() && j["aud"][0].is_string()) {
            claims.aud = j["aud"][0].get<std::string>();
        }
    }

    // groups claim: array of Entra security group object IDs. `groups_claim_present`
    // is set whenever the key exists at all (even an empty array) — that is what
    // lets the caller distinguish "IdP asserts zero groups" from "IdP omitted the
    // claim" below.
    if (j.contains("groups") && j["groups"].is_array()) {
        claims.groups_claim_present = true;
        for (auto& g : j["groups"])
            if (g.is_string())
                claims.groups.push_back(g.get<std::string>());
    }

    // Group overage (UP-1): Entra (and Graph-backed IdPs generally) OMIT the
    // `groups` claim entirely — replacing it with an indirection pointer —
    // once a user belongs to more groups than fit in the token (the
    // documented threshold is 200 for a v2.0 token with the default claim).
    // The overage pointer is a `_claim_names` object whose keys name the
    // overaged claims (`{"groups": "src1"}`), paired with a `_claim_sources`
    // object describing where to fetch them (e.g. the Graph `getMemberObjects`
    // endpoint). We key overage detection on `_claim_names.groups`
    // SPECIFICALLY: a bare `_claim_sources` (or a `_claim_names` naming some
    // OTHER overaged claim such as `roles`) does NOT mean the groups claim is
    // truncated, so it must not suppress a genuine groups deprovision. When
    // groups IS overaged, a caller MUST NOT read the (absent) `groups` array as
    // "this user is in zero groups", or a heavily-grouped legitimate user has
    // every one of their IdP-sourced RBAC memberships silently deleted on next
    // login (see `groups_claim_reconcilable`).
    if (j.contains("_claim_names") && j["_claim_names"].is_object() &&
        j["_claim_names"].contains("groups")) {
        claims.groups_overage = true;
    }

    // amr claim: RFC 8176 authentication-method references. Array of
    // strings per the spec; tolerate a lone string for non-conformant
    // IdPs. Consumed by /auth/callback to decide whether the IdP attested
    // a multi-factor login (see docs/auth-mfa-design.md "OIDC interop").
    if (j.contains("amr")) {
        if (j["amr"].is_array()) {
            for (auto& a : j["amr"])
                if (a.is_string())
                    claims.amr.push_back(a.get<std::string>());
        } else if (j["amr"].is_string()) {
            claims.amr.push_back(j["amr"].get<std::string>());
        }
    }

    return claims;
}

bool groups_claim_reconcilable(const IdTokenClaims& claims) {
    return claims.groups_claim_present && !claims.groups_overage;
}

std::expected<void, std::string>
OidcProvider::validate_claims(const IdTokenClaims& claims,
                              const std::string& expected_nonce) const {
    // Defensive: `iss` is compared against the configured issuer just below,
    // so an empty `iss` is already rejected UNLESS the operator somehow
    // configured an empty issuer — guard it explicitly rather than rely on
    // that coincidence.
    if (claims.iss.empty())
        return std::unexpected("missing iss claim");

    // `iss` is the other half of the stable principal `oidc:<iss>#<sub>` and,
    // like `sub` below, lands in the audit `principal` column. It is pinned to
    // the operator-configured issuer by the equality check just below (so it is
    // not attacker-controllable), but validate its length/bytes anyway as
    // defense-in-depth against a misconfigured issuer string and to keep the
    // principal well-formed. (Mirrors the `sub` validation.)
    constexpr std::size_t kMaxIssLength = 255;
    if (claims.iss.size() > kMaxIssLength)
        return std::unexpected("iss claim exceeds maximum length");
    for (unsigned char c : claims.iss) {
        if (c < 0x20 || c == 0x7F)
            return std::unexpected("iss claim contains control characters");
    }

    if (claims.iss != config_.issuer)
        return std::unexpected("iss mismatch: got '" + ::yuzu::log_key_token(claims.iss) +
                               "', expected '" + config_.issuer + "'");

    if (claims.aud != config_.client_id)
        return std::unexpected("aud mismatch: got '" + ::yuzu::log_key_token(claims.aud) +
                               "', expected '" + config_.client_id + "'");

    // #1837 governance follow-up — `sub` is now the authorization-load-
    // bearing half of the stable RBAC principal `oidc:<iss>#<sub>`
    // (auth_routes.cpp /auth/callback, AuthManager::create_oidc_session). An
    // IdP token that omits `sub` (or sends it empty/non-string —
    // parse_id_token leaves it as the default-constructed empty string in
    // that case) would collapse EVERY such login onto the single principal
    // `oidc:<iss>#`, and #1832's group-membership reconcile makes that
    // collision actively destructive (one user's login can deprovision
    // another's roles). `sub` also flows unsanitized into the audit
    // `principal` column (never through sanitize_detail_value, which is
    // reserved for `detail` fields) — a control/newline byte there is an
    // audit-log injection/readability hazard. Reject the token outright
    // (fail-closed: no session minted) rather than sanitizing-and-continuing,
    // since a legitimate IdP never sends a malformed `sub`.
    if (claims.sub.empty())
        return std::unexpected("missing sub claim");
    constexpr std::size_t kMaxSubLength = 255;
    if (claims.sub.size() > kMaxSubLength)
        return std::unexpected("sub claim exceeds maximum length");
    for (unsigned char c : claims.sub) {
        if (c < 0x20 || c == 0x7F)
            return std::unexpected("sub claim contains control characters");
    }

    // ADR-2001 §1 — `oid` enters the trust path (it becomes the SCIM join
    // key) ONLY when the operator selected it via `--oidc-scim-link-claim`.
    // Mirrors the `sub` validation immediately above EXACTLY (same length
    // cap, same control-byte rejection) — a malformed `oid` must be
    // rejected the way a malformed `sub` is, since both flow unsanitized
    // into a durable join key (`identity_links`/`oidc_login_observations`).
    // When `sub` is the configured link claim (the default), a
    // missing/empty `oid` is NOT an error — Okta and most non-Entra IdPs
    // never send it, and this claim is otherwise unused.
    if (config_.scim_link_claim == "oid") {
        if (claims.oid.empty())
            return std::unexpected("missing oid claim");
        constexpr std::size_t kMaxOidLength = 255;
        if (claims.oid.size() > kMaxOidLength)
            return std::unexpected("oid claim exceeds maximum length");
        for (unsigned char c : claims.oid) {
            if (c < 0x20 || c == 0x7F)
                return std::unexpected("oid claim contains control characters");
        }
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    constexpr int64_t kClockSkew = 60;
    // OIDC Core 1.0 §2 requires `exp`. A token with no (or non-positive)
    // exp must be rejected, not silently treated as never-expiring — the
    // prior `exp > 0 &&` guard let a missing/malformed exp skip the
    // expiry check entirely (governance Gate 8). `parse_id_token` leaves
    // `exp` at 0 when the claim is absent or not a positive number.
    if (claims.exp <= 0)
        return std::unexpected("missing or invalid exp claim");
    if (claims.exp + kClockSkew < now)
        return std::unexpected("token expired");
    // Reject a future-dated `iat` (Hermes A1/L-2). PR3 seeds the MFA
    // step-up window from `iat`; a grossly future-dated token is an
    // IdP-key-compromise lever. Use a GENEROUS future skew (not the tight
    // 60 s `exp` skew) — real IdP↔server NTP drift routinely exceeds 60 s,
    // and Okta/Entra default their own `iat`/`nbf` tolerance to ~300 s.
    // Rejecting at 60 s turned ordinary clock drift into a total SSO outage
    // (governance UP-D4). Within the window the future `iat` is clamped to
    // "now" during seeding anyway (auth_routes.cpp), so a generous bound
    // costs no freshness — it only rejects the clearly-forged case.
    constexpr int64_t kFutureSkew = 300;
    if (claims.iat > 0 && claims.iat > now + kFutureSkew)
        return std::unexpected("iat is in the future");
    // Honour `nbf` (RFC 7519 §4.1.5) if present — a pre-issued token must
    // not be accepted before its validity window (Hermes A3) — with the
    // same generous skew so NTP drift does not reject legitimate tokens.
    if (claims.nbf > 0 && claims.nbf > now + kFutureSkew)
        return std::unexpected("token not yet valid (nbf)");

    if (claims.nonce != expected_nonce)
        return std::unexpected("nonce mismatch");

    return {};
}

// ── IdP response size cap ────────────────────────────────────────────────────

namespace {
// The most bytes read from any IdP response: a discovery document, a JWKS (GET) and a token
// endpoint reply (POST on every platform) are a few KiB. The one definition for all of them.
constexpr std::size_t kHttpMaxBody = 256 * 1024;
} // namespace

// ── WinHTTP helper (Windows only) ────────────────────────────────────────────

#ifdef _WIN32
namespace {
// Owns the three HINTERNETs of one WinHTTP request. Declared session, connect, request, so the
// destructor closes them request first, then connect, then session, on every return path
// (early failure, the size cap and success alike). Move-only: a copy would double-close.
struct WinHttpHandles {
    HINTERNET session = nullptr;
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;

    WinHttpHandles() = default;
    WinHttpHandles(const WinHttpHandles&) = delete;
    WinHttpHandles& operator=(const WinHttpHandles&) = delete;
    WinHttpHandles(WinHttpHandles&& other) noexcept
        : session(std::exchange(other.session, nullptr)),
          connect(std::exchange(other.connect, nullptr)),
          request(std::exchange(other.request, nullptr)) {}
    WinHttpHandles& operator=(WinHttpHandles&&) = delete;
    ~WinHttpHandles() {
        if (request)
            WinHttpCloseHandle(request);
        if (connect)
            WinHttpCloseHandle(connect);
        if (session)
            WinHttpCloseHandle(session);
    }
};
} // namespace

// `vetted_host` is the host the egress policy classified (split_http_url's, brackets stripped):
// WinHTTP cannot pin an address, so the one thing this leg can still do is refuse to connect to a
// host other than the one that was vetted. WinHttpCrackUrl parses the URL a second time and a
// disagreement between the two parsers must fail closed, as the POSIX paths do (they compare
// `client->host()` with the vetted host).
static std::string winhttp_post(const std::string& url, const std::string& vetted_host,
                                unsigned vetted_port, const std::string& form_body,
                                const std::string& auth_header = {}) {
    // Parse URL into components
    // Expected: https://host/path
    std::wstring wurl(url.begin(), url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    // With no extra-info buffer WinHttpCrackUrl keeps the query ("?...") in the path component, so
    // a token endpoint with a query is requested as `path?query`; a test pins what the IdP receives
    // (including an empty path with a query, which arrives as `/?x=1`).
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        spdlog::error("WinHTTP: failed to crack URL: {}", ::yuzu::log_key_token(url));
        return {};
    }
    if (!cracked_endpoint_is_vetted(std::wstring_view(host, uc.dwHostNameLength),
                                    static_cast<unsigned>(uc.nPort), vetted_host, vetted_port)) {
        spdlog::error("WinHTTP: the URL's host or port is not the host and port the egress policy "
                      "vetted: {}",
                      ::yuzu::log_key_token(url));
        return {};
    }

    WinHttpHandles h;
    h.session = WinHttpOpen(L"Yuzu-Server/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session) {
        spdlog::error("WinHTTP: WinHttpOpen failed: {}", GetLastError());
        return {};
    }

    h.connect = WinHttpConnect(h.session, host, uc.nPort, 0);
    if (!h.connect) {
        spdlog::error("WinHTTP: WinHttpConnect failed: {}", GetLastError());
        return {};
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    h.request = WinHttpOpenRequest(h.connect, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!h.request) {
        spdlog::error("WinHTTP: WinHttpOpenRequest failed: {}", GetLastError());
        return {};
    }

    // Never follow a redirect. The token endpoint was vetted against the egress policy before
    // this call; WinHTTP's default policy would follow a 3xx to a host that was never vetted
    // (including an internal one). A 3xx is then refused by the status check after the response
    // arrives, so the sign-in fails closed. If the policy cannot be set, fail too.
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(h.request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy,
                          sizeof(redirect_policy))) {
        spdlog::error("WinHTTP: could not disable redirects: {}", GetLastError());
        return {};
    }

    // Add Authorization header if provided (HTTP Basic auth for client credentials)
    if (!auth_header.empty()) {
        std::wstring wauth(auth_header.begin(), auth_header.end());
        WinHttpAddRequestHeaders(h.request, wauth.c_str(), static_cast<DWORD>(wauth.size()),
                                 WINHTTP_ADDREQ_FLAG_ADD);
    }

    const wchar_t* content_type = L"Content-Type: application/x-www-form-urlencoded";
    BOOL ok = WinHttpSendRequest(h.request, content_type, -1L, const_cast<char*>(form_body.data()),
                                 static_cast<DWORD>(form_body.size()),
                                 static_cast<DWORD>(form_body.size()), 0);
    if (!ok) {
        spdlog::error("WinHTTP: WinHttpSendRequest failed: {}", GetLastError());
        return {};
    }

    ok = WinHttpReceiveResponse(h.request, nullptr);
    if (!ok) {
        spdlog::error("WinHTTP: WinHttpReceiveResponse failed: {}", GetLastError());
        return {};
    }

    // Only a 200 carries a token response (RFC 6749 section 5.1), as on the POSIX path. WinHTTP
    // hands the body of any status to the caller, so a 3xx (redirects are off) or an error status
    // with a well-formed body would otherwise be parsed as one. The status is a number, safe to
    // log.
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (!WinHttpQueryHeaders(h.request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
                             WINHTTP_NO_HEADER_INDEX)) {
        spdlog::error("WinHTTP: WinHttpQueryHeaders (status) failed: {}", GetLastError());
        return {};
    }
    if (status_code != 200) {
        spdlog::error("WinHTTP: token endpoint returned HTTP status {}", status_code);
        return {};
    }

    std::string response;
    for (;;) {
        // Reset every pass: a failed query must not leave the previous count behind and spin.
        DWORD bytes_available = 0;
        if (!WinHttpQueryDataAvailable(h.request, &bytes_available)) {
            spdlog::error("WinHTTP: WinHttpQueryDataAvailable failed: {}", GetLastError());
            return {};
        }
        if (bytes_available == 0)
            break;
        // Bound the allocation BEFORE it is made: response.size() <= kHttpMaxBody holds here (the
        // cap below fails the call as soon as it is exceeded), so the subtraction cannot wrap.
        if (bytes_available > kHttpMaxBody - response.size()) {
            spdlog::error("WinHTTP: response exceeds {} bytes, aborting", kHttpMaxBody);
            return {};
        }
        std::vector<char> buf(bytes_available);
        DWORD bytes_read = 0;
        if (!WinHttpReadData(h.request, buf.data(), bytes_available, &bytes_read)) {
            spdlog::error("WinHTTP: WinHttpReadData failed: {}", GetLastError());
            return {};
        }
        if (bytes_read == 0)
            break;
        response.append(buf.data(), bytes_read);
        // Same cap as the POSIX client: an oversize reply is a failure (empty), not a
        // reason to keep growing.
        if (response.size() > kHttpMaxBody) {
            spdlog::error("WinHTTP: response exceeds {} bytes, aborting", kHttpMaxBody);
            return {};
        }
    }

    spdlog::info("WinHTTP: POST {} -> {} bytes", ::yuzu::log_key_token(url), response.size());
    return response;
}
#endif

// ── IdP URL handling (#5692) ─────────────────────────────────────────────────

namespace {

// The longest endpoint (or issuer) accepted from an IdP document or the configuration.
constexpr std::size_t kMaxIdpUrlBytes = 2048;

// A well-formed `host[:port]` or `[ipv6][:port]` authority: no userinfo, no backslash, a host of
// 1..253 bytes, a port of 1..5 digits in 1..65535. httplib::Client's constructor runs a
// std::regex over the origin, which overflows the stack on a host of tens of thousands of bytes
// and throws on a port that does not fit an int, so this keeps such values away from it. The
// bracketed form takes hexadecimal digits and ':' only, the same class httplib's regex accepts
// (a dotted IPv4-mapped form such as [::ffff:1.2.3.4] is refused here: httplib would otherwise
// treat the whole string as a plain-http host name). The host is ASCII: an IDN is given as
// punycode.
bool authority_well_formed(std::string_view authority) {
    constexpr std::size_t kMaxHostBytes = 253;
    std::string_view host;
    std::string_view port;
    bool has_port = false;
    if (authority.starts_with('[')) {
        const auto close = authority.find(']');
        if (close == std::string_view::npos)
            return false;
        host = authority.substr(1, close - 1);
        for (const char c : host)
            if (!std::isxdigit(static_cast<unsigned char>(c)) && c != ':')
                return false;
        const auto after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after.front() != ':')
                return false;
            port = after.substr(1);
            has_port = true;
        }
    } else {
        const auto colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != std::string_view::npos) {
            port = authority.substr(colon + 1);
            has_port = true;
        }
        for (const char c : host)
            if (c == '@' || c == '\\' || c == '[' || c == ']')
                return false;
    }
    if (host.empty() || host.size() > kMaxHostBytes)
        return false;
    // ASCII only: the egress pre-check resolves the name as UTF-8, while the Windows token POST
    // widens each byte on its own, so a byte >= 0x80 could make the two ask for different names.
    // An internationalized name is configured in its punycode (xn--) form.
    for (const char c : host)
        if (static_cast<unsigned char>(c) >= 0x80)
            return false;
    if (has_port) {
        if (port.empty() || port.size() > 5)
            return false;
        unsigned value = 0;
        for (const char c : port) {
            if (c < '0' || c > '9')
                return false;
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value == 0 || value > 65535)
            return false;
    }
    return true;
}

// The `scheme://host[:port]` a httplib::Client wants and the request path (with its query).
struct HttpUrl {
    std::string origin;
    std::string host; // the authority's host, brackets stripped (what httplib connects to)
    std::string path;
    bool cleartext{}; // plain http (the egress policy refuses it to a public address)
};

// Splits "http(s)://authority[/path][?query][#fragment]" at the FIRST of '/', '?' or '#' after
// the scheme, so `https://host?x` has the authority `host` and the path "/?x" (never a host of
// "host?x"). A #fragment is never sent (RFC 3986 3.5: it is client-side only), so the path ends
// at the first '#': `https://host#f` has the path "/" and `https://h/jwks?a=b#x` has
// "/jwks?a=b". nullopt for anything that is not an http(s) URL with a well-formed authority.
std::optional<HttpUrl> split_http_url(const std::string& url) {
    std::string_view scheme;
    if (url.starts_with("https://")) {
        scheme = "https://";
    } else if (url.starts_with("http://")) {
        scheme = "http://";
    } else {
        return std::nullopt;
    }
    const std::string_view rest = std::string_view(url).substr(scheme.size());
    const auto end = rest.find_first_of("/?#");
    const auto authority = rest.substr(0, end);
    if (!authority_well_formed(authority))
        return std::nullopt;
    HttpUrl out;
    out.origin = std::string(scheme) + std::string(authority);
    out.cleartext = scheme == "http://";
    // authority_well_formed vouched for the shape: "[hex:colons]" or "host" before an optional
    // ":port". This is the same host httplib::Client's constructor extracts from the origin.
    out.host = std::string(authority.starts_with('[') ? authority.substr(1, authority.find(']') - 1)
                                                      : authority.substr(0, authority.find(':')));
    if (end == std::string_view::npos || rest[end] == '#') {
        out.path = "/";
        return out;
    }
    auto tail = rest.substr(end);
    tail = tail.substr(0, tail.find('#'));
    out.path = (tail.front() == '/') ? std::string(tail) : "/" + std::string(tail);
    return out;
}

// True when `s` holds a byte that could split a request line or a log line: a control byte or
// space (<= 0x20), DEL, or the UTF-8 form of NEL (U+0085), LINE SEPARATOR (U+2028) or PARAGRAPH
// SEPARATOR (U+2029), which line-oriented log readers treat as line breaks. The one predicate for
// every IdP-controlled or configured URL that is sent on the wire or logged.
bool has_line_splitting_bytes(std::string_view s) {
    for (std::size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c <= 0x20 || c == 0x7f)
            return true;
        const auto at = [&](std::size_t k) {
            return k < s.size() ? static_cast<unsigned char>(s[k]) : 0u;
        };
        if (c == 0xC2 && at(i + 1) == 0x85)
            return true;
        if (c == 0xE2 && at(i + 1) == 0x80 && (at(i + 2) == 0xA8 || at(i + 2) == 0xA9))
            return true;
    }
    return false;
}

// Cuts `s` to at most `max` bytes without splitting a UTF-8 sequence.
std::string_view truncate_utf8(std::string_view s, std::size_t max) {
    if (s.size() <= max)
        return s;
    std::size_t cut = max;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80)
        --cut;
    return s.substr(0, cut);
}

// ── Egress policy (oidc_egress_policy.hpp) ───────────────────────────────────

// The fixed reasons a vetted target is not connected to. None names a resolved address.
constexpr const char* kEgressRefusedReason = OidcProvider::kEgressRefused;
constexpr const char* kEgressCleartextPublicReason = OidcProvider::kEgressCleartextPublicRefused;
constexpr const char* kEgressUnresolvedReason = "the host name did not resolve";

// Decides where ONE fetch may connect, BEFORE any socket exists. A host that is an IP literal is
// classified directly (no DNS). Any other host (a name, or a numeric spelling the OS resolver
// might read differently, such as `127.1`) is resolved here, with httplib's own bounded resolver,
// and EVERY returned address is classified by its bytes. Returns the numeric addresses the
// connection may be PINNED to (the permitted ones, in resolver order, at most kMaxPinnedAddresses),
// or an EMPTY list when the host is an IP literal that needs no pin. A refusal or a resolver
// failure is a fixed reason (never the address, never resolver text). Pinning closes the window
// between this check and the connect: httplib is told to connect to that numeric address and does
// no second lookup, so a DNS answer that changes in between cannot redirect the request. The
// caller tries the permitted addresses in order while a connect fails (a host whose first address
// family is unreachable still works, as it did when httplib walked the resolver's list itself). TLS
// server-name indication and certificate verification keep using the host NAME (httplib keys them
// on the host, not on the pinned address).
constexpr std::size_t kMaxPinnedAddresses = 4;

// The test resolver (OidcProvider::set_resolver_for_test); empty in production.
std::mutex& test_resolver_mutex() {
    static std::mutex m;
    return m;
}
OidcProvider::ResolverForTest& test_resolver_slot() {
    static OidcProvider::ResolverForTest r;
    return r;
}

// One resolved address: its family and raw network-order bytes (4 or 16 used).
struct ResolvedAddress {
    int family{};
    std::array<unsigned char, 16> bytes{};
};

// Resolves `host` (a name, not a literal) to its IPv4 and IPv6 addresses within about
// `timeout_sec` seconds. False when the name did not resolve or the lookup timed out. Own
// function per platform because httplib's helper cannot be consumed generically: on Windows it
// returns a GetAddrInfoExW result cast to `addrinfo`, whose layout differs after ai_addr (the
// blob, blob length and provider fields precede ai_next) and which must be released with
// FreeAddrInfoExW, so walking it as `addrinfo` misses addresses and freeing it with freeaddrinfo
// is the wrong deleter.
#ifdef _WIN32
// One GetAddrInfoExW lookup. It owns a HANDLE and a resolver-allocated list, and the OS references
// it while the lookup is pending, so it may be destroyed only once the lookup has completed.
struct ResolverRequest {
    OVERLAPPED overlapped{};
    PADDRINFOEXW result{};
    HANDLE cancel{};
    std::wstring name;
    ResolverRequest() = default;
    ResolverRequest(const ResolverRequest&) = delete;
    ResolverRequest& operator=(const ResolverRequest&) = delete;
    ~ResolverRequest() {
        if (result != nullptr)
            ::FreeAddrInfoExW(result);
        if (overlapped.hEvent != nullptr)
            ::CloseHandle(overlapped.hEvent);
    }
};

// Process-wide owner of the lookups whose cancellation the resolver did not acknowledge in time
// (oidc_abandoned_ledger.hpp): such a request cannot be freed (the OS may still write into it) and
// must not be lost, so it moves here and is destroyed by a later sweep once its event is signaled.
// A slot is reserved before each lookup, so abandoned plus in-flight lookups never exceed
// kMaxAbandonedResolverRequests; when that many are stuck a new lookup fails closed ("did not
// resolve") instead of growing the set. The instance is never destroyed: exiting with a lookup
// still pending must not free memory the resolver may write to, and the OS reclaims it with the
// process.
constexpr std::size_t kMaxAbandonedResolverRequests = 16;

using ResolverLedger = ::yuzu::server::oidc::AbandonedRequestLedger<ResolverRequest>;

ResolverLedger& resolver_request_ledger() {
    static ResolverLedger& ledger =
        *new ResolverLedger(kMaxAbandonedResolverRequests, [](const ResolverRequest& r) {
            return ::WaitForSingleObject(r.overlapped.hEvent, 0) == WAIT_OBJECT_0;
        });
    return ledger;
}

bool resolve_host_addresses(const std::string& host, int timeout_sec,
                            std::vector<ResolvedAddress>& out) {
    auto& ledger = resolver_request_ledger();
    if (!ledger.try_reserve()) {
        spdlog::warn("OIDC egress: too many resolver lookups are stuck; refusing a new lookup");
        return false;
    }
    ResolverLedger::Slot slot(ledger);
    const int wide_len =
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host.c_str(), -1, nullptr, 0);
    if (wide_len <= 1)
        return false;
    auto request = std::make_unique<ResolverRequest>();
    request->name.assign(static_cast<std::size_t>(wide_len), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host.c_str(), -1, request->name.data(),
                              wide_len) <= 0)
        return false;
    request->overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (request->overlapped.hEvent == nullptr)
        return false;

    ADDRINFOEXW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc =
        ::GetAddrInfoExW(request->name.c_str(), L"0", NS_DNS, nullptr, &hints, &request->result,
                         nullptr, &request->overlapped, nullptr, &request->cancel);
    if (rc == WSA_IO_PENDING) {
        if (::WaitForSingleObject(request->overlapped.hEvent,
                                  static_cast<DWORD>(timeout_sec) * 1000U) != WAIT_OBJECT_0) {
            ::GetAddrInfoExCancel(&request->cancel);
            // The canceled lookup still completes into `overlapped` and `result`; they must
            // outlive that completion. It follows a cancel promptly, so wait for it briefly; if it
            // does not arrive, hand the request to the ledger, which frees it once the lookup
            // completes (a later lookup sweeps it), rather than free memory the resolver may still
            // write to.
            if (::WaitForSingleObject(request->overlapped.hEvent, 5000) != WAIT_OBJECT_0) {
                spdlog::warn("OIDC egress: the resolver did not acknowledge a canceled lookup; "
                             "the request is kept until it completes");
                slot.abandon(std::move(request));
            }
            return false;
        }
        rc = ::GetAddrInfoExOverlappedResult(&request->overlapped);
    }
    if (rc != NO_ERROR || request->result == nullptr)
        return false;
    // Walk the REAL list type: ADDRINFOEXW, whose ai_next sits after the blob fields.
    for (const ADDRINFOEXW* ai = request->result; ai != nullptr; ai = ai->ai_next) {
        ResolvedAddress address;
        // ai_family names the sockaddr type ai_addr points at (the documented Winsock contract),
        // and ai_addrlen is checked before the address bytes are read.
        if (ai->ai_family == AF_INET && ai->ai_addr != nullptr &&
            ai->ai_addrlen >= sizeof(sockaddr_in)) {
            address.family = AF_INET;
            std::memcpy(address.bytes.data(),
                        &reinterpret_cast<const sockaddr_in*>(ai->ai_addr)->sin_addr, 4);
            out.push_back(address);
        } else if (ai->ai_family == AF_INET6 && ai->ai_addr != nullptr &&
                   ai->ai_addrlen >= sizeof(sockaddr_in6)) {
            address.family = AF_INET6;
            std::memcpy(address.bytes.data(),
                        &reinterpret_cast<const sockaddr_in6*>(ai->ai_addr)->sin6_addr, 16);
            out.push_back(address);
        }
    }
    return true;
}
#else
bool resolve_host_addresses(const std::string& host, int timeout_sec,
                            std::vector<ResolvedAddress>& out) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;
    if (::httplib::detail::getaddrinfo_with_timeout(host.c_str(), "0", &hints, &result,
                                                    static_cast<time_t>(timeout_sec)) != 0 ||
        result == nullptr)
        return false;
    struct Freer {
        struct addrinfo* p;
        Freer(struct addrinfo* list) : p(list) {}
        Freer(const Freer&) = delete;
        Freer& operator=(const Freer&) = delete;
        ~Freer() { ::freeaddrinfo(p); }
    } freer{result};
    for (const struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
        ResolvedAddress address;
        // ai_family names the sockaddr type ai_addr points at (the documented BSD sockets
        // contract), and ai_addrlen is checked before the address bytes are read.
        if (ai->ai_family == AF_INET && ai->ai_addr != nullptr &&
            ai->ai_addrlen >= sizeof(sockaddr_in)) {
            address.family = AF_INET;
            std::memcpy(address.bytes.data(),
                        &reinterpret_cast<const sockaddr_in*>(ai->ai_addr)->sin_addr, 4);
            out.push_back(address);
        } else if (ai->ai_family == AF_INET6 && ai->ai_addr != nullptr &&
                   ai->ai_addrlen >= sizeof(sockaddr_in6)) {
            address.family = AF_INET6;
            std::memcpy(address.bytes.data(),
                        &reinterpret_cast<const sockaddr_in6*>(ai->ai_addr)->sin6_addr, 16);
            out.push_back(address);
        }
    }
    return true;
}
#endif

// ── NAT64 prefix discovery (RFC 7050) ────────────────────────────────────────
// A DNS64 resolver answers AAAA for `ipv4only.arpa` with the NAT64 prefix wrapped around the
// well-known 192.0.0.170/171; decoding that answer tells the policy which IPv6 addresses are
// really translated IPv4 destinations. Process-wide, because the prefix belongs to the network the
// server sits on and not to one provider. A failed or empty lookup is "none discovered", not a
// refusal: DNS64 is absent on most networks and a transient resolver error must not break every
// IPv6 destination.
//
// LEARNED PREFIXES NEVER SHRINK. The cache is a set that only grows: an answered refresh MERGES
// (set union, under the cache mutex) into it, so an empty, A-only or different answer adds nothing
// and removes nothing, and two concurrent refreshes cannot lose each other's entries. The TTLs
// below control only WHEN the name is looked up again, never what is retained: a prefix, once
// learned, is kept for the life of the process (a restart clears it). A resolver the attacker can
// influence therefore cannot make the server forget a translator it already saw.
//
// The set is bounded (kMaxDiscoveredNat64Prefixes). An answer that would take it past the bound is
// never installed partially: the fetch is REFUSED (kEgressNat64OverflowReason) until a later
// answer fits. A partial set would be a silent hole: the prefix that was cut off is the one the
// attacker wants unclassified.
constexpr const char* kNat64ProbeName = "ipv4only.arpa";
constexpr std::chrono::minutes kNat64PositiveTtl{10};
constexpr std::chrono::minutes kNat64NegativeTtl{1};
constexpr std::size_t kMaxDiscoveredNat64Prefixes = 64;
constexpr const char* kEgressNat64OverflowReason = OidcProvider::kEgressNat64Overflow;

struct Nat64DiscoveryCache {
    std::mutex mu;
    bool filled{false};
    // The latest answer would not fit under kMaxDiscoveredNat64Prefixes: fetches that need the
    // learned prefixes are refused until an answer fits.
    bool overflowed{false};
    std::chrono::steady_clock::time_point expires{};
    std::vector<::yuzu::server::oidc::egress::Nat64Prefix> prefixes;
};
Nat64DiscoveryCache& nat64_discovery_cache() {
    static Nat64DiscoveryCache c;
    return c;
}

// The IPv6 answers for `ipv4only.arpa`. False when the lookup failed or timed out (no answer at
// all); an answer with no IPv6 address is true and empty.
bool lookup_ipv4only_answers(int dns_timeout_ms,
                             std::vector<::yuzu::server::oidc::egress::Ipv6>& out) {
    namespace egress = ::yuzu::server::oidc::egress;
    OidcProvider::ResolverForTest test_resolver;
    {
        std::lock_guard lock(test_resolver_mutex());
        test_resolver = test_resolver_slot();
    }
    if (test_resolver) {
        for (const auto& text : test_resolver(kNat64ProbeName))
            if (text.find(':') != std::string::npos)
                if (const auto v6 = egress::parse_ipv6(text))
                    out.push_back(*v6);
        return true;
    }
    std::vector<ResolvedAddress> resolved;
    if (!resolve_host_addresses(kNat64ProbeName, std::max(1, (dns_timeout_ms + 999) / 1000),
                                resolved))
        return false;
    for (const auto& address : resolved)
        if (address.family == AF_INET6) {
            egress::Ipv6 bytes{};
            std::memcpy(bytes.data(), address.bytes.data(), bytes.size());
            out.push_back(bytes);
        }
    return true;
}

// The prefixes learned from `ipv4only.arpa`, from the cache while it is fresh. nullopt = the
// learned set overflowed (see above): the caller must refuse. The cache mutex is never held across
// the lookup (two concurrent lookups are harmless: their answers are merged).
std::optional<std::vector<::yuzu::server::oidc::egress::Nat64Prefix>>
discovered_nat64_prefixes(int dns_timeout_ms) {
    namespace egress = ::yuzu::server::oidc::egress;
    auto& cache = nat64_discovery_cache();
    {
        std::lock_guard lock(cache.mu);
        if (cache.filled && std::chrono::steady_clock::now() < cache.expires) {
            if (cache.overflowed)
                return std::nullopt;
            return cache.prefixes;
        }
    }
    std::vector<egress::Ipv6> answers;
    const bool answered = lookup_ipv4only_answers(dns_timeout_ms, answers);
    std::vector<egress::Nat64Prefix> found;
    for (const auto& answer : answers)
        if (const auto prefix = egress::discover_prefix_from_ipv4only_answer(answer))
            if (std::find(found.begin(), found.end(), *prefix) == found.end())
                found.push_back(*prefix);
    if (!answered)
        spdlog::warn("OIDC egress: the NAT64 prefix lookup (ipv4only.arpa) failed; IPv6 "
                     "destinations are classified without it until the lookup is retried");
    bool learned = false;
    bool overflow_now = false;
    std::optional<std::vector<egress::Nat64Prefix>> result;
    {
        std::lock_guard lock(cache.mu);
        if (answered) {
            // Union into what is already known; nothing is ever removed.
            std::vector<egress::Nat64Prefix> merged = cache.prefixes;
            for (const auto& prefix : found)
                if (std::find(merged.begin(), merged.end(), prefix) == merged.end())
                    merged.push_back(prefix);
            if (merged.size() > kMaxDiscoveredNat64Prefixes) {
                // Never a partial set: keep what was known, remember the overflow.
                overflow_now = !cache.overflowed;
                cache.overflowed = true;
            } else {
                learned = merged.size() > cache.prefixes.size();
                cache.prefixes = std::move(merged);
                cache.overflowed = false;
            }
        }
        // A failed lookup changes nothing (an earlier overflow stays in force).
        cache.filled = true;
        cache.expires = std::chrono::steady_clock::now() +
                        (answered && !cache.overflowed && !found.empty() ? kNat64PositiveTtl
                                                                         : kNat64NegativeTtl);
        if (!cache.overflowed)
            result = cache.prefixes;
    }
    if (overflow_now)
        spdlog::warn("OIDC egress: the NAT64 prefix answer for ipv4only.arpa would exceed {} "
                     "learned prefixes; fetches to IPv6 destinations are refused until an answer "
                     "fits",
                     kMaxDiscoveredNat64Prefixes);
    if (learned)
        spdlog::info("OIDC egress: learned {} NAT64 prefix(es) from ipv4only.arpa (RFC 7050); "
                     "IPv6 destinations inside them are classified by the IPv4 address they embed",
                     result ? result->size() : std::size_t{0});
    return result;
}

// `require_all_permitted` is for a caller that CANNOT pin the connect (the Windows token POST:
// WinHTTP does its own second lookup and may pick any member of the answer): ANY refused address
// in the answer then refuses the whole target, not only an answer with no permitted address. The
// default (false) keeps the pin-the-permitted semantics of the callers that do pin.
std::expected<std::vector<std::string>, const char*>
vet_egress_target(const std::string& host, bool allow_private, bool cleartext, int dns_timeout_ms,
                  std::span<const ::yuzu::server::oidc::egress::Nat64Prefix> nat64_prefixes,
                  bool require_all_permitted = false) {
    namespace egress = ::yuzu::server::oidc::egress;
    const auto refuse = [&](egress::AddressClass cls) -> std::unexpected<const char*> {
        // Plain http to a public address is refused whatever the switch says (a distinct reason).
        if (cleartext && cls == egress::AddressClass::Public) {
            spdlog::warn("OIDC egress: refused host '{}': plain http to a {} address (never "
                         "allowed; use an https URL)",
                         ::yuzu::log_key_token(host), egress::class_name(cls));
            return std::unexpected(kEgressCleartextPublicReason);
        }
        spdlog::warn("OIDC egress: refused host '{}': {} address{}", ::yuzu::log_key_token(host),
                     egress::class_name(cls),
                     egress::decision(cls, true) == egress::Verdict::Allow
                         ? " (permitted only with --oidc-allow-private-networks)"
                         : " (never allowed)");
        return std::unexpected(kEgressRefusedReason);
    };

    // The class of an IPv6 address: the configured NAT64 prefixes always apply; the learned ones
    // (RFC 7050) are looked up only for an address that would otherwise be permitted, because only
    // then can a hidden translation change the answer. An IPv4-only fetch never reaches this.
    // When the learned set overflowed (discovered_nat64_prefixes), the address is classed as
    // refused and the whole target fails with the distinct overflow reason below.
    std::optional<std::vector<egress::Nat64Prefix>> active_prefixes;
    bool nat64_overflow = false;
    const auto classify_v6 = [&](const egress::Ipv6& bytes) {
        const auto cls = egress::classify_ipv6(bytes, nat64_prefixes);
        if (egress::decision(cls, allow_private, cleartext) != egress::Verdict::Allow)
            return cls;
        if (!active_prefixes) {
            const auto learned_set = discovered_nat64_prefixes(dns_timeout_ms);
            if (!learned_set) {
                nat64_overflow = true;
                return egress::AddressClass::Reserved;
            }
            active_prefixes.emplace(nat64_prefixes.begin(), nat64_prefixes.end());
            for (const auto& learned : *learned_set)
                if (std::find(active_prefixes->begin(), active_prefixes->end(), learned) ==
                    active_prefixes->end())
                    active_prefixes->push_back(learned);
        }
        return egress::classify_ipv6(bytes, *active_prefixes);
    };
    const auto refuse_overflow = [&]() -> std::unexpected<const char*> {
        spdlog::warn("OIDC egress: refused host '{}': the learned NAT64 prefix set overflowed",
                     ::yuzu::log_key_token(host));
        return std::unexpected(kEgressNat64OverflowReason);
    };
    const auto classify_text = [&](const std::string& text) -> std::optional<egress::AddressClass> {
        if (text.find(':') != std::string::npos) {
            if (const auto v6 = egress::parse_ipv6(text))
                return classify_v6(*v6);
            return std::nullopt;
        }
        return egress::classify_literal(text);
    };

    if (const auto literal = classify_text(host)) {
        if (nat64_overflow)
            return refuse_overflow();
        if (egress::decision(*literal, allow_private, cleartext) != egress::Verdict::Allow)
            return refuse(*literal);
        return std::vector<std::string>{};
    }

    std::vector<std::string> pins;
    std::optional<egress::AddressClass> first_refused;
    const auto consider = [&](egress::AddressClass cls, const char* text) {
        if (egress::decision(cls, allow_private, cleartext) == egress::Verdict::Allow) {
            if (pins.size() < kMaxPinnedAddresses &&
                std::find(pins.begin(), pins.end(), text) == pins.end())
                pins.emplace_back(text);
        } else if (!first_refused) {
            first_refused = cls;
        }
    };

    OidcProvider::ResolverForTest test_resolver;
    {
        std::lock_guard lock(test_resolver_mutex());
        test_resolver = test_resolver_slot();
    }
    if (test_resolver) {
        for (const auto& text : test_resolver(host))
            if (const auto cls = classify_text(text))
                consider(*cls, text.c_str());
    } else {
        std::vector<ResolvedAddress> resolved;
        const int dns_timeout_sec = std::max(1, (dns_timeout_ms + 999) / 1000);
        if (!resolve_host_addresses(host, dns_timeout_sec, resolved) || resolved.empty())
            return std::unexpected(kEgressUnresolvedReason);
        for (const auto& address : resolved) {
            char text[INET6_ADDRSTRLEN] = {};
            if (address.family == AF_INET) {
                if (::inet_ntop(AF_INET, address.bytes.data(), text, sizeof(text)) != nullptr) {
                    egress::Ipv4 bytes{};
                    std::memcpy(bytes.data(), address.bytes.data(), bytes.size());
                    consider(egress::classify_ipv4(bytes), text);
                }
            } else if (address.family == AF_INET6) {
                if (::inet_ntop(AF_INET6, address.bytes.data(), text, sizeof(text)) != nullptr) {
                    egress::Ipv6 bytes{};
                    std::memcpy(bytes.data(), address.bytes.data(), bytes.size());
                    consider(classify_v6(bytes), text);
                }
            }
            // any other address family is never connected to
        }
    }
    if (nat64_overflow)
        return refuse_overflow();
    if (require_all_permitted && first_refused)
        return refuse(*first_refused);
    if (!pins.empty())
        return pins;
    if (first_refused)
        return refuse(*first_refused);
    return std::unexpected(kEgressUnresolvedReason);
}

} // namespace

// ── Token exchange ───────────────────────────────────────────────────────────

std::expected<std::string, std::string>
OidcProvider::exchange_code(const std::string& code, const std::string& code_verifier,
                            const std::string& redirect_uri) {
    auto token_endpoint = ensure_discovered(Need::Token);
    if (!token_endpoint)
        return std::unexpected(token_endpoint.error());

    std::string form_body = "grant_type=authorization_code"
                            "&code=" +
                            url_encode(code) + "&redirect_uri=" + url_encode(redirect_uri) +
                            "&code_verifier=" + url_encode(code_verifier);

    // RFC 6749 §2.3.1: confidential clients SHOULD use HTTP Basic auth
    // instead of sending client_secret in the POST body.
    std::string auth_header;
    if (!config_.client_secret.empty()) {
        auto credentials =
            base64_encode(config_.client_id + ":" + config_.client_secret);
        auth_header = "Authorization: Basic " + credentials;
    } else {
        // Public client: include client_id in body (no secret)
        form_body += "&client_id=" + url_encode(config_.client_id);
    }

    spdlog::info("OIDC token exchange: endpoint={} redirect_uri={}",
                 ::yuzu::log_key_token(*token_endpoint), redirect_uri);

    std::string response_body;

#ifdef _WIN32
    // Egress policy. WinHTTP resolves and connects on its own and offers no way to pin the
    // address, so this is a PRE-RESOLVE check only: the name is resolved and classified here,
    // then WinHTTP resolves it again and may pick ANY address of its answer. So the check is
    // STRICT: one refused address in the answer refuses the whole target (a mixed answer is not
    // pinned to its permitted member, as the httplib paths do). A DNS answer that changes between
    // the two lookups (DNS rebinding) is still NOT covered on this path; the httplib paths
    // (discovery, JWKS, and the token POST on Linux/macOS) pin the vetted address and have no such
    // window.
    const auto egress_target = split_http_url(*token_endpoint);
    if (!egress_target)
        return std::unexpected("invalid token endpoint URL");
    if (const auto vet = vet_egress_target(egress_target->host, config_.allow_private_networks,
                                           egress_target->cleartext, kHttpOperationTimeoutMs,
                                           config_.nat64_prefixes, /*require_all_permitted=*/true);
        !vet) {
        spdlog::error("OIDC token exchange: request refused: {}", vet.error());
        return std::unexpected(std::string("token endpoint request failed: ") + vet.error());
    }
    // Use WinHTTP on Windows — httplib's OpenSSL client fails from handler threads.
    // The vetted port comes from the same parse the vet used; WinHTTP cracks the URL again and
    // the two must agree (cracked_endpoint_is_vetted).
    const unsigned vetted_port =
        vetted_port_from_origin(egress_target->origin, egress_target->cleartext);
    response_body = winhttp_post(*token_endpoint, egress_target->host, vetted_port, form_body,
                                 auth_header);
    if (response_body.empty()) {
        spdlog::error("OIDC token exchange: WinHTTP POST failed");
        return std::unexpected("token endpoint request failed (WinHTTP)");
    }
#else
    const auto target = split_http_url(*token_endpoint);
    if (!target)
        return std::unexpected("invalid token endpoint URL");

    // Construction and the request can throw (httplib's URL regex, allocation): fail closed to
    // the same error a failed request gives rather than let it escape the callback route.
    int status_code = 0;
    std::string body_copy;
    std::string err_str;
    try {
        // Use heap-allocated client and explicit reset to work around httplib
        // 0.37.1 SSLClient destructor crash (invalid free in OpenSSL context
        // cleanup after HTTPS connections).
        // Egress policy: vet the target and pin the connect to a vetted address (the same
        // function the GETs use); nothing is sent to an address the policy refuses. A failed
        // CONNECT moves on to the next permitted address (no request was sent, so a retry is
        // safe); any other outcome is final.
        const auto pins =
            vet_egress_target(target->host, config_.allow_private_networks, target->cleartext,
                              kHttpOperationTimeoutMs, config_.nat64_prefixes);
        if (!pins) {
            spdlog::error("OIDC token exchange: request refused: {}", pins.error());
            return std::unexpected(std::string("token endpoint request failed: ") + pins.error());
        }
        const std::size_t attempts = std::max<std::size_t>(1, pins->size());
        for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
            auto client = std::make_unique<httplib::Client>(target->origin);
            if (client->host() != target->host)
                return std::unexpected(std::string("token endpoint request failed: ") +
                                       kEgressRefusedReason);
            if (!pins->empty())
                client->set_hostname_addr_map({{target->host, (*pins)[attempt]}});
            client->set_connection_timeout(10);
            client->set_read_timeout(15);
            client->set_write_timeout(15);
            client->set_payload_max_length(kHttpMaxBody);
            client->enable_server_certificate_verification(!config_.skip_tls_verify);
            httplib::Headers headers;
            if (!auth_header.empty())
                headers.emplace("Authorization", "Basic " + base64_encode(config_.client_id + ":" +
                                                                          config_.client_secret));
            auto result =
                client->Post(target->path, headers, form_body, "application/x-www-form-urlencoded");
            // Copy result data before destroying the client
            status_code = result ? result->status : 0;
            body_copy = result ? result->body : "";
            err_str = result ? "" : httplib::to_string(result.error());
            const bool connect_failed = !result && result.error() == httplib::Error::Connection;
            client.reset(); // Explicit destroy before any return
            if (!connect_failed)
                break;
        }
    } catch (const std::exception& e) {
        status_code = 0;
        err_str = std::string("exception: ") + ::yuzu::log_key_token(e.what());
    }

    if (status_code == 0) {
        spdlog::error("OIDC token exchange: httplib failed: {}", err_str);
        return std::unexpected("token endpoint request failed: " + err_str);
    }
    if (status_code != 200) {
        spdlog::error("OIDC token exchange: status={} body={}", status_code,
                      ::yuzu::log_key_token(body_copy.substr(0, 500)));
        return std::unexpected("token endpoint returned " + std::to_string(status_code));
    }
    response_body = std::move(body_copy);
#endif

    spdlog::info("OIDC token exchange: response_len={}", response_body.size());

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(response_body);
    } catch (const nlohmann::json::parse_error& e) {
        // The parser's text quotes IdP bytes, and so does the body: neutralize both.
        const auto what = ::yuzu::log_key_token(e.what());
        spdlog::error("OIDC token exchange: parse error: {} body={}", what,
                      ::yuzu::log_key_token(response_body.substr(0, 500)));
        return std::unexpected(std::string("token response parse error: ") + what);
    }

    if (j.contains("error")) {
        // IdP-controlled JSON: a non-string `error` / `error_description` is read as empty, never
        // thrown on (a 200 carrying an error body of the wrong type must still be a clean failure).
        const auto str_member = [&j](const char* key) {
            const auto it = j.find(key);
            return (it != j.end() && it->is_string()) ? it->get<std::string>() : std::string{};
        };
        auto err = str_member("error");
        auto desc = str_member("error_description");
        // `error` and `error_description` are IdP-controlled. Fold `err` where the returned string
        // is built so the caller's "OIDC callback failed: {}" line and event attribute are safe.
        const auto safe_err = ::yuzu::log_key_token(err);
        spdlog::error("OIDC token exchange error: {} - {}", safe_err,
                      ::yuzu::log_key_token(desc.substr(0, 300)));
        return std::unexpected("token endpoint error: " + safe_err);
    }

    if (!j.contains("id_token") || !j["id_token"].is_string())
        return std::unexpected("no id_token in token response");

    return j["id_token"].get<std::string>();
}

// ── JWKS fetching and JWT signature verification (G2-SEC-A1-001) ─────────────

// Convert base64url-encoded big-endian integer to BIGNUM
static BIGNUM* base64url_to_bn(const std::string& b64url) {
    auto bytes = OidcProvider::base64url_decode(b64url);
    return BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.data()),
                     static_cast<int>(bytes.size()), nullptr);
}

// Parse a single JWK (RSA public key) into an EVP_PKEY
static std::shared_ptr<EVP_PKEY> jwk_to_pkey(const nlohmann::json& jwk) {
    auto kty = jwk.value("kty", "");
    if (kty != "RSA")
        return nullptr; // only RSA keys supported

    auto n_str = jwk.value("n", "");
    auto e_str = jwk.value("e", "");
    if (n_str.empty() || e_str.empty())
        return nullptr;

    BIGNUM* bn_n = base64url_to_bn(n_str);
    BIGNUM* bn_e = base64url_to_bn(e_str);
    if (!bn_n || !bn_e) {
        BN_free(bn_n);
        BN_free(bn_e);
        return nullptr;
    }

    // Build RSA public key and wrap in EVP_PKEY.
    // RSA_new / RSA_set0_key / EVP_PKEY_assign_RSA are OSSL_DEPRECATEDIN_3_0.
    // Suppress the deprecation on every compiler now that this compiles on
    // Windows too (MSVC C4996; GCC/Clang -Wdeprecated-declarations). The GCC
    // pragma is guarded away from MSVC so it does not itself warn (C4068).
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    RSA* rsa = RSA_new();
    if (!rsa) {
        BN_free(bn_n);
        BN_free(bn_e);
        return nullptr;
    }
    if (RSA_set0_key(rsa, bn_n, bn_e, nullptr) != 1) {
        // On failure RSA_set0_key does NOT take ownership (it rejects before
        // assigning), so RSA_free won't touch the BIGNUMs — free them here to
        // avoid a leak.
        BN_free(bn_n);
        BN_free(bn_e);
        RSA_free(rsa);
        return nullptr;
    }
    // bn_n and bn_e now owned by rsa

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        return nullptr;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return nullptr;
    }
#if defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    // rsa now owned by pkey

    return std::shared_ptr<EVP_PKEY>(pkey, EVP_PKEY_free);
}

std::expected<std::vector<CachedJwk>, std::string> OidcProvider::parse_jwks(const std::string& body) {
    try {
        auto j = nlohmann::json::parse(body);
        if (!j.is_object() || !j.contains("keys") || !j["keys"].is_array())
            return std::unexpected("JWKS response missing 'keys' array");

        std::vector<CachedJwk> keys;
        // IdP-controlled JSON: one malformed key (not an object, or a `use`/`kid`/`alg` that is
        // not a string, or key material of the wrong type) is skipped and its siblings are kept;
        // only a structural error in the document fails the whole parse (the catch below).
        std::size_t index = 0;
        // Every sign-in now parses a fresh JWKS, so a hostile or broken IdP serving thousands of
        // malformed members would otherwise write that many warn lines PER SIGN-IN: log at most
        // kMaxSkipWarnings per document and one summary line for the rest.
        constexpr std::size_t kMaxSkipWarnings = 8;
        std::size_t skipped = 0;
        for (const auto& key : j["keys"]) {
            const std::size_t at = index++;
            const auto string_member = [&key](const char* name, const char* fallback,
                                              std::string& out) {
                const auto it = key.find(name);
                if (it == key.end()) {
                    out = fallback;
                    return true;
                }
                if (!it->is_string())
                    return false;
                out = it->get<std::string>();
                return true;
            };
            std::string use;
            CachedJwk cached;
            if (!key.is_object() || !string_member("use", "sig", use) ||
                !string_member("kid", "", cached.kid) ||
                !string_member("alg", "RS256", cached.alg)) {
                if (++skipped <= kMaxSkipWarnings)
                    spdlog::warn("OidcProvider: skipping JWK #{}: not an object or a use/kid/alg "
                                 "member that is not a string",
                                 at);
                continue;
            }
            if (use != "sig")
                continue;

            try {
                cached.pkey = jwk_to_pkey(key);
            } catch (const std::exception&) { // kty/n/e of the wrong type
                if (++skipped <= kMaxSkipWarnings)
                    spdlog::warn("OidcProvider: skipping JWK #{}: key material of the wrong type",
                                 at);
                continue;
            }
            if (!cached.pkey) {
                if (++skipped <= kMaxSkipWarnings)
                    spdlog::warn("OidcProvider: failed to parse JWK kid={}",
                                 ::yuzu::log_key_token(cached.kid));
                continue;
            }
            keys.push_back(std::move(cached));
        }
        if (skipped > kMaxSkipWarnings)
            spdlog::warn("OidcProvider: {} JWKs were skipped in total; only the first {} are "
                         "logged individually",
                         skipped, kMaxSkipWarnings);
        return keys;
    } catch (const std::exception& e) {
        return std::unexpected(std::string("JWKS parse error: ") + ::yuzu::log_key_token(e.what()));
    }
}

std::expected<std::vector<CachedJwk>, std::string> OidcProvider::fetch_jwks_snapshot() {
    // A fresh fetch on every call, returned to the caller and kept nowhere: a key the IdP no
    // longer publishes must stop verifying at the next sign-in, not after a cache expires
    // (#1901 UP-19). There is deliberately no cache and no stale-key fallback; a failed or
    // empty answer fails the sign-in closed.
    auto jwks_uri = ensure_discovered(Need::Jwks);
    if (!jwks_uri) {
        spdlog::warn("OidcProvider: discovery is unavailable, cannot fetch signing keys");
        return std::unexpected(std::string(kJwksUnavailable));
    }

    spdlog::info("OidcProvider: fetching JWKS from {}", ::yuzu::log_key_token(*jwks_uri));
    auto body = http_get_bounded(*jwks_uri, config_.skip_tls_verify, config_.allow_private_networks,
                                 http_timeout_ms_.load(), config_.nat64_prefixes);
    if (!body) {
        spdlog::error("OidcProvider: JWKS fetch failed: {}", body.error());
        return std::unexpected(std::string(kJwksUnavailable));
    }
    auto keys = parse_jwks(*body);
    if (!keys) {
        spdlog::error("OidcProvider: {}", ::yuzu::log_key_token(keys.error()));
        return std::unexpected(std::string(kJwksUnavailable));
    }
    spdlog::info("OidcProvider: fetched {} JWKS signing keys", keys->size());
    return keys;
}

std::expected<void, std::string> OidcProvider::verify_jwt_signature(const std::string& jwt) {
    // Split JWT into header.payload.signature
    auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos)
        return std::unexpected("invalid JWT: no dots");
    auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos)
        return std::unexpected("invalid JWT: only one dot");

    // Parse the header to extract alg and kid
    auto header_json = base64url_decode(jwt.substr(0, dot1));

    nlohmann::json hdr;
    try {
        hdr = nlohmann::json::parse(header_json);
    } catch (...) {
        return std::unexpected("JWT header parse error");
    }

    // IdP-controlled JSON: a header that is not an object, or whose `alg` / `kid` is not a string,
    // is a clean verification failure (an empty `alg` is refused just below), never a throw.
    if (!hdr.is_object())
        return std::unexpected("JWT header is not an object");
    const auto header_string = [&hdr](const char* key) {
        const auto it = hdr.find(key);
        return (it != hdr.end() && it->is_string()) ? it->get<std::string>() : std::string{};
    };
    auto alg = header_string("alg");
    auto kid = header_string("kid");
    // A kid member that is present but not a non-empty string is malformed: refuse it rather
    // than let it fall through to the no-kid first-key path below.
    if (const auto kid_it = hdr.find("kid"); kid_it != hdr.end() && kid.empty())
        return std::unexpected("JWT kid is not a non-empty string");

    // Reject alg:none — the classic JWT bypass attack
    if (alg.empty() || alg == "none" || alg == "None" || alg == "NONE")
        return std::unexpected("JWT algorithm 'none' is not allowed");

    // Only RS256/RS384/RS512 supported (Entra ID uses RS256)
    if (alg != "RS256" && alg != "RS384" && alg != "RS512")
        return std::unexpected("unsupported JWT algorithm: " + ::yuzu::log_key_token(alg));

    // The key set for THIS verification: a fresh fetch (or the keys a test injected), never a
    // set kept from an earlier sign-in.
    std::vector<CachedJwk> keys;
    {
        std::lock_guard lock(jwks_mu_);
        keys = test_jwks_keys_;
    }
    if (keys.empty()) {
        auto fetched = fetch_jwks_snapshot();
        if (!fetched)
            return std::unexpected(fetched.error());
        keys = std::move(*fetched);
    }

    // A token that names a kid is checked against the key with that kid only; one that names a
    // kid the key set does not hold is refused, never checked against another key. A token with
    // NO kid member uses the first key (some IdPs do not set kid).
    std::shared_ptr<EVP_PKEY> pkey;
    for (const auto& k : keys) {
        if (!kid.empty() && k.kid == kid) {
            pkey = k.pkey;
            break;
        }
    }
    if (!pkey && kid.empty() && !keys.empty())
        pkey = keys.front().pkey;
    if (!pkey) {
        if (kid.empty())
            spdlog::warn("OidcProvider: the token has no kid and the fetched key set has no usable "
                         "key");
        else
            spdlog::warn("OidcProvider: the token names kid={}, which the fetched key set does not "
                         "hold",
                         ::yuzu::log_key_token(kid));
        return std::unexpected("no matching JWKS key found for kid=" + ::yuzu::log_key_token(kid));
    }

    // The signing input is "header.payload" (first two base64url segments verbatim)
    auto signing_input = jwt.substr(0, dot2);

    // Decode the signature (third segment)
    auto sig_bytes = base64url_decode(jwt.substr(dot2 + 1));

    // Select hash algorithm
    const EVP_MD* md = nullptr;
    if (alg == "RS256")
        md = EVP_sha256();
    else if (alg == "RS384")
        md = EVP_sha384();
    else if (alg == "RS512")
        md = EVP_sha512();

    // Verify the signature
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return std::unexpected("EVP_MD_CTX_new failed");

    int rc = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey.get());
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected("EVP_DigestVerifyInit failed");
    }

    rc = EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size());
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected("EVP_DigestVerifyUpdate failed");
    }

    rc = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(sig_bytes.data()),
                               sig_bytes.size());
    EVP_MD_CTX_free(ctx);

    if (rc != 1)
        return std::unexpected("JWT signature verification failed — token may be forged");

    spdlog::debug("OidcProvider: JWT signature verified (alg={}, kid={})",
                  ::yuzu::log_key_token(alg), ::yuzu::log_key_token(kid));
    return {};
}

bool OidcProvider::add_test_jwks_key(const std::string& kid, const std::string& n_b64url,
                                     const std::string& e_b64url) {
    // Reuse the real JWK→EVP_PKEY parser so tests exercise the same code the
    // production JWKS fetch does.
    nlohmann::json jwk = {{"kty", "RSA"}, {"n", n_b64url}, {"e", e_b64url}};
    auto pkey = jwk_to_pkey(jwk);
    if (!pkey)
        return false;

    CachedJwk cached;
    cached.kid = kid;
    cached.alg = "RS256";
    cached.pkey = std::move(pkey);

    // While any injected key exists, verify_jwt_signature uses exactly the injected keys and
    // makes no network fetch.
    std::lock_guard lock(jwks_mu_);
    test_jwks_keys_.push_back(std::move(cached));
    return true;
}

#ifdef _WIN32
bool OidcProvider::winhttp_url_agrees_for_test(const std::string& url) {
    const auto target = split_http_url(url);
    if (!target)
        return false; // refused before WinHTTP is ever reached
    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc))
        return false;
    return cracked_endpoint_is_vetted(std::wstring_view(host, uc.dwHostNameLength),
                                      static_cast<unsigned>(uc.nPort), target->host,
                                      vetted_port_from_origin(target->origin, target->cleartext));
}
#endif

// ── Discovery (#5692) ────────────────────────────────────────────────────────

namespace {

// The scheme prefix of an http(s) issuer ("" when it is neither); case-sensitive on purpose.
std::string_view issuer_scheme(std::string_view issuer) {
    if (issuer.starts_with("https://"))
        return "https://";
    if (issuer.starts_with("http://"))
        return "http://";
    return {};
}

// A percent-decoded copy of `in`: "%XY" with two hex digits becomes that byte, anything else is
// copied as is (so a malformed escape stays visible rather than vanishing).
std::string percent_decode_lenient(std::string_view in) {
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size() && hex(in[i + 1]) >= 0 && hex(in[i + 2]) >= 0) {
            out.push_back(static_cast<char>(hex(in[i + 1]) * 16 + hex(in[i + 2])));
            i += 2;
        } else {
            out.push_back(in[i]);
        }
    }
    return out;
}

// The authorization endpoint's own query must not use the name of a parameter Yuzu appends
// (RFC 6749 3.1: a request parameter MUST NOT be included more than once, and the endpoint's pair
// would come BEFORE Yuzu's, ahead of the value Yuzu means the IdP to use). Pairs split on '&'
// only (';' is not a separator); the name is the text before the first '=', percent-decoded and
// compared ASCII case-insensitively (case-insensitive IdP stacks, ASP.NET and ADFS among them,
// would otherwise read `CLIENT_ID` as a second `client_id`), so `client%5Fid` and `CLIENT_ID` are
// both the reserved `client_id`.
bool authorization_query_ok(std::string_view endpoint) {
    const auto q = endpoint.find('?');
    if (q == std::string_view::npos)
        return true;
    constexpr std::string_view kReserved[] = {
        "client_id", "response_type", "scope",          "redirect_uri",
        "state",     "nonce",         "code_challenge", "code_challenge_method"};
    std::string_view query = endpoint.substr(q + 1);
    while (true) {
        const auto amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        std::string name = percent_decode_lenient(pair.substr(0, pair.find('=')));
        for (char& c : name)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        for (const auto reserved : kReserved)
            if (name == reserved)
                return false;
        if (amp == std::string_view::npos)
            return true;
        query.remove_prefix(amp + 1);
    }
}

// An endpoint from the discovery document: absolute, at most 2048 bytes, the issuer's scheme, a
// well-formed host[:port] authority, no fragment (RFC 6749 3.1 / 3.2: an endpoint URI MUST NOT
// include one, and a browser would drop every parameter appended after it), and no byte that
// could split the request line it will be sent in or the log line it is written to
// (`has_line_splitting_bytes`). A query is allowed: start_auth_flow keeps it and appends with '&'
// (the AUTHORIZATION endpoint's query additionally must not use a name Yuzu appends,
// `authorization_query_ok`). The '#' rule is applied to jwks_uri too: one rule for every
// discovered endpoint, harmless for a plain GET.
bool endpoint_acceptable(const std::string& value, std::string_view scheme,
                         bool authorization = false) {
    if (value.size() > kMaxIdpUrlBytes || !value.starts_with(scheme))
        return false;
    if (has_line_splitting_bytes(value) || value.find('#') != std::string::npos)
        return false;
    if (authorization && !authorization_query_ok(value))
        return false;
    return split_http_url(value).has_value();
}

// A total-deadline watchdog for ONE httplib request. httplib's `set_max_timeout` is consulted only
// while it waits to read or write an established stream, so a server that accepts the TCP
// connection and then drips TLS handshake bytes (each inside the per-operation timeout) holds
// `Client::Get` for as long as it likes: the handshake restarts a fresh per-timeout wait on every
// step, and `Client::stop()` is a no-op until the socket is in flight. On POSIX this closes that:
// httplib's socket-options callback hands the new socket to `adopt` BEFORE `connect()` (once per
// candidate address); `adopt` makes the descriptor this object already holds an alias of that
// socket (dup2), and once the budget (measured from this object's construction) runs out the
// watchdog thread calls shutdown(SHUT_RD) on it. That acts on the socket itself, so a blocked
// handshake read or response read returns at once (end of stream) and `Get` fails; a connect is
// bounded by httplib's own timeouts. The shutdown is RE-ISSUED every 50 ms until the request
// ends: on Linux a shutdown of a not yet connected socket persists across the later connect(),
// on macOS it does NOT (measured: the flag is gone once connect() completes), so a socket that
// connects after the deadline (for example a resolver that burned the budget) is still woken by
// the next tick. On both, a reader blocked in recv/poll/select/SSL_connect is woken (measured).
//
// The descriptor is RESERVED at construction (open of /dev/null) so that adopting a socket can
// never fail with EMFILE: under descriptor exhaustion a dup() taken after httplib's socket() would
// fail and the request would run unwatched with no bound. If the reservation fails the request
// is refused before any socket exists (`reserved()` is false); a dup2 that fails anyway sets
// `failed()`, shuts the raw socket down (best effort) and the caller reports an error instead of
// trusting the answer; that branch is unreachable in practice. dup2 does not carry
// FD_CLOEXEC, so it is set right after; the window in between is harmless because the server
// does not fork or exec on this path. The reserved number is ours alone, so it cannot be reused
// by httplib: it keeps the socket's identity until the destructor closes it. Every use of the
// descriptor happens under `mu_`. The destructor wakes the thread (condition variable, no
// polling of the request), joins it, then closes the descriptor, so nothing outlives the request.
//
// SHUT_RD, not SHUT_RDWR. Shutting the write side too killed a test process with SIGPIPE in 4 of
// 4 runs of an HTTPS response that completes right at the deadline (default SIGPIPE disposition;
// measured in Gate 5, not the handshake-drip case); with SHUT_RD there were none. Production is
// protected anyway: httplib::Server's constructor ignores SIGPIPE process-wide (httplib.h:10405)
// and nothing in server/core/src installs another disposition; the read side is simply the
// smaller hammer. Tests that drive the watchdog set SIGPIPE to ignored themselves.
//
// Windows has the same watchdog with a different owner (the second class below): there is no dup2,
// and a SOCKET is a plain number that httplib closes and Windows may hand out again, so the
// watchdog never keeps httplib's value. `adopt` takes a PRIVATE duplicate of the socket
// (WSADuplicateSocketW + WSASocketW from the protocol info), a second handle on the same kernel
// socket that only this object closes. Measured on Windows in a standalone experiment with
// select(): shutdown() (SD_RECEIVE or SD_BOTH) on the duplicate or on the original does NOT wake
// the waiter, but CancelIoEx() on the duplicate does (select() returned WSAEINTR at once; 6 of 6
// runs), without touching the connection. That experiment is not the evidence for this class:
// httplib 0.37.1 waits with WSAPoll on Windows (httplib.h poll_wrapper, behind select_impl and
// wait_until_socket_is_ready), not select(). The evidence that the cut ends a stalled handshake
// through httplib's real wait is the end-to-end Windows drip test (test_oidc_provider.cpp).
#ifndef _WIN32
class RequestDeadlineWatchdog {
public:
    explicit RequestDeadlineWatchdog(std::chrono::milliseconds budget)
        : deadline_(std::chrono::steady_clock::now() + budget),
          fd_(::open("/dev/null", O_RDONLY | O_CLOEXEC)), thread_([this] { run(); }) {}

    ~RequestDeadlineWatchdog() {
        {
            std::lock_guard lock(mu_);
            done_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }

    RequestDeadlineWatchdog(const RequestDeadlineWatchdog&) = delete;
    RequestDeadlineWatchdog& operator=(const RequestDeadlineWatchdog&) = delete;
    RequestDeadlineWatchdog(RequestDeadlineWatchdog&&) = delete;
    RequestDeadlineWatchdog& operator=(RequestDeadlineWatchdog&&) = delete;

    // True when the spare descriptor was obtained; check BEFORE creating the client.
    [[nodiscard]] bool reserved() const noexcept { return fd_.fd >= 0; }

    // True when a socket could not be put under watch (dup2 failed): the answer is not trusted.
    [[nodiscard]] bool failed() const {
        std::lock_guard lock(mu_);
        return failed_;
    }

    // httplib::Client::set_socket_options callback: runs on the request thread, after socket()
    // and before connect(). Replaces the socket held for a candidate address that failed.
    void adopt(socket_t sock) noexcept {
        std::lock_guard lock(mu_);
        // dup2 can be interrupted by a signal (EINTR) before it did anything: retry that, and
        // fail closed on every other error.
        int rc = -1;
        if (fd_.fd >= 0) {
            do {
                rc = ::dup2(sock, fd_.fd);
            } while (rc < 0 && errno == EINTR);
        }
        if (rc < 0) {
            failed_ = true;
            // Best effort: the socket cannot be watched, so shut its read side down at once so
            // that the connect or handshake fails fast instead of running unbounded (persists on
            // Linux, not on macOS). SHUT_RD, not SHUT_RDWR, for the reason in the class banner:
            // the write side stays usable, so a first write() cannot raise SIGPIPE.
            // Unreachable in practice: the reserved descriptor is ours alone and dup2 onto it
            // cannot hit EMFILE.
            ::shutdown(sock, SHUT_RD);
            return;
        }
        (void)::fcntl(fd_.fd, F_SETFD, FD_CLOEXEC);
        if (expired_)
            ::shutdown(fd_.fd, SHUT_RD);
    }

private:
    // Owns the one reserved descriptor.
    struct OwnedFd {
        int fd{-1};
        explicit OwnedFd(int adopted) noexcept : fd(adopted) {}
        ~OwnedFd() {
            if (fd >= 0)
                ::close(fd);
        }
        OwnedFd(const OwnedFd&) = delete;
        OwnedFd& operator=(const OwnedFd&) = delete;
    };

    void run() {
        using namespace std::chrono_literals;
        std::unique_lock lock(mu_);
        if (cv_.wait_until(lock, deadline_, [this] { return done_; }))
            return; // the request finished first
        expired_ = true;
        do {
            // Harmless ENOTSOCK while the descriptor still aliases /dev/null (no socket yet).
            if (fd_.fd >= 0)
                ::shutdown(fd_.fd, SHUT_RD);
        } while (!cv_.wait_for(lock, 50ms, [this] { return done_; }));
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool done_{false};
    bool expired_{false};
    bool failed_{false};
    const std::chrono::steady_clock::time_point deadline_;
    OwnedFd fd_;
    std::thread thread_; // last: starts running once every member above exists
};
#else
// The Windows leg. Winsock is up when `adopt` runs: httplib initializes it (a static WSAStartup
// in every translation unit that includes it) before any client exists. Every use of the
// duplicate happens under `mu_`, and a candidate address that failed has its duplicate closed
// before the next one is taken, so at most one is open. Unlike the POSIX leg nothing is reserved
// up front (a handle, not a descriptor-table slot, is what a duplicate costs), so `reserved()` is
// always true and a duplicate that cannot be taken sets `failed()`: the caller refuses the answer
// with the same fixed error as the POSIX dup2 failure. Windows has no SIGPIPE, so SD_BOTH is safe.
// The cut is CancelIoEx() on the duplicate plus shutdown(SD_BOTH). Neither persists on a socket
// that is not connected yet, so the 50 ms re-issue is what cuts a connect that completes after the
// deadline. If the cancel did not release the request after 10 re-issues (500 ms), the duplicate
// is closed with SO_LINGER {1, 0}, an abortive close that resets the connection (measured with
// select(): wakes it as readable). The escalation count restarts for each duplicate `adopt`
// installs, so a candidate socket taken after an escalation can escalate too, and once the
// duplicate is gone later ticks have nothing to cut. Only the duplicate is ever closed here,
// never httplib's own SOCKET.
class RequestDeadlineWatchdog {
public:
    explicit RequestDeadlineWatchdog(std::chrono::milliseconds budget)
        : deadline_(std::chrono::steady_clock::now() + budget), thread_([this] { run(); }) {}

    ~RequestDeadlineWatchdog() {
        {
            std::lock_guard lock(mu_);
            done_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }

    RequestDeadlineWatchdog(const RequestDeadlineWatchdog&) = delete;
    RequestDeadlineWatchdog& operator=(const RequestDeadlineWatchdog&) = delete;
    RequestDeadlineWatchdog(RequestDeadlineWatchdog&&) = delete;
    RequestDeadlineWatchdog& operator=(RequestDeadlineWatchdog&&) = delete;

    [[nodiscard]] bool reserved() const noexcept { return true; }

    // True when a socket could not be put under watch (no duplicate): the answer is not trusted.
    [[nodiscard]] bool failed() const {
        std::lock_guard lock(mu_);
        return failed_;
    }

    // httplib::Client::set_socket_options callback: runs on the request thread, after socket()
    // and before connect(). Replaces the duplicate held for a candidate address that failed.
    void adopt(socket_t sock) noexcept {
        std::lock_guard lock(mu_);
        dup_.reset();
        SOCKET dup = INVALID_SOCKET;
        WSAPROTOCOL_INFOW info{};
        if (::WSADuplicateSocketW(sock, ::GetCurrentProcessId(), &info) == 0)
            dup = ::WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0,
                               WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
        if (dup == INVALID_SOCKET) {
            failed_ = true;
            // Best effort, as on POSIX: the socket cannot be watched, so shut it down at once so
            // that the connect or handshake fails fast instead of running unbounded. Unlike
            // Linux, a Windows shutdown of a socket that is not connected yet does not persist.
            // Unreachable in practice: duplicating a handle of our own process does not fail
            // short of handle exhaustion.
            ::shutdown(sock, SD_BOTH);
            return;
        }
        dup_.reset(dup);
        cuts_ = 0; // a new socket gets its own escalation count
        if (expired_)
            cut_locked();
    }

private:
    // Owns the one private duplicate.
    struct OwnedSocket {
        SOCKET s{INVALID_SOCKET};
        OwnedSocket() noexcept = default;
        ~OwnedSocket() { reset(); }
        OwnedSocket(const OwnedSocket&) = delete;
        OwnedSocket& operator=(const OwnedSocket&) = delete;
        void reset(SOCKET next = INVALID_SOCKET) noexcept {
            if (s != INVALID_SOCKET)
                ::closesocket(s);
            s = next;
        }
    };

    // Under `mu_`. Cancels what the request thread is waiting on (the poll wait, recv()) and shuts
    // the connection down; escalates to an abortive close of the duplicate if that did not end it.
    void cut_locked() noexcept {
        if (dup_.s == INVALID_SOCKET)
            return;
        // A SOCKET made by WSASocketW (here, from the duplicated protocol info) is an IFS handle on
        // the supported Windows versions, so it is a valid HANDLE for CancelIoEx.
        ::CancelIoEx(reinterpret_cast<HANDLE>(dup_.s), nullptr);
        ::shutdown(dup_.s, SD_BOTH);
        if (++cuts_ == kEscalateAfterCuts) {
            linger reset_on_close{1, 0};
            ::setsockopt(dup_.s, SOL_SOCKET, SO_LINGER,
                         reinterpret_cast<const char*>(&reset_on_close), sizeof(reset_on_close));
            dup_.reset(); // closesocket(): RST for the connection; httplib's own SOCKET is
                          // untouched
        }
    }

    void run() {
        using namespace std::chrono_literals;
        std::unique_lock lock(mu_);
        if (cv_.wait_until(lock, deadline_, [this] { return done_; }))
            return; // the request finished first
        expired_ = true;
        do {
            cut_locked();
        } while (!cv_.wait_for(lock, 50ms, [this] { return done_; }));
    }

    static constexpr int kEscalateAfterCuts = 10;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool done_{false};
    bool expired_{false};
    bool failed_{false};
    int cuts_{0};
    const std::chrono::steady_clock::time_point deadline_;
    OwnedSocket dup_;
    std::thread thread_; // last: starts running once every member above exists
};
#endif

} // namespace

std::expected<std::string, std::string>
OidcProvider::http_get_bounded(const std::string& url, bool skip_tls_verify,
                               bool allow_private_networks, int timeout_ms,
                               std::span<const egress::Nat64Prefix> nat64_prefixes) {
    const auto target = split_http_url(url);
    if (!target)
        return std::unexpected("not an http or https URL");
    try {
        // Declared BEFORE the client so it is destroyed after it (the client holds a reference).
        const auto t = std::chrono::milliseconds(timeout_ms);
        const auto started = std::chrono::steady_clock::now();
        RequestDeadlineWatchdog watchdog(kHttpTotalBoundMultiplier * t);
        // Fail closed before any socket exists: without the reserved descriptor the watchdog
        // could not take hold of the socket (see RequestDeadlineWatchdog).
        if (!watchdog.reserved())
            return std::unexpected("request failed: no file descriptor available");
        // Egress policy: resolve and classify the target BEFORE any socket exists, then pin the
        // connect to a vetted address (see vet_egress_target). Name resolution is part of the
        // total bound below.
        const auto pins = vet_egress_target(target->host, allow_private_networks, target->cleartext,
                                            timeout_ms, nat64_prefixes);
        if (!pins)
            return std::unexpected(std::string("request failed: ") + pins.error());

        // One attempt per permitted address while the CONNECT fails (a host whose first address
        // family is unreachable still works); any other outcome, success or not, is final.
        int status = 0;
        std::string body;
        std::string err;
        const std::size_t attempts = std::max<std::size_t>(1, pins->size());
        for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
            // Heap-allocated with an explicit reset: httplib 0.37.1's SSLClient destructor can
            // crash after a failed connection to a non-routable host.
            auto client = std::make_unique<httplib::Client>(target->origin);
            // Fail closed if httplib would connect to a host other than the one just vetted.
            if (client->host() != target->host)
                return std::unexpected("request failed: " + std::string(kEgressRefusedReason));
            if (!pins->empty())
                client->set_hostname_addr_map({{target->host, (*pins)[attempt]}});
            client->set_connection_timeout(t);
            client->set_read_timeout(t);
            client->set_write_timeout(t);
            // Those three are per operation: a server that sends one byte just inside each read
            // timeout would hold the GET for as long as it likes. The connect is bounded by
            // set_connection_timeout (per candidate address); set_max_timeout bounds the
            // response waits on the established stream at twice the per-operation timeout (10 s
            // by default), measured from the start of the request. Neither covers the TLS
            // handshake, so the watchdog shuts the socket down at the same deadline (and keeps
            // doing so every 50 ms; see RequestDeadlineWatchdog for the POSIX and Windows
            // owners). The bound counts from the start of this call, so the time spent
            // resolving the name (and on earlier attempts) comes off what this exchange may
            // take.
            client->set_max_timeout(
                std::max(std::chrono::milliseconds(1),
                         kHttpTotalBoundMultiplier * t -
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - started)));
            client->set_socket_options([&watchdog](socket_t sock) { watchdog.adopt(sock); });
            client->set_payload_max_length(kHttpMaxBody);
            client->set_follow_location(false);
            client->enable_server_certificate_verification(!skip_tls_verify);

            auto result = client->Get(target->path);
            status = result ? result->status : 0;
            body = result ? std::move(result->body) : std::string{};
            err = result ? std::string{} : httplib::to_string(result.error());
            const bool connect_failed = !result && result.error() == httplib::Error::Connection;
            client.reset();
            if (!connect_failed)
                break;
        }

        if (status == 0)
            return std::unexpected("request failed: " + err);
        if (watchdog.failed()) // a socket escaped the watchdog: do not trust an unbounded answer
            return std::unexpected("request failed: no file descriptor available");
        if (status != 200)
            return std::unexpected("HTTP " + std::to_string(status));
        return body;
    } catch (const std::exception& e) {
        return std::unexpected(std::string("request exception: ") +
                               ::yuzu::log_key_token(e.what()));
    } catch (...) {
        return std::unexpected("request failed");
    }
}

std::expected<OidcProvider::DiscoveryDocument, std::string>
OidcProvider::fetch_discovery_document(const std::string& issuer, bool skip_tls_verify,
                                       bool allow_private_networks, int timeout_ms,
                                       std::span<const egress::Nat64Prefix> nat64_prefixes) {
    if (issuer_scheme(issuer).empty())
        return std::unexpected("the issuer must be an http or https URL");
    if (issuer.size() > kMaxIdpUrlBytes)
        return std::unexpected("the issuer is longer than 2048 bytes");
    if (has_line_splitting_bytes(issuer))
        return std::unexpected("the issuer contains a space or control character");
    if (!split_http_url(issuer))
        return std::unexpected("the issuer has no well-formed host");
    // OIDC Discovery 3: an issuer has no query or fragment (the discovery URL is built by
    // appending a path, so either would land in the wrong place).
    if (issuer.find_first_of("?#") != std::string::npos)
        return std::unexpected("the issuer must not contain a query or fragment");

    auto url = issuer;
    if (url.ends_with('/'))
        url.pop_back();
    url += "/.well-known/openid-configuration";

    auto body =
        http_get_bounded(url, skip_tls_verify, allow_private_networks, timeout_ms, nat64_prefixes);
    if (!body)
        return std::unexpected(body.error());
    return parse_discovery_document(*body, issuer);
}

std::expected<OidcProvider::DiscoveryDocument, std::string>
OidcProvider::parse_discovery_document(const std::string& body, const std::string& issuer) {
    const auto scheme = issuer_scheme(issuer);
    if (scheme.empty())
        return std::unexpected("the issuer must be an http or https URL");

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(body);
    } catch (const std::exception& e) {
        return std::unexpected(std::string("discovery response is not valid JSON: ") +
                               ::yuzu::log_key_token(e.what()));
    }
    if (!j.is_object())
        return std::unexpected("discovery response is not a JSON object");

    const auto str = [&j](const char* key) -> std::string {
        const auto it = j.find(key);
        return (it != j.end() && it->is_string()) ? it->get<std::string>() : std::string{};
    };
    if (!split_http_url(issuer))
        return std::unexpected("the issuer has no well-formed host");
    // OIDC Discovery 4.3: the document's issuer MUST equal the issuer it was fetched for. The
    // value is IdP-controlled text bound for the log and the Test Connection answer: cut it on a
    // UTF-8 boundary and neutralize control bytes.
    if (str("issuer") != issuer)
        return std::unexpected("issuer mismatch: the discovery document names \"" +
                               ::yuzu::log_token(truncate_utf8(str("issuer"), 200)) + "\"");

    DiscoveryDocument doc{str("authorization_endpoint"), str("token_endpoint"), str("jwks_uri")};
    const std::pair<const char*, const std::string*> fields[] = {
        {"authorization_endpoint", &doc.authorization_endpoint},
        {"token_endpoint", &doc.token_endpoint},
        {"jwks_uri", &doc.jwks_uri}};
    for (const auto& [name, value] : fields) {
        if (value->empty())
            return std::unexpected(std::string("discovery document has no ") + name);
        if (!endpoint_acceptable(*value, scheme, value == &doc.authorization_endpoint))
            return std::unexpected(std::string(name) + " is not an absolute " +
                                   std::string(scheme.substr(0, scheme.size() - 3)) +
                                   " URL on the issuer's scheme");
    }
    return doc;
}

std::expected<std::string, std::string> OidcProvider::ensure_discovered(Need need) {
    const auto pick = [need](const auto& src) -> const std::string& {
        switch (need) {
        case Need::Authorize:
            return src.authorization_endpoint;
        case Need::Token:
            return src.token_endpoint;
        case Need::Jwks:
            return src.jwks_uri;
        }
        throw std::logic_error("OidcProvider::ensure_discovered: unhandled Need");
    };
    // config_ is immutable after construction, so this read needs no lock. A configured endpoint
    // is authoritative but still goes on the wire and into logs: refuse one that could split a
    // request or log line, as the discovered ones are.
    if (const auto& explicit_ep = pick(config_); !explicit_ep.empty()) {
        if (has_line_splitting_bytes(explicit_ep) || explicit_ep.find('#') != std::string::npos ||
            (need == Need::Authorize && !authorization_query_ok(explicit_ep))) {
            spdlog::error("OidcProvider: a configured endpoint contains a space, control "
                          "character, fragment or reserved query parameter and is refused");
            return std::unexpected(std::string(kDiscoveryUnavailable));
        }
        return explicit_ep;
    }
    // Validate-only providers (no redirect_uri, so no flow) never touch the network.
    if (config_.redirect_uri.empty())
        return std::unexpected(std::string(kDiscoveryUnavailable));

    std::unique_lock lock(discovery_mu_);
    if (!discovered_) {
        if (std::chrono::steady_clock::now() < discovery_retry_after_)
            return std::unexpected(std::string(kDiscoveryUnavailable));
        // Another thread is mid-fetch: fail fast rather than queue behind it (a blackholed IdP
        // would otherwise stall every login for the whole bound) and never start a second fetch.
        if (discovery_in_flight_)
            return std::unexpected(std::string(kDiscoveryUnavailable));
        discovery_in_flight_ = true;
        // Clears the flag on EVERY exit from this block: a normal return, or an exception
        // unwinding out of the fetch, the log calls or the result handling (an allocation
        // failure, say). Created straight after the flag is set, and without a throwing step in
        // between, so the flag can never be left set (every later caller would otherwise fail
        // fast until a Settings save). It re-takes `lock` if the unwind left it released, and
        // clears the flag while the lock is held, in the same critical section that commits the
        // result, so single-flight holds: no second fetch can start between result and clear.
        struct InFlightGuard {
            std::unique_lock<std::mutex>& lock;
            bool& flag;
            ~InFlightGuard() {
                if (!lock.owns_lock())
                    lock.lock();
                flag = false;
            }
        } in_flight_guard{lock, discovery_in_flight_};
        lock.unlock(); // the network round trip runs WITHOUT discovery_mu_
        auto doc = [&]() -> std::expected<DiscoveryDocument, std::string> {
            try {
                spdlog::info("OidcProvider: fetching discovery for issuer {}",
                             ::yuzu::log_key_token(config_.issuer));
                return fetch_discovery_document(config_.issuer, config_.skip_tls_verify,
                                                config_.allow_private_networks,
                                                http_timeout_ms_.load(), config_.nat64_prefixes);
            } catch (const std::exception& e) {
                return std::unexpected(std::string("discovery exception: ") +
                                       ::yuzu::log_key_token(e.what()));
            } catch (...) {
                return std::unexpected("discovery exception");
            }
        }();
        lock.lock();
        if (!doc) {
            // The reason can carry IdP-controlled text: neutralize control bytes for the log.
            spdlog::error("OidcProvider: discovery failed for issuer {}: {}",
                          ::yuzu::log_key_token(config_.issuer),
                          ::yuzu::log_key_token(doc.error()));
            discovery_retry_after_ = std::chrono::steady_clock::now() + discovery_retry_window_;
            return std::unexpected(std::string(kDiscoveryUnavailable));
        }
        // IdP-controlled values: neutralize control bytes and Unicode line breaks for the log
        // even though endpoint_acceptable already refused them.
        spdlog::info("OidcProvider: authorize={} token={} jwks_uri={}",
                     ::yuzu::log_key_token(doc->authorization_endpoint),
                     ::yuzu::log_key_token(doc->token_endpoint),
                     ::yuzu::log_key_token(doc->jwks_uri));
        discovered_ = std::move(*doc);
    }
    return pick(*discovered_);
}

void OidcProvider::set_resolver_for_test(ResolverForTest resolver) {
    std::lock_guard lock(test_resolver_mutex());
    test_resolver_slot() = std::move(resolver);
}

void OidcProvider::clear_nat64_discovery_cache_for_test() {
    auto& cache = nat64_discovery_cache();
    std::lock_guard lock(cache.mu);
    cache.filled = false;
    cache.overflowed = false;
    cache.prefixes.clear();
}

void OidcProvider::expire_nat64_discovery_cache_for_test() {
    auto& cache = nat64_discovery_cache();
    std::lock_guard lock(cache.mu);
    cache.expires = {}; // the learned prefixes stay; only the next lookup is due
}

std::expected<std::vector<std::string>, std::string> OidcProvider::vet_egress_target_for_test(
    const std::string& host, bool allow_private_networks, bool cleartext, int timeout_ms,
    std::span<const egress::Nat64Prefix> nat64_prefixes, bool require_all_permitted) {
    auto vet = vet_egress_target(host, allow_private_networks, cleartext, timeout_ms,
                                 nat64_prefixes, require_all_permitted);
    if (!vet)
        return std::unexpected(std::string(vet.error()));
    return std::move(*vet);
}

void OidcProvider::set_http_timeouts_for_test(int ms) {
    http_timeout_ms_.store(ms);
}

void OidcProvider::set_discovery_negative_cache_for_test(int ms) {
    std::lock_guard lock(discovery_mu_);
    discovery_retry_window_ = std::chrono::milliseconds(ms);
    discovery_retry_after_ = {};
}

std::size_t OidcProvider::pending_flow_count_for_test() const {
    std::lock_guard lock(mu_);
    return pending_challenges_.size();
}

// ── OidcProvider ─────────────────────────────────────────────────────────────

OidcProvider::~OidcProvider() {
    std::unique_lock lock(lease_mu_);
    lease_cv_.wait(lock, [this] { return leases_ == 0; });
}

OidcProvider::Lease OidcProvider::acquire_lease() noexcept {
    std::lock_guard lock(lease_mu_);
    ++leases_;
    return Lease(this);
}

void OidcProvider::release_lease() noexcept {
    // Notify under the lock: the destructor may be waiting, and it frees `lease_cv_` as soon as
    // it wakes, so the notify must happen before this thread lets go of `lease_mu_`.
    std::lock_guard lock(lease_mu_);
    --leases_;
    lease_cv_.notify_all();
}

bool OidcProvider::has_leases() const {
    std::lock_guard lock(lease_mu_);
    return leases_ != 0;
}

std::size_t OidcProvider::lease_count_for_test() const {
    std::lock_guard lock(lease_mu_);
    return leases_;
}

namespace {

/// Providers swapped out by a Settings save that still have a request in flight. Never
/// destroyed (a function-local pointer, like the abandoned-request ledger) so no static
/// destructor can wait on a request at exit; `drain_retired` empties it at server stop.
struct RetiredProviders {
    std::mutex mu;
    std::vector<std::unique_ptr<OidcProvider>> list;
};

RetiredProviders& retired_providers() {
    static auto* const instance = new RetiredProviders();
    return *instance;
}

} // namespace

void OidcProvider::retire(std::unique_ptr<OidcProvider> unpublished) {
    if (!unpublished)
        return;
    std::vector<std::unique_ptr<OidcProvider>> to_destroy; // destroyed after the list mutex drops
    std::vector<std::size_t> overflow_counts;              // logged after the list mutex drops
    {
        auto& r = retired_providers();
        std::lock_guard lock(r.mu);
        r.list.push_back(std::move(unpublished));
        // Sweep: a retired provider with no lease can never gain one (it is unpublished), so
        // destroying it now cannot block. The others wait for their requests to finish.
        for (auto it = r.list.begin(); it != r.list.end();) {
            if (!(*it)->has_leases()) {
                to_destroy.push_back(std::move(*it));
                it = r.list.erase(it);
            } else {
                ++it;
            }
        }
        // Bounded: beyond the cap, the oldest is destroyed below, which waits for its leases.
        while (r.list.size() > kMaxRetired) {
            // Logged after the list mutex drops: a slow log sink must not hold up every other
            // retire().
            overflow_counts.push_back(r.list.size());
            to_destroy.push_back(std::move(r.list.front()));
            r.list.erase(r.list.begin());
        }
    }
    for (const auto n : overflow_counts)
        spdlog::warn("OidcProvider: {} replaced providers still have a request in flight; "
                     "waiting for the oldest to finish (the reply to this Settings save is held "
                     "until then; the settings are already stored)",
                     n);
    to_destroy.clear();
}

void OidcProvider::drain_retired() {
    std::vector<std::unique_ptr<OidcProvider>> to_destroy;
    {
        auto& r = retired_providers();
        std::lock_guard lock(r.mu);
        to_destroy.swap(r.list);
    }
    to_destroy.clear();
}

std::size_t OidcProvider::retired_count_for_test() {
    auto& r = retired_providers();
    std::lock_guard lock(r.mu);
    return r.list.size();
}

OidcProvider::OidcProvider(OidcConfig config) : config_(std::move(config)) {
    // No network here: endpoints are discovered lazily by ensure_discovered, so a provider can be
    // built (and a Settings save can succeed) while the IdP is briefly unreachable.
    spdlog::info("OidcProvider: issuer={} client_id={}", ::yuzu::log_key_token(config_.issuer),
                 ::yuzu::log_key_token(config_.client_id));

    // Posture warnings about the configured issuer, once per construction, folded.
    namespace egress = ::yuzu::server::oidc::egress;
    if (const auto url = split_http_url(config_.issuer)) {
        const auto literal = egress::classify_literal(url->host, config_.nat64_prefixes);
        // The scheme matters: plain http to a public address is refused whatever the switch says.
        const bool cleartext = url->cleartext;
        if (literal && egress::decision(*literal, config_.allow_private_networks, cleartext) !=
                           egress::Verdict::Allow) {
            const bool flag_helps =
                egress::decision(*literal, true, cleartext) == egress::Verdict::Allow;
            spdlog::warn("OIDC egress: the issuer host of {} is an IP address in a refused class "
                         "({}); every OIDC request to it will be refused{}",
                         ::yuzu::log_key_token(config_.issuer), egress::class_name(*literal),
                         flag_helps ? " unless the server runs with --oidc-allow-private-networks"
                         : (cleartext && *literal == egress::AddressClass::Public)
                             ? " (plain http to a public address is never allowed; use https)"
                             : " (this class is never allowed)");
        }
        // A plain-http issuer sends the JWKS (the ID token signature trust root) and the client
        // secret in the clear; fine for a loopback lab, an authentication bypass on a network an
        // attacker can sit on. Not refused (documented as lab-only), but never silent.
        if (config_.issuer.starts_with("http://") && url->host != "localhost" &&
            literal != egress::AddressClass::Loopback)
            spdlog::warn("OIDC issuer {} uses http:// on a non-loopback host: the signing keys "
                         "(the trust root for every ID token) and the client secret travel "
                         "unencrypted and anyone on the path can forge a sign-in (plain http to a "
                         "PUBLIC address is refused outright; a private address needs "
                         "--oidc-allow-private-networks); use an https issuer outside a lab",
                         ::yuzu::log_key_token(config_.issuer));
    }
}

bool OidcProvider::is_enabled() const {
    return config_.is_enabled();
}

OidcProvider::AuthFlowStart OidcProvider::start_auth_flow(const std::string& request_redirect_uri) {
    // Resolve the endpoint first: a flow whose authorization URL cannot be built must leave no
    // pending challenge behind (and the route then sets no binding cookie).
    auto authorization_endpoint = ensure_discovered(Need::Authorize);
    if (!authorization_endpoint)
        throw std::runtime_error(authorization_endpoint.error());

    auto verifier = generate_code_verifier();
    auto challenge = compute_code_challenge(verifier);
    auto state = bytes_to_hex(random_bytes(32));
    auto nonce = bytes_to_hex(random_bytes(16));
    // The initiating-browser binding secret. Independent of state/nonce/verifier (which travel
    // through the IdP and the URL); only its hash is kept. Hashed before anything is stored, so
    // a digest failure leaves no pending flow behind.
    auto binding_secret = bytes_to_hex(random_bytes(32));
    auto binding_hash = binding_digest(binding_secret);

    // Use the request-derived redirect URI if provided, otherwise fall back to config
    auto redirect_uri = request_redirect_uri.empty() ? config_.redirect_uri : request_redirect_uri;

    PkceChallenge pkce;
    pkce.code_verifier = verifier;
    pkce.code_challenge = challenge;
    pkce.state = state;
    pkce.nonce = nonce;
    pkce.binding_hash = std::move(binding_hash);
    pkce.redirect_uri = redirect_uri;
    pkce.expires_at = std::chrono::steady_clock::now() + kChallengeTtl;

    {
        std::lock_guard lock(mu_);
        cleanup_expired_states_locked();
        if (pending_challenges_.size() >= 1000) {
            spdlog::warn("OIDC pending challenges map at capacity (1000), evicting oldest entries");
            // Evict oldest entries to make room
            auto oldest = pending_challenges_.begin();
            for (auto it = pending_challenges_.begin(); it != pending_challenges_.end(); ++it) {
                if (it->second.expires_at < oldest->second.expires_at)
                    oldest = it;
            }
            pending_challenges_.erase(oldest);
        }
        pending_challenges_[state] = std::move(pkce);
    }

    // An endpoint that already carries a query keeps it: the client parameters join with '&',
    // with NO separator only when the first '?' is the LAST character (an empty query) or the
    // endpoint ends in '&'; else they start the query with '?'. A later '?' is data inside the
    // query (`/a?x=1?` -> `/a?x=1?&client_id=`), never an opening that would swallow client_id.
    const char* separator = "?";
    if (const auto q = authorization_endpoint->find('?'); q != std::string::npos)
        separator =
            (q + 1 == authorization_endpoint->size() || authorization_endpoint->back() == '&')
                ? ""
                : "&";
    auto url = *authorization_endpoint + separator + "client_id=" + url_encode(config_.client_id) +
               "&response_type=code" + "&scope=" + url_encode("openid profile email") +
               "&redirect_uri=" + url_encode(redirect_uri) + "&state=" + url_encode(state) +
               "&nonce=" + url_encode(nonce) + "&code_challenge=" + url_encode(challenge) +
               "&code_challenge_method=S256";

    // `state` here is server-generated hex (never attacker bytes); folded for consistency.
    spdlog::debug("OIDC auth flow started: state={} redirect_uri={}",
                  ::yuzu::log_key_token(state.substr(0, 8)), redirect_uri);
    return AuthFlowStart{std::move(url), std::move(binding_secret)};
}

std::expected<IdTokenClaims, std::string> OidcProvider::handle_callback(
    const std::string& code, const std::string& state, const std::string& binding_secret,
    bool* binding_verified) {
    if (binding_verified)
        *binding_verified = false;
    // `state` is the caller's callback parameter, unauthenticated: neutralize it for the log.
    spdlog::info("OIDC handle_callback: state={} code_len={}",
                 ::yuzu::log_key_token(state.substr(0, 8)), code.size());

    // Hash the presented secret before taking the lock. FAIL CLOSED: a digest failure is a
    // refusal that leaves the pending flow untouched, never an unbound pass.
    std::string provided_hash;
    try {
        provided_hash = binding_digest(binding_secret);
    } catch (const std::exception& e) {
        spdlog::error("OIDC handle_callback: binding hash failed ({}), login refused", e.what());
        return std::unexpected(std::string(kBrowserBindingUnavailable));
    }

    PkceChallenge challenge;
    {
        std::lock_guard lock(mu_);
        spdlog::info("OIDC handle_callback: {} pending challenges", pending_challenges_.size());
        auto it = pending_challenges_.find(state);
        if (it == pending_challenges_.end()) {
            spdlog::error("OIDC handle_callback: state not found in pending challenges");
            return std::unexpected(std::string(kUnknownState));
        }

        if (std::chrono::steady_clock::now() > it->second.expires_at) {
            pending_challenges_.erase(it);
            spdlog::error("OIDC handle_callback: PKCE challenge expired");
            return std::unexpected("PKCE challenge expired");
        }

        // Browser binding: the callback must come from the browser that started the flow.
        // Constant-time on the hash, and decided BEFORE the entry is consumed: a refusal leaves
        // the legitimate flow completable. An empty stored hash (never produced by
        // start_auth_flow) is never honoured.
        const auto& stored_hash = it->second.binding_hash;
        const bool bound = !stored_hash.empty() && provided_hash.size() == stored_hash.size() &&
                           CRYPTO_memcmp(provided_hash.data(), stored_hash.data(),
                                         stored_hash.size()) == 0;
        if (!bound) {
            // `state` already matched a pending_challenges_ key, so it is server-generated hex;
            // folded for consistency with the unauthenticated log at the top of this function.
            spdlog::error("OIDC handle_callback: browser binding mismatch (state={})",
                          ::yuzu::log_key_token(state.substr(0, 8)));
            return std::unexpected(std::string(kBrowserBindingMismatch));
        }
        if (binding_verified)
            *binding_verified = true;

        challenge = std::move(it->second);
        pending_challenges_.erase(it); // single-use
    }

    // Everything below handles IdP-controlled bytes. The parsers type-guard what they read, but
    // this is the backstop: whatever escapes (a JSON type_error, bad_alloc) becomes an ordinary
    // failure so the route still writes its audit row, bumps its counter and clears the binding
    // cookie. The flow is already consumed above and `*binding_verified` is left as set there.
    // The returned string is FIXED: the route forwards it into emit_event, and e.what() can
    // quote IdP bytes.
    try {
        spdlog::info("OIDC handle_callback: found challenge, redirect_uri={}",
                     challenge.redirect_uri);

        // Exchange code for tokens (use the same redirect_uri from the authorize step)
        auto id_token_result = exchange_code(code, challenge.code_verifier, challenge.redirect_uri);
        if (!id_token_result) {
            spdlog::error("OIDC handle_callback: token exchange failed: {}",
                          id_token_result.error());
            return std::unexpected(id_token_result.error());
        }

        spdlog::info("OIDC handle_callback: got id_token (len={})", id_token_result->size());

        // Verify JWT signature before trusting any claims (G2-SEC-A1-001)
        auto sig_check = verify_jwt_signature(*id_token_result);
        if (!sig_check) {
            spdlog::error("OIDC handle_callback: JWT signature verification failed: {}",
                          sig_check.error());
            if (sig_check.error() == kJwksUnavailable)
                return std::unexpected(std::string(kJwksUnavailable)); // fixed token, no prefix
            return std::unexpected("JWT signature verification failed: " + sig_check.error());
        }

        // Parse ID token (claims can now be trusted)
        auto claims_result = parse_id_token(*id_token_result);
        if (!claims_result) {
            spdlog::error("OIDC handle_callback: JWT parse failed: {}", claims_result.error());
            return std::unexpected(claims_result.error());
        }

        spdlog::info(
            "OIDC handle_callback: parsed claims sub={} iss={} aud={} nonce={}",
            ::yuzu::log_key_token(claims_result->sub), ::yuzu::log_key_token(claims_result->iss),
            ::yuzu::log_key_token(claims_result->aud), ::yuzu::log_key_token(claims_result->nonce));

        // Validate claims
        auto validation = validate_claims(*claims_result, challenge.nonce);
        if (!validation) {
            spdlog::error("OIDC handle_callback: claim validation failed: {}", validation.error());
            return std::unexpected(validation.error());
        }

        spdlog::info(
            "OIDC auth succeeded: sub={} email={} name={}",
            ::yuzu::log_key_token(claims_result->sub),
            claims_result->email.empty() ? "(none)" : ::yuzu::log_key_token(claims_result->email),
            claims_result->name.empty() ? "(none)" : ::yuzu::log_key_token(claims_result->name));

        return claims_result;
    } catch (const std::exception& e) {
        spdlog::error("OIDC handle_callback: unexpected {} while processing the IdP response",
                      typeid(e).name());
        return std::unexpected(std::string(kCallbackInternalError));
    }
}

void OidcProvider::cleanup_expired_states() {
    std::lock_guard lock(mu_);
    cleanup_expired_states_locked();
}

void OidcProvider::cleanup_expired_states_locked() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = pending_challenges_.begin(); it != pending_challenges_.end();) {
        if (now > it->second.expires_at)
            it = pending_challenges_.erase(it);
        else
            ++it;
    }
}

} // namespace yuzu::server::oidc
