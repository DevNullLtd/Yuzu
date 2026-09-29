#include "oidc_provider.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstdio>
#include <sstream>

// OpenSSL is an unconditional server dependency on every platform (vcpkg.json;
// server/core/meson.build). RSA JWKS parsing and JWT signature verification use
// the OpenSSL EVP path on all platforms, including Windows (#1856/#1782). Include
// the OpenSSL headers before <windows.h> so OpenSSL's X509_NAME type is declared
// before wincrypt.h (pulled by windows.h) redefines X509_NAME as a macro.
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h> // RAND_bytes — non-Windows random_bytes() only (Windows uses BCryptGenRandom)
#include <openssl/rsa.h>

#ifdef _WIN32
// clang-format off
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

static std::vector<uint8_t> sha256_raw(const std::string& input) {
    std::vector<uint8_t> hash(32);
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                   static_cast<ULONG>(input.size()), 0);
    BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash.data(), nullptr);
    EVP_MD_CTX_free(ctx);
#endif
    return hash;
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
        return std::unexpected(std::string("JWT payload parse error: ") + e.what());
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

    // aud can be a string or array
    if (j.contains("aud")) {
        if (j["aud"].is_string()) {
            claims.aud = j["aud"].get<std::string>();
        } else if (j["aud"].is_array() && !j["aud"].empty()) {
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
        return std::unexpected("iss mismatch: got '" + claims.iss + "', expected '" +
                               config_.issuer + "'");

    if (claims.aud != config_.client_id)
        return std::unexpected("aud mismatch: got '" + claims.aud + "', expected '" +
                               config_.client_id + "'");

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

// ── WinHTTP helper (Windows only) ────────────────────────────────────────────

#ifdef _WIN32
static std::string winhttp_post(const std::string& url, const std::string& form_body,
                                const std::string& auth_header = {}) {
    // Parse URL into components
    // Expected: https://host/path
    std::wstring wurl(url.begin(), url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        spdlog::error("WinHTTP: failed to crack URL: {}", url);
        return {};
    }

    HINTERNET session = WinHttpOpen(L"Yuzu-Server/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        spdlog::error("WinHTTP: WinHttpOpen failed: {}", GetLastError());
        return {};
    }

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        spdlog::error("WinHTTP: WinHttpConnect failed: {}", GetLastError());
        WinHttpCloseHandle(session);
        return {};
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        spdlog::error("WinHTTP: WinHttpOpenRequest failed: {}", GetLastError());
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    // Add Authorization header if provided (HTTP Basic auth for client credentials)
    if (!auth_header.empty()) {
        std::wstring wauth(auth_header.begin(), auth_header.end());
        WinHttpAddRequestHeaders(request, wauth.c_str(), static_cast<DWORD>(wauth.size()),
                                 WINHTTP_ADDREQ_FLAG_ADD);
    }

    const wchar_t* content_type = L"Content-Type: application/x-www-form-urlencoded";
    BOOL ok = WinHttpSendRequest(request, content_type, -1L, const_cast<char*>(form_body.data()),
                                 static_cast<DWORD>(form_body.size()),
                                 static_cast<DWORD>(form_body.size()), 0);
    if (!ok) {
        spdlog::error("WinHTTP: WinHttpSendRequest failed: {}", GetLastError());
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    ok = WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
        spdlog::error("WinHTTP: WinHttpReceiveResponse failed: {}", GetLastError());
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    std::string response;
    DWORD bytes_available = 0;
    do {
        WinHttpQueryDataAvailable(request, &bytes_available);
        if (bytes_available > 0) {
            std::vector<char> buf(bytes_available);
            DWORD bytes_read = 0;
            WinHttpReadData(request, buf.data(), bytes_available, &bytes_read);
            response.append(buf.data(), bytes_read);
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    spdlog::info("WinHTTP: POST {} -> {} bytes", url, response.size());
    return response;
}
#endif

// ── Token exchange ───────────────────────────────────────────────────────────

std::expected<std::string, std::string>
OidcProvider::exchange_code(const std::string& code, const std::string& code_verifier,
                            const std::string& redirect_uri) {
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

    spdlog::info("OIDC token exchange: endpoint={} redirect_uri={}", config_.token_endpoint,
                 redirect_uri);

    std::string response_body;

#ifdef _WIN32
    // Use WinHTTP on Windows — httplib's OpenSSL client fails from handler threads.
    response_body = winhttp_post(config_.token_endpoint, form_body, auth_header);
    if (response_body.empty()) {
        spdlog::error("OIDC token exchange: WinHTTP POST failed");
        return std::unexpected("token endpoint request failed (WinHTTP)");
    }
#else
    // Parse URL for httplib
    auto url = config_.token_endpoint;
    std::string scheme, host, path;
    if (url.starts_with("https://")) {
        scheme = "https://";
        url = url.substr(8);
    } else if (url.starts_with("http://")) {
        scheme = "http://";
        url = url.substr(7);
    } else
        return std::unexpected("invalid token endpoint URL");
    auto slash = url.find('/');
    host = (slash != std::string::npos) ? url.substr(0, slash) : url;
    path = (slash != std::string::npos) ? url.substr(slash) : "/";

    // Use heap-allocated client and explicit reset to work around httplib
    // 0.37.1 SSLClient destructor crash (invalid free in OpenSSL context
    // cleanup after HTTPS connections).
    auto client = std::make_unique<httplib::Client>(scheme + host);
    client->set_connection_timeout(10);
    client->set_read_timeout(15);
    client->set_write_timeout(15);
    client->enable_server_certificate_verification(!config_.skip_tls_verify);
    httplib::Headers headers;
    if (!auth_header.empty())
        headers.emplace("Authorization", "Basic " +
            base64_encode(config_.client_id + ":" + config_.client_secret));
    auto result = client->Post(path, headers, form_body, "application/x-www-form-urlencoded");
    // Copy result data before destroying the client
    int status_code = result ? result->status : 0;
    std::string body_copy = result ? result->body : "";
    std::string err_str = result ? "" : httplib::to_string(result.error());
    client.reset(); // Explicit destroy before any return

    if (status_code == 0) {
        spdlog::error("OIDC token exchange: httplib failed: {}", err_str);
        return std::unexpected("token endpoint request failed: " + err_str);
    }
    if (status_code != 200) {
        spdlog::error("OIDC token exchange: status={} body={}", status_code,
                      body_copy.substr(0, 500));
        return std::unexpected("token endpoint returned " + std::to_string(status_code));
    }
    response_body = std::move(body_copy);
#endif

    spdlog::info("OIDC token exchange: response_len={}", response_body.size());

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(response_body);
    } catch (const nlohmann::json::parse_error& e) {
        spdlog::error("OIDC token exchange: parse error: {} body={}", e.what(),
                      response_body.substr(0, 500));
        return std::unexpected(std::string("token response parse error: ") + e.what());
    }

    if (j.contains("error")) {
        auto err = j["error"].get<std::string>();
        auto desc = j.value("error_description", "");
        spdlog::error("OIDC token exchange error: {} - {}", err, desc.substr(0, 300));
        return std::unexpected("token endpoint error: " + err);
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

void OidcProvider::fetch_jwks() {
    if (config_.jwks_uri.empty()) {
        spdlog::warn("OidcProvider: no jwks_uri configured, cannot fetch signing keys");
        return;
    }

    spdlog::info("OidcProvider: fetching JWKS from {}", config_.jwks_uri);

    std::string response_body;
    try {
        auto url = config_.jwks_uri;
        std::string scheme;
        if (url.starts_with("https://")) {
            scheme = "https://";
            url = url.substr(8);
        } else if (url.starts_with("http://")) {
            scheme = "http://";
            url = url.substr(7);
        } else {
            spdlog::error("OidcProvider: invalid jwks_uri scheme");
            return;
        }
        auto slash = url.find('/');
        auto host = (slash != std::string::npos) ? url.substr(0, slash) : url;
        auto path = (slash != std::string::npos) ? url.substr(slash) : "/";

        auto client = std::make_unique<httplib::Client>(scheme + host);
        client->set_connection_timeout(5);
        client->set_read_timeout(5);
        client->set_write_timeout(5);
        client->enable_server_certificate_verification(!config_.skip_tls_verify);

        auto result = client->Get(path);
        int status = result ? result->status : 0;
        response_body = result ? result->body : "";
        client.reset();

        if (status != 200) {
            spdlog::error("OidcProvider: JWKS fetch failed (status={})", status);
            return;
        }
    } catch (const std::exception& e) {
        spdlog::error("OidcProvider: JWKS fetch exception: {}", e.what());
        return;
    }

    try {
        auto j = nlohmann::json::parse(response_body);
        if (!j.contains("keys") || !j["keys"].is_array()) {
            spdlog::error("OidcProvider: JWKS response missing 'keys' array");
            return;
        }

        std::vector<CachedJwk> new_keys;
        for (const auto& key : j["keys"]) {
            auto use = key.value("use", "sig");
            if (use != "sig")
                continue;

            CachedJwk cached;
            cached.kid = key.value("kid", "");
            cached.alg = key.value("alg", "RS256");

            cached.pkey = jwk_to_pkey(key);
            if (!cached.pkey) {
                spdlog::warn("OidcProvider: failed to parse JWK kid={}", cached.kid);
                continue;
            }
            new_keys.push_back(std::move(cached));
        }

        std::lock_guard lock(jwks_mu_);
        jwks_cache_ = std::move(new_keys);
        jwks_fetched_at_ = std::chrono::steady_clock::now();
        spdlog::info("OidcProvider: cached {} JWKS signing keys", jwks_cache_.size());
    } catch (const std::exception& e) {
        spdlog::error("OidcProvider: JWKS parse error: {}", e.what());
    }
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

    auto alg = hdr.value("alg", "");
    auto kid = hdr.value("kid", "");

    // Reject alg:none — the classic JWT bypass attack
    if (alg.empty() || alg == "none" || alg == "None" || alg == "NONE")
        return std::unexpected("JWT algorithm 'none' is not allowed");

    // Only RS256/RS384/RS512 supported (Entra ID uses RS256)
    if (alg != "RS256" && alg != "RS384" && alg != "RS512")
        return std::unexpected("unsupported JWT algorithm: " + alg);

    // Ensure JWKS is cached and fresh
    {
        std::lock_guard lock(jwks_mu_);
        auto age = std::chrono::steady_clock::now() - jwks_fetched_at_;
        if (jwks_cache_.empty() || age > kJwksCacheTtl) {
            // Need to fetch — release lock first (fetch acquires its own)
        } else {
            goto find_key; // cache is fresh, skip fetch
        }
    }
    fetch_jwks();

find_key:;
    // Find the key matching kid
    std::shared_ptr<EVP_PKEY> pkey;
    {
        std::lock_guard lock(jwks_mu_);
        for (const auto& k : jwks_cache_) {
            if (!kid.empty() && k.kid == kid) {
                pkey = k.pkey;
                break;
            }
        }
    }
    // If kid didn't match, re-fetch JWKS once (key rotation)
    if (!pkey && !kid.empty()) {
        spdlog::info("OidcProvider: kid={} not in cache, re-fetching JWKS", kid);
        fetch_jwks();
        std::lock_guard lock(jwks_mu_);
        for (const auto& k : jwks_cache_) {
            if (k.kid == kid) {
                pkey = k.pkey;
                break;
            }
        }
    }
    // If kid is empty, use the first key (some IdPs don't set kid)
    if (!pkey) {
        std::lock_guard lock(jwks_mu_);
        if (!jwks_cache_.empty())
            pkey = jwks_cache_.front().pkey;
    }
    if (!pkey)
        return std::unexpected("no matching JWKS key found for kid=" + kid);

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

    spdlog::debug("OidcProvider: JWT signature verified (alg={}, kid={})", alg, kid);
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

    std::lock_guard lock(jwks_mu_);
    jwks_cache_.push_back(std::move(cached));
    // Mark the cache fresh so verify_jwt_signature uses the injected key without
    // attempting a (test-absent) network fetch.
    jwks_fetched_at_ = std::chrono::steady_clock::now();
    return true;
}

// ── OidcProvider ─────────────────────────────────────────────────────────────

OidcProvider::OidcProvider(OidcConfig config)
    : config_(std::move(config)), exchange_script_path_(config_.exchange_script) {
    // Skip discovery if endpoints are already configured (common for Entra
    // where we derive endpoints from the issuer pattern).
    if (!config_.authorization_endpoint.empty()) {
        spdlog::info("OidcProvider: using pre-configured endpoints, skipping discovery");
        spdlog::info("OidcProvider: issuer={} client_id={}", config_.issuer, config_.client_id);
        return;
    }
    // Skip discovery for validate-only usage (unit tests that only call
    // validate_claims / parse_id_token — no redirect_uri means no flow).
    if (config_.redirect_uri.empty()) {
        spdlog::info("OidcProvider: no redirect_uri configured, skipping discovery (validate-only)");
        spdlog::info("OidcProvider: issuer={} client_id={}", config_.issuer, config_.client_id);
        return;
    }

    auto discovery_url = config_.issuer + "/.well-known/openid-configuration";
    spdlog::info("OidcProvider: fetching discovery from {}", discovery_url);

    try {
        // Parse host and path from discovery URL
        std::string disc_url = discovery_url;
        std::string scheme;
        if (disc_url.starts_with("https://")) {
            scheme = "https://";
            disc_url = disc_url.substr(8);
        } else if (disc_url.starts_with("http://")) {
            scheme = "http://";
            disc_url = disc_url.substr(7);
        }
        auto slash = disc_url.find('/');
        auto host = disc_url.substr(0, slash);
        auto path = disc_url.substr(slash);

        // Use a heap-allocated client to control destruction order and
        // avoid a crash in httplib::SSLClient::~SSLClient when the SSL
        // context is left in a partially-initialised state after a failed
        // connection to a non-routable host (observed with httplib 0.37.1).
        auto client = std::make_unique<httplib::Client>(scheme + host);
        client->set_connection_timeout(5);
        client->set_read_timeout(5);
        client->set_write_timeout(5);
        client->enable_server_certificate_verification(!config_.skip_tls_verify);

        auto result = client->Get(path);

        // Explicitly destroy the client before touching config_ to ensure
        // any SSL resources are freed while the stack is still valid.
        client.reset();

        if (result && result->status == 200) {
            auto j = nlohmann::json::parse(result->body);
            if (j.contains("authorization_endpoint"))
                config_.authorization_endpoint = j["authorization_endpoint"].get<std::string>();
            if (j.contains("token_endpoint"))
                config_.token_endpoint = j["token_endpoint"].get<std::string>();
            if (j.contains("jwks_uri"))
                config_.jwks_uri = j["jwks_uri"].get<std::string>();
            spdlog::info("OidcProvider: authorize={}", config_.authorization_endpoint);
            spdlog::info("OidcProvider: token={}", config_.token_endpoint);
            spdlog::info("OidcProvider: jwks_uri={}", config_.jwks_uri);
        } else {
            spdlog::warn("OidcProvider: discovery fetch failed (status={}), using fallback endpoints",
                         result ? result->status : 0);
        }
    } catch (const std::exception& e) {
        spdlog::warn("OidcProvider: discovery fetch exception: {}, using fallback endpoints",
                     e.what());
    } catch (...) {
        spdlog::warn("OidcProvider: discovery fetch failed, using fallback endpoints");
    }

    spdlog::info("OidcProvider: issuer={} client_id={}", config_.issuer, config_.client_id);
}

bool OidcProvider::is_enabled() const {
    return config_.is_enabled();
}

std::string OidcProvider::start_auth_flow(const std::string& request_redirect_uri) {
    auto verifier = generate_code_verifier();
    auto challenge = compute_code_challenge(verifier);
    auto state = bytes_to_hex(random_bytes(32));
    auto nonce = bytes_to_hex(random_bytes(16));

    // Use the request-derived redirect URI if provided, otherwise fall back to config
    auto redirect_uri = request_redirect_uri.empty() ? config_.redirect_uri : request_redirect_uri;

    PkceChallenge pkce;
    pkce.code_verifier = verifier;
    pkce.code_challenge = challenge;
    pkce.state = state;
    pkce.nonce = nonce;
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

    auto url = config_.authorization_endpoint + "?client_id=" + url_encode(config_.client_id) +
               "&response_type=code" + "&scope=" + url_encode("openid profile email") +
               "&redirect_uri=" + url_encode(redirect_uri) + "&state=" + url_encode(state) +
               "&nonce=" + url_encode(nonce) + "&code_challenge=" + url_encode(challenge) +
               "&code_challenge_method=S256";

    spdlog::debug("OIDC auth flow started: state={} redirect_uri={}", state.substr(0, 8),
                  redirect_uri);
    return url;
}

std::expected<IdTokenClaims, std::string> OidcProvider::handle_callback(const std::string& code,
                                                                        const std::string& state) {
    spdlog::info("OIDC handle_callback: state={} code_len={}", state.substr(0, 8), code.size());

    PkceChallenge challenge;
    {
        std::lock_guard lock(mu_);
        spdlog::info("OIDC handle_callback: {} pending challenges", pending_challenges_.size());
        auto it = pending_challenges_.find(state);
        if (it == pending_challenges_.end()) {
            spdlog::error("OIDC handle_callback: state not found in pending challenges");
            return std::unexpected("unknown or expired state parameter");
        }

        if (std::chrono::steady_clock::now() > it->second.expires_at) {
            pending_challenges_.erase(it);
            spdlog::error("OIDC handle_callback: PKCE challenge expired");
            return std::unexpected("PKCE challenge expired");
        }

        challenge = std::move(it->second);
        pending_challenges_.erase(it); // single-use
    }

    spdlog::info("OIDC handle_callback: found challenge, redirect_uri={}", challenge.redirect_uri);

    // Exchange code for tokens (use the same redirect_uri from the authorize step)
    auto id_token_result = exchange_code(code, challenge.code_verifier, challenge.redirect_uri);
    if (!id_token_result) {
        spdlog::error("OIDC handle_callback: token exchange failed: {}", id_token_result.error());
        return std::unexpected(id_token_result.error());
    }

    spdlog::info("OIDC handle_callback: got id_token (len={})", id_token_result->size());

    // Verify JWT signature before trusting any claims (G2-SEC-A1-001)
    auto sig_check = verify_jwt_signature(*id_token_result);
    if (!sig_check) {
        spdlog::error("OIDC handle_callback: JWT signature verification failed: {}",
                       sig_check.error());
        return std::unexpected("JWT signature verification failed: " + sig_check.error());
    }

    // Parse ID token (claims can now be trusted)
    auto claims_result = parse_id_token(*id_token_result);
    if (!claims_result) {
        spdlog::error("OIDC handle_callback: JWT parse failed: {}", claims_result.error());
        return std::unexpected(claims_result.error());
    }

    spdlog::info("OIDC handle_callback: parsed claims sub={} iss={} aud={} nonce={}",
                 claims_result->sub, claims_result->iss, claims_result->aud, claims_result->nonce);

    // Validate claims
    auto validation = validate_claims(*claims_result, challenge.nonce);
    if (!validation) {
        spdlog::error("OIDC handle_callback: claim validation failed: {}", validation.error());
        return std::unexpected(validation.error());
    }

    spdlog::info("OIDC auth succeeded: sub={} email={} name={}", claims_result->sub,
                 claims_result->email.empty() ? "(none)" : claims_result->email,
                 claims_result->name.empty() ? "(none)" : claims_result->name);

    return claims_result;
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
