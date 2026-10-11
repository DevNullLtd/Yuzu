#pragma once

// test_oidc_mock_idp.hpp -- a loopback OIDC token endpoint plus RS256 signing, so a test can
// drive `OidcProvider::handle_callback` and `/auth/callback` through their SUCCESS path with no
// network and no live IdP (OIDC browser-binding tests).
//
// What is real: the provider's own `exchange_code` (an httplib POST to `token_endpoint`), JWT
// parsing, signature verification through `add_test_jwks_key` (the same jwk_to_pkey + EVP path as
// production) and claim validation. What is a stand-in: the IdP itself, which is this loopback
// httplib server returning `{"id_token": <jwt>}` for POST /token.
//
// A real httplib acceptor thread crashes the ThreadSanitizer build (#438), so a test that uses
// `MockIdp` is wrapped in `#ifndef YUZU_OIDC_MOCK_IDP_TSAN`.

#include "oidc_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_OIDC_MOCK_IDP_TSAN 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define YUZU_OIDC_MOCK_IDP_TSAN 1
#endif

namespace yuzu::server::test {

#ifndef YUZU_OIDC_MOCK_IDP_TSAN

/// A loopback token endpoint. `set_id_token` chooses what POST /token returns; `token_calls`
/// counts the exchanges the provider attempted (a refused callback must leave it at 0).
struct MockIdp {
    httplib::Server svr;
    std::thread thread;
    int port{0};
    std::mutex mu;
    std::string id_token;
    std::atomic<int> token_calls{0};

    MockIdp() {
        svr.Post("/token", [this](const httplib::Request&, httplib::Response& res) {
            token_calls.fetch_add(1);
            std::string tok;
            {
                std::lock_guard lk(mu);
                tok = id_token;
            }
            res.set_content(R"({"id_token":")" + tok + R"(","token_type":"Bearer"})",
                            "application/json");
        });
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        thread = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
    }
    ~MockIdp() {
        svr.stop();
        if (thread.joinable())
            thread.join();
    }
    MockIdp(const MockIdp&) = delete;
    MockIdp& operator=(const MockIdp&) = delete;

    std::string token_endpoint() const { return "http://127.0.0.1:" + std::to_string(port) + "/token"; }
    void set_id_token(std::string t) {
        std::lock_guard lk(mu);
        id_token = std::move(t);
    }
};

/// One RSA-2048 test keypair per process (keygen is the slow step; every test only needs a
/// signing key the provider trusts, not a fresh one). The public half is base64url n/e.
struct SharedRsaKey {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk{nullptr, EVP_PKEY_free};
    std::string n_b64, e_b64;
};

inline const SharedRsaKey& shared_rsa_key() {
    static const SharedRsaKey key = [] {
        SharedRsaKey k;
        k.pk.reset(EVP_RSA_gen(2048));
        REQUIRE(k.pk);
        BIGNUM* raw_n = nullptr;
        BIGNUM* raw_e = nullptr;
        REQUIRE(EVP_PKEY_get_bn_param(k.pk.get(), "n", &raw_n) == 1);
        REQUIRE(EVP_PKEY_get_bn_param(k.pk.get(), "e", &raw_e) == 1);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_n(raw_n, BN_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_e(raw_e, BN_free);
        auto enc = [](const BIGNUM* bn) {
            std::vector<uint8_t> buf(static_cast<size_t>(BN_num_bytes(bn)));
            BN_bn2bin(bn, buf.data());
            return oidc::OidcProvider::base64url_encode(buf);
        };
        k.n_b64 = enc(bn_n.get());
        k.e_b64 = enc(bn_e.get());
        return k;
    }();
    return key;
}

/// Register the shared public key in `provider` under `kid` and return a genuinely RS256-signed
/// JWT over `payload_json` (drives the SAME jwk_to_pkey + EVP verify path as production).
/// "" on any failure (callers REQUIRE non-empty).
inline std::string sign_and_register_rs256(oidc::OidcProvider& provider, const std::string& kid,
                                           const std::string& payload_json) {
    const auto& key = shared_rsa_key();
    if (!provider.add_test_jwks_key(kid, key.n_b64, key.e_b64))
        return "";
    auto b64 = [](const std::string& s) {
        return oidc::OidcProvider::base64url_encode(std::vector<uint8_t>(s.begin(), s.end()));
    };
    const std::string header = R"({"alg":"RS256","kid":")" + kid + R"(","typ":"JWT"})";
    const std::string signing_input = b64(header) + "." + b64(payload_json);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md || EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, key.pk.get()) != 1)
        return "";
    const auto* in = reinterpret_cast<const unsigned char*>(signing_input.data());
    size_t sig_len = 0;
    if (EVP_DigestSign(md.get(), nullptr, &sig_len, in, signing_input.size()) != 1)
        return "";
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md.get(), sig.data(), &sig_len, in, signing_input.size()) != 1)
        return "";
    sig.resize(sig_len);
    return signing_input + "." + oidc::OidcProvider::base64url_encode(sig);
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN

/// The value of query parameter `name` in `url` ("" when absent). Values the provider emits
/// (state, nonce) are lower-case hex, so no percent-decoding is needed.
inline std::string url_query_param(const std::string& url, const std::string& name) {
    const auto q = url.find('?');
    if (q == std::string::npos)
        return {};
    const std::string needle = name + "=";
    std::size_t pos = q + 1;
    while (pos < url.size()) {
        const auto amp = url.find('&', pos);
        const auto end = amp == std::string::npos ? url.size() : amp;
        if (url.compare(pos, needle.size(), needle) == 0)
            return url.substr(pos + needle.size(), end - pos - needle.size());
        pos = end + 1;
    }
    return {};
}

/// The RS256 id_token payload the callback tests sign: a valid token for `cfg` bound to `nonce`.
inline std::string id_token_payload(const oidc::OidcConfig& cfg, const std::string& nonce,
                                    const std::string& sub = "alice-sub") {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return R"({"iss":")" + cfg.issuer + R"(","aud":")" + cfg.client_id + R"(","sub":")" + sub +
           R"(","nonce":")" + nonce + R"(","email":"alice@example.test","name":"Alice",)" +
           R"("exp":)" + std::to_string(now + 3600) + R"(,"iat":)" + std::to_string(now) + "}";
}

} // namespace yuzu::server::test
