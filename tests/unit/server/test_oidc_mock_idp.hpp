#pragma once

// test_oidc_mock_idp.hpp -- a loopback OIDC IdP plus RS256 signing, so a test can drive
// `OidcProvider::handle_callback` and `/auth/callback` through their SUCCESS path with no network
// and no live IdP. Real: the provider's discovery fetch, `fetch_jwks_snapshot`, `exchange_code`, JWT
// verification and claim validation. Stand-in: the IdP, a loopback httplib server serving
// /.well-known/openid-configuration (knobs below), /jwks (the shared key under a swappable kid),
// /authorize (302 back with code and state, remembering the nonce) and POST /token (the
// `set_id_token` value, else a token signed for the last authorize nonce).
//
// A real httplib acceptor thread crashes the ThreadSanitizer build (#438), so a test that uses
// `MockIdp` is wrapped in `#ifndef YUZU_OIDC_MOCK_IDP_TSAN`.
//
// Trickle knobs (`trickle_discovery`, `trickle_jwks`): the answer is a CHUNKED body of one byte
// per `trickle_interval_ms`, `trickle_chunks` times, paced by a condition variable that the
// destructor signals, so a trickle a test has abandoned ends at once instead of running out.
// `trickle_chunks_sent` counts the bytes written, so a test can tell "cut mid-trickle" from "never
// started" without a clock. `jwks_body` serves a chosen (malformed) JWKS verbatim.
// `hold_discovery` / `release_discovery` keep a discovery fetch in flight on a latch.

#include "oidc_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
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

// Defined below; MockIdp's handlers need them.
inline std::string jwks_json(const std::string& kid);
inline std::string jwks_json_n(const std::string& kid, int count);
struct SharedRsaKey;
inline const SharedRsaKey& shared_rsa_key();
inline std::string rs256_sign(const std::string& kid, const std::string& payload_json);
inline std::string id_token_payload(const oidc::OidcConfig& cfg, const std::string& nonce,
                                    const std::string& sub);

/// A loopback IdP. Every knob is guarded by `mu`; every counter is atomic and counts the
/// requests the provider actually made (an offline-by-design case asserts it stays 0).
struct MockIdp {
    httplib::Server svr;
    std::thread thread;
    int port{0};
    std::mutex mu;
    std::string id_token;                ///< POST /token returns this when non-empty ...
    std::string last_nonce;              ///< ... else a token signed for this (set by GET /authorize)
    std::string token_client_id{"yuzu-test-client"}; ///< `aud` of a signed token
    std::string token_kid{"mock-kid-1"};             ///< the kid a signed token and GET /jwks use
    std::string discovery_issuer;        ///< "" = this server's own base URL
    std::string discovery_body;          ///< non-empty = served verbatim instead of the document
    std::string discovery_redirect;      ///< non-empty = 302 to this instead of answering
    int discovery_status{200};
    std::size_t discovery_pad{0};        ///< extra bytes in the document (oversize-body knob)
    int discovery_delay_ms{0};
    int jwks_status{200};
    int jwks_key_count{1};         ///< keys in the served JWKS (0 = an empty key set)
    bool trickle_discovery{false}; ///< answer GET /.well-known/... as a slow chunked body
    bool trickle_jwks{false};      ///< answer GET /jwks as a slow chunked body
    int trickle_interval_ms{40};
    int trickle_chunks{100};
    std::string jwks_body; ///< non-empty = GET /jwks serves this verbatim (a malformed JWKS)
    // Non-empty `token_body` = POST /token answers it verbatim, with `token_status`; the normal
    // (valid, signed) answer carries `token_status` too.
    std::string token_body;
    int token_status{200};
    // Non-empty = the token answer (either form) carries a `Location` header of this value, so a
    // 3xx `token_status` is a real redirect a client could follow.
    std::string token_location;
    // true = POST /token answers `token_status` with NO body (a 204, say), whatever `token_body`
    // is.
    bool token_no_body{false};
    // > 0 = the normal answer is padded to EXACTLY this many bytes in total (the id_token itself
    // stays valid), so a test can sit on either side of a size cap. Below the smallest padded form
    // the answer is unpadded.
    std::size_t token_body_total{0};
    // > 0 = the normal answer is sent as a CHUNKED body of pieces of this many bytes (no
    // Content-Length), so a size cap sees a stream whose pieces are each small.
    std::size_t token_chunk_size{0};
    // Counts requests to /elsewhere (GET and POST): where a redirect from the token endpoint
    // points. A client that follows the redirect, with either method, makes it non-zero.
    std::atomic<int> elsewhere_calls{0};
    // > 0 = the normal POST /token answer carries an extra `"pad":"xxx..."` member of this many
    // bytes (a token response of a chosen size; the id_token itself stays valid).
    std::size_t token_body_pad{0};
    // Non-empty = the discovery document advertises `base() + token_endpoint_advert` as its
    // token_endpoint (default "/token"): "/token?p=b2c_1_signin" is a query-bearing endpoint,
    // "?x=1" an EMPTY path with a query. `last_token_target` (under mu) is the request target
    // (path plus query) of the last POST that reached the token handler.
    std::string token_endpoint_advert;
    std::string last_token_target;
    std::atomic<int> trickle_chunks_sent{0}; ///< bytes a trickle has written so far (all GETs)
    std::string last_discovery_path; ///< the request path of the last discovery GET
    std::mutex trickle_mu;
    std::condition_variable trickle_cv;
    bool trickle_stop{false};
    bool discovery_hold{false}; ///< under trickle_mu: a discovery GET waits until released
    bool token_hold{false};     ///< under trickle_mu: a POST /token waits until released
    bool jwks_hold{false};      ///< under trickle_mu: a GET /jwks waits until released
    std::atomic<int> token_calls{0};
    std::atomic<int> discovery_calls{0};
    std::atomic<int> jwks_calls{0};
    std::atomic<int> authorize_calls{0};
    std::atomic<int> root_calls{0};
    std::string last_root_target; ///< under `mu`: the path (with query) of the last GET /

    MockIdp() {
        // A regex route so an issuer with a path prefix (/realms/x, /<tenant>/v2.0) is served;
        // the exact path each request used is recorded for the tests that pin URL building.
        svr.Get(R"(.*/\.well-known/openid-configuration)",
                [this](const httplib::Request& req, httplib::Response& res) {
                    discovery_calls.fetch_add(1);
                    std::string body, redirect, issuer;
                    int status, delay;
                    std::size_t pad;
                    bool trickle;
                    {
                        std::lock_guard lk(mu);
                        last_discovery_path = req.path;
                        trickle = trickle_discovery;
                        body = discovery_body;
                        redirect = discovery_redirect;
                        issuer = discovery_issuer.empty() ? base() : discovery_issuer;
                        status = discovery_status;
                        pad = discovery_pad;
                        delay = discovery_delay_ms;
                    }
                    if (delay > 0)
                        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                    {
                        // Event-driven hold (hold_discovery / release_discovery); the
                        // destructor's trickle_stop also ends it.
                        std::unique_lock hold(trickle_mu);
                        trickle_cv.wait(hold, [this] { return !discovery_hold || trickle_stop; });
                    }
                    if (trickle) {
                        start_trickle(res);
                        return;
                    }
                    if (!redirect.empty()) {
                        res.set_redirect(redirect);
                        return;
                    }
                    if (body.empty()) {
                        body = R"({"issuer":")" + issuer + R"(","authorization_endpoint":")" +
                               base() + R"(/authorize","token_endpoint":")" + base() +
                               (token_endpoint_advert.empty() ? std::string("/token")
                                                              : token_endpoint_advert) +
                               R"(","jwks_uri":")" + base() + R"(/jwks")";
                        if (pad > 0)
                            body += R"(,"x":")" + std::string(pad, 'a') + "\"";
                        body += "}";
                    }
                    res.status = status;
                    res.set_content(body, "application/json");
                });
        // GET / answers "root" and records the exact request target, so a test can pin what
        // the provider put on the request line for a URL with a query or a fragment.
        svr.Get("/", [this](const httplib::Request& req, httplib::Response& res) {
            root_calls.fetch_add(1);
            {
                std::lock_guard lk(mu);
                last_root_target = req.target;
            }
            res.set_content("root", "text/plain");
        });
        svr.Get("/jwks", [this](const httplib::Request&, httplib::Response& res) {
            jwks_calls.fetch_add(1);
            {
                std::unique_lock hold(trickle_mu);
                trickle_cv.wait(hold, [this] { return !jwks_hold || trickle_stop; });
            }
            std::string kid, raw;
            int status, key_count;
            bool trickle;
            {
                std::lock_guard lk(mu);
                kid = token_kid;
                status = jwks_status;
                key_count = jwks_key_count;
                trickle = trickle_jwks;
                raw = jwks_body;
            }
            if (trickle) {
                start_trickle(res);
                return;
            }
            res.status = status;
            res.set_content(raw.empty() ? jwks_json_n(kid, key_count) : raw, "application/json");
        });
        svr.Get("/authorize", [this](const httplib::Request& req, httplib::Response& res) {
            authorize_calls.fetch_add(1);
            {
                std::lock_guard lk(mu);
                last_nonce = req.get_param_value("nonce");
            }
            res.set_redirect(req.get_param_value("redirect_uri") + "?code=the-code&state=" +
                             req.get_param_value("state"));
        });
        const auto token_handler = [this](const httplib::Request& req, httplib::Response& res) {
            token_calls.fetch_add(1);
            {
                // Event-driven hold (hold_token / release_token), after the call is counted.
                std::unique_lock hold(trickle_mu);
                trickle_cv.wait(hold, [this] { return !token_hold || trickle_stop; });
            }
            std::string tok;
            std::string location;
            int status;
            bool no_body;
            std::size_t total, chunk;
            {
                std::lock_guard lk(mu);
                last_token_target = req.target;
                location = token_location;
                status = token_status;
                no_body = token_no_body;
                total = token_body_total;
                chunk = token_chunk_size;
            }
            res.status = status;
            if (!location.empty())
                res.set_header("Location", location);
            if (no_body)
                return;
            std::string out;
            {
                std::lock_guard lk(mu);
                if (!token_body.empty()) {
                    out = token_body;
                } else {
                    tok = id_token;
                    if (tok.empty()) {
                        oidc::OidcConfig c;
                        c.issuer = discovery_issuer.empty() ? base() : discovery_issuer;
                        c.client_id = token_client_id;
                        tok = rs256_sign(token_kid, id_token_payload(c, last_nonce, "alice-sub"));
                    }
                    out = R"({"id_token":")" + tok + R"(","token_type":"Bearer")";
                    // `,"pad":"` + n bytes + `"` is 9 bytes plus the pad; the closing brace is 1.
                    constexpr std::size_t kPadFrame = 9;
                    if (total > 0 && total >= out.size() + 1 + kPadFrame)
                        out += R"(,"pad":")" +
                               std::string(total - out.size() - 1 - kPadFrame, 'x') + '"';
                    else if (token_body_pad > 0)
                        out += R"(,"pad":")" + std::string(token_body_pad, 'x') + '"';
                    out += "}";
                }
            }
            if (chunk == 0) {
                res.set_content(out, "application/json");
                return;
            }
            auto data = std::make_shared<std::string>(std::move(out));
            res.set_chunked_content_provider(
                "application/json", [data, chunk](std::size_t offset, httplib::DataSink& sink) {
                    if (offset >= data->size()) {
                        sink.done();
                        return true;
                    }
                    return sink.write(data->data() + offset,
                                      std::min(chunk, data->size() - offset));
                });
        };
        // Where a redirect from the token endpoint points (see `elsewhere_calls`).
        const auto elsewhere_handler = [this](const httplib::Request&, httplib::Response& res) {
            elsewhere_calls.fetch_add(1);
            res.set_content("elsewhere", "text/plain");
        };
        svr.Get("/elsewhere", elsewhere_handler);
        svr.Post("/elsewhere", elsewhere_handler);
        svr.Post("/token", token_handler);
        svr.Post("/", token_handler); // an empty-path token endpoint with a query: POST /?x=1
        // Generate the shared key here, on the test thread: the first call may otherwise run on
        // a handler thread (and REQUIRE is not safe there).
        (void)shared_rsa_key();
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        thread = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
    }
    ~MockIdp() {
        {
            std::lock_guard lk(trickle_mu);
            trickle_stop = true;
        }
        trickle_cv.notify_all();
        svr.stop();
        if (thread.joinable())
            thread.join();
    }
    MockIdp(const MockIdp&) = delete;
    MockIdp& operator=(const MockIdp&) = delete;

    /// Answer `res` with a chunked body of `trickle_chunks` bytes, one per `trickle_interval_ms`
    /// (the provider's per-operation timeouts see steady progress; only a TOTAL bound cuts it).
    void start_trickle(httplib::Response& res) {
        int interval, chunks;
        {
            std::lock_guard lk(mu);
            interval = trickle_interval_ms;
            chunks = trickle_chunks;
        }
        auto sent = std::make_shared<int>(0);
        // Not a compressible type: a gzip compressor would hold the bytes back until the end and
        // the client would see silence, not a trickle.
        res.set_chunked_content_provider(
            "application/octet-stream",
            [this, sent, interval, chunks](std::size_t, httplib::DataSink& sink) {
                std::unique_lock lk(trickle_mu);
                const bool stopped = trickle_cv.wait_for(lk, std::chrono::milliseconds(interval),
                                                         [this] { return trickle_stop; });
                lk.unlock();
                if (stopped || *sent >= chunks) {
                    sink.done();
                    return true;
                }
                ++*sent;
                trickle_chunks_sent.fetch_add(1);
                return sink.write("a", 1);
            });
    }

    /// Make every later discovery GET wait, after it is counted, until `release_discovery()`:
    /// a fetch the test can keep in flight for exactly as long as it needs, with no sleep.
    void hold_discovery() {
        std::lock_guard lk(trickle_mu);
        discovery_hold = true;
    }
    void release_discovery() {
        {
            std::lock_guard lk(trickle_mu);
            discovery_hold = false;
        }
        trickle_cv.notify_all();
    }

    /// Same latch for POST /token and GET /jwks: a call the test can keep in flight (the IdP
    /// "stops answering" at exactly that step) for as long as it needs, with no sleep and no
    /// wall-clock dependence. The call is counted (`token_calls`, `jwks_calls`) before it waits.
    void hold_token() {
        std::lock_guard lk(trickle_mu);
        token_hold = true;
    }
    void release_token() {
        {
            std::lock_guard lk(trickle_mu);
            token_hold = false;
        }
        trickle_cv.notify_all();
    }
    void hold_jwks() {
        std::lock_guard lk(trickle_mu);
        jwks_hold = true;
    }
    void release_jwks() {
        {
            std::lock_guard lk(trickle_mu);
            jwks_hold = false;
        }
        trickle_cv.notify_all();
    }

    /// The request target of the last GET /.
    std::string root_target() {
        std::lock_guard lk(mu);
        return last_root_target;
    }

    /// The request path of the last discovery GET.
    std::string discovery_path() {
        std::lock_guard lk(mu);
        return last_discovery_path;
    }

    /// `http://127.0.0.1:<port>`: also the issuer a provider under test is configured with.
    std::string base() const { return "http://127.0.0.1:" + std::to_string(port); }
    std::string token_endpoint() const { return base() + "/token"; }
    void set_id_token(std::string t) {
        std::lock_guard lk(mu);
        id_token = std::move(t);
    }
    /// Change a knob under the lock: `idp.with([](MockIdp& m) { m.discovery_status = 500; });`
    template <class F> void with(F&& f) {
        std::lock_guard lk(mu);
        f(*this);
    }

    /// What a browser does after the provider's authorization URL: GET it from this IdP and
    /// return the redirect target (redirect_uri with code and state), "" on any failure.
    std::string follow_authorize(const std::string& authorization_url) {
        const auto prefix = base();
        if (!authorization_url.starts_with(prefix))
            return {};
        httplib::Client cli(prefix);
        auto r = cli.Get(authorization_url.substr(prefix.size()));
        return (r && r->status == 302) ? r->get_header_value("Location") : std::string{};
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

/// The JWKS document a loopback IdP serves: the shared public key under `kid`.
inline std::string jwks_json(const std::string& kid) {
    const auto& key = shared_rsa_key();
    return R"({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":")" + kid + R"(","n":")" +
           key.n_b64 + R"(","e":")" + key.e_b64 + R"("}]})";
}

/// A JWKS with `count` keys (the shared public key under `kid`, `kid-2`, ...); 0 = no keys.
inline std::string jwks_json_n(const std::string& kid, int count) {
    if (count == 1)
        return jwks_json(kid);
    const auto& key = shared_rsa_key();
    std::string out = R"({"keys":[)";
    for (int i = 0; i < count; ++i) {
        if (i > 0)
            out += ",";
        out += R"({"kty":"RSA","use":"sig","alg":"RS256","kid":")" + kid +
               (i == 0 ? "" : "-" + std::to_string(i + 1)) + R"(","n":")" + key.n_b64 +
               R"(","e":")" + key.e_b64 + R"("})";
    }
    return out + "]}";
}

/// A genuinely RS256-signed JWT over `payload_json` under `kid` ("" on any failure).
inline std::string rs256_sign(const std::string& kid, const std::string& payload_json) {
    const auto& key = shared_rsa_key();
    auto b64 = [](const std::string& s) {
        return oidc::OidcProvider::base64url_encode(std::vector<uint8_t>(s.begin(), s.end()));
    };
    // An empty kid omits the member (a token with no kid); a hand-built header covers the rest.
    const std::string header = kid.empty()
                                   ? std::string(R"({"alg":"RS256","typ":"JWT"})")
                                   : R"({"alg":"RS256","kid":")" + kid + R"(","typ":"JWT"})";
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

/// Register the shared public key in `provider` under `kid` and return a signed JWT over
/// `payload_json` (drives the SAME jwk_to_pkey + EVP verify path as production).
inline std::string sign_and_register_rs256(oidc::OidcProvider& provider, const std::string& kid,
                                           const std::string& payload_json) {
    const auto& key = shared_rsa_key();
    if (!provider.add_test_jwks_key(kid, key.n_b64, key.e_b64))
        return "";
    return rs256_sign(kid, payload_json);
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
