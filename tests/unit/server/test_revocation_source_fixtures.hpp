#pragma once

/// test_revocation_source_fixtures.hpp - shared builders for the revocation-source tests
/// (store, service validation, REST routes, MCP twins): CA certificates minted with OpenSSL, a
/// fake resolver / own-address environment so no test touches DNS or the host's interfaces, and
/// registration-body builders.

#include "revocation_source_service.hpp"

#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <map>
#include <set>
#include <memory>
#include <string>
#include <vector>

namespace rstest {

struct CaSpec {
    std::string cn{"Registered Test CA"};
    bool ca{true};                                      ///< basicConstraints cA:TRUE vs cA:FALSE
    const char* key_usage{"critical,keyCertSign,cRLSign"}; ///< null = no key usage extension
};

/// One PEM certificate over a FRESH P-256 key (so two calls with the same CN are two keys of one
/// subject Name - a CA renewal).
inline std::string make_ca_pem(const CaSpec& spec = {}) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    REQUIRE(kctx);
    REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), NID_X9_62_prime256v1) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);

    std::unique_ptr<X509, decltype(&X509_free)> x(X509_new(), X509_free);
    REQUIRE(x);
    REQUIRE(X509_set_version(x.get(), 2) == 1);
    static std::uint64_t serial = 0x5eed0000ULL;
    REQUIRE(ASN1_INTEGER_set_uint64(X509_get_serialNumber(x.get()), ++serial) == 1);
    X509_NAME* name = X509_get_subject_name(x.get());
    REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                       reinterpret_cast<const unsigned char*>(spec.cn.c_str()), -1,
                                       -1, 0) == 1);
    REQUIRE(X509_set_issuer_name(x.get(), name) == 1);
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(x.get()), -300) != nullptr);
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(x.get()), 3600L * 24 * 365) != nullptr);
    REQUIRE(X509_set_pubkey(x.get(), key.get()) == 1);
    const auto add_ext = [&](int nid, const char* value) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x.get(), x.get(), nullptr, nullptr, 0);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
            X509V3_EXT_conf_nid(nullptr, &ctx, nid, value), X509_EXTENSION_free);
        REQUIRE(ext);
        REQUIRE(X509_add_ext(x.get(), ext.get(), -1) == 1);
    };
    add_ext(NID_subject_key_identifier, "hash");
    add_ext(NID_basic_constraints, spec.ca ? "critical,CA:TRUE" : "CA:FALSE");
    if (spec.key_usage != nullptr)
        add_ext(NID_key_usage, spec.key_usage);
    REQUIRE(X509_sign(x.get(), key.get(), EVP_sha256()) > 0);
    std::unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new(BIO_s_mem()), BIO_free);
    REQUIRE(PEM_write_bio_X509(out.get(), x.get()) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(out.get(), &data);
    return std::string(data, static_cast<std::size_t>(len));
}

/// A PEM PRIVATE KEY block (never accepted in ca_certificates).
inline std::string make_key_pem() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), NID_X9_62_prime256v1) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new(BIO_s_mem()), BIO_free);
    REQUIRE(PEM_write_bio_PrivateKey(out.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(out.get(), &data);
    return std::string(data, static_cast<std::size_t>(len));
}

/// The own address the fake environment reports; a URL resolving to it is always refused.
inline constexpr const char* kOwnAddress = "10.9.9.9";

/// Knobs of the fake environment beyond the DNS table and own addresses.
struct FakeEnvOptions {
    std::vector<std::string> own{kOwnAddress};
    bool own_fails{false};                       ///< interface enumeration fails (nullopt)
    std::set<std::string> dns_unavailable;       ///< hosts whose lookup times out
    std::vector<yuzu::server::oidc::egress::Nat64Prefix> nat64;
    std::vector<std::string>* degrades{nullptr}; ///< records every note_degrade reason
    int* own_calls{nullptr};                     ///< counts local_addresses() calls
};

/// A resolver over a fixed table (a name absent from it does not resolve) and a fixed set of
/// own addresses. Literal hosts never reach the resolver.
inline yuzu::server::revocation_source::EgressEnv
fake_env(std::map<std::string, std::vector<std::string>> dns = {}, FakeEnvOptions opt = {}) {
    using yuzu::server::revocation_source::EgressEnv;
    EgressEnv env;
    env.resolve = [dns = std::move(dns), un = opt.dns_unavailable](
                      const std::string& host, std::chrono::milliseconds) -> EgressEnv::Resolved {
        if (un.contains(host))
            return {EgressEnv::ResolveStatus::kUnavailable, {}};
        const auto it = dns.find(host);
        if (it == dns.end())
            return {EgressEnv::ResolveStatus::kNotFound, {}};
        return {EgressEnv::ResolveStatus::kOk, it->second};
    };
    env.local_addresses = [own = opt.own, fails = opt.own_fails, calls = opt.own_calls](
                              std::chrono::milliseconds)
        -> std::optional<std::vector<std::string>> {
        if (calls)
            ++*calls;
        if (fails)
            return std::nullopt;
        return own;
    };
    env.nat64_prefixes = opt.nat64;
    if (opt.degrades)
        env.note_degrade = [d = opt.degrades](std::string_view r) { d->emplace_back(r); };
    return env;
}

/// The default DNS table of the tests: a public CDN, an internal host, and the refused kinds.
inline std::map<std::string, std::vector<std::string>> default_dns() {
    return {
        {"crl.example.com", {"93.184.216.34"}},       // public
        {"pki.corp.example", {"10.20.30.40"}},         // private
        {"dual.example.com", {"93.184.216.34", "10.20.30.41"}}, // public + private
        {"mixed-loop.example.com", {"93.184.216.34", "127.0.0.1"}},
        {"shorthand.example.com", {"127.0.0.1"}},      // a name that resolves to loopback
        {"127.1", {"127.0.0.1"}},                      // the numeric shorthand: not a canonical quad
        {"metadata.example.com", {"169.254.169.254"}},
        {"linklocal.example.com", {"169.254.1.1"}},
        {"multicast.example.com", {"224.0.0.1"}},
        {"unspecified.example.com", {"0.0.0.0"}},
        {"self.example.com", {kOwnAddress}},
        {"mapped-self.example.com", {"::ffff:10.9.9.9"}},
        {"v6.example.com", {"2606:2800:220:1:248:1893:25c8:1946"}}, // public IPv6
        {"zone.example.com", {"fe80::1%eth0"}},        // link-local with a zone
    };
}

inline nlohmann::json url_entry(const std::string& url, std::vector<std::string> confirmed = {}) {
    nlohmann::json j{{"url", url}};
    if (!confirmed.empty())
        j["confirmed_address_classes"] = confirmed;
    return j;
}

/// A valid registration body: one CA certificate, one public URL confirmed as `public`.
inline nlohmann::json valid_body(const std::string& cn = "Registered Test CA",
                                 const std::string& name = "Corp issuing CA") {
    return {{"name", name},
            {"ca_certificates", nlohmann::json::array({make_ca_pem({.cn = cn})})},
            {"crl_urls", nlohmann::json::array({url_entry("http://crl.example.com/ca.crl",
                                                          {"public"})})}};
}

} // namespace rstest
