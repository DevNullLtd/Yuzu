/**
 * test_cert_reloader.cpp — Unit tests for certificate hot-reload (H4)
 *
 * Covers: Config defaults, PEM validation, file change detection, permission checks,
 * try_reload failure paths, start/stop lifecycle.
 */

#include <yuzu/server/server.hpp>

#include "cert_reloader.hpp"
#include "file_utils.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <yuzu/tls_policy.hpp>
#endif

#include <string_view>
#include <vector>

using namespace yuzu::server;

// ── Config defaults ────────────────────────────────────────────────────────

TEST_CASE("Cert reload config: defaults", "[cert-reload][config]") {
    Config cfg;
    CHECK(cfg.cert_reload_enabled == true);
    CHECK(cfg.cert_reload_interval_seconds == 60);
}

TEST_CASE("Cert reload config: disabled", "[cert-reload][config]") {
    Config cfg;
    cfg.cert_reload_enabled = false;
    cfg.cert_reload_interval_seconds = 120;
    CHECK(cfg.cert_reload_enabled == false);
    CHECK(cfg.cert_reload_interval_seconds == 120);
}

TEST_CASE("Cert reload: max PEM file size constant", "[cert-reload][config]") {
    CHECK(CertReloader::kMaxPemFileSize == 1024 * 1024);
}

// ── PEM validation (requires OpenSSL) ──────────────────────────────────────

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

namespace {

struct PemPair {
    std::string cert;
    std::string key;
};

PemPair generate_self_signed() {
    PemPair result;

    auto* pkey = EVP_PKEY_new();
    auto* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    auto* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 365 * 24 * 3600);
    X509_set_pubkey(x509, pkey);

    auto* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>("test"), -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    auto* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, x509);
    char* cert_data = nullptr;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    result.cert.assign(cert_data, static_cast<size_t>(cert_len));
    BIO_free(cert_bio);

    auto* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* key_data = nullptr;
    long key_len = BIO_get_mem_data(key_bio, &key_data);
    result.key.assign(key_data, static_cast<size_t>(key_len));
    BIO_free(key_bio);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return result;
}

// Write a PEM pair to disk with secure permissions
void write_pem_files(const std::filesystem::path& cert_path,
                     const std::filesystem::path& key_path,
                     const PemPair& pair) {
    {
        std::ofstream f(cert_path, std::ios::binary | std::ios::trunc);
        f << pair.cert;
    }
    {
        std::ofstream f(key_path, std::ios::binary | std::ios::trunc);
        f << pair.key;
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif
}

// The TLS 1.2 cipher names an SSL_CTX currently carries. TLS 1.3 ciphersuites
// are enumerated by SSL_CTX_get_ciphers too (they're not controlled by
// SSL_CTX_set_cipher_list at all) -- filter to the TLS 1.2 subset the #4722
// pin actually governs, same partition yuzu::tls::resolve_cipher_policy()
// does. Shared by the live-reload test and the build_validation_context
// tests below.
std::vector<std::string> cipher_names(SSL_CTX* c) {
    std::vector<std::string> names;
    STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(c);
    int n = ciphers ? sk_SSL_CIPHER_num(ciphers) : 0;
    for (int i = 0; i < n; ++i) {
        const SSL_CIPHER* sc = sk_SSL_CIPHER_value(ciphers, i);
        if (sc && std::string_view(SSL_CIPHER_get_version(sc)) != "TLSv1.3")
            names.emplace_back(SSL_CIPHER_get_name(sc));
    }
    return names;
}

} // namespace

TEST_CASE("validate_pem_pair: valid cert+key", "[cert-reload][pem]") {
    auto pair = generate_self_signed();
    CHECK(CertReloader::validate_pem_pair(pair.cert, pair.key));
}

TEST_CASE("validate_pem_pair: mismatched cert+key", "[cert-reload][pem]") {
    auto pair1 = generate_self_signed();
    auto pair2 = generate_self_signed();
    CHECK_FALSE(CertReloader::validate_pem_pair(pair1.cert, pair2.key));
}

TEST_CASE("validate_pem_pair: garbage input", "[cert-reload][pem]") {
    CHECK_FALSE(CertReloader::validate_pem_pair("not-a-cert", "not-a-key"));
}

TEST_CASE("validate_pem_pair: empty strings", "[cert-reload][pem]") {
    CHECK_FALSE(CertReloader::validate_pem_pair("", ""));
}

TEST_CASE("validate_pem_pair: binary garbage", "[cert-reload][pem]") {
    std::string binary(256, '\0');
    for (int i = 0; i < 256; ++i)
        binary[static_cast<size_t>(i)] = static_cast<char>(i);
    CHECK_FALSE(CertReloader::validate_pem_pair(binary, binary));
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

// ── File change detection ──────────────────────────────────────────────────

TEST_CASE("CertReloader: construction records mtimes", "[cert-reload][mtime]") {
    // Process-salted scratch dirs (here and in every test below): the previous
    // fixed dir names were cross-JOB shared resources on the shared-identity
    // CI pools — one job's trailing remove_all deleted another job's live
    // test.pem/test-key.pem mid-test (#1883). TempDir's dtor also makes the
    // cleanup exception-safe (the old trailing remove_all was skipped whenever
    // a CHECK/REQUIRE threw). Declared FIRST so it destructs after the
    // reloader (thread joined before the dir goes away).
    yuzu::test::TempDir tmp_dir{"yuzu_cert_reload_mtime-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    {
        std::ofstream(cert_path) << "initial-cert";
        std::ofstream(key_path) << "initial-key";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{60};
    params.web_server = nullptr;

    CertReloader reloader(params);
    CHECK(reloader.reload_count() == 0);
    CHECK(reloader.failure_count() == 0);
}

// ── try_reload failure paths ────────────────────────────────────────────────

TEST_CASE("CertReloader: try_reload fails with null web_server", "[cert-reload][reload]") {
    yuzu::test::TempDir tmp_dir{"yuzu_cert_reload_null-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    // Write valid-looking PEM (just needs to not be empty for the early checks)
    {
        std::ofstream(cert_path) << "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        std::ofstream(key_path) << "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{60};
    params.web_server = nullptr; // <-- null

    CertReloader reloader(params);
    // PEM validation will fail on the fake content (OpenSSL can't parse it)
    // or the null server check will catch it. Either way it should fail safely.
    bool result = reloader.try_reload();
    CHECK_FALSE(result);
    CHECK(reloader.failure_count() > 0);
    CHECK(reloader.reload_count() == 0);
}

TEST_CASE("CertReloader: try_reload fails with empty files", "[cert-reload][reload]") {
    yuzu::test::TempDir tmp_dir{"yuzu_cert_reload_empty-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    // Write empty files (must touch them so they exist with 0 bytes)
    { std::ofstream f(cert_path, std::ios::trunc); f.flush(); }
    { std::ofstream f(key_path, std::ios::trunc); f.flush(); }
#ifndef _WIN32
    // Only set permissions if files exist
    if (std::filesystem::exists(key_path)) {
        std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                    std::filesystem::perms::owner_write);
    }
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{60};
    params.web_server = nullptr;

    CertReloader reloader(params);
    bool result = reloader.try_reload();
    CHECK_FALSE(result);
    CHECK(reloader.failure_count() > 0);
}

// #4722: the only test that reaches the new test_ctx cipher application --
// the reload/lifecycle cases above write fake PEM with a null web_server and
// stop at validate_pem_pair.
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST_CASE("CertReloader: try_reload succeeds against a live SSLServer and keeps the cipher pin",
         "[cert-reload][reload][tls]") {
    yuzu::test::TempDir tmp_dir{"yuzu_test_cert_reload_live-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    write_pem_files(cert_path, key_path, generate_self_signed());

    httplib::SSLServer ssl_server(cert_path.string().c_str(), key_path.string().c_str());
    REQUIRE(ssl_server.is_valid());
    auto* ctx = static_cast<SSL_CTX*>(ssl_server.tls_context());
    REQUIRE(yuzu::tls::apply_tls12_cipher_list(ctx));

    auto names_before = cipher_names(ctx);

    // Overwrite the same files with a SECOND self-signed pair for the reload.
    write_pem_files(cert_path, key_path, generate_self_signed());

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{10};
    params.web_server = &ssl_server;

    CertReloader reloader(params);
    REQUIRE(reloader.try_reload());
    CHECK(reloader.reload_count() == 1);
    CHECK(reloader.failure_count() == 0);

    auto names_after = cipher_names(ctx);
    CHECK(names_after == names_before);
    auto expected = yuzu::tls::resolve_cipher_policy();
    REQUIRE(expected.has_value());
    CHECK(names_after == expected->tls12);
}

// #4722: try_reload()'s pass/fail outcome does not depend on the cipher pin
// applying to the validation context (the pin has no effect on cert/key
// loading or SSL_CTX_check_private_key) -- these two cases are the only way
// to observe build_validation_context's own contract directly.
TEST_CASE("CertReloader::build_validation_context applies the cipher pin and validates cert/key",
         "[cert-reload][tls]") {
    auto pair = generate_self_signed();
    auto validated = CertReloader::build_validation_context(pair.cert, pair.key);
    REQUIRE(validated.has_value());

    auto names = cipher_names(validated->get());
    auto expected = yuzu::tls::resolve_cipher_policy();
    REQUIRE(expected.has_value());
    CHECK(names == expected->tls12);
}

TEST_CASE("CertReloader::build_validation_context rejects a mismatched cert/key pair",
         "[cert-reload][tls]") {
    auto pair_a = generate_self_signed();
    auto pair_b = generate_self_signed();
    auto validated = CertReloader::build_validation_context(pair_a.cert, pair_b.key);
    REQUIRE_FALSE(validated.has_value());
    CHECK(validated.error() == "SSL context test validation rejected");
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

// ── Start / stop lifecycle ──────────────────────────────────────────────────

TEST_CASE("CertReloader: start and stop without crash", "[cert-reload][lifecycle]") {
    yuzu::test::TempDir tmp_dir{"yuzu_cert_reload_lifecycle-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    {
        std::ofstream(cert_path) << "cert-content";
        std::ofstream(key_path) << "key-content";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{10};
    params.web_server = nullptr;

    CertReloader reloader(params);
    reloader.start();
    // Let it run briefly
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    reloader.stop();
    // No crash, no hang
    CHECK(true);
}

TEST_CASE("CertReloader: destructor stops cleanly", "[cert-reload][lifecycle]") {
    yuzu::test::TempDir tmp_dir{"yuzu_cert_reload_dtor-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    {
        std::ofstream(cert_path) << "cert-content";
        std::ofstream(key_path) << "key-content";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    {
        CertReloader::Params params;
        params.cert_path = cert_path;
        params.key_path = key_path;
        params.interval = std::chrono::seconds{10};
        params.web_server = nullptr;

        CertReloader reloader(params);
        reloader.start();
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        // Destructor should call stop() and join the thread
    }
    CHECK(true);
}

// ── Permission validation (Unix only) ──────────────────────────────────────

#ifndef _WIN32
TEST_CASE("validate_key_file_permissions: rejects group-readable", "[cert-reload][perms]") {
    // These two Unix-only tests run on the Linux pool (Big Tam), where all 4
    // runner agents share one /tmp — under the old fixed dir a concurrent job
    // flipping permissions on the SAME key file inverted the expected result.
    yuzu::test::TempDir tmp_dir{"yuzu_perm_grp-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto key_path = tmp / "test-key.pem";

    { std::ofstream(key_path) << "test-key-content"; }

    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write |
                                                std::filesystem::perms::group_read);
    CHECK_FALSE(detail::validate_key_file_permissions(key_path, "test"));

    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
    CHECK(detail::validate_key_file_permissions(key_path, "test"));
}

TEST_CASE("validate_key_file_permissions: rejects others-readable", "[cert-reload][perms]") {
    yuzu::test::TempDir tmp_dir{"yuzu_perm_oth-"};
    const auto& tmp = tmp_dir.path;
    std::filesystem::create_directories(tmp);
    auto key_path = tmp / "test-key.pem";

    { std::ofstream(key_path) << "test-key-content"; }

    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write |
                                                std::filesystem::perms::others_read);
    CHECK_FALSE(detail::validate_key_file_permissions(key_path, "test"));
}
#endif
