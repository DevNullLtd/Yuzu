/**
 * test_agent_csr.cpp — Unit tests for the agent-side PKI provisioning module
 * (PKI PR3): EC P-256 keypair + CSR generation, 0600 leaf persistence, and the
 * renew-ahead state machine (Missing/Valid/NeedsRenew/Expired).
 */

#include <yuzu/agent/agent_csr.hpp>

#include "test_helpers.hpp"

#include <atomic_file_write.hpp>

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;
using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

std::string read_all(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

// Minimal self-signed cert over `key_pem` with a chosen validity window — lets
// the inspect() state-machine tests control notBefore/notAfter precisely. Test
// helper only (no RAII niceties); frees what it allocates.
std::string self_sign(const std::string& key_pem, std::chrono::system_clock::time_point nb,
                      std::chrono::system_clock::time_point na, const std::string& cn) {
    BIO* kb = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
    BIO_free(kb);
    REQUIRE(key != nullptr);

    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    ASN1_TIME* t1 = ASN1_TIME_set(nullptr, std::chrono::system_clock::to_time_t(nb));
    ASN1_TIME* t2 = ASN1_TIME_set(nullptr, std::chrono::system_clock::to_time_t(na));
    X509_set1_notBefore(x, t1);
    X509_set1_notAfter(x, t2);
    ASN1_TIME_free(t1);
    ASN1_TIME_free(t2);
    X509_set_pubkey(x, key);
    X509_NAME* nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, nm);
    REQUIRE(X509_sign(x, key, EVP_sha256()) != 0);

    BIO* ob = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(ob, x);
    char* data = nullptr;
    const long len = BIO_get_mem_data(ob, &data);
    std::string out(data, static_cast<std::size_t>(len));
    BIO_free(ob);
    X509_free(x);
    EVP_PKEY_free(key);
    return out;
}

} // namespace

TEST_CASE("generate_key_and_csr produces a valid P-256 key + CSR", "[agent_csr][pki]") {
    auto kc = generate_key_and_csr("agent-abc-123");
    REQUIRE(kc.has_value());
    REQUIRE(kc->private_key_pem.find("PRIVATE KEY") != std::string::npos);
    REQUIRE(kc->csr_pem.find("CERTIFICATE REQUEST") != std::string::npos);

    // Parse the CSR and verify its proof-of-possession self-signature.
    BIO* b = BIO_new_mem_buf(kc->csr_pem.data(), static_cast<int>(kc->csr_pem.size()));
    X509_REQ* req = PEM_read_bio_X509_REQ(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    REQUIRE(req != nullptr);

    EVP_PKEY* pub = X509_REQ_get_pubkey(req);
    REQUIRE(pub != nullptr);
    // POP: the CSR is signed by the key whose public half it carries.
    REQUIRE(X509_REQ_verify(req, pub) == 1);
    // It is an EC P-256 key (256-bit).
    REQUIRE(EVP_PKEY_base_id(pub) == EVP_PKEY_EC);
    REQUIRE(EVP_PKEY_bits(pub) == 256);

    // Subject CN carries the agent id (advisory — the server overrides it).
    X509_NAME* nm = X509_REQ_get_subject_name(req);
    char cn[256] = {};
    REQUIRE(X509_NAME_get_text_by_NID(nm, NID_commonName, cn, sizeof(cn)) > 0);
    REQUIRE(std::string(cn) == "agent-abc-123");

    EVP_PKEY_free(pub);
    X509_REQ_free(req);
}

TEST_CASE("generate_key_and_csr yields a distinct key each call", "[agent_csr][pki]") {
    auto a = generate_key_and_csr("dup");
    auto b = generate_key_and_csr("dup");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(a->private_key_pem != b->private_key_pem);
    REQUIRE(a->csr_pem != b->csr_pem);
}

TEST_CASE("persist + inspect round-trips and keys are 0600", "[agent_csr][pki]") {
    const fs::path dir = yuzu::test::unique_temp_path("agent-csr-");
    auto kc = generate_key_and_csr("persist-1");
    REQUIRE(kc.has_value());

    const auto now = std::chrono::system_clock::now();
    const std::string leaf = self_sign(kc->private_key_pem, now - 1h, now + 24h * 365, "persist-1");
    const std::string chain = self_sign(kc->private_key_pem, now - 1h, now + 24h * 3650, "Test CA");

    REQUIRE(persist_provisioned_cert(dir, kc->private_key_pem, leaf, chain));
    const auto paths = provisioned_cert_paths(dir);
    REQUIRE(fs::exists(paths.key_path));
    REQUIRE(fs::exists(paths.cert_path));
    REQUIRE(fs::exists(paths.ca_path));
    REQUIRE(read_all(paths.cert_path) == leaf);
    REQUIRE(read_all(paths.key_path) == kc->private_key_pem);

#ifndef _WIN32
    // Key must not be group/other-readable.
    const auto perms = fs::status(paths.key_path).permissions();
    REQUIRE((perms & fs::perms::group_all) == fs::perms::none);
    REQUIRE((perms & fs::perms::others_all) == fs::perms::none);
    // The cert dir itself is owner-only (0700) — a regression that drops the
    // fs::permissions() call in persist_provisioned_cert would surface here.
    const auto dperms = fs::status(dir).permissions();
    REQUIRE((dperms & fs::perms::group_all) == fs::perms::none);
    REQUIRE((dperms & fs::perms::others_all) == fs::perms::none);
    // The public artifacts are NOT narrowed to 0600: owner_only_mode=false, so
    // the process umask applies (a regression passing true would fail here).
    const mode_t u = ::umask(0);
    ::umask(u);
    CHECK((fs::status(paths.cert_path).permissions() & fs::perms::mask) ==
          static_cast<fs::perms>(0666 & ~u));
#endif

    // A fresh 1-year leaf is Valid.
    REQUIRE(inspect_provisioned_cert(dir, now) == CertState::Valid);

    fs::remove_all(dir);
}

TEST_CASE("inspect reports Missing when nothing is provisioned", "[agent_csr][pki]") {
    const fs::path dir = yuzu::test::unique_temp_path("agent-csr-missing-");
    REQUIRE(inspect_provisioned_cert(dir) == CertState::Missing);
}

TEST_CASE("inspect renew-ahead state machine", "[agent_csr][pki]") {
    const fs::path dir = yuzu::test::unique_temp_path("agent-csr-sm-");
    auto kc = generate_key_and_csr("sm-1");
    REQUIRE(kc.has_value());

    // A 300-day window: notBefore = now-100d, notAfter = now+200d. 2/3 of the
    // 300-day life elapses at now+100d, so:
    const auto now = std::chrono::system_clock::now();
    const auto nb = now - 24h * 100;
    const auto na = now + 24h * 200;
    const std::string leaf = self_sign(kc->private_key_pem, nb, na, "sm-1");
    REQUIRE(persist_provisioned_cert(dir, kc->private_key_pem, leaf, ""));

    // Just after notBefore → well before the 2/3 mark → Valid.
    REQUIRE(inspect_provisioned_cert(dir, nb + 24h) == CertState::Valid);
    // Boundary exactness: renew_at = nb + (na-nb)*2/3 = nb + 200d. One second
    // before is still Valid; exactly at the threshold flips to NeedsRenew (the
    // `now >= renew_at` comparison + integer-division rounding are pinned here).
    REQUIRE(inspect_provisioned_cert(dir, nb + 24h * 200 - 1s) == CertState::Valid);
    REQUIRE(inspect_provisioned_cert(dir, nb + 24h * 200) == CertState::NeedsRenew);
    // Past the 2/3 mark but before expiry → NeedsRenew.
    REQUIRE(inspect_provisioned_cert(dir, nb + 24h * 250) == CertState::NeedsRenew);
    // After notAfter → Expired.
    REQUIRE(inspect_provisioned_cert(dir, na + 24h) == CertState::Expired);

    fs::remove_all(dir);
}

TEST_CASE("persist refuses an empty key or leaf", "[agent_csr][pki]") {
    const fs::path dir = yuzu::test::unique_temp_path("agent-csr-empty-");
    REQUIRE_FALSE(persist_provisioned_cert(dir, "", "leaf", "chain"));
    REQUIRE_FALSE(persist_provisioned_cert(dir, "key", "", "chain"));
}

TEST_CASE("inspect treats a garbage leaf as Missing", "[agent_csr][pki]") {
    const fs::path dir = yuzu::test::unique_temp_path("agent-csr-garbage-");
    const auto paths = provisioned_cert_paths(dir);
    fs::create_directories(dir);
    {
        std::ofstream(paths.key_path) << "not a key";
        std::ofstream(paths.cert_path) << "-----BEGIN CERTIFICATE-----\nnonsense\n-----END CERTIFICATE-----\n";
    }
    REQUIRE(inspect_provisioned_cert(dir) == CertState::Missing);
    fs::remove_all(dir);
}

TEST_CASE("inspect reports Missing for a leaf that does not match the key on disk "
          "(partial renewal)",
          "[agent_csr][pki]") {
    const fs::path dir = yuzu::test::unique_temp_path("agent-csr-mismatch-");
    const auto now = std::chrono::system_clock::now();
    auto kc1 = generate_key_and_csr("pair-1");
    REQUIRE(kc1.has_value());
    const std::string leaf = self_sign(kc1->private_key_pem, now - 1h, now + 24h * 365, "pair-1");
    REQUIRE(persist_provisioned_cert(dir, kc1->private_key_pem, leaf, ""));
    REQUIRE(inspect_provisioned_cert(dir, now) == CertState::Valid);

    // The on-disk state a key-success/leaf-failure renewal leaves: old leaf, new key.
    const auto paths = provisioned_cert_paths(dir);
    auto kc2 = generate_key_and_csr("pair-2");
    REQUIRE(kc2.has_value());
    REQUIRE(yuzu::shared::write_file_atomic(paths.key_path, kc2->private_key_pem,
                                            {.owner_only_mode = true}));
    CHECK(inspect_provisioned_cert(dir, now) == CertState::Missing);

    // Restoring the matching key makes it Valid again: the check is the pairing.
    REQUIRE(yuzu::shared::write_file_atomic(paths.key_path, kc1->private_key_pem,
                                            {.owner_only_mode = true}));
    CHECK(inspect_provisioned_cert(dir, now) == CertState::Valid);

    // A key file that is not a private key is Missing too.
    REQUIRE(yuzu::shared::write_file_atomic(paths.key_path, "not a key",
                                            {.owner_only_mode = true}));
    CHECK(inspect_provisioned_cert(dir, now) == CertState::Missing);

    // An ENCRYPTED key fails to Missing (a terminal run would prompt without the no-op
    // passphrase callback; CI has no tty either way).
    BIO* pb = BIO_new_mem_buf(kc1->private_key_pem.data(),
                              static_cast<int>(kc1->private_key_pem.size()));
    EVP_PKEY* pk = PEM_read_bio_PrivateKey(pb, nullptr, nullptr, nullptr);
    BIO_free(pb);
    REQUIRE(pk != nullptr);
    BIO* eb = BIO_new(BIO_s_mem());
    REQUIRE(PEM_write_bio_PrivateKey(eb, pk, EVP_aes_256_cbc(), nullptr, 0, nullptr,
                                     const_cast<char*>("hunter2")) == 1);
    char* ed = nullptr;
    const long el = BIO_get_mem_data(eb, &ed);
    const std::string enc(ed, static_cast<std::size_t>(el));
    BIO_free(eb);
    EVP_PKEY_free(pk);
    REQUIRE(enc.find("ENCRYPTED") != std::string::npos);
    REQUIRE(yuzu::shared::write_file_atomic(paths.key_path, enc, {.owner_only_mode = true}));
    CHECK(inspect_provisioned_cert(dir, now) == CertState::Missing);

    fs::remove_all(dir);
}
