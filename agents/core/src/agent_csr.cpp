#include <yuzu/agent/agent_csr.hpp>

#include <atomic_file_write.hpp>

#include <spdlog/spdlog.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <string_view>
#include <system_error>
#include <utility>

namespace yuzu::agent {

// This module uses OpenSSL 3.0 entry points (EVP_EC_gen, ASN1_TIME_to_tm). The
// agent is the widest-deployed Yuzu binary, so fail the build loudly on a
// distro that still ships 1.1.1 rather than emit a binary that link-fails or
// mis-behaves at runtime on an endpoint (#1239 should-fix).
static_assert(OPENSSL_VERSION_NUMBER >= 0x30000000L,
              "Yuzu agent CSR generation requires OpenSSL >= 3.0 "
              "(EVP_EC_gen / ASN1_TIME_to_tm). Rebuild against OpenSSL 3.x.");

namespace fs = std::filesystem;

namespace {

// ── RAII for OpenSSL objects (mirrors server/core/src/x509_ca.cpp) ─────────────
#define YUZU_SSL_PTR(T, freefn)                                                                    \
    struct T##_Deleter {                                                                            \
        void operator()(T* p) const noexcept {                                                      \
            freefn(p);                                                                              \
        }                                                                                          \
    };                                                                                             \
    using T##_ptr = std::unique_ptr<T, T##_Deleter>

YUZU_SSL_PTR(BIO, BIO_free);
YUZU_SSL_PTR(EVP_PKEY, EVP_PKEY_free);
YUZU_SSL_PTR(X509, X509_free);
YUZU_SSL_PTR(X509_REQ, X509_REQ_free);
YUZU_SSL_PTR(X509_NAME, X509_NAME_free);
#undef YUZU_SSL_PTR

void log_ssl_errors(std::string_view ctx) {
    unsigned long e = 0;
    bool any = false;
    while ((e = ERR_get_error()) != 0) {
        std::array<char, 256> buf{};
        ERR_error_string_n(e, buf.data(), buf.size());
        spdlog::error("agent_csr: {}: {}", ctx, buf.data());
        any = true;
    }
    if (!any)
        spdlog::error("agent_csr: {} (no OpenSSL error detail)", ctx);
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (!data || len <= 0)
        return {};
    return std::string(data, static_cast<std::size_t>(len));
}

template <typename Fn>
std::optional<std::string> to_pem(Fn&& write_fn, std::string_view ctx, bool sensitive = false) {
    BIO_ptr bio{BIO_new(BIO_s_mem())};
    if (!bio) {
        log_ssl_errors(ctx);
        return std::nullopt;
    }
    if (write_fn(bio.get()) != 1) {
        log_ssl_errors(ctx);
        return std::nullopt;
    }
    auto out = bio_to_string(bio.get());
    // cpp-safety (#1239): for a private key, scrub the BIO's in-memory copy
    // before BIO_free (which does NOT zero the buffer). The returned std::string
    // is the caller's to scrub (agent.cpp zeroes pending_key_pem after persist).
    if (sensitive) {
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        if (data && len > 0)
            OPENSSL_cleanse(data, static_cast<std::size_t>(len));
    }
    return out;
}

constexpr std::size_t kMaxPemSize = 1024 * 1024; // 1 MiB — far above any cert/key

X509_ptr load_cert(std::string_view pem) {
    if (pem.empty() || pem.size() > kMaxPemSize)
        return nullptr;
    BIO_ptr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!bio)
        return nullptr;
    return X509_ptr{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

EVP_PKEY_ptr load_private_key(std::string_view pem) {
    if (pem.empty() || pem.size() > kMaxPemSize)
        return nullptr;
    BIO_ptr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!bio)
        return nullptr;
    // No-op passphrase callback: an encrypted key must fail to load, never prompt a tty.
    return EVP_PKEY_ptr{PEM_read_bio_PrivateKey(
        bio.get(), nullptr, [](char*, int, int, void*) { return 0; }, nullptr)};
}

std::optional<std::chrono::system_clock::time_point> from_asn1_time(const ASN1_TIME* at) {
    if (!at)
        return std::nullopt;
    std::tm tm{};
    if (ASN1_TIME_to_tm(at, &tm) != 1)
        return std::nullopt;
#ifdef _WIN32
    const std::time_t t = _mkgmtime(&tm);
#else
    const std::time_t t = timegm(&tm);
#endif
    if (t == static_cast<std::time_t>(-1))
        return std::nullopt;
    return std::chrono::system_clock::from_time_t(t);
}

std::string read_text_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in)
        return {};
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

// This helper delegates to yuzu::shared::write_file_atomic (#4723 option 3: one
// audited implementation shared with asset_tags). The residual path-based rename
// window and the Windows DACL gap are shared with asset_tags and documented in
// the banner of agents/shared/atomic_file_write.hpp.
bool write_atomic(const fs::path& dest, const std::string& contents, bool owner_only) {
    auto r = yuzu::shared::write_file_atomic(dest, contents, {.owner_only_mode = owner_only});
    if (!r) {
        spdlog::error("agent_csr: {}", r.error().message);
        return false;
    }
    if (r.value())
        spdlog::warn("agent_csr: {}", r.value()->message);
    return true;
}

} // namespace

std::optional<KeyAndCsr> generate_key_and_csr(const std::string& agent_id) {
    EVP_PKEY_ptr key{EVP_EC_gen("P-256")};
    if (!key) {
        log_ssl_errors("generate_key_and_csr EVP_EC_gen");
        return std::nullopt;
    }
    auto key_pem = to_pem(
        [&](BIO* b) {
            return PEM_write_bio_PrivateKey(b, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        },
        "generate_key_and_csr key to_pem", /*sensitive=*/true);
    if (!key_pem)
        return std::nullopt;

    X509_REQ_ptr req{X509_REQ_new()};
    if (!req || X509_REQ_set_version(req.get(), 0) != 1) {
        log_ssl_errors("generate_key_and_csr req new");
        return std::nullopt;
    }
    X509_NAME_ptr name{X509_NAME_new()};
    if (!name) {
        log_ssl_errors("generate_key_and_csr name new");
        return std::nullopt;
    }
    // O=Yuzu Agent, CN=<agent_id>. Explicit byte lengths (not strlen) so an
    // embedded NUL in a future agent_id can't silently truncate the DN.
    static constexpr char kOrg[] = "Yuzu Agent";
    if (X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(kOrg),
                                   static_cast<int>(sizeof(kOrg) - 1), -1, 0) != 1) {
        log_ssl_errors("generate_key_and_csr name O");
        return std::nullopt;
    }
    if (!agent_id.empty() &&
        X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(agent_id.data()),
                                   static_cast<int>(agent_id.size()), -1, 0) != 1) {
        log_ssl_errors("generate_key_and_csr name CN");
        return std::nullopt;
    }
    if (X509_REQ_set_subject_name(req.get(), name.get()) != 1) {
        log_ssl_errors("generate_key_and_csr set subject");
        return std::nullopt;
    }
    if (X509_REQ_set_pubkey(req.get(), key.get()) != 1) {
        log_ssl_errors("generate_key_and_csr set pubkey");
        return std::nullopt;
    }
    // P-256 → SHA-256 (ECDSA pairs the digest to the curve size).
    if (X509_REQ_sign(req.get(), key.get(), EVP_sha256()) == 0) {
        log_ssl_errors("generate_key_and_csr sign");
        return std::nullopt;
    }
    auto csr_pem =
        to_pem([&](BIO* b) { return PEM_write_bio_X509_REQ(b, req.get()); },
               "generate_key_and_csr csr to_pem");
    if (!csr_pem)
        return std::nullopt;

    return KeyAndCsr{std::move(*key_pem), std::move(*csr_pem)};
}

ProvisionedCertPaths provisioned_cert_paths(const fs::path& cert_dir) {
    return ProvisionedCertPaths{.key_path = cert_dir / "agent-client.key",
                                .cert_path = cert_dir / "agent-client.pem",
                                .ca_path = cert_dir / "agent-ca.pem"};
}

bool persist_provisioned_cert(const fs::path& cert_dir, const std::string& key_pem,
                              const std::string& leaf_pem, const std::string& ca_chain_pem) {
    if (key_pem.empty() || leaf_pem.empty()) {
        spdlog::error("agent_csr: refusing to persist an empty key or leaf");
        return false;
    }
    std::error_code ec;
    fs::create_directories(cert_dir, ec);
    if (ec) {
        spdlog::error("agent_csr: cannot create {}: {}", cert_dir.string(), ec.message());
        return false;
    }
    fs::permissions(cert_dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700

    const auto paths = provisioned_cert_paths(cert_dir);
    // Key first (the secret), then the public artifacts. The two writes are not one
    // transaction: a failure after the key write (rename error, ENOSPC, Windows
    // sharing violation, fsync EIO) leaves the OLD leaf beside the NEW key.
    // inspect_provisioned_cert() detects that pairing mismatch and reports Missing,
    // so the next startup re-enrolls instead of presenting an unusable pair. On first
    // enrollment a crash between writes simply leaves the leaf missing → Missing →
    // clean enroll.
    // PRIVATE key: 0600 from creation, re-asserted on the open fd (no umask window).
    if (!write_atomic(paths.key_path, key_pem, /*owner_only=*/true))
        return false;
    // PUBLIC artifacts (leaf / chain): default perms (umask) are fine - not secrets.
    if (!write_atomic(paths.cert_path, leaf_pem, /*owner_only=*/false))
        return false;
    if (!ca_chain_pem.empty() && !write_atomic(paths.ca_path, ca_chain_pem, /*owner_only=*/false))
        return false;
    spdlog::info("agent_csr: provisioned per-agent client certificate under {}", cert_dir.string());
    return true;
}

CertState inspect_provisioned_cert(const fs::path& cert_dir,
                                   std::chrono::system_clock::time_point now) {
    const auto paths = provisioned_cert_paths(cert_dir);
    std::error_code ec;
    if (!fs::exists(paths.cert_path, ec) || !fs::exists(paths.key_path, ec))
        return CertState::Missing;
    const std::string leaf = read_text_file(paths.cert_path);
    if (leaf.empty())
        return CertState::Missing;
    X509_ptr cert = load_cert(leaf);
    if (!cert)
        return CertState::Missing;
    // The leaf must pair with the key on disk (a renewal that replaced the key but
    // not the leaf leaves a date-valid but unusable pair).
    std::string key_pem = read_text_file(paths.key_path);
    EVP_PKEY_ptr key = load_private_key(key_pem);
    OPENSSL_cleanse(key_pem.data(), key_pem.size());
    if (!key) {
        spdlog::warn("agent_csr: {} is unreadable or not a private key — treating the "
                     "credential as missing",
                     paths.key_path.string());
        return CertState::Missing;
    }
    if (X509_check_private_key(cert.get(), key.get()) != 1) {
        ERR_clear_error();
        spdlog::warn("agent_csr: {} does not match the public key in {} — a renewal "
                     "replaced the key but not the leaf; treating the credential as "
                     "missing so startup re-enrolls",
                     paths.key_path.string(), paths.cert_path.string());
        return CertState::Missing;
    }
    auto nb = from_asn1_time(X509_get0_notBefore(cert.get()));
    auto na = from_asn1_time(X509_get0_notAfter(cert.get()));
    if (!nb || !na || *na <= *nb)
        return CertState::Missing;
    if (now >= *na)
        return CertState::Expired;
    // Renew once two-thirds of the validity window has elapsed (renew-ahead).
    const auto renew_at = *nb + ((*na - *nb) * 2) / 3;
    if (now >= renew_at)
        return CertState::NeedsRenew;
    return CertState::Valid;
}

} // namespace yuzu::agent
