#include "grpc_tls_credentials.hpp"

#include <spdlog/spdlog.h>

#include "file_utils.hpp"

#include <yuzu/secure_zero.hpp>

namespace yuzu::server::detail {

namespace {

// #4722 F1/G1: zero the private key material on every exit path, not just the
// success path. Both references are bound at construction — `raw_key` covers
// the pre-move early returns (missing/unreadable cert or key); `opts` covers
// the post-move early returns (CA unreadable; no CA and no insecure opt-in)
// and the success path alike. Binding `opts` by reference at construction (no
// nullable pointer, no later assignment) means the guard cannot exist before
// the `SslServerCredentialsOptions` it scrubs, so C++'s reverse-construction-
// order destruction rule enforces the guard running before that options
// object's vector backing store is freed — the guard is declared AFTER
// `ssl_opts` for exactly this reason; do not reorder them. Before `ssl_opts`
// is populated (the raw-key early return below), the guard simply zeroes an
// empty `pem_key_cert_pairs`, which is harmless.
struct KeyZeroGuard {
    std::string& raw_key;
    grpc::SslServerCredentialsOptions& opts;
    KeyZeroGuard(std::string& k, grpc::SslServerCredentialsOptions& o) : raw_key(k), opts(o) {}
    ~KeyZeroGuard() {
        yuzu::secure_zero(raw_key);
        for (auto& kc : opts.pem_key_cert_pairs) {
            yuzu::secure_zero(kc.private_key);
        }
    }
    KeyZeroGuard(const KeyZeroGuard&) = delete;
    KeyZeroGuard& operator=(const KeyZeroGuard&) = delete;
};

// #4722 G4: same construction-order-enforced discipline as KeyZeroGuard above,
// for the sibling client-credentials builder — the reference is bound at
// construction (never a nullable pointer assigned later), so the guard scrubs
// all three PEM buffers on every exit (the two early-return failure paths and
// the success path alike) instead of relying on manual secure_zero calls at
// each exit point.
struct SslOptsZeroGuard {
    grpc::SslCredentialsOptions& opts;
    explicit SslOptsZeroGuard(grpc::SslCredentialsOptions& o) : opts(o) {}
    ~SslOptsZeroGuard() {
        yuzu::secure_zero(opts.pem_private_key);
        yuzu::secure_zero(opts.pem_cert_chain);
        yuzu::secure_zero(opts.pem_root_certs);
    }
    SslOptsZeroGuard(const SslOptsZeroGuard&) = delete;
    SslOptsZeroGuard& operator=(const SslOptsZeroGuard&) = delete;
};

} // namespace

std::shared_ptr<grpc::ServerCredentials>
build_server_tls_credentials(const std::filesystem::path& cert_path,
                              const std::filesystem::path& key_path,
                              const std::filesystem::path& ca_path,
                              bool insecure_skip_client_verify, bool require_client_cert,
                              std::string_view listener_name) {
    if (cert_path.empty() || key_path.empty()) {
        spdlog::error("{} TLS requires certificate and key", listener_name);
        return nullptr;
    }

    if (!detail::validate_key_file_permissions(key_path, listener_name)) {
        return nullptr;
    }

    auto cert = detail::read_file_contents(cert_path);
    auto key = detail::read_file_contents(key_path);
    grpc::SslServerCredentialsOptions ssl_opts;
    KeyZeroGuard key_guard(key, ssl_opts);
    if (cert.empty() || key.empty()) {
        spdlog::error("Failed to read {} TLS cert/key files", listener_name);
        return nullptr;
    }

    grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert;
    key_cert.private_key = std::move(key);
    key_cert.cert_chain = std::move(cert);
    ssl_opts.pem_key_cert_pairs.push_back(std::move(key_cert));

    if (!ca_path.empty()) {
        auto ca = detail::read_file_contents(ca_path);
        if (ca.empty()) {
            spdlog::error("Failed to read {} CA cert from {}", listener_name, ca_path.string());
            return nullptr;
        }

        ssl_opts.pem_root_certs = std::move(ca);
        // Under built-in default certs the agent has no client cert yet
        // (per-agent issuance is PR3): REQUEST + VERIFY if presented, but do
        // NOT REQUIRE — otherwise no agent could connect. Operator-provided
        // certs keep the strict REQUIRE posture.
        ssl_opts.client_certificate_request =
            require_client_cert ? GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY
                                : GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY;
    } else {
        if (!insecure_skip_client_verify) {
            spdlog::error("{} TLS requires --ca-cert (or enable "
                          "--insecure-skip-client-verify with YUZU_ALLOW_INSECURE_TLS=1)",
                          listener_name);
            return nullptr;
        }
        spdlog::warn("{} TLS running without client certificate verification "
                     "(--insecure-skip-client-verify)",
                     listener_name);
    }

    return grpc::SslServerCredentials(ssl_opts);
}

std::shared_ptr<grpc::ChannelCredentials>
build_mtls_client_credentials(const std::filesystem::path& ca_path,
                               const std::filesystem::path& cert_path,
                               const std::filesystem::path& key_path,
                               std::string_view plane_name) {
    if (cert_path.empty() || key_path.empty()) {
        spdlog::error("{}: TLS is enabled but the server has no "
                      "client cert/key to present for mutual TLS — command forwarding "
                      "DISABLED (fail-closed). Provide server certs or --no-tls.",
                      plane_name);
        return nullptr;
    }
    if (ca_path.empty()) {
        spdlog::error("{}: TLS is enabled but no CA cert is configured "
                      "to verify the gateway — command forwarding DISABLED (fail-closed).",
                      plane_name);
        return nullptr;
    }
    if (!detail::validate_key_file_permissions(key_path, plane_name)) {
        return nullptr;
    }
    grpc::SslCredentialsOptions ssl_opts;
    // #4722 G4 (#1314 L-1): the private key is the sensitive buffer; the CA/cert
    // are public. All three are scrubbed for hygiene by the guard below on
    // every exit, so no cert metadata sits resident longer than needed.
    SslOptsZeroGuard ssl_opts_guard(ssl_opts);
    ssl_opts.pem_root_certs = detail::read_file_contents(ca_path);
    ssl_opts.pem_cert_chain = detail::read_file_contents(cert_path);
    ssl_opts.pem_private_key = detail::read_file_contents(key_path);
    if (ssl_opts.pem_root_certs.empty() || ssl_opts.pem_cert_chain.empty() ||
        ssl_opts.pem_private_key.empty()) {
        spdlog::error("{}: failed to read CA/cert/key for mutual TLS — "
                      "command forwarding DISABLED (fail-closed).",
                      plane_name);
        return nullptr;
    }
    return grpc::SslCredentials(ssl_opts);
}

} // namespace yuzu::server::detail
