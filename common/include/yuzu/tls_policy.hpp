#pragma once

/**
 * tls_policy.hpp -- shared TLS 1.2 cipher allow-list, applied identically to
 * every listener in the process: the gRPC agent/management listeners, the
 * gRPC gateway-command client, and the HTTPS dashboard listener (#4722 Part
 * A; agents/core is Part B, not yet pinned by this header).
 *
 * WHY A PROCESS-ENVIRONMENT VARIABLE FOR gRPC. gRPC's public C++ credentials
 * API (`grpc::SslServerCredentialsOptions`, `grpc::SslCredentialsOptions`)
 * has no cipher/ciphersuite setter of its own -- verified against
 * `grpcpp/security/tls_credentials_options.h`, whose experimental
 * `TlsCredentialsOptions` exposes only `set_min_tls_version`/
 * `set_max_tls_version`, no cipher-list method either. The only lever gRPC's
 * OpenSSL/BoringSSL-derived core (`libgrpc`/`libgpr`) exposes is the
 * `GRPC_SSL_CIPHER_SUITES` environment variable, read once through
 * `grpc_core::ConfigVars` on first use and applied via
 * `SSL_CTX_set_cipher_list` -- confirmed by `nm -u` over every
 * `libgrpc*`/`libgpr` archive in the vcpkg prefix: they reference
 * `SSL_CTX_set_cipher_list` and never `SSL_CTX_set_ciphersuites`. That means
 * TLS 1.3 ciphersuite selection is not influenced by this variable (or by
 * anything else gRPC exposes) -- it is always OpenSSL's own default
 * (`TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`,
 * confirmed by `strings` over `libgpr.a`), and `tls_policy_report_lines()`
 * says so explicitly rather than implying this pin covers TLS 1.3 too.
 *
 * ORDERING IS THE CONTRACT: `pin_grpc_cipher_env()` must run before the
 * first gRPC call in the process, because `ConfigVars` snapshots the
 * environment once and never re-reads it. `main.cpp` calls it before
 * constructing `CLI::App` (which is itself before any gRPC symbol runs) --
 * see the ordering-contract comment there. It is an UNCONDITIONAL overwrite:
 * an operator- or container-inherited value for `GRPC_SSL_CIPHER_SUITES` is
 * never honoured. That is a deliberate design choice, not an oversight --
 * this policy is meant to be the floor, not a tunable an inherited
 * environment can silently loosen.
 *
 * WHY THE LEGACY (NOT EXPERIMENTAL) TLS CREDENTIALS API: settled by Alex for
 * this PR. The experimental `grpc::experimental::TlsServerCredentials`/
 * `TlsCredentialsOptions` API does not close the cipher-setter gap either
 * (see above), so migrating to it would add API-surface churn without
 * buying cipher control. No ADR was written for this (Alex's call) --
 * this comment is the durable record of the decision and its evidence.
 *
 * FIREWALL NOTE (`common/include/` firewall, CLAUDE.md/AGENTS.md "Project
 * layout"): this header does ONE process-environment write
 * (`pin_grpc_cipher_env()`) plus memory-only OpenSSL `SSL_CTX` calls. No
 * file or socket I/O, no store or wire types, no server-trust-boundary
 * authority -- it selects which ciphers TLS may negotiate, it authenticates
 * nobody. Named as the second exception in both files' firewall annotation
 * alongside `shutdown_watcher.hpp`.
 */

#include <array>
#include <cstdlib>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace yuzu::tls {

/// The six-suite TLS 1.2 allow-list applied to every listener/client in this
/// process. All ECDHE (forward secrecy); both ECDSA and RSA families so
/// operator-supplied RSA certificates keep working. NUL-terminated string
/// literal -- `.data()` is safe to pass directly to a C API expecting a
/// C string (see `apply_tls12_cipher_list`).
inline constexpr std::string_view kTls12CipherList =
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305";

/// The same six suites as individual names, in the same order, for tests
/// and for building the startup report line without re-parsing the list.
inline constexpr std::array<std::string_view, 6> kTls12CipherNames{
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",   "ECDHE-RSA-CHACHA20-POLY1305",
};

/// The environment variable gRPC's ConfigVars reads on first use. NUL-
/// terminated string literal -- `.data()` is safe as a C string.
inline constexpr std::string_view kGrpcCipherSuitesEnvVar = "GRPC_SSL_CIPHER_SUITES";

/// Pin `GRPC_SSL_CIPHER_SUITES` to `kTls12CipherList` in this process's
/// environment, unconditionally overwriting anything already there. Must
/// run before the first gRPC call (see header comment). Returns false only
/// if the underlying platform call fails.
[[nodiscard]] inline bool pin_grpc_cipher_env() noexcept {
#ifdef _WIN32
    return _putenv_s(kGrpcCipherSuitesEnvVar.data(), kTls12CipherList.data()) == 0;
#else
    return ::setenv(kGrpcCipherSuitesEnvVar.data(), kTls12CipherList.data(), 1) == 0;
#endif
}

/// The result of resolving `kTls12CipherList` (or a caller-supplied list, for
/// tests) against the OpenSSL build actually linked: which of its entries
/// resolved to a usable TLS 1.2 cipher, and which TLS 1.3 suites this
/// OpenSSL build offers by default (informational only -- see the header
/// comment on why gRPC never lets us pin those).
struct CipherResolution {
    std::vector<std::string> tls12;
    std::vector<std::string> tls13;
};

/// Why `resolve_cipher_policy` failed to produce a usable TLS 1.2 cipher
/// set. Kept distinct (rather than collapsed to nullopt) so a caller can
/// report the actual cause instead of a single generic message.
enum class CipherPolicyError {
    context_unavailable, ///< SSL_CTX_new failed.
    list_rejected,       ///< SSL_CTX_set_cipher_list rejected the list outright.
    no_tls12_ciphers,    ///< The list applied but resolved to zero TLS 1.2 ciphers.
};

/// The exact critical-startup message for each `CipherPolicyError` cause, as
/// a pure function so the enum-to-message mapping is testable without
/// needing to actually trigger the underlying OpenSSL failure (in
/// particular, `context_unavailable` is an OOM-class condition that cannot
/// be forced in a unit test). The caller (main.cpp) still owns the
/// `spdlog::critical(...)` call and the `EXIT_FAILURE` decision.
[[nodiscard]] inline std::string
describe_cipher_policy_error(CipherPolicyError err, std::string_view list = kTls12CipherList) {
    switch (err) {
    case CipherPolicyError::context_unavailable:
        return "TLS policy: could not create an OpenSSL context to resolve the cipher "
               "policy — refusing to start";
    case CipherPolicyError::list_rejected:
        return std::string("TLS policy: cipher list '") + std::string(list) +
               "' was rejected outright by this OpenSSL build — refusing to start";
    case CipherPolicyError::no_tls12_ciphers:
        return std::string("TLS policy: cipher list '") + std::string(list) +
               "' resolves to zero TLS 1.2 ciphers in this OpenSSL build — refusing to start";
    }
    return "TLS policy: unknown cipher policy error — refusing to start";
}

/// Resolve `list` against a throwaway `SSL_CTX` and partition the resulting
/// cipher set by protocol version. Fails if the context could not be
/// created, the list failed to apply, or it resolved to zero usable TLS 1.2
/// ciphers (an allow-list that silently resolves to nothing is refused
/// rather than treated as "no policy").
[[nodiscard]] inline std::expected<CipherResolution, CipherPolicyError>
resolve_cipher_policy(std::string_view list = kTls12CipherList) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_method()),
                                                           &SSL_CTX_free);
    if (!ctx) {
        ERR_clear_error();
        return std::unexpected(CipherPolicyError::context_unavailable);
    }

    if (SSL_CTX_set_cipher_list(ctx.get(), std::string(list).c_str()) != 1) {
        ERR_clear_error();
        return std::unexpected(CipherPolicyError::list_rejected);
    }

    CipherResolution result;
    STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(ctx.get());
    const int n = ciphers ? sk_SSL_CIPHER_num(ciphers) : 0;
    for (int i = 0; i < n; ++i) {
        const SSL_CIPHER* c = sk_SSL_CIPHER_value(ciphers, i);
        if (!c)
            continue;
        const char* name = SSL_CIPHER_get_name(c);
        if (!name)
            continue;
        if (std::string_view(SSL_CIPHER_get_version(c)) == "TLSv1.3") {
            result.tls13.emplace_back(name);
        } else {
            result.tls12.emplace_back(name);
        }
    }
    ERR_clear_error();

    if (result.tls12.empty())
        return std::unexpected(CipherPolicyError::no_tls12_ciphers);
    return result;
}

/// Apply `kTls12CipherList` to an already-constructed `SSL_CTX*` (the HTTPS
/// listener and the certificate-reload validation context; the gRPC
/// listeners go through `pin_grpc_cipher_env()` instead since gRPC builds
/// its own `SSL_CTX` internally). Returns false (and clears the OpenSSL
/// error queue) on failure; never throws.
[[nodiscard]] inline bool apply_tls12_cipher_list(SSL_CTX* ctx) noexcept {
    if (!ctx)
        return false;
    if (SSL_CTX_set_cipher_list(ctx, kTls12CipherList.data()) != 1) {
        ERR_clear_error();
        return false;
    }
    return true;
}

/// Two human-readable lines for the startup log: the pinned TLS 1.2 list,
/// and an explicit disclosure that TLS 1.3 suite selection is not pinned.
[[nodiscard]] inline std::array<std::string, 2>
tls_policy_report_lines(const CipherResolution& r) {
    auto join = [](const std::vector<std::string>& v) {
        std::string out;
        for (size_t i = 0; i < v.size(); ++i) {
            if (i)
                out += ':';
            out += v[i];
        }
        return out;
    };
    std::array<std::string, 2> lines;
    lines[0] = "TLS policy: TLS 1.2 cipher list pinned for gRPC and HTTPS: " + join(r.tls12);
    lines[1] = "TLS policy: TLS 1.3 suites are OpenSSL's own default (" + join(r.tls13) +
              ") — gRPC never calls SSL_CTX_set_ciphersuites on any credentials API, so "
              "TLS 1.3 suite selection is not pinned";
    return lines;
}

} // namespace yuzu::tls
