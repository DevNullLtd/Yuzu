#pragma once

/// @file gateway_peer_cert.hpp
/// Checked certificate facts for gateway-upstream peer authorization.
///
/// The only code that turns a presented client certificate (PEM) into the facts
/// `gateway_peer_policy.hpp` decides on: the public-key pin, the serverAuth
/// extended-key-usage flag, and the validity window. Every function is
/// fail-closed: any parse, allocation or digest failure yields `nullopt`, never
/// a success value carrying an empty or partial field.
///
/// THE PIN VALUE. `spki_sha256_hex` is SHA-256 over the full DER
/// SubjectPublicKeyInfo (`i2d_X509_PUBKEY`) as 64 lowercase hex characters. It is
/// meant to equal `yuzu_gw_authz:spki_sha256/1` in the gateway and
///     openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
/// (the unit test pins a fixed vector computed with that pipeline). It is NOT
/// `pki::issuer_key_id` (x509_ca.hpp), which digests only the subjectPublicKey
/// BIT STRING; do not substitute one for the other.
///
/// OWNERSHIP. OpenSSL objects are held in RAII wrappers inside the .cpp; no
/// OpenSSL type crosses this header (`x509_st` is forward-declared for the
/// borrowed-pointer overload). Without OpenSSL support in the build
/// (`CPPHTTPLIB_OPENSSL_SUPPORT` unset) every function returns `nullopt`.

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

struct x509_st; // OpenSSL's X509, forward-declared so this header needs no OpenSSL include.

namespace yuzu::server::gateway_peer {

/// Whole-second wall-clock instants. A 64-bit second count holds any ASN.1 time
/// (the no-expiry sentinel 9999-12-31 included); converting such a value to
/// `system_clock::duration` overflows on libstdc++ (nanosecond ticks), so nothing
/// in the gateway-peer code does.
using CertInstant = std::chrono::sys_seconds;

/// Upper bound on the PEM handed to OpenSSL, so an attacker-controlled blob cannot
/// make the parser allocate without limit. A presented leaf is a few KiB.
inline constexpr std::size_t kMaxCertPemBytes = 64 * 1024;

/// Facts extracted from one certificate. Built only by `parse_cert_facts`, which
/// never returns a value with an empty `spki_sha256_hex`.
struct CertFacts {
    std::string spki_sha256_hex; ///< 64 lowercase hex characters.
    /// The certificate carries an extendedKeyUsage extension that lists serverAuth.
    /// An ABSENT (or malformed) extension is `false`: the usage must be stated.
    bool has_server_auth_eku{false};
    CertInstant not_before{};
    CertInstant not_after{};
};

/// SHA-256 over the DER SubjectPublicKeyInfo of `cert`, 64 lowercase hex.
/// `nullopt` for a null certificate or any encoding/digest failure.
[[nodiscard]] std::optional<std::string> spki_sha256_hex(const x509_st* cert);

/// As above for the FIRST certificate in `cert_pem`. `nullopt` when the input is
/// empty, larger than `kMaxCertPemBytes`, or does not parse.
[[nodiscard]] std::optional<std::string> spki_sha256_hex(std::string_view cert_pem);

/// The facts the policy needs from the first certificate in `cert_pem`.
[[nodiscard]] std::optional<CertFacts> parse_cert_facts(std::string_view cert_pem);

} // namespace yuzu::server::gateway_peer
