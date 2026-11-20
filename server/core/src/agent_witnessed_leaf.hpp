#pragma once

/// @file agent_witnessed_leaf.hpp
///
/// WP01: does a client certificate the GATEWAY witnessed in an agent's TLS handshake prove that the
/// caller is agent `agent_id`? Used by `ServerImpl` (wired into `AgentIdentityHooks::
/// attested_leaf_proves`) for the gateway-relayed re-registration path. Header-only and free of
/// store, wire and server state so the whole predicate is unit-testable with real certificates
/// (`tests/unit/server/test_agent_witnessed_leaf.cpp`); `ServerImpl` supplies the three things it
/// owns (the issuing CA certificate, the revocation check, the URI-segment encoder).
///
/// The gateway's agent listener accepts ANY certificate a client presents (`witness_client_cert`:
/// a stale or foreign leaf must not abort the handshake and lock an agent out), so this function is
/// the ONLY verifier and every check here is load-bearing:
///   - the chain verifies to OUR issuing CA (an UNCACHED verify: a peer can present arbitrarily
///     many self-made certificates and a verdict cache would remember each one);
///   - the leaf is inside its validity window now;
///   - it is an AGENT leaf: the install-scoped `.../agent/<id>` URI SAN `sign_agent_csr` sets, which a
///     code-signing leaf (empty SAN) never carries;
///   - its CN is exactly `agent_id`;
///   - it is not revoked (the callback fails CLOSED on a degraded read, which here means "no proof").
/// The TLS handshake (CertificateVerify) is what proves the caller holds the leaf's private key; this
/// proves the leaf is one WE issued for THIS agent id.

#include <chrono>
#include <functional>
#include <string>
#include <string_view>

#include "x509_ca.hpp"

namespace yuzu::server {

/// PEM from the wire is size-bounded before any parse.
inline constexpr std::size_t kMaxWitnessedLeafPemBytes = 16 * 1024;

[[nodiscard]] inline bool witnessed_leaf_proves_agent_identity(
    std::string_view cert_pem, std::string_view agent_id, std::string_view issuing_ca_cert_pem,
    std::chrono::system_clock::time_point now,
    const std::function<bool(const std::string& cert_pem)>& is_revoked,
    const std::function<std::string(std::string_view)>& uri_encode_segment) {
    if (agent_id.empty() || cert_pem.empty() || cert_pem.size() > kMaxWitnessedLeafPemBytes ||
        issuing_ca_cert_pem.empty() || !is_revoked || !uri_encode_segment)
        return false;
    // Cheap checks on attacker-controlled input first, the chain verify second.
    const auto details = pki::parse_certificate(cert_pem);
    if (!details || details->subject.common_name != agent_id)
        return false;
    if (now < details->not_before - pki::kClockSkewBackdate || now >= details->not_after)
        return false;
    const std::string want_suffix = "/agent/" + uri_encode_segment(agent_id);
    bool agent_uri = false;
    for (const auto& uri : details->san.uris) {
        if (uri.size() >= want_suffix.size() &&
            uri.compare(uri.size() - want_suffix.size(), want_suffix.size(), want_suffix) == 0) {
            agent_uri = true;
            break;
        }
    }
    if (!agent_uri)
        return false;
    if (!pki::verify_chain(cert_pem, issuing_ca_cert_pem))
        return false;
    return !is_revoked(std::string(cert_pem));
}

} // namespace yuzu::server
