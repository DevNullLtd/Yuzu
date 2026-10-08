#pragma once

/// @file grpc_peer_evidence.hpp
/// Reads what the gRPC transport established about a caller, without
/// interpreting it.
///
/// Returns the two facts SEPARATELY: whether the transport authenticated the
/// peer, and the client certificate PEM if the auth context carries one. They
/// are deliberately not collapsed into "the PEM, or empty if unauthenticated"
/// (which is what `AgentServiceImpl::extract_peer_cert_pem` does): a policy that
/// must treat "PEM present but peer not authenticated" as its own denial needs
/// both. That older helper is left as it is for its existing call sites.
///
/// `x509_pem_cert` is the PEM of the presented LEAF only, also when the peer sent a chain
/// (pinned by `test_gateway_peer_guard.cpp`). What gRPC reports when no client certificate was
/// presented is likewise asserted there and not assumed here: the guard denies on either
/// missing input.

#include <string>

#include <grpc/grpc_security_constants.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/auth_context.h>

namespace yuzu::server::grpc_peer {

struct PeerCertEvidence {
    bool authenticated{false};
    std::string pem; ///< empty when no certificate property is present
};

[[nodiscard]] inline PeerCertEvidence read_peer_cert_evidence(const grpc::ServerContext& context) {
    PeerCertEvidence e;
    const auto auth_ctx = context.auth_context();
    if (!auth_ctx)
        return e;
    e.authenticated = auth_ctx->IsPeerAuthenticated();
    const auto vals = auth_ctx->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    if (!vals.empty())
        e.pem.assign(vals.front().data(), vals.front().size());
    return e;
}

} // namespace yuzu::server::grpc_peer
