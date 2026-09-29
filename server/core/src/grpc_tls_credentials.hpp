#pragma once

// grpc_tls_credentials.hpp -- gRPC TLS credential builders extracted from
// ServerImpl (#4722 Part A) so the real-handshake test suite
// (test_grpc_tls_policy.cpp) can drive the exact production credential
// construction instead of building its own parallel copy.

// Belt-and-suspenders for whichever TU includes this file: grpc's own port_platform.h defines
// NOMINMAX before its own windows.h include, but only protects THAT include -- if some earlier,
// unrelated header in the SAME translation unit already pulled in an unguarded windows.h, the
// resulting min/max macros stay live for the rest of the file no matter what this header does.
// Defining them here first is a no-op when the includer already guarded (both branches are
// idempotent #ifndef), and closes the gap for any includer that doesn't.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>

#include <filesystem>
#include <memory>
#include <string_view>

namespace yuzu::server::detail {

/// Build server-side TLS credentials for a gRPC listener (agent or
/// management). Returns nullptr (fail-closed) on missing/unreadable
/// cert material or a permissions failure on the key file.
[[nodiscard]] std::shared_ptr<grpc::ServerCredentials>
build_server_tls_credentials(const std::filesystem::path& cert_path,
                              const std::filesystem::path& key_path,
                              const std::filesystem::path& ca_path,
                              bool insecure_skip_client_verify, bool require_client_cert,
                              std::string_view listener_name);

// HIGH-2 (#1314): mutual-TLS client credentials for the server→gateway command
// plane (ManagementService at --gateway-command-addr). The gateway's mgmt
// listener is the PRIVILEGED command-fan-out plane; without mTLS it is an
// unauthenticated fleet-RCE surface reachable by any container that can route
// to it (incl. a compromised agent). Here the server PRESENTS its own leaf as
// the client cert and VERIFIES the gateway against the install CA, so the
// gateway can require a client cert (strict mTLS) and reject anyone who can't
// present a CA-issued cert. Returns nullptr (fail-closed — caller disables
// command forwarding) if the required cert material is missing/unreadable.
//
// The two directions are NOT symmetric. Server→gateway (here): grpc verifies
// the gateway's identity by SNI/SAN against the dialled host, so the server
// talks only to the real gateway. Gateway→server (the listener's acceptance
// policy): verify_peer authenticates to the CA, NOT to a specific identity.
//
// #1422: the gateway side no longer stops at the CA check. Its mgmt
// listener's grpcbox auth_fun (yuzu_gw_authz:check_mgmt_peer/1) pins the
// peer to THIS server's key — SPKI SHA-256 of the presented leaf against
// {yuzu_gw, mgmt_peer_pins} (default: the default-server.pem in the shared
// cert volume), plus a serverAuth-EKU requirement agent leaves can never
// satisfy (sign_agent_csr grants clientAuth only). So a stolen agent leaf,
// an enrollment-minted CN-collision leaf, or the group-readable
// default-gateway leaf all get UNAUTHENTICATED. Consequence for THIS
// function: the cert presented here must stay the leaf the gateway pins —
// rotating the server leaf out-of-band without updating the pin (or using
// BYO certs without pointing mgmt_peer_pins at them) kills command
// forwarding with UNAUTHENTICATED, not a TLS error.
//
// Residual (tracked on #1422): no CRL/OCSP check on this path yet, so a
// revoked-but-stolen SERVER leaf still passes until rotation; and
// through-gateway operator identity stays app-layer.
[[nodiscard]] std::shared_ptr<grpc::ChannelCredentials>
build_mtls_client_credentials(const std::filesystem::path& ca_path,
                               const std::filesystem::path& cert_path,
                               const std::filesystem::path& key_path, std::string_view plane_name);

} // namespace yuzu::server::detail
