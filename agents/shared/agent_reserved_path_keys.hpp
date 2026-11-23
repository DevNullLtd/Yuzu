#pragma once

/// @file agent_reserved_path_keys.hpp
/// WP06 F55: the ONE authoritative list of the `agent.*` plugin-config keys that publish a PATH
/// to something the agent treats as secret or trust-bearing. The filesystem plugin derives its
/// reserved set from these arrays (a dir key reserves the directory and everything under it; a
/// file key reserves the file and its rotated `<file>.<n>` siblings). agent.cpp publishes the
/// values; `tests/test_agent_reserved_path_keys.py` fails when agent.cpp publishes a new path-like
/// `agent.*` key that is in none of the three arrays, so a new credential path cannot ship
/// readable through `FileRetrieval:Read`. EXTEND these arrays, never fork a second list.
/// Not covered (cannot be enumerated): well-known install-path certificates found by
/// auto-discovery outside cert_dir/data_dir, and Windows certificate-store material.

#include <array>
#include <string_view>

namespace yuzu::shared::agent_paths {

/// Directories: the directory and everything beneath it is refused.
inline constexpr std::array<std::string_view, 2> kReservedDirKeys = {
    "agent.data_dir", // agent.db, guardian/dedup stores, enrolment state, auto-provisioned certs
    "agent.cert_dir", // agent-client.key / agent-client.pem / agent-ca.pem
};

/// Files: the file (and rotated siblings) is refused.
inline constexpr std::array<std::string_view, 8> kReservedFileKeys = {
    "agent.log_file",              // the agent log (a session id may appear in it)
    "agent.tls_ca_cert",           // trust anchor
    "agent.tls_client_cert",       // mTLS identity
    "agent.tls_client_key",        // mTLS private key
    "agent.enrollment_token_file", // enrolment bearer token
    "agent.plugin_allowlist",      // plugin integrity trust list
    "agent.plugin_trust_bundle",   // plugin code-signing trust anchors
    "agent.update_trust_bundle",   // OTA update trust anchors
};

/// Path-like keys that are deliberately NOT reserved, each with its reason.
inline constexpr std::array<std::string_view, 2> kPublishedNonSecretPathKeys = {
    "agent.plugin_dir",                 // plugin binaries: public code, not secret
    "agent.container_runtime_endpoint", // a socket the operator opted into; guarded by its own design note
};

} // namespace yuzu::shared::agent_paths
