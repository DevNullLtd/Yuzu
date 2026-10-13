#pragma once

/// @file agent_csr.hpp
/// Agent-side per-agent mTLS provisioning (PKI PR3).
///
/// On first enrollment the agent generates its OWN EC P-256 keypair and a CSR;
/// the server signs a client leaf bound to agent_id and returns it (the private
/// key never leaves the host). The leaf + key + issuing chain are persisted under
/// the cert-dir (key 0600) and presented on every subsequent connection,
/// upgrading the agent↔server channel to mutual TLS. The leaf is renewed ahead of
/// expiry (at 2/3 of its lifetime).
///
/// Self-contained OpenSSL module: the agent cannot link the server's `x509_ca`
/// engine, but it only needs to PRODUCE a keypair + CSR and inspect a leaf's
/// validity — it never signs certificates.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

namespace yuzu::agent {

/// A freshly generated EC P-256 keypair + its self-signed PKCS#10 CSR.
struct KeyAndCsr {
    std::string private_key_pem; ///< PKCS#8 EC P-256 (unencrypted; persisted 0600).
    std::string csr_pem;         ///< PEM CSR, CN=<agent_id> (server ignores subject).
};

/// Generate an EC P-256 keypair and a CSR with subject CN=<agent_id>. Returns
/// nullopt on any OpenSSL failure (logged). SECURITY: the server sets the issued
/// cert's identity from the authenticated enrollment, never from the CSR — the
/// subject here is advisory and the SAN is intentionally omitted.
[[nodiscard]] YUZU_EXPORT std::optional<KeyAndCsr>
generate_key_and_csr(const std::string& agent_id);

/// Resolved on-disk paths for a provisioned per-agent credential under cert_dir.
struct ProvisionedCertPaths {
    std::filesystem::path key_path;  ///< <cert_dir>/agent-client.key (0600)
    std::filesystem::path cert_path; ///< <cert_dir>/agent-client.pem (leaf)
    std::filesystem::path ca_path;   ///< <cert_dir>/agent-ca.pem (issuing chain)
};

[[nodiscard]] YUZU_EXPORT ProvisionedCertPaths
provisioned_cert_paths(const std::filesystem::path& cert_dir);

/// Persist a freshly issued credential: key 0600 via atomic stage-and-rename,
/// leaf + chain owner-readable. Creates cert_dir (0700) if absent. Returns false
/// on any write failure; a failed write removes its own temp, but a failure AFTER the key
/// write leaves the NEW key beside the OLD leaf — inspect_provisioned_cert() reports that pair
/// as Missing so the next start re-enrols. `ca_chain_pem` may be empty.
[[nodiscard]] YUZU_EXPORT bool persist_provisioned_cert(const std::filesystem::path& cert_dir,
                                                       const std::string& key_pem,
                                                       const std::string& leaf_pem,
                                                       const std::string& ca_chain_pem);

/// State of the on-disk provisioned credential.
enum class CertState {
    Missing,    ///< No usable leaf+key present → must enroll (send a CSR).
    Valid,      ///< Present and not yet at the renewal threshold → use as-is.
    NeedsRenew, ///< Present, still valid, but past 2/3 of its lifetime → renew.
    Expired,    ///< Present but already expired → treat like Missing (re-enroll).
};

/// Inspect the persisted leaf (if any) and decide whether the agent should send a
/// CSR. Pure read — modifies nothing. `now` is injectable for tests. A leaf that
/// cannot be parsed, or is missing its key, is reported as Missing. A leaf whose
/// public key does not match the key on disk (a renewal that replaced the key but
/// not the leaf) is also Missing, so startup re-enrolls instead of presenting the pair.
[[nodiscard]] YUZU_EXPORT CertState
inspect_provisioned_cert(const std::filesystem::path& cert_dir,
                         std::chrono::system_clock::time_point now =
                             std::chrono::system_clock::now());

} // namespace yuzu::agent
