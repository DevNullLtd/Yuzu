#pragma once

/// @file default_certs.hpp
/// First-boot, zero-config certificate bootstrap (PKI PR2).
///
/// A fresh Yuzu install has no operator-provided certs. Rather than refuse to
/// start (the old behaviour, papered over everywhere with --no-tls --no-https),
/// the server generates a per-install internal CA + the server-side leaves on
/// first boot so every transport is encrypted with no operator action — while
/// making it impossible to miss that defaults are in use (see the six
/// notification surfaces wired in server.cpp / main.cpp).
///
/// Built on the PR1 engine: x509_ca (key/cert/CRL), key_provider (0600 key
/// custody), ca_store (inventory). No bundled/shared private keys — every
/// install generates its own root.

#include "ca_store.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Resolved on-disk locations + identity of the generated default cert set.
struct DefaultCertSet {
    std::filesystem::path ca_cert;     ///< default-ca.pem  (public root; also the mTLS CA bundle)
    std::filesystem::path https_cert;  ///< default-https.pem
    std::filesystem::path https_key;   ///< default-https.key (0600)
    std::filesystem::path server_cert; ///< default-server.pem (agent + mgmt gRPC listener)
    std::filesystem::path server_key;  ///< default-server.key (0600)
    std::filesystem::path gateway_cert; ///< default-gateway.pem (consumed by PR5)
    std::filesystem::path gateway_key;  ///< default-gateway.key (0600)
    std::string ca_fingerprint_sha256;  ///< colon-hex; surfaced in banner/health/audit
    std::chrono::system_clock::time_point ca_expires_at{};
    bool freshly_generated{false}; ///< true only on the boot that created the set
    /// true only on the boot that re-issued `default-server.pem` in place to add
    /// the server identity URI SAN (#6016). The serials let the caller audit the
    /// supersession; both are empty otherwise.
    bool server_identity_upgraded{false};
    std::string superseded_server_serial; ///< serial_hex of the leaf that was revoked
    std::string new_server_serial;        ///< serial_hex of its same-key replacement
    /// false when the superseded serial's revoke did not take effect (a store error, or
    /// the row was unknown / already revoked by someone else — except an identical sibling
    /// upgrade's `superseded`) — the audit row then carries a warning.
    bool superseded_revoke_confirmed{false};
    /// true when the superseded serial was revoked by someone else (for a real reason, e.g. key
    /// compromise) while the upgrade ran, so the replacement over the same key was revoked too.
    bool replacement_withdrawn{false};
};

/// Best-effort local hostname for the leaf SANs; falls back to "localhost".
[[nodiscard]] std::string detect_hostname();

/// The per-install id used in every `yuzu://<install>/...` identity URI: the CA
/// fingerprint with its colons stripped (a valid URI authority), upper-case as
/// `pki::fingerprint_sha256` emits it. ONE definition, shared by the agent leaf
/// (`sign_agent_csr`) and the server leaf below, so the two URI families can
/// never drift apart (#6016).
[[nodiscard]] std::string install_id_from_fingerprint(std::string_view ca_fingerprint);

/// The server-only identity URI `yuzu://<install>/server` (#6016). Minted ONLY
/// onto the `default-server` leaf, by this translation unit; agents and the
/// gateway can never obtain it (`sign_agent_csr` ignores the CSR's SAN and only
/// ever emits `/agent/<id>`). The gateway's management plane WILL admit a peer by
/// exact equality with this value (#6016 PR 2); today it still pins the server's SPKI and
/// does not read this URI. Empty when `ca_fingerprint` yields no id.
[[nodiscard]] std::string server_identity_uri(std::string_view ca_fingerprint);

/// True iff `set.server_cert` parses and carries the server identity URI SAN for the
/// set's CA (`server_identity_uri(set.ca_fingerprint_sha256)`). False on any read /
/// parse failure, or when the fingerprint yields no URI. Drives the
/// `yuzu_server_identity_uri_present` gauge (#6016). It describes the FILE
/// `default-server.pem`, not what a given listener serves.
[[nodiscard]] bool default_server_leaf_has_identity(const DefaultCertSet& set);

/// Result of settling the superseded server serial after the re-issued leaf is published.
struct SupersessionOutcome {
    /// false unless the old serial is now revoked as superseded (by us, or by a sibling's
    /// identical upgrade) — see `DefaultCertSet::superseded_revoke_confirmed`.
    bool revoke_confirmed{true};
    /// true when the old serial turned out to be revoked for a real reason (e.g. key
    /// compromise) meanwhile, so the replacement over the same key was revoked to match.
    bool replacement_withdrawn{false};
};

/// Revoke `old_serial` as superseded, treating `Ok(false)` (unknown or already-revoked row) as
/// UNCONFIRMED rather than done: a concurrent operator revoke takes no bootstrap lock, so the
/// old row may have been withdrawn for compromise after the upgrade's guard reads. In that case
/// `new_serial` (same key) is revoked with the same reason. Exposed for tests (#6016): the race
/// cannot be provoked deterministically through `ensure_default_certs`.
[[nodiscard]] SupersessionOutcome settle_superseded_server_leaf(CaStore& ca_store,
                                                                const std::string& old_serial,
                                                                const std::string& new_serial);

/// Ensure a complete default cert set exists under `dir`.
///
/// On first boot generates a per-install ECDSA P-384 root CA (10-year) and
/// P-256 leaves for the HTTPS, agent/management-gRPC, and gateway listeners.
/// Each leaf's SAN carries DNS:localhost, IP:127.0.0.1, IP:::1, DNS:<hostname>;
/// the `default-server` leaf additionally carries the server-only identity URI
/// SAN (#6016, `server_identity_uri()`); an existing set whose server leaf lacks
/// it is upgraded in place — re-issued under the SAME root with the SAME key.
/// Each leaf is sized to the CA's notAfter so it can never outlive the issuer.
/// A `default-marker.json` records {version, generated_at, ca_fingerprint,
/// expires_at, hostname}.
///
/// Idempotent: if the marker + every cert/key file exist and the CA cert's
/// fingerprint matches the marker, returns the existing set unchanged
/// (freshly_generated = false) — except that a server leaf lacking the identity
/// URI SAN is re-issued in place first (server_identity_upgraded = true). If the marker is missing
/// or anything is corrupt/mismatched, regenerates the WHOLE set atomically (never a partial state).
/// When `ca_store` is non-null, records the root + each issued leaf in the inventory (best-effort;
/// a record failure is logged, not fatal).
///
/// Returns false only on an unrecoverable failure (e.g. keygen / signing /
/// filesystem error, or — when ca_store is non-null — a failed inventory write,
/// which is fatal so the inventory stays consistent for revocation/rotation) —
/// the caller should refuse to start rather than serve without the certs it
/// expected.
///
/// `extra_sans` (operator `--cert-san`) are injected into EVERY default leaf in
/// addition to the localhost/loopback/hostname base set. Each entry is
/// "dns:<name>", "ip:<addr>", or a bare value classified IP-vs-DNS by the exact
/// OpenSSL parser the SAN builder uses; a single entry may be comma-separated.
/// This lets an operator make the built-in certs valid for a deployment name
/// (e.g. "dns:gateway" so an agent reaching the gateway by that name passes
/// hostname verification) without standing up external PKI. Input is validated
/// and bounded — invalid IP literals, malformed/over-RFC-length DNS names,
/// control characters, and entries beyond a fixed cap are each dropped with a
/// warning, NEVER aborting the boot; an explicit "dns:"-prefixed IP literal is
/// honoured as a DNS-type SAN (warned) and wildcards are warned on. Extras apply
/// identically to all three leaves, exactly as the base SAN set already does.
///
/// NOTES: default-marker.json is crash-recovery idempotency, NOT tamper evidence
/// (an attacker who can write the 0700 cert dir is already past the boundary; the
/// fast path still chain-verifies the leaves as a corruption check). Beyond the
/// localhost / loopback IPs / detected hostname (+ any `extra_sans`), access by
/// another LAN IP or FQDN needs operator-provided certs or DNS. Leaves are sized
/// to the CA notAfter (10y) by design: there is no server-leaf auto-renewal, so a
/// short life would be a guaranteed future outage, and the operator is loudly
/// told to replace defaults. NOTE: adding/removing `extra_sans` does NOT
/// regenerate an existing set — the marker fast path returns the prior certs
/// unchanged. For new SANs, rename default-marker.json aside (moving it back
/// undoes this) and restart: the leaves are re-minted under the SAME root. Never
/// clear the whole directory: it holds the CA key and the secrets KEK (#5370).
///
/// `cert_group` (PKI #1289): when non-empty (a group name or numeric gid that the
/// server, gateway, and agent users all belong to), the shared cert volume is made
/// group-readable so sibling containers running as different uids can read the CA +
/// their leaf material — dir 0750 + group, default-gateway.key 0640 + group. Empty
/// (default) keeps the tight single-host posture (dir 0700, keys 0600). POSIX-only.
///
/// `out`'s contents are UNSPECIFIED when this function returns false — the sole
/// caller (bootstrap_default_certs()) never reads it again and refuses to start,
/// but do not add a new caller that reads `out` without first checking the
/// return value.
[[nodiscard]] bool ensure_default_certs(const std::filesystem::path& dir,
                                        const std::string& hostname, CaStore* ca_store,
                                        DefaultCertSet& out,
                                        const std::vector<std::string>& extra_sans = {},
                                        const std::string& cert_group = {});

} // namespace yuzu::server
