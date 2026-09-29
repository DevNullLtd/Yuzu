#pragma once

/// @file x509_ca.hpp
/// Pure-OpenSSL PKI engine for Yuzu's internal Certificate Authority.
///
/// This module is the single crypto primitive layer shared by the default-cert
/// bootstrap (`default_certs.*`), the issuance subsystem (`ca_store.*`), and the
/// per-agent enrollment signer (`agent_service_impl.cpp`). It has NO dependency
/// on SQLite, the server config, or any Yuzu store — it deals only in PEM/DER
/// strings and value types so it can be unit-tested in isolation and, later,
/// extracted into a lib shared with the agent (PR3) without dragging server
/// state along.
///
/// Algorithm policy (locked): ECDSA P-256 leaves, P-384 root. ECDSA is the
/// roadmap-aligned choice for the planned gRPC→QUIC move (#376): QUIC mandates
/// TLS 1.3, which treats ecdsa_secp256r1_sha256 / ecdsa_secp384r1_sha384 as
/// first-class, and the smaller certs cost fewer bytes under QUIC's
/// anti-amplification limit. The signature digest is chosen from the *issuer*
/// key strength (P-384 CA → SHA-384, P-256 → SHA-256).
///
/// Every function returns std::nullopt on failure and logs the OpenSSL error
/// stack via spdlog. The implementation is compiled only when OpenSSL is
/// available (`CPPHTTPLIB_OPENSSL_SUPPORT`, the project-wide signal that
/// libssl/libcrypto are linked — see `cert_reloader.cpp`); without it every
/// entry point returns std::nullopt so the build stays green on a
/// TLS-less configuration (which cannot serve HTTPS anyway).

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pki {

/// Elliptic-curve key strength. No RSA in Milestone 1 (documented add-on).
enum class KeyAlgo {
    EcP256, ///< prime256v1 / secp256r1 — leaves.
    EcP384, ///< secp384r1 — the install root / issuing CA.
};

/// Minimal distinguished name. Yuzu only ever sets CN (+ a fixed O); a richer
/// DN is unnecessary for an internal PKI and only widens the parse surface.
struct DistinguishedName {
    std::string common_name;
    std::string organization; ///< Defaults to "Yuzu" when empty at call sites.
};

/// Subject Alternative Names. IPs are textual ("127.0.0.1", "::1"); URIs carry
/// the agent identity ("yuzu://<install-id>/agent/<agent_id>").
struct SubjectAltNames {
    std::vector<std::string> dns;
    std::vector<std::string> ips;
    std::vector<std::string> uris;

    [[nodiscard]] bool empty() const {
        return dns.empty() && ips.empty() && uris.empty();
    }
};

/// Validity window. Callers build explicit time points; helpers below cover the
/// common "N years/days from now" cases so the call sites read cleanly.
struct Validity {
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
};

/// Clock-skew backdating allowance. Every cert minted through the validity
/// helpers (and the agent leaf in `sign_agent_csr`) has its `notBefore` set this
/// far in the past. Rationale (PR3 H-2 / inherited PR1 UP-9 / PR2 UP-15): a
/// freshly-issued leaf presented by an endpoint whose clock lags the issuer by a
/// few minutes is otherwise "not yet valid" — the TLS handshake rejects it and
/// the agent's reconnect path does NOT recover from "valid cert, skewed clock",
/// so the agent would be wedged until its clock caught up. 5 min is the de-facto
/// PKI default (matches the X.509 nsCertType skew convention) and is negligible
/// against the 1y leaf / 10y CA lifetimes.
inline constexpr std::chrono::seconds kClockSkewBackdate{300};

// Validity-window helpers. NOTE (SRE): leaf/CA expiry must be alerted on before
// it bites the fleet. PR2 publishes the default set's notAfter as
// `yuzu_server_cert_expiry_timestamp_seconds{cert="default-ca"}` at bootstrap,
// and the yuzu-tls alert rules (warn @7d / crit @1d, docs/prometheus/yuzu-alerts.yml)
// fire on it. Assumes a 64-bit time_t (true for every current build target).
// Both helpers backdate `not_before` by kClockSkewBackdate (see above).
[[nodiscard]] Validity validity_years_from_now(int years);
[[nodiscard]] Validity validity_days_from_now(int days);

/// Extended-key-usage selection for a leaf. A leaf may be both server- and
/// client-auth (the default server leaves are server-auth only; agent leaves
/// are client-auth only).
struct LeafUsage {
    bool server_auth{false};
    bool client_auth{false};
    bool code_signing{false};
};

// ── Key generation ───────────────────────────────────────────────────────────

/// Generate an EC private key. Returns PKCS#8 PEM (unencrypted — storage-layer
/// encryption / file mode is the `key_provider`'s job, not ours).
[[nodiscard]] std::optional<std::string> generate_private_key(KeyAlgo algo);

// ── CA root ──────────────────────────────────────────────────────────────────

struct CaParams {
    DistinguishedName subject;
    Validity validity;
    /// basicConstraints pathlen. 0 = this CA may issue end-entity certs only
    /// (no sub-CAs beneath it) — correct for the single-tier install CA.
    int path_len{0};
};

/// Self-sign a CA root certificate over `ca_key_pem`. Sets
/// basicConstraints=critical,CA:TRUE,pathlen:N; keyUsage=critical,keyCertSign,
/// cRLSign; subjectKeyIdentifier; authorityKeyIdentifier=keyid,issuer.
[[nodiscard]] std::optional<std::string> self_sign_ca(std::string_view ca_key_pem,
                                                      const CaParams& params);

// ── CSR ──────────────────────────────────────────────────────────────────────

struct CsrParams {
    DistinguishedName subject;
    SubjectAltNames san;
};

/// Build a PKCS#10 CSR over `key_pem`, self-signed for proof-of-possession.
/// Used (a) agent-side for the per-agent client cert and (b) server-side to
/// export the install CA's CSR for an enterprise root to sign (subordinate-CA,
/// PR6).
[[nodiscard]] std::optional<std::string> make_csr(std::string_view key_pem,
                                                  const CsrParams& params);

// ── Leaf issuance ────────────────────────────────────────────────────────────

struct LeafParams {
    DistinguishedName subject; ///< Server-chosen subject (CN). See sign_csr note.
    SubjectAltNames san;       ///< Server-chosen SAN. See sign_csr note.
    Validity validity;
    LeafUsage usage;
    /// Caller-assigned serial as uppercase colon-free hex (e.g. from
    /// `ca_store`). Empty → the engine generates a random 128-bit serial and
    /// returns it in `IssuedCert::serial_hex`.
    std::string serial_hex;
};

struct IssuedCert {
    std::string cert_pem;
    std::string serial_hex; ///< The serial actually embedded (uppercase hex).
};

/// Sign an end-entity certificate from a CSR.
///
/// SECURITY: the CSR is used ONLY for its public key, and ONLY after its
/// self-signature is verified (proof the requester holds the matching private
/// key). The issued cert's subject, SAN, EKU, and validity come entirely from
/// `params` — the CSR's own subject/SAN are deliberately IGNORED. This is what
/// stops an enrolling agent from requesting another agent's identity: the
/// server sets CN=<agent_id> and the URI SAN itself from the authenticated
/// enrollment, never from attacker-controlled CSR fields.
[[nodiscard]] std::optional<IssuedCert> sign_csr(std::string_view csr_pem,
                                                 std::string_view ca_cert_pem,
                                                 std::string_view ca_key_pem,
                                                 const LeafParams& params);

struct KeyAndCert {
    std::string private_key_pem;
    std::string cert_pem;
    std::string serial_hex;
};

/// Generate a fresh leaf key and sign a leaf for it in one step. For the
/// server-side default leaves (HTTPS / agent-listener / gateway) where the
/// server legitimately holds the private key. Never used for agent client
/// certs — the agent generates its own key and only sends a CSR (so the server
/// never sees an agent private key).
[[nodiscard]] std::optional<KeyAndCert> issue_leaf(std::string_view ca_cert_pem,
                                                   std::string_view ca_key_pem, KeyAlgo leaf_algo,
                                                   const LeafParams& params);

// ── CRL ──────────────────────────────────────────────────────────────────────

struct CrlRevocation {
    std::string serial_hex; ///< Uppercase hex, matching IssuedCert::serial_hex.
    std::chrono::system_clock::time_point revoked_at;
};

/// Build a DER-encoded X.509 CRL signed by the CA. `crl_number` is the
/// monotonic CRL sequence (from `ca_store.ca_crl_versions`). Returns the DER
/// bytes for `GET /api/v1/ca/crl` and on-disk publication.
[[nodiscard]] std::optional<std::vector<uint8_t>> build_crl(
    std::string_view ca_cert_pem, std::string_view ca_key_pem,
    const std::vector<CrlRevocation>& revoked, const Validity& crl_validity, uint64_t crl_number);

// ── Inspection / verification ────────────────────────────────────────────────

/// SHA-256 fingerprint of the DER form of a PEM certificate, formatted as
/// uppercase colon-separated hex ("AB:CD:…"). This is the canonical
/// "which CA / cert is this" identifier surfaced in banners, /health, and audit.
[[nodiscard]] std::optional<std::string> fingerprint_sha256(std::string_view cert_pem);

/// SHA-256 of the certificate's subjectPublicKey (X509_pubkey_digest) — a STABLE,
/// key-based CA identity, formatted as uppercase colon-separated hex. Unlike
/// fingerprint_sha256 (a hash of the whole cert), this depends ONLY on the public
/// key, so it is **invariant across a subordinate-CA re-key** (PR6): importing an
/// enterprise-signed intermediate swaps the issuer CERT but keeps the issuing KEY,
/// so the key id is unchanged while the cert fingerprint changes. This is the
/// identity an "issued by THIS CA" inventory query must key on so it never orphans
/// leaves minted before the re-key (#1296). Conceptually the SubjectKeyIdentifier,
/// computed deterministically here rather than read from the (optional) X509v3
/// extension so it is robust to externally-signed intermediates.
[[nodiscard]] std::optional<std::string> issuer_key_id(std::string_view cert_pem);

/// True iff `s` is a syntactically valid IPv4 or IPv6 literal, judged by the
/// exact parser the SAN builder uses for an iPAddress entry (OpenSSL
/// `a2i_IPADDRESS`). Callers classifying a SAN as IP-vs-DNS should gate on this
/// so a value they accept as an IP cannot later be rejected by `issue_leaf`
/// (an accept-then-reject mismatch would hard-fail certificate generation).
[[nodiscard]] bool is_valid_ip_literal(const std::string& s);

/// gov B1: minimum subject-key strength for a code-signing leaf — the leaf
/// becomes a trusted plugin-signing anchor, so an operator-submitted CSR
/// carrying a factorable/weak key must be refused rather than signed. Parses
/// `csr_pem` and inspects ONLY its embedded public key (the same key
/// `sign_csr` later binds proof-of-possession against — this makes no claim
/// about the CSR signature itself). Rule: RSA must be 2048–16384 bits (mirrors
/// the SAML SP signing-key floor, `saml_provider.cpp`); an EC key must be on
/// an approved NIST curve (P-256/P-384/P-521); Ed25519/Ed448 are allowed (no
/// "bits" floor applies, and OpenSSL 3's CMS_verify accepts them). Any other
/// key type, or a CSR that fails to parse, returns false — FAIL CLOSED, so an
/// unrecognised key type is never silently waved through as "no floor
/// applies". Pure inspection — does not touch the CA key or record anything.
[[nodiscard]] bool subject_key_meets_code_signing_floor(std::string_view csr_pem);

struct CertDetails {
    DistinguishedName subject;
    DistinguishedName issuer;
    std::string serial_hex;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    SubjectAltNames san;
    bool is_ca{false};
};

[[nodiscard]] std::optional<CertDetails> parse_certificate(std::string_view cert_pem);

/// True iff `leaf_pem` verifies up to `ca_pem` as a trust anchor (signature +
/// validity period + basic-constraints path). Used by tests and by the
/// subordinate-CA import path (PR6) to confirm an uploaded chain actually signs
/// our CA public key.
///
/// NOTE: this does NOT consult the CRL / revocation status — a revoked cert
/// still returns true. Revocation is enforced separately (`CaStore::is_revoked`
/// at the mTLS-accept gate, PR3). Never use verify_chain alone as an admission
/// decision.
[[nodiscard]] bool verify_chain(std::string_view leaf_pem, std::string_view ca_pem);

// ── Subordinate-CA support (PR6) ─────────────────────────────────────────────

/// True iff the public key embedded in `cert_pem` matches the private key in
/// `key_pem` (a private EVP_PKEY carries its public component, so an equality
/// check against the cert's public key proves the pair).
///
/// This is THE load-bearing check of the subordinate-CA import: when an operator
/// uploads an enterprise-signed intermediate, we must confirm it carries OUR CA
/// public key — i.e. the enterprise signed the exact CSR we exported, not some
/// unrelated CA. Without it, importing a foreign chain would switch our issuing
/// cert to one whose private key we do NOT hold, silently breaking ALL future
/// issuance (every subsequent sign_csr would fail) and could point the install
/// at an attacker-chosen trust hierarchy. Returns false on any parse failure
/// (fail closed).
[[nodiscard]] bool cert_matches_key(std::string_view cert_pem, std::string_view key_pem);

/// True iff `cert_pem` is a CA certificate — basicConstraints present with
/// CA:TRUE. The subordinate-CA import requires the uploaded intermediate to be a
/// CA (it must be able to sign leaves); a non-CA cert would pass the chain check
/// yet be unable to issue. Returns false on parse failure.
[[nodiscard]] bool cert_is_ca(std::string_view cert_pem);

/// True iff `cert_pem` verifies to a trust anchor found within `bundle_pem` — a
/// PEM concatenation of one or more parent certs (the enterprise root and any
/// intermediates above ours). Generalises `verify_chain` (single anchor) to the
/// multi-tier parent chain an operator uploads at subordinate-CA import. Every
/// cert in the bundle is added to the trust store, so a chain of any depth that
/// roots `cert_pem` validates. Returns false on an empty/garbage bundle or any
/// verification failure (fail closed). Like verify_chain it does NOT consult
/// revocation — it answers only "does the uploaded parent material actually sign
/// our intermediate".
[[nodiscard]] bool verify_chain_to_bundle(std::string_view cert_pem, std::string_view bundle_pem);

} // namespace yuzu::server::pki
