#pragma once

/// @file key_provider.hpp
/// Storage abstraction for CA / leaf private keys.
///
/// The CA root key is the install's crown jewel. `KeyProvider` is the seam that
/// keeps key custody policy out of the crypto engine (`x509_ca`) and the
/// inventory store (`ca_store`): Milestone 1 ships `FileKeyProvider` (0600 PEM
/// under an owner-only directory), and a future `Pkcs11KeyProvider` /
/// `HsmKeyProvider` can implement the same interface with `key_ref` = a PKCS#11
/// URI, with zero change to callers. This is skill gap #10's "preferred keyring
/// abstraction".
///
/// `key_ref` is an opaque token the caller persists (in `ca_store.ca_root`) and
/// hands back to `load_key`. For `FileKeyProvider` it is the absolute path to
/// the PEM; callers MUST treat it as opaque so the HSM swap stays transparent.

#include "secure_buffer.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Result of wrapping a 32-byte DEK under a KEK — AES-256-GCM with an
/// independent random nonce (ADR-0010 §1 "Wrap algorithm"). The widths are
/// the blob-v1 pinned widths; `SecretCodec` copies these fields into the
/// stored blob verbatim.
struct WrappedDek {
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 32> wrapped{}; ///< GCM ciphertext of the DEK (tag separate)
    std::array<std::uint8_t, 16> tag{};
};

/// Failure classes for the KEK wrap/unwrap seam. `SecretCodec` maps these
/// onto its audit taxonomy (ADR-0010 §1 decrypt-failure semantics) — they
/// deliberately carry no message so secret material can never ride in one;
/// implementations log diagnostic detail themselves.
enum class KekError {
    unresolvable,   ///< key_ref does not resolve to usable key material
    tag_mismatch,   ///< GCM auth failed: wrong KEK, wrong wrap AAD, or tampered field
    crypto_failure, ///< CSPRNG or EVP failure
};

class KeyProvider {
public:
    virtual ~KeyProvider() = default;

    /// Persist `pem` under a logical `key_id`. Returns an opaque `key_ref` to
    /// store, or std::nullopt on failure. Implementations MUST persist the key
    /// material at rest with owner-only access.
    ///
    /// OPERATOR/SRE NOTE: the stored key (for FileKeyProvider, the 0600 PEM at
    /// `<base>/<key_id>.key`) is a trust anchor — losing the CA root key without
    /// a backup forces a full fleet re-enrollment. Back it up to offline /
    /// encrypted storage; verify a restore by comparing `CaRoot::fingerprint_sha256`
    /// (in ca_store) against `openssl x509 -fingerprint -sha256` on the restored cert.
    [[nodiscard]] virtual std::optional<std::string> store_key(std::string_view key_id,
                                                               std::string_view pem) = 0;

    /// Resolve a previously-stored key. Returns the PEM, or std::nullopt if the
    /// ref does not resolve / cannot be read. Callers should `secure_zero` the
    /// returned buffer once finished with it.
    [[nodiscard]] virtual std::optional<std::string> load_key(std::string_view key_ref) = 0;

    /// True iff `key_ref` currently resolves to a readable key.
    [[nodiscard]] virtual bool has_key(std::string_view key_ref) = 0;

    /// Best-effort removal (rotation / cleanup). Returns true if the key is
    /// gone afterwards (including the already-absent case).
    virtual bool delete_key(std::string_view key_ref) = 0;
};

/// KEK wrap/unwrap seam (ADR-0010 §2) — a SEPARATE interface from
/// `KeyProvider`, deliberately (interface segregation, governance arch-S2):
/// the two contracts are disjoint. `KeyProvider` is the raw-PEM CA/TLS key
/// custody contract; `KekProvider` is wrap/unwrap, NOT key export (#1333
/// HIGH-2) — `SecretCodec` holds opaque `key_ref`s and never sees raw KEK
/// bytes. A PKCS#11/KMS secrets provider implements ONLY this interface by
/// delegating to the token (a non-exportable KEK is fully supported, and the
/// realistic split deployment — KMS for secrets, file for the CA root —
/// needs the interfaces separable). `FileKeyProvider` implements both.
class KekProvider {
public:
    virtual ~KekProvider() = default;

    /// Mint a fresh 256-bit KEK under `key_id` (ADR naming:
    /// "secrets-kek-v<N>") and persist it durably. Returns the opaque
    /// `key_ref`, or std::nullopt on CSPRNG/storage failure — the caller
    /// treats that as fatal (startup_failed posture), never retries into a
    /// half-written key.
    [[nodiscard]] virtual std::optional<std::string> generate_kek(std::string_view key_id) = 0;

    /// Resolve an existing KEK by its logical `key_id` (the inverse of
    /// `generate_kek`, for boot verification: the substrate meta table
    /// records versions + check values only — never refs or key material —
    /// so the codec re-derives each version's ref through the provider; for
    /// a file provider this is a path, for PKCS#11 a CKA_LABEL lookup, for
    /// KMS an alias). std::nullopt when no such key exists.
    [[nodiscard]] virtual std::optional<std::string> resolve_kek(std::string_view key_id) = 0;

    /// Wrap a 32-byte DEK under the KEK at `key_ref`: AES-256-GCM, fresh
    /// random nonce per call, `wrap_aad` bound into the tag.
    [[nodiscard]] virtual std::expected<WrappedDek, KekError>
    wrap_dek(std::string_view key_ref, std::span<const std::uint8_t, 32> dek,
             std::span<const std::uint8_t> wrap_aad) = 0;

    /// Unwrap a DEK. Returns the 32-byte DEK in a zeroizing buffer, or
    /// `KekError::tag_mismatch` when GCM authentication fails (tampered
    /// wrapped_dek/tag/nonce, tampered blob `kek_version` — the wrap AAD
    /// binds it — or the wrong KEK).
    [[nodiscard]] virtual std::expected<SecureBuffer, KekError>
    unwrap_dek(std::string_view key_ref, const WrappedDek& wrapped,
               std::span<const std::uint8_t> wrap_aad) = 0;

    /// Deterministic, non-secret key-check value for fingerprint
    /// registration (ADR-0010 §2): for an exportable key, SHA-256 of the key
    /// material (safe — full-entropy 256-bit key, no dictionary angle); a
    /// non-exportable provider derives it on-token.
    ///
    /// `kcv_alg` names the derivation a given KEK version was minted under
    /// (the `kek_meta.kcv_alg` column, ADR-0010 Amendment 4). After a
    /// FileKeyProvider → HSM/KMS swap, SHA-256-derived and token-derived
    /// versions coexist; boot verification passes each version's recorded
    /// algorithm so the provider compares like-for-like. A provider returns
    /// std::nullopt when `key_ref` does not resolve OR when it cannot compute
    /// the named algorithm (e.g. a FileKeyProvider asked for a token KCV) —
    /// the caller turns that into a distinct, actionable boot error rather
    /// than silently mis-verifying valid material.
    [[nodiscard]] virtual std::optional<std::array<std::uint8_t, 32>>
    kek_check_value(std::string_view key_ref, std::string_view kcv_alg) = 0;

    /// Delete a retired KEK from provider storage. Best-effort; true if gone
    /// afterwards. The ONLY sanctioned caller is `SecretCodec::retire_kek`,
    /// which enforces the zero-references precondition (ADR-0010 §3) —
    /// nothing else may destroy KEK material.
    virtual bool delete_kek(std::string_view key_ref) = 0;
};

/// File-backed key store. Keys live as `<base_dir>/<key_id>.key` with mode 0600
/// inside a 0700 directory. `key_ref` is the absolute file path. Implements
/// BOTH custody contracts: raw-PEM CA/TLS keys (`KeyProvider`) and the
/// secrets KEK wrap/unwrap seam (`KekProvider`).
class FileKeyProvider : public KeyProvider, public KekProvider {
public:
    explicit FileKeyProvider(std::filesystem::path base_dir);

    [[nodiscard]] std::optional<std::string> store_key(std::string_view key_id,
                                                       std::string_view pem) override;
    [[nodiscard]] std::optional<std::string> load_key(std::string_view key_ref) override;
    [[nodiscard]] bool has_key(std::string_view key_ref) override;
    bool delete_key(std::string_view key_ref) override;

    // KEK seam (ADR-0010 §2). KEKs are raw 32-byte files (`<key_id>.key`,
    // 0600/0700 like the PEMs), written temp → fsync → rename so power loss
    // during first-boot generation can never leave a torn file that
    // "resolves" but fails every decrypt as pseudo-tamper. The raw KEK is
    // loaded once into a zeroizing buffer at first use and lives INSIDE the
    // provider (one resident copy beats N transient ones); callers only ever
    // hold `key_ref`s.
    [[nodiscard]] std::optional<std::string> generate_kek(std::string_view key_id) override;
    [[nodiscard]] std::optional<std::string> resolve_kek(std::string_view key_id) override;
    [[nodiscard]] std::expected<WrappedDek, KekError>
    wrap_dek(std::string_view key_ref, std::span<const std::uint8_t, 32> dek,
             std::span<const std::uint8_t> wrap_aad) override;
    [[nodiscard]] std::expected<SecureBuffer, KekError>
    unwrap_dek(std::string_view key_ref, const WrappedDek& wrapped,
               std::span<const std::uint8_t> wrap_aad) override;
    [[nodiscard]] std::optional<std::array<std::uint8_t, 32>>
    kek_check_value(std::string_view key_ref, std::string_view kcv_alg) override;
    bool delete_kek(std::string_view key_ref) override;

    /// Exposed for callers/tests that need the resolved on-disk location for a
    /// given id without storing anything.
    [[nodiscard]] std::filesystem::path path_for(std::string_view key_id) const;

private:
    std::filesystem::path base_dir_;

    /// Resident KEKs, keyed by canonical key_ref. Guarded by kek_mutex_
    /// (wrap/unwrap are called from store threads; load happens once).
    std::mutex kek_mutex_;
    std::map<std::string, SecureBuffer, std::less<>> kek_cache_;

    /// Load (or fetch the cached) 32-byte KEK for `key_ref`. Returns nullptr
    /// when the ref does not resolve, is outside base, or is not exactly 32
    /// bytes (a torn/corrupt file must read as unresolvable here; the
    /// fingerprint check in SecretCodec::init turns that into a distinct
    /// boot error). Caller must hold kek_mutex_.
    [[nodiscard]] const SecureBuffer* kek_for_locked(std::string_view key_ref);

    /// Atomic durable write: temp file (0600 from creation, O_EXCL) → fsync
    /// → rename. Shared by store_key and generate_kek.
    [[nodiscard]] bool write_file_atomic(std::string_view key_id, const std::filesystem::path& dest,
                                         std::span<const std::uint8_t> bytes);

    /// Reject a key_id that is not a bare, safe filename component (prevents
    /// path traversal via a crafted id). Returns false on any of: empty, path
    /// separators, "..", or characters outside [A-Za-z0-9._-].
    [[nodiscard]] static bool is_safe_key_id(std::string_view key_id);

    /// Confirm `p` canonicalises to a location inside base_dir_ (defence in
    /// depth for load/has/delete, which take an opaque ref from the DB).
    [[nodiscard]] bool within_base(const std::filesystem::path& p) const;
};

} // namespace yuzu::server
