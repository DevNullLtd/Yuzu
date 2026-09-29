#pragma once

/// @file detached_signature.hpp
///
/// Verification of a detached PEM CMS signature over a local file, against an
/// operator-supplied PEM trust bundle.
///
/// WHY IT IS SHARED. This is the plugin loader's verifier, lifted so the OTA
/// update path can use the same one (#416/#3807). Two independent verifiers for
/// "is this binary the one my operator authorised" would be two places to get
/// the CMS flags wrong, and the flags here are load-bearing enough that two
/// separate governance findings are pinned in the comments below.
///
/// WHAT IT DOES NOT DO: it does not bind a signature to a filename or a version.
/// The signature covers file CONTENT only.
///
/// For the PLUGIN loader that is sufficient: its allowlist supplies the name
/// binding, and the allowlist is local operator configuration, not something the
/// party being defended against can author.
///
/// For the OTA path it is NOT, and the residual is deliberate and documented
/// rather than closed here. `CheckForUpdate` carries `latest_version` and
/// `sha256`, and BOTH are supplied by the same server the signature exists to
/// distrust. So a malicious or impersonated server can serve a GENUINELY signed
/// OLD agent binary — a real release, with a real signature over its real bytes
/// — while claiming `latest_version="99.0.0"` and a `sha256` recomputed over
/// those same bytes. Every check the agent applies passes: the hash matches, the
/// semver comparison sees an upgrade, and this function verifies a true
/// signature. The agent installs a known-vulnerable build and reports itself
/// current. That is the classic ROLLBACK attack, and neither the hash nor the
/// downgrade check defends against it, because the adversary authors both.
///
/// What this verifier DOES close is the substitution of ARBITRARY bytes: the
/// server can no longer serve a binary that was never signed by the operator's
/// own signing key. The attacker is confined to the set of binaries that key has
/// signed at some point — a materially smaller set than "anything", and the
/// reason this is worth shipping — but that set is not {the latest release}.
///
/// Closing the residual requires binding the VERSION into the signed material —
/// signing a manifest of (version, digest) rather than the raw binary, the way
/// TUF does — which changes the release-signing format and is tracked separately.
/// Do NOT describe this path as closing the malicious-server threat until that
/// lands.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::agent {

/// The closed set of refusal reasons, so producers and consumers cannot drift.
///
/// `updater.cpp` labels a refusal with one of these; `agent.cpp` sums them onto
/// the heartbeat. Those were two hardcoded lists, so a fourth reason would have
/// been counted by neither the tag nor the fleet gauge derived from it — a new
/// failure mode that is invisible by construction.
inline constexpr std::string_view kSignatureRefusalReasons[] = {"missing", "untrusted", "invalid"};

/// Upper bound on a detached signature read from a FILE by this binary.
///
/// A PEM CMS detached signature is a few KB — a signer chain plus one digest.
/// The bound exists because a whole-file read has none of its own: the plugin
/// loader reads a sibling `.sig` off disk and should not be able to exhaust
/// memory on a malformed or hostile file.
///
/// Its only consumer is `plugin_loader.cpp`. The OTA path does NOT read this
/// constant: it receives the signature over the wire, already bounded by the
/// SERVER's own `yuzu::server::kMaxSignatureBytes` (which refuses to serve an
/// over-cap sidecar) and by gRPC's message limit. Those two constants live in
/// different binaries with no shared header, so their equal value is incidental
/// — do not treat either as enforcing the other, and do not "unify" them by
/// citing this one in server code.
inline constexpr std::size_t kMaxSignatureBytes = 64 * 1024;

/// Why a signature did not verify. Callers map this onto their own
/// subject-specific reason strings, which is why this enum carries no prose.
enum class CmsFailure {
    /// The signature is malformed, or the digest does not cover this file.
    kInvalid,
    /// The signer's certificate does not chain to the trust bundle, or does not
    /// carry the codeSigning EKU, or the bundle itself could not be read (an
    /// unreadable bundle proves nothing, so it is a trust failure, not a pass).
    kUntrusted,
};

struct CmsVerifyError {
    CmsFailure kind;
    std::string detail; ///< drained OpenSSL error text, for the log line
};

/// Verify `signature_pem` as a detached CMS signature over the bytes of
/// `artifact_path`, with signer certificates chained against `trust_bundle_path`.
///
/// Returns `std::nullopt` when the signature verifies. The signature is taken as
/// a buffer rather than a path because the OTA path receives it over the wire,
/// while the plugin path reads it from a sibling file.
///
/// The trust store is built with `X509_PURPOSE_CODE_SIGN`, so a leaf WITHOUT the
/// codeSigning EKU is rejected even when it chains to a CA in the bundle. That
/// matters because internal PKIs very commonly issue mTLS and S/MIME certs from
/// the same root: without the purpose, trusting that root for signing would make
/// every cert it ever issued a signing authority. (plugin governance sec-LOW-2 /
/// UP-8, preserved in the lift.)
[[nodiscard]] YUZU_EXPORT std::optional<CmsVerifyError>
verify_detached_cms(const std::filesystem::path& artifact_path, std::string_view signature_pem,
                    const std::filesystem::path& trust_bundle_path);

/// Same verification, reading the artifact from an ALREADY-OPEN descriptor.
///
/// Two reasons this exists rather than everything going through the path form:
///
///  1. It removes the re-open entirely, so the bytes verified are provably the
///     bytes the caller already hashed — there is no window in which the path
///     could be repointed at a different inode between the hash and the
///     signature check.
///  2. On Windows it is not optional. The updater stages its download with
///     `dwShareMode=0`, so nothing — including this process — can open that path
///     a second time while the handle is held. A path-based verifier would fail
///     with a sharing violation on every Windows update.
///
/// The descriptor's file offset is saved and restored, and the descriptor is NOT
/// closed; the caller keeps ownership. On Windows, pass a CRT descriptor obtained
/// from a DUPLICATED handle, so closing it cannot disturb the caller's own.
[[nodiscard]] YUZU_EXPORT std::optional<CmsVerifyError>
verify_detached_cms_fd(int artifact_fd, std::string_view signature_pem,
                       const std::filesystem::path& trust_bundle_path);

} // namespace yuzu::agent
