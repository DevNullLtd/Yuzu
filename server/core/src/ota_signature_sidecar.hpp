#pragma once

/// @file ota_signature_sidecar.hpp
///
/// The detached-signature sidecar's lifecycle, as PURE decisions (#416/#3807).
///
/// WHY IT IS SEPARATE. The two call sites that move a signature from an operator's
/// upload to an agent's `CheckForUpdate` response both live behind Postgres —
/// `settings_routes.cpp`'s upload handler needs a multipart request the test route
/// sink cannot build, and `agent_service_impl.cpp`'s reader needs an
/// `UpdateRegistry`, which needs a `PgPool`. So the ~200 production lines carrying
/// the signature end to end had NO discriminating test, which two independent
/// external reviewers found in the same round. The decisions live here instead,
/// where they are testable with a temp directory and nothing else; the call sites
/// keep only the I/O they cannot avoid.

#include <cstddef>
#include <filesystem>
#include <string>

namespace yuzu::server {

/// Upper bound on a package's detached signature.
///
/// A PEM CMS detached signature is a few KB — a signer certificate chain plus one
/// digest. The cap is not about disk: this blob is attached to EVERY
/// CheckForUpdateResponse, and gRPC clients default to a 4 MB receive limit, so a
/// wrong file uploaded into the signature field would push that response past the
/// limit and break update checks for the whole fleet at once.
inline constexpr std::size_t kMaxSignatureBytes = 64 * 1024;

/// Why a sidecar was not served. Anything but `kServed` means the package is
/// offered to agents as UNSIGNED — never as an error, because whether an unsigned
/// package is acceptable is the AGENT's decision, not this server's.
enum class SidecarOutcome {
    kServed,
    kAbsent,     ///< the ordinary unsigned case
    kOverCap,    ///< larger than kMaxSignatureBytes, or a size we cannot determine
    kUnreadable, ///< present but could not be opened
};

/// The sidecar path for a package binary. Derived from the binary path, never from
/// a separately-supplied name: the filename is operator-controlled, and letting the
/// signature location be named independently would let one package point at
/// another's signature.
[[nodiscard]] std::filesystem::path signature_sidecar_path(const std::filesystem::path& binary);

/// Read the sidecar if it may be served, into `out`.
///
/// SIZE IS CHECKED BEFORE ANYTHING IS OPENED. Constructing the stream first would
/// defeat the check: `open(2)` on a FIFO blocks until a writer appears, so a FIFO
/// named `<package>.sig` would wedge the CheckForUpdate handler thread — one wedged
/// thread per agent check — before the cap was ever consulted. A size we cannot
/// determine is therefore treated as over-cap rather than probed.
[[nodiscard]] SidecarOutcome read_signature_sidecar(const std::filesystem::path& sidecar,
                                                    std::string& out);

/// The same decision, for callers that only need the verdict and not the bytes.
///
/// It DOES still read the file — it delegates to `read_signature_sidecar` and
/// discards the buffer, deliberately, so that "would this be served?" has one
/// implementation rather than two that can drift. What it saves the caller is
/// the buffer, not the read: the Settings table renders one row per package and
/// would otherwise have to hold up to 64 KB per package alive per render.
/// (An earlier version of this comment claimed it avoided the read; it does not.)
[[nodiscard]] SidecarOutcome signature_sidecar_outcome(const std::filesystem::path& sidecar);

/// Flush one already-written, already-closed FILE to stable storage.
///
/// Exposed so the OTA binary upload can stage-and-publish with the same
/// durability discipline as the sidecar, rather than growing a second copy of
/// the platform dance. Returns false if the file cannot be opened or the flush
/// fails; callers treat that as a failed write, because a file that is "written"
/// but not durable is indistinguishable from one that was never written.
[[nodiscard]] bool fsync_file(const std::filesystem::path& path);

/// Can this sidecar possibly cover this binary? (OPERATOR-FACING ONLY.)
///
/// A successful SIGNED upload writes the sidecar first and the binary second, so
/// the binary's mtime is always at or after the sidecar's. (An unsigned upload
/// runs the other way round — the binary first, then the removal — because the
/// step that weakens the signature always goes last; it leaves no sidecar, so
/// this function short-circuits on the unreadable-mtime path below.) A sidecar STRICTLY NEWER
/// than its binary therefore proves the binary write did not follow it — the
/// upload died in between, or the binary write failed — and the stored signature
/// cannot cover the bytes actually on disk.
///
/// DELIBERATELY NOT CONSULTED BY THE WIRE PATH, and this is the one place the
/// server and the settings column are allowed to disagree. They answer different
/// questions. `CheckForUpdate` must keep SERVING the mismatched signature so
/// agents verify it, fail, and refuse — fail-closed. Withholding it would make
/// the package read as unsigned, and a permissive agent would then apply the
/// binary UNVERIFIED, which is the single unsafe state this whole design avoids.
/// The column's job is the opposite: tell the operator the truth, so "signed"
/// never appears beside a package no agent can install.
///
/// Returns true when the pair is consistent, and when either mtime cannot be
/// read (an unreadable file is not evidence of a mismatch). Equal timestamps
/// count as consistent, so a filesystem with coarse mtime granularity degrades
/// to today's behaviour rather than to false alarms.
///
/// IT IS A HEURISTIC, NOT A PROOF, IN BOTH DIRECTIONS. A restore or copy that
/// does not preserve timestamps (`cp -r` without `-p` writes `agent.bin` before
/// `agent.bin.sig`) yields a strictly-newer sidecar for a perfectly valid pair,
/// so the operator-facing string says the pair cannot be CONFIRMED rather than
/// asserting a failed upload. Nothing is gated on it — only the label.
[[nodiscard]] bool signature_sidecar_covers_binary(const std::filesystem::path& binary,
                                                   const std::filesystem::path& sidecar);

/// Does `signature_pem` have the shape of a PEM-armoured CMS signature?
///
/// A pure, cheap SHAPE check — NOT a verification. It cannot tell a valid
/// signature from a well-formed one over the wrong bytes; only the agent's
/// `verify_detached_cms` decides that, and it needs a trust bundle the server
/// does not have.
///
/// It exists because the one sidecar state every surface agrees is servable is
/// also the one nobody validates: a well-sized file of garbage is stored, the
/// settings column reports "signed", the server serves it, and every anchored
/// agent then refuses the package in BOTH enforcement modes — including
/// permissive, where the documented contract is that unsigned packages are
/// accepted with a warning. The operator's only signal is a fleet gauge rising
/// after the fact. Catching the obvious case at upload turns that into an
/// immediate, attributable rejection.
[[nodiscard]] bool looks_like_pem_cms(const std::string& signature_pem);

/// Replace the sidecar beside a freshly-uploaded binary.
///
/// REMOVAL IS UNCONDITIONAL FOR AN EMPTY SIGNATURE, and is the reason this is one
/// function rather than two. The binary is overwritten in place, so an operator
/// re-uploading a rebuilt package under the same filename WITHOUT a signature
/// would otherwise leave the previous `.sig` on disk — a signature over bytes
/// that no longer exist. Every anchored agent would then refuse the package, in
/// both enforcement modes, and rotating a signing key is exactly the sequence
/// that walks into it.
///
/// "Unconditional" scopes to THAT case alone — the operator explicitly chose to
/// upload unsigned. It is emphatically NOT a failure recovery; see the next
/// paragraph, and `discard_staging` in the .cpp for why the distinction is the
/// difference between failing closed and shipping an unverified binary.
///
/// Returns false only when a NON-EMPTY signature could not be written. In that
/// case any PREVIOUS sidecar is deliberately LEFT IN PLACE: a stale signature
/// makes agents refuse (fail closed), whereas removing it would leave the new
/// binary unsigned and permissive agents would apply it UNVERIFIED. The caller
/// must surface the failure — the package is now in a state the operator has to
/// resolve, not one to report as success.
[[nodiscard]] bool replace_signature_sidecar(const std::filesystem::path& sidecar,
                                             const std::string& signature_pem);

/// What a package delete actually did to the two files on disk.
///
/// `*_failed` carries the filesystem error; `*_removed` says a file was really
/// unlinked. Both false with no error means the file was not there to begin with,
/// which is a THIRD outcome and not a synonym for either of the others.
struct PackageDeleteOutcome {
    bool matched = false;            ///< a registry row matched the requested package
    bool binary_removed = false;
    bool signature_removed = false;
    std::string binary_error;        ///< empty unless the binary unlink failed
    std::string signature_error;     ///< empty unless the sidecar unlink failed
};

/// The audit `result` token and `detail` string for a package delete.
///
/// PURE so it can be tested, because the branch that matters cannot be reached
/// from a unit test of the route: it needs a filesystem `remove` to FAIL, which
/// means a read-only parent on POSIX and an open handle on Windows — a test that
/// would be platform-guarded on both legs, and a platform-guarded test is how a
/// dead leg hides. The route keeps only the two `remove` calls.
///
/// A FAILED unlink is never reported as a successful removal. The registry row is
/// gone either way, so this is not an OTA-serving bypass — but audit-log.md
/// documents this verb as meaning both files were removed, and an audit chain that
/// asserts a removal which did not happen is worth less than one that admits it.
/// `partial` is the token this codebase already uses for "the durable part landed,
/// a dependent step did not" (cf. `session.revoke_all`).
struct PackageDeleteAudit {
    std::string result;
    std::string detail;
};
[[nodiscard]] PackageDeleteAudit describe_package_delete(const PackageDeleteOutcome& outcome);

} // namespace yuzu::server
