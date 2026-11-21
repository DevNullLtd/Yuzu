#pragma once

/**
 * echo_module_etw.hpp — gap-free module/image-load capture via ETW (M2).
 *
 * The Windows peer of the $Module capture source, structurally mirroring
 * echo_proc_etw.hpp. Subscribes a real-time ETW session to the
 * Microsoft-Windows-Kernel-Process provider with the IMAGE keyword (0x40) and
 * decodes image load (event 5) into the shared ModuleEventRing the Echo
 * plugin drains and persists; event 6 (unload) is not consumed, unloads are
 * not stored. Answers "what did a
 * process LOAD" — the DLL-search-order-hijack / injection / BYOVD surface
 * $Process cannot see.
 *
 * DELIBERATE DIVERGENCE from docs/echo-module-loads.md §2 ("extend the same
 * session the process source runs"): this collector opens its OWN session on the
 * same provider with the IMAGE keyword. That preserves the one-collector-one-
 * session ownership invariant the ImageStreamCollector interface documents (a
 * concrete collector owns a live session; sharing would force one Impl to demux
 * two keywords into a foreign ring). Two real-time sessions on one provider with
 * distinct keyword masks is sound ETW — the kernel fans the provider out to each
 * enabled session independently.
 *
 * windows.h-free by design: all ETW/TDH/WinTrust usage lives in the .cpp
 * (mirrors echo_proc_etw.hpp). Off-Windows the collector is a no-op: start()
 * returns false, the ring stays empty, drain() yields nothing.
 *
 * Split for testability (mirrors echo_proc_es.hpp's es_sample_to_proc_event): the
 * pure ETW-sample → ModuleEvent mapping and the signing-verdict cache are
 * compiled and unit-tested on EVERY platform; only the live session +
 * WinVerifyTrust verifier are Windows-gated.
 */

#include "echo_module_stream.hpp" // ModuleEvent, ModuleEventRing, ImageStreamCollector

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::echo {

/// Platform-agnostic projection of the fields the Windows on_event callback
/// extracts from an ETW image-load event via TDH. Splitting it from
/// EVENT_RECORD keeps the ModuleEvent mapping unit-testable without ETW headers.
struct EtwImageSample {
    std::int64_t ts_unix{0};
    bool is_load{true};     ///< always true from the ETW callback; false only in the pure mapping
    std::uint32_t pid{0};   ///< loading process id (System/Idle ⇒ kernel/driver load)
    std::string image_path; ///< full image path (NT \Device\... or drive form)
};

/// Pure mapping: ETW sample → ModuleEvent. Splits image_path into module_name
/// (basename) + module_dir (directory — NOT yet redacted; the collector redacts
/// at drain, AFTER signing, since signing needs the real path). is_kernel =
/// pid <= 4 (System/Idle own kernel/driver image loads). action = loaded, or
/// unloaded when is_load is false (only this pure mapping produces that; the ETW
/// callback never does, and apply_module_risk_filter drops it). A 'blocked'
/// verdict comes only from the M3 CodeIntegrity overlay, never this provider.
/// signed_state/signer/process_name stay default — resolved by the collector at
/// drain. Defined in the .cpp, exercised on every platform by the unit tests.
ModuleEvent etw_image_sample_to_module_event(const EtwImageSample& s);

/// A code-signing verdict for one image, returned by a ModuleVerifier.
struct ModuleSignVerdict {
    ModuleSignedState state{ModuleSignedState::kUnknown};
    std::string signer; ///< publisher CN / team id; "" if unresolved
};

/// What the system-catalog lookup found for an image WinVerifyTrust reported as having no
/// embedded signature (TRUST_E_NOSIGNATURE). Most Windows system binaries carry no embedded
/// signature: their hashes are listed in signed catalog files instead.
enum class CatalogLookup : std::uint8_t {
    kNotFound,   ///< no installed catalog lists the file hash: genuinely unsigned
    kFoundValid, ///< a catalog lists the hash and WinVerifyTrust accepts the catalog member
    kError,      ///< any API failure, or a catalog that lists the hash but did not verify
};

/// Pure mapping from a catalog lookup to a verdict: NotFound is kUnsigned, FoundValid is
/// kSigned carrying the catalog's signer, everything else is kUnknown. A failed lookup is
/// never kUnsigned, so it cannot make an ordinary system DLL read as risky.
[[nodiscard]] ModuleSignVerdict catalog_lookup_verdict(CatalogLookup lookup,
                                                       std::string catalog_signer = {});

/// Verifier callback: full image path → verdict. The real Windows verifier
/// (WinVerifyTrust on an open handle, signer from its provider chain, in the .cpp)
/// is wired at drain; tests inject a fake. A null verifier yields {kUnknown, ""}
/// (never fabricates signed).
using ModuleVerifier = std::function<ModuleSignVerdict(const std::string& full_path)>;

/// Identity + change-counter of ONE open image file (WP13 / F47). Cache-key material that the
/// file's writer cannot reset: the NTFS/ReFS file id and the file's USN (the change-journal
/// sequence number, which advances on every data or basic-info change and cannot be set from
/// user mode). Last-write time and size are carried only as extra equality terms: both are
/// attacker-settable and must NEVER be the sole binding (the old key was exactly mtime).
/// `available == false` means the stamp could not be read or proves nothing (USN unreadable, or
/// 0 = the file has no journal record); such an image is re-verified on every load and its
/// verdict is not cached. Plain data, so SigningCache stays portable and unit-testable.
struct FileVersionStamp {
    bool available{false};
    std::uint64_t volume_serial{0};
    std::uint64_t file_id_hi{0};
    std::uint64_t file_id_lo{0};
    std::uint64_t size{0};
    std::int64_t mtime{0}; ///< extra term only (settable)
    std::int64_t usn{0};
    bool operator==(const FileVersionStamp&) const = default;
};

/// Bounded cache of signing verdicts keyed by (path, FileVersionStamp), so the costly
/// WinVerifyTrust runs ~once per (file, version) instead of per load. A verdict is served only
/// when the stamp is `available` and EVERY field matches; otherwise the image is re-verified
/// (and an unavailable stamp is never stored - no mtime fallback). Pure + cross-platform (the
/// verifier is injected) → unit-tested on Linux/macOS with a fake. Touched only on the drain
/// thread, so no internal lock.
class SigningCache {
public:
    explicit SigningCache(std::size_t cap = 8192) : cap_(cap == 0 ? 1 : cap) {}

    /// Verdict for (full_path, stamp). Cache hit only when `stamp.available` AND the stored
    /// stamp is identical (a changed file re-verifies). On a miss, calls `verify`. Bounded:
    /// when full and inserting a new key, clears the cache first — the working set of distinct
    /// loaded images is small and stable, so a periodic flush is cheaper than per-entry LRU
    /// bookkeeping. A null verifier yields kUnknown (never fabricates signed). Take the stamp
    /// BEFORE verifying so a change in between only costs a re-verify, never a stale hit.
    ModuleSignVerdict get(const std::string& full_path, const FileVersionStamp& stamp,
                          const ModuleVerifier& verify);

    std::size_t size() const noexcept { return entries_.size(); }

private:
    struct Entry {
        FileVersionStamp stamp;
        ModuleSignVerdict verdict;
    };
    std::unordered_map<std::string, Entry> entries_;
    std::size_t cap_;
};

#ifdef _WIN32
// Windows shell seams (defined in the .cpp; declared so the Windows-only tests drive the real
// functions the drain calls). Windows types stay out of this header: a HANDLE is a void*.
struct ImageHandleCloser {
    void operator()(void* h) const noexcept; ///< CloseHandle; null is a no-op
};
/// An open image file; empty = no handle.
using ImageHandle = std::unique_ptr<void, ImageHandleCloser>;

/// Opens the IMAGE event's NT path as delivered (`\Device\HarddiskVolumeN\...`) ONCE, through
/// NtCreateFile with OBJ_DONT_REPARSE: a symbolic link or junction anywhere in the path
/// (including one planted after the event) fails the open instead of being followed. Callers
/// classify with image_path_is_local FIRST. Empty on ANY failure: open error, a name-surrogate
/// reparse point at the leaf, an over-long path, or a build that rejects OBJ_DONT_REPARSE.
/// Filter-handled tags (WOF/CompactOS, dedup, cloud files) are ordinary images, NOT refused.
/// Nothing is ever reopened by name.
[[nodiscard]] ImageHandle open_local_image_no_reparse(const std::string& nt_path);

/// Last-write time of the OPEN image, unix seconds; 0 on failure. Only an extra term of the
/// stamp (settable by the file's writer, so never the binding on its own).
[[nodiscard]] std::int64_t image_mtime_unix(void* image) noexcept;

/// The SigningCache key for the OPEN image (F47): volume serial + 128-bit file id + size from
/// the handle, and the USN from FSCTL_READ_FILE_USN_DATA. `available == false` on ANY failure
/// (non-journaled volume, USN 0, IOCTL refused). Measured on NTFS only (Windows 11
/// 26200, standalone harness); ReFS and journal-less volumes untested - see docs/echo-module-loads.md.
[[nodiscard]] FileVersionStamp read_image_version_stamp(void* image) noexcept;

/// WinVerifyTrust on the OPEN handle (WINTRUST_FILE_INFO::hFile); `nt_path` only fills the
/// required path field. The signer is the leaf of the provider chain's first signer.
[[nodiscard]] ModuleSignVerdict verify_image_signature_win(void* image, const std::string& nt_path);
#endif // _WIN32

/// Owns a real-time ETW session on Microsoft-Windows-Kernel-Process (IMAGE
/// keyword) and decodes image load (event 5; unloads are not consumed) into a
/// ModuleEventRing on a dedicated ProcessTrace thread. The $Module peer of
/// ProcEtwCollector. The ImageStreamCollector base is non-copyable/non-movable
/// (it owns a live session). Windows-only; every method is a no-op off-Windows and start()
/// returns false so the source simply produces nothing (no poll fallback for
/// modules — unlike process, there is no snapshot-diff equivalent).
class ModuleEtwCollector : public ImageStreamCollector {
public:
    /// `ring_capacity` bounds buffered-but-not-yet-drained events. Module loads
    /// are ~10× process starts, so this is sized generously; overflow drops with
    /// a counter (surfaced via echo.status module_stream_dropped).
    explicit ModuleEtwCollector(std::size_t ring_capacity = 100000);
    ~ModuleEtwCollector() override;

    bool start() override;
    void stop() override;
    bool running() const noexcept override;

    /// Drain buffered events for the batched echo.db write. Resolves the signing
    /// verdict (cached) and redacts module_dir off the ETW thread — mirroring
    /// ProcEtwCollector::drain resolving the owning user off-thread. Returns
    /// empty when not running / off-Windows.
    std::vector<ModuleEvent> drain() override;

    std::uint64_t dropped() const noexcept override;

    /// Always "etw".
    const char* method_name() const noexcept override { return "etw"; }

private:
    struct Impl;                 ///< Windows ETW/TDH state; defined only in the .cpp
    std::unique_ptr<Impl> impl_; ///< null off-Windows / when not running
    ModuleEventRing ring_;
    SigningCache sign_cache_;     ///< drain-thread only (no lock)
};

} // namespace yuzu::echo
