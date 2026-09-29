#pragma once

/**
 * confined_fs.hpp -- platform shell API for confined recursive delete: a
 * root is pinned ONCE (open/handle held for the lifetime of the operation)
 * and every subsequent read/enumerate/delete is PARENT-HANDLE-RELATIVE
 * (POSIX `*at()` on a held `dir_fd`, Windows `NtCreateFile` with a held
 * parent `HANDLE` as the root object) -- confined_fs.hpp declares this
 * surface; the platform TUs (separate packages, one per OS) define it. This
 * header itself stays syntax-checkable under BOTH `#ifdef` branches on any
 * host, but only one branch's bodies exist on any given build.
 *
 * ── Threat model ─────────────────────────────────────────────────────────
 * The primitive this header fronts exists to delete content below an
 * attacker-influenced directory (a plugin's staging area, a quarantined
 * download, generated scratch output) WITHOUT trusting that directory's
 * structure. The threat is a symlink or junction swapped in between when an
 * entry is CHECKED (stat/enumerate) and when it is ACTED on (unlink/open) --
 * classic TOCTOU. This is why every operation past `open_root` is
 * PARENT-HANDLE-RELATIVE and NEVER re-resolves a path from a string: once a
 * directory handle is open, later operations address entries BY NAME
 * against that already-open handle, so there is no path string left for an
 * attacker to re-point mid-operation. A freshly `::open()`ed-by-path call
 * anywhere in this flow would reintroduce exactly the race the whole design
 * exists to close.
 *
 * ── Recorded exception: read-only, selection-only target resolution ──────
 * One sibling consumer of this design -- the certificates plugin's Linux
 * store scan (agents/plugins/certificates/src/certificates_linux_store.hpp,
 * read_cert_entry) -- deliberately performs ONE string-resolved open below
 * its held root: a symlinked store entry is `readlinkat`-resolved and its
 * target re-opened read-only, solely to parse certificate CONTENT for
 * SELECTION. That is a recognised, bounded deviation from the rule above,
 * not a licence for it, and it is safe only because the two halves of that
 * flow carry different contracts -- exactly the "confinement absolute,
 * selection best-effort" split confined_fs_posix.cpp documents above its
 * capture-then-measure step. CONFINEMENT stays absolute: the only
 * destructive syscall in that flow (`unlinkat`) is dirfd + validated-name
 * relative and removes the entry's OWN name, never anything the resolved
 * target handle reached. SELECTION is best-effort: the read-only open is
 * O_RDONLY|O_NONBLOCK, its handle is never acted on destructively, and a
 * pre-unlink identity recheck (link inode + target text + target inode)
 * refuses (kChanged) any retarget or replacement it OBSERVES -- which
 * narrows the residual recheck-to-unlink window to microseconds but does
 * not close it (delete_cert_linux's own comment records why the rename
 * step is not adopted against a live trust store). A new consumer wanting
 * the same latitude must meet all of those conditions and record them at
 * its own open site.
 *
 * ── InvalidName rule (PLAN-015, adopted) ─────────────────────────────────
 * A name is refused BEFORE any syscall touches it -- never partially
 * processed -- if it is: empty; exactly "." or ".."; contains a '/' (or,
 * additionally on Windows, a '\\'); or contains an EMBEDDED NUL byte. All
 * four are structurally never a legitimate single path COMPONENT, and each
 * one is a known technique for confusing a syscall about which entry it is
 * actually touching (NUL-truncation being the classic one).
 *
 * ── Root-authorization contract (PLAN-009) ───────────────────────────────
 * Confinement here applies STRICTLY BELOW the supplied root: everything
 * this header's functions do stays inside the subtree rooted at whatever
 * `open_root` was given. Deciding whether a root MAY be targeted at all --
 * never "/", never a system directory, never another tenant's tree -- is
 * the CALLER'S authorization policy, enforced at the consuming action layer
 * (PR6.1-a), NOT by this primitive. `open_root` itself refuses only a
 * non-directory or a reparse-point root; it has no opinion on WHICH
 * directories are appropriate targets.
 *
 * ── Zero-adoption ruling: FileIdentity / capture_identity ────────────────
 * `FileIdentity` + `capture_identity` are the ONLY helper hoisted out of the
 * three existing agent-core sites that each already do something in this
 * space -- every other primitive here is new. The three sites keep their
 * own, DELIBERATELY DIFFERENT contracts and are NOT migrated onto this
 * header (zero-adoption is final for this PR):
 *
 *   - plugin_loader.cpp:523 (Windows) / :560 (POSIX) has NO dev/ino identity
 *     contract at all -- it pins the loaded inode by HOLDING the handle/fd
 *     open across the hash-then-load sequence (Windows: CreateFileW with
 *     FILE_SHARE_READ only + FILE_FLAG_OPEN_REPARSE_POINT; POSIX: ::open
 *     with O_RDONLY|O_NOFOLLOW|O_CLOEXEC). That is a share-mode/fd PIN, not
 *     a comparable identity VALUE -- there is no dev:ino pair constructed or
 *     compared anywhere in that flow.
 *
 *   A note on `WinHandle` below, since it is a fourth thing in this space:
 *   `guard_win_handle.hpp` already has `ScopedWinHandle<CloseFn>` with the same
 *   semantics, but it is a PRIVATE header under src/ and this is a PUBLIC
 *   header, so reusing it would mean hoisting it into include/ and widening its
 *   audience as a side effect of this PR. That is a deliberate deferral, not an
 *   oversight: if a third consumer appears, hoist it and collapse the two.
 *
 *   - guardian_state_reader.cpp:95 builds a `dev:ino` STRING
 *     (`file_identity()`) purely as an opaque change-detection token for
 *     convergence bookkeeping -- explicitly "NOT part of any verdict". Its
 *     :317 caller deliberately FOLLOWS reparse points (matches POSIX
 *     symlink-follow semantics for spark-detection reads), the opposite of
 *     this header's NOFOLLOW-everywhere posture.
 *   - updater.cpp:716 re-verifies `st_ino`/`st_dev` between an already-open
 *     fd and a fresh path-based stat as a TOCTOU detector on its own update
 *     temp file, and :568 uses Windows `FileDispositionInfo` to delete an
 *     open temp file by HANDLE on process exit -- both narrowly scoped to
 *     updater.cpp's single-file replace flow, not a general primitive.
 *
 * Each of these has a shape close enough to this header's `FileIdentity`
 * that a naive reviewer might expect adoption; the recorded reasoning here
 * is that none of them are a byte-for-byte match to what this header needs,
 * and forcing them onto a shared type they were not designed for would be a
 * worse outcome than the (small) duplication. A wanted-but-undeclared
 * helper beyond `FileIdentity`/`capture_identity` and `WinHandle` is a flag
 * to the orchestrator, not an invention.
 */

#include <yuzu/agent/confined_fs_rules.hpp>

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>

#include <yuzu/agent/scoped_fd.hpp>
#endif

namespace yuzu::agent::confined_fs {

/// Prefix of the transient name an entry is renamed to while it is measured and
/// deleted (POSIX only; the Windows leg deletes by handle and never renames).
///
/// EXPORTED DELIBERATELY. A hard kill between the rename and the unlink, or a
/// restore that finds the original name occupied, leaves a real file under this
/// prefix. A consuming action that reclaims disk MUST make a recorded decision
/// about such entries -- reap them, or exclude them from the entry budget --
/// and it cannot do that against a literal copied out of a .cpp. Reaping widens
/// blast radius, because a local user can create a file with this prefix to bait
/// it, so this is a decision for the action layer, not an obvious default.
inline constexpr const char* kCaptureNamePrefix = ".yuzu_cfs_capture_";


#ifdef _WIN32
/// Windows identity: NTFS volume serial + file index (the `dev:ino`
/// analogue on this platform).
struct FileIdentity {
    std::uint32_t volume_serial;
    std::uint64_t file_index;

    friend bool operator==(const FileIdentity&, const FileIdentity&) = default;
};

/// Capture the identity of an already-open HANDLE. The caller retains
/// ownership of `h`. Returns nullopt on any failure to query it.
[[nodiscard]] YUZU_EXPORT std::optional<FileIdentity> capture_identity(HANDLE h);

/// Move-only owner of a kernel HANDLE (PLAN-003, adopted). Non-exported,
/// header-inline: closes the owned handle on destruction unless released or
/// reset first. Used by BOTH `ConfinedRoot` and `OpenDirResult` so no raw
/// HANDLE ever crosses this header's exported API.
class WinHandle {
public:
    WinHandle() = default;
    explicit WinHandle(HANDLE h) noexcept : h_(h) {}

    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;

    WinHandle(WinHandle&& other) noexcept : h_(other.release()) {}
    WinHandle& operator=(WinHandle&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~WinHandle() { reset(); }

    [[nodiscard]] bool valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }
    explicit operator bool() const noexcept { return valid(); }

    /// The raw HANDLE, or an invalid sentinel if this instance owns
    /// nothing. Ownership is retained.
    [[nodiscard]] HANDLE get() const noexcept { return h_; }

    /// Give up ownership without closing. The result must be handed
    /// immediately to another named owner (docs/cpp-conventions.md
    /// resource rules) -- never left as a bare local HANDLE.
    [[nodiscard]] HANDLE release() noexcept {
        HANDLE h = h_;
        h_ = INVALID_HANDLE_VALUE;
        return h;
    }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        if (h == h_)
            return;
        if (valid())
            CloseHandle(h_);
        h_ = h;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};
#else
/// POSIX identity: device + inode (the values `stat()` already exposes).
struct FileIdentity {
    std::uint64_t dev;
    std::uint64_t ino;

    friend bool operator==(const FileIdentity&, const FileIdentity&) = default;
};

/// Capture the identity of an already-open fd. The caller retains ownership
/// of `fd`. Returns nullopt on any failure to query it.
[[nodiscard]] YUZU_EXPORT std::optional<FileIdentity> capture_identity(int fd);
#endif

/// A pinned, held-open confinement root. Non-exported, move-only: the
/// entire point of this type is that its handle/fd stays open for the
/// lifetime of a `delete_matching` call, so every operation below the root
/// can be parent-handle-relative instead of re-resolving a path.
struct ConfinedRoot {
#ifdef _WIN32
    WinHandle h_;
#else
    ScopedFd fd_;
#endif
    FileIdentity id_;

    [[nodiscard]] const FileIdentity& identity() const noexcept { return id_; }
};

/// Result of `open_root`.
struct OpenRootResult {
    std::optional<ConfinedRoot> root;
    Reason reason{Reason::None};
    int os_error{0};
};

/// Result of a lower-level `open_dir_at` call. Holds the SAME owner type as
/// `ConfinedRoot` (`WinHandle` / `ScopedFd`) so a raw HANDLE/fd never
/// crosses this header's exported API in either direction.
struct OpenDirResult {
#ifdef _WIN32
    WinHandle h;
#else
    ScopedFd fd;
#endif
    Reason reason;
    int os_error;
};

/// Open and pin `path` as a confinement root. Refuses (via `reason`) a
/// non-directory or a reparse-point/symlink root -- see the root-
/// authorization contract in the header banner for what this function
/// deliberately does NOT decide.
[[nodiscard]] YUZU_EXPORT OpenRootResult open_root(const std::filesystem::path& path);

/// Walk `root` deleting every entry `match` accepts, subject to `limits`.
/// The single entry point most callers use; internally drives
/// `confined_fs_walk.hpp`'s `walk_delete` against this platform's `Ops`.
[[nodiscard]] YUZU_EXPORT DeleteResult delete_matching(const ConfinedRoot& root,
                                                        const MatchFn& match,
                                                        const DeleteLimits& limits);

#ifdef _WIN32
/// Enumerate `dir` under `budget`. `root_id` is used to re-verify the
/// enumerated directory is still within the pinned root's volume.
[[nodiscard]] YUZU_EXPORT EnumerateResult enumerate_at(HANDLE dir, const FileIdentity& root_id,
                                                        const EnumBudget& budget);

/// Delete `name` (a File or an EmptyDirectory) inside `parent`. `root_id` is
/// carried because the Windows delete handle must be volume-verified
/// (PLAN-008, adopted) -- unlike POSIX `unlinkat`, which is name-level and
/// opens nothing, so it needs no such check. This POSIX/Windows asymmetry
/// is deliberate, not an oversight.
[[nodiscard]] YUZU_EXPORT UnlinkOutcome unlink_at(HANDLE parent, const std::string& name,
                                                   UnlinkKind kind, std::uint64_t max_bytes_remaining, const FileIdentity& root_id);

/// Open `name` inside `parent` as a new confined directory handle. `root_id`
/// re-verifies the opened directory is still within the pinned root's
/// volume.
[[nodiscard]] YUZU_EXPORT OpenDirResult open_dir_at(HANDLE parent, const std::string& name,
                                                     const FileIdentity& root_id);

namespace detail {

/// TEST SEAM (PLAN-011, adopted): substitute the resolved `NtCreateFile`
/// function pointer used internally by the platform TU. `enable=true`
/// installs `fn` (a null `fn` simulates ntdll-resolution failure, which
/// this primitive treats as `Reason::Unsupported` -- fail-closed, never a
/// silent fallback to a different open path); `enable=false` restores the
/// real resolved pointer. Single-threaded, test-only, NO internal
/// synchronization -- callers MUST restore (`enable=false`) before the test
/// ends, or a later test observes the substituted pointer.
YUZU_EXPORT void set_ntcreatefile_for_test(void* fn, bool enable) noexcept;
} // namespace detail
#else
/// Enumerate the directory referenced by `dir_fd` under `budget`. `root_id`
/// is used to re-verify the enumerated directory is still within the
/// pinned root's device.
[[nodiscard]] YUZU_EXPORT EnumerateResult enumerate_at(int dir_fd, const FileIdentity& root_id,
                                                        const EnumBudget& budget);

/// Delete `name` (a File or an EmptyDirectory) inside the directory
/// referenced by `dir_fd`, via `unlinkat`. POSIX `unlinkat` is name-level
/// and opens nothing, so unlike the Windows twin it needs no root-identity
/// parameter -- see the asymmetry note above `unlink_at`'s Windows overload.
[[nodiscard]] YUZU_EXPORT UnlinkOutcome unlink_at(int dir_fd, const std::string& name,
                                                   UnlinkKind kind, std::uint64_t max_bytes_remaining);

namespace detail {
/// POSIX metadata-syscall seams, declared here rather than left as an undeclared
/// exported symbol the test hand-redeclares: these redirect the fstat/fstatat
/// calls this primitive's device, type and byte-cap decisions rest on, so their
/// signatures belong under the same review as the API. Mirrors the Windows
/// `set_ntcreatefile_for_test` seam below. Test-only and single-threaded:
/// `enable=true` substitutes `fn` (nullptr simulates failure), `enable=false`
/// restores the real syscall, and every caller MUST restore before test end.
using FstatFn = int (*)(int, struct stat*);
using FstatatFn = int (*)(int, const char*, struct stat*, int);
YUZU_EXPORT void set_fstat_for_test(FstatFn fn, bool enable) noexcept;
YUZU_EXPORT void set_fstatat_for_test(FstatatFn fn, bool enable) noexcept;
} // namespace detail


/// Open `name` inside the directory referenced by `parent_fd` as a new
/// confined directory fd. `root_id` re-verifies the opened directory is
/// still within the pinned root's device.
[[nodiscard]] YUZU_EXPORT OpenDirResult open_dir_at(int parent_fd, const std::string& name,
                                                     const FileIdentity& root_id);
#endif

} // namespace yuzu::agent::confined_fs
