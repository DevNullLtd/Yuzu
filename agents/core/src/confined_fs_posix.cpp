#ifndef _WIN32

// MUST be the first thing in this TU, before ANY #include -- project, spdlog,
// or libc. glibc's <features.h> reads _GNU_SOURCE once, when the first libc
// header pulls it in, and is then guarded against re-entry; a definition that
// appears after that point is silently INERT. This sat below <dirent.h> and
// <fcntl.h> until it was moved here, which meant the Linux `renameat2` /
// RENAME_NOREPLACE declaration was not actually being secured by it -- the TU
// compiled only because libstdc++ (reached via spdlog) defines _GNU_SOURCE
// itself, the exact accidental reliance the guard was added to remove.
//
// Verified on glibc 2.43 / gcc-13: with the define in its old position and no
// libstdc++ in the include graph, this TU fails with "renameat2 implicitly
// declared" and "RENAME_NOREPLACE undeclared"; with the define here, it
// compiles. No configured Linux leg uses libc++ today (checked across
// .github/workflows, meson/native, meson/cross), so nothing was broken in
// practice -- but the guard now does the job its comment claims.
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

/**
 * confined_fs_posix.cpp -- POSIX shell for confined recursive delete
 * (confined_fs.hpp's platform contract). Every operation past `open_root`
 * is PARENT-HANDLE-RELATIVE: `openat`/`fstatat`/`unlinkat` against an
 * already-open `dir_fd`, never a freshly `::open()`ed/`::stat()`ed path
 * below the root. The ONE exception is `openat(fd, ".")`, used both here
 * (delete_matching's root frame) and in `enumerate_at` below to obtain an
 * INDEPENDENT open-file-description over an already-held fd's own inode --
 * it resolves through that fd, not a path string, so it is not a re-
 * resolution and is exempt from the no-path-below-root rule (see
 * confined_fs.hpp's header banner).
 *
 * This TU carries NO duplicated walk/tally/deadline/cap policy: all of that
 * lives in confined_fs_walk.hpp's `walk_delete`, which `delete_matching`
 * below instantiates with a file-local `PosixOps` that does nothing beyond
 * adapt `open_dir_at`/`enumerate_at`/`unlink_at`/`steady_clock::now()` to
 * the `Ops` shape `walk_delete` expects (PLAN-010).
 */

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/confined_fs_walk.hpp>

#include <spdlog/spdlog.h>

#include <dirent.h>
#include <fcntl.h>
#if defined(__APPLE__)
#include <sys/stdio.h> // renameatx_np, RENAME_EXCL
#elif defined(__linux__)
// glibc declares renameat2 in <stdio.h>, and only under __USE_GNU, which is
// selected by _GNU_SOURCE -- see the hoisted #define at the TOP of this file
// and the comment there explaining why it cannot live here.
#include <stdio.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::agent::confined_fs {

namespace {

/// InvalidName rule (confined_fs.hpp banner, PLAN-015): refused BEFORE any
/// syscall touches the name -- checked against `std::string::size()` (via
/// `find`, which respects embedded NULs), never `strlen`, so a NUL-
/// truncation attempt is caught rather than silently shortening the name
/// the syscall actually receives.

EntryType classify_mode(mode_t mode) {
    if (S_ISREG(mode))
        return EntryType::RegularFile;
    if (S_ISDIR(mode))
        return EntryType::Directory;
    if (S_ISLNK(mode))
        return EntryType::Symlink;
    return EntryType::Other;
}

/// RAII closer for the `DIR*` opened in `enumerate_at`. `fdopendir` takes
/// ownership of the fd handed to it, so from that call on the fd's lifetime
/// is tied to this, not to a `ScopedFd`.
struct DirCloser {
    DIR* dirp;
    explicit DirCloser(DIR* d) noexcept : dirp(d) {}
    ~DirCloser() {
        if (dirp != nullptr)
            ::closedir(dirp);
    }
    DirCloser(const DirCloser&) = delete;
    DirCloser& operator=(const DirCloser&) = delete;
};

using FstatFn = int (*)(int, struct stat*);
using FstatatFn = int (*)(int, const char*, struct stat*, int);

FstatFn g_fstat_fn = &::fstat;
FstatatFn g_fstatat_fn = &::fstatat;

} // namespace

namespace detail {

/// TEST SEAM: substitutes the `fstat`/`fstatat` function this TU calls
/// through -- mirrors the Windows leg's `detail::set_ntcreatefile_for_test`
/// (confined_fs.hpp), just for the two POSIX metadata syscalls instead of
/// `NtCreateFile`. Lets a test force a deterministic real POSIX metadata
/// failure (root identity capture, per-entry `fstatat`) without racing a
/// live TOCTOU window. `enable=true` installs `fn`; `enable=false` restores
/// the real syscall. Single-threaded, test-only, no internal
/// synchronization -- a test MUST restore (`enable=false`) before it ends,
/// or a later test observes the substituted pointer.
YUZU_EXPORT void set_fstat_for_test(FstatFn fn, bool enable) noexcept {
    g_fstat_fn = enable ? fn : &::fstat;
}
YUZU_EXPORT void set_fstatat_for_test(FstatatFn fn, bool enable) noexcept {
    g_fstatat_fn = enable ? fn : &::fstatat;
}

} // namespace detail

std::optional<FileIdentity> capture_identity(int fd) {
    struct stat st {};
    if (g_fstat_fn(fd, &st) != 0)
        return std::nullopt;
    return FileIdentity{static_cast<std::uint64_t>(st.st_dev), static_cast<std::uint64_t>(st.st_ino)};
}

// `openat`/`open` with O_NOFOLLOW|O_DIRECTORY does NOT report a refused symlink
// the same way across POSIX platforms: Linux returns ELOOP, but Darwin/BSD
// return ENOTDIR when both flags are set and the last component is a symlink.
// The refusal is safe either way -- the link is never followed -- but the
// REASON is part of this API's contract (callers surface it per path), so an
// ENOTDIR is disambiguated here rather than blanket-reported as NotRegularFile.
// Uses the fstatat seam so a test can drive both branches.
namespace {
bool is_symlink_at(int dirfd, const char* name) {
    struct stat st{};
    if (g_fstatat_fn(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return false; // cannot tell -- fall back to the non-symlink reason
    return S_ISLNK(st.st_mode);
}
} // namespace

OpenRootResult open_root(const std::filesystem::path& path) {
    // An embedded NUL would be truncated by c_str(), pinning a DIFFERENT
    // directory than the caller named and confining every later operation to
    // the wrong root. Entry names are checked for this (is_invalid_name); the
    // root path is the caller's own string and needs the same check.
    if (path.native().find('\0') != std::string::npos) {
        spdlog::warn("confined_fs::open_root: refused root path containing an embedded NUL");
        return OpenRootResult{std::nullopt, Reason::RootInvalid, 0};
    }
    const int raw = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (raw < 0) {
        const int err = errno;
        // ELOOP here means `path`'s last component is a symlink (O_NOFOLLOW
        // refused it) -- a security-class refusal, logged at warn like
        // open_dir_at's ELOOP branch below; every other open_root failure
        // (missing path, not-a-directory, ...) stays debug.
        if (err == ELOOP || (err == ENOTDIR && is_symlink_at(AT_FDCWD, path.c_str()))) {
            spdlog::warn("confined_fs::open_root: refused symlink root '{}'", path.string());
        } else {
            spdlog::debug("confined_fs::open_root: refused '{}': {}", path.string(),
                          std::strerror(err));
        }
        return OpenRootResult{std::nullopt, Reason::RootInvalid, err};
    }
    ScopedFd fd{raw};
    const auto id = capture_identity(fd.get());
    if (!id) {
        const int err = errno;
        spdlog::debug("confined_fs::open_root: fstat failed for '{}': {}", path.string(),
                      std::strerror(err));
        return OpenRootResult{std::nullopt, Reason::RootInvalid, err};
    }
    return OpenRootResult{ConfinedRoot{std::move(fd), *id}, Reason::None, 0};
}

OpenDirResult open_dir_at(int parent_fd, const std::string& name, const FileIdentity& root_id) {
    if (is_invalid_component(name, /*windows_separators=*/false))
        return OpenDirResult{ScopedFd{}, Reason::InvalidName, 0};

    const int raw = ::openat(parent_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (raw < 0) {
        const int err = errno;
        if (err == ELOOP) {
            spdlog::warn("confined_fs::open_dir_at: symlink rejected for '{}'", name);
            return OpenDirResult{ScopedFd{}, Reason::SymlinkRejected, err};
        }
        if (err == ENOTDIR) {
            if (is_symlink_at(parent_fd, name.c_str())) {
                spdlog::warn("confined_fs::open_dir_at: symlink rejected for '{}'", name);
                return OpenDirResult{ScopedFd{}, Reason::SymlinkRejected, err};
            }
            spdlog::debug("confined_fs::open_dir_at: not a directory: '{}'", name);
            return OpenDirResult{ScopedFd{}, Reason::NotRegularFile, err};
        }
        spdlog::debug("confined_fs::open_dir_at: openat('{}') failed: {}", name, std::strerror(err));
        return OpenDirResult{ScopedFd{}, Reason::OsError, err};
    }

    ScopedFd fd{raw};
    const auto id = capture_identity(fd.get());
    if (!id) {
        const int err = errno;
        return OpenDirResult{ScopedFd{}, Reason::OsError, err};
    }
    // Post-open fstat device re-verify -- the device check happens on the
    // FD we just opened, never on a path-based stat of `name`.
    if (id->dev != root_id.dev) {
        spdlog::warn("confined_fs::open_dir_at: device boundary crossed at '{}'", name);
        return OpenDirResult{ScopedFd{}, Reason::DeviceBoundary, 0};
    }
    return OpenDirResult{std::move(fd), Reason::None, 0};
}

EnumerateResult enumerate_at(int dir_fd, const FileIdentity& root_id, const EnumBudget& budget) {
    EnumerateResult result{};

    // INDEPENDENT-DESCRIPTION rule (PLAN-005/PLAN-012): obtain the
    // enumeration stream via a FRESH open-file-description over `dir_fd`'s
    // own inode, NEVER `::dup` on `dir_fd` -- duplicating shares the same
    // open-file-description, including its directory read offset, so a
    // second enumeration of a reused root would silently resume (empty)
    // from wherever the first walk's readdir cursor stopped; duplicating
    // also does not carry FD_CLOEXEC forward. `openat(dir_fd, ".")`
    // resolves through `dir_fd`'s own inode, not a path string, so it is
    // exempt from the no-path-below-root rule.
    const int raw = ::openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (raw < 0) {
        result.reason = Reason::OsError;
        result.os_error = errno;
        return result;
    }
    ScopedFd owned{raw};
    DIR* dirp = ::fdopendir(owned.get());
    if (dirp == nullptr) {
        result.reason = Reason::OsError;
        result.os_error = errno;
        return result; // `owned` still closes `raw` on scope exit
    }
    [[maybe_unused]] const int released = owned.release(); // closedir() now owns the fd
    DirCloser closer{dirp};

    // EXCEPTION FIREWALL: this TU's own "no exceptions escape" invariant
    // (file banner) applies to `enumerate_at` as a directly-callable export,
    // not just when it runs inside `walk_delete`'s own outer try/catch --
    // `std::string`/`std::vector` allocation below can throw `bad_alloc`.
    // Best-effort partial result on catch, same mapping `walk_delete` uses
    // for an exception it did not itself throw (confined_fs_walk.hpp rule 7).
    try {
        // Cross-leg parity (B004's principle): a zero entry budget reports
        // EntryCap on BOTH legs. The Windows leg has this same early guard
        // before its own deadline check; without it here, a default-
        // constructed DeleteLimits -- every cap zero, so every cap is
        // simultaneously hit -- reported WallTimeCap on POSIX and EntryCap on
        // Windows for byte-identical input. Both refuse and both delete
        // nothing, so this was never a safety difference, but a caller
        // asserting on the fail-closed default's reason should not get a
        // different answer per platform.
        if (budget.max_entries == 0) {
            result.reason = Reason::EntryCap;
            return result;
        }

        while (true) {
            if (std::chrono::steady_clock::now() >= budget.deadline) {
                result.reason = Reason::WallTimeCap;
                return result;
            }

            errno = 0;
            struct dirent* de = ::readdir(dirp);
            if (de == nullptr) {
                if (errno != 0) {
                    result.reason = Reason::OsError;
                    result.os_error = errno;
                }
                return result; // fully enumerated (reason stays None)
            }

            const std::string name = de->d_name;
            if (name == "." || name == "..")
                continue;

            if (static_cast<std::uint64_t>(result.entries.size()) >= budget.max_entries) {
                // Another entry exists beyond the budget: this is a real
                // truncation, not "happened to finish exactly at the cap".
                result.reason = Reason::EntryCap;
                return result;
            }

            DirEntry entry{};
            entry.name = name;
            struct stat st {};
            if (g_fstatat_fn(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                // PLAN-002: a stat failure is recorded as-is, never silently
                // reclassified as Other -- the walker reports Failed(OsError)
                // and never deletes it.
                entry.stat_error = errno;
            } else {
                const EntryType type = classify_mode(st.st_mode);
                const std::uint64_t size =
                    (type == EntryType::RegularFile) ? static_cast<std::uint64_t>(st.st_size) : 0;
                entry.meta =
                    EntryMeta{type, size, static_cast<std::uint64_t>(st.st_dev) == root_id.dev,
                              // Already in hand from the fstatat above, which is
                              // parent-handle-relative -- no extra syscall, no path open.
                              //
                              // ALWAYS ENGAGED on POSIX, deliberately, and this
                              // differs from the Windows leg on purpose. fstatat
                              // always populates st_mtime; POSIX has no "unset"
                              // encoding, so st_mtime == 0 is a genuine
                              // 1970-01-01 timestamp (a real value on restored
                              // archives) rather than absence. Mapping it to
                              // nullopt would discard a true fact. Windows'
                              // FILETIME 0 genuinely DOES mean "not set", which
                              // is why that leg returns nullopt for it.
                              //
                              // CAVEAT, and it is the one hole in that reasoning:
                              // a FUSE or network mount that supplies no
                              // timestamps also returns st_mtime == 0, which is
                              // the same "unset" signal Windows maps to nullopt
                              // but arrives here as a genuine-looking 1970. An
                              // age filter reads that as maximally old. This is
                              // within the best-effort SELECTION envelope the
                              // header documents, not a confinement issue, and
                              // is left as-is rather than guessing which zero
                              // is which.
                              std::optional<std::int64_t>{static_cast<std::int64_t>(st.st_mtime)}};
            }
            result.entries.push_back(std::move(entry));
        }
    } catch (...) {
        result.reason = Reason::Internal;
        return result;
    }
}

// Unpredictable capture name. The byte cap cannot be enforced by measuring a
// NAME and then unlinking that name: fstatat and unlinkat are separate calls,
// and an attacker who controls the tree can swap a large file over the measured
// name in between. Reproduced: a 1-byte entry measured, replaced with a
// 4096-byte file, deleted under a 10-byte remaining budget and charged 1.
//
// The fix is capture-then-measure: renameat the entry to a name the attacker
// cannot PREDICT, then measure and unlink that name. rename is atomic, so the
// inode is bound to the new name in one step.
//
// HONEST LIMIT, and it is WIDER than byte accounting. The capture name is
// unpredictable but NOT hidden: anyone who can read the directory sees it appear
// and can rename their own file over it before we measure and unlink. We would
// then stat AND delete THEIR inode -- a file MatchFn was never offered -- and
// report it as {Deleted, rel_path=<original name>}. So the swap defeats WHAT is
// deleted, not merely HOW MUCH is charged. POSIX offers no atomic "unlink this
// specific inode by name", so the window is NARROWED -- from one an attacker can
// wait for and win at leisure, to one requiring them to observe and act inside a
// few syscalls -- not CLOSED.
//
// Therefore, against an adversary holding write access to the parent directory:
//   * CONFINEMENT holds absolutely -- every operation is relative to the pinned
//     parent handle, so nothing outside the root can be reached.
//   * SELECTION (which entry is deleted) and ACCOUNTING (the byte cap) are both
//     BEST-EFFORT, and the action layer must not present either as a guarantee.
//
// A separate staging DIRECTORY was considered and deliberately not used: on
// POSIX a same-UID attacker can reach any directory we can create, so it adds
// no confidentiality, while adding cross-directory rename, orphan purging and
// enumeration-exclusion failure modes. The unpredictability of the name is what
// closes the window, and that works in the entry's own parent.
//
// Residual, documented: a hard kill between the rename and the unlink leaves one
// orphan named with the prefix below. Every non-crash path restores or removes it.
constexpr const char* kCapturePrefix = kCaptureNamePrefix; // exported in confined_fs.hpp

/// Rename WITHOUT replacing an existing destination. A plain renameat() silently
/// unlinks whatever occupies the target name, which on the restore path means an
/// entry the local user created at the original name during the capture window is
/// destroyed -- deleted uncharged against the byte cap, never offered to MatchFn,
/// and absent from every EntryOutcome. Measured: renameat over an existing
/// destination returns 0 and the destination's contents are gone.
int rename_noreplace(int dir_fd, const char* from, const char* to) {
#if defined(__APPLE__)
    if (::renameatx_np(dir_fd, from, dir_fd, to, RENAME_EXCL) == 0)
        return 0;
    if (errno != ENOTSUP && errno != EINVAL && errno != ENOSYS)
        return -1; // a real failure, not an unsupported flag
#elif defined(__linux__)
    if (::renameat2(dir_fd, from, dir_fd, to, RENAME_NOREPLACE) == 0)
        return 0;
    if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP)
        return -1;
#endif
    // FALLBACK -- the no-replace flag is FILESYSTEM-gated, not merely
    // kernel-gated: NFS, CIFS and most FUSE backends (including the
    // fuse-overlayfs that rootless Docker defaults to) reject it with EINVAL.
    // Refusing outright there would make EVERY refusal path -- including an
    // ordinary byte-cap skip -- orphan the entry under its capture name, so the
    // primitive would never cleanly decline on such a mount. Check-then-rename
    // is racy, but it is exactly as racy as the plain renameat this replaced,
    // and strictly better than orphaning: we lose the guarantee on those
    // filesystems, we do not lose the operation.
    if (::faccessat(dir_fd, to, F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST; // occupied -- do not clobber it
        return -1;
    }
    return ::renameat(dir_fd, from, dir_fd, to);
}

std::optional<std::string> make_capture_name() {
    unsigned char raw[8];
    // ScopedFd, not a raw open/close pair: manual cleanup in new code is a
    // governance policy floor even where no early return currently sits between
    // acquire and release, because the next edit is what introduces one.
    ScopedFd urandom{::open("/dev/urandom", O_RDONLY | O_CLOEXEC)};
    if (!urandom.valid()) {
        // Capture errno HERE: ScopedFd's destructor runs close() on the way out
        // and can clobber it before the caller reads it.
        const int err = errno;
        spdlog::warn("confined_fs: cannot open /dev/urandom for a capture name: {}",
                     std::strerror(err));
        errno = err;
        return std::nullopt;
    }
    ssize_t got = 0;
    do {
        got = ::read(urandom.get(), raw, sizeof raw);
    } while (got < 0 && errno == EINTR); // short/interrupted read is not a failure to ignore
    if (got != static_cast<ssize_t>(sizeof raw)) {
        // Capture before ~ScopedFd's close() can overwrite it, exactly as the
        // open-failure branch above does.
        const int err = errno;
        errno = err;
        return std::nullopt;
    }
    static const char* kHex = "0123456789abcdef";
    std::string out = kCapturePrefix;
    for (unsigned char b : raw) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

UnlinkOutcome unlink_at(int dir_fd, const std::string& name, UnlinkKind kind,
                        std::uint64_t max_bytes_remaining) {
    if (is_invalid_component(name, /*windows_separators=*/false))
        return UnlinkOutcome{EntryStatus::Failed, Reason::InvalidName, 0, 0};

    // CAPTURE. Bind the directory entry to an unpredictable name before doing
    // anything else, so the object we measure is provably the object we delete.
    const auto captured = make_capture_name();
    if (!captured) {
        const int err = errno;
        spdlog::warn("confined_fs::unlink_at: cannot generate a capture name ({}) -- refusing",
                     std::strerror(err));
        return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, err, 0};
    }
    if (::renameat(dir_fd, name.c_str(), dir_fd, captured->c_str()) != 0) {
        const int err = errno;
        spdlog::debug("confined_fs::unlink_at: capture rename of '{}' failed: {}", name,
                      std::strerror(err));
        return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, err, 0};
    }

    // Restores the entry to its original name on any refusal path below, so a
    // declined delete leaves the tree exactly as it was found.
    // Returns true when the entry is back under its original name. NEVER
    // overwrites: if something now occupies that name it is left alone and the
    // caller reports CaptureOrphaned rather than destroying it.
    const auto restore = [&]() -> bool {
        if (rename_noreplace(dir_fd, captured->c_str(), name.c_str()) == 0)
            return true;
        const int err = errno;
        spdlog::warn("confined_fs::unlink_at: could not restore '{}' ({}); it remains as '{}' "
                     "and the tree HAS been modified", name, std::strerror(err), *captured);
        return false;
    };

    // MEASURE the captured name. The attacker cannot GUESS this name, but they
    // can observe it via readdir and rename over it -- see the honest-limit note
    // above. This narrows the window; it does not close it.
    std::uint64_t live_bytes = 0;
    if (kind == UnlinkKind::File) {
        struct stat st{};
        if (g_fstatat_fn(dir_fd, captured->c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            const int err = errno;
            if (!restore())
                return UnlinkOutcome{EntryStatus::Failed, Reason::CaptureOrphaned, err, 0};
            spdlog::warn("confined_fs::unlink_at: cannot measure '{}' before deleting ({}) -- "
                         "refusing rather than deleting it uncharged", name, std::strerror(err));
            return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, err, 0};
        }
        if (S_ISREG(st.st_mode)) {
            live_bytes = static_cast<std::uint64_t>(st.st_size);
            if (live_bytes > max_bytes_remaining) {
                if (!restore())
                    return UnlinkOutcome{EntryStatus::Failed, Reason::CaptureOrphaned, 0, 0};
                spdlog::warn("confined_fs::unlink_at: '{}' exceeds the remaining byte cap -- "
                             "refusing", name);
                return UnlinkOutcome{EntryStatus::Skipped, Reason::ByteCap, 0, 0};
            }
        }
    }

    // DELETE the captured name -- the same object that was just measured.
    const int flags = (kind == UnlinkKind::EmptyDirectory) ? AT_REMOVEDIR : 0;
    if (::unlinkat(dir_fd, captured->c_str(), flags) != 0) {
        const int err = errno;
        if (!restore())
            return UnlinkOutcome{EntryStatus::Failed, Reason::CaptureOrphaned, err, 0};
        spdlog::debug("confined_fs::unlink_at: unlinkat('{}') failed: {}", name,
                      std::strerror(err));
        return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, err, 0};
    }
    return UnlinkOutcome{EntryStatus::Deleted, Reason::None, 0, live_bytes};
}

namespace {

/// `Ops` adapter (confined_fs_walk.hpp) binding `walk_delete` to this TU's
/// primitives. Carries no policy of its own -- every branch here is a
/// direct pass-through to `open_dir_at`/`enumerate_at`/`unlink_at`.
struct PosixOps {
    using DirHandle = ScopedFd;

    FileIdentity root_id;

    OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name) {
        OpenDirResult r = open_dir_at(parent.get(), name, root_id);
        if (r.reason != Reason::None)
            return OpenDirRes<DirHandle>{std::nullopt, r.reason, r.os_error};
        return OpenDirRes<DirHandle>{std::move(r.fd), Reason::None, 0};
    }

    EnumerateResult enumerate(DirHandle& dir, const EnumBudget& budget) {
        return enumerate_at(dir.get(), root_id, budget);
    }

    UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind kind,
                         std::uint64_t max_bytes_remaining) {
        return unlink_at(parent.get(), name, kind, max_bytes_remaining);
    }

    std::chrono::steady_clock::time_point now() { return std::chrono::steady_clock::now(); }
};

} // namespace

DeleteResult delete_matching(const ConfinedRoot& root, const MatchFn& match,
                              const DeleteLimits& limits) {
    // The root frame handed to `walk_delete` must be an INDEPENDENT
    // open-file-description from `root.fd_` (same rule as enumerate_at
    // above), not the root's own fd moved out from under it -- `root` is
    // `const&` here specifically so a caller can run `delete_matching`
    // again on the SAME `ConfinedRoot` (root reuse, PLAN-005) after this
    // call returns.
    const int raw = ::openat(root.fd_.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (raw < 0) {
        DeleteResult result{};
        result.stop_reason = Reason::OsError;
        return result;
    }

    PosixOps ops{root.identity()};
    return walk_delete<PosixOps>(ScopedFd{raw}, ops, match, limits);
}

} // namespace yuzu::agent::confined_fs

#endif // !_WIN32
