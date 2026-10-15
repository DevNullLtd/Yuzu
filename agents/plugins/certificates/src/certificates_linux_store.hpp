#pragma once

// certificates_linux_store.hpp -- POSIX cert-store directory/entry/delete
// machinery for the Linux cert-store implementation, moved out of
// certificates_plugin.cpp's anonymous namespace so
// tests/unit/test_certificates_linux_store.cpp can drive a REAL delete
// against a TempDir, on macOS and Linux alike. Every syscall this header
// touches (openat/fstatat/readlinkat/unlinkat/readdir) is plain POSIX, not
// Linux-specific -- only the PRODUCTION call sites in certificates_plugin.cpp
// stay `#ifdef __linux__`, because /etc/ssl/certs as a flat PEM-directory
// store is a Linux distribution convention, not a POSIX one.
//
// Whole body guarded `#if !defined(_WIN32)` (rather than `#ifdef __linux__`)
// so this header itself compiles wherever the test TU does, including on
// macOS CI.

#if !defined(_WIN32)

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include "certificates_macos_parsers.hpp"
#include "certificates_x509.hpp"

namespace yuzu::certificates_linux {

using yuzu::certificates_macos::CertDirOpen;
using yuzu::certificates_macos::CertEntryIdentity;
using yuzu::certificates_macos::CertEntryOpen;
using yuzu::certificates_macos::DeleteRecheck;
using yuzu::certificates_macos::canonical_thumbprint;
using yuzu::certificates_macos::classify_cert_dir_open;
using yuzu::certificates_macos::classify_cert_entry_open;
using yuzu::certificates_macos::classify_delete_recheck;
using yuzu::certificates_macos::is_cert_entry_name;

/// Injected syscall boundary for the store machinery below -- test
/// discipline per CLAUDE.md's "inject the boundary" rule. Mirrors
/// confined_fs_posix.cpp:103-123's fstat/fstatat seam, but as a parameter
/// rather than a process-global function pointer: every production call
/// site passes nothing (the defaults bind the real syscalls, so production
/// behavior is unchanged), and a test passes a fake that performs whatever
/// swap it needs to exercise INSIDE the call, then ordinarily delegates to
/// the real syscall -- see test_confined_fs_posix.cpp:397-420 for the
/// pattern this follows. `::openat`/`::open`/`::fstat`/`::read` stay real
/// throughout this header -- only the four syscalls a test needs to force a
/// deterministic TOCTOU/enumeration outcome for are injectable.
struct StoreSyscalls {
    int (*fstatat)(int, const char*, struct stat*, int) = &::fstatat;
    ssize_t (*readlinkat)(int, const char*, char*, std::size_t) = &::readlinkat;
    struct dirent* (*readdir)(DIR*) = &::readdir;
    int (*unlinkat)(int, const char*, int) = &::unlinkat;
};

inline constexpr const char* kDefaultCertDir = "/etc/ssl/certs";

/// Outcome of opening the Linux cert-store directory itself (open_cert_dir).
struct CertDir {
    yuzu::agent::ScopedFd fd;
    CertDirOpen state;
    int err = 0;
};

/// Opens `dir_path` ONCE and holds the descriptor for every subsequent
/// per-entry operation (enumeration, per-entry open/stat, and -- on delete --
/// the pre-unlink recheck + unlinkat itself) -- the held-dirfd design #3245
/// depends on: every syscall below is parent-handle-relative, never a fresh
/// pathname lookup, so a directory swapped for another between two separate
/// opens cannot make this code enumerate one directory and act on another.
[[nodiscard]] inline CertDir open_cert_dir(const char* dir_path) {
    // O_NONBLOCK is inert on a directory open (only a FIFO/device open can
    // block) but is included unconditionally per the "no open in this block
    // without O_NONBLOCK" rule below, so every open/openat call site is
    // uniform and the lexical gate has no exception to special-case.
    //
    // O_NOFOLLOW refuses a symlinked root, matching confined_fs.hpp's
    // open_root contract: without it, a swapped /etc/ssl/certs would be
    // silently followed before the held-dirfd protection above ever
    // engages. A symlink root fails ELOOP, which classify_cert_dir_open
    // folds into kUnreadable like any other open failure.
    int fd = ::open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    int err = fd < 0 ? errno : 0;
    return CertDir{yuzu::agent::ScopedFd(fd), classify_cert_dir_open(fd >= 0, err), err};
}

/// RAII owner for a DIR* opened via fdopendir -- closedir must run on every
/// exit from for_each_cert_entry below, including a THROWING one (peer
/// review: `std::string{name}` can throw bad_alloc, and on_name goes on to
/// call parse_pem_certs / std::string allocation / ctx.write_output; a bare
/// `::closedir(d)` at the bottom of the loop never runs if any of that
/// throws, leaking the directory stream and its descriptor).
struct ScopedDir {
    DIR* d = nullptr;
    ScopedDir() = default;
    explicit ScopedDir(DIR* dir) : d(dir) {}
    ScopedDir(const ScopedDir&) = delete;
    ScopedDir& operator=(const ScopedDir&) = delete;
    ~ScopedDir() {
        if (d)
            ::closedir(d);
    }
};

/// Enumerates `dirfd` THROUGH THE HELD DESCRIPTOR, never by pathname (peer
/// review F4: `directory_iterator("/etc/ssl/certs")` opens the path a SECOND
/// time, which would defeat the whole held-dirfd design -- a directory
/// swapped between the two opens would be enumerated in one directory and
/// read/unlinked in another). `fdopendir` takes ownership of the fd it is
/// given, so this dups first to keep `dirfd` (owned by the caller's CertDir)
/// alive for the openat/fstatat/unlinkat calls each `on_name` invocation
/// goes on to make. Returns false on a dup/fdopendir failure OR a readdir
/// failure mid-enumeration (peer review F5: an errno-bearing nullptr must
/// not look like a clean end-of-directory) -- callers treat false exactly
/// like CertDirOpen::kUnreadable: the scan cannot be trusted as complete.
/// `out_errno`, when given, receives the errno of whichever failure caused
/// the false return, so callers can report WHY the scan didn't complete,
/// not just that it didn't.
template <typename OnName>
[[nodiscard]] bool for_each_cert_entry(int dirfd, OnName&& on_name, int* out_errno = nullptr,
                         const StoreSyscalls& sys = {}) {
    int dup_fd = ::dup(dirfd);
    if (dup_fd < 0) {
        if (out_errno)
            *out_errno = errno;
        return false;
    }
    DIR* raw = ::fdopendir(dup_fd);
    if (!raw) {
        if (out_errno)
            *out_errno = errno;
        ::close(dup_fd);
        return false;
    }
    ScopedDir d(raw);
    bool complete = true;
    for (;;) {
        errno = 0;
        dirent* e = sys.readdir(d.d);
        if (!e) {
            complete = (errno == 0);
            if (!complete && out_errno)
                *out_errno = errno;
            break;
        }
        std::string_view name{e->d_name};
        if (name == "." || name == "..")
            continue;
        if (!is_cert_entry_name(name))
            continue;
        on_name(std::string{name});
    }
    return complete;
}

/// Result of reading one directory entry as a candidate certificate.
struct CertEntryRead {
    std::optional<yuzu::certificates_x509::CertFields> cert;
    CertEntryOpen state;
    std::optional<CertEntryIdentity> identity;
};

/// Opens and parses ONE cert-store entry, dirfd-relative throughout. O_NONBLOCK
/// is LOAD-BEARING on every open/openat here (peer review F1): open(2) of a
/// FIFO with no writer blocks forever, and the S_ISREG check below cannot run
/// until open returns, so a blocking open would let a crafted FIFO wedge a
/// worker before the type filter ever gets a chance to reject it. Once fstat
/// proves S_ISREG the flag is inert (POSIX: reads of a regular file never
/// block), so no fcntl clear is needed afterward.
[[nodiscard]] inline CertEntryRead read_cert_entry(int dirfd, const std::string& name,
                                     const StoreSyscalls& sys = {}) {
    CertEntryRead result;

    int fd = ::openat(dirfd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int err = fd < 0 ? errno : 0;
    result.state = classify_cert_entry_open(fd >= 0, err);
    yuzu::agent::ScopedFd parse_fd(fd);

    std::string link_target;
    if (result.state == CertEntryOpen::kSymlink) {
        // ELOOP from the O_NOFOLLOW open above -- this entry is a symlink.
        // Resolve the link text, then open the TARGET read-only for parsing
        // only (never for the eventual unlink, which always acts on the
        // link's own name via unlinkat).
        //
        // This string-resolved read-only target open is the SELECTION-only
        // exception confined_fs.hpp's banner records: SELECTION and
        // ACCOUNTING stay best-effort against a writer controlling the
        // parent dir, and are never restated as absolute, while confinement
        // itself -- unlinkat by name on the held dirfd, below in
        // delete_matching_cert -- is what stays absolute. The pre-unlink
        // identity recheck (also delete_matching_cert) NARROWS the
        // recheck-to-unlink window this open is part of; it does not close
        // it.
        char buf[PATH_MAX];
        ssize_t n = sys.readlinkat(dirfd, name.c_str(), buf, sizeof(buf));
        if (n < 0) {
            result.state = CertEntryOpen::kUnreadable;
            return result;
        }
        link_target.assign(buf, static_cast<std::size_t>(n));

        int target_fd = !link_target.empty() && link_target.front() == '/'
                            ? ::open(link_target.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)
                            : ::openat(dirfd, link_target.c_str(),
                                       O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        int target_err = target_fd < 0 ? errno : 0;
        if (target_fd < 0) {
            // A dangling link (target removed) is not a read failure -- it is
            // simply not a certificate right now; skip it silently like any
            // other vanished entry. Anything else is a genuine read failure.
            result.state = (target_err == ENOENT) ? CertEntryOpen::kVanished
                                                    : CertEntryOpen::kUnreadable;
            return result;
        }
        parse_fd.reset(target_fd);
    } else if (result.state != CertEntryOpen::kOpened) {
        return result; // kVanished / kUnreadable: nothing left to read
    }

    // Applied AFTER the (nonblocking) open, so a FIFO/device/socket cannot be
    // bypassed by racing a blocking open ahead of this check -- today's
    // is_regular_file filter, now unconditionally enforced on the parse fd.
    struct stat st {};
    if (::fstat(parse_fd.get(), &st) != 0) {
        // fstat failing on an fd this function just successfully opened is
        // a genuine I/O error, not "this entry doesn't exist" -- conflating
        // the two (peer review) would let a transient fstat failure on the
        // actual delete/details target silently present as kVanished
        // (skipped, scan_complete stays true) and reach a false
        // status|not_found instead of an honest unreadable/partial signal.
        result.state = CertEntryOpen::kUnreadable;
        return result;
    }
    if (!S_ISREG(st.st_mode)) {
        // A FIFO, device, socket or directory successfully IDENTIFIED as
        // such is not a read failure -- it is simply not a certificate;
        // skip it silently like any other non-candidate entry.
        result.state = CertEntryOpen::kVanished;
        return result;
    }

    // Identity capture. For a symlink this binds BOTH the link's own inode
    // (fstatat AT_SYMLINK_NOFOLLOW, so the link is not followed here) AND the
    // resolved target's inode (capture_identity of the fd that actually did
    // the parse) -- peer review F2: a link whose text is unchanged but whose
    // target was rename-replaced underneath it must be detectable, and text
    // alone cannot see that. A regular entry's identity is just its own
    // parsed fd. Any capture failure leaves identity nullopt, which
    // classify_delete_recheck (certificates_macos_parsers.hpp) treats as
    // kUnknown -- fail closed, never unlink on missing identity.
    if (result.state == CertEntryOpen::kOpened) {
        if (auto id = yuzu::agent::confined_fs::capture_identity(parse_fd.get())) {
            result.identity = CertEntryIdentity{false, id->dev, id->ino, "", 0, 0};
        }
    } else {
        struct stat link_st {};
        if (sys.fstatat(dirfd, name.c_str(), &link_st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (auto target_id = yuzu::agent::confined_fs::capture_identity(parse_fd.get())) {
                result.identity =
                    CertEntryIdentity{true, static_cast<std::uint64_t>(link_st.st_dev),
                                      static_cast<std::uint64_t>(link_st.st_ino), link_target,
                                      target_id->dev, target_id->ino};
            }
        }
    }

    std::string contents;
    char rbuf[65536];
    for (;;) {
        ssize_t n = ::read(parse_fd.get(), rbuf, sizeof(rbuf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            result.state = CertEntryOpen::kUnreadable;
            return result;
        }
        if (n == 0)
            break;
        contents.append(rbuf, static_cast<std::size_t>(n));
    }

    auto certs = yuzu::certificates_x509::parse_pem_certs(contents);
    if (!certs.empty())
        result.cert = std::move(certs.front());
    return result;
}

/// Outcome of scanning the store for the entry matching `canonical_needle`
/// and, when found, attempting to delete it.
enum class DeleteScanKind {
    kDeleted,
    kUnlinkFailed,
    kChanged,
    kUnverifiable,
    kNotFound,
    kUnreadableEntries,
    kEnumerationFailed,
};

/// Result of delete_matching_cert. `entry` is always set to the matched
/// directory entry's name when a match occurred (empty otherwise).
/// `enumeration_failed`/`enum_err`/`unreadable_entries` are recorded
/// alongside whatever `kind` a match already decided -- a readdir failure on
/// entries scanned AFTER a match cannot undo a mutation (or a definitive
/// non-mutation) that already happened, so `kind` is NEVER overridden by
/// them once a match occurred.
struct DeleteScan {
    DeleteScanKind kind;
    std::string entry;
    int unlink_err = 0;
    unsigned unreadable_entries = 0;
    bool enumeration_failed = false;
    int enum_err = 0;
};

/// Deletes the certificate matching `canonical_needle` (already
/// canonical_thumbprint-normalized) from the directory held open at `dirfd`.
///
/// A symlinked entry: the LINK is removed (untrusted), never the target --
/// unlinkat(dirfd, name, 0) always acts on the entry's own name, and this
/// code never opens or resolves the target for anything other than parsing.
/// The identity that must match binds the link's own inode, the target
/// TEXT, and the target's resolved INODE (capture_identity of the parse fd),
/// so a link retargeted to a different path, or rename-over-replaced at the
/// SAME path text, is refused by classify_delete_recheck (kChanged). An
/// in-place rewrite of the same target inode (open+truncate+write, no
/// rename) is NOT detectable this way -- the decision is identity-bound, not
/// content-bound, and that is a deliberate, documented limit, not a gap.
///
/// The residual fstatat-then-unlinkat window (POSIX has no unlink-by-fd) is
/// narrowed to the identity-verified microseconds between the two calls, but
/// not closed. That window is narrower still than it first looks: for a
/// symlink entry, the recheck itself is three non-atomic syscalls
/// (fstatat(NOFOLLOW) for the link's own identity, readlinkat for its text,
/// fstatat(follow) for the target's identity), so a content-preserving
/// swap timed strictly between the first and the other two can in principle
/// glue a stale own-inode to fresh text/target that still happens to equal
/// at_match -- governance Gate 4 (UP-1) traced this and found it bounded:
/// the replacement must preserve both link text and target identity to pass
/// at all, so the entry actually removed is semantically equivalent to the
/// one matched: no wrong-file deletion results. confined_fs_posix.cpp:348-366 documents a STRONGER mitigation
/// for its own (different) delete-with-byte-cap problem -- capture-then-
/// measure: renameat the entry to an unpredictable name, then measure and
/// unlink THAT name -- and that comment is explicit that even THAT only
/// narrows the window further, it does not close it either. This function
/// deliberately does NOT adopt that rename step: /etc/ssl/certs is the
/// host's live trust store, and renaming an entry there before unlinking it
/// has its own hazards a staging/quarantine directory doesn't -- a renamed
/// entry keeping its .pem/.crt suffix would still be trusted under the new
/// name, one without the suffix would be silently untrusted before this
/// function ever verifies it, a crash between rename and unlink would leave
/// renamed residue sitting in a security-relevant directory, and a rename-
/// back on a failed recheck is itself just as racy as the original problem.
/// fstatat-then-unlinkat with full identity verification is the WEAKER but
/// side-effect-free sequence, and is chosen here for exactly that reason.
[[nodiscard]] inline DeleteScan delete_matching_cert(int dirfd, std::string_view canonical_needle,
                                       const StoreSyscalls& sys = {}) {
    DeleteScan scan{DeleteScanKind::kNotFound, {}};
    bool matched = false;
    unsigned unreadable = 0;
    int enum_err = 0;
    bool dir_complete = for_each_cert_entry(
        dirfd,
        [&](const std::string& name) {
            if (matched)
                return;
            // parity: only the entry's FIRST certificate is a delete target
            // -- see the guard comment above read_cert_entry.
            auto read = read_cert_entry(dirfd, name, sys);
            if (read.state == CertEntryOpen::kVanished)
                return;
            if (read.state == CertEntryOpen::kUnreadable || !read.cert) {
                // An unreadable entry here means this scan cannot prove the
                // target is absent (consistency-auditor Gate-4 BLOCKING
                // finding) -- the shell surfaces this via
                // mark_result_partial when no match is found.
                ++unreadable;
                return;
            }
            if (canonical_thumbprint(read.cert->thumbprint) != canonical_needle)
                return;

            matched = true;
            scan.entry = name;

            // Re-check identity immediately before unlink -- #3245's TOCTOU
            // close. Re-derived independently of `read.identity` (captured
            // at match time above) rather than reused, so this genuinely
            // observes the entry's CURRENT state.
            struct stat st {};
            std::optional<CertEntryIdentity> at_unlink;
            if (sys.fstatat(dirfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
                if (S_ISLNK(st.st_mode)) {
                    char buf[PATH_MAX];
                    ssize_t n = sys.readlinkat(dirfd, name.c_str(), buf, sizeof(buf));
                    struct stat target_st {};
                    if (n >= 0 && sys.fstatat(dirfd, name.c_str(), &target_st, 0) == 0) {
                        at_unlink = CertEntryIdentity{
                            true, static_cast<std::uint64_t>(st.st_dev),
                            static_cast<std::uint64_t>(st.st_ino),
                            std::string(buf, static_cast<std::size_t>(n)),
                            static_cast<std::uint64_t>(target_st.st_dev),
                            static_cast<std::uint64_t>(target_st.st_ino)};
                    }
                } else if (S_ISREG(st.st_mode)) {
                    at_unlink = CertEntryIdentity{false, static_cast<std::uint64_t>(st.st_dev),
                                                  static_cast<std::uint64_t>(st.st_ino), "", 0, 0};
                }
                // Anything else (removed, or replaced by a non-reg/non-link
                // type): at_unlink stays nullopt.
            }

            switch (classify_delete_recheck(read.identity, at_unlink)) {
            case DeleteRecheck::kProceed:
                if (sys.unlinkat(dirfd, name.c_str(), 0) == 0) {
                    scan.kind = DeleteScanKind::kDeleted;
                } else {
                    scan.unlink_err = errno;
                    scan.kind = DeleteScanKind::kUnlinkFailed;
                }
                break;
            case DeleteRecheck::kChanged:
                scan.kind = DeleteScanKind::kChanged;
                break;
            case DeleteRecheck::kUnknown:
                scan.kind = DeleteScanKind::kUnverifiable;
                break;
            }
        },
        &enum_err, sys);

    scan.unreadable_entries = unreadable;
    if (!dir_complete) {
        scan.enumeration_failed = true;
        scan.enum_err = enum_err;
    }
    // A match already decided `scan.kind` above (deleted / unlink_failed /
    // changed / unverifiable) -- a readdir failure on entries scanned AFTER
    // that match cannot undo a mutation (or a definitive non-mutation) that
    // already happened, so `kind` is never re-derived once matched=true; the
    // enumeration/unreadable fields above still carry the extra signal.
    if (!matched) {
        if (scan.enumeration_failed)
            scan.kind = DeleteScanKind::kEnumerationFailed;
        else if (scan.unreadable_entries > 0)
            scan.kind = DeleteScanKind::kUnreadableEntries;
        else
            scan.kind = DeleteScanKind::kNotFound;
    }
    return scan;
}

} // namespace yuzu::certificates_linux

#endif // !defined(_WIN32)
