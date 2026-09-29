/**
 * filesystem_posture_macos.cpp -- macOS leg: mounts (getmntinfo/statfs),
 * volume-level quotas (getattrlist), snapshot enumeration (fs_snapshot_list).
 * One TU, entirely #if defined(__APPLE__); defines the three emit_* entry
 * points declared in filesystem_posture_legs.hpp. The only leg
 * runtime-verifiable on this build host -- the W6P-14 spike settled all
 * three mechanisms below; do not re-open them.
 *
 * Three traps this file guards against:
 *  1. ATTR_BULK_REQUIRED (= ATTR_CMN_NAME | ATTR_CMN_RETURNED_ATTRS,
 *     $(xcrun --show-sdk-path)/usr/include/sys/attr.h:591) is REQUIRED in
 *     commonattr for fs_snapshot_list -- omitting it is the documented trap
 *     that yields an empty/garbage result with no error.
 *  2. fs_snapshot_list's fd MUST be a volume ROOT: a non-root directory
 *     (e.g. /Users) returns EINVAL. Walk getmntinfo's mount points, never an
 *     arbitrary path.
 *  3. The getattrlist volume-quota reply struct MUST be declared
 *     `__attribute__((aligned(4), packed))`. The plain (unpacked) struct is
 *     sizeof 24 (4 bytes of tail padding after the uint32 len), but the
 *     kernel packs its reply at 4-byte alignment for a true size of 20 --
 *     reading the unpacked layout silently pulls quota/reserved from the
 *     wrong offset. Verified by compilation on this host 2026-09-02.
 *
 * getmntinfo(3) returns a process-wide STATIC buffer and is documented
 * not-thread-safe; every call below goes through snapshot_mounts(), which
 * serializes the call behind a mutex and copies the array out before
 * releasing the lock. The libc-owned buffer itself is never released (the
 * thread-safe alternative, getmntinfo_r_np, would require the caller to
 * release its caller-owned result -- serializing plain getmntinfo avoids
 * that entirely).
 *
 * Volume-lineage duplication note: a single APFS volume can appear at
 * multiple mount points (e.g. `/` and `/System/Volumes/Update/mnt1` are the
 * same disk3s1 lineage) and fs_snapshot_list on each reports the SAME
 * snapshot names. Rows are keyed by mount point -- this file does NOT
 * deduplicate across mounts or union into a global list; every APFS mount
 * point gets its own independently-enumerated row set.
 */
#if defined(__APPLE__)

#include "filesystem_posture_legs.hpp"

#include <yuzu/agent/scoped_fd.hpp>

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/snapshot.h>
#include <unistd.h> // getattrlist() is declared here (unistd.h:763/771), NOT sys/attr.h
#include <fcntl.h>

#include <cerrno>
#include <cstring>
#include <cstdint>
#include <limits>
#include <mutex>
#include <span>
#include <string> // std::string -- denied_detail; previously transitive
#include <vector>

namespace yuzu::filesystem_posture {

namespace {

// getmntinfo(3) writes to a static per-process buffer and is NOT
// thread-safe; every entry point below calls getmntinfo on a bounded
// dispatch-pool thread, so serialize the call and copy the array out while
// still holding the lock -- no caller ever sees a bare pointer into the
// shared static buffer.
struct MntSnapshot {
    std::vector<struct statfs> entries;
    bool ok = false;
    int err = 0;
};

MntSnapshot snapshot_mounts() {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);

    struct statfs* mnt = nullptr;
    const int n = ::getmntinfo(&mnt, MNT_NOWAIT); // MNT_NOWAIT: return the kernel's
                                                   // cached statfs, never block on a
                                                   // wedged remote mount.
    MntSnapshot out;
    if (n <= 0) {
        out.err = errno;
        return out;
    }
    out.entries.assign(mnt, mnt + n); // copy under the lock; mnt is libc-owned,
                                      // never freed.
    out.ok = true;
    return out;
}

std::string flags_from_statfs(std::uint32_t f_flags) {
    // Fixed vocabulary, fixed order: ro/rw, nosuid, nodev, noexec, noatime.
    std::string out;
    auto add = [&](const char* name) {
        if (!out.empty())
            out += ',';
        out += name;
    };
    add((f_flags & MNT_RDONLY) ? "ro" : "rw");
    if (f_flags & MNT_NOSUID)
        add("nosuid");
    if (f_flags & MNT_NODEV)
        add("nodev");
    if (f_flags & MNT_NOEXEC)
        add("noexec");
    if (f_flags & MNT_NOATIME)
        add("noatime");
    return out;
}

// Overflow guard on the block-count * block-size products (PKG-LINUX parity
// -- the rule should not differ by leg): f_blocks/f_bfree/f_bavail are
// already unsigned 64-bit on this ABI, but f_bsize is attacker/FS-controlled
// on a hostile or corrupt mount, so clamp instead of wrapping silently.
unsigned long long checked_block_bytes(std::uint64_t blocks, std::uint32_t block_size) {
    constexpr unsigned long long kMax = std::numeric_limits<unsigned long long>::max();
    const auto b = static_cast<unsigned long long>(blocks);
    const auto sz = static_cast<unsigned long long>(block_size);
    if (b != 0 && sz > kMax / b)
        return kMax;
    return b * sz;
}

bool is_quota_capable_fstype(std::string_view fstype) {
    return fstype == "apfs" || fstype == "hfs";
}

constexpr std::string_view kQuotaDetail =
    "volume-level only; per-user/group quotas are unsupported on APFS (quotactl "
    "returns ENOTSUP on every APFS mount, though it succeeds on HFS+)";

// The kernel's getattrlist volume-quota reply is packed at 4-byte alignment
// (total 20 bytes: uint32 len + off_t quota + off_t reserved). The plain
// struct is sizeof 24 (4 bytes of padding inserted after `len` to align the
// following off_t) -- declaring this WITHOUT `packed` silently misreads
// quota/reserved from the wrong offset (peer H5).
struct __attribute__((aligned(4), packed)) VolQuotaReply {
    u_int32_t len;
    off_t quota;
    off_t reserved;
};
static_assert(sizeof(VolQuotaReply) == 20, "getattrlist reply must match the kernel's packed layout");

} // namespace

int emit_mounts(yuzu::CommandContext& ctx) {
    const MntSnapshot snap = snapshot_mounts();
    if (!snap.ok) {
        mark_result_partial(ctx, "macos:getmntinfo", std::strerror(snap.err));
        return 0;
    }

    for (const struct statfs& s : snap.entries) {
        const unsigned long long total = checked_block_bytes(s.f_blocks, s.f_bsize);
        const unsigned long long free_bytes = checked_block_bytes(s.f_bfree, s.f_bsize);
        const unsigned long long avail = checked_block_bytes(s.f_bavail, s.f_bsize);
        write_mount_row(ctx, s.f_mntonname, s.f_mntfromname, s.f_fstypename, "-", total, free_bytes,
                        avail, flags_from_statfs(s.f_flags));
    }
    return 0;
}

int emit_quotas(yuzu::CommandContext& ctx) {
    const MntSnapshot snap = snapshot_mounts();
    if (!snap.ok) {
        mark_result_partial(ctx, "macos:getmntinfo", std::strerror(snap.err));
        return 0;
    }

    // UP-3/CA-2: recorded in the loop, reported after it, so a denial cannot be
    // overwritten by a later mount's generic degradation.
    bool any_permission_denied = false;
    std::string denied_detail;

    for (const struct statfs& s : snap.entries) {
        if (!is_quota_capable_fstype(s.f_fstypename)) {
            // Leg-level fstype decision, deliberately outside the classifier:
            // a non-apfs/non-hfs mount is reported unsupported without the
            // syscall.
            write_quota_row(ctx, s.f_mntonname, QuotaState::UnsupportedFs, std::nullopt,
                            std::nullopt, kQuotaDetail);
            continue;
        }

        struct attrlist al{};
        al.bitmapcount = ATTR_BIT_MAP_COUNT;
        // ATTR_VOL_INFO is REQUIRED alongside any other volattr bit
        // (sys/attr.h:509-510 -- ATTR_VOL_QUOTA_SIZE / ATTR_VOL_RESERVED_SIZE).
        al.volattr = ATTR_VOL_INFO | ATTR_VOL_QUOTA_SIZE | ATTR_VOL_RESERVED_SIZE;

        VolQuotaReply reply{};
        const int rc = ::getattrlist(s.f_mntonname, &al, &reply, sizeof reply, FSOPT_NOFOLLOW);
        const int err = errno;

        if (rc == 0 && reply.len != sizeof(VolQuotaReply)) {
            // Never trust the fields when the kernel's reply length doesn't
            // match the packed layout we asked for (peer H5).
            mark_result_partial(ctx, "macos:getattrlist", "unexpected attr reply length");
            write_quota_row(ctx, s.f_mntonname, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            kQuotaDetail);
            continue;
        }

        const unsigned long long quota_size =
            rc == 0 ? static_cast<unsigned long long>(reply.quota) : 0;
        const unsigned long long reserved_size =
            rc == 0 ? static_cast<unsigned long long>(reply.reserved) : 0;
        const QuotaState state = classify_getattrlist_quota(rc, err, quota_size, reserved_size);

        // CDX-P2-04: the row alone is not enough. set_result_status defaults to
        // UNDECLARED, from which the agent derives coarse SUCCESS -- so a
        // permission-denied or unavailable probe would otherwise be reported as
        // a clean run. UnsupportedFs is NOT a degradation: it is a truthful,
        // complete answer for a filesystem that has no volume quotas.
        // CP-1 (Gate 3, cross-platform): classify_getattrlist_quota has already
        // distinguished a denial (EPERM/EACCES) from a generic unavailability,
        // so the reported STATUS distinguishes them too rather than collapsing
        // both to CONSTRAINED.
        //
        // UP-3/CA-2 (Gate 4, raised independently by unhappy-path and
        // consistency-auditor): set_result_status ASSIGNS, so marking a denial
        // HERE let a later mount's generic partial overwrite it and the leg
        // discarded a cause it had already established. The denial is recorded
        // and re-reported once after the walk, matching the end-of-run summary
        // shape the Linux and Windows legs already use.
        if (state == QuotaState::PermissionDenied) {
            if (!any_permission_denied) {
                any_permission_denied = true;
                denied_detail = std::string(s.f_mntonname) + ": " + std::strerror(err);
            }
            mark_result_partial(ctx, "macos:getattrlist",
                                std::string(s.f_mntonname) + ": " + std::strerror(err));
        } else if (state == QuotaState::Unavailable) {
            mark_result_partial(ctx, "macos:getattrlist",
                                std::string(s.f_mntonname) + ": " + std::strerror(err));
        }

        write_quota_row(ctx, s.f_mntonname, state,
                        state == QuotaState::Configured
                            ? std::optional<unsigned long long>(quota_size)
                            : std::nullopt,
                        state == QuotaState::Configured
                            ? std::optional<unsigned long long>(reserved_size)
                            : std::nullopt,
                        kQuotaDetail);
    }

    // Reported LAST so it survives set_result_status's last-writer-wins
    // assignment. A mixed walk that saw a real denial reports the denial:
    // that is the one cause an operator can act on.
    if (any_permission_denied)
        mark_result_denied(ctx, "macos:getattrlist", denied_detail);

    return 0;
}

int emit_snapshots(yuzu::CommandContext& ctx) {
    const MntSnapshot snap = snapshot_mounts();
    if (!snap.ok) {
        mark_result_partial(ctx, "macos:getmntinfo", std::strerror(snap.err));
        return 0;
    }

    bool any_row = false;
    bool any_failure = false;
    bool any_success = false; // a probe that returned cleanly, names or not
    // UP-3/CA-2: same deferral as emit_quotas above.
    bool any_permission_denied = false;
    std::string denied_detail;

    for (const struct statfs& s : snap.entries) {
        if (std::string_view(s.f_fstypename) != "apfs")
            continue;

        // fs_snapshot_list's fd MUST be a volume ROOT -- a subdirectory
        // (e.g. /Users) returns EINVAL. getmntinfo's mount points are always
        // volume roots, so this is safe by construction.
        yuzu::agent::ScopedFd fd(::open(s.f_mntonname, O_RDONLY));
        if (!fd) {
            const int open_err = errno; // capture before anything else can clobber it
            any_failure = true;
            // CP-1 (Gate 3): EACCES/EPERM on the volume root is a privilege
            // denial and is reported as one; every other errno stays a generic
            // degradation, because guessing a cause from an unrelated errno is
            // exactly the over-attribution Gate 2 flagged elsewhere.
            const std::string detail =
                std::string(s.f_mntonname) + ": " + std::strerror(open_err);
            if (open_err == EACCES || open_err == EPERM) {
                if (!any_permission_denied) {
                    any_permission_denied = true;
                    denied_detail = detail;
                }
            }
            mark_result_partial(ctx, "macos:fs_snapshot_list", detail);
            continue;
        }

        struct attrlist al{};
        al.bitmapcount = ATTR_BIT_MAP_COUNT;
        al.commonattr = ATTR_BULK_REQUIRED; // ATTR_CMN_NAME | ATTR_CMN_RETURNED_ATTRS;
                                            // omitting this is the documented trap.

        std::vector<std::byte> buf(64 * 1024);
        int rc = ::fs_snapshot_list(fd.get(), &al, buf.data(), buf.size(), 0);
        if (rc < 0 && errno == ERANGE) {
            buf.assign(1024 * 1024, std::byte{0});
            rc = ::fs_snapshot_list(fd.get(), &al, buf.data(), buf.size(), 0);
        }
        if (rc < 0) {
            any_failure = true;
            mark_result_partial(ctx, "macos:fs_snapshot_list",
                                std::string(s.f_mntonname) + ": " + std::strerror(errno));
            continue;
        }

        const auto parsed =
            parse_fs_snapshot_list_buffer(std::span<const std::byte>(buf.data(), buf.size()), rc);
        for (const auto& name : parsed.names) {
            write_snapshot_row(ctx, s.f_mntonname, name, "apfs", "-");
            any_row = true;
        }
        // BRACES ARE LOAD-BEARING. Without them only the assignment is
        // guarded and mark_result_partial runs on EVERY successfully-probed
        // mount, so a healthy host permanently reports CONSTRAINED/PARTIAL
        // with a fabricated "malformed reply buffer" provenance -- which
        // makes real degradation indistinguishable from the constant noise.
        // Apple Clang catches exactly this with -Wmisleading-indentation.
        if (parsed.malformed) {
            any_failure = true;
            mark_result_partial(ctx, "macos:fs_snapshot_list",
                                std::string(s.f_mntonname) + ": malformed reply buffer");
            // SG-2/K10: the 1024-name cap was silently ignored here. The
            // unbraced-if defect above was accidentally masking it by marking
            // EVERY run partial; fixing that unmasked a genuine silent
            // truncation. The Windows leg has always handled this flag.
        } else if (parsed.truncated) {
            any_failure = true;
            mark_result_partial(ctx, "macos:fs_snapshot_list",
                                std::string(s.f_mntonname) + ": snapshot list truncated at the "
                                                             "1024-entry cap");
        } else {
            // A probe that returned cleanly is a SUCCESS even when it yielded
            // no names: "this volume has no snapshots" is an answer, not a
            // failure. Tracked separately from any_row so the summary below
            // can tell "none anywhere" from "some volumes failed".
            any_success = true;
        }
    }

    // Rows are keyed by mount point and never deduplicated/unioned across
    // mounts (see the file-header volume-lineage note); the "no snapshots
    // anywhere" fallback below is a single global row, distinct from that
    // per-mount behavior, and only fires when literally no APFS mount
    // yielded a name.
    // BR-001: "no snapshots" and "every enumeration failed" are different
    // facts and must not share one row. any_failure is set wherever a probe
    // errored above; matching the Windows leg's failure-vs-empty contract.
    if (!any_row) {
        if (any_failure && !any_success) {
            write_snapshot_row(ctx, "-", "-", "none",
                               "APFS snapshot enumeration failed on every volume");
        } else if (any_failure) {
            // Mixed: some volumes answered cleanly with no snapshots, others
            // failed. Claiming "every volume" would be false (CDX-P2-10).
            write_snapshot_row(ctx, "-", "-", "none",
                               "no APFS snapshots present on the volumes that could be "
                               "read; enumeration failed on at least one other volume");
        } else {
            write_snapshot_row(ctx, "-", "-", "none", "no APFS snapshots present");
        }
    }

    // Reported LAST, for the same last-writer-wins reason as emit_quotas.
    if (any_permission_denied)
        mark_result_denied(ctx, "macos:fs_snapshot_list", denied_detail);

    return 0;
}

} // namespace yuzu::filesystem_posture

#endif // defined(__APPLE__)
