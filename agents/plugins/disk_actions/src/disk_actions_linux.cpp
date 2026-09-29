/**
 * disk_actions_linux.cpp — Linux leg entry points.
 *
 * DELIBERATELY UNIMPLEMENTED, and this file exists to make that honest rather
 * than silent.
 *
 * The `smart` mechanism could not be BOUND. The Wave 6 design's rule is that a
 * leg resolves to a named mechanism and a support level before it is authored,
 * or the objective narrows; the spike on 2026-09-03 could reach no Linux host
 * with real storage — WSL2 exposes four `Virtual Disk` SCSI nodes, no
 * `/dev/nvme*` character devices, and no `smartctl`. Writing an
 * `NVME_IOCTL_ADMIN_CMD` get-log-page path from the kernel documentation and
 * shipping it compile-verified-only is precisely how this plugin's sibling
 * shipped a Windows snapshots leg that had been compiled out entirely and did
 * nothing on every host, through a clean compile and a green suite.
 *
 * So the leg reports UNSUPPORTED and says why. `volumes` follows it: the
 * physical-to-logical join is only meaningful next to a working health read,
 * and shipping half of a pair invites a consumer to build on the half that is
 * there.
 *
 * What a future implementation should bind, on real hardware:
 *   - NVMe: ioctl(fd, NVME_IOCTL_ADMIN_CMD) with opcode 0x02 (Get Log Page),
 *     log identifier 0x02 (SMART / Health Information) -- the same 512-byte
 *     structure the Windows leg already decodes, so the parser is shareable.
 *   - SATA/SAS: SG_IO ATA PASS-THROUGH (12/16), which needs CAP_SYS_RAWIO --
 *     measure whether the unprivileged agent account can issue it before
 *     declaring a support level, exactly as the Windows leg's zero-access-rights
 *     handle was measured rather than assumed.
 *   - The physical-to-logical join is the cheap half: /sys/block/<dev>/<part>
 *     plus /proc/self/mountinfo needs no privilege at all.
 */

#if defined(__linux__)

#include "disk_actions_legs.hpp"

namespace yuzu::disk_actions {

namespace {

/// One honest row plus a typed status. The row matters: a consumer that reads
/// rows and never inspects the status must still see something that cannot be
/// mistaken for "this host has no drives".
void emit_unsupported(yuzu::CommandContext& ctx, std::string_view provenance,
                      std::string_view detail) {
    // UNAVAILABLE, not CONSTRAINED: this leg produces no data at all, and
    // "partial data" would be a false description of that (spec-axis F5).
    mark_result_unavailable(ctx, provenance, detail);
}

} // namespace

int emit_smart(yuzu::CommandContext& ctx) {
    write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unsupported, std::nullopt,
                    std::nullopt,
                    "drive health is not implemented on Linux in this release; no mechanism was "
                    "bound against real hardware");
    emit_unsupported(ctx, "linux:smart",
                     "no mechanism bound -- see the descriptor fallback prose");
    return 0;
}

int emit_volumes(yuzu::CommandContext& ctx) {
    write_volume_row(ctx, "-", "-", "-", "-", std::nullopt,
                     "physical-to-logical volume mapping is not implemented on Linux in this "
                     "release; it ships with the smart leg it exists to support");
    emit_unsupported(ctx, "linux:volumes",
                     "not implemented -- see the descriptor fallback prose");
    return 0;
}

} // namespace yuzu::disk_actions

#endif // defined(__linux__)
