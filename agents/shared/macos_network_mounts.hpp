// macos_network_mounts.hpp -- the macOS network-mount snapshot, shared by every leg that must not
// open a directory on a mount whose server may be down (remote_access_audit, runtimes).
//
// The table is getmntinfo_r_np(MNT_NOWAIT): the kernel's cache, answered without a call into any
// server, unprivileged. A mount whose filesystem type is a network one
// (yuzu::shared::is_network_mount_fstype, network_fstype.hpp) is reported by its mount-on path.
// The system lists a mount it creates under the Data volume (autofs `/home` can appear as
// `/System/Volumes/Data/home`), while a walk compares the logical root-relative path, so that
// spelling is reported with the volume prefix stripped as well; the extra entry only ever widens
// the guard.
//
// `macos_network_mount_points` is the filter over a table the caller already holds (the unit test
// fills a `statfs` array by hand); `read_macos_network_mounts` is the one OS call. A table that
// reads zero entries is a failed read, not an empty host (the root mount is always listed), so it
// answers nullopt. Residuals the snapshot cannot close: a mount that appears after it, a stacked
// filesystem over a dead network mount, a network type the deny-list does not name.
//
// Apple only: `f_fstypename` / `f_mntonname` are BSD `statfs` members. Header-only, no state.
#pragma once

#if defined(__APPLE__)

#include <network_fstype.hpp>

#include <sys/mount.h>
#include <sys/param.h>

#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::shared {

/// Mount-on paths of the network-typed entries of `table[0..n)`, plus the Data-volume firmlink
/// spelling of any that live under /System/Volumes/Data.
[[nodiscard]] inline std::vector<std::string> macos_network_mount_points(const struct statfs* table,
                                                                         int n) {
    constexpr std::string_view kDataVolume = "/System/Volumes/Data";
    std::vector<std::string> out;
    for (int i = 0; i < n; ++i) {
        if (!is_network_mount_fstype(table[i].f_fstypename)) continue;
        const std::string_view on{table[i].f_mntonname};
        out.emplace_back(on);
        if (on.size() > kDataVolume.size() + 1 && on.substr(0, kDataVolume.size()) == kDataVolume &&
            on[kDataVolume.size()] == '/')
            out.emplace_back(on.substr(kDataVolume.size()));
    }
    return out;
}

/// The live snapshot; nullopt when the table could not be read.
[[nodiscard]] inline std::optional<std::vector<std::string>> read_macos_network_mounts() {
    struct statfs* raw = nullptr;
    const int n = ::getmntinfo_r_np(&raw, MNT_NOWAIT);
    const std::unique_ptr<struct statfs, decltype(&::free)> mnt{raw, &::free};
    if (n <= 0 || raw == nullptr) return std::nullopt;
    return macos_network_mount_points(mnt.get(), n);
}

} // namespace yuzu::shared

#endif // defined(__APPLE__)
