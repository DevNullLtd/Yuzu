// macos_user_home_entry.hpp -- the pure rule for which /Users entry is a real per-user home,
// shared by its two users: privacy_permissions (which re-exports it) and pkg_inventory. The
// autoruns and remote_access_audit legs keep their own copy of the rule.
//
// Pure constexpr, no OS call and no OS header (so it is not __APPLE__-gated and unit-tests on
// every host). The caller does the I/O: an fstatat with AT_SYMLINK_NOFOLLOW supplies
// `is_directory` and `uid`, so a symlink is never a home.
#pragma once

#include <cstdint>
#include <string_view>

namespace yuzu::shared {

/// The autoruns collect_user_launchagents rule: a real home is uid 500 or above (below is a
/// system account's directory).
inline constexpr std::uint32_t kMinUserHomeUid = 500;

/// A /Users entry name worth an fstatat at all: not empty, not a dotfile (`.`, `..`,
/// `.localized`, ...).
[[nodiscard]] constexpr bool home_name_eligible(std::string_view name) noexcept {
    return !name.empty() && name.front() != '.';
}

/// Whether one /Users entry is a real per-user home: an eligible name, a directory as seen
/// WITHOUT following a symlink (`is_directory` from an AT_SYMLINK_NOFOLLOW fstatat, so a
/// symlink is never a home), owned by uid >= `min_uid` (`Shared` and system entries are
/// skipped). `min_uid` defaults to kMinUserHomeUid; a test injects its own floor.
[[nodiscard]] constexpr bool is_user_home_entry(std::string_view name, bool is_directory,
                                                std::uint32_t uid,
                                                std::uint32_t min_uid = kMinUserHomeUid) noexcept {
    return home_name_eligible(name) && is_directory && uid >= min_uid;
}

} // namespace yuzu::shared
