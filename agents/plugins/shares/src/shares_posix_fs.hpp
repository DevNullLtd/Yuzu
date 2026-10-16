/**
 * shares_posix_fs.hpp -- the POSIX shell for the shares plugin's file reads: binds the
 * no-follow primitives of agents/shared/posix_secure_read.hpp to the LinuxFs boundary that
 * `list_linux` decides over. Parameterised on Paths so the real binding is unit-tested under
 * a TempDir on any POSIX host.
 *
 * Reads are bounded (kFileCap) and never follow a symlink leaf; the exports.d directory is
 * opened per listing with O_NOFOLLOW|O_DIRECTORY and every snippet is then read through THAT
 * descriptor (dir-fd confinement), never through a re-resolved path join. One LinuxFs per
 * execute(): it holds that descriptor, so it is not thread-safe and not for sharing.
 */
#pragma once

#if !defined(_WIN32)

#include "shares_legs.hpp"

#include <posix_dir_walk.hpp>
#include <posix_secure_read.hpp>

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace yuzu::shares {

inline constexpr std::size_t kFileCap = 256 * 1024;
inline constexpr std::size_t kMaxExportsFiles = 64;
inline constexpr std::size_t kMaxDirEntries = 4096; ///< entries examined in exports.d

struct Paths {
    std::string exports;
    std::string exports_d;
    std::string smb_conf;
    std::string usershares_default;
    std::size_t max_dir_entries = kMaxDirEntries; ///< injectable so a test need not make 4097 files
};

// ReadErr mirrors yuzu::shared::ReadError enumerator-for-enumerator, so one cast maps it; an
// unknown value would land in classify_read's `unknown` failed arm, never a silent success.
static_assert(static_cast<int>(ReadErr::none) == static_cast<int>(yuzu::shared::ReadError::none));
static_assert(static_cast<int>(ReadErr::symlink_refused) ==
              static_cast<int>(yuzu::shared::ReadError::symlink_refused));
static_assert(static_cast<int>(ReadErr::not_regular) ==
              static_cast<int>(yuzu::shared::ReadError::not_regular));
static_assert(static_cast<int>(ReadErr::oversized) ==
              static_cast<int>(yuzu::shared::ReadError::oversized));
static_assert(static_cast<int>(ReadErr::io) == static_cast<int>(yuzu::shared::ReadError::io));

inline FileReadLike to_read_like(yuzu::shared::FileRead&& r) {
    FileReadLike out;
    out.data = std::move(r.data);
    out.err = r.err;
    out.error = static_cast<ReadErr>(r.error);
    return out;
}

/// Bounded no-follow read of one regular file (the LinuxFs `read` boundary).
inline FileReadLike read_no_follow(const std::string& path) {
    return to_read_like(yuzu::shared::read_file_no_follow(path, kFileCap));
}

inline LinuxFs make_posix_fs(const Paths& p) {
    // The directory the last list_exports_d opened, kept alive across the snippet reads.
    auto dir = std::make_shared<yuzu::shared::DirOpen>();
    LinuxFs fs;
    fs.exports_path = p.exports;
    fs.smb_conf_path = p.smb_conf;
    fs.usershares_default = p.usershares_default;
    fs.read = &read_no_follow;
    fs.list_exports_d = [dir, path = p.exports_d,
                         cap = p.max_dir_entries](std::vector<std::string>& names, bool& too_many) {
        *dir = yuzu::shared::open_dir_no_follow(path);
        if (!dir->opened()) {
            // A symlinked exports.d answers ENOTDIR (O_NOFOLLOW|O_DIRECTORY), not ELOOP.
            return dir->err != 0 ? dir->err : EIO;
        }
        const auto w = yuzu::shared::walk_dir_capped(dir->dir.get(), cap, [&](const dirent* e) {
            if (is_exports_name(e->d_name))
                names.emplace_back(e->d_name);
            return true;
        });
        if (w.enumeration_error) {
            names.clear();
            return EIO;
        }
        too_many = w.truncated;
        std::ranges::sort(names);
        if (names.size() > kMaxExportsFiles) {
            names.resize(kMaxExportsFiles);
            too_many = true;
        }
        return 0;
    };
    fs.read_exports_d_file = [dir](const std::string& name) {
        return to_read_like(yuzu::shared::read_file_no_follow_at(dir->dir.fd(), name.c_str(), kFileCap));
    };
    fs.dir_probe = [](const std::string& path) -> int {
        struct stat st{};
        if (::lstat(path.c_str(), &st) != 0)
            return errno;
        return S_ISDIR(st.st_mode) ? 0 : ENOTDIR;
    };
    return fs;
}

} // namespace yuzu::shares

#endif // !defined(_WIN32)
