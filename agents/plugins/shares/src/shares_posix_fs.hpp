/**
 * shares_posix_fs.hpp -- the POSIX shell for the shares plugin's file reads: binds the
 * no-follow primitives of agents/shared/posix_secure_read.hpp to the LinuxFs boundary that
 * `list_linux` / `list_macos` decide over. Parameterised on Paths so the real binding is
 * unit-tested under a TempDir on Linux AND macOS.
 *
 * Reads are bounded (kFileCap) and never follow a symlink leaf; the exports.d directory is
 * opened once with O_NOFOLLOW|O_DIRECTORY and every snippet is then read through THAT
 * descriptor (dir-fd confinement), never through a re-resolved path join.
 */
#pragma once

#if !defined(_WIN32)

#include "shares_legs.hpp"

#include <posix_secure_read.hpp>

#include <cerrno>
#include <dirent.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace yuzu::shares {

struct Paths {
    std::string exports;
    std::string exports_d;
    std::string smb_conf;
    std::string usershares_default;
};

inline constexpr std::size_t kFileCap = 256 * 1024;
inline constexpr std::size_t kMaxExportsFiles = 64;
inline constexpr std::size_t kMaxDirEntries = 4096; ///< entries examined in exports.d

inline FileReadLike to_read_like(yuzu::shared::FileRead&& r) {
    FileReadLike out;
    out.data = std::move(r.data);
    out.err = r.err;
    switch (r.error) {
    case yuzu::shared::ReadError::none:
        out.error = ReadErr::none;
        break;
    case yuzu::shared::ReadError::symlink_refused:
        out.error = ReadErr::symlink_refused;
        break;
    case yuzu::shared::ReadError::not_regular:
        out.error = ReadErr::not_regular;
        break;
    case yuzu::shared::ReadError::oversized:
        out.error = ReadErr::oversized;
        break;
    case yuzu::shared::ReadError::io:
        out.error = ReadErr::io;
        break;
    }
    return out;
}

inline LinuxFs make_posix_fs(const Paths& p) {
    // The directory the last list_exports_d opened, kept alive across the snippet reads.
    auto dir = std::make_shared<yuzu::shared::DirOpen>();
    LinuxFs fs;
    fs.exports_path = p.exports;
    fs.smb_conf_path = p.smb_conf;
    fs.usershares_default = p.usershares_default;
    fs.read = [](const std::string& path) {
        return to_read_like(yuzu::shared::read_file_no_follow(path, kFileCap));
    };
    fs.list_exports_d = [dir, path = p.exports_d](std::vector<std::string>& names, bool& too_many) {
        *dir = yuzu::shared::open_dir_no_follow(path);
        if (!dir->opened()) {
            // A symlinked exports.d answers ENOTDIR on Linux and ELOOP on macOS: one contract.
            const int e = dir->err == ELOOP ? ENOTDIR : dir->err;
            return e != 0 ? e : EIO;
        }
        std::size_t examined = 0;
        for (;;) {
            errno = 0;
            const dirent* e = ::readdir(dir->dir.get());
            if (e == nullptr) {
                if (errno != 0) {
                    names.clear();
                    return errno;
                }
                break;
            }
            if (++examined > kMaxDirEntries) {
                too_many = true;
                break;
            }
            if (is_exports_name(e->d_name))
                names.emplace_back(e->d_name);
        }
        finalize_names(names, kMaxExportsFiles, too_many);
        return 0;
    };
    fs.read_exports_d_file = [dir](const std::string& name) {
        if (!dir->opened()) {
            FileReadLike r;
            r.error = ReadErr::io;
            r.err = EBADF;
            return r;
        }
        return to_read_like(yuzu::shared::read_file_no_follow_at(dir->dir.fd(), name.c_str(), kFileCap));
    };
    fs.dir_exists = [](const std::string& path) {
        struct stat st{};
        return ::lstat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    };
    return fs;
}

} // namespace yuzu::shares

#endif // !defined(_WIN32)
