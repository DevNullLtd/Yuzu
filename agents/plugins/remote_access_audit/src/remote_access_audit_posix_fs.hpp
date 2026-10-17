/**
 * remote_access_audit_posix_fs.hpp -- the POSIX shell for the remote_access_audit plugin's
 * reads: binds the bounded read primitives of agents/shared/posix_secure_read.hpp to the PosixFs
 * boundary that `list_posix` decides over. Parameterised on Paths so the real binding is
 * unit-tested under a TempDir on any POSIX host.
 *
 * Two-tier symlink rule. CONFIG side (sshd_config, the Include directory, every Include file)
 * follows a symlink leaf: /etc/ssh is writable by root only, a link there is root's own
 * configuration exactly as a directive is, sshd follows it, and stock macOS (crypto.conf) and
 * NixOS ship such links. The reader still refuses a non-regular target by fstat on the
 * descriptor it reads and caps the size. KEY side (account homes, .ssh, authorized_keys*,
 * absolute AuthorizedKeysFile entries) never follows: the subject can write there, and a link
 * would make a root agent read what the subject cannot.
 *
 * Reads are bounded. An Include directory and each account home are opened ONCE and every read
 * under them goes through THAT descriptor, one path component per openat() (dir-fd
 * confinement), never through a re-resolved path join. One PosixFs per execute(): it holds
 * those descriptors, so it is not thread-safe and not for sharing.
 *
 * Blocking: open and read carry no deadline of their own (posix_secure_read.hpp). The legs
 * decision logic skips every path under a network mount named by the mount table BEFORE any
 * call here; stacked filesystems and a bare `fuse` mount over a dead server still block (#4875).
 */
#pragma once

#if !defined(_WIN32)

#include "remote_access_audit_legs.hpp"

#include <network_fstype.hpp>
#include <posix_dir_walk.hpp>
#include <posix_secure_read.hpp>

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fnmatch.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <vector>

namespace yuzu::remote_access_audit {

struct Paths {
    std::string os;       ///< "linux" | "macos"
    bool launchd = false;
    std::string config;   ///< /etc/ssh/sshd_config
    std::vector<std::string> home_parents; ///< directories whose subdirectories are homes (/home, /Users)
    std::vector<std::string> single_homes; ///< homes that are themselves a directory (/root, /var/root)
    unsigned min_uid = 0; ///< a home-parent entry owned by a lower uid is not an account (macOS: 500); 0 = no filter
    std::size_t max_dir_entries = kMaxDirEntries; ///< injectable so a test need not make 4097 files
    std::function<std::optional<std::vector<std::string>>()> mounts; ///< network mount points
    RunFn run;
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

/// A directory hop that failed: ELOOP is a symlink refused, anything else its errno.
inline FileReadLike hop_failure(int err) {
    FileReadLike out;
    out.error = err == ELOOP ? ReadErr::symlink_refused : ReadErr::io;
    out.err = err;
    return out;
}

inline std::string unescape_mountinfo(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '3' &&
            s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7') {
            out += static_cast<char>(((s[i + 1] - '0') << 6) | ((s[i + 2] - '0') << 3) | (s[i + 3] - '0'));
            i += 3;
        } else {
            out += s[i];
        }
    }
    return out;
}

/// Mount points of the network filesystems in a /proc/self/mountinfo text: field 5 is the
/// mount point (octal-escaped), the filesystem type is the first field after the standalone
/// `-` separator that closes the optional fields (runtimes_linux_parsers.hpp's rule).
inline std::vector<std::string> mountinfo_network_prefixes(std::string_view text) {
    std::vector<std::string> out;
    std::size_t at = 0;
    while (at < text.size()) {
        const auto nl = text.find('\n', at);
        const auto line = nl == std::string_view::npos ? text.substr(at) : text.substr(at, nl - at);
        at = nl == std::string_view::npos ? text.size() : nl + 1;
        std::vector<std::string_view> f;
        std::size_t b = 0;
        while (b < line.size()) {
            const auto sp = line.find(' ', b);
            f.push_back(line.substr(b, sp == std::string_view::npos ? std::string_view::npos : sp - b));
            if (sp == std::string_view::npos)
                break;
            b = sp + 1;
        }
        std::size_t sep = 6;
        while (sep < f.size() && f[sep] != "-")
            ++sep;
        if (f.size() < 7 || sep + 1 >= f.size())
            continue;
        if (yuzu::shared::is_network_fstype(f[sep + 1]))
            out.push_back(unescape_mountinfo(f[4]));
    }
    return out;
}

/// The Linux mount table via the bounded no-follow reader; nullopt when it cannot be read in full.
inline std::optional<std::vector<std::string>> linux_mountinfo_prefixes(const std::string& path) {
    const auto r = yuzu::shared::read_file_no_follow(path, 1024 * 1024);
    if (!r.ok())
        return std::nullopt;
    return mountinfo_network_prefixes(r.data);
}

inline std::string basename_of(const std::string& p) {
    const auto slash = p.find_last_of('/');
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

inline PosixFs make_posix_fs(const Paths& p) {
    // The directory the last list_include_dir opened, kept alive across the per-file reads.
    auto inc_dir = std::make_shared<yuzu::shared::DirOpen>();
    // The home the last open_home opened, kept alive across the hop-by-hop key reads.
    auto home_dir = std::make_shared<yuzu::shared::DirOpen>();
    PosixFs fs;
    fs.os = p.os;
    fs.launchd = p.launchd;
    fs.config_path = p.config;
    fs.home_roots = p.home_parents;
    fs.home_roots.insert(fs.home_roots.end(), p.single_homes.begin(), p.single_homes.end());
    fs.run = p.run;
    fs.network_mount_prefixes = p.mounts;

    fs.read_config = [](const std::string& path) {
        return to_read_like(yuzu::shared::read_file(path, kConfigFileCap, yuzu::shared::Leaf::follow));
    };
    fs.list_include_dir = [inc_dir, cap = p.max_dir_entries](const std::string& dir, const std::string& leaf,
                                                            std::vector<std::string>& names,
                                                            bool& too_many) {
        *inc_dir = yuzu::shared::open_dir(dir, yuzu::shared::Leaf::follow);
        if (!inc_dir->opened())
            return inc_dir->err != 0 ? inc_dir->err : EIO;
        const auto w = yuzu::shared::walk_dir_capped(inc_dir->dir.get(), cap, [&](const dirent* e) {
            if (::fnmatch(leaf.c_str(), e->d_name, FNM_PERIOD) == 0)
                names.emplace_back(e->d_name);
            return true;
        });
        if (w.enumeration_error) {
            names.clear();
            return EIO;
        }
        too_many = w.truncated;
        std::ranges::sort(names);
        if (names.size() > kMaxIncludeFiles) {
            names.resize(kMaxIncludeFiles);
            too_many = true;
        }
        return 0;
    };
    fs.read_include_at = [inc_dir](const std::string& name) {
        return to_read_like(yuzu::shared::read_file_at(inc_dir->dir.fd(), name.c_str(), kConfigFileCap, yuzu::shared::Leaf::follow));
    };

    fs.list_homes = [singles = p.single_homes, min_uid = p.min_uid, cap = p.max_dir_entries](
                        const std::vector<std::string>& roots, std::vector<HomeEntry>& homes,
                        bool& too_many) {
        int first_err = 0;
        bool any_listed = false;
        for (const auto& root : roots) {
            if (std::ranges::find(singles, root) != singles.end()) {
                homes.push_back({basename_of(root), root});
                any_listed = true;
                continue;
            }
            auto d = yuzu::shared::open_dir_no_follow(root);
            if (!d.opened()) {
                if (d.err != ENOENT && first_err == 0)
                    first_err = d.err != 0 ? d.err : EIO;
                continue;
            }
            any_listed = true;
            const auto w = yuzu::shared::walk_dir_capped(d.dir.get(), cap, [&](const dirent* e) {
                // Only directories (and links, so a refused symlinked home is visible) can be homes.
                if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN && e->d_type != DT_LNK)
                    return true;
                if (min_uid > 0) {
                    auto h = yuzu::shared::open_dir_no_follow_at(d.dir.fd(), e->d_name);
                    struct stat st{};
                    if (!h.opened() || ::fstat(h.dir.fd(), &st) != 0 || st.st_uid < min_uid)
                        return true; // not a real account home (macOS: uid < 500, or unopenable)
                }
                if (homes.size() >= kMaxHomes) {
                    too_many = true;
                    return false;
                }
                homes.push_back({e->d_name, root + "/" + e->d_name});
                return true;
            });
            if (w.enumeration_error && first_err == 0)
                first_err = EIO;
            if (w.truncated)
                too_many = true;
        }
        std::ranges::sort(homes, {}, &HomeEntry::name);
        if (first_err != 0)
            return first_err;
        return any_listed ? 0 : ENOENT;
    };
    fs.open_home = [home_dir](const HomeEntry& h) {
        *home_dir = yuzu::shared::open_dir_no_follow(h.path);
        if (home_dir->opened())
            return 0;
        return home_dir->err != 0 ? home_dir->err : EIO;
    };
    fs.read_key_file = [home_dir](const std::vector<std::string>& components) -> FileReadLike {
        if (components.empty() || !home_dir->opened())
            return hop_failure(EINVAL);
        // One component per openat(); each directory handle lives until the read returns.
        std::vector<yuzu::shared::DirOpen> hops;
        int fd = home_dir->dir.fd();
        for (std::size_t i = 0; i + 1 < components.size(); ++i) {
            auto d = yuzu::shared::open_dir_no_follow_at(fd, components[i].c_str());
            if (!d.opened())
                return hop_failure(d.err != 0 ? d.err : EIO);
            fd = d.dir.fd();
            hops.push_back(std::move(d));
        }
        return to_read_like(yuzu::shared::read_file_no_follow_at(fd, components.back().c_str(), kKeyFileCap));
    };
    fs.read_key_file_abs = [](const std::string& path) {
        return to_read_like(yuzu::shared::read_file_no_follow(path, kKeyFileCap));
    };
    return fs;
}

} // namespace yuzu::remote_access_audit

#endif // !defined(_WIN32)
