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
 * descriptor it reads and caps the size. A home PARENT (/home, /Users) is the same kind of
 * root-only-writable path, so ONE link hop is allowed (Fedora Atomic ships /home -> var/home):
 * resolve_root readlinks it, the legs check the target against the mount table before anything
 * is opened, and the lister then opens the target component by component from "/" with no
 * further link followed, so a link chain or a linked component is refused (ELOOP), never
 * walked. Only the entries beneath the parent are subject-writable. KEY side (each account
 * home, .ssh, authorized_keys*, absolute AuthorizedKeysFile entries) never follows: the
 * subject can write there, and a link would make a root agent read what the subject cannot. An
 * absolute entry is opened from "/" one O_NOFOLLOW component at a time, so a link in ANY
 * directory of its chain is refused, not only at the leaf (stock macOS /etc, /var, /tmp are
 * links: an absolute entry through one reports `failed` + symlink_refused, there is no
 * trusted-alias table). A single home (/root, /var/root) is a home, not a parent: it stays
 * no-follow.
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
#include <climits>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <fnmatch.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace yuzu::remote_access_audit {

struct Paths {
    std::string os;       ///< "linux" | "macos"
    bool launchd = false;
    std::string config;   ///< /etc/ssh/sshd_config
    std::vector<std::string> home_parents; ///< directories whose subdirectories are homes (/home, /Users)
    std::vector<std::string> single_homes; ///< homes that are themselves a directory (/root, /var/root)
    unsigned min_uid = 0; ///< a home-parent entry owned by a lower uid is not an account (macOS: 500); 0 = no filter (see PosixFs::is_account_home)
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

/// The Linux mount table via the bounded no-follow reader; nullopt when it cannot be read in full.
inline std::optional<std::vector<std::string>> linux_mountinfo_prefixes(const std::string& path) {
    const auto r = yuzu::shared::read_file_no_follow(path, 1024 * 1024);
    if (!r.ok())
        return std::nullopt;
    return yuzu::shared::network_mount_points(r.data);
}

/// One readlink hop of a configured home parent. A root that is not a link, a single home, and
/// any lstat/readlink failure answer `root` unchanged (the no-follow open then reports it
/// loudly). The link is read, never the target; a relative target is taken against the
/// parent's directory; the result is lexically normalised with no trailing slash.
inline std::string resolve_home_root(const std::string& root, const std::vector<std::string>& single_homes) {
    if (std::ranges::find(single_homes, root) != single_homes.end())
        return root;
    struct stat st{};
    if (::lstat(root.c_str(), &st) != 0 || !S_ISLNK(st.st_mode))
        return root;
    char buf[PATH_MAX];
    const ssize_t n = ::readlink(root.c_str(), buf, sizeof buf);
    if (n <= 0 || static_cast<std::size_t>(n) >= sizeof buf)
        return root;
    std::filesystem::path target{std::string(buf, static_cast<std::size_t>(n))};
    if (target.is_relative())
        target = std::filesystem::path(root).parent_path() / target;
    auto out = target.lexically_normal().string();
    if (out.size() > 1 && out.back() == '/')
        out.pop_back();
    return out;
}

/// Opens the absolute directory `path` one component at a time from "/", every hop O_NOFOLLOW:
/// no link anywhere in it is followed. A hop that is a link answers ELOOP on every OS (Linux
/// reports ENOTDIR for O_DIRECTORY|O_NOFOLLOW on a link; the lstat tells the two apart).
inline yuzu::shared::DirOpen open_dir_hops(const std::string& path) {
    if (path.empty() || path.front() != '/') {
        yuzu::shared::DirOpen bad;
        bad.err = EINVAL;
        return bad;
    }
    auto cur = yuzu::shared::open_dir_no_follow("/");
    for (const auto& part : std::filesystem::path(path).relative_path()) {
        if (!cur.opened())
            break;
        const std::string name = part.string();
        if (name.empty()) // a trailing slash
            continue;
        auto next = yuzu::shared::open_dir_no_follow_at(cur.dir.fd(), name.c_str());
        if (!next.opened() && next.err == ENOTDIR) {
            struct stat st{};
            if (::fstatat(cur.dir.fd(), name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode))
                next.err = ELOOP;
        }
        cur = std::move(next);
    }
    return cur;
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
    fs.resolve_root = [singles = p.single_homes](const std::string& root) {
        return resolve_home_root(root, singles);
    };

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

    // Lists NAMES only: no entry is opened here, so an unopenable home is listed and surfaces as
    // a refused file row when the leg opens it. Account eligibility is is_account_home (below).
    fs.list_homes = [singles = p.single_homes, cap = p.max_dir_entries](
                        const std::vector<std::string>& roots, std::vector<HomeEntry>& homes,
                        bool& too_many) {
        int first_err = 0;
        bool any_listed = false;
        for (const auto& root : roots) {
            if (std::ranges::find(singles, root) != singles.end()) {
                homes.push_back({std::filesystem::path(root).filename().string(), root});
                any_listed = true;
                continue;
            }
            // `root` is already resolved (one link hop, mount-checked by the caller): nothing
            // in it is followed here, so a chain or a linked component answers ELOOP.
            auto d = open_dir_hops(root);
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
    if (p.min_uid > 0) {
        // A path lstat: nothing is opened and nothing is followed. false ONLY on a confirmed
        // owner of the HOME below the floor; a failed stat answers true so open_home reports the
        // errno (refused / failed) rather than the home vanishing, and so does a link, whose
        // lstat owner (often root, for a relocated home) says nothing about the home it names:
        // eligible at any floor, refused loudly at open. A single home (/root, /var/root) is
        // never filtered: root's own home is owned by uid 0 by definition.
        fs.is_account_home = [singles = p.single_homes, min_uid = p.min_uid](const HomeEntry& h) {
            if (std::ranges::find(singles, h.path) != singles.end())
                return true;
            struct stat st{};
            if (::lstat(h.path.c_str(), &st) != 0 || S_ISLNK(st.st_mode))
                return true;
            return st.st_uid >= min_uid;
        };
    }
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
    fs.read_key_file_abs = [](const std::string& path) -> FileReadLike {
        // The parent is opened from "/" one O_NOFOLLOW component at a time, exactly as the
        // lister opens a home parent, so a link anywhere in the chain is refused (ELOOP), never
        // walked; the leaf is then read no-follow through that descriptor. The handle is a local
        // and outlives the read.
        const std::filesystem::path p{path};
        const std::string leaf = p.filename().string();
        if (!p.is_absolute() || leaf.empty())
            return hop_failure(EINVAL);
        auto d = open_dir_hops(p.parent_path().string());
        if (!d.opened())
            return hop_failure(d.err != 0 ? d.err : EIO);
        return to_read_like(yuzu::shared::read_file_no_follow_at(d.dir.fd(), leaf.c_str(), kKeyFileCap));
    };
    return fs;
}

} // namespace yuzu::remote_access_audit

#endif // !defined(_WIN32)
