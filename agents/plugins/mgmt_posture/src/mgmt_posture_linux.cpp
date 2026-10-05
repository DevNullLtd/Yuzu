/**
 * mgmt_posture_linux.cpp -- Linux leg: management plane from configuration files.
 *
 * Only the POSIX shell lives here: the bounded small-file reader, the conf.d lister and
 * the keytab presence probe, injected into `posture_linux` (mgmt_posture_legs.hpp), which
 * owns every decision (refused != absent: a refused sssd.conf is permission_denied with
 * plane `unknown`, never "not joined"). The keytab is probed with access(2) and never
 * opened: it holds key material.
 */
#include "mgmt_posture_legs.hpp"

#if defined(__linux__)

#include <yuzu/agent/scoped_fd.hpp>

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace yuzu::mgmt_posture {

namespace {

constexpr size_t kFileCap = 64 * 1024;
constexpr size_t kMaxSnippets = 32;
constexpr size_t kMaxDirEntries = 4096; ///< enumeration budget: entries examined in conf.d

// ponytail: private reader. It follows symlinks by decision (root-owned /etc is the trust
// anchor), so a later move onto agents/shared/posix_secure_read.hpp needs a follow-leaf variant.
// Symlinks are followed on purpose: root-owned /etc is the trust anchor. O_NONBLOCK keeps
// open(2) on a FIFO from wedging the dispatch thread before the S_ISREG check can run.
ReadResult read_small_file(const char* path, size_t cap = kFileCap) {
    ReadResult out;
    const yuzu::agent::ScopedFd fd(::open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC));
    if (!fd) {
        out.err = errno;
        return out;
    }
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) {
        out.err = errno;
        return out;
    }
    if (!S_ISREG(st.st_mode)) {
        out.err = kErrNotRegular;
        return out;
    }
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd.get(), buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            out.err = errno;
            out.data.clear();
            break;
        }
        if (n == 0)
            break;
        out.data.append(buf, static_cast<size_t>(n));
        if (out.data.size() > cap) {
            out.err = kErrOversized;
            out.data.clear();
            break;
        }
    }
    return out;
}

struct DirDeleter {
    void operator()(DIR* d) const noexcept { ::closedir(d); }
};

/// Lists conf.d `*.conf` names (no dotfiles) into `out`, sorted and cut to kMaxSnippets by
/// finalize_snippets. At most kMaxDirEntries entries are examined, which bounds memory;
/// either overflow sets `too_many` (the caller reports constrained). Returns 0, or the errno
/// of a failed opendir/readdir. A readdir error is never an end-of-directory; the caller
/// cannot tell an opendir ENOENT (absent) from a readdir ENOENT (directory removed mid-scan),
/// and treats both as absent: a snapshot of a changing directory.
int list_snippets(std::vector<std::string>& out, bool& too_many) {
    const std::unique_ptr<DIR, DirDeleter> d(::opendir(kSssdConfD));
    if (!d)
        return errno;
    size_t examined = 0;
    for (;;) {
        errno = 0;
        const dirent* e = ::readdir(d.get());
        if (!e) {
            if (errno != 0)
                return errno;
            break;
        }
        if (++examined > kMaxDirEntries) {
            too_many = true;
            break;
        }
        if (is_snippet_name(e->d_name))
            out.emplace_back(e->d_name);
    }
    finalize_snippets(out, kMaxSnippets, too_many);
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx) {
    const LinuxFs fs{
        [](const std::string& p) { return read_small_file(p.c_str()); },
        [](std::vector<std::string>& n, bool& tm) { return list_snippets(n, tm); },
        [] { return ::access(kKeytab, F_OK) == 0 ? 0 : errno; },
    };
    report_posture(ctx, posture_linux(fs));
    return 0;
}

} // namespace yuzu::mgmt_posture

#endif // defined(__linux__)
