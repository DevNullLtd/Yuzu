/**
 * posix_secure_read.hpp -- shared no-follow directory open and bounded
 * regular-file read primitives (#4866).
 *
 * Header-only, zero-dependency leaf: libc and the C++ standard library only,
 * no project include of any kind (docs/cpp-conventions.md: the shared
 * directory holds leaves with no core or plugin dependency edge). POSIX only; the whole
 * body is compiled out on Windows.
 *
 * Divergences between the per-plugin copies this replaces:
 *   1. Directory handles: some copies hand a raw fd to fdopendir() and keep
 *      closing it on the failure path; here the fd is owned by exactly one of
 *      the raw int or the DIR*, never both (see finish_dir_open).
 *   2. Symlink-leaf errno: under O_DIRECTORY|O_NOFOLLOW a symlink answers
 *      ENOTDIR, not ELOOP. ELOOP on a directory open means a link loop. File
 *      reads carry no O_DIRECTORY, so there a symlink leaf is ELOOP and maps
 *      to ReadError::symlink_refused.
 *   3. Size handling: reads go to EOF in fixed chunks and stop with
 *      `oversized` the moment the cap is exceeded. They never trust st_size
 *      (browser_inventory reads to st_size, which a growing or sparse file
 *      defeats).
 *   4. Non-regular leaves: O_NONBLOCK is load-bearing. Opening a FIFO
 *      O_RDONLY without it blocks until a writer appears, hanging the agent
 *      on an attacker-planted FIFO (same reasoning as
 *      local_security_policy_legs.hpp:148-156). With it the open succeeds, the
 *      fstat reports !S_ISREG, and the read is refused.
 *
 * SINGLE-COMPONENT CONTRACT for every `_at` form: `name` must be a non-empty
 * single path component. It is rejected with err = EINVAL, before any
 * syscall, when it is empty, contains '/', or is "." or "..". Dir-fd
 * confinement holds ONLY because of this: openat() does not confine an
 * absolute path, "..", or intermediate symlinks in a multi-component name.
 * Walk a tree hop by hop, one component per call.
 *
 * The path forms (open_dir_no_follow, read_file_no_follow) apply O_NOFOLLOW
 * to the leaf only; intermediate components ARE followed. Use the dir-fd
 * forms to confine. Both reject, with err = EINVAL before any syscall, a path
 * holding a NUL byte (it would silently open the prefix) and a path ending in
 * '/' or '/.' (the kernel follows a symlink leaf named that way, defeating
 * O_NOFOLLOW); the single path "/" is allowed. A caller that holds a root
 * with a trailing separator must strip it first.
 *
 * Blocking: open and read carry no deadline of their own, so a path on a dead
 * hard network mount can pin the calling worker (#4875 tracks the host-level
 * guard).
 *
 * errno policy: err is reported verbatim. ENOENT is NOT special-cased here;
 * each consumer keeps its own benign-absent predicate (autoruns_macos.hpp,
 * browser_inventory_linux_parsers.hpp, pkg_inventory_parsers.hpp).
 *
 * Out of scope: owner/mode policy checks (caller-side), reason-token
 * vocabulary (per plugin), and deadlines/timeouts (#4875 is host-level).
 *
 * Consumers still to migrate: pkg_inventory (posix::Dir hand-over),
 * browser_inventory (st_size read), local_security_policy (strict arm stays
 * caller-side), autoruns_linux / autoruns_macos.
 */
#pragma once

#if !defined(_WIN32)

#include <cerrno>
#include <cstddef>
#include <string>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace yuzu::shared {

/// Move-only owner of a DIR*.
class ScopedDir {
public:
    ScopedDir() noexcept = default;
    explicit ScopedDir(DIR* d) noexcept : d_(d) {}
    ~ScopedDir() {
        if (d_ != nullptr) ::closedir(d_);
    }
    ScopedDir(const ScopedDir&) = delete;
    ScopedDir& operator=(const ScopedDir&) = delete;
    ScopedDir(ScopedDir&& o) noexcept : d_(o.d_) { o.d_ = nullptr; }
    ScopedDir& operator=(ScopedDir&& o) noexcept {
        if (this != &o) {
            if (d_ != nullptr) ::closedir(d_);
            d_ = o.d_;
            o.d_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return d_; }
    [[nodiscard]] bool valid() const noexcept { return d_ != nullptr; }
    [[nodiscard]] int fd() const noexcept { return d_ != nullptr ? ::dirfd(d_) : -1; }

private:
    DIR* d_ = nullptr;
};

/// Result of a directory open: `err` is 0 on success, else the errno.
struct DirOpen {
    ScopedDir dir;
    int err = 0;
    [[nodiscard]] bool opened() const noexcept { return dir.valid(); }
};

enum class ReadError : int { none = 0, symlink_refused, not_regular, oversized, io };

/// Result of a bounded file read. `err` carries the errno when error == io.
struct FileRead {
    std::string data;
    ReadError error = ReadError::none;
    int err = 0;
    [[nodiscard]] bool ok() const noexcept { return error == ReadError::none; }
};

namespace detail {

/// False for a path the no-follow guarantee cannot hold for: an embedded NUL, or a trailing
/// '/' or '/.' (the kernel resolves those through a symlink leaf). "/" alone is fine.
inline bool is_plain_leaf_path(const std::string& p) {
    if (p.find('\0') != std::string::npos)
        return false;
    if (p.size() > 1 && p.back() == '/')
        return false;
    return !(p.size() >= 2 && p.compare(p.size() - 2, 2, "/.") == 0);
}

/// True for a name that is safe to hand to openat() as one hop.
inline bool is_single_component(const char* name) noexcept {
    if (name == nullptr || name[0] == '\0') return false;
    if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) return false;
    for (const char* p = name; *p != '\0'; ++p) {
        if (*p == '/') return false;
    }
    return true;
}

/// Takes ownership of raw_fd. After fdopendir succeeds the DIR* owns it; on
/// failure it is closed here exactly once. No path leaves it owned twice.
inline DirOpen finish_dir_open(int raw_fd) {
    DirOpen out;
    if (raw_fd < 0) {
        out.err = errno;
        return out;
    }
    DIR* d = ::fdopendir(raw_fd);
    if (d == nullptr) {
        const int e = errno;
        ::close(raw_fd);
        out.err = e;
        return out;
    }
    out.dir = ScopedDir{d};
    return out;
}

inline FileRead read_open_fd(int fd, std::size_t cap) {
    FileRead out;
    struct FdCloser {
        int fd;
        ~FdCloser() { ::close(fd); }
    } closer{fd};

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        out.error = ReadError::io;
        out.err = errno;
        return out;
    }
    if (!S_ISREG(st.st_mode)) {
        out.error = ReadError::not_regular;
        return out;
    }
    char buf[8192];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            out.data.clear();
            out.error = ReadError::io;
            out.err = errno;
            return out;
        }
        if (n == 0) break;
        if (out.data.size() + static_cast<std::size_t>(n) > cap) {
            out.data.clear();
            out.error = ReadError::oversized;
            return out;
        }
        out.data.append(buf, static_cast<std::size_t>(n));
    }
    return out;
}

inline FileRead finish_file_open(int fd, std::size_t cap) {
    if (fd < 0) {
        FileRead out;
        const int e = errno;
        if (e == ELOOP) {
            out.error = ReadError::symlink_refused;
        } else {
            out.error = ReadError::io;
        }
        out.err = e;
        return out;
    }
    return read_open_fd(fd, cap);
}

inline constexpr int kDirFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
inline constexpr int kFileFlags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC;

} // namespace detail

/// Open `path` as a directory; the leaf is not followed (intermediates are).
inline DirOpen open_dir_no_follow(const std::string& path) {
    if (!detail::is_plain_leaf_path(path)) {
        DirOpen out;
        out.err = EINVAL;
        return out;
    }
    return detail::finish_dir_open(::open(path.c_str(), detail::kDirFlags));
}

/// Open the single component `name` under `parent_fd` as a directory.
inline DirOpen open_dir_no_follow_at(int parent_fd, const char* name) {
    if (!detail::is_single_component(name)) {
        DirOpen out;
        out.err = EINVAL;
        return out;
    }
    return detail::finish_dir_open(::openat(parent_fd, name, detail::kDirFlags));
}

/// Read the regular file at `path` (leaf not followed) up to `cap` bytes.
inline FileRead read_file_no_follow(const std::string& path, std::size_t cap) {
    if (!detail::is_plain_leaf_path(path)) {
        FileRead out;
        out.error = ReadError::io;
        out.err = EINVAL;
        return out;
    }
    return detail::finish_file_open(::open(path.c_str(), detail::kFileFlags), cap);
}

/// Read the regular file `name` under `dir_fd` up to `cap` bytes.
inline FileRead read_file_no_follow_at(int dir_fd, const char* name, std::size_t cap) {
    if (!detail::is_single_component(name)) {
        FileRead out;
        out.error = ReadError::io;
        out.err = EINVAL;
        return out;
    }
    return detail::finish_file_open(::openat(dir_fd, name, detail::kFileFlags), cap);
}

} // namespace yuzu::shared

#endif // !_WIN32
