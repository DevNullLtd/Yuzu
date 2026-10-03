/**
 * update_source_trust_linux_parsers.hpp -- the INJECTED-ROOT walk shell for the
 * Linux leg (apt sources + keyrings, and the planned-constraint tripwire for the
 * deferred rpm .repo family), plus the POSIX bounded read/list primitives
 * (`posix_io`) both are built on.
 *
 * SHAPE. The portable pure parsers live in
 * update_source_trust_parsers.hpp and compile everywhere. THIS header is the
 * POSIX-only walk shell: it needs <dirent.h>/<fcntl.h> (agents/shared/
 * posix_dir_walk.hpp is `#if !defined(_WIN32)`), so the whole body is guarded
 * out on Windows and the tests that exercise it guard their BODIES the same way.
 *
 * INJECTED ROOT. Every filesystem access takes a `root` path parameter --
 * production (update_source_trust_linux.cpp's `run_linux`) passes "/", the unit
 * suite passes a materialised fixture tree -- and every emitted path is the
 * LOGICAL absolute path ("/etc/apt/sources.list.d/x.sources"), never the
 * root-prefixed one. There is no subprocess of any kind
 * (scripts/ci/check-plugin-spawn-lexical.sh).
 *
 * HARDENING. Files and directories are opened with O_NOFOLLOW: a symlink as the
 * FINAL path component is refused, never followed (`symlink_refused` for a
 * file; a symlinked directory fails the O_DIRECTORY open with `not_a_directory`
 * on Linux). Intermediate directories resolve normally, as they do for apt
 * itself. Files also get O_NONBLOCK so a writer-less FIFO cannot block open()
 * before the regular-file check rejects it as `not_regular`. File reads are
 * capped at 1 MiB (same cap as autoruns_macos.cpp's kMaxPlistBytes; an oversized
 * file is `oversized`, never silently truncated -- a truncated parse could drop
 * later sources; a file that shrinks mid-read is `short_read`). Directory
 * listings go through yuzu::shared::walk_dir_capped, and directory_iterator is
 * never used.
 *
 * OUTPUT BUDGET. The rows of one whole walk share a single 1 MiB budget
 * (kMaxOutputBytes): the per-file and per-directory caps bound each read, not
 * their sum. Past it the newest rows are dropped, no further file is read and
 * `output_cap` is recorded. It bounds the rows KEPT, not the work of reading
 * them, which has its own INPUT BUDGET: the bytes the walk pulls from the kernel
 * share one 16 MiB InputBudget (kMaxInputBytes), charged inside read_file on
 * EVERY outcome after the first read -- bytes read, successful or not -- so a run
 * of failing files cannot bypass it. Once it is exceeded the walk stops and
 * `input_cap` is recorded; what was not read is not reported.
 *
 * FILES apt READS. Names in sources.list.d must pass apt's own filter
 * (apt_dir_name_ok: not hidden, only [A-Za-z0-9_.:-]) before the suffix test, so
 * the plugin reports the sources apt reads and no phantom ones. trusted.gpg.d is
 * selected by suffix (.gpg/.asc) ONLY: apt before 3.0 trusts a key under any such
 * name, so a name filter there would hide a global trust anchor. /etc/apt/keyrings
 * is listed by any name (apt never scans it; a Signed-By names its files).
 *
 * WIRE SAFETY. File text and names are OS-supplied bytes. Every wire field
 * replaces a NUL or a byte outside well-formed UTF-8 with '?' (scrub_wire_bytes:
 * a NUL would cut the row at the C-string ABI and an invalid byte makes the whole
 * response unparseable downstream). A replacement inside an EMITTED field is
 * recorded as `invalid_bytes`; bytes in a comment or an ignored field never reach
 * the wire and are not flagged.
 *
 * STABLE READS. A file is read between two fstat calls on the same fd; a changed
 * size or mtime means an in-place writer raced the read, and so does a text file
 * that is empty and was modified within the last two seconds: both are recorded
 * as `modified_during_read`, so an emptied-then-rewritten sources.list does not
 * read as "no sources". A writer that keeps the file empty for longer than that
 * cannot be told from a genuinely empty file.
 *
 * FAILURE NEVER READS AS ABSENT. Every non-ENOENT open/read/list failure, an
 * entry-cap truncation, a listing I/O error and an unparseable entry is a token
 * in the shared ConstraintAccumulator (`<os>:<source>:<detail>`); the caller
 * reports constrained + those tokens. Only a genuinely absent file/directory
 * (ENOENT) is zero rows and still `supported` -- a host with no apt
 * configuration simply has no apt sources.
 *
 * DEFERRED rpm/dnf FAMILY. The `.repo` family is not read yet, and the skipped
 * rpm/dnf family must not read as an empty one (other families -- zypper, pacman,
 * apk -- are not detected at all): rpm_family_planned_at records
 * `linux:rpm_repo:planned` whenever /etc/yum.repos.d has entries, so an rpm host
 * reports constrained -- exactly as a planned OS leg reports `unsupported` --
 * rather than `supported` with zero rows. run_linux_at (bottom of this header)
 * is linux_rows_at followed by report_sources; the unit suite drives
 * run_linux_at itself through a real CommandContext, so dropping the tripwire
 * from the SHIPPED leg fails a test.
 *
 * Namespace `lnx`, not `linux` (a predefined macro under GNU extension modes).
 */
#pragma once

#if !defined(_WIN32)

#include "update_source_trust_parsers.hpp"
#include "update_source_trust_legs.hpp"

#include <constraint_accumulator.hpp>
#include <posix_dir_walk.hpp>
#include <wire_utf8.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::update_source_trust::posix_io {

inline constexpr std::size_t kMaxFileBytes = 1024 * 1024; // 1 MiB, matches autoruns
inline constexpr std::size_t kMaxDirEntries = 1024;
inline constexpr std::size_t kKeyringHeadBytes = 64;
/// One budget for the wire rows of the WHOLE walk. The per-file and per-directory
/// caps above bound each read, not their sum: 1,024 files of 1 MiB each would
/// otherwise build a multi-gigabyte row vector before any downstream cap applies.
/// A real host reports a few KiB, so this is ~250x headroom.
inline constexpr std::size_t kMaxOutputBytes = 1024 * 1024;
/// One budget for the bytes READ by the whole walk (see the banner's INPUT BUDGET).
inline constexpr std::size_t kMaxInputBytes = 16 * 1024 * 1024;

/// `input_cap`: the input budget is spent; the walk must stop (token recorded).
enum class Outcome { ok, absent, failed, input_cap };

/// Bytes pulled from the kernel so far by one walk. read_file charges it on every
/// exit after its read loop starts, so a failed or torn read still counts.
struct InputBudget {
    std::size_t max_input_bytes = kMaxInputBytes;
    std::size_t used = 0;
};

namespace detail {
/// The real walk_dir_capped behind PosixOps::walk (a template cannot be a plain
/// function pointer).
inline yuzu::shared::DirWalkResult real_walk(DIR* d, std::size_t cap,
                                             const std::function<bool(const dirent*)>& on_entry) {
    return yuzu::shared::walk_dir_capped(d, cap, on_entry);
}
} // namespace detail

/// The syscall seam: production uses the defaults; the unit suite injects failures
/// no healthy filesystem produces on demand (EMFILE on open, EIO on read, a failed
/// fdopendir, a readdir fault).
struct PosixOps {
    int (*open)(const char*, int, ...) = &::open;
    int (*fstat)(int, struct stat*) = &::fstat;
    ssize_t (*read)(int, void*, std::size_t) = &::read;
    DIR* (*fdopendir)(int) = &::fdopendir;
    yuzu::shared::DirWalkResult (*walk)(DIR*, std::size_t,
                                        const std::function<bool(const dirent*)>&) = &detail::real_walk;
};

/// (size, mtime) of an open file: what two fstat calls on one fd are compared by.
/// The seconds and nanoseconds stay separate: a flattened nanosecond product
/// overflows int64 for an mtime after 2262, which ext4 allows.
struct FileStamp {
    std::uint64_t size = 0;
    std::int64_t sec = 0;
    std::int64_t nsec = 0;
    friend bool operator==(const FileStamp&, const FileStamp&) = default;
};

[[nodiscard]] inline FileStamp stamp_of(const struct stat& st) noexcept {
#if defined(__APPLE__)
    const timespec& ts = st.st_mtimespec;
#else
    const timespec& ts = st.st_mtim;
#endif
    return {static_cast<std::uint64_t>(st.st_size), static_cast<std::int64_t>(ts.tv_sec),
            static_cast<std::int64_t>(ts.tv_nsec)};
}

/// The default `after_read` hook of read_file: does nothing. The unit suite passes
/// a hook that rewrites the file between the read and the second fstat, the only
/// deterministic way to observe the stability check.
struct NoHook {
    void operator()() const noexcept {}
};

/// Records `<source_prefix>:<detail>` (e.g. "linux:apt_sources:permission_denied").
inline void note_failure(yuzu::shared::ConstraintAccumulator& acc, std::string_view source_prefix,
                         std::string_view detail) {
    std::string tok{source_prefix};
    tok += ':';
    tok.append(detail);
    acc.add_failure(tok);
    acc.mark_incomplete();
}

/// `<root>` + a logical absolute path ("/etc/apt/x") -> the on-disk path.
[[nodiscard]] inline std::filesystem::path under(const std::filesystem::path& root,
                                                 std::string_view logical) {
    if (!logical.empty() && logical.front() == '/')
        logical.remove_prefix(1);
    return root / std::filesystem::path(std::string{logical});
}

[[nodiscard]] inline bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

/// Reads one regular file, refusing a symlink leaf (O_NOFOLLOW). `head_only`
/// reads at most `cap` leading bytes of a file of ANY size (keyring sniffing);
/// otherwise a file larger than `cap` is `oversized`. `size_bytes` is the
/// file's full size from fstat. ENOENT -> absent (no token); anything else
/// (including a non-regular file, a short read and a file rewritten while it was
/// read) -> a token and `failed`. `after_read` runs once, after the bytes are
/// read and before the closing fstat (test seam, see NoHook).
template <class AfterRead = NoHook>
inline Outcome read_file(const std::filesystem::path& path, std::size_t cap, bool head_only,
                         std::string& out, std::uint64_t& size_bytes,
                         yuzu::shared::ConstraintAccumulator& acc, std::string_view source_prefix,
                         InputBudget& budget, const PosixOps& ops = {},
                         AfterRead&& after_read = AfterRead{}) {
    // O_NONBLOCK: open(2) of a writer-less FIFO blocks forever otherwise, before
    // the S_ISREG guard below can reject it. It is a no-op for regular files.
    yuzu::agent::ScopedFd fd(
        ops.open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.valid()) {
        const int err = errno;
        if (err == ENOENT)
            return Outcome::absent;
        note_failure(acc, source_prefix, errno_detail(err, IoStage::open_file));
        return Outcome::failed;
    }
    struct stat st{};
    if (ops.fstat(fd.get(), &st) != 0) {
        note_failure(acc, source_prefix, errno_detail(errno, IoStage::read_file));
        return Outcome::failed;
    }
    if (!S_ISREG(st.st_mode)) {
        note_failure(acc, source_prefix, "not_regular");
        return Outcome::failed;
    }
    size_bytes = static_cast<std::uint64_t>(st.st_size);
    if (!head_only && size_bytes > cap) {
        note_failure(acc, source_prefix, "oversized");
        return Outcome::failed;
    }
    const std::size_t want = head_only ? static_cast<std::size_t>(std::min<std::uint64_t>(size_bytes, cap))
                                       : static_cast<std::size_t>(size_bytes);
    out.assign(want, '\0');
    std::size_t total = 0;
    // Charges the bytes pulled from the kernel on EVERY exit below (ok, short_read,
    // read_failed, the closing fstat failing, modified_during_read): charging only a
    // successful read would let a run of failing files bypass the budget.
    struct Charge {
        InputBudget& b;
        std::size_t& total;
        bool done = false;
        void flush() noexcept {
            if (!done)
                b.used += total;
            done = true;
        }
        ~Charge() { flush(); }
    } charge{budget, total};
    // A failure token, then (budget now spent) the cap token that stops the walk.
    const auto fail = [&](std::string_view detail) {
        note_failure(acc, source_prefix, detail);
        charge.flush();
        if (budget.used <= budget.max_input_bytes)
            return Outcome::failed;
        note_failure(acc, source_prefix, "input_cap");
        return Outcome::input_cap;
    };
    while (total < want) {
        const ssize_t n = ops.read(fd.get(), out.data() + total, want - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return fail(errno_detail(errno, IoStage::read_file));
        }
        if (n == 0) {
            // EOF before fstat's size: the file shrank under us. Parsing what is
            // left would silently drop sources, so it is a constraint, not ok.
            return fail("short_read");
        }
        total += static_cast<std::size_t>(n);
    }
    after_read();
    struct stat after{};
    if (ops.fstat(fd.get(), &after) != 0)
        return fail(errno_detail(errno, IoStage::read_file));
    const FileStamp seen = stamp_of(after);
    // An in-place writer (truncate + write) raced the read: what was read may be an
    // empty or torn file, and an empty sources.list is normal on a host with no apt
    // sources, so it must not read as one. A changed size or mtime is the direct
    // signal. A text file that is EMPTY and was modified within the last two
    // seconds is treated the same way: a writer that empties the file for the whole
    // read window changes nothing between the two fstat calls, but its truncate
    // just bumped the mtime. (A file left empty for longer, or emptied by a writer
    // slower than that, cannot be told from a genuinely empty one: a documented
    // limit.)
    const auto now_s = static_cast<std::int64_t>(::time(nullptr));
    const bool just_emptied = !head_only && seen.size == 0 && seen.sec >= now_s - 2 && seen.sec <= now_s + 2;
    if (seen != stamp_of(st) || just_emptied)
        return fail("modified_during_read");
    charge.flush();
    if (budget.used > budget.max_input_bytes) {
        note_failure(acc, source_prefix, "input_cap");
        return Outcome::input_cap;
    }
    return Outcome::ok;
}

/// Lists the entry NAMES of a directory (sorted, so output is deterministic --
/// readdir order is unspecified), capped at kMaxDirEntries. ENOENT -> absent.
/// A cap truncation or a mid-scan I/O error is a token (`entry_cap` /
/// `enumeration_error`) but the names gathered so far are still returned.
inline Outcome list_dir(const std::filesystem::path& dir, std::vector<std::string>& names,
                        yuzu::shared::ConstraintAccumulator& acc, std::string_view source_prefix,
                        const PosixOps& ops = {}) {
    names.clear();
    yuzu::agent::ScopedFd fd(ops.open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.valid()) {
        const int err = errno;
        if (err == ENOENT)
            return Outcome::absent;
        note_failure(acc, source_prefix, errno_detail(err, IoStage::open_dir));
        return Outcome::failed;
    }
    std::unique_ptr<DIR, int (*)(DIR*)> d(ops.fdopendir(fd.get()), &::closedir);
    if (!d) {
        note_failure(acc, source_prefix, errno_detail(errno, IoStage::open_dir));
        return Outcome::failed;
    }
    (void)fd.release(); // fdopendir succeeded: closedir() now owns the fd
    const auto walk = ops.walk(d.get(), kMaxDirEntries, [&](const dirent* e) {
        names.emplace_back(e->d_name);
        return true;
    });
    if (walk.enumeration_error)
        note_failure(acc, source_prefix, "enumeration_error");
    if (walk.truncated)
        note_failure(acc, source_prefix, "entry_cap");
    std::sort(names.begin(), names.end());
    return Outcome::ok;
}

} // namespace yuzu::update_source_trust::posix_io

namespace yuzu::update_source_trust::lnx {

namespace pio = yuzu::update_source_trust::posix_io;

inline constexpr std::string_view kAptSourcesPrefix = "linux:apt_sources";
inline constexpr std::string_view kAptKeyringPrefix = "linux:apt_keyring";
inline constexpr std::string_view kRpmRepoPrefix = "linux:rpm_repo"; // planned family: tripwire token only

namespace detail {

/// Enforces the aggregate row budget (pio::kMaxOutputBytes) after a file's rows
/// were appended. Over budget: drops the newest rows until the total fits (every
/// earlier file already passed this check, so only the file just read loses
/// rows), records `<prefix>:output_cap` and returns false -- the caller stops
/// reading further files. Every add_* below returns this "keep walking" flag.
[[nodiscard]] inline bool within_output_budget(std::vector<std::string>& rows,
                                               yuzu::shared::ConstraintAccumulator& acc,
                                               std::string_view source_prefix) {
    std::size_t total = 0;
    for (const auto& r : rows)
        total += r.size() + 1; // + the row separator
    if (total <= pio::kMaxOutputBytes)
        return true;
    while (total > pio::kMaxOutputBytes && !rows.empty()) {
        total -= rows.back().size() + 1;
        rows.pop_back();
    }
    pio::note_failure(acc, source_prefix, "output_cap");
    return false;
}

inline bool add_apt_file(const std::filesystem::path& root, const std::string& logical,
                         AptFormat fmt, std::vector<std::string>& rows,
                         yuzu::shared::ConstraintAccumulator& acc, pio::InputBudget& budget,
                         const pio::PosixOps& ops) {
    std::string data;
    std::uint64_t size = 0;
    const pio::Outcome got = pio::read_file(pio::under(root, logical), pio::kMaxFileBytes, false,
                                            data, size, acc, kAptSourcesPrefix, budget, ops);
    if (got == pio::Outcome::input_cap)
        return false; // input budget spent (token recorded): stop the walk
    if (got != pio::Outcome::ok)
        return true; // this file failed (token recorded); the walk goes on
    std::size_t altered = 0;
    const std::size_t malformed = apt_rows_from_text(logical, fmt, data, rows, &altered);
    if (altered != 0)
        pio::note_failure(acc, kAptSourcesPrefix, "invalid_bytes"); // a replaced byte reached a field
    if (malformed != 0)
        pio::note_failure(acc, kAptSourcesPrefix, "unparsed_entry");
    return within_output_budget(rows, acc, kAptSourcesPrefix);
}

inline bool add_keyring_file(const std::filesystem::path& root, const std::string& logical,
                             std::string_view scope, std::vector<std::string>& rows,
                             yuzu::shared::ConstraintAccumulator& acc, pio::InputBudget& budget,
                             const pio::PosixOps& ops) {
    std::string head;
    std::uint64_t size = 0;
    const pio::Outcome got = pio::read_file(pio::under(root, logical), pio::kKeyringHeadBytes, true,
                                            head, size, acc, kAptKeyringPrefix, budget, ops);
    if (got == pio::Outcome::input_cap)
        return false;
    if (got != pio::Outcome::ok)
        return true;
    // The row's path field is scrubbed by format_apt_keyring_row; the name only
    // needs the constraint (a keyring name is not filtered by the walk).
    if (yuzu::shared::count_invalid_wire_bytes(logical) != 0)
        pio::note_failure(acc, kAptKeyringPrefix, "invalid_bytes");
    rows.push_back(format_apt_keyring_row(logical, scope, sniff_keyring(head), size));
    return within_output_budget(rows, acc, kAptKeyringPrefix);
}

inline bool add_keyring_dir(const std::filesystem::path& root, std::string_view logical_dir,
                            std::string_view scope, bool gpg_asc_only,
                            std::vector<std::string>& rows,
                            yuzu::shared::ConstraintAccumulator& acc, pio::InputBudget& budget,
                            const pio::PosixOps& ops) {
    std::vector<std::string> names;
    if (pio::list_dir(pio::under(root, logical_dir), names, acc, kAptKeyringPrefix, ops) ==
        pio::Outcome::failed)
        return true;
    for (const auto& n : names) {
        if (gpg_asc_only && !pio::ends_with(n, ".gpg") && !pio::ends_with(n, ".asc"))
            continue; // apt ignores every other suffix in trusted.gpg.d (see apt_dir_name_ok for the name rule)
        if (!add_keyring_file(root, std::string{logical_dir} + '/' + n, scope, rows, acc, budget, ops))
            return false;
    }
    return true;
}

} // namespace detail

/// apt facts under `root`: /etc/apt/sources.list (one-line),
/// /etc/apt/sources.list.d/*.list (one-line) and *.sources (deb822), then the
/// keyrings /etc/apt/trusted.gpg (legacy, global trust),
/// /etc/apt/trusted.gpg.d/*.{gpg,asc} (global trust) and /etc/apt/keyrings/*
/// (referenced via Signed-By). A host with no apt configuration returns zero
/// rows and no failure token. The rows of the whole walk share one budget
/// (pio::kMaxOutputBytes): once it is spent no further file is read and
/// `<prefix>:output_cap` is recorded. The bytes read share `budget`
/// (pio::InputBudget); once it is exceeded the walk stops with `<prefix>:input_cap`.
[[nodiscard]] inline std::vector<std::string>
apt_rows_at(const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
            pio::InputBudget& budget, const pio::PosixOps& ops = {}) {
    std::vector<std::string> rows;

    if (!detail::add_apt_file(root, "/etc/apt/sources.list", AptFormat::one_line, rows, acc,
                              budget, ops))
        return rows;

    constexpr std::string_view kListDir = "/etc/apt/sources.list.d";
    std::vector<std::string> names;
    if (pio::list_dir(pio::under(root, kListDir), names, acc, kAptSourcesPrefix, ops) !=
        pio::Outcome::failed) {
        for (const auto& n : names) {
            const bool deb822 = pio::ends_with(n, ".sources");
            if (!apt_dir_name_ok(n) || (!deb822 && !pio::ends_with(n, ".list")))
                continue; // apt skips hidden and oddly named files and any other suffix
            if (!detail::add_apt_file(root, std::string{kListDir} + '/' + n,
                                      deb822 ? AptFormat::deb822 : AptFormat::one_line, rows, acc,
                                      budget, ops))
                return rows;
        }
    }

    if (!detail::add_keyring_file(root, "/etc/apt/trusted.gpg", "legacy_trusted_gpg", rows, acc, budget,
                                  ops) ||
        !detail::add_keyring_dir(root, "/etc/apt/trusted.gpg.d", "trusted_gpg_d", true, rows, acc,
                                 budget, ops))
        return rows;
    detail::add_keyring_dir(root, "/etc/apt/keyrings", "etc_apt_keyrings", false, rows, acc, budget,
                            ops);
    return rows;
}

/// The rpm/dnf family is not read yet: no `.repo` file is opened or
/// parsed and no row is emitted. What this records instead is the fact that the
/// family exists here but is not yet read -- `linux:rpm_repo:planned` -- when
/// /etc/yum.repos.d lists at least one entry, so the caller reports constrained
/// rather than a clean, complete "no sources" for a Rocky/RHEL/Fedora host. A
/// missing or empty directory is silent (nothing was skipped); an unreadable or
/// over-cap one is the usual `linux:rpm_repo:<detail>` token from list_dir.
inline void rpm_family_planned_at(const std::filesystem::path& root,
                                  yuzu::shared::ConstraintAccumulator& acc,
                                  const pio::PosixOps& ops = {}) {
    std::vector<std::string> names;
    if (pio::list_dir(pio::under(root, "/etc/yum.repos.d"), names, acc, kRpmRepoPrefix, ops) ==
            pio::Outcome::ok &&
        !names.empty())
        pio::note_failure(acc, kRpmRepoPrefix, "planned");
}

/// Everything the Linux leg reports under `root`: the apt rows, plus the rpm
/// family's planned constraint (a token, never a row). run_linux_at is exactly
/// this call followed by report_sources.
[[nodiscard]] inline std::vector<std::string>
linux_rows_at(const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
              pio::InputBudget& budget, const pio::PosixOps& ops = {}) {
    std::vector<std::string> rows = apt_rows_at(root, acc, budget, ops);
    rpm_family_planned_at(root, acc, ops);
    return rows;
}

/// The production Linux leg body over an INJECTED root: the walk above, then
/// the one emission seam (report_sources), so the wire status row and the
/// CC-07 typed status are produced here. run_linux
/// (update_source_trust_linux.cpp) calls it with "/"; the unit suite drives it
/// over a fixture tree through a real CommandContext. MUTATION: calling
/// apt_rows_at instead of linux_rows_at here (dropping the rpm tripwire from
/// the shipped leg) fails the [seam] cases in
/// test_update_source_trust_linux_parsers.cpp.
inline int run_linux_at(yuzu::CommandContext& ctx, const std::filesystem::path& root) {
    yuzu::shared::ConstraintAccumulator acc;
    pio::InputBudget budget; // fresh per walk
    const std::vector<std::string> rows = linux_rows_at(root, acc, budget);
    report_sources(ctx, rows, acc);
    return 0;
}

} // namespace yuzu::update_source_trust::lnx

#endif // !defined(_WIN32)
