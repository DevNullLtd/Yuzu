/**
 * update_source_trust_linux_parsers.hpp -- the INJECTED-ROOT walk shell for the
 * Linux leg (apt sources + keyrings, and the planned-constraint tripwire for the
 * deferred rpm .repo family), plus the POSIX bounded read/list primitives
 * (`posix_io`) both are built on.
 *
 * SHAPE (X2 contract). The portable pure parsers live in
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
 * HARDENING. Files and directories are opened with O_NOFOLLOW (a symlink leaf
 * is refused and reported as `symlink_refused`, never followed). Files also get
 * O_NONBLOCK so a writer-less FIFO cannot block open() before the regular-file
 * check rejects it as `not_regular`. File reads are capped at 1 MiB (same cap as
 * autoruns_macos.cpp's kMaxPlistBytes; an oversized file is `oversized`, never
 * silently truncated -- a truncated parse could drop later sources; a file that
 * shrinks mid-read is `short_read`). Directory listings go through
 * yuzu::shared::walk_dir_capped, and directory_iterator is never used.
 *
 * FAILURE NEVER READS AS ABSENT. Every non-ENOENT open/read/list failure, an
 * entry-cap truncation, a listing I/O error and an unparseable entry is a token
 * in the shared ConstraintAccumulator (`<os>:<source>:<detail>`); the caller
 * reports constrained + those tokens. Only a genuinely absent file/directory
 * (ENOENT) is zero rows and still `supported` -- a host with no apt
 * configuration simply has no apt sources.
 *
 * DEFERRED rpm/dnf FAMILY. The `.repo` family follows as its own PR, and a
 * skipped family must not read as an empty one: rpm_family_planned_at records
 * `linux:rpm_repo:planned` whenever /etc/yum.repos.d has entries, so an rpm host
 * reports constrained -- exactly as a planned OS leg reports `unsupported` --
 * rather than `supported` with zero rows. linux_rows_at is the composition
 * run_linux_at reports; the unit suite drives it, so dropping the tripwire from
 * the leg fails a test.
 *
 * Namespace `lnx`, not `linux` (a predefined macro under GNU extension modes).
 */
#pragma once

#if !defined(_WIN32)

#include "update_source_trust_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <posix_dir_walk.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::update_source_trust::posix_io {

inline constexpr std::size_t kMaxFileBytes = 1024 * 1024; // 1 MiB, matches autoruns
inline constexpr std::size_t kMaxDirEntries = 1024;
inline constexpr std::size_t kKeyringHeadBytes = 64;

enum class Outcome { ok, absent, failed };

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
/// (including a non-regular file and a short read) -> a token and `failed`.
inline Outcome read_file(const std::filesystem::path& path, std::size_t cap, bool head_only,
                         std::string& out, std::uint64_t& size_bytes,
                         yuzu::shared::ConstraintAccumulator& acc, std::string_view source_prefix) {
    // O_NONBLOCK: open(2) of a writer-less FIFO blocks forever otherwise, before
    // the S_ISREG guard below can reject it. It is a no-op for regular files.
    yuzu::agent::ScopedFd fd(
        ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.valid()) {
        const int err = errno;
        if (err == ENOENT)
            return Outcome::absent;
        note_failure(acc, source_prefix, errno_detail(err, IoStage::open_file));
        return Outcome::failed;
    }
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) {
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
    while (total < want) {
        const ssize_t n = ::read(fd.get(), out.data() + total, want - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            note_failure(acc, source_prefix, errno_detail(errno, IoStage::read_file));
            return Outcome::failed;
        }
        if (n == 0) {
            // EOF before fstat's size: the file shrank under us. Parsing what is
            // left would silently drop sources, so it is a constraint, not ok.
            note_failure(acc, source_prefix, "short_read");
            return Outcome::failed;
        }
        total += static_cast<std::size_t>(n);
    }
    return Outcome::ok;
}

/// Lists the entry NAMES of a directory (sorted, so output is deterministic --
/// readdir order is unspecified), capped at kMaxDirEntries. ENOENT -> absent.
/// A cap truncation or a mid-scan I/O error is a token (`entry_cap` /
/// `enumeration_error`) but the names gathered so far are still returned.
inline Outcome list_dir(const std::filesystem::path& dir, std::vector<std::string>& names,
                        yuzu::shared::ConstraintAccumulator& acc, std::string_view source_prefix) {
    names.clear();
    yuzu::agent::ScopedFd fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.valid()) {
        const int err = errno;
        if (err == ENOENT)
            return Outcome::absent;
        note_failure(acc, source_prefix, errno_detail(err, IoStage::open_dir));
        return Outcome::failed;
    }
    std::unique_ptr<DIR, int (*)(DIR*)> d(::fdopendir(fd.get()), &::closedir);
    if (!d) {
        note_failure(acc, source_prefix, errno_detail(errno, IoStage::open_dir));
        return Outcome::failed;
    }
    (void)fd.release(); // fdopendir succeeded: closedir() now owns the fd
    const auto walk = yuzu::shared::walk_dir_capped(d.get(), kMaxDirEntries, [&](const dirent* e) {
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

inline void add_apt_file(const std::filesystem::path& root, const std::string& logical,
                         AptFormat fmt, std::vector<std::string>& rows,
                         yuzu::shared::ConstraintAccumulator& acc) {
    std::string data;
    std::uint64_t size = 0;
    if (pio::read_file(pio::under(root, logical), pio::kMaxFileBytes, false, data, size, acc,
                       kAptSourcesPrefix) != pio::Outcome::ok)
        return;
    if (apt_rows_from_text(logical, fmt, data, rows) != 0)
        pio::note_failure(acc, kAptSourcesPrefix, "unparsed_entry");
}

inline void add_keyring_file(const std::filesystem::path& root, const std::string& logical,
                             std::string_view scope, std::vector<std::string>& rows,
                             yuzu::shared::ConstraintAccumulator& acc) {
    std::string head;
    std::uint64_t size = 0;
    if (pio::read_file(pio::under(root, logical), pio::kKeyringHeadBytes, true, head, size, acc,
                       kAptKeyringPrefix) != pio::Outcome::ok)
        return;
    rows.push_back(format_apt_keyring_row(logical, scope, sniff_keyring(head), size));
}

inline void add_keyring_dir(const std::filesystem::path& root, std::string_view logical_dir,
                            std::string_view scope, bool gpg_asc_only,
                            std::vector<std::string>& rows,
                            yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string> names;
    if (pio::list_dir(pio::under(root, logical_dir), names, acc, kAptKeyringPrefix) ==
        pio::Outcome::failed)
        return;
    for (const auto& n : names) {
        if (gpg_asc_only && !pio::ends_with(n, ".gpg") && !pio::ends_with(n, ".asc"))
            continue; // apt itself ignores every other name in trusted.gpg.d
        add_keyring_file(root, std::string{logical_dir} + '/' + n, scope, rows, acc);
    }
}

} // namespace detail

/// apt facts under `root`: /etc/apt/sources.list (one-line),
/// /etc/apt/sources.list.d/*.list (one-line) and *.sources (deb822), then the
/// keyrings /etc/apt/trusted.gpg (legacy, global trust),
/// /etc/apt/trusted.gpg.d/*.{gpg,asc} (global trust) and /etc/apt/keyrings/*
/// (referenced via Signed-By). A host with no apt configuration returns zero
/// rows and no failure token.
[[nodiscard]] inline std::vector<std::string>
apt_rows_at(const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string> rows;

    detail::add_apt_file(root, "/etc/apt/sources.list", AptFormat::one_line, rows, acc);

    constexpr std::string_view kListDir = "/etc/apt/sources.list.d";
    std::vector<std::string> names;
    if (pio::list_dir(pio::under(root, kListDir), names, acc, kAptSourcesPrefix) !=
        pio::Outcome::failed) {
        for (const auto& n : names) {
            const std::string logical = std::string{kListDir} + '/' + n;
            if (pio::ends_with(n, ".sources"))
                detail::add_apt_file(root, logical, AptFormat::deb822, rows, acc);
            else if (pio::ends_with(n, ".list"))
                detail::add_apt_file(root, logical, AptFormat::one_line, rows, acc);
        }
    }

    detail::add_keyring_file(root, "/etc/apt/trusted.gpg", "legacy_trusted_gpg", rows, acc);
    detail::add_keyring_dir(root, "/etc/apt/trusted.gpg.d", "trusted_gpg_d", true, rows, acc);
    detail::add_keyring_dir(root, "/etc/apt/keyrings", "etc_apt_keyrings", false, rows, acc);
    return rows;
}

/// The rpm/dnf family is DEFERRED (its own PR): no `.repo` file is opened or
/// parsed and no row is emitted. What this records instead is the fact that the
/// family exists here but is not yet read -- `linux:rpm_repo:planned` -- when
/// /etc/yum.repos.d lists at least one entry, so the caller reports constrained
/// rather than a clean, complete "no sources" for a Rocky/RHEL/Fedora host. A
/// missing or empty directory is silent (nothing was skipped); an unreadable or
/// over-cap one is the usual `linux:rpm_repo:<detail>` token from list_dir.
inline void rpm_family_planned_at(const std::filesystem::path& root,
                                  yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string> names;
    if (pio::list_dir(pio::under(root, "/etc/yum.repos.d"), names, acc, kRpmRepoPrefix) ==
            pio::Outcome::ok &&
        !names.empty())
        pio::note_failure(acc, kRpmRepoPrefix, "planned");
}

/// Everything the Linux leg reports under `root`: the apt rows, plus the rpm
/// family's planned constraint (a token, never a row). run_linux_at is exactly
/// this call followed by report_sources.
[[nodiscard]] inline std::vector<std::string>
linux_rows_at(const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string> rows = apt_rows_at(root, acc);
    rpm_family_planned_at(root, acc);
    return rows;
}

} // namespace yuzu::update_source_trust::lnx

#endif // !defined(_WIN32)
