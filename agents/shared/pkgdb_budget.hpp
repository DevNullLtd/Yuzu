#pragma once

/**
 * pkgdb_budget.hpp -- the closed failure vocabulary and the rows / bytes / time
 * budget shared by every in-process package-database reader (dpkg status text,
 * rpm sqlite, rpm ndb, rpm Berkeley DB hash).
 *
 * Header-only, zero-dependency leaf (libc++ only, no project include): there is
 * no clock in here. The caller supplies `expired`, so a unit test drives the
 * time cause with a lambda and no sleep, and the production caller points it at
 * one steady_clock deadline.
 *
 * Contract every reader built on this header keeps:
 *   - it returns std::expected<T, PkgDbCause>; none throws on input;
 *   - none allocates from a length it has not first checked against the file
 *     size, the per-item cap and the byte budget;
 *   - a failure returns no partial result: one unreadable record fails the
 *     whole read, so a caller never publishes a smaller roster as the host's
 *     complete one.
 *
 * The cause names are an operator-facing vocabulary (they reach the typed
 * result's provenance token and the `list`/`query` error row), so adding one is
 * a docs change (agents/plugins/installed_apps/README.md result-status table).
 */

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string_view>

namespace yuzu::shared {

enum class PkgDbCause {
    unreadable,          ///< open/read/stat failed, or the database could not be queried
    symlink_refused,     ///< the database (or a directory on the way) is a symlink
    not_regular,         ///< a directory, FIFO or device where a database file belongs
    oversized,           ///< a file, row or length above its cap
    corrupt,             ///< a bound, magic or structure check failed on bytes that were read
    truncated,           ///< a header promises more bytes than the file holds
    unsupported_format,  ///< a recognised container this reader does not decode
    locked,              ///< the database is write-locked by its owner past the busy timeout
    changed_during_read, ///< the file's size or times moved while it was being read
    row_cap,             ///< more rows than the budget admits
    byte_cap,            ///< more bytes than the budget admits
    timeout,             ///< the wall-clock deadline passed
    busy,                ///< the bounded-call ceiling refused the read; nothing ran
};

/// The wire/log token for a cause. Lower-case ASCII, no delimiter characters.
[[nodiscard]] constexpr std::string_view pkgdb_cause_token(PkgDbCause c) noexcept {
    switch (c) {
    case PkgDbCause::unreadable: return "unreadable";
    case PkgDbCause::symlink_refused: return "symlink_refused";
    case PkgDbCause::not_regular: return "not_regular";
    case PkgDbCause::oversized: return "oversized";
    case PkgDbCause::corrupt: return "corrupt";
    case PkgDbCause::truncated: return "truncated";
    case PkgDbCause::unsupported_format: return "unsupported_format";
    case PkgDbCause::locked: return "locked";
    case PkgDbCause::changed_during_read: return "changed_during_read";
    case PkgDbCause::row_cap: return "row_cap";
    case PkgDbCause::byte_cap: return "byte_cap";
    case PkgDbCause::timeout: return "timeout";
    case PkgDbCause::busy: return "busy";
    }
    return "unreadable";
}

/// The largest single rpm header any reader will materialise: the structural
/// ceiling of the header format itself (rpmdb_parsers.hpp RpmHeader::parse). A
/// caller lowers it through PkgDbBudget::max_item_bytes.
inline constexpr std::uint64_t kPkgDbMaxItemBytes = 256ull * 1024 * 1024;

using PkgDbVoid = std::expected<void, PkgDbCause>;

/// Rows, bytes and time one read may spend. Plain arithmetic, never sticky: an
/// exact fill is admitted, the next charge is refused. `expired` may be empty
/// (no deadline); it is called from check_time() only, so a reader decides how
/// often a clock read is worth paying for.
struct PkgDbBudget {
    std::size_t rows_left = static_cast<std::size_t>(-1);
    std::uint64_t bytes_left = static_cast<std::uint64_t>(-1);
    std::uint64_t max_item_bytes = kPkgDbMaxItemBytes; ///< one rpm header, one status file
    std::function<bool()> expired;

    [[nodiscard]] PkgDbVoid charge_row() noexcept {
        if (rows_left == 0)
            return std::unexpected(PkgDbCause::row_cap);
        --rows_left;
        return {};
    }

    [[nodiscard]] PkgDbVoid charge_bytes(std::uint64_t n) noexcept {
        if (n > bytes_left)
            return std::unexpected(PkgDbCause::byte_cap);
        bytes_left -= n;
        return {};
    }

    [[nodiscard]] PkgDbVoid check_time() const {
        if (expired && expired())
            return std::unexpected(PkgDbCause::timeout);
        return {};
    }
};

} // namespace yuzu::shared
