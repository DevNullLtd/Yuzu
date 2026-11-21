/**
 * file_search_rows.hpp -- the rows of one search slice, the named budgets that bound them and the
 * user-directory tag. Pure: strings in, strings out; no OS call, no clock, no I/O.
 *
 * ROW KINDS (every row is one '\n'-free line of '|'-separated columns; names go through
 * file_search::encode_name, so a column never holds the delimiter):
 *   match|<path>|<file|directory>|<dev:id>|<size|->|<mtime|->|<system|user>
 *   extents|<dev:id>|<state>|<total>|<list>              (file_search_extents.hpp)
 *   volume|<mount>|<fstype>|<state>|<reason>|extents=<..>|entries=<n>   (file_search_coverage.hpp)
 *   gap|<path>|<cause>                                   (file_search_coverage.hpp)
 *   gaps_dropped|<n>, volumes_dropped|<n>                (file_search_coverage.hpp)
 *   coverage|<complete|partial>|slices=<n>|prior_gaps=<n>|consistency=<..>   (file_search_coverage.hpp)
 *   cursor|<token>
 *   search|<status>|<reason>|<semantics id>|seq=<n>|q=<8 hex>|links_skipped=<n>
 * A match row's directory entries carry no size or time (the search never opens a directory), and a
 * file whose leaf could not be opened carries "-" for both.
 *
 * BUDGETS. The slice's answer must fit under the server's per-pair frame cap (response_store.hpp,
 * agent.cpp), so every part of it is bounded by a named constant and the bounds are checked at compile
 * time against each other: the match and extents rows may use kMatchRowBudget bytes and the tail (gap,
 * volume, coverage and cursor rows, then the trailer) is reserved kTailReserveBytes, which its own
 * worst case cannot exceed.
 */
#pragma once

#include <file_search_coverage.hpp>
#include <file_search_cursor.hpp>
#include <file_search_names.hpp>
#include <file_search_position.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::file_search {

namespace fsr = yuzu::shared::file_search;

/// The platform a leg runs on; it picks the name rule, the user-directory rule and the mount rules.
enum class Os { linux_os, macos };

// ---- named budgets (code and tests only: the README names a budget, never its figure) ----

/// A search ends, with its own reason, when its next cursor would reach this sequence number.
inline constexpr std::uint64_t kMaxSlices = 5'000;
/// How long past the slice time the pool thread waits for the worker before it abandons it.
inline constexpr std::chrono::milliseconds kSliceGrace{5'000};
/// Volumes (units, then refused rows) one search plans; the rest are counted, never silently lost.
inline constexpr std::size_t kMaxVolumes = 64;
/// The whole answer of one slice.
inline constexpr std::size_t kSliceRowBytes = 8u * 1024 * 1024;
/// A gap path longer than this is counted in gaps_dropped, never emitted.
inline constexpr std::size_t kMaxGapPathBytes = 1'024;
/// Matches reported per directory per slice; the next one is a match_cap gap.
inline constexpr std::size_t kMaxMatchesPerDirectory = 500;

/// Bounds on what a row can name: a root (the request parser) and a mount point (the plan).
inline constexpr std::size_t kMaxRootBytes = 4'096;
inline constexpr std::size_t kMaxVolumePathBytes = 4'096;
inline constexpr std::size_t kMaxFstypeBytes = 64;

/// The most bytes one match row or one extents row can take: an encoded path of a root plus the deepest
/// position, three bytes per byte at worst, plus the other columns.
inline constexpr std::size_t kMaxMatchRowBytes = 64u * 1024;
static_assert(3 * (kMaxRootBytes + (fsr::kMaxPositionDepth + 1) * (fsr::kMaxNameBytes + 1)) + 512 <=
                  kMaxMatchRowBytes,
              "a match row must fit kMaxMatchRowBytes for every path a walk can reach");

/// Reserved for everything after the match rows: gap rows, volume rows, coverage, cursor, trailer.
inline constexpr std::size_t kTailReserveBytes = 4u * 1024 * 1024;
static_assert(fsr::kMaxGaps * (3 * kMaxGapPathBytes + 64) +
                      kMaxVolumes * (3 * kMaxVolumePathBytes + 3 * kMaxFstypeBytes + 128) +
                      fsr::kMaxCursorTokenBytes + 1'024 <=
                  kTailReserveBytes,
              "the tail of a slice must fit its reserve in the worst case");

/// What the match and extents rows may use: the `max_bytes` of the driver's RowByteBudget.
inline constexpr std::size_t kMatchRowBudget = kSliceRowBytes - kTailReserveBytes;

// ---- scope tag ----

enum class Scope { system, user };

[[nodiscard]] constexpr const char* to_token(Scope s) noexcept {
    return s == Scope::user ? "user" : "system";
}

// ---- path tests ----

/// `path` is `prefix` or below it, on a component boundary. Both are absolute and have no trailing slash
/// ("/" is the prefix of everything). The ONE component-boundary test every path rule here uses.
[[nodiscard]] constexpr bool under(std::string_view path, std::string_view prefix) noexcept {
    if (prefix == "/")
        return !path.empty() && path.front() == '/';
    return path.size() >= prefix.size() && path.substr(0, prefix.size()) == prefix &&
           (path.size() == prefix.size() || path[prefix.size()] == '/');
}

/// A user profile directory or anything below one. Linux: /home/<name> and /root. macOS: /Users/<name>
/// except /Users/Shared, and /private/var/root (/var is a link there, so /var/root is never walked into
/// and is not tagged). A home relocated elsewhere is NOT tagged: the tag is a path rule, not a lookup.
[[nodiscard]] constexpr bool is_user_profile_path(std::string_view path, Os os) noexcept {
    if (os == Os::linux_os)
        return (path.size() > 6 && path.substr(0, 6) == "/home/") || under(path, "/root");
    if (under(path, "/private/var/root"))
        return true;
    return path.size() > 7 && path.substr(0, 7) == "/Users/" && !under(path, "/Users/Shared");
}

/// A gap path that may be emitted; a longer one is counted in gaps_dropped.
[[nodiscard]] constexpr bool gap_path_fits(std::string_view path) noexcept {
    return path.size() <= kMaxGapPathBytes;
}

// ---- match row ----

struct MatchInfo {
    std::string path;
    fsr::EntryKind kind{fsr::EntryKind::file};
    fsr::FileIdentity id{};
    std::optional<std::uint64_t> size; // nullopt: not known ("-")
    std::optional<std::int64_t> mtime; // seconds; nullopt: not known ("-")
    Scope scope{Scope::system};
};

[[nodiscard]] inline std::string format_match_row(const MatchInfo& m) {
    std::string row = fsr::format_match_row(m.path, m.kind, m.id);
    row += '|';
    row += m.size ? std::to_string(*m.size) : "-";
    row += '|';
    row += m.mtime ? std::to_string(*m.mtime) : "-";
    row += '|';
    row += to_token(m.scope);
    return row;
}

// ---- cursor row and trailer ----

[[nodiscard]] inline std::string format_cursor_row(std::string_view token) {
    return "cursor|" + std::string(token);
}

/// The slice's own outcome. `ok`: the slice ran (a cursor, if one is issued, continues the search);
/// `invalid`: the request or cursor was refused before anything ran; `busy`: another search slice holds
/// the agent's one slot; `failed`: the slice or the search ended without a result for the reason named.
enum class Status { ok, invalid, busy, failed };

[[nodiscard]] constexpr const char* to_token(Status s) noexcept {
    switch (s) {
    case Status::ok:
        return "ok";
    case Status::invalid:
        return "invalid";
    case Status::busy:
        return "busy";
    case Status::failed:
        return "failed";
    }
    return "failed";
}

/// Why a slice answered without a result, beyond the coverage reasons of file_search_coverage.hpp.
enum class Fault { busy, timed_out, rejected, no_progress, internal_error, cursor_refused };

[[nodiscard]] constexpr const char* to_token(Fault f) noexcept {
    switch (f) {
    case Fault::busy:
        return "busy";
    case Fault::timed_out:
        return "timed_out";
    case Fault::rejected:
        return "rejected";
    case Fault::no_progress:
        return "no_progress";
    case Fault::internal_error:
        return "internal_error";
    case Fault::cursor_refused:
        return "cursor_refused";
    }
    return "internal_error";
}

/// First 4 bytes of the query hash as lowercase hex: names a search in a log line, reveals neither the
/// pattern nor the root.
[[nodiscard]] inline std::string query_prefix(const fsr::QueryHash& h) {
    return std::format("{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3]);
}

struct Trailer {
    Status status{Status::failed};
    std::string reason{"none"};   // a closed token: a coverage reason, a Fault or a request error
    std::string semantics{"-"};   // the name rule that ran; "-" when no query was compiled
    std::uint64_t sequence{0};
    std::string query{"-"};       // query_prefix(), "-" when no query was compiled
    std::size_t links_skipped{0};
};

[[nodiscard]] inline std::string format_search_row(const Trailer& t) {
    return std::string("search|") + to_token(t.status) + "|" + t.reason + "|" + t.semantics +
           "|seq=" + std::to_string(t.sequence) + "|q=" + t.query +
           "|links_skipped=" + std::to_string(t.links_skipped);
}

} // namespace yuzu::file_search
